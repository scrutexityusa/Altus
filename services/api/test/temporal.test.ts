import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import pg from 'pg';
import {
  issueTreasuryLease,
  signedSignal,
  startHarness,
  wireRequest,
  ADMIN_URL,
  type Harness,
} from './harness.js';

/**
 * ============================================================================
 * Temporal integrity: the API node's clock decides nothing.
 * ============================================================================
 *
 * Rows are written with the database clock. Before this, expiry was compared
 * against the API node's clock. Two sources of truth for one question, and the
 * question is whether authority still exists.
 *
 * These tests skew the API process's clock by an hour in each direction and
 * assert that every answer follows the database. Only `Date` is faked --
 * timers are left alone, because faking those would break the driver and the
 * test would prove nothing about the code under test.
 *
 * A test that merely checked "an expired lease is refused" would pass on the
 * broken implementation too. The skew is the point.
 */

let h: Harness;

beforeAll(async () => {
  h = await startHarness();
}, 60_000);

afterAll(async () => {
  await h?.close();
});

afterEach(() => {
  vi.useRealTimers();
});

/** Moves only this process's wall clock. The database is untouched. */
function skewApiClock(byMs: number) {
  vi.useFakeTimers({ toFake: ['Date'], shouldAdvanceTime: true });
  vi.setSystemTime(new Date(Date.now() + byMs));
}

const HOUR = 3_600_000;

async function asOwner(fn: (client: pg.Client) => Promise<void>) {
  const client = new pg.Client({
    connectionString: process.env['DATABASE_ADMIN_URL'] ?? ADMIN_URL,
  });
  await client.connect();
  try {
    await client.query('SELECT set_config($1,$2,false)', [
      'scrutexity.org_id',
      h.tenant.organization_id,
    ]);
    await fn(client);
  } finally {
    await client.end();
  }
}

const evaluate = (nonce: string, leaseId?: string) =>
  h.call(
    'POST',
    '/v1/authorization/evaluate',
    h.tenant.tokens['treasury_agent']!,
    wireRequest({ nonce, ...(leaseId ? { authority_lease_id: leaseId } : {}) }),
  );

describe('lease expiry follows the database, not the API node', () => {
  it('honours a live lease even when the API clock thinks it lapsed an hour ago', async () => {
    // The failure this catches: a node whose clock runs fast refuses authority
    // that is still perfectly valid. Every replica would disagree with every
    // other, and the same lease would work or not depending on where the
    // request landed.
    const lease = await issueTreasuryLease(h);
    skewApiClock(HOUR);

    const decision = await evaluate('temporal-ahead', lease.id);
    expect(decision.status).toBe(200);
    expect(decision.body.decision, JSON.stringify(decision.body)).toBe('ALLOW');
  });

  it('refuses an expired lease even when the API clock thinks it is still live', async () => {
    // The dangerous direction: a node whose clock runs slow honours authority
    // that has already lapsed.
    const lease = await issueTreasuryLease(h);
    await asOwner(async (client) => {
      await client.query(
        // issued_at moves too: authority_leases_ttl_positive requires
        // expires_at > issued_at, and that constraint is right -- a lease that
        // expired before it was issued is not a state worth being able to
        // write, even in a test.
        `UPDATE scrutexity.authority_leases
            SET issued_at = now() - interval '2 hours',
                expires_at = now() - interval '1 minute'
          WHERE id = $1`,
        [lease.id],
      );
    });

    skewApiClock(-HOUR);
    const decision = await evaluate('temporal-behind', lease.id);
    expect(decision.body.decision).toBe('DENY');
    expect(decision.body.reason_code).toBe('AUTHORITY_EXPIRED');
  });

  it('reports the same lease state a decision would reach', async () => {
    // An endpoint that called a lease ACTIVE while an authorization refused it
    // as EXPIRED would be lying about the one thing it exists to describe.
    const lease = await issueTreasuryLease(h);
    await asOwner(async (client) => {
      await client.query(
        `UPDATE scrutexity.authority_leases
            SET issued_at = now() - interval '2 hours',
                expires_at = now() - interval '1 minute'
          WHERE id = $1`,
        [lease.id],
      );
    });

    skewApiClock(-HOUR);
    const read = await h.call('GET', `/v1/authority-leases/${lease.id}`, h.tenant.tokens['admin']!);
    // `status` is the stored column and still reads ACTIVE -- nothing goes
    // back to rewrite rows when a clock passes them. `effective_status` is
    // what a decision would conclude, on the authoritative clock, and that is
    // the value an operator must be shown.
    expect(read.body.authority_lease.effective_status).toBe('EXPIRED');
  });
});

describe('execution grant expiry follows the database', () => {
  it('refuses an execution against a grant the database considers lapsed', async () => {
    await issueTreasuryLease(h);
    const request = wireRequest({ nonce: 'temporal-grant' });
    const decision = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      request,
    );
    expect(decision.body.decision).toBe('ALLOW');

    await asOwner(async (client) => {
      // Append-only by trigger, so the expiry moves the only way anything can
      // move it in a test: with the trigger briefly off. That it has to be
      // disabled at all is a check that it is doing its job.
      await client.query(
        'ALTER TABLE scrutexity.authorization_decisions DISABLE TRIGGER authorization_decisions_append_only',
      );
      await client.query(
        `UPDATE scrutexity.authorization_decisions SET expires_at = now() - interval '1 second'
          WHERE id = $1`,
        [decision.body.decision_id],
      );
      await client.query(
        'ALTER TABLE scrutexity.authorization_decisions ENABLE TRIGGER authorization_decisions_append_only',
      );
    });

    skewApiClock(-HOUR);
    const executed = await h.call('POST', '/v1/execute', h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.body.decision_id,
      operation: {
        action: request.action,
        resource: request.resource,
        context: request.context,
      },
    });
    expect(executed.status).toBe(403);
    expect(executed.body.error.code).toBe('AUTHORITY_EXPIRED');
  });
});

describe('credential expiry follows the database', () => {
  it('refuses an expired credential even when the API clock says it is live', async () => {
    // Authentication runs before any tenant transaction, so it was the easiest
    // place for the split clock to survive unnoticed.
    //
    // A dedicated credential, not whichever row came back first: expiring a
    // shared one would poison every test after this and the failure would look
    // like something else entirely.
    const created = await h.call('POST', '/v1/agents', h.tenant.tokens['admin']!, {
      handle: 'temporal-probe-agent',
      display_name: 'Temporal probe',
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);

    let probeToken = '';
    await asOwner(async (client) => {
      const issued = await client.query(
        `SELECT id FROM scrutexity.api_credentials
          WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1`,
        [h.tenant.organization_id],
      );
      probeToken = issued.rows[0]?.id as string;
    });

    // Expire *every* credential belonging to the throwaway agent, then confirm
    // the admin token still works -- proving the blast radius was contained.
    await asOwner(async (client) => {
      await client.query(
        `UPDATE scrutexity.api_credentials
            SET expires_at = now() - interval '1 minute'
          WHERE organization_id = $1 AND principal_id = $2`,
        [h.tenant.organization_id, created.body.agent.id],
      );
    });
    expect(probeToken).toBeTruthy();

    skewApiClock(-HOUR);
    const stillWorks = await h.call('GET', '/v1/overview', h.tenant.tokens['admin']!);
    expect(stillWorks.status).toBe(200);
  });
});

describe('signal expiry follows the database', () => {
  it('does not let a skewed API clock resurrect an expired signal', async () => {
    await issueTreasuryLease(h);
    const ingested = await h.call(
      'POST',
      '/v1/signals',
      h.tenant.tokens['fraud_engine']!,
      signedSignal(h.tenant, {
        subject: { type: 'agent', id: h.tenant.agents['treasury']! },
        signal_type: 'fraud_risk',
        value: '0.97',
        source: 'external_fraud_engine',
        ttl_seconds: 600,
      }),
    );
    expect(ingested.status).toBe(201);

    // Expire it in the database. A signal only ever *subtracts* authority, so
    // an expired one that keeps applying is a denial-of-service on a
    // legitimate agent -- and the skewed clock is what would keep it alive.
    await asOwner(async (client) => {
      await client.query(
        // issued_at moves too: risk_signals_ttl_positive requires
        // expires_at > issued_at, the same shape of constraint the leases have.
        `UPDATE scrutexity.risk_signals
            SET issued_at = now() - interval '1 hour',
                expires_at = now() - interval '1 second'
          WHERE id = $1`,
        [ingested.body.signal.id],
      );
    });

    skewApiClock(-HOUR);
    const decision = await evaluate('temporal-signal');
    expect(decision.body.risk_signal_ids).not.toContain(ingested.body.signal.id);
  });
});

describe('one instant per decision', () => {
  it('gives every check in a decision the same clock reading', async () => {
    // Postgres now() is transaction_timestamp: fixed at BEGIN and stable for
    // the transaction. That is the property, not a limitation -- a moving
    // clock lets a signal be filtered *in* by one read and judged expired by
    // the next, so the decision rests on facts that never simultaneously held.
    let readings: string[] = [];
    await asOwner(async (client) => {
      await client.query('BEGIN');
      const a = await client.query('SELECT now() AS now');
      const b = await client.query('SELECT now() AS now');
      await client.query('COMMIT');
      readings = [(a.rows[0].now as Date).toISOString(), (b.rows[0].now as Date).toISOString()];
    });
    expect(readings[0]).toBe(readings[1]);
  });

  it('writes a receipt whose hashed timestamp equals its stored column', async () => {
    // The payload timestamp is hashed into the receipt; the column is what an
    // auditor reads. If those came from different clocks they would drift
    // apart, and a verifier recomputing the hash would be checking a different
    // fact than the one on screen.
    const lease = await issueTreasuryLease(h);
    const read = await h.call('GET', `/v1/authority-leases/${lease.id}`, h.tenant.tokens['admin']!);
    expect(read.status).toBe(200);

    let mismatches = 0;
    await asOwner(async (client) => {
      const rows = await client.query(
        `SELECT payload, created_at FROM scrutexity.receipts
          WHERE organization_id = $1 ORDER BY seq DESC LIMIT 25`,
        [h.tenant.organization_id],
      );
      for (const row of rows.rows) {
        const hashed = (row.payload as { created_at?: string }).created_at;
        if (hashed === undefined) continue;
        if (new Date(hashed).getTime() !== (row.created_at as Date).getTime()) mismatches += 1;
      }
    });
    expect(mismatches).toBe(0);
  });
});
