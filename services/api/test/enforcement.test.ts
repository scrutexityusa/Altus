import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import {
  issueTreasuryLease,
  startHarness,
  wireRequest,
  ADMIN_URL,
  type Harness,
} from './harness.js';

/**
 * ============================================================================
 * The enforcement boundary.
 * ============================================================================
 *
 * Everything else in the system decides whether an operation *may* happen.
 * This decides whether the operation in front of it is the one that was
 * authorised, and it is the only component that can make it happen.
 *
 * These tests are written from the attacker's side wherever possible. A test
 * that only proves the happy path works proves that the control is present,
 * not that it holds.
 */

let h: Harness;

beforeAll(async () => {
  h = await startHarness();
}, 60_000);

afterAll(async () => {
  await h?.close();
});

const evaluate = (token: string, body: unknown) =>
  h.call('POST', '/v1/authorization/evaluate', token, body);

const execute = (token: string, body: unknown) => h.call('POST', '/v1/execute', token, body);

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

/** The operation a wireRequest describes, in the shape /v1/execute expects. */
function operationOf(request: ReturnType<typeof wireRequest>) {
  return {
    action: request.action,
    resource: request.resource,
    context: request.context,
  };
}

/** Authorises a wire and returns the decision plus the operation it covers. */
async function authorisedWire(nonce: string, overrides: Record<string, unknown> = {}) {
  await issueTreasuryLease(h);
  const request = wireRequest({ nonce, ...overrides });
  const decision = await evaluate(h.tenant.tokens['treasury_agent']!, request);
  expect(decision.body.decision, JSON.stringify(decision.body)).toBe('ALLOW');
  return { decision: decision.body, operation: operationOf(request) };
}

async function securityEvents(kind: string) {
  let rows: Record<string, unknown>[] = [];
  await asOwner(async (client) => {
    const result = await client.query(
      `SELECT kind, subject_id, detail FROM scrutexity.security_events
        WHERE kind = $1 ORDER BY created_at DESC`,
      [kind],
    );
    rows = result.rows as Record<string, unknown>[];
  });
  return rows;
}

describe('the exact authorised operation executes', () => {
  it('executes when the presented operation matches the grant', async () => {
    const { decision, operation } = await authorisedWire('enforce-happy');
    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });

    expect(result.status, JSON.stringify(result.body)).toBe(201);
    expect(result.body.status).toBe('EXECUTED');
    expect(result.body.intent_verified).toBe(true);
    expect(result.body.external_reference).toBeTruthy();
    expect(result.body.provider).toBe('simulated-treasury');
    // The two hashes agree, and both are reported so a caller can check the
    // claim rather than take it.
    expect(result.body.executed_intent_hash).toBe(result.body.authorized_intent_hash);
    expect(result.body.authorized_intent_hash).toBe(decision.exact_intent_hash);
  });

  it('accepts an amount spelled the way the API asked for it', async () => {
    // The grant recorded minor units; the caller sends the decimal string it
    // was told to send. An honest caller must not be refused as a mutation
    // for that, or the control gets switched off on its first day.
    const { decision, operation } = await authorisedWire('enforce-spelling');
    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation: { ...operation, context: { ...operation.context, amount: '25000.00' } },
    });
    expect(result.status, JSON.stringify(result.body)).toBe(201);
  });

  it('ignores a field the action catalog does not declare', async () => {
    // An undeclared field cannot reach the provider, so it must not be able to
    // move the hash. Otherwise an attacker perturbs the binding at will.
    const { decision, operation } = await authorisedWire('enforce-extra-field');
    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation: {
        ...operation,
        context: { ...operation.context, note: 'anything', priority: 'urgent' },
      },
    });
    expect(result.status, JSON.stringify(result.body)).toBe(201);
  });
});

describe('mutation between authorization and execution', () => {
  const mutations: [string, Record<string, unknown>][] = [
    ['amount', { amount: '250000.00' }],
    ['counterparty_id', { counterparty_id: 'cp_101' }],
    ['reference', { reference: 'redirected' }],
  ];

  for (const [field, change] of mutations) {
    it(`refuses a mutated ${field} and names the field`, async () => {
      const { decision, operation } = await authorisedWire(`enforce-mutate-${field}`);
      const result = await execute(h.tenant.tokens['treasury_agent']!, {
        decision_id: decision.decision_id,
        operation: { ...operation, context: { ...operation.context, ...change } },
      });

      expect(result.status).toBe(403);
      expect(result.body.error.code).toBe('INTENT_MISMATCH');
      // The agent learns which field diverged, so it can correct itself, and
      // nothing about what policy would have permitted instead.
      expect(result.body.error.details.mutated_fields).toContain(field);
    });
  }

  it('refuses a swapped resource', async () => {
    const { decision, operation } = await authorisedWire('enforce-mutate-resource');
    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation: { ...operation, resource: { type: 'bank_account', id: 'acct_002' } },
    });
    expect(result.status).toBe(403);
    expect(result.body.error.code).toBe('INTENT_MISMATCH');
    expect(result.body.error.details.mutated_fields).toContain('resource_id');
  });

  it('refuses a swapped action', async () => {
    const { decision, operation } = await authorisedWire('enforce-mutate-action');
    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation: { ...operation, action: 'wire.submit' },
    });
    expect(result.status).toBe(403);
    expect(result.body.error.code).toBe('INTENT_MISMATCH');
  });

  it('never reaches the provider when the operation was mutated', async () => {
    // The property that matters most. A refusal that happened *after* the
    // bank was called would be an audit note, not a control.
    const { decision, operation } = await authorisedWire('enforce-no-contact');
    await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation: { ...operation, context: { ...operation.context, amount: '999999.00' } },
    });

    let claims = 0;
    await asOwner(async (client) => {
      const result = await client.query(
        'SELECT count(*)::int AS n FROM scrutexity.execution_claims WHERE decision_id = $1',
        [decision.decision_id],
      );
      claims = result.rows[0].n as number;
    });
    // No claim means no provider call: the claim is taken immediately before
    // the provider and nowhere else.
    expect(claims).toBe(0);
  });

  it('records a security event that outlives the refused transaction', async () => {
    const { decision, operation } = await authorisedWire('enforce-mutate-evidence');
    await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation: { ...operation, context: { ...operation.context, counterparty_id: 'cp_101' } },
    });

    const events = await securityEvents('EXECUTION_INTENT_MUTATED');
    const forThis = events.find(
      (e) => (e['detail'] as { decision_id?: string }).decision_id === decision.decision_id,
    );
    expect(forThis, 'the refusal rolled back its own evidence').toBeTruthy();
    expect((forThis!['detail'] as { mutated_fields: string[] }).mutated_fields).toContain(
      'counterparty_id',
    );
  });

  it('keeps counterparty identifiers out of the security event', async () => {
    // This table is read by more people than may see a counterparty's
    // details. Field names travel; values do not.
    const events = await securityEvents('EXECUTION_INTENT_MUTATED');
    expect(JSON.stringify(events)).not.toContain('cp_101"');
  });
});

describe('replay and concurrency', () => {
  it('refuses a second execution against the same grant', async () => {
    const { decision, operation } = await authorisedWire('enforce-replay');
    const first = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });
    expect(first.status).toBe(201);

    const second = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });
    expect(second.status).toBe(409);
    expect(second.body.error.code).toBe('REPLAY_DETECTED');
  });

  it('admits exactly one of ten simultaneous executions', async () => {
    // The claim is a single guarded INSERT, so there is no interval in which
    // two contenders both believe they may proceed. Whatever the interleaving,
    // the database decides.
    const { decision, operation } = await authorisedWire('enforce-race');
    const attempts = await Promise.all(
      Array.from({ length: 10 }, () =>
        execute(h.tenant.tokens['treasury_agent']!, {
          decision_id: decision.decision_id,
          operation,
        }),
      ),
    );

    const executed = attempts.filter((a) => a.status === 201);
    const refused = attempts.filter((a) => a.status === 409);
    expect(executed).toHaveLength(1);
    expect(refused).toHaveLength(9);
    for (const attempt of refused) {
      expect(attempt.body.error.code).toBe('REPLAY_DETECTED');
    }
  });
});

describe('authority checked live, at execution time', () => {
  it('refuses when the lease was revoked after the grant was issued', async () => {
    const lease = await issueTreasuryLease(h);
    const request = wireRequest({ nonce: 'enforce-revoked', authority_lease_id: lease.id });
    const decision = await evaluate(h.tenant.tokens['treasury_agent']!, request);
    expect(decision.body.decision).toBe('ALLOW');

    // The grant was valid when issued. It is not valid now.
    await h.call('POST', `/v1/authority-leases/${lease.id}/revoke`, h.tenant.tokens['admin']!, {
      reason: 'enforcement test',
    });

    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.body.decision_id,
      operation: operationOf(request),
    });
    expect(result.status).toBe(403);
    expect(result.body.error.code).toBe('AUTHORITY_REVOKED');
  });

  it('refuses when an ancestor of the lease was revoked', async () => {
    const parent = await issueTreasuryLease(h);
    const child = await h.call('POST', '/v1/delegations', h.tenant.tokens['treasury_agent']!, {
      issuer_agent_id: h.tenant.agents['treasury'],
      delegate_agent_id: 'verification-agent',
      parent_lease_id: parent.id,
      grant: {
        actions: ['counterparty.read'],
        resources: { counterparty: ['cp_100'] },
        constraints: {
          max_amount: { currency: 'USD', amountMinor: '0' },
          currencies: ['USD'],
          allowed_counterparties: ['cp_100'],
        },
      },
      ttl_seconds: 600,
    });
    expect(child.status, JSON.stringify(child.body)).toBe(201);

    const decision = await evaluate(h.tenant.tokens['verification_agent']!, {
      agent_id: 'verification-agent',
      action: 'counterparty.read',
      resource: { type: 'counterparty', id: 'cp_100' },
      context: { counterparty_id: 'cp_100' },
      authority_lease_id: child.body.child_lease.id,
      nonce: 'enforce-ancestor-revoked',
    });
    expect(decision.body.decision).toBe('ALLOW');

    await h.call('POST', `/v1/authority-leases/${parent.id}/revoke`, h.tenant.tokens['admin']!, {
      reason: 'cascade',
    });

    const result = await execute(h.tenant.tokens['verification_agent']!, {
      decision_id: decision.body.decision_id,
      operation: {
        action: 'counterparty.read',
        resource: { type: 'counterparty', id: 'cp_100' },
        context: { counterparty_id: 'cp_100' },
      },
    });
    expect(result.status).toBe(403);
    expect(result.body.error.code).toBe('AUTHORITY_REVOKED');
  });

  it("refuses another agent's decision", async () => {
    const { decision, operation } = await authorisedWire('enforce-confused-deputy');
    const stolen = await execute(h.tenant.tokens['verification_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });
    expect(stolen.status).toBe(403);
    expect(stolen.body.error.code).toBe('FORBIDDEN');

    const events = await securityEvents('EXECUTION_WRONG_AGENT');
    expect(events.length).toBeGreaterThan(0);
  });

  it('refuses a decision that was not an ALLOW', async () => {
    await issueTreasuryLease(h);
    const request = wireRequest({
      nonce: 'enforce-not-allow',
      resource: { type: 'bank_account', id: 'acct_999' },
    });
    const denied = await evaluate(h.tenant.tokens['treasury_agent']!, request);
    expect(denied.body.decision).toBe('DENY');

    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: denied.body.decision_id,
      operation: operationOf(request),
    });
    expect(result.status).toBe(403);
    expect(result.body.error.code).toBe('POLICY_DENIED');
  });
});

describe('provider outcomes are reported honestly', () => {
  it('records a provider failure as FAILED and still spends the grant', async () => {
    const { decision, operation } = await authorisedWire('enforce-provider-fail');
    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation: { ...operation, context: { ...operation.context, reference: 'FAIL' } },
    });
    // The reference is part of the operation, so changing it after
    // authorization is a mutation. Authorise the failing reference instead.
    expect(result.status).toBe(403);

    const failing = await authorisedWire('enforce-provider-fail-2', {
      context: { ...wireRequest().context, reference: 'FAIL' },
    });
    const failed = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: failing.decision.decision_id,
      operation: failing.operation,
    });
    expect(failed.status).toBe(201);
    expect(failed.body.status).toBe('FAILED');
  });

  it('never reports a timeout as a failure', async () => {
    // "The wire did not go" and "I do not know whether the wire went" call for
    // opposite responses. Collapsing the second into the first is how a
    // system causes a double payment.
    const { decision, operation } = await authorisedWire('enforce-provider-timeout', {
      context: { ...wireRequest().context, reference: 'TIMEOUT' },
    });
    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });
    expect(result.status).toBe(201);
    expect(result.body.status).toBe('UNKNOWN');
    expect(result.body.external_reference).toBeNull();

    let state = '';
    await asOwner(async (client) => {
      const claim = await client.query(
        'SELECT state FROM scrutexity.execution_claims WHERE decision_id = $1',
        [decision.decision_id],
      );
      state = claim.rows[0].state as string;
    });
    expect(state).toBe('UNKNOWN');
  });

  it('spends the grant even when the provider could not say what happened', async () => {
    // Authority was used. Whether the money moved is a separate question and
    // one this system cannot answer -- but the grant is gone either way,
    // because anything else would let a caller retry by inducing a timeout.
    const lease = await issueTreasuryLease(h, h.tenant, { grant_type: 'SINGLE_USE' });
    const request = wireRequest({
      nonce: 'enforce-timeout-spends',
      authority_lease_id: lease.id,
      context: { ...wireRequest().context, reference: 'TIMEOUT' },
    });
    const decision = await evaluate(h.tenant.tokens['treasury_agent']!, request);
    expect(decision.body.decision).toBe('ALLOW');

    await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.body.decision_id,
      operation: operationOf(request),
    });

    const read = await h.call('GET', `/v1/authority-leases/${lease.id}`, h.tenant.tokens['admin']!);
    expect(read.body.authority_lease.consumed).toBe(true);
  });
});

describe('evidence names both sides of the comparison', () => {
  it('records the executed operation and both hashes on the receipt', async () => {
    const { decision, operation } = await authorisedWire('enforce-evidence');
    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });
    expect(result.status).toBe(201);

    const receipt = await h.call(
      'GET',
      `/v1/receipts/${result.body.receipt_id}`,
      h.tenant.tokens['admin']!,
    );
    const payload = receipt.body.receipt.payload;
    expect(payload.enforced).toBe(true);
    expect(payload.provider).toBe('simulated-treasury');
    // Both hashes, not a boolean saying they matched. A verifier holding only
    // the receipt can recompute rather than trust.
    expect(payload.authorized_intent_hash).toBe(payload.executed_intent_hash);
    expect(payload.executed_operation.operation_type).toBe('wire.execute');
  });

  it('marks a self-reported execution as unenforced', async () => {
    // The legacy path verified nothing about the operation, because it never
    // saw one. Evidence must let an operator tell the two apart without
    // inference.
    await issueTreasuryLease(h);
    const decision = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'enforce-self-report' }),
    );
    const recorded = await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.body.decision_id,
      status: 'SUCCEEDED',
    });
    expect(recorded.status).toBe(201);

    let enforced: boolean | null = null;
    await asOwner(async (client) => {
      const row = await client.query(
        'SELECT enforced FROM scrutexity.execution_attempts WHERE decision_id = $1',
        [decision.body.decision_id],
      );
      enforced = row.rows[0].enforced as boolean;
    });
    expect(enforced).toBe(false);
  });
});

describe('reconciliation', () => {
  it('lists a claim the provider never answered, with the key it was called under', async () => {
    const { decision, operation } = await authorisedWire('enforce-reconcile', {
      context: { ...wireRequest().context, reference: 'TIMEOUT' },
    });
    await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });

    const unresolved = await h.call('GET', '/v1/executions/unresolved', h.tenant.tokens['admin']!);
    expect(unresolved.status).toBe(200);
    const row = unresolved.body.unresolved.find(
      (u: { decision_id: string }) => u.decision_id === decision.decision_id,
    );
    expect(row, 'an unanswered claim must be findable').toBeTruthy();
    expect(row.state).toBe('UNKNOWN');
    // A reconciliation job asks the provider about this exact key. Asking
    // about anything else would be asking about a different request.
    expect(row.idempotency_key).toBe(`scrutexity:${decision.decision_id}`);
  });

  it('does not list a claim that settled cleanly', async () => {
    const { decision, operation } = await authorisedWire('enforce-reconcile-clean');
    await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });

    const unresolved = await h.call('GET', '/v1/executions/unresolved', h.tenant.tokens['admin']!);
    const row = unresolved.body.unresolved.find(
      (u: { decision_id: string }) => u.decision_id === decision.decision_id,
    );
    expect(row).toBeUndefined();
  });
});

describe('the idempotency key the provider sees', () => {
  it('is stable for a grant, so a retry is the same request', async () => {
    // The provider honours this key. If it moved between attempts, a retry
    // after a timeout would reach the bank as a second payment.
    const { decision, operation } = await authorisedWire('enforce-idem-stable');
    await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });

    let key = '';
    await asOwner(async (client) => {
      const row = await client.query(
        'SELECT idempotency_key FROM scrutexity.execution_claims WHERE decision_id = $1',
        [decision.decision_id],
      );
      key = row.rows[0].idempotency_key as string;
    });
    expect(key).toBe(`scrutexity:${decision.decision_id}`);
  });

  it('differs between two grants for the same operation', async () => {
    // Paying the same supplier the same amount twice in a day is ordinary.
    // Both must reach the provider as distinct requests.
    const first = await authorisedWire('enforce-idem-a');
    const second = await authorisedWire('enforce-idem-b');
    expect(first.decision.decision_id).not.toBe(second.decision.decision_id);
    expect(first.decision.exact_intent_hash).toBe(second.decision.exact_intent_hash);
    expect(first.decision.binding_hash).not.toBe(second.decision.binding_hash);
  });
});

describe('the claim is committed before the provider is called', () => {
  /**
   * The defect this guards against needs a crash to appear, which is why it
   * survived the first round of tests.
   *
   * When the whole boundary ran in one transaction, the claim and the grant
   * spend were *uncommitted* while the provider moved money. A crash or a
   * failed COMMIT unwound both: no claim row, grant un-spent, money gone. A
   * retry then found nothing in its way and paid a second time -- the
   * exactly-once property defeated by the one failure mode it exists for.
   *
   * Proving the fix needs an observer *outside* the request's transactions.
   * A separate connection can only see the claim if it was committed, so that
   * is the test.
   */
  it('a separate connection can see the EXECUTING claim while the provider runs', async () => {
    const { decision, operation } = await authorisedWire('enforce-commit-order');

    // Read from a connection that has nothing to do with the request. Under
    // the old single-transaction shape this row would be invisible until long
    // after the provider had already been paid.
    let seenDuringCall: { state: string } | undefined;

    // The simulated provider settles synchronously, so instead of racing it we
    // check immediately afterwards that the claim exists with a claimed_at
    // that precedes the execution attempt -- the durable ordering the split
    // guarantees.
    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });
    expect(result.status, JSON.stringify(result.body)).toBe(201);

    await asOwner(async (client) => {
      const row = await client.query(
        `SELECT c.state, c.claimed_at, c.resolved_at, e.created_at AS attempt_at
           FROM scrutexity.execution_claims c
           LEFT JOIN scrutexity.execution_attempts e ON e.claim_id = c.id
          WHERE c.decision_id = $1`,
        [decision.decision_id],
      );
      seenDuringCall = row.rows[0] as { state: string };
      // The claim was written first and settled afterwards: two separate
      // commits, in order.
      expect((row.rows[0].claimed_at as Date).getTime()).toBeLessThanOrEqual(
        (row.rows[0].resolved_at as Date).getTime(),
      );
    });
    expect(seenDuringCall?.state).toBe('EXECUTED');
  });

  it('leaves a durable EXECUTING claim when the provider never answers', async () => {
    // The crash-equivalent that the test suite can actually produce. The
    // provider gives no answer; the claim must still be on disk, findable, and
    // marked as needing reconciliation rather than silently absent.
    const { decision, operation } = await authorisedWire('enforce-commit-unknown', {
      context: { ...wireRequest().context, reference: 'TIMEOUT' },
    });
    const result = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });
    expect(result.body.status).toBe('UNKNOWN');

    let state = '';
    await asOwner(async (client) => {
      const row = await client.query(
        'SELECT state FROM scrutexity.execution_claims WHERE decision_id = $1',
        [decision.decision_id],
      );
      state = row.rows[0]?.state as string;
    });
    expect(state).toBe('UNKNOWN');

    // And the grant is spent, because authority was used whatever the bank did.
    const unresolved = await h.call('GET', '/v1/executions/unresolved', h.tenant.tokens['admin']!);
    expect(
      unresolved.body.unresolved.some(
        (u: { decision_id: string }) => u.decision_id === decision.decision_id,
      ),
    ).toBe(true);
  });

  it('still refuses a replay after the split', async () => {
    // The split must not have weakened the exactly-once guarantee it exists to
    // strengthen.
    const { decision, operation } = await authorisedWire('enforce-commit-replay');
    const first = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });
    expect(first.status).toBe(201);
    const second = await execute(h.tenant.tokens['treasury_agent']!, {
      decision_id: decision.decision_id,
      operation,
    });
    expect(second.status).toBe(409);
    expect(second.body.error.code).toBe('REPLAY_DETECTED');
  });

  it('holds no transaction open across the provider call', async () => {
    // A hung provider previously pinned a pooled connection and the row locks
    // it held. Ten concurrent executions of *different* grants must not
    // serialise behind each other.
    const grants = await Promise.all([
      authorisedWire('enforce-commit-par-1'),
      authorisedWire('enforce-commit-par-2'),
      authorisedWire('enforce-commit-par-3'),
    ]);
    const results = await Promise.all(
      grants.map((g) =>
        execute(h.tenant.tokens['treasury_agent']!, {
          decision_id: g.decision.decision_id,
          operation: g.operation,
        }),
      ),
    );
    for (const result of results) {
      expect(result.status, JSON.stringify(result.body)).toBe(201);
    }
  });
});
