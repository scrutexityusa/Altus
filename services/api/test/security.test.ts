import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { issueTreasuryLease, startHarness, wireRequest, ADMIN_URL, type Harness } from './harness.js';

/**
 * The attacks from Section 23 and 29, run against the real service.
 *
 * Each test is written from the attacker's point of view: what would I try,
 * and what must the platform do about it? A test here that starts passing for
 * the wrong reason is worse than no test, so every one of them asserts the
 * specific refusal, not merely "not 200".
 */

let h: Harness;
let lease: { id: string; expires_at: string };
let delegatedLease: { id: string };

beforeAll(async () => {
  h = await startHarness();
  lease = await issueTreasuryLease(h);

  const delegation = await h.call('POST', '/v1/delegations', h.tenant.tokens['treasury_agent']!, {
    issuer_agent_id: h.tenant.agents['treasury'],
    delegate_agent_id: 'verification-agent',
    parent_lease_id: lease.id,
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
  delegatedLease = delegation.body.child_lease;
}, 60_000);

afterAll(async () => {
  await h?.close();
});

async function asOwner(fn: (client: pg.Client) => Promise<void>, orgId = h.tenant.organization_id) {
  const client = new pg.Client({ connectionString: ADMIN_URL });
  await client.connect();
  try {
    await client.query('SELECT set_config($1,$2,false)', ['scrutexity.org_id', orgId]);
    await fn(client);
  } finally {
    await client.end();
  }
}

describe('unauthenticated and malformed credentials', () => {
  it('refuses a request with no credential', async () => {
    const response = await h.call('POST', '/v1/authorization/evaluate', null, wireRequest());
    expect(response.status).toBe(401);
  });

  it('refuses a well-formed token that does not exist', async () => {
    const response = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      `scr_${'a'.repeat(16)}.${'B'.repeat(43)}`,
      wireRequest(),
    );
    expect(response.status).toBe(401);
  });

  it('refuses a token whose prefix is right and whose secret is wrong', async () => {
    const real = h.tenant.tokens['treasury_agent']!;
    const forged = `${real.split('.')[0]}.${'Z'.repeat(43)}`;
    const response = await h.call('POST', '/v1/authorization/evaluate', forged, wireRequest());
    expect(response.status).toBe(401);
  });

  it('refuses a revoked credential', async () => {
    const token = h.other.tokens['fraud_engine']!;
    await asOwner(async (client) => {
      await client.query(
        `UPDATE scrutexity.api_credentials SET status = 'REVOKED'
          WHERE token_prefix = $1`,
        [token.slice(4).split('.')[0]],
      );
    }, h.other.organization_id);
    const response = await h.call('POST', '/v1/signals', token, {
      subject: { type: 'agent', id: h.other.agents['treasury'] },
      signal_type: 'fraud_risk',
      value: '0.5',
      source: 'x',
      ttl_seconds: 60,
    });
    expect(response.status).toBe(401);
  });
});

describe('tenant isolation', () => {
  it('cannot read another tenant agent by id', async () => {
    const response = await h.call(
      'GET',
      `/v1/agents/${h.other.agents['treasury']}`,
      h.tenant.tokens['admin']!,
    );
    expect(response.status).toBe(404);
  });

  it('cannot authorize an agent belonging to another tenant', async () => {
    const response = await h.call('POST', '/v1/authorization/evaluate', h.tenant.tokens['admin']!, {
      ...wireRequest(),
      agent_id: h.other.agents['treasury'],
    });
    expect(response.status).toBe(404);
  });

  it('cannot issue authority into another tenant', async () => {
    const response = await h.call('POST', '/v1/authority-leases', h.tenant.tokens['admin']!, {
      agent_id: h.other.agents['treasury'],
      grant: { actions: ['wire.execute'], resources: { bank_account: ['*'] }, constraints: {} },
      ttl_seconds: 600,
    });
    expect(response.status).toBe(404);
  });

  it('cannot read another tenant decision or its explanation', async () => {
    const otherLease = await issueTreasuryLease(h, h.other);
    expect(otherLease.id).toBeTruthy();
    const decision = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.other.tokens['treasury_agent']!,
      wireRequest({ nonce: 'x-tenant-1' }),
    );
    expect(decision.body.decision).toBe('ALLOW');

    const crossRead = await h.call(
      'GET',
      `/v1/authorization-decisions/${decision.body.decision_id}`,
      h.tenant.tokens['admin']!,
    );
    expect(crossRead.status).toBe(404);
  });

  it('cannot read or verify another tenant receipt', async () => {
    const decision = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.other.tokens['treasury_agent']!,
      wireRequest({ nonce: 'x-tenant-2' }),
    );
    const read = await h.call(
      'GET',
      `/v1/receipts/${decision.body.receipt_id}`,
      h.tenant.tokens['admin']!,
    );
    expect(read.status).toBe(404);
    const verify = await h.call(
      'POST',
      `/v1/receipts/${decision.body.receipt_id}/verify`,
      h.tenant.tokens['admin']!,
      {},
    );
    expect(verify.status).toBe(404);
  });

  it('keeps each tenant evidence chain independent', async () => {
    const a = await h.call('POST', '/v1/authorization/evaluate', h.tenant.tokens['treasury_agent']!, wireRequest({ nonce: 'chain-t1' }));
    const b = await h.call('POST', '/v1/authorization/evaluate', h.other.tokens['treasury_agent']!, wireRequest({ nonce: 'chain-t2' }));
    const first = await h.call('GET', `/v1/receipts/${a.body.receipt_id}`, h.tenant.tokens['admin']!);
    const second = await h.call('GET', `/v1/receipts/${b.body.receipt_id}`, h.other.tokens['admin']!);
    // Sequence numbers advance independently: neither tenant learns the other's
    // decision rate from its own chain.
    expect(first.body.receipt.organization_id).toBe(h.tenant.organization_id);
    expect(second.body.receipt.organization_id).toBe(h.other.organization_id);
    expect(first.body.receipt.hash).not.toBe(second.body.receipt.previous_hash);
  });

  it('refuses at the database layer even when the application is bypassed', async () => {
    // Directly as the application role, with the wrong tenant set. This is the
    // last line of defence, and it is the one that holds if a handler forgets.
    const client = new pg.Client({
      connectionString:
        process.env['DATABASE_URL'] ?? 'postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity',
    });
    await client.connect();
    try {
      await client.query('SELECT set_config($1,$2,false)', [
        'scrutexity.org_id',
        h.tenant.organization_id,
      ]);
      const visible = await client.query('SELECT id FROM scrutexity.agents WHERE id = $1', [
        h.other.agents['treasury'],
      ]);
      expect(visible.rowCount).toBe(0);

      const anyAgent = await client.query('SELECT organization_id FROM scrutexity.agents');
      expect(new Set(anyAgent.rows.map((r) => r.organization_id))).toEqual(
        new Set([h.tenant.organization_id]),
      );
    } finally {
      await client.end();
    }
  });
});

describe('privilege escalation by an agent', () => {
  it('cannot issue itself authority', async () => {
    const response = await h.call('POST', '/v1/authority-leases', h.tenant.tokens['treasury_agent']!, {
      agent_id: 'treasury-agent',
      grant: { actions: ['*'], resources: { bank_account: ['*'] }, constraints: {} },
      ttl_seconds: 3600,
    });
    expect(response.status).toBe(403);
  });

  it('cannot author or activate policy', async () => {
    const response = await h.call('POST', '/v1/policy-versions', h.tenant.tokens['treasury_agent']!, {
      document: { apiVersion: 'scrutexity.dev/policy/v1' },
    });
    expect(response.status).toBe(403);
  });

  it('cannot approve an escalation, even holding a credential that could', async () => {
    const escalated = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'sec-self-approve', context: { ...wireRequest().context, amount: '250000.00' } }),
    );
    const attempt = await h.call('POST', '/v1/approvals', h.tenant.tokens['treasury_agent']!, {
      approval_request_id: escalated.body.approval_request_id,
      vote: 'APPROVED',
    });
    expect(attempt.status).toBe(403);
  });

  it('cannot authorize on behalf of a different agent (confused deputy)', async () => {
    const response = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['verification_agent']!,
      wireRequest({ agent_id: 'treasury-agent', nonce: 'sec-deputy-1' }),
    );
    expect(response.status).toBe(403);
  });

  it('cannot execute against another agent decision', async () => {
    const allowed = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'sec-deputy-2' }),
    );
    const stolen = await h.call('POST', '/v1/executions', h.tenant.tokens['verification_agent']!, {
      decision_id: allowed.body.decision_id,
      status: 'SUCCEEDED',
    });
    expect(stolen.status).toBe(403);
  });

  it('cannot delegate authority it does not hold', async () => {
    const response = await h.call('POST', '/v1/delegations', h.tenant.tokens['verification_agent']!, {
      issuer_agent_id: h.tenant.agents['treasury'],
      delegate_agent_id: 'verification-agent',
      parent_lease_id: lease.id,
      grant: {
        actions: ['counterparty.read'],
        resources: { counterparty: ['cp_100'] },
        constraints: {
          max_amount: { currency: 'USD', amountMinor: '0' },
          currencies: ['USD'],
          allowed_counterparties: ['cp_100'],
        },
      },
      ttl_seconds: 300,
    });
    expect(response.status).toBe(403);
  });
});

describe('forged and overreaching delegation', () => {
  const widen = (grant: Record<string, unknown>) =>
    h.call('POST', '/v1/delegations', h.tenant.tokens['treasury_agent']!, {
      issuer_agent_id: h.tenant.agents['treasury'],
      delegate_agent_id: 'verification-agent',
      parent_lease_id: lease.id,
      grant,
      ttl_seconds: 300,
    });

  it('refuses a raised amount ceiling', async () => {
    const response = await widen({
      actions: ['counterparty.read'],
      resources: { counterparty: ['cp_100'] },
      constraints: {
        max_amount: { currency: 'USD', amountMinor: '999999999' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    });
    expect(response.status).toBe(422);
    expect(response.body.error.reason_code).toBe('DELEGATION_EXCEEDS_PARENT');
  });

  it('refuses a dropped constraint', async () => {
    const response = await widen({
      actions: ['counterparty.read'],
      resources: { counterparty: ['cp_100'] },
      constraints: {},
    });
    expect(response.body.error.reason_code).toBe('DELEGATION_EXCEEDS_PARENT');
  });

  it('refuses a widened resource claim', async () => {
    const response = await widen({
      actions: ['counterparty.read'],
      resources: { counterparty: ['*'] },
      constraints: {
        max_amount: { currency: 'USD', amountMinor: '0' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    });
    expect(response.body.error.reason_code).toBe('DELEGATION_EXCEEDS_PARENT');
  });

  it('refuses a resource type the parent never held', async () => {
    const response = await widen({
      actions: ['counterparty.read'],
      resources: { counterparty: ['cp_100'], ledger: ['*'] },
      constraints: {
        max_amount: { currency: 'USD', amountMinor: '0' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    });
    expect(response.body.error.reason_code).toBe('DELEGATION_EXCEEDS_PARENT');
  });

  it('refuses delegating a non-delegable action however narrow the ask', async () => {
    const response = await widen({
      actions: ['wire.execute'],
      resources: { bank_account: ['acct_001'] },
      constraints: {
        max_amount: { currency: 'USD', amountMinor: '1' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    });
    expect(response.body.error.reason_code).toBe('ACTION_NOT_DELEGABLE');
  });

  it('blocks the delegated agent from acting outside its remit', async () => {
    const response = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['verification_agent']!,
      {
        agent_id: 'verification-agent',
        action: 'wire.execute',
        resource: { type: 'bank_account', id: 'acct_001' },
        context: { amount: '1.00', currency: 'USD', counterparty_id: 'cp_100' },
      },
    );
    expect(response.body.decision).toBe('DENY');
    expect(response.body.reason_code).toBe('ACTION_NOT_IN_AUTHORITY');
    expect(response.body.approval_requirement).toBeNull();
  });

  it('blocks a resource the delegation did not include', async () => {
    const response = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['verification_agent']!,
      {
        agent_id: 'verification-agent',
        action: 'counterparty.read',
        resource: { type: 'counterparty', id: 'cp_102' },
        context: { counterparty_id: 'cp_102' },
      },
    );
    expect(response.body.decision).toBe('DENY');
    expect(response.body.reason_code).toBe('RESOURCE_NOT_IN_AUTHORITY');
  });
});

describe('expired and revoked authority', () => {
  it('refuses an expired lease', async () => {
    const shortLease = await issueTreasuryLease(h, h.tenant, { ttl_seconds: 60 });
    await asOwner(async (client) => {
      await client.query(
        `UPDATE scrutexity.authority_leases
            SET issued_at = now() - interval '2 hours', expires_at = now() - interval '1 second'
          WHERE id = $1`,
        [shortLease.id],
      );
    });
    const response = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ authority_lease_id: shortLease.id, nonce: 'sec-expired-1' }),
    );
    expect(response.body.decision).toBe('DENY');
    expect(response.body.reason_code).toBe('AUTHORITY_EXPIRED');
  });

  it('kills a delegated lease the moment its parent is revoked', async () => {
    const parent = await issueTreasuryLease(h);
    const child = await h.call('POST', '/v1/delegations', h.tenant.tokens['treasury_agent']!, {
      issuer_agent_id: h.tenant.agents['treasury'],
      delegate_agent_id: 'verification-agent',
      parent_lease_id: parent.id,
      grant: {
        actions: ['counterparty.read'],
        resources: { counterparty: ['cp_101'] },
        constraints: {
          max_amount: { currency: 'USD', amountMinor: '0' },
          currencies: ['USD'],
          allowed_counterparties: ['cp_101'],
        },
      },
      ttl_seconds: 600,
    });
    expect(child.status).toBe(201);

    const before = await h.call('POST', '/v1/authorization/evaluate', h.tenant.tokens['verification_agent']!, {
      agent_id: 'verification-agent',
      action: 'counterparty.read',
      resource: { type: 'counterparty', id: 'cp_101' },
      context: { counterparty_id: 'cp_101' },
      authority_lease_id: child.body.child_lease.id,
    });
    expect(before.body.decision).toBe('ALLOW');

    await h.call('POST', `/v1/authority-leases/${parent.id}/revoke`, h.tenant.tokens['admin']!, {
      reason: 'security test',
    });

    const after = await h.call('POST', '/v1/authorization/evaluate', h.tenant.tokens['verification_agent']!, {
      agent_id: 'verification-agent',
      action: 'counterparty.read',
      resource: { type: 'counterparty', id: 'cp_101' },
      context: { counterparty_id: 'cp_101' },
      authority_lease_id: child.body.child_lease.id,
    });
    expect(after.body.decision).toBe('DENY');
    expect(after.body.reason_code).toBe('AUTHORITY_REVOKED');
  });

  it('refuses to delegate from a revoked lease', async () => {
    const parent = await issueTreasuryLease(h);
    await h.call('POST', `/v1/authority-leases/${parent.id}/revoke`, h.tenant.tokens['admin']!, {
      reason: 'security test',
    });
    const response = await h.call('POST', '/v1/delegations', h.tenant.tokens['treasury_agent']!, {
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
      ttl_seconds: 300,
    });
    expect(response.status).toBe(409);
  });
});

describe('replay', () => {
  it('refuses a reused authorization nonce', async () => {
    const body = wireRequest({ nonce: 'sec-replay-nonce-1' });
    const first = await h.call('POST', '/v1/authorization/evaluate', h.tenant.tokens['treasury_agent']!, body);
    expect(first.status).toBe(200);
    const second = await h.call('POST', '/v1/authorization/evaluate', h.tenant.tokens['treasury_agent']!, body);
    expect(second.status).toBe(409);
    expect(second.body.error.code).toBe('REPLAY_DETECTED');
  });

  it('refuses a second execution against the same grant', async () => {
    const allowed = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'sec-replay-exec-1' }),
    );
    await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: allowed.body.decision_id,
      status: 'SUCCEEDED',
    });
    const replay = await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: allowed.body.decision_id,
      status: 'SUCCEEDED',
    });
    expect(replay.body.error.code).toBe('REPLAY_DETECTED');
  });

  it('refuses an expired execution grant', async () => {
    const allowed = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'sec-grant-expiry-1' }),
    );
    await asOwner(async (client) => {
      // authorization_decisions is append-only by trigger, so the expiry is
      // moved the only way anything can move it: by time. Simulated here by
      // rewriting the row as the owner with the trigger temporarily off, which
      // is itself a check that the trigger exists.
      await client.query('ALTER TABLE scrutexity.authorization_decisions DISABLE TRIGGER authorization_decisions_append_only');
      await client.query(
        `UPDATE scrutexity.authorization_decisions SET expires_at = now() - interval '1 second' WHERE id = $1`,
        [allowed.body.decision_id],
      );
      await client.query('ALTER TABLE scrutexity.authorization_decisions ENABLE TRIGGER authorization_decisions_append_only');
    });
    const late = await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: allowed.body.decision_id,
      status: 'SUCCEEDED',
    });
    expect(late.status).toBe(403);
    expect(late.body.error.code).toBe('AUTHORITY_EXPIRED');
  });
});

describe('evidence integrity', () => {
  it('detects a decision receipt whose payload was altered in the database', async () => {
    const allowed = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'sec-tamper-1' }),
    );

    // The append-only trigger must refuse this outright.
    let blocked = false;
    await asOwner(async (client) => {
      try {
        await client.query(
          `UPDATE scrutexity.receipts SET payload = '{"tampered":true}'::jsonb WHERE id = $1`,
          [allowed.body.receipt_id],
        );
      } catch (error) {
        blocked = (error as { code?: string }).code === '42501';
      }
    });
    expect(blocked, 'receipts must be append-only at the database layer').toBe(true);

    // Force the write past the trigger, as a compromised operator would, and
    // confirm verification still catches it.
    await asOwner(async (client) => {
      await client.query('ALTER TABLE scrutexity.receipts DISABLE TRIGGER receipts_append_only');
      await client.query(
        `UPDATE scrutexity.receipts SET payload = '{"decision":"ALLOW","tampered":true}'::jsonb WHERE id = $1`,
        [allowed.body.receipt_id],
      );
      await client.query('ALTER TABLE scrutexity.receipts ENABLE TRIGGER receipts_append_only');
    });

    const verification = await h.call(
      'POST',
      `/v1/receipts/${allowed.body.receipt_id}/verify`,
      h.tenant.tokens['admin']!,
      {},
    );
    expect(verification.body.integrity).toBe('COMPROMISED');
    expect(
      verification.body.receipt_verification.checks.find(
        (c: { check: string }) => c.check === 'PAYLOAD_HASH',
      ).passed,
    ).toBe(false);
    expect(verification.body.chain_verification.intact).toBe(false);
  });

  it('refuses to evaluate against a policy version that fails its integrity check', async () => {
    let original: string | undefined;
    await asOwner(async (client) => {
      const before = await client.query('SELECT content FROM scrutexity.policy_versions WHERE id = $1', [
        h.tenant.policy_version_id,
      ]);
      original = JSON.stringify(before.rows[0].content);
      await client.query(
        `UPDATE scrutexity.policy_versions
            SET content = jsonb_set(content, '{metadata,title}', '"Silently edited"')
          WHERE id = $1`,
        [h.tenant.policy_version_id],
      );
    });

    try {
      const response = await h.call(
        'POST',
        '/v1/authorization/evaluate',
        h.tenant.tokens['treasury_agent']!,
        wireRequest({ nonce: 'sec-policy-tamper-1' }),
      );
      expect(response.status).toBe(503);
      expect(response.body.error.code).toBe('POLICY_UNAVAILABLE');
      // The cached parse must not paper over it on the next request either.
      const again = await h.call(
        'POST',
        '/v1/authorization/evaluate',
        h.tenant.tokens['treasury_agent']!,
        wireRequest({ nonce: 'sec-policy-tamper-2' }),
      );
      expect(again.status).toBe(503);
    } finally {
      await asOwner(async (client) => {
        await client.query('UPDATE scrutexity.policy_versions SET content = $2::jsonb WHERE id = $1', [
          h.tenant.policy_version_id,
          original,
        ]);
      });
    }

    const restored = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'sec-policy-restored-1' }),
    );
    expect(restored.status).toBe(200);
  });
});

describe('hostile input', () => {
  it('refuses a signal dated in the future', async () => {
    const response = await h.call('POST', '/v1/signals', h.other.tokens['admin']!, {
      subject: { type: 'agent', id: h.other.agents['treasury'] },
      signal_type: 'fraud_risk',
      value: '0.99',
      source: 'attacker',
      ttl_seconds: 86_400,
      issued_at: new Date(Date.now() + 3_600_000).toISOString(),
    });
    expect(response.status).toBe(400);
  });

  it('refuses a signal TTL beyond the platform maximum', async () => {
    const response = await h.call('POST', '/v1/signals', h.other.tokens['admin']!, {
      subject: { type: 'agent', id: h.other.agents['treasury'] },
      signal_type: 'fraud_risk',
      value: '0.99',
      source: 'attacker',
      ttl_seconds: 31_536_000,
    });
    expect(response.status).toBe(400);
  });

  it('refuses an unknown field rather than ignoring it', async () => {
    const response = await h.call('POST', '/v1/authorization/evaluate', h.tenant.tokens['treasury_agent']!, {
      ...wireRequest(),
      decision: 'ALLOW',
    });
    expect(response.status).toBe(400);
  });

  it('refuses an oversized payload', async () => {
    const response = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ context: { ...wireRequest().context, padding: 'x'.repeat(300_000) } }),
    );
    expect(response.status).toBe(413);
  });

  it('does not let a policy selector escape into the host language', async () => {
    // The predicate language has no expression evaluation to escape from;
    // hostile context values are compared, never executed.
    const response = await h.call('POST', '/v1/authorization/evaluate', h.tenant.tokens['treasury_agent']!, {
      ...wireRequest({ nonce: 'sec-injection-1' }),
      context: {
        amount: '100.00',
        currency: 'USD',
        counterparty_id: "cp_100'; DROP TABLE scrutexity.receipts; --",
        destination_country: 'US',
      },
    });
    expect([200, 400]).toContain(response.status);
    const stillThere = await h.call('GET', '/v1/overview', h.tenant.tokens['admin']!);
    expect(stillThere.status).toBe(200);
  });

  it('does not leak internal detail on a generic failure', async () => {
    const response = await h.call(
      'GET',
      `/v1/agents/${h.other.agents['treasury']}`,
      h.tenant.tokens['admin']!,
    );
    expect(JSON.stringify(response.body)).not.toContain(h.other.organization_id);
    expect(response.body.error.message).toBe('Not found.');
  });
});
