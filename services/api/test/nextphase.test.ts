import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { signSignalHmac, signalSigningPayload } from '@scrutexity/core';
import {
  issueTreasuryLease,
  startHarness,
  wireRequest,
  ADMIN_URL,
  type Harness,
} from './harness.js';

let h: Harness;

beforeAll(async () => {
  h = await startHarness();
}, 60_000);

afterAll(async () => {
  await h?.close();
});

const evaluate = (token: string, body: unknown) =>
  h.call('POST', '/v1/authorization/evaluate', token, body);

async function asOwner(fn: (client: pg.Client) => Promise<void>, orgId = h.tenant.organization_id) {
  const client = new pg.Client({
    connectionString: process.env['DATABASE_ADMIN_URL'] ?? ADMIN_URL,
  });
  await client.connect();
  try {
    await client.query('SELECT set_config($1,$2,false)', ['scrutexity.org_id', orgId]);
    await fn(client);
  } finally {
    await client.end();
  }
}

/** Issues a purpose-bound single-use grant covering the standard wire request. */
async function issueSingleUseGrant(purpose?: string) {
  const response = await h.call('POST', '/v1/authority-leases', h.tenant.tokens['admin']!, {
    agent_id: 'treasury-agent',
    grant: {
      actions: ['wire.execute'],
      resources: { bank_account: ['acct_001'] },
      constraints: {
        max_amount: { currency: 'USD', amountMinor: '5000000' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    },
    ttl_seconds: 3600,
    grant_type: 'SINGLE_USE',
    ...(purpose ? { purpose } : {}),
  });
  expect(response.status, JSON.stringify(response.body)).toBe(201);
  return response.body.authority_lease;
}

describe('single-use grants, exactly once', () => {
  it('authorizes once and refuses every later request', async () => {
    const grant = await issueSingleUseGrant();

    const first = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ authority_lease_id: grant.id, nonce: 'nextphase-su-first' }),
    );
    expect(first.body.decision).toBe('ALLOW');

    const second = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ authority_lease_id: grant.id, nonce: 'nextphase-su-second' }),
    );
    expect(second.body.decision).toBe('DENY');
    expect(second.body.reason_code).toBe('AUTHORITY_CONSUMED');
  });

  it('admits exactly one winner under concurrent requests', async () => {
    const grant = await issueSingleUseGrant();

    // Ten simultaneous attempts against one grant. Whatever the interleaving,
    // the database serialises the claim and exactly one may proceed.
    const attempts = await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        evaluate(
          h.tenant.tokens['treasury_agent']!,
          wireRequest({ authority_lease_id: grant.id, nonce: `nextphase-su-race-${index}` }),
        ),
      ),
    );

    const allowed = attempts.filter((a) => a.body?.decision === 'ALLOW');
    const refused = attempts.filter((a) => a.body?.decision === 'DENY');
    expect(allowed).toHaveLength(1);
    expect(refused.length + allowed.length).toBe(10);
    for (const denial of refused) {
      expect(denial.body.reason_code).toBe('AUTHORITY_CONSUMED');
    }
  });

  it('records the claim against the decision that won', async () => {
    const grant = await issueSingleUseGrant();
    const allowed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ authority_lease_id: grant.id, nonce: 'nextphase-su-claim' }),
    );
    const lease = await h.call(
      'GET',
      `/v1/authority-leases/${grant.id}`,
      h.tenant.tokens['admin']!,
    );
    expect(lease.body.authority_lease.claimed_by_decision_id).toBe(allowed.body.decision_id);
    expect(lease.body.authority_lease.consumed).toBe(false);
  });

  it('marks the grant spent once it is executed', async () => {
    const grant = await issueSingleUseGrant();
    const allowed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ authority_lease_id: grant.id, nonce: 'nextphase-su-exec' }),
    );
    const execution = await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: allowed.body.decision_id,
      status: 'SUCCEEDED',
    });
    expect(execution.status).toBe(201);

    const lease = await h.call(
      'GET',
      `/v1/authority-leases/${grant.id}`,
      h.tenant.tokens['admin']!,
    );
    expect(lease.body.authority_lease.consumed).toBe(true);
    expect(lease.body.authority_lease.used_at).not.toBeNull();
  });

  it('binds a purpose-bound grant to the intent it was issued for', async () => {
    const grant = await issueSingleUseGrant('reconcile_cash_position');
    const mismatched = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        authority_lease_id: grant.id,
        declared_intent: 'execute_wire_transfers',
        nonce: 'nextphase-su-purpose',
      }),
    );
    expect(mismatched.body.decision).toBe('DENY');
    expect(mismatched.body.reason_code).toBe('INTENT_MISMATCH');
    expect(mismatched.body.intent_evaluation.reason).toBe('purpose_mismatch');
  });
});

describe('approval-to-execution binding (TOCTOU)', () => {
  it('refuses execution when a signal arrives after approval', async () => {
    await issueTreasuryLease(h);

    const escalated = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'nextphase-toctou-1',
        context: { ...wireRequest().context, amount: '250000.00' },
      }),
    );
    expect(escalated.body.decision).toBe('ESCALATE');

    const approval = await h.call('POST', '/v1/approvals', h.tenant.tokens['treasurer']!, {
      approval_request_id: escalated.body.approval_request_id,
      vote: 'APPROVED',
    });
    expect(approval.body.decision.decision).toBe('ALLOW');

    // The risk picture moves between the human saying yes and the money moving.
    const ingested = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'fraud_risk',
      value: '0.97',
      source: 'external_fraud_engine',
      ttl_seconds: 600,
    });
    expect(ingested.status).toBe(201);

    const execution = await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: approval.body.decision.decision_id,
      status: 'SUCCEEDED',
    });
    expect(execution.status).toBe(409);
    expect(execution.body.error.code).toBe('APPROVAL_CONTEXT_MISMATCH');

    // Clean up so later cases see an unclouded risk picture.
    await asOwner(async (client) => {
      await client.query(`UPDATE scrutexity.risk_signals SET superseded_at = now() WHERE id = $1`, [
        ingested.body.signal.id,
      ]);
    });
  });

  it('permits execution when nothing changed', async () => {
    await issueTreasuryLease(h);
    const allowed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'nextphase-toctou-2' }),
    );
    expect(allowed.body.decision).toBe('ALLOW');
    const execution = await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: allowed.body.decision_id,
      status: 'SUCCEEDED',
    });
    expect(execution.status).toBe(201);
  });

  it('reports a plain authorization differently from an approved one', async () => {
    await issueTreasuryLease(h);
    const allowed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'nextphase-toctou-3' }),
    );

    const ingested = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'counterparty_risk',
      value: '0.2',
      source: 'external_fraud_engine',
      ttl_seconds: 600,
    });
    expect(ingested.status).toBe(201);

    const execution = await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: allowed.body.decision_id,
      status: 'SUCCEEDED',
    });
    // No human was involved, so this is CONTEXT_CHANGED rather than
    // APPROVAL_CONTEXT_MISMATCH -- the same control, named for what happened.
    expect(execution.status).toBe(409);
    expect(execution.body.error.code).toBe('CONTEXT_CHANGED');

    await asOwner(async (client) => {
      await client.query(`UPDATE scrutexity.risk_signals SET superseded_at = now() WHERE id = $1`, [
        ingested.body.signal.id,
      ]);
    });
  });

  it('records on each approval the conditions that approver was shown', async () => {
    await issueTreasuryLease(h);
    const escalated = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'nextphase-toctou-4',
        context: { ...wireRequest().context, amount: '250000.00' },
      }),
    );
    await h.call('POST', '/v1/approvals', h.tenant.tokens['treasurer']!, {
      approval_request_id: escalated.body.approval_request_id,
      vote: 'APPROVED',
    });

    const trace = await h.call(
      'GET',
      `/v1/trace/${escalated.body.decision_id}`,
      h.tenant.tokens['admin']!,
    );
    const approval = trace.body.trace.find(
      (node: { type: string }) => node.type === 'human_approval',
    );
    expect(approval.detail.approved_context_hash).toBe(escalated.body.context_hash);
  });
});

describe('corrective handshake over the API', () => {
  it('offers a lease request when the agent holds no authority', async () => {
    const response = await evaluate(
      h.tenant.tokens['verification_agent']!,
      wireRequest({ agent_id: 'verification-agent', nonce: 'nextphase-ch-1' }),
    );
    expect(response.body.decision).toBe('DENY');
    const actions = response.body.corrective_actions;
    expect(actions).toHaveLength(1);
    expect(actions[0].type).toBe('REQUEST_LEASE');
    expect(actions[0].payload.grant.actions).toEqual(['wire.execute']);
  });

  it('offers a delegation request addressed to the delegating agent', async () => {
    const parent = await issueTreasuryLease(h);
    const delegation = await h.call('POST', '/v1/delegations', h.tenant.tokens['treasury_agent']!, {
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
    expect(delegation.status).toBe(201);

    const refused = await evaluate(h.tenant.tokens['verification_agent']!, {
      agent_id: 'verification-agent',
      action: 'counterparty.read',
      resource: { type: 'counterparty', id: 'cp_102' },
      context: { counterparty_id: 'cp_102' },
    });
    expect(refused.body.reason_code).toBe('RESOURCE_NOT_IN_AUTHORITY');
    const action = refused.body.corrective_actions[0];
    expect(action).toMatchObject({ type: 'REQUEST_DELEGATION', target_agent: 'treasury-agent' });
  });

  it('offers a human escalation with the approval request already open', async () => {
    await issueTreasuryLease(h);
    const escalated = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'nextphase-ch-3',
        context: { ...wireRequest().context, amount: '250000.00' },
      }),
    );
    const action = escalated.body.corrective_actions.find(
      (a: { type: string }) => a.type === 'HUMAN_ESCALATION',
    );
    expect(action.payload.approval_request_id).toBe(escalated.body.approval_request_id);
    expect(action.payload.required_roles).toEqual(['treasurer']);
  });

  it('offers nothing for a hard violation, and leaks nothing either', async () => {
    const response = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'nextphase-ch-4',
        context: { ...wireRequest().context, destination_country: 'KP' },
      }),
    );
    expect(response.body.decision).toBe('DENY');
    expect(response.body.corrective_actions).toEqual([]);
    expect(JSON.stringify(response.body)).not.toContain('sanctioned_destination');
  });

  it('records the actions it offered as evidence', async () => {
    const response = await evaluate(
      h.tenant.tokens['verification_agent']!,
      wireRequest({ agent_id: 'verification-agent', nonce: 'nextphase-ch-5' }),
    );
    const receipt = await h.call(
      'GET',
      `/v1/receipts/${response.body.receipt_id}`,
      h.tenant.tokens['admin']!,
    );
    expect(receipt.body.receipt.payload.corrective_actions).toHaveLength(1);
  });
});

describe('root-cause trace', () => {
  it('reconstructs the causal chain in causal order', async () => {
    const parent = await issueTreasuryLease(h);
    const delegation = await h.call('POST', '/v1/delegations', h.tenant.tokens['treasury_agent']!, {
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
    expect(delegation.status).toBe(201);

    const allowed = await evaluate(h.tenant.tokens['verification_agent']!, {
      agent_id: 'verification-agent',
      action: 'counterparty.read',
      resource: { type: 'counterparty', id: 'cp_101' },
      context: { counterparty_id: 'cp_101' },
      authority_lease_id: delegation.body.child_lease.id,
    });
    expect(allowed.body.decision).toBe('ALLOW');

    const trace = await h.call(
      'GET',
      `/v1/trace/${allowed.body.decision_id}`,
      h.tenant.tokens['admin']!,
    );
    expect(trace.status).toBe(200);

    const types = trace.body.trace.map((n: { type: string }) => n.type);
    expect(types[0]).toBe('policy_activation');
    expect(types).toContain('authority_lease');
    expect(types).toContain('delegation');
    expect(types).toContain('authorization_request');
    expect(types[types.length - 1]).toBe('authorization_decision');
    expect(trace.body.complete).toBe(true);
    expect(trace.body.root_cause.type).toBe('policy_activation');
  });

  it('numbers steps consecutively and links every node to its cause', async () => {
    const parent = await issueTreasuryLease(h);
    expect(parent.id).toBeTruthy();
    const allowed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'nextphase-trace-2' }),
    );
    const trace = await h.call(
      'GET',
      `/v1/trace/${allowed.body.decision_id}`,
      h.tenant.tokens['admin']!,
    );

    const nodes = trace.body.trace as Array<{
      step: number;
      id: string;
      causal_parent_id: string | null;
      timestamp: string;
      causal_link_type: string;
    }>;
    expect(nodes.map((n) => n.step)).toEqual(nodes.map((_, index) => index + 1));
    expect(nodes[0]!.causal_parent_id).toBeNull();
    expect(nodes[0]!.causal_link_type).toBe('origin');

    const seen = new Set<string>();
    for (const node of nodes) {
      if (node.causal_parent_id !== null) {
        expect(seen.has(node.causal_parent_id), `${node.id} cites an unseen cause`).toBe(true);
      }
      seen.add(node.id);
      expect(Number.isNaN(Date.parse(node.timestamp))).toBe(false);
    }
  });

  it('shows the escalation, the human, and the superseding decision', async () => {
    await issueTreasuryLease(h);
    const escalated = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'nextphase-trace-3',
        context: { ...wireRequest().context, amount: '250000.00' },
      }),
    );
    const approval = await h.call('POST', '/v1/approvals', h.tenant.tokens['treasurer']!, {
      approval_request_id: escalated.body.approval_request_id,
      vote: 'APPROVED',
    });

    const trace = await h.call(
      'GET',
      `/v1/trace/${approval.body.decision.decision_id}`,
      h.tenant.tokens['admin']!,
    );
    const types = trace.body.trace.map((n: { type: string }) => n.type);
    expect(types).toContain('human_approval');
    // Both the escalation it superseded and the decision itself are present.
    expect(types.filter((t: string) => t === 'authorization_decision').length).toBe(2);
  });

  it('includes only the signals the decision actually read', async () => {
    await issueTreasuryLease(h);
    const ingested = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'fraud_risk',
      value: '0.95',
      source: 'external_fraud_engine',
      ttl_seconds: 600,
    });
    const decayed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'nextphase-trace-4' }),
    );
    expect(decayed.body.decision).toBe('ESCALATE');

    const trace = await h.call(
      'GET',
      `/v1/trace/${decayed.body.decision_id}`,
      h.tenant.tokens['admin']!,
    );
    const signals = trace.body.trace.filter((n: { type: string }) => n.type === 'risk_signal');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe(ingested.body.signal.id);
    expect(signals[0].causal_link_type).toBe('influenced_by');

    await asOwner(async (client) => {
      await client.query(`UPDATE scrutexity.risk_signals SET superseded_at = now() WHERE id = $1`, [
        ingested.body.signal.id,
      ]);
    });
  });

  it('is deterministic', async () => {
    await issueTreasuryLease(h);
    const allowed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'nextphase-trace-5' }),
    );
    const first = await h.call(
      'GET',
      `/v1/trace/${allowed.body.decision_id}`,
      h.tenant.tokens['admin']!,
    );
    const second = await h.call(
      'GET',
      `/v1/trace/${allowed.body.decision_id}`,
      h.tenant.tokens['admin']!,
    );
    expect(JSON.stringify(first.body)).toBe(JSON.stringify(second.body));
  });

  it('is tenant-scoped', async () => {
    await issueTreasuryLease(h);
    const allowed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'nextphase-trace-6' }),
    );
    const crossTenant = await h.call(
      'GET',
      `/v1/trace/${allowed.body.decision_id}`,
      h.other.tokens['admin']!,
    );
    expect(crossTenant.status).toBe(404);
  });
});

describe('signal authentication over the API', () => {
  const source = 'signed_fraud_engine';
  const secret = 'a-shared-secret-of-adequate-length';

  it('accepts a correctly signed signal and marks it authenticated', async () => {
    const registered = await h.call('POST', '/v1/signal-keys', h.tenant.tokens['admin']!, {
      source,
      key_id: 'k1',
      algorithm: 'HMAC_SHA256',
      key_material: secret,
    });
    expect(registered.status).toBe(201);
    // The secret is never echoed back.
    expect(JSON.stringify(registered.body)).not.toContain(secret);

    const issuedAt = new Date().toISOString();
    const envelope = {
      organization_id: h.tenant.organization_id,
      subject_type: 'agent',
      subject_id: h.tenant.agents['treasury']!,
      signal_type: 'fraud_risk',
      value: '0.4',
      confidence: '1',
      source,
      event_id: 'evt-signed-1',
      issued_at: issuedAt,
      ttl_seconds: 600,
    };

    const response = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: envelope.subject_id },
      signal_type: 'fraud_risk',
      value: '0.4',
      confidence: '1',
      source,
      ttl_seconds: 600,
      issued_at: issuedAt,
      event_id: 'evt-signed-1',
      signature: signSignalHmac(envelope, secret),
      signing_key_id: 'k1',
    });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    expect(response.body.signal.authenticated).toBe(true);
  });

  it('rejects a forged signal and does not modify authority', async () => {
    const before = await h.call('GET', '/v1/overview', h.tenant.tokens['admin']!);
    const liveBefore = before.body.live_signals.length;

    const response = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'fraud_risk',
      value: '0.99',
      source,
      ttl_seconds: 600,
      event_id: 'evt-forged-1',
      signature: 'Zm9yZ2Vk',
      signing_key_id: 'k1',
    });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('SIGNAL_SIGNATURE_INVALID');

    const after = await h.call('GET', '/v1/overview', h.tenant.tokens['admin']!);
    expect(after.body.live_signals.length).toBe(liveBefore);

    const events = await h.call('GET', '/v1/security-events', h.tenant.tokens['admin']!);
    expect(
      events.body.security_events.some(
        (e: { kind: string; detail: { event_id?: string } }) =>
          e.kind === 'SIGNAL_REJECTED' && e.detail.event_id === 'evt-forged-1',
      ),
    ).toBe(true);
  });

  it('rejects a signal signed with an unknown key id', async () => {
    const response = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: h.tenant.agents['treasury'] },
      signal_type: 'fraud_risk',
      value: '0.1',
      source,
      ttl_seconds: 600,
      event_id: 'evt-unknown-key',
      signature: 'c2ln',
      signing_key_id: 'nonexistent',
    });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('SIGNAL_KEY_UNKNOWN');
  });

  it('refuses a replayed delivery of a signal it already accepted', async () => {
    const issuedAt = new Date().toISOString();
    const envelope = {
      organization_id: h.tenant.organization_id,
      subject_type: 'agent',
      subject_id: h.tenant.agents['treasury']!,
      signal_type: 'model_confidence',
      value: '0.8',
      confidence: '1',
      source,
      event_id: 'evt-replay-1',
      issued_at: issuedAt,
      ttl_seconds: 600,
    };
    const body = {
      subject: { type: 'agent' as const, id: envelope.subject_id },
      signal_type: 'model_confidence',
      value: '0.8',
      confidence: '1',
      source,
      ttl_seconds: 600,
      issued_at: issuedAt,
      event_id: 'evt-replay-1',
      signature: signSignalHmac(envelope, secret),
      signing_key_id: 'k1',
    };

    const first = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, body);
    expect(first.status).toBe(201);

    // A valid signature is not enough: the same event twice is still a replay.
    const replay = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, body);
    expect(replay.status).toBe(409);
    expect(replay.body.error.code).toBe('REPLAY_DETECTED');
  });

  it('honours a rotation grace period and then stops accepting the old key', async () => {
    const keys = await h.call('GET', '/v1/signal-keys', h.tenant.tokens['admin']!);
    const key = keys.body.signal_keys.find((k: { key_id: string }) => k.key_id === 'k1');

    const retired = await h.call(
      'POST',
      `/v1/signal-keys/${key.id}/retire`,
      h.tenant.tokens['admin']!,
      { grace_period_seconds: 3600 },
    );
    expect(retired.body.signal_key.status).toBe('RETIRING');

    const issuedAt = new Date().toISOString();
    const envelope = {
      organization_id: h.tenant.organization_id,
      subject_type: 'agent',
      subject_id: h.tenant.agents['treasury']!,
      signal_type: 'fraud_risk',
      value: '0.3',
      confidence: '1',
      source,
      event_id: 'evt-grace-1',
      issued_at: issuedAt,
      ttl_seconds: 600,
    };
    // Inside the window the outgoing key still works.
    const during = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: envelope.subject_id },
      signal_type: 'fraud_risk',
      value: '0.3',
      confidence: '1',
      source,
      ttl_seconds: 600,
      issued_at: issuedAt,
      event_id: 'evt-grace-1',
      signature: signSignalHmac(envelope, secret),
      signing_key_id: 'k1',
    });
    expect(during.status).toBe(201);

    // Revocation, by contrast, takes effect at once.
    const revoked = await h.call(
      'POST',
      `/v1/signal-keys/${key.id}/revoke`,
      h.tenant.tokens['admin']!,
      {},
    );
    expect(revoked.body.signal_key.status).toBe('REVOKED');

    const after = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: envelope.subject_id },
      signal_type: 'fraud_risk',
      value: '0.3',
      confidence: '1',
      source,
      ttl_seconds: 600,
      event_id: 'evt-after-revoke',
      signature: signSignalHmac({ ...envelope, event_id: 'evt-after-revoke' }, secret),
      signing_key_id: 'k1',
    });
    expect(after.status).toBe(403);
  });

  it('accepts an Ed25519 signature, storing only the public key', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const registered = await h.call('POST', '/v1/signal-keys', h.tenant.tokens['admin']!, {
      source: 'ed_source',
      key_id: 'ed1',
      algorithm: 'ED25519',
      key_material: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    });
    expect(registered.status).toBe(201);

    const issuedAt = new Date().toISOString();
    const envelope = {
      organization_id: h.tenant.organization_id,
      subject_type: 'agent',
      subject_id: h.tenant.agents['treasury']!,
      signal_type: 'anomaly_score',
      value: '0.2',
      confidence: '1',
      source: 'ed_source',
      event_id: 'evt-ed-1',
      issued_at: issuedAt,
      ttl_seconds: 600,
    };
    const signature = edSign(
      null,
      Buffer.from(signalSigningPayload(envelope), 'utf8'),
      privateKey,
    ).toString('base64url');

    const response = await h.call('POST', '/v1/signals', h.tenant.tokens['fraud_engine']!, {
      subject: { type: 'agent', id: envelope.subject_id },
      signal_type: 'anomaly_score',
      value: '0.2',
      confidence: '1',
      source: 'ed_source',
      ttl_seconds: 600,
      issued_at: issuedAt,
      event_id: 'evt-ed-1',
      signature,
      signing_key_id: 'ed1',
    });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    expect(response.body.signal.authenticated).toBe(true);
  });

  it('keeps signing keys tenant-scoped', async () => {
    const keys = await h.call('GET', '/v1/signal-keys', h.other.tokens['admin']!);
    expect(keys.body.signal_keys).toEqual([]);
  });
});

describe('cascading revocation', () => {
  async function buildChain() {
    const parent = await issueTreasuryLease(h);
    const delegation = await h.call('POST', '/v1/delegations', h.tenant.tokens['treasury_agent']!, {
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
      ttl_seconds: 3600,
    });
    expect(delegation.status).toBe(201);
    return { parent, child: delegation.body.child_lease };
  }

  const readAsDelegate = (leaseId: string) =>
    evaluate(h.tenant.tokens['verification_agent']!, {
      agent_id: 'verification-agent',
      action: 'counterparty.read',
      resource: { type: 'counterparty', id: 'cp_100' },
      context: { counterparty_id: 'cp_100' },
      authority_lease_id: leaseId,
    });

  it('invalidates a child the instant its parent is revoked', async () => {
    const { parent, child } = await buildChain();
    expect((await readAsDelegate(child.id)).body.decision).toBe('ALLOW');

    await h.call('POST', `/v1/authority-leases/${parent.id}/revoke`, h.tenant.tokens['admin']!, {
      reason: 'cascade test',
    });

    const after = await readAsDelegate(child.id);
    expect(after.body.decision).toBe('DENY');
    expect(after.body.reason_code).toBe('AUTHORITY_REVOKED');
  });

  it('invalidates a child when the parent expires, with no sweep involved', async () => {
    const { parent, child } = await buildChain();
    await asOwner(async (client) => {
      await client.query(
        `UPDATE scrutexity.authority_leases
            SET issued_at = now() - interval '2 hours', expires_at = now() - interval '1 second'
          WHERE id = $1`,
        [parent.id],
      );
    });
    const after = await readAsDelegate(child.id);
    expect(after.body.decision).toBe('DENY');
    expect(after.body.reason_code).toBe('AUTHORITY_EXPIRED');
  });

  it('leaves the child row untouched: the chain walk is what enforces it', async () => {
    const { parent, child } = await buildChain();
    await h.call('POST', `/v1/authority-leases/${parent.id}/revoke`, h.tenant.tokens['admin']!, {
      reason: 'cascade test',
    });
    const lease = await h.call(
      'GET',
      `/v1/authority-leases/${child.id}`,
      h.tenant.tokens['admin']!,
    );
    // Still ACTIVE on paper, and refused in practice. No cascade job to lag.
    expect(lease.body.authority_lease.status).toBe('ACTIVE');
    expect((await readAsDelegate(child.id)).body.reason_code).toBe('AUTHORITY_REVOKED');
  });

  it('refuses a grandchild when the root is revoked', async () => {
    const { parent, child } = await buildChain();
    const grandchild = await h.call(
      'POST',
      '/v1/delegations',
      h.tenant.tokens['verification_agent']!,
      {
        issuer_agent_id: h.tenant.agents['verification'],
        delegate_agent_id: 'treasury-agent',
        parent_lease_id: child.id,
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
      },
    );
    expect(grandchild.status, JSON.stringify(grandchild.body)).toBe(201);

    await h.call('POST', `/v1/authority-leases/${parent.id}/revoke`, h.tenant.tokens['admin']!, {
      reason: 'cascade test',
    });

    const after = await evaluate(h.tenant.tokens['treasury_agent']!, {
      agent_id: 'treasury-agent',
      action: 'counterparty.read',
      resource: { type: 'counterparty', id: 'cp_100' },
      context: { counterparty_id: 'cp_100' },
      authority_lease_id: grandchild.body.child_lease.id,
    });
    expect(after.body.reason_code).toBe('AUTHORITY_REVOKED');
  });
});
