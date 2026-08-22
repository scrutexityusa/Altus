import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import {
  issueTreasuryLease,
  signedSignal,
  startHarness,
  wireRequest,
  ADMIN_URL,
  type Harness,
} from './harness.js';

let h: Harness;
let lease: { id: string };

beforeAll(async () => {
  h = await startHarness();
  lease = await issueTreasuryLease(h);
}, 60_000);

afterAll(async () => {
  await h?.close();
});

const evaluate = (token: string, body: unknown) =>
  h.call('POST', '/v1/authorization/evaluate', token, body);

describe('the authorization loop', () => {
  it('allows a wire inside the agent authority and confers a bounded grant', async () => {
    const agentToken = h.tenant.tokens['treasury_agent']!;
    const response = await evaluate(agentToken, wireRequest({ nonce: 'n-allow-1' }));

    expect(response.status).toBe(200);
    expect(response.body.decision).toBe('ALLOW');
    expect(response.body.reason_code).toBe('WITHIN_LEASED_AUTHORITY');
    expect(response.body.authority_lease_id).toBe(lease.id);
    expect(response.body.receipt_id).toMatch(/^rcpt_/);
    expect(new Date(response.body.expires_at).getTime()).toBeGreaterThan(Date.now());
  });

  it('returns 200 for a denial: an evaluated "no" is not a failed request', async () => {
    const response = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'n-deny-1',
        context: {
          amount: '100.00',
          currency: 'USD',
          counterparty_id: 'cp_unknown',
          destination_country: 'US',
        },
      }),
    );
    expect(response.status).toBe(200);
    expect(response.body.decision).toBe('DENY');
    expect(response.body.reason_code).toBe('UNKNOWN_COUNTERPARTY');
  });

  it('derives counterparty_known itself and ignores what the caller claims', async () => {
    const response = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'n-forged-context',
        context: {
          amount: '100.00',
          currency: 'USD',
          counterparty_id: 'cp_totally_made_up',
          destination_country: 'US',
          // The agent asserts the counterparty is registered. It is not.
          counterparty_known: true,
        },
      }),
    );
    expect(response.body.decision).toBe('DENY');
    expect(response.body.reason_code).toBe('UNKNOWN_COUNTERPARTY');
  });

  it('rejects an unknown action rather than letting it fall through to a default', async () => {
    const response = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ action: 'wire.exceute' }),
    );
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('INVALID_REQUEST');
  });

  it('rejects a money-bearing action with no amount', async () => {
    const response = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ context: { currency: 'USD', counterparty_id: 'cp_100' } }),
    );
    expect(response.status).toBe(400);
    expect(response.body.error.details.errors.join()).toContain('amount');
  });

  it('rejects a fractional float amount instead of comparing it', async () => {
    const response = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        context: { amount: 0.1 + 0.2, currency: 'USD', counterparty_id: 'cp_100' },
      }),
    );
    expect(response.status).toBe(400);
  });

  it('escalates above the ceiling and opens exactly one approval request', async () => {
    const response = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'n-escalate-1',
        context: { ...wireRequest().context, amount: '250000.00' },
      }),
    );
    expect(response.body.decision).toBe('ESCALATE');
    expect(response.body.approval_request_id).toMatch(/^apr_/);
    expect(response.body.approval_requirement).toMatchObject({ quorum: 1, roles: ['treasurer'] });

    const pending = await h.call('GET', '/v1/approval-requests', h.tenant.tokens['admin']!);
    expect(
      pending.body.approval_requests.filter(
        (r: { id: string }) => r.id === response.body.approval_request_id,
      ),
    ).toHaveLength(1);
  });

  it('completes the escalation loop through a human and supersedes the escalation', async () => {
    const escalated = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'n-escalate-2',
        context: { ...wireRequest().context, amount: '250000.00' },
      }),
    );
    const approval = await h.call('POST', '/v1/approvals', h.tenant.tokens['treasurer']!, {
      approval_request_id: escalated.body.approval_request_id,
      vote: 'APPROVED',
      comment: 'Checked against the invoice.',
    });
    expect(approval.status).toBe(201);
    expect(approval.body.decision.decision).toBe('ALLOW');

    const original = await h.call(
      'GET',
      `/v1/authorization-decisions/${escalated.body.decision_id}`,
      h.tenant.tokens['admin']!,
    );
    // The escalated decision still says ESCALATE. It was never rewritten.
    expect(original.body.decision.decision).toBe('ESCALATE');

    const superseding = await h.call(
      'GET',
      `/v1/authorization-decisions/${approval.body.decision.decision_id}`,
      h.tenant.tokens['admin']!,
    );
    expect(superseding.body.decision.supersedes_decision_id).toBe(escalated.body.decision_id);
    expect(superseding.body.approvals).toHaveLength(1);
    expect(superseding.body.approvals[0].satisfied_role).toBe('treasurer');
  });

  it('requires both roles when the amount crosses the seven-figure threshold', async () => {
    const escalated = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'n-dual-1',
        context: { ...wireRequest().context, amount: '2000000.00' },
      }),
    );
    expect(escalated.body.approval_requirement).toMatchObject({
      quorum: 2,
      roles: ['cfo', 'treasurer'],
    });

    const first = await h.call('POST', '/v1/approvals', h.tenant.tokens['treasurer']!, {
      approval_request_id: escalated.body.approval_request_id,
      vote: 'APPROVED',
    });
    // One approval is not enough: the CFO role is still outstanding.
    expect(first.body.decision.decision).toBe('ESCALATE');

    const second = await h.call('POST', '/v1/approvals', h.tenant.tokens['cfo']!, {
      approval_request_id: escalated.body.approval_request_id,
      vote: 'APPROVED',
    });
    expect(second.body.decision.decision).toBe('ALLOW');
  });

  it('treats a rejection as terminal', async () => {
    const escalated = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'n-reject-1',
        context: { ...wireRequest().context, amount: '250000.00' },
      }),
    );
    const rejection = await h.call('POST', '/v1/approvals', h.tenant.tokens['treasurer']!, {
      approval_request_id: escalated.body.approval_request_id,
      vote: 'REJECTED',
      comment: 'Not recognised.',
    });
    expect(rejection.body.decision.decision).toBe('DENY');
    expect(rejection.body.decision.reason_code).toBe('APPROVAL_REJECTED');

    const retry = await h.call('POST', '/v1/approvals', h.tenant.tokens['cfo']!, {
      approval_request_id: escalated.body.approval_request_id,
      vote: 'APPROVED',
    });
    expect(retry.status).toBe(409);
  });

  it('answers the why-was-I-allowed question from structured facts', async () => {
    const allowed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'n-explain-1' }),
    );
    const detail = await h.call(
      'GET',
      `/v1/authorization-decisions/${allowed.body.decision_id}`,
      h.tenant.tokens['admin']!,
    );
    expect(detail.status).toBe(200);
    const { explanation } = detail.body;
    for (const key of ['what', 'authority', 'policy', 'signals', 'approvals', 'why']) {
      expect(explanation.facts[key], `explanation is missing "${key}"`).toBeTruthy();
    }
    expect(explanation.headline).toBe('ALLOWED');
    expect(detail.body.decision.policy_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(detail.body.decision.evaluation.policy_outcome.rule_traces.length).toBeGreaterThan(5);
  });

  it('is idempotent under a retried evaluation', async () => {
    const body = wireRequest({ nonce: 'n-idem-unique' });
    const key = 'idem-key-evaluate-1';
    const first = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      body,
      {
        'idempotency-key': key,
      },
    );
    const second = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      body,
      {
        'idempotency-key': key,
      },
    );
    expect(first.body.decision_id).toBe(second.body.decision_id);
    expect(first.body.receipt_id).toBe(second.body.receipt_id);
  });

  it('reports an idempotency key reused with a different body', async () => {
    const key = 'idem-key-conflict-1';
    await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'n-idem-conflict-a' }),
      { 'idempotency-key': key },
    );
    const conflict = await h.call(
      'POST',
      '/v1/authorization/evaluate',
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'n-idem-conflict-b' }),
      { 'idempotency-key': key },
    );
    expect(conflict.status).toBe(409);
    expect(conflict.body.error.code).toBe('IDEMPOTENCY_CONFLICT');
  });
});

describe('signals and authority decay', () => {
  it('narrows autonomy while a signal is live and restores it once it expires', async () => {
    const agentId = h.tenant.agents['treasury']!;

    const before = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'n-decay-before' }),
    );
    expect(before.body.decision).toBe('ALLOW');

    const ingested = await h.call(
      'POST',
      '/v1/signals',
      h.tenant.tokens['fraud_engine']!,
      signedSignal(h.tenant, {
        subject: { type: 'agent', id: agentId },
        signal_type: 'fraud_risk',
        value: '0.97',
        confidence: '0.91',
        source: 'external_fraud_engine',
        ttl_seconds: 600,
      }),
    );
    expect(ingested.status).toBe(201);

    const during = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'n-decay-during' }),
    );
    expect(during.body.decision).toBe('ESCALATE');
    expect(during.body.reason_code).toBe('AUTHORITY_DECAYED');
    expect(during.body.risk_signal_ids).toContain(ingested.body.signal.id);

    // Expire the signal by moving its window into the past, exactly as time
    // passing would. Freshness is enforced at read, so authority returns.
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query('SELECT set_config($1,$2,false)', [
      'scrutexity.org_id',
      h.tenant.organization_id,
    ]);
    await admin.query(
      `UPDATE scrutexity.risk_signals
          SET issued_at = now() - interval '20 minutes', expires_at = now() - interval '1 second'
        WHERE id = $1`,
      [ingested.body.signal.id],
    );
    await admin.end();

    const after = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'n-decay-after' }),
    );
    expect(after.body.decision).toBe('ALLOW');
    expect(after.body.risk_signal_ids).toEqual([]);
  });

  it('supersedes an older assertion from the same source', async () => {
    const agentId = h.tenant.agents['verification']!;
    const first = await h.call(
      'POST',
      '/v1/signals',
      h.tenant.tokens['fraud_engine']!,
      signedSignal(h.tenant, {
        subject: { type: 'agent', id: agentId },
        signal_type: 'model_confidence',
        value: '0.4',
        source: 'agent_self_report',
        ttl_seconds: 600,
      }),
    );
    const second = await h.call(
      'POST',
      '/v1/signals',
      h.tenant.tokens['fraud_engine']!,
      signedSignal(h.tenant, {
        subject: { type: 'agent', id: agentId },
        signal_type: 'model_confidence',
        value: '0.95',
        source: 'agent_self_report',
        ttl_seconds: 600,
      }),
    );
    expect(second.status, JSON.stringify(second.body)).toBe(201);
    expect(second.body.superseded_signal_ids).toContain(first.body.signal.id);
  });
});

describe('evidence', () => {
  it('verifies a receipt and its chain segment', async () => {
    const allowed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'n-receipt-1' }),
    );
    const verification = await h.call(
      'POST',
      `/v1/receipts/${allowed.body.receipt_id}/verify`,
      h.tenant.tokens['admin']!,
      {},
    );
    expect(verification.body.integrity).toBe('INTACT');
    expect(verification.body.attests).toBe('evidence_integrity_and_provenance');
    expect(verification.body.chain_verification.intact).toBe(true);
    expect(
      verification.body.receipt_verification.checks.map((c: { check: string }) => c.check),
    ).toContain('SIGNATURE');
  });

  it('links receipts into one chain per tenant', async () => {
    const a = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'n-chain-a' }),
    );
    const b = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'n-chain-b' }),
    );
    const first = await h.call(
      'GET',
      `/v1/receipts/${a.body.receipt_id}`,
      h.tenant.tokens['admin']!,
    );
    const second = await h.call(
      'GET',
      `/v1/receipts/${b.body.receipt_id}`,
      h.tenant.tokens['admin']!,
    );
    expect(second.body.receipt.seq).toBe(first.body.receipt.seq + 1);
    expect(second.body.receipt.previous_hash).toBe(first.body.receipt.hash);
  });
});

describe('execution grants', () => {
  it('is single-use', async () => {
    const allowed = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({ nonce: 'n-exec-1' }),
    );
    const first = await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: allowed.body.decision_id,
      status: 'SUCCEEDED',
    });
    expect(first.status).toBe(201);
    const second = await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: allowed.body.decision_id,
      status: 'SUCCEEDED',
    });
    expect(second.status).toBe(409);
    expect(second.body.error.code).toBe('REPLAY_DETECTED');
  });

  it('refuses execution against a decision that was not an ALLOW', async () => {
    const escalated = await evaluate(
      h.tenant.tokens['treasury_agent']!,
      wireRequest({
        nonce: 'n-exec-2',
        context: { ...wireRequest().context, amount: '250000.00' },
      }),
    );
    const attempt = await h.call('POST', '/v1/executions', h.tenant.tokens['treasury_agent']!, {
      decision_id: escalated.body.decision_id,
      status: 'SUCCEEDED',
    });
    expect(attempt.status).toBe(403);
  });
});
