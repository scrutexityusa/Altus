import { describe, expect, it } from 'vitest';
import { evaluateAuthorization } from '../src/evaluate.js';
import { explainDecision } from '../src/explain.js';
import { parseMoney } from '../src/money.js';
import type { Approval } from '../src/approval.js';
import { grant, lease, signal, snapshot, T0 } from './fixtures.js';

const approval = (overrides: Partial<Approval> = {}): Approval => ({
  id: 'apv_1',
  approval_request_id: 'apr_1',
  approver_user_id: 'user_treasurer',
  vote: 'APPROVED',
  roles_at_decision: ['treasurer'],
  satisfied_role: 'treasurer',
  comment: null,
  created_at: T0.toISOString(),
  ...overrides,
});

const requirement = {
  required: true as const,
  quorum: 1,
  roles: ['treasurer'],
  forbid_self_approval: true,
  ttl_seconds: 3600,
};

// The delegated verification agent used across the delegation scenes.
const verificationLease = lease({
  id: 'lease_child',
  agent_id: 'agent_verification',
  parent_lease_id: 'lease_root',
  depth: 1,
  grant: {
    actions: ['counterparty.read'],
    resources: { counterparty: ['cp_100', 'cp_101'] },
    constraints: {
      max_amount: parseMoney('0', 'USD'),
      currencies: ['USD'],
      allowed_counterparties: ['cp_100', 'cp_101'],
    },
  },
  expires_at: new Date(T0.getTime() + 600_000).toISOString(),
});

describe('demo scene 2 -- a $25,000 wire is allowed', () => {
  const result = evaluateAuthorization(snapshot({ amount: '25000' }));

  it('allows autonomously', () => {
    expect(result.decision).toBe('ALLOW');
    expect(result.reason_code).toBe('WITHIN_LEASED_AUTHORITY');
    expect(result.authority_lease_id).toBe('lease_root');
  });

  it('confers a time-boxed execution grant rather than an open licence', () => {
    expect(result.expires_at).toBe(new Date(T0.getTime() + 300_000).toISOString());
  });

  it('records the constraint checks that were actually performed', () => {
    expect(result.constraints_evaluated.map((c) => c.constraint).sort()).toEqual([
      'allowed_counterparties',
      'currencies',
      'max_amount',
    ]);
    expect(result.constraints_evaluated.every((c) => c.satisfied)).toBe(true);
  });
});

describe('demo scene 3 -- a $250,000 wire escalates', () => {
  const result = evaluateAuthorization(snapshot({ amount: '250000' }));

  it('escalates to the treasurer instead of denying', () => {
    expect(result.decision).toBe('ESCALATE');
    expect(result.reason_code).toBe('TREASURER_APPROVAL_REQUIRED');
    expect(result.approval_requirement).toMatchObject({ quorum: 1, roles: ['treasurer'] });
  });

  it('confers no execution grant while it is pending', () => {
    expect(result.expires_at).toBeNull();
  });

  it('names the ceiling that was exceeded, not a generic refusal', () => {
    expect(result.evaluation.autonomy.blocked_by).toMatchObject({
      kind: 'CONSTRAINT',
      constraint: 'max_amount',
    });
  });
});

describe('demo scene 4 -- the treasurer approves', () => {
  const result = evaluateAuthorization(
    snapshot({
      amount: '250000',
      priorApproval: {
        approval_request_id: 'apr_1',
        requirement,
        approvals: [approval()],
        expires_at: new Date(T0.getTime() + 3_600_000).toISOString(),
      },
    }),
  );

  it('allows once the requirement is satisfied', () => {
    expect(result.decision).toBe('ALLOW');
    expect(result.reason_code).toBe('APPROVED_BY_HUMAN');
    expect(result.approval_state?.status).toBe('SATISFIED');
  });

  it('records who supplied the missing authority and in what role', () => {
    expect(result.approval_state?.counted).toEqual([
      { approval_id: 'apv_1', user_id: 'user_treasurer', role: 'treasurer' },
    ]);
  });
});

describe('human approval is not a boolean', () => {
  const escalated = (approvals: Approval[], ownerUserId: string | null = 'user_owner') =>
    evaluateAuthorization(
      snapshot({
        amount: '250000',
        ownerUserId,
        priorApproval: {
          approval_request_id: 'apr_1',
          requirement,
          approvals,
          expires_at: new Date(T0.getTime() + 3_600_000).toISOString(),
        },
      }),
    );

  it('refuses an approval from the agent owner when policy forbids self-approval', () => {
    const result = escalated([approval({ approver_user_id: 'user_owner' })]);
    expect(result.decision).toBe('ESCALATE');
    expect(result.approval_state?.discounted[0]?.reason).toBe('SELF_APPROVAL_FORBIDDEN');
  });

  it('refuses an approval from someone who did not hold the required role', () => {
    const result = escalated([approval({ approver_user_id: 'user_intern', roles_at_decision: ['analyst'] })]);
    expect(result.decision).toBe('ESCALATE');
    expect(result.approval_state?.discounted[0]?.reason).toBe('APPROVER_HELD_NO_REQUIRED_ROLE');
  });

  it('treats a rejection as terminal, not as a vote to be outnumbered', () => {
    const result = escalated([
      approval({ id: 'apv_reject', approver_user_id: 'user_cfo', roles_at_decision: ['cfo', 'treasurer'], vote: 'REJECTED' }),
      approval({ id: 'apv_ok', approver_user_id: 'user_treasurer' }),
    ]);
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('APPROVAL_REJECTED');
  });

  it('denies once the approval window has closed', () => {
    const result = evaluateAuthorization(
      snapshot({
        amount: '250000',
        priorApproval: {
          approval_request_id: 'apr_1',
          requirement,
          approvals: [],
          expires_at: new Date(T0.getTime() - 1).toISOString(),
        },
      }),
    );
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('APPROVAL_EXPIRED');
  });

  it('requires every named role, not merely enough bodies', () => {
    const dualRequirement = { ...requirement, quorum: 2, roles: ['treasurer', 'cfo'] };
    const withTwoTreasurers = evaluateAuthorization(
      snapshot({
        amount: '2000000',
        priorApproval: {
          approval_request_id: 'apr_1',
          requirement: dualRequirement,
          approvals: [
            approval({ id: 'apv_a', approver_user_id: 'user_t1' }),
            approval({ id: 'apv_b', approver_user_id: 'user_t2' }),
          ],
          expires_at: new Date(T0.getTime() + 3_600_000).toISOString(),
        },
      }),
    );
    expect(withTwoTreasurers.decision).toBe('ESCALATE');
    expect(withTwoTreasurers.approval_state?.outstanding_roles).toEqual(['cfo']);

    const withBothRoles = evaluateAuthorization(
      snapshot({
        amount: '2000000',
        priorApproval: {
          approval_request_id: 'apr_1',
          requirement: dualRequirement,
          approvals: [
            approval({ id: 'apv_a', approver_user_id: 'user_t1' }),
            approval({ id: 'apv_b', approver_user_id: 'user_c1', roles_at_decision: ['cfo'] }),
          ],
          expires_at: new Date(T0.getTime() + 3_600_000).toISOString(),
        },
      }),
    );
    expect(withBothRoles.decision).toBe('ALLOW');
  });

  it('does not let one multi-role approver starve a role only they could cover', () => {
    const dualRequirement = { ...requirement, quorum: 2, roles: ['treasurer', 'cfo'] };
    const result = evaluateAuthorization(
      snapshot({
        amount: '2000000',
        priorApproval: {
          approval_request_id: 'apr_1',
          requirement: dualRequirement,
          approvals: [
            // Assigned first if ordering were naive, consuming "treasurer".
            approval({ id: 'apv_a', approver_user_id: 'user_both', roles_at_decision: ['treasurer', 'cfo'] }),
            approval({ id: 'apv_b', approver_user_id: 'user_t_only', roles_at_decision: ['treasurer'] }),
          ],
          expires_at: new Date(T0.getTime() + 3_600_000).toISOString(),
        },
      }),
    );
    expect(result.decision).toBe('ALLOW');
  });
});

describe('demo scene 6 -- the delegated agent reaches beyond its remit', () => {
  const root = lease();
  const result = evaluateAuthorization(
    snapshot({
      agentId: 'agent_verification',
      agentHandle: 'verification-agent',
      action: 'wire.modify',
      amount: '5000',
      candidates: [{ lease: verificationLease, chain: [verificationLease, root] }],
    }),
  );

  it('denies, and does not offer an approval path', () => {
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('ACTION_NOT_IN_AUTHORITY');
    expect(result.approval_requirement).toBeNull();
  });

  it('records exactly which authority was consulted and why it failed', () => {
    expect(result.authority_lease_id).toBe('lease_child');
    expect(result.evaluation.autonomy.blocked_by).toMatchObject({ kind: 'ENVELOPE' });
  });

  it('explains the denial in the customer-facing form', () => {
    const explanation = explainDecision(result, {
      agent_handle: 'verification-agent',
      delegated_by_handle: 'treasury-agent',
    });
    expect(explanation.headline).toBe('DENIED');
    expect(explanation.facts.why).toContain('wire.modify');
    expect(explanation.facts.why).toContain('delegated by treasury-agent');
    expect(explanation.facts.why).toContain('Execution blocked');
    // Every fact is kept separable; none of them is generated prose.
    expect(explanation.facts.authority).toContain('lease_child');
    expect(explanation.facts.policy).toContain('treasury_wire');
  });

  it('still permits the read it actually was delegated', () => {
    const allowed = evaluateAuthorization(
      snapshot({
        agentId: 'agent_verification',
        agentHandle: 'verification-agent',
        action: 'counterparty.read',
        resourceType: 'counterparty',
        resourceId: 'cp_100',
        candidates: [{ lease: verificationLease, chain: [verificationLease, root] }],
      }),
    );
    expect(allowed.decision).toBe('ALLOW');
    expect(allowed.reason_code).toBe('READ_ONLY_ACTION');
  });
});

describe('demo scene 7 -- a fraud signal shrinks live authority', () => {
  const withoutSignal = evaluateAuthorization(snapshot({ amount: '25000' }));
  const withSignal = evaluateAuthorization(snapshot({ amount: '25000', signals: [signal()] }));

  it('turns a formerly autonomous action into one needing a human', () => {
    expect(withoutSignal.decision).toBe('ALLOW');
    expect(withSignal.decision).toBe('ESCALATE');
    expect(withSignal.reason_code).toBe('AUTHORITY_DECAYED');
  });

  it('attributes the narrowing to the rule and the signal that caused it', () => {
    expect(withSignal.evaluation.autonomy.blocked_by).toMatchObject({
      kind: 'DECAY',
      rule_ids: ['elevated_fraud_risk'],
    });
    expect(withSignal.risk_signal_ids).toEqual(['sig_1']);
    expect(withSignal.evaluation.authority_effects_applied).toEqual([
      { rule_id: 'elevated_fraud_risk', duration_seconds: 600 },
    ]);
  });

  it('narrows autonomy without redefining the agent role', () => {
    const finding = withSignal.evaluation.authority_findings[0]!;
    expect(finding.envelope_covered).toBe(true);
    expect(finding.effective_grant?.actions).not.toContain('wire.execute');
  });

  it('restores authority once the signal expires', () => {
    const afterExpiry = evaluateAuthorization(
      snapshot({
        amount: '25000',
        now: new Date(T0.getTime() + 601_000),
        // A stale signal is not passed to the evaluator at all: freshness is
        // enforced when signals are read, not by policy remembering to check.
        signals: [],
      }),
    );
    expect(afterExpiry.decision).toBe('ALLOW');
  });
});

describe('expired and revoked authority never authorizes', () => {
  it('denies on an expired lease', () => {
    const expired = lease({ expires_at: new Date(T0.getTime() - 1).toISOString() });
    const result = evaluateAuthorization(
      snapshot({ amount: '25000', candidates: [{ lease: expired, chain: [expired] }] }),
    );
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('AUTHORITY_EXPIRED');
  });

  it('denies on a revoked lease with no grace period', () => {
    const revoked = lease({ status: 'REVOKED', revoked_at: T0.toISOString() });
    const result = evaluateAuthorization(
      snapshot({ amount: '25000', candidates: [{ lease: revoked, chain: [revoked] }] }),
    );
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('AUTHORITY_REVOKED');
  });

  it('denies a delegated action the instant the parent lease is revoked', () => {
    const revokedRoot = lease({ status: 'REVOKED', revoked_at: T0.toISOString() });
    const result = evaluateAuthorization(
      snapshot({
        agentId: 'agent_verification',
        action: 'counterparty.read',
        resourceType: 'counterparty',
        resourceId: 'cp_100',
        candidates: [{ lease: verificationLease, chain: [verificationLease, revokedRoot] }],
      }),
    );
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('AUTHORITY_REVOKED');
  });

  it('denies when the agent holds no authority at all', () => {
    const result = evaluateAuthorization(snapshot({ amount: '25000', candidates: [] }));
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('AUTHORITY_MISSING');
  });

  it('denies a suspended agent identity regardless of its leases', () => {
    const result = evaluateAuthorization(snapshot({ amount: '5000', agentStatus: 'SUSPENDED' }));
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('AGENT_NOT_ACTIVE');
  });
});

describe('failure modes are policy data, not a global switch', () => {
  it('fails closed when the policy itself cannot be read', () => {
    const result = evaluateAuthorization(snapshot({ amount: '100', policy: null }));
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('POLICY_UNAVAILABLE');
    expect(result.failover_behavior).toBe('FAIL_CLOSED');
  });

  it('fails closed when risk signals cannot be read, per the treasury pack', () => {
    const result = evaluateAuthorization(
      snapshot({ amount: '5000', dependencies: { signals_available: false } }),
    );
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('SIGNAL_UNAVAILABLE');
  });

  it('records the failover behaviour that was applied', () => {
    const result = evaluateAuthorization(
      snapshot({ amount: '5000', dependencies: { enforcement_available: false } }),
    );
    expect(result.failover_behavior).toBe('FAIL_CLOSED');
    expect(result.decision).toBe('DENY');
  });
});

describe('determinism', () => {
  it('produces byte-identical output for identical inputs', () => {
    const once = evaluateAuthorization(snapshot({ amount: '250000', signals: [signal({ value: '0.5' })] }));
    const twice = evaluateAuthorization(snapshot({ amount: '250000', signals: [signal({ value: '0.5' })] }));
    expect(JSON.stringify(once)).toBe(JSON.stringify(twice));
  });

  it('selects the same lease when several could apply', () => {
    const a = lease({ id: 'lease_aaa' });
    const b = lease({ id: 'lease_bbb', grant: grant({ constraints: { max_amount: parseMoney('10', 'USD') } }) });
    const forwards = evaluateAuthorization(
      snapshot({ amount: '25000', candidates: [{ lease: a, chain: [a] }, { lease: b, chain: [b] }] }),
    );
    const backwards = evaluateAuthorization(
      snapshot({ amount: '25000', candidates: [{ lease: b, chain: [b] }, { lease: a, chain: [a] }] }),
    );
    expect(forwards.authority_lease_id).toBe(backwards.authority_lease_id);
    expect(forwards.decision).toBe('ALLOW');
  });
});
