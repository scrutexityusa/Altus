import { describe, expect, it } from 'vitest';
import {
  evaluatePolicy,
  mergeApprovalRequirements,
  policyHash,
  strictest,
} from '../src/policy/engine.js';
import { loadPolicyDocument, loadPolicyYaml } from '../src/policy/loader.js';
import { ScrutexityError } from '../src/errors.js';
import { parseMoney } from '../src/money.js';
import { signal, treasuryPolicy } from './fixtures.js';

const input = (overrides: Record<string, unknown> = {}) =>
  ({
    action: 'wire.execute',
    agent: { id: 'agent_treasury', handle: 'treasury-agent' },
    resource: { type: 'bank_account', id: 'acct_001', attributes: {} },
    context: {
      amount: parseMoney('25000', 'USD'),
      currency: 'USD',
      counterparty_id: 'cp_100',
      counterparty_known: true,
      destination_country: 'US',
    } as Record<string, unknown>,
    authority: { present: true, lease_id: null, depth: null },
    signals: [],
    ...overrides,
  }) as Parameters<typeof evaluatePolicy>[1];

describe('policy document validation', () => {
  it('loads the shipped treasury pack', () => {
    expect(treasuryPolicy.id).toBe('treasury_wire');
    expect(treasuryPolicy.rules.length).toBeGreaterThan(5);
  });

  it('is hash-stable across equivalent serialisations', () => {
    const once = policyHash(treasuryPolicy);
    const again = loadPolicyDocument(JSON.parse(JSON.stringify(treasuryPolicy))).hash;
    expect(again).toBe(once);
  });

  it('rejects an unknown selector rather than silently never matching', () => {
    expect(() =>
      loadPolicyYaml(`
apiVersion: scrutexity.dev/policy/v1
id: bad_policy
version: 1.0.0
metadata: { title: Bad }
rules:
  - id: typo_rule
    when: { contxt.amount: { gte: 1 } }
    then: { decision: ALLOW }
`),
    ).toThrow(ScrutexityError);
  });

  it('rejects an escalation with no approver', () => {
    expect(() =>
      loadPolicyYaml(`
apiVersion: scrutexity.dev/policy/v1
id: bad_policy
version: 1.0.0
metadata: { title: Bad }
rules:
  - id: dangling_escalation
    when: { action: wire.execute }
    then: { decision: ESCALATE }
`),
    ).toThrow(/names no approval requirement/);
  });

  it('rejects duplicate rule ids', () => {
    expect(() =>
      loadPolicyYaml(`
apiVersion: scrutexity.dev/policy/v1
id: bad_policy
version: 1.0.0
metadata: { title: Bad }
rules:
  - id: same_id
    when: { action: a.b }
    then: { decision: ALLOW }
  - id: same_id
    when: { action: c.d }
    then: { decision: ALLOW }
`),
    ).toThrow(/duplicate rule id/);
  });

  it('defaults to DENY and FAIL_CLOSED when the author says nothing', () => {
    const { document } = loadPolicyYaml(`
apiVersion: scrutexity.dev/policy/v1
id: minimal
version: 1.0.0
metadata: { title: Minimal }
rules:
  - id: only_rule
    when: { action: ping.read }
    then: { decision: ALLOW }
`);
    expect(document.defaults.decision).toBe('DENY');
    expect(document.failure_modes.policy_unavailable).toBe('FAIL_CLOSED');
    expect(document.defaults.execution_grant_ttl_seconds).toBe(300);
  });
});

describe('policy evaluation', () => {
  it('is deterministic for identical inputs', () => {
    const a = evaluatePolicy(treasuryPolicy, input());
    const b = evaluatePolicy(treasuryPolicy, input());
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it('allows a routine low-value wire', () => {
    const outcome = evaluatePolicy(
      treasuryPolicy,
      input({ context: { ...input().context, amount: parseMoney('5000', 'USD') } }),
    );
    expect(outcome.decision).toBe('ALLOW');
    expect(outcome.reason_code).toBe('BELOW_AUTONOMOUS_THRESHOLD');
  });

  it('allows a mid-value wire under a lease', () => {
    const outcome = evaluatePolicy(treasuryPolicy, input());
    expect(outcome.decision).toBe('ALLOW');
    expect(outcome.matched_rule_ids).toEqual(['wire_ten_to_fifty_thousand']);
  });

  it('escalates to the treasurer above fifty thousand', () => {
    const outcome = evaluatePolicy(
      treasuryPolicy,
      input({ context: { ...input().context, amount: parseMoney('250000', 'USD') } }),
    );
    expect(outcome.decision).toBe('ESCALATE');
    expect(outcome.reason_code).toBe('TREASURER_APPROVAL_REQUIRED');
    expect(outcome.approval_requirement).toMatchObject({ quorum: 1, roles: ['treasurer'] });
  });

  it('merges layered thresholds into the stricter requirement above a million', () => {
    const outcome = evaluatePolicy(
      treasuryPolicy,
      input({ context: { ...input().context, amount: parseMoney('2000000', 'USD') } }),
    );
    expect(outcome.decision).toBe('ESCALATE');
    // Both the >=50k and the >=1M rules matched; the requirement is the union.
    expect(outcome.matched_rule_ids).toEqual([
      'wire_fifty_thousand_and_above',
      'wire_one_million_and_above',
    ]);
    expect(outcome.approval_requirement).toMatchObject({ quorum: 2, roles: ['cfo', 'treasurer'] });
    // The most specific matched rule names the reason.
    expect(outcome.reason_code).toBe('TREASURER_AND_CFO_APPROVAL_REQUIRED');
    // The shortest window wins, not the longest.
    expect(outcome.approval_requirement?.ttl_seconds).toBe(3600);
  });

  it('lets a DENY override a matched ALLOW at the same evaluation', () => {
    const outcome = evaluatePolicy(
      treasuryPolicy,
      input({
        context: {
          ...input().context,
          amount: parseMoney('5000', 'USD'),
          counterparty_known: false,
        },
      }),
    );
    expect(outcome.decision).toBe('DENY');
    expect(outcome.reason_code).toBe('UNKNOWN_COUNTERPARTY');
    expect(outcome.matched_rule_ids).toContain('wire_under_ten_thousand');
  });

  it('denies a sanctioned destination outright', () => {
    const outcome = evaluatePolicy(
      treasuryPolicy,
      input({
        context: {
          ...input().context,
          amount: parseMoney('100', 'USD'),
          destination_country: 'KP',
        },
      }),
    );
    expect(outcome.decision).toBe('DENY');
    expect(outcome.reason_code).toBe('SANCTIONED_DESTINATION');
  });

  it('falls through to the default DENY when no rule matches', () => {
    const outcome = evaluatePolicy(treasuryPolicy, input({ action: 'ledger.close' }));
    expect(outcome.decision).toBe('DENY');
    expect(outcome.reason_code).toBe('NO_RULE_MATCHED');
    expect(outcome.matched_rule_ids).toEqual([]);
  });

  it('reads a live fraud signal and emits the matching authority effect', () => {
    const outcome = evaluatePolicy(treasuryPolicy, input({ signals: [signal()] }));
    expect(outcome.decision).toBe('ESCALATE');
    expect(outcome.reason_code).toBe('FRAUD_RISK_HUMAN_REVIEW');
    expect(outcome.authority_effects[0]).toMatchObject({
      rule_id: 'elevated_fraud_risk',
      duration_seconds: 600,
    });
    expect(outcome.consulted_signal_ids).toEqual(['sig_1']);
  });

  it('ignores a signal about a different agent', () => {
    const outcome = evaluatePolicy(
      treasuryPolicy,
      input({ signals: [signal({ subject_id: 'agent_someone_else' })] }),
    );
    expect(outcome.decision).toBe('ALLOW');
    expect(outcome.consulted_signal_ids).toEqual([]);
  });

  it('takes the most severe live signal when sources disagree', () => {
    const outcome = evaluatePolicy(
      treasuryPolicy,
      input({
        signals: [
          signal({ id: 'sig_low', value: '0.10', source: 'internal' }),
          signal({ id: 'sig_high', value: '0.97', source: 'external_fraud_engine' }),
        ],
      }),
    );
    expect(outcome.decision).toBe('ESCALATE');
    expect(outcome.consulted_signal_ids).toEqual(['sig_high']);
  });

  it('compares the fraud threshold exactly at the boundary', () => {
    const at = evaluatePolicy(treasuryPolicy, input({ signals: [signal({ value: '0.9' })] }));
    const below = evaluatePolicy(
      treasuryPolicy,
      input({ signals: [signal({ value: '0.8999999' })] }),
    );
    expect(at.decision).toBe('ESCALATE');
    expect(below.decision).toBe('ALLOW');
  });

  it('escalates when the agent reports low confidence in itself', () => {
    const outcome = evaluatePolicy(
      treasuryPolicy,
      input({ signals: [signal({ signal_type: 'model_confidence', value: '0.4' })] }),
    );
    expect(outcome.reason_code).toBe('LOW_MODEL_CONFIDENCE');
  });

  it('does not match a numeric comparison against a missing value', () => {
    const outcome = evaluatePolicy(
      treasuryPolicy,
      input({ context: { counterparty_known: true } }),
    );
    // No amount at all: none of the amount rules may fire, so the default holds.
    expect(outcome.matched_rule_ids).toEqual([]);
    expect(outcome.decision).toBe('DENY');
  });
});

describe('decision algebra', () => {
  it('orders DENY above ESCALATE above ALLOW', () => {
    expect(strictest('ALLOW', 'ESCALATE')).toBe('ESCALATE');
    expect(strictest('ESCALATE', 'DENY')).toBe('DENY');
    expect(strictest('DENY', 'ALLOW')).toBe('DENY');
  });

  it('merges approval requirements only in the more-demanding direction', () => {
    const merged = mergeApprovalRequirements([
      {
        required: true,
        quorum: 1,
        roles: ['treasurer'],
        forbid_self_approval: false,
        ttl_seconds: 7200,
      },
      { required: true, quorum: 2, roles: ['cfo'], forbid_self_approval: true, ttl_seconds: 1800 },
    ]);
    expect(merged).toEqual({
      required: true,
      quorum: 2,
      roles: ['cfo', 'treasurer'],
      forbid_self_approval: true,
      ttl_seconds: 1800,
    });
  });

  it('raises quorum to cover every distinct required role', () => {
    const merged = mergeApprovalRequirements([
      {
        required: true,
        quorum: 1,
        roles: ['treasurer', 'cfo'],
        forbid_self_approval: true,
        ttl_seconds: 3600,
      },
    ]);
    expect(merged?.quorum).toBe(2);
  });
});
