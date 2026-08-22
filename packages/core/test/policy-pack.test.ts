import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadPolicyYaml } from '../src/policy/loader.js';
import { evaluateAuthorization } from '../src/evaluate.js';
import { parseMoney } from '../src/money.js';
import type { PolicyDocument } from '../src/policy/schema.js';
import { lease, snapshot, T0, type SnapshotOptions } from './fixtures.js';

/**
 * ============================================================================
 * The design-partner treasury policy pack.
 * ============================================================================
 *
 * `policies/treasury-wire.yaml` is handed to a design partner as the file they
 * copy and edit. It is not the reference tenant's policy -- that is
 * `treasury_wire.yaml`, with an underscore, which the seed and the demo use.
 *
 * Two policy files could drift into disagreeing about what "the treasury
 * ladder" means, so this asserts the starter pack's behaviour directly rather
 * than trusting that it still resembles its sibling. A partner who edits a
 * threshold and breaks a tier boundary finds out here, by name.
 *
 * Documented in docs/design-partner/policy-pack-treasury.md, and the tier
 * table in that document is what these cases pin.
 */

const starterPack: PolicyDocument = loadPolicyYaml(
  readFileSync(
    fileURLToPath(new URL('../../../policies/treasury-wire.yaml', import.meta.url)),
    'utf8',
  ),
).document;

/**
 * A lease wide enough that the *policy* is what decides every case below.
 * Anything narrower and a DENY could be the lease refusing rather than the
 * tier, and the test would pass for the wrong reason.
 */
const wideLease = () =>
  lease({
    grant: {
      actions: ['wire.create', 'wire.submit', 'wire.execute', 'wire.read', 'counterparty.read'],
      resources: { bank_account: ['acct_001'], counterparty: ['cp_100'] },
      constraints: {
        max_amount: parseMoney('10000000', 'USD'),
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    },
  });

function decide(options: SnapshotOptions = {}) {
  const candidate = wideLease();
  return evaluateAuthorization(
    snapshot({
      policy: starterPack,
      action: 'wire.execute',
      resourceId: 'acct_001',
      counterpartyId: 'cp_100',
      candidates: [{ lease: candidate, chain: [candidate] }],
      ...options,
    }),
  );
}

const liveSignal = (signalType: string, value: string, subjectType: 'agent' | 'counterparty') => [
  {
    id: `sig_${signalType}`,
    subject_type: subjectType,
    subject_id: subjectType === 'agent' ? 'agent_treasury' : 'cp_100',
    signal_type: signalType,
    value,
    confidence: '1',
    source: 'external_fraud_engine',
    issued_at: new Date(T0.getTime() - 60_000).toISOString(),
    expires_at: new Date(T0.getTime() + 600_000).toISOString(),
  },
];

describe('the starter pack is a valid policy document', () => {
  it('parses and declares what the documentation says it declares', () => {
    expect(starterPack.id).toBe('treasury_wire_starter');
    expect(starterPack.defaults.decision).toBe('DENY');
    expect(starterPack.issuance.enforced).toBe(true);
  });

  it('fails closed on every dependency', () => {
    // A control-plane outage must never become an authorization. All three,
    // asserted individually so that weakening one is a visible diff.
    expect(starterPack.failure_modes.policy_unavailable).toBe('FAIL_CLOSED');
    expect(starterPack.failure_modes.signal_unavailable).toBe('FAIL_CLOSED');
    expect(starterPack.failure_modes.enforcement_unavailable).toBe('FAIL_CLOSED');
  });

  it('never permits a financial action to be delegated', () => {
    for (const action of ['wire.create', 'wire.modify', 'wire.submit', 'wire.execute']) {
      expect(starterPack.delegation.non_delegable_actions).toContain(action);
    }
  });

  it('lets a treasurer issue nothing that can pay', () => {
    // A treasurer approves; they do not provision. The $0 ceiling is the
    // control, not a placeholder.
    const treasurer = starterPack.issuance.ceilings.find((c) => c.role === 'treasurer');
    expect(treasurer).toBeDefined();
    expect(treasurer!.grant.actions).not.toContain('wire.execute');
    expect(treasurer!.grant.constraints.max_amount?.amountMinor).toBe('0');
  });
});

describe('the amount ladder', () => {
  // The table in policy-pack-treasury.md, executed.
  const tiers = [
    { amount: '9999.99', decision: 'ALLOW', reason: 'BELOW_AUTONOMOUS_THRESHOLD' },
    { amount: '10000.00', decision: 'ALLOW', reason: 'WITHIN_LEASED_AUTHORITY' },
    { amount: '49999.99', decision: 'ALLOW', reason: 'WITHIN_LEASED_AUTHORITY' },
    { amount: '50000.00', decision: 'ESCALATE', reason: 'TREASURER_APPROVAL_REQUIRED' },
    { amount: '999999.99', decision: 'ESCALATE', reason: 'TREASURER_APPROVAL_REQUIRED' },
    { amount: '1000000.00', decision: 'ESCALATE', reason: 'TREASURER_AND_CFO_APPROVAL_REQUIRED' },
  ] as const;

  for (const tier of tiers) {
    it(`$${tier.amount} is ${tier.decision} (${tier.reason})`, () => {
      const result = decide({ amount: tier.amount });
      expect(result.decision).toBe(tier.decision);
      expect(result.reason_code).toBe(tier.reason);
    });
  }

  it('requires one treasurer between $50k and $1M', () => {
    const result = decide({ amount: '75000.00' });
    expect(result.approval_requirement).toMatchObject({
      quorum: 1,
      roles: ['treasurer'],
      forbid_self_approval: true,
    });
  });

  it('requires two approvers at $1M without the tier-4 rule restating tier 3', () => {
    // Both rules match a seven-figure wire. Approval requirements merge in the
    // more-demanding direction, so quorum 2 across {treasurer, cfo} falls out
    // of the merge rather than being repeated in the policy -- which is why
    // the tier-4 rule is as short as it is.
    const result = decide({ amount: '2000000.00' });
    expect(result.approval_requirement?.quorum).toBe(2);
    expect([...(result.approval_requirement?.roles ?? [])].sort()).toEqual(['cfo', 'treasurer']);
  });
});

describe('counterparty controls', () => {
  it('refuses an unregistered counterparty outright, at any amount', () => {
    // DENY rather than ESCALATE: a new counterparty is the highest signal of a
    // compromised agent and also the case a tired approver waves through.
    for (const amount of ['100.00', '9000.00', '2000000.00']) {
      const result = decide({ amount, counterpartyKnown: false });
      expect(result.decision, amount).toBe('DENY');
      expect(result.reason_code, amount).toBe('UNKNOWN_COUNTERPARTY');
    }
  });

  it('refuses a sanctioned destination outright', () => {
    const result = decide({ amount: '100.00', destinationCountry: 'KP' });
    expect(result.decision).toBe('DENY');
    expect(result.reason_code).toBe('SANCTIONED_DESTINATION');
  });

  it('lets a read through that a wire would not get', () => {
    const result = decide({
      action: 'counterparty.read',
      resourceType: 'counterparty',
      resourceId: 'cp_100',
    });
    expect(result.decision).toBe('ALLOW');
    expect(result.reason_code).toBe('READ_ONLY_ACTION');
  });
});

describe('signals reduce authority and never expand it', () => {
  it('turns an unattended payment into a human review under fraud risk', () => {
    const baseline = decide({ amount: '25000.00' });
    expect(baseline.decision).toBe('ALLOW');

    const underRisk = decide({
      amount: '25000.00',
      signals: liveSignal('fraud_risk', '0.97', 'agent'),
    });
    expect(underRisk.decision).toBe('ESCALATE');
    expect(underRisk.reason_code).toBe('AUTHORITY_DECAYED');
  });

  it('pulls a human in for a risky counterparty regardless of amount', () => {
    const result = decide({
      amount: '100.00',
      signals: liveSignal('counterparty_risk', '0.9', 'counterparty'),
    });
    expect(result.decision).toBe('ESCALATE');
  });

  it('does not let a self-reported high confidence widen anything', () => {
    // The rule only reads model_confidence in the narrowing direction, so a
    // confident agent gets exactly what an unremarked one gets -- never more.
    const silent = decide({ amount: '25000.00' });
    const confident = decide({
      amount: '25000.00',
      signals: liveSignal('model_confidence', '1', 'agent'),
    });
    expect(confident.decision).toBe(silent.decision);
    expect(confident.reason_code).toBe(silent.reason_code);
  });

  it('cannot make a refused payment approvable', () => {
    // G-19. Every signal the pack reads, against a request policy refuses on
    // its merits. A signal source holding a valid key must not be able to
    // summon an approval request for it.
    for (const signal of [
      liveSignal('fraud_risk', '0.97', 'agent'),
      liveSignal('counterparty_risk', '0.9', 'counterparty'),
      liveSignal('model_confidence', '0.1', 'agent'),
    ]) {
      const result = decide({ amount: '25000.00', counterpartyKnown: false, signals: signal });
      expect(result.decision).toBe('DENY');
      expect(result.approval_requirement).toBeNull();
    }
  });
});

describe('nothing a rule did not permit', () => {
  it('denies an action no rule mentions', () => {
    const result = decide({ action: 'statement.export' });
    expect(result.decision).toBe('DENY');
  });
});
