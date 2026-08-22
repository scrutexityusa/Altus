import { describe, expect, it } from 'vitest';
import {
  containsGrant,
  coversAttempt,
  restrictGrant,
  type AuthorityGrant,
  type Constraints,
} from '../src/authority/grant.js';
import { authorizeDelegation } from '../src/delegation.js';
import { evaluateAuthorization } from '../src/evaluate.js';
import { parseMoney } from '../src/money.js';
import { lease, snapshot, treasuryPolicy, T0 } from './fixtures.js';

/**
 * Containment is a property of the authority lattice, not of any one policy.
 * The treasury pack forbids delegating money-moving actions at all, which
 * would mask the lattice behind a policy check, so these tests use a policy
 * that permits everything and lets containment do the work alone.
 */
const permissivePolicy = {
  ...treasuryPolicy,
  delegation: { ...treasuryPolicy.delegation, max_depth: 5, non_delegable_actions: [] },
};

/**
 * Randomised invariant tests. These are not scenario tests: they generate
 * thousands of grants and delegation proposals and assert the properties that
 * must hold for every one of them. A counterexample here is a security bug,
 * not a failing expectation.
 */

// Deterministic PRNG so a failure is reproducible from the seed alone.
function rng(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0;
    return state / 0x1_0000_0000;
  };
}

const ACTIONS = [
  'wire.create',
  'wire.submit',
  'wire.execute',
  'wire.modify',
  'counterparty.read',
  'account.read',
];
const WILDCARDS = ['wire.*', '*', 'counterparty.*'];
const ACCOUNTS = ['acct_001', 'acct_002', 'acct_003', '*'];
const COUNTERPARTIES = ['cp_100', 'cp_101', 'cp_102', '*'];
const CURRENCIES = ['USD', 'EUR', 'JPY'];
const AMOUNTS = ['0', '100', '1000', '50000', '1000000'];

function pickSome<T>(random: () => number, pool: readonly T[], min = 0): T[] {
  const chosen = pool.filter(() => random() < 0.5);
  while (chosen.length < min) chosen.push(pool[Math.floor(random() * pool.length)]!);
  return [...new Set(chosen)];
}

function randomGrant(random: () => number): AuthorityGrant {
  const actions = pickSome(random, random() < 0.2 ? [...ACTIONS, ...WILDCARDS] : ACTIONS, 1);
  const resources: Record<string, string[]> = {};
  if (random() < 0.85) resources['bank_account'] = pickSome(random, ACCOUNTS, 1);
  if (random() < 0.85) resources['counterparty'] = pickSome(random, COUNTERPARTIES, 1);
  const constraints: Constraints = {};
  if (random() < 0.8) {
    constraints.max_amount = parseMoney(
      AMOUNTS[Math.floor(random() * AMOUNTS.length)]!,
      CURRENCIES[Math.floor(random() * (random() < 0.9 ? 1 : CURRENCIES.length))]!,
    );
  }
  if (random() < 0.7) constraints.currencies = pickSome(random, CURRENCIES, 1);
  if (random() < 0.7) constraints.allowed_counterparties = pickSome(random, COUNTERPARTIES, 1);
  if (random() < 0.3)
    constraints.denied_counterparties = pickSome(random, COUNTERPARTIES.slice(0, 3), 1);
  return { actions, resources, constraints };
}

/**
 * Produces a plausible delegation ask from a parent grant: usually a genuine
 * narrowing, sometimes a mutation designed to widen one axis. Purely random
 * grants almost never form a valid pair, so without this the success path
 * would go unexercised and the invariant would prove nothing.
 */
function derivedGrant(random: () => number, parent: AuthorityGrant): AuthorityGrant {
  const actions = parent.actions.filter(() => random() < 0.6);
  const resources: Record<string, string[]> = {};
  for (const [type, ids] of Object.entries(parent.resources)) {
    if (random() < 0.3) continue;
    const kept = ids.filter(() => random() < 0.7);
    resources[type] = kept.length > 0 ? kept : [ids[0]!];
  }
  const constraints: Constraints = { ...parent.constraints };
  if (parent.constraints.max_amount && random() < 0.6) {
    constraints.max_amount = parseMoney('100', parent.constraints.max_amount.currency);
  }

  const child: AuthorityGrant = {
    actions: actions.length > 0 ? actions : [parent.actions[0]!],
    resources,
    constraints,
  };

  // Adversarial mutations: each one must be caught by containment.
  const mutation = random();
  if (mutation < 0.08) child.actions = [...child.actions, 'ledger.close'];
  else if (mutation < 0.16) child.resources = { ...child.resources, ledger: ['*'] };
  else if (mutation < 0.24)
    child.constraints = { ...constraints, max_amount: parseMoney('1000000', 'USD') };
  else if (mutation < 0.32) delete child.constraints.max_amount;
  else if (mutation < 0.4) child.constraints = { ...constraints, allowed_counterparties: ['*'] };
  else if (mutation < 0.46) child.actions = ['*'];
  return child;
}

describe('invariant: child authority never exceeds parent authority', () => {
  it('holds for 4000 random delegation proposals', () => {
    const random = rng(20260301);
    let authorized = 0;
    for (let i = 0; i < 4000; i++) {
      const parentGrant = randomGrant(random);
      const requested = random() < 0.75 ? derivedGrant(random, parentGrant) : randomGrant(random);
      const parent = lease({ grant: parentGrant });
      const result = authorizeDelegation(
        {
          issuer_agent_id: parent.agent_id,
          delegate_agent_id: 'agent_delegate',
          requested_grant: requested,
          requested_ttl_seconds: 600,
        },
        { now: T0, parent_lease: parent, parent_chain: [parent], policy: permissivePolicy },
      );
      if (result.ok) {
        authorized++;
        const containment = containsGrant(parentGrant, result.child_grant);
        expect(
          containment.contained,
          `iteration ${i}: ${JSON.stringify({ parentGrant, requested })}`,
        ).toBe(true);
      }
    }
    // The generator must actually exercise the success path.
    expect(authorized).toBeGreaterThan(50);
  });

  it('holds transitively: anything the child can do, the parent could have done', () => {
    const random = rng(777);
    for (let i = 0; i < 3000; i++) {
      const parentGrant = randomGrant(random);
      const childGrant = randomGrant(random);
      if (!containsGrant(parentGrant, childGrant).contained) continue;

      const attempt = {
        action: ACTIONS[Math.floor(random() * ACTIONS.length)]!,
        resourceType: random() < 0.5 ? 'bank_account' : 'counterparty',
        resourceId: ACCOUNTS[Math.floor(random() * 3)]!,
        context: {
          amount: parseMoney(AMOUNTS[Math.floor(random() * AMOUNTS.length)]!, 'USD'),
          currency: 'USD',
          counterparty_id: COUNTERPARTIES[Math.floor(random() * 3)]!,
        } as Record<string, unknown>,
      };
      if (coversAttempt(childGrant, attempt).covered) {
        expect(
          coversAttempt(parentGrant, attempt).covered,
          `iteration ${i}: child covered an attempt its parent does not: ${JSON.stringify({ parentGrant, childGrant, attempt })}`,
        ).toBe(true);
      }
    }
  });
});

describe('invariant: decay only ever shrinks authority', () => {
  it('holds for 2000 random restrictions', () => {
    const random = rng(4242);
    for (let i = 0; i < 2000; i++) {
      const base = randomGrant(random);
      const decayed = restrictGrant(base, {
        remove_actions: pickSome(random, [...ACTIONS, ...WILDCARDS]),
        tighten: randomGrant(random).constraints,
      });
      expect(
        containsGrant(base, decayed).contained,
        `iteration ${i}: ${JSON.stringify(base)}`,
      ).toBe(true);
    }
  });
});

/**
 * ---------------------------------------------------------------------------
 * G-5, containment layer.
 * ---------------------------------------------------------------------------
 *
 * The property above proves that `restrictGrant` narrows. This one proves the
 * thing that actually matters at the boundary: that no *signal* -- of any type,
 * at any value, from any source, in any combination -- can make a decision more
 * permissive than the same decision with no signals at all.
 *
 * That is the layer that survives a compromised issuer. The cryptography
 * assumes an attacker cannot sign; this assumes they can, and holds anyway. So
 * it is asserted here, over randomised input, rather than in a handful of
 * scenario tests that only cover the signal values somebody thought of.
 */
const SIGNAL_TYPES = [
  'fraud_risk',
  'counterparty_risk',
  'model_confidence',
  'anomaly_score',
  // A type no rule reads. A signal the policy has no opinion about must be
  // inert, not a default of any kind.
  'unrecognised_reading',
];
const SIGNAL_VALUES = ['0', '0.0001', '0.5', '0.9', '1', '9999', '-1'];

/** Strictest first. A decision may move down this list under a signal, never up. */
const PERMISSIVENESS = ['DENY', 'ESCALATE', 'ALLOW'];

function randomSignals(random: () => number, agentId: string, counterpartyId: string) {
  const count = Math.floor(random() * 4);
  return Array.from({ length: count }, (_unused, index) => {
    const signalType = SIGNAL_TYPES[Math.floor(random() * SIGNAL_TYPES.length)]!;
    const onCounterparty = signalType === 'counterparty_risk';
    return {
      id: `sig_${index}`,
      subject_type: (onCounterparty ? 'counterparty' : 'agent') as 'counterparty' | 'agent',
      subject_id: onCounterparty ? counterpartyId : agentId,
      signal_type: signalType,
      value: SIGNAL_VALUES[Math.floor(random() * SIGNAL_VALUES.length)]!,
      confidence: random() < 0.5 ? '1' : '0.5',
      source: random() < 0.5 ? 'external_fraud_engine' : 'agent_self_report',
      issued_at: new Date(T0.getTime() - 60_000).toISOString(),
      expires_at: new Date(T0.getTime() + 600_000).toISOString(),
    };
  });
}

describe('invariant: a signal can only ever subtract authority', () => {
  it('holds over 1500 randomised signal sets', () => {
    const random = rng(90_210);
    for (let i = 0; i < 1500; i++) {
      const counterpartyId = COUNTERPARTIES[Math.floor(random() * 3)]!;
      const amount = AMOUNTS[Math.floor(random() * AMOUNTS.length)]!;
      const resourceId = ACCOUNTS[Math.floor(random() * 3)]!;
      const candidate = lease({ grant: randomGrant(random) });
      const base = {
        amount,
        action: 'wire.execute',
        resourceId,
        counterpartyId,
        candidates: [{ lease: candidate, chain: [candidate] }],
      };

      const without = evaluateAuthorization(snapshot(base));
      const withSignals = evaluateAuthorization(
        snapshot({ ...base, signals: randomSignals(random, 'agent_treasury', counterpartyId) }),
      );

      const context = () => `iteration ${i}: ${JSON.stringify({ candidate, amount })}`;

      // 1. The decision never becomes more permissive.
      expect(
        PERMISSIVENESS.indexOf(withSignals.decision) <= PERMISSIVENESS.indexOf(without.decision),
        `${context()}: ${without.decision} became ${withSignals.decision} under a signal`,
      ).toBe(true);

      // 2. The effective grant is still contained by the authority actually
      //    held. A decision that stayed the same while the grant behind it
      //    widened is a defect waiting for the next request.
      for (const finding of withSignals.evaluation.authority_findings) {
        expect(
          containsGrant(candidate.grant, finding.effective_grant).contained,
          `${context()}: signal widened the effective grant`,
        ).toBe(true);
      }
    }
  });
});

describe('regression: a signal cannot make a refusal approvable (G-5)', () => {
  /**
   * The concrete case the randomised property found, pinned so the fix cannot
   * regress silently. A lease denominated in EUR does not cover a USD wire, so
   * the request is refused outright: the policy's ordinary rule for this action
   * names no approver, and nobody can supply the difference.
   *
   * Then the fraud engine -- which we assume is fully compromised, holding a
   * key Scrutexity correctly trusts -- asserts a fraud score above the
   * escalation threshold. That rule *does* name a treasurer. Before the fix,
   * the shortfall became something a treasurer could approve: asserting more
   * risk produced a more permissive outcome, and the approver became a
   * confused deputy for an action the agent's authority never covered.
   */
  const eurOnlyLease = () =>
    lease({
      grant: {
        actions: ['wire.execute'],
        resources: { bank_account: ['acct_001'], counterparty: ['cp_100'] },
        constraints: {
          max_amount: parseMoney('1000000', 'EUR'),
          currencies: ['EUR'],
          allowed_counterparties: ['cp_100'],
        },
      },
    });

  const evaluateWith = (signals: Parameters<typeof snapshot>[0]['signals']) => {
    const candidate = eurOnlyLease();
    return evaluateAuthorization(
      snapshot({
        action: 'wire.execute',
        amount: '100',
        currency: 'USD',
        resourceId: 'acct_001',
        counterpartyId: 'cp_100',
        candidates: [{ lease: candidate, chain: [candidate] }],
        ...(signals ? { signals } : {}),
      }),
    );
  };

  const highFraudSignal = [
    {
      id: 'sig_fraud',
      subject_type: 'agent' as const,
      subject_id: 'agent_treasury',
      signal_type: 'fraud_risk',
      value: '0.99',
      confidence: '1',
      source: 'external_fraud_engine',
      issued_at: new Date(T0.getTime() - 60_000).toISOString(),
      expires_at: new Date(T0.getTime() + 600_000).toISOString(),
    },
  ];

  it('denies the uncovered request with no signal present', () => {
    const result = evaluateWith(undefined);
    expect(result.decision).toBe('DENY');
    expect(result.approval_requirement).toBeNull();
  });

  it('still denies it when a trusted source asserts maximum risk', () => {
    const result = evaluateWith(highFraudSignal);
    expect(result.decision).toBe('DENY');
    // And no approval requirement is published, so nothing downstream can
    // present a treasurer with a request to approve.
    expect(result.approval_requirement).toBeNull();
  });

  it('still lets a signal escalate something policy already permitted', () => {
    // The positive control. Without it, the two assertions above would also
    // pass if signals had simply been made inert, which would remove authority
    // decay -- the feature the signal plane exists for.
    const covering = lease();
    const result = evaluateAuthorization(
      snapshot({
        action: 'wire.execute',
        amount: '100',
        resourceId: 'acct_001',
        counterpartyId: 'cp_100',
        candidates: [{ lease: covering, chain: [covering] }],
        signals: highFraudSignal,
      }),
    );
    expect(result.decision).toBe('ESCALATE');
    expect(result.approval_requirement).not.toBeNull();
  });
});

describe('invariant: expired and revoked authority never authorizes', () => {
  it('holds across every action in the catalog', () => {
    for (const action of ['wire.execute', 'wire.create', 'counterparty.read', 'account.read']) {
      for (const broken of [
        lease({ expires_at: new Date(T0.getTime() - 1).toISOString() }),
        lease({ status: 'REVOKED', revoked_at: T0.toISOString() }),
        lease({ status: 'SUSPENDED' }),
      ]) {
        const result = evaluateAuthorization(
          snapshot({
            action,
            amount: '100',
            resourceType: action.startsWith('counterparty') ? 'counterparty' : 'bank_account',
            resourceId: action.startsWith('counterparty') ? 'cp_100' : 'acct_001',
            candidates: [{ lease: broken, chain: [broken] }],
          }),
        );
        expect(result.decision, `${action} under ${broken.status}`).toBe('DENY');
      }
    }
  });
});

describe('invariant: identical inputs produce identical decisions', () => {
  it('holds over randomised requests', () => {
    const random = rng(90210);
    for (let i = 0; i < 300; i++) {
      const options = {
        amount: AMOUNTS[Math.floor(random() * AMOUNTS.length)]!,
        action: random() < 0.5 ? 'wire.execute' : 'wire.create',
        counterpartyKnown: random() < 0.9,
        destinationCountry: random() < 0.95 ? 'US' : 'KP',
      };
      const a = evaluateAuthorization(snapshot(options));
      const b = evaluateAuthorization(snapshot(options));
      expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    }
  });
});

describe('invariant: an ALLOW is never issued without covering authority', () => {
  it('holds over randomised leases and requests', () => {
    const random = rng(31337);
    for (let i = 0; i < 2000; i++) {
      const candidate = lease({ grant: randomGrant(random) });
      const amount = AMOUNTS[Math.floor(random() * AMOUNTS.length)]!;
      const result = evaluateAuthorization(
        snapshot({
          amount,
          action: 'wire.execute',
          resourceId: ACCOUNTS[Math.floor(random() * 3)]!,
          counterpartyId: COUNTERPARTIES[Math.floor(random() * 3)]!,
          candidates: [{ lease: candidate, chain: [candidate] }],
        }),
      );
      if (result.decision === 'ALLOW') {
        const finding = result.evaluation.authority_findings.find(
          (f) => f.lease_id === result.authority_lease_id,
        );
        expect(finding?.autonomous, `iteration ${i}: allowed without autonomous authority`).toBe(
          true,
        );
        expect(finding?.chain.usable).toBe(true);
      }
    }
  });
});
