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

const ACTIONS = ['wire.create', 'wire.submit', 'wire.execute', 'wire.modify', 'counterparty.read', 'account.read'];
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
  if (random() < 0.3) constraints.denied_counterparties = pickSome(random, COUNTERPARTIES.slice(0, 3), 1);
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
  else if (mutation < 0.24) child.constraints = { ...constraints, max_amount: parseMoney('1000000', 'USD') };
  else if (mutation < 0.32) delete child.constraints.max_amount;
  else if (mutation < 0.40) child.constraints = { ...constraints, allowed_counterparties: ['*'] };
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
        expect(containment.contained, `iteration ${i}: ${JSON.stringify({ parentGrant, requested })}`).toBe(true);
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
      expect(containsGrant(base, decayed).contained, `iteration ${i}: ${JSON.stringify(base)}`).toBe(true);
    }
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
        expect(finding?.autonomous, `iteration ${i}: allowed without autonomous authority`).toBe(true);
        expect(finding?.chain.usable).toBe(true);
      }
    }
  });
});
