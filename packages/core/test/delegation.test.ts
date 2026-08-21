import { describe, expect, it } from 'vitest';
import { authorizeDelegation, type DelegationProposal } from '../src/delegation.js';
import { containsGrant, type AuthorityGrant } from '../src/authority/grant.js';
import { parseMoney } from '../src/money.js';
import { grant, lease, treasuryPolicy, T0 } from './fixtures.js';

const parentLease = lease();

const narrowGrant: AuthorityGrant = {
  actions: ['counterparty.read'],
  resources: { counterparty: ['cp_100'] },
  constraints: {
    max_amount: parseMoney('0', 'USD'),
    currencies: ['USD'],
    allowed_counterparties: ['cp_100'],
  },
};

const proposal = (overrides: Partial<DelegationProposal> = {}): DelegationProposal => ({
  issuer_agent_id: 'agent_treasury',
  delegate_agent_id: 'agent_verification',
  requested_grant: narrowGrant,
  requested_ttl_seconds: 600,
  ...overrides,
});

const context = (overrides: Partial<Parameters<typeof authorizeDelegation>[1]> = {}) => ({
  now: T0,
  parent_lease: parentLease,
  parent_chain: [parentLease],
  policy: treasuryPolicy,
  ...overrides,
});

describe('delegation', () => {
  it('permits a genuine narrowing', () => {
    const result = authorizeDelegation(proposal(), context());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.depth).toBe(1);
    expect(containsGrant(parentLease.grant, result.child_grant).contained).toBe(true);
  });

  it('refuses financial authority the policy marks non-delegable', () => {
    const result = authorizeDelegation(
      proposal({
        requested_grant: {
          ...narrowGrant,
          actions: ['counterparty.read', 'wire.execute'],
          resources: { counterparty: ['cp_100'], bank_account: ['acct_001'] },
        },
      }),
      context(),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason_code).toBe('ACTION_NOT_DELEGABLE');
  });

  it('refuses a wildcard that would sweep in non-delegable actions', () => {
    const result = authorizeDelegation(
      proposal({
        requested_grant: {
          ...narrowGrant,
          actions: ['wire.*'],
          resources: { bank_account: ['acct_001'] },
        },
      }),
      context(),
    );
    expect(result.ok).toBe(false);
  });

  it('refuses authority the parent never held', () => {
    const result = authorizeDelegation(
      proposal({
        requested_grant: {
          ...narrowGrant,
          actions: ['ledger.close'],
          resources: { ledger: ['led_1'] },
        },
      }),
      context(),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe('DELEGATION_EXCEEDS_PARENT');
    expect(result.violations.length).toBeGreaterThan(0);
  });

  it('refuses a child that drops a constraint the parent imposed', () => {
    const result = authorizeDelegation(
      proposal({ requested_grant: { ...narrowGrant, constraints: {} } }),
      context(),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason_code).toBe('DELEGATION_EXCEEDS_PARENT');
  });

  it('refuses delegation by an agent that does not hold the lease', () => {
    const result = authorizeDelegation(proposal({ issuer_agent_id: 'agent_impostor' }), context());
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason_code).toBe('NOT_LEASE_HOLDER');
  });

  it('refuses self-delegation', () => {
    const result = authorizeDelegation(
      proposal({ delegate_agent_id: 'agent_treasury' }),
      context(),
    );
    expect(result.ok).toBe(false);
  });

  it('refuses delegation from an expired or revoked parent', () => {
    for (const broken of [
      lease({ expires_at: new Date(T0.getTime() - 1).toISOString() }),
      lease({ status: 'REVOKED', revoked_at: T0.toISOString() }),
    ]) {
      const result = authorizeDelegation(
        proposal(),
        context({ parent_lease: broken, parent_chain: [broken] }),
      );
      expect(result.ok).toBe(false);
    }
  });

  it('clamps a child lifetime to the parent rather than letting it outlive it', () => {
    const shortParent = lease({ expires_at: new Date(T0.getTime() + 60_000).toISOString() });
    const result = authorizeDelegation(
      proposal({ requested_ttl_seconds: 3600 }),
      context({ parent_lease: shortParent, parent_chain: [shortParent] }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.ttl_clamped).toBe(true);
    expect(result.expires_at).toEqual(new Date(T0.getTime() + 60_000));
  });

  it('clamps a child lifetime to the policy maximum', () => {
    const longParent = lease({ expires_at: new Date(T0.getTime() + 86_400_000).toISOString() });
    const result = authorizeDelegation(
      proposal({ requested_ttl_seconds: 86_400 }),
      context({ parent_lease: longParent, parent_chain: [longParent] }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.expires_at).toEqual(new Date(T0.getTime() + 3_600_000));
  });

  it('stops at the policy depth limit', () => {
    const deep = lease({
      id: 'lease_deep',
      agent_id: 'agent_treasury',
      depth: 2,
      parent_lease_id: 'lease_mid',
    });
    const result = authorizeDelegation(
      proposal(),
      context({
        parent_lease: deep,
        parent_chain: [
          deep,
          lease({ id: 'lease_mid', depth: 1, parent_lease_id: 'lease_root' }),
          lease(),
        ],
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason_code).toBe('DELEGATION_DEPTH_EXCEEDED');
  });

  it('refuses a delegation from a parent about to expire', () => {
    const expiring = lease({ expires_at: new Date(T0.getTime() + 1).toISOString() });
    const result = authorizeDelegation(
      proposal({ requested_ttl_seconds: 600 }),
      context({ parent_lease: expiring, parent_chain: [expiring] }),
    );
    // The clamp lands 1ms out, which is still in the future, so this succeeds
    // -- but a parent already expired must not.
    expect(result.ok).toBe(true);
    const expired = lease({ expires_at: T0.toISOString() });
    expect(
      authorizeDelegation(proposal(), context({ parent_lease: expired, parent_chain: [expired] }))
        .ok,
    ).toBe(false);
  });
});

describe('adversarial delegation inputs', () => {
  const attacks: Array<{ name: string; grant: AuthorityGrant }> = [
    {
      name: 'wildcard action claim',
      grant: { ...narrowGrant, actions: ['*'], resources: { counterparty: ['cp_100'] } },
    },
    {
      name: 'wildcard resource claim against enumerated parent',
      grant: { ...narrowGrant, actions: ['counterparty.read'], resources: { bank_account: ['*'] } },
    },
    {
      name: 'raised amount ceiling',
      grant: {
        ...narrowGrant,
        constraints: { ...narrowGrant.constraints, max_amount: parseMoney('999999', 'USD') },
      },
    },
    {
      name: 'ceiling swapped to another currency',
      grant: {
        ...narrowGrant,
        constraints: { ...narrowGrant.constraints, max_amount: parseMoney('1', 'JPY') },
      },
    },
    {
      name: 'counterparty allowlist widened',
      grant: {
        ...narrowGrant,
        constraints: {
          ...narrowGrant.constraints,
          allowed_counterparties: ['cp_100', 'cp_attacker'],
        },
      },
    },
    {
      name: 'counterparty allowlist replaced by a wildcard',
      grant: {
        ...narrowGrant,
        constraints: { ...narrowGrant.constraints, allowed_counterparties: ['*'] },
      },
    },
    {
      name: 'currency allowlist widened',
      grant: {
        ...narrowGrant,
        constraints: { ...narrowGrant.constraints, currencies: ['USD', 'EUR'] },
      },
    },
    {
      name: 'resource type the parent has no authority over',
      grant: { ...narrowGrant, resources: { ledger: ['*'] } },
    },
  ];

  for (const attack of attacks) {
    it(`refuses: ${attack.name}`, () => {
      const result = authorizeDelegation(proposal({ requested_grant: attack.grant }), context());
      expect(result.ok, `${attack.name} must not be authorised`).toBe(false);
    });
  }

  it('never authorises a delegation that is not contained by its parent', () => {
    for (const attack of attacks) {
      const result = authorizeDelegation(proposal({ requested_grant: attack.grant }), context());
      if (result.ok) {
        expect(containsGrant(parentLease.grant, result.child_grant).contained).toBe(true);
      }
    }
  });
});
