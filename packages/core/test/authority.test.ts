import { describe, expect, it } from 'vitest';
import {
  actionMatches,
  containsGrant,
  coversAttempt,
  normalizeGrant,
  restrictGrant,
  type AuthorityGrant,
} from '../src/authority/grant.js';
import { effectiveLeaseStatus, evaluateChain, clampExpiry } from '../src/authority/lease.js';
import { parseMoney } from '../src/money.js';
import { grant, lease, T0 } from './fixtures.js';

const parent = grant();

describe('action patterns', () => {
  it('matches exact and prefix forms only', () => {
    expect(actionMatches('wire.execute', 'wire.execute')).toBe(true);
    expect(actionMatches('wire.*', 'wire.execute')).toBe(true);
    expect(actionMatches('wire.*', 'wire.batch.execute')).toBe(true);
    expect(actionMatches('wire.*', 'wired.execute')).toBe(false);
    expect(actionMatches('*', 'anything.at.all')).toBe(true);
    expect(actionMatches('wire.execute', 'wire.executeX')).toBe(false);
  });
});

describe('containment: child ⊆ parent', () => {
  const child = (overrides: Partial<AuthorityGrant>): AuthorityGrant => ({
    actions: ['counterparty.read'],
    resources: { counterparty: ['cp_100'] },
    constraints: {
      max_amount: parseMoney('1000', 'USD'),
      currencies: ['USD'],
      allowed_counterparties: ['cp_100'],
    },
    ...overrides,
  });

  it('accepts a genuine narrowing on every axis', () => {
    expect(containsGrant(parent, child({})).contained).toBe(true);
  });

  it('rejects an action the parent never held', () => {
    const result = containsGrant(parent, child({ actions: ['wire.execute', 'ledger.close'] }));
    expect(result.contained).toBe(false);
    expect(result.violations.map((v) => v.dimension)).toContain('ledger.close');
  });

  it('rejects a wildcard that widens a parent wildcard', () => {
    const wide: AuthorityGrant = { actions: ['wire.*'], resources: {}, constraints: {} };
    expect(
      containsGrant(wide, { actions: ['wire.batch.*'], resources: {}, constraints: {} }).contained,
    ).toBe(true);
    expect(containsGrant(wide, { actions: ['*'], resources: {}, constraints: {} }).contained).toBe(
      false,
    );
    expect(
      containsGrant(wide, { actions: ['ledger.*'], resources: {}, constraints: {} }).contained,
    ).toBe(false);
  });

  it('rejects a resource type the parent holds no authority over', () => {
    const result = containsGrant(parent, child({ resources: { ledger: ['led_1'] } }));
    expect(result.contained).toBe(false);
    expect(result.violations[0]?.axis).toBe('resources');
  });

  it('rejects a wildcard resource claim against an enumerated parent', () => {
    const result = containsGrant(parent, child({ resources: { bank_account: ['*'] } }));
    expect(result.contained).toBe(false);
  });

  it('allows a wildcard claim where the parent itself holds a wildcard', () => {
    expect(containsGrant(parent, child({ resources: { counterparty: ['*'] } })).contained).toBe(
      true,
    );
  });

  // The attack this whole module exists to stop: widening by omission.
  it('rejects a child that drops a constraint its parent imposed', () => {
    for (const dropped of ['max_amount', 'currencies', 'allowed_counterparties'] as const) {
      const constraints = { ...child({}).constraints };
      delete constraints[dropped];
      const result = containsGrant(parent, child({ constraints }));
      expect(result.contained, `dropping ${dropped} must not widen authority`).toBe(false);
      expect(result.violations.some((v) => v.dimension === dropped)).toBe(true);
    }
  });

  it('rejects an empty constraint set against a constrained parent', () => {
    expect(containsGrant(parent, child({ constraints: {} })).contained).toBe(false);
  });

  it('rejects a higher ceiling', () => {
    const result = containsGrant(
      parent,
      child({
        constraints: { ...child({}).constraints, max_amount: parseMoney('50000.01', 'USD') },
      }),
    );
    expect(result.contained).toBe(false);
  });

  it('accepts a ceiling exactly equal to the parent ceiling', () => {
    expect(
      containsGrant(
        parent,
        child({
          constraints: { ...child({}).constraints, max_amount: parseMoney('50000', 'USD') },
        }),
      ).contained,
    ).toBe(true);
  });

  it('rejects a ceiling denominated in another currency rather than converting it', () => {
    const result = containsGrant(
      parent,
      child({ constraints: { ...child({}).constraints, max_amount: parseMoney('1', 'EUR') } }),
    );
    expect(result.contained).toBe(false);
    expect(result.violations[0]?.message).toMatch(/cannot be compared/);
  });

  it('requires a child to inherit every denied value from its parent', () => {
    const denyingParent = grant({
      constraints: { ...parent.constraints, denied_counterparties: ['cp_sanctioned'] },
    });
    const withoutDeny = containsGrant(denyingParent, child({}));
    expect(withoutDeny.contained).toBe(false);
    const withDeny = containsGrant(
      denyingParent,
      child({
        constraints: {
          ...child({}).constraints,
          denied_counterparties: ['cp_sanctioned', 'cp_extra'],
        },
      }),
    );
    expect(withDeny.contained).toBe(true);
  });

  it('is reflexive', () => {
    expect(containsGrant(parent, parent).contained).toBe(true);
  });

  it('is transitive over a delegation chain', () => {
    const mid = child({
      constraints: { ...child({}).constraints, max_amount: parseMoney('5000', 'USD') },
    });
    const leaf = child({
      constraints: { ...child({}).constraints, max_amount: parseMoney('100', 'USD') },
    });
    expect(containsGrant(parent, mid).contained).toBe(true);
    expect(containsGrant(mid, leaf).contained).toBe(true);
    expect(containsGrant(parent, leaf).contained).toBe(true);
  });
});

describe('coverage of a concrete attempt', () => {
  const attempt = (overrides: Partial<Parameters<typeof coversAttempt>[1]> = {}) => ({
    action: 'wire.execute',
    resourceType: 'bank_account',
    resourceId: 'acct_001',
    context: {
      amount: parseMoney('25000', 'USD'),
      currency: 'USD',
      counterparty_id: 'cp_100',
    } as Record<string, unknown>,
    ...overrides,
  });

  it('covers an attempt inside every axis', () => {
    expect(coversAttempt(parent, attempt()).covered).toBe(true);
  });

  it('reports the amount ceiling as the failure, not a generic denial', () => {
    const result = coversAttempt(
      parent,
      attempt({
        context: {
          amount: parseMoney('250000', 'USD'),
          currency: 'USD',
          counterparty_id: 'cp_100',
        },
      }),
    );
    expect(result.covered).toBe(false);
    expect(result.failure).toEqual({
      kind: 'CONSTRAINT_VIOLATION',
      constraint: 'max_amount',
      detail: expect.stringContaining('exceeds'),
    });
    // The envelope is intact even though the constraint is not: that is what
    // makes the outcome escalatable rather than terminal.
    expect(result.action_covered).toBe(true);
    expect(result.resource_covered).toBe(true);
  });

  it('fails closed when a constrained dimension is absent from the request', () => {
    const result = coversAttempt(parent, attempt({ context: { counterparty_id: 'cp_100' } }));
    expect(result.covered).toBe(false);
    expect(result.failure?.kind).toBe('CONSTRAINT_VIOLATION');
  });

  it('fails closed when the request is in a currency the ceiling is not denominated in', () => {
    const result = coversAttempt(
      parent,
      attempt({
        context: { amount: parseMoney('1', 'EUR'), currency: 'EUR', counterparty_id: 'cp_100' },
      }),
    );
    expect(result.covered).toBe(false);
  });

  it('reports an ungranted action and an ungranted resource distinctly', () => {
    expect(coversAttempt(parent, attempt({ action: 'wire.modify' })).failure?.kind).toBe(
      'ACTION_NOT_GRANTED',
    );
    expect(coversAttempt(parent, attempt({ resourceId: 'acct_999' })).failure?.kind).toBe(
      'RESOURCE_NOT_GRANTED',
    );
    expect(coversAttempt(parent, attempt({ resourceType: 'ledger' })).failure?.kind).toBe(
      'RESOURCE_NOT_GRANTED',
    );
  });
});

describe('restriction (authority decay)', () => {
  it('produces a grant that is still contained by the original', () => {
    const decayed = restrictGrant(parent, {
      remove_actions: ['wire.execute', 'wire.submit'],
      tighten: { max_amount: parseMoney('1000', 'USD') },
    });
    expect(decayed.actions).toEqual(['wire.create', 'counterparty.read']);
    expect(containsGrant(parent, decayed).contained).toBe(true);
  });

  it('never widens a ceiling, even when asked to', () => {
    const decayed = restrictGrant(parent, { tighten: { max_amount: parseMoney('999999', 'USD') } });
    expect(decayed.constraints.max_amount).toEqual(parseMoney('50000', 'USD'));
  });

  it('never widens an allowlist, even when asked to', () => {
    const decayed = restrictGrant(parent, {
      tighten: { allowed_counterparties: ['cp_100', 'cp_999'] },
    });
    expect(decayed.constraints.allowed_counterparties).toEqual(['cp_100']);
  });

  it('removes wildcard-granted actions when the removal covers them', () => {
    const wide: AuthorityGrant = { actions: ['wire.*'], resources: {}, constraints: {} };
    expect(restrictGrant(wide, { remove_actions: ['wire.*'] }).actions).toEqual([]);
    expect(restrictGrant(wide, { remove_actions: ['*'] }).actions).toEqual([]);
  });
});

describe('lease lifecycle', () => {
  it('derives expiry from server time regardless of stored status', () => {
    const expired = lease({ expires_at: new Date(T0.getTime() - 1).toISOString() });
    expect(effectiveLeaseStatus(expired, T0)).toBe('EXPIRED');
  });

  it('never lets a revoked lease read as active, even before its expiry', () => {
    const revoked = lease({ status: 'REVOKED', revoked_at: T0.toISOString() });
    expect(effectiveLeaseStatus(revoked, T0)).toBe('REVOKED');
  });

  it('expires exactly at the boundary instant', () => {
    const boundary = lease({ expires_at: T0.toISOString() });
    expect(effectiveLeaseStatus(boundary, T0)).toBe('EXPIRED');
    expect(effectiveLeaseStatus(boundary, new Date(T0.getTime() - 1))).toBe('ACTIVE');
  });

  it('kills a child the instant its parent is revoked, with no cascade job', () => {
    const root = lease({ id: 'lease_root', status: 'REVOKED', revoked_at: T0.toISOString() });
    const child = lease({ id: 'lease_child', parent_lease_id: 'lease_root', depth: 1 });
    const result = evaluateChain([child, root], T0);
    expect(result.usable).toBe(false);
    expect(result.blocked_by).toMatchObject({ lease_id: 'lease_root', status: 'REVOKED' });
  });

  it('kills a child when an ancestor expires, at any depth', () => {
    const root = lease({ id: 'lease_root', expires_at: new Date(T0.getTime() - 1).toISOString() });
    const mid = lease({ id: 'lease_mid', parent_lease_id: 'lease_root', depth: 1 });
    const leaf = lease({ id: 'lease_leaf', parent_lease_id: 'lease_mid', depth: 2 });
    expect(evaluateChain([leaf, mid, root], T0).blocked_by?.lease_id).toBe('lease_root');
  });

  it('clamps a child expiry to its parent', () => {
    const parentExpiry = new Date(T0.getTime() + 60_000);
    expect(clampExpiry(new Date(T0.getTime() + 3_600_000), parentExpiry)).toEqual(parentExpiry);
    expect(clampExpiry(new Date(T0.getTime() + 1_000), parentExpiry)).toEqual(
      new Date(T0.getTime() + 1_000),
    );
  });
});

describe('normalisation', () => {
  it('is stable under reordering, so hashes of equivalent grants agree', () => {
    const a = normalizeGrant({
      actions: ['b.x', 'a.y'],
      resources: { z: ['2', '1'], a: ['1'] },
      constraints: { currencies: ['USD', 'EUR'] },
    });
    const b = normalizeGrant({
      actions: ['a.y', 'b.x'],
      resources: { a: ['1'], z: ['1', '2'] },
      constraints: { currencies: ['EUR', 'USD'] },
    });
    expect(a).toEqual(b);
  });
});
