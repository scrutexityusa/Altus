import { describe, expect, it } from 'vitest';
import { verifyAuthorityInvariants, describeInvariantFailure } from '../src/invariants.js';
import { parseMoney } from '../src/money.js';
import type { AuthorityGrant } from '../src/authority/grant.js';
import type { AuthorityLease } from '../src/authority/lease.js';

/**
 * The laws, checked as postconditions.
 *
 * These are not tests of `containsGrant` -- that has its own suite and its own
 * property tests. They test that the verifier notices when a lattice that is
 * supposed to hold does not, which is the case a derivation-only system misses
 * entirely.
 */

const T0 = new Date('2026-01-01T00:00:00.000Z');

const grant = (over: Partial<AuthorityGrant> = {}): AuthorityGrant => ({
  actions: ['wire.execute', 'counterparty.read'],
  resources: { bank_account: ['acct_001'], counterparty: ['cp_100'] },
  constraints: {
    max_amount: parseMoney('50000.00', 'USD'),
    currencies: ['USD'],
    allowed_counterparties: ['cp_100'],
  },
  ...over,
});

const lease = (over: Partial<AuthorityLease> = {}): AuthorityLease =>
  ({
    id: 'lease_root',
    agent_id: 'agent_treasury',
    parent_lease_id: null,
    depth: 0,
    grant: grant(),
    status: 'ACTIVE',
    issued_at: T0.toISOString(),
    expires_at: new Date(T0.getTime() + 3_600_000).toISOString(),
    revoked_at: null,
    revocable: true,
    grant_type: 'REUSABLE',
    consumed: false,
    claimed_at: null,
    claimed_by_decision_id: null,
    used_at: null,
    purpose: null,
    ...over,
  }) as AuthorityLease;

describe('LAW 1 — a child never exceeds its parent', () => {
  it('passes a chain that narrows', () => {
    const parent = lease({ id: 'lease_parent' });
    const child = lease({
      id: 'lease_child',
      parent_lease_id: 'lease_parent',
      depth: 1,
      grant: grant({ actions: ['counterparty.read'] }),
    });
    const report = verifyAuthorityInvariants({ now: T0, chain: [child, parent] });
    expect(report.valid).toBe(true);
  });

  it('catches a child that gained an action its parent never had', () => {
    // The delegation path would have refused this at creation. The point of
    // the postcondition is the case where it exists anyway -- a bug, a direct
    // database write, a dropped constraint.
    const parent = lease({ id: 'lease_parent', grant: grant({ actions: ['counterparty.read'] }) });
    const child = lease({
      id: 'lease_child',
      parent_lease_id: 'lease_parent',
      depth: 1,
      grant: grant({ actions: ['wire.execute'] }),
    });
    const report = verifyAuthorityInvariants({ now: T0, chain: [child, parent] });
    expect(report.valid).toBe(false);
    expect(report.failed).toContain('CHILD_SUBSET_OF_PARENT');
  });

  it('catches a child that raised its own ceiling', () => {
    const parent = lease({ id: 'lease_parent' });
    const child = lease({
      id: 'lease_child',
      parent_lease_id: 'lease_parent',
      depth: 1,
      grant: grant({
        constraints: {
          max_amount: parseMoney('500000.00', 'USD'),
          currencies: ['USD'],
          allowed_counterparties: ['cp_100'],
        },
      }),
    });
    const report = verifyAuthorityInvariants({ now: T0, chain: [child, parent] });
    expect(report.valid).toBe(false);
    expect(report.failed).toContain('CHILD_SUBSET_OF_PARENT');
  });

  it('checks every link of a deep chain, not only the first', () => {
    const root = lease({ id: 'lease_root' });
    const middle = lease({ id: 'lease_mid', parent_lease_id: 'lease_root', depth: 1 });
    const leaf = lease({
      id: 'lease_leaf',
      parent_lease_id: 'lease_mid',
      depth: 2,
      grant: grant({ resources: { bank_account: ['acct_999'] } }),
    });
    const report = verifyAuthorityInvariants({ now: T0, chain: [leaf, middle, root] });
    expect(report.valid).toBe(false);
    expect(report.failed).toContain('CHILD_SUBSET_OF_PARENT');
  });
});

describe('LAW 2 — the effective grant never exceeds what was granted', () => {
  it('passes when decay narrowed', () => {
    const report = verifyAuthorityInvariants({
      now: T0,
      chain: [lease()],
      effectiveGrant: grant({ actions: ['counterparty.read'] }),
    });
    expect(report.valid).toBe(true);
  });

  it('catches an effective grant that widened', () => {
    // A signal must only ever subtract. This is the assertion behind that
    // sentence: if decay ever produced a wider grant, the ALLOW is refused.
    const report = verifyAuthorityInvariants({
      now: T0,
      chain: [lease()],
      effectiveGrant: grant({ actions: ['wire.execute', 'policy.write'] }),
    });
    expect(report.valid).toBe(false);
    expect(report.failed).toContain('EFFECTIVE_SUBSET_OF_GRANTED');
  });
});

describe('LAW 3 — an execution grant never exceeds its lease', () => {
  it('catches an execution grant reaching a resource the lease never covered', () => {
    const report = verifyAuthorityInvariants({
      now: T0,
      chain: [lease()],
      executionGrant: grant({ resources: { bank_account: ['acct_002'] } }),
    });
    expect(report.valid).toBe(false);
    expect(report.failed).toContain('EXECUTION_GRANT_SUBSET_OF_LEASE');
  });
});

describe('liveness', () => {
  it('catches a revoked acting lease', () => {
    const report = verifyAuthorityInvariants({
      now: T0,
      chain: [lease({ status: 'REVOKED', revoked_at: T0.toISOString() })],
    });
    expect(report.failed).toContain('LEASE_ACTIVE');
  });

  it('catches a revoked ancestor even when the child looks fine', () => {
    const parent = lease({ id: 'lease_parent', status: 'REVOKED', revoked_at: T0.toISOString() });
    const child = lease({ id: 'lease_child', parent_lease_id: 'lease_parent', depth: 1 });
    const report = verifyAuthorityInvariants({ now: T0, chain: [child, parent] });
    expect(report.failed).toContain('ANCESTORS_ACTIVE');
  });

  it('catches an expired lease using the clock it was given', () => {
    const late = new Date(T0.getTime() + 7_200_000);
    const report = verifyAuthorityInvariants({ now: late, chain: [lease()] });
    expect(report.failed).toContain('LEASE_ACTIVE');
  });

  it('treats a consumed single-use lease as live', () => {
    // The execution being verified is what consumed it. Calling that a
    // violation would make every successful single-use execution unlawful
    // the moment it succeeded.
    const report = verifyAuthorityInvariants({
      now: T0,
      chain: [
        lease({
          grant_type: 'SINGLE_USE',
          consumed: true,
          claimed_at: T0.toISOString(),
          used_at: T0.toISOString(),
        }),
      ],
    });
    expect(report.failed).not.toContain('LEASE_ACTIVE');
  });
});

describe('chain completeness', () => {
  it('catches a chain that stops before its root', () => {
    // A traversal that did not reach the top checked less than it appears to.
    // Reporting that as valid would be the worst kind of false assurance.
    const orphan = lease({ id: 'lease_child', parent_lease_id: 'lease_missing', depth: 1 });
    const report = verifyAuthorityInvariants({ now: T0, chain: [orphan] });
    expect(report.valid).toBe(false);
    expect(report.failed).toContain('ANCESTRY_COMPLETE');
  });
});

describe('the report itself', () => {
  it('names every law that broke, not just the first', () => {
    const parent = lease({ id: 'lease_parent', grant: grant({ actions: ['counterparty.read'] }) });
    const child = lease({
      id: 'lease_child',
      parent_lease_id: 'lease_parent',
      depth: 1,
      grant: grant({ actions: ['wire.execute'] }),
      status: 'REVOKED',
      revoked_at: T0.toISOString(),
    });
    const report = verifyAuthorityInvariants({ now: T0, chain: [child, parent] });
    expect(report.failed).toContain('CHILD_SUBSET_OF_PARENT');
    expect(report.failed).toContain('LEASE_ACTIVE');
  });

  it('carries no account identifiers into its details', () => {
    // This report travels into security events and operator alerts, which are
    // read by more people than may see a counterparty's account.
    const parent = lease({ id: 'lease_parent' });
    const child = lease({
      id: 'lease_child',
      parent_lease_id: 'lease_parent',
      depth: 1,
      grant: grant({ resources: { bank_account: ['acct_secret_9999'] } }),
    });
    const report = verifyAuthorityInvariants({ now: T0, chain: [child, parent] });
    expect(report.valid).toBe(false);
    expect(JSON.stringify(report)).not.toContain('acct_secret_9999');
  });

  it('summarises to one line naming the laws', () => {
    const report = verifyAuthorityInvariants({
      now: T0,
      chain: [lease({ status: 'REVOKED', revoked_at: T0.toISOString() })],
    });
    expect(describeInvariantFailure(report)).toContain('LEASE_ACTIVE');
  });

  it('says so plainly when everything holds', () => {
    const report = verifyAuthorityInvariants({ now: T0, chain: [lease()] });
    expect(describeInvariantFailure(report)).toBe('all authority invariants hold');
  });
});
