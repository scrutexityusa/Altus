import { containsGrant, type AuthorityGrant } from './authority/grant.js';
import { effectiveLeaseStatus, type AuthorityLease, type LeaseStatus } from './authority/lease.js';

/**
 * ============================================================================
 * The constitutional invariants, checked at runtime.
 * ============================================================================
 *
 * The containment lattice is already correct: `containsGrant` decides whether
 * a child grant fits inside a parent, property tests hammer it, and the
 * delegation path refuses anything that fails. So why check again here?
 *
 * Because *computing* containment correctly and *asserting* it are different
 * things, and only the second survives a bug. Until this module existed, a
 * defect in the evaluator -- or a row written directly to the database, or a
 * migration that dropped a constraint -- produced a wrong ALLOW with nothing
 * to notice. The decision path used the lattice to *derive* an answer; nothing
 * checked the answer against the laws afterwards.
 *
 * This is a postcondition, and it is a security boundary rather than a test
 * helper. A failure here is not a policy denial and must never be reported as
 * one: policy denials are ordinary, and an operator who sees them daily will
 * not notice one more. A law being violated means the system's model of its
 * own authority is wrong, which is a different and much worse fact.
 *
 * ## The laws
 *
 *   LAW 1   ChildAuthority     ⊆ ParentAuthority     (delegation containment)
 *   LAW 2   EffectiveAuthority ⊆ GrantedAuthority    (decay only subtracts)
 *   LAW 3   ExecutionGrant     ⊆ AuthorityLease      (execution never widens)
 *   LAW 4   ExecutedIntent     = AuthorizedIntent    (enforcement boundary)
 *
 * Laws 1-3 are checked here, because all three are containment questions over
 * grants. Law 4 is a hash comparison at the execution boundary and lives in
 * `operation.ts` -- it has no grant to reason about.
 *
 * ## Pure, like everything else in this package
 *
 * No clock, no database. `now` is passed in, leases are passed in. The caller
 * assembles the facts; this decides whether they are lawful. That keeps the
 * check replayable against historical evidence, which is what makes the
 * verification endpoint possible at all.
 */

export type InvariantName =
  /** LAW 1. A delegated grant fits inside the one it came from. */
  | 'CHILD_SUBSET_OF_PARENT'
  /** LAW 2. Decay and signals only ever subtract. */
  | 'EFFECTIVE_SUBSET_OF_GRANTED'
  /** LAW 3. The operation authorised fits inside the lease that authorised it. */
  | 'EXECUTION_GRANT_SUBSET_OF_LEASE'
  /** The acting lease is usable right now. */
  | 'LEASE_ACTIVE'
  /** Every ancestor is usable right now -- revocation cascades. */
  | 'ANCESTORS_ACTIVE'
  /** The chain is intact: every non-root lease's parent was actually found. */
  | 'ANCESTRY_COMPLETE';

export interface InvariantCheck {
  invariant: InvariantName;
  passed: boolean;
  /**
   * Forensic detail. Never contains a secret, a signature or a counterparty
   * account number: this travels into security events and operator alerts,
   * both of which are read by more people than may see those.
   */
  details: Record<string, unknown>;
}

export interface InvariantReport {
  valid: boolean;
  checks: InvariantCheck[];
  /** The invariants that failed, for a metric label and an alert subject. */
  failed: InvariantName[];
}

export interface VerifyAuthorityInput {
  /** Evaluation time. Passed in so the check is replayable. */
  now: Date;
  /**
   * The lease the decision acted under, followed by its ancestors in order.
   * Root last. Empty when the decision rested on no lease at all, in which
   * case there is nothing to contain and the containment laws are vacuous.
   */
  chain: readonly AuthorityLease[];
  /**
   * The grant after decay and signal restriction -- what the evaluator
   * actually used. Compared against the acting lease's own grant (LAW 2).
   */
  effectiveGrant?: AuthorityGrant | undefined;
  /**
   * The authority an ALLOW confers, when it is narrower than the effective
   * grant. Compared against the acting lease (LAW 3).
   */
  executionGrant?: AuthorityGrant | undefined;
}

/**
 * Verifies the containment laws over an assembled authority chain.
 *
 * Returns a structured report rather than throwing, because the caller decides
 * what a violation means: the decision path turns it into a DENY plus a
 * security event, while the verification endpoint renders it for an auditor.
 * Throwing here would force the second caller to catch its own success case.
 */
export function verifyAuthorityInvariants(input: VerifyAuthorityInput): InvariantReport {
  const checks: InvariantCheck[] = [];
  const [acting, ...ancestors] = input.chain;

  // -- LAW 1: every link in the chain fits inside the one above it ----------
  //
  // Re-derived from the stored grants rather than trusted from the delegation
  // that created them. A child that was lawful when created and is not lawful
  // now means something changed that should not have.
  const parentViolations: Record<string, unknown>[] = [];
  for (let i = 0; i < input.chain.length - 1; i += 1) {
    const child = input.chain[i]!;
    const parent = input.chain[i + 1]!;
    const containment = containsGrant(parent.grant, child.grant);
    if (!containment.contained) {
      parentViolations.push({
        child_lease_id: child.id,
        parent_lease_id: parent.id,
        // Axis and dimension only. The values would carry account ids.
        axes: containment.violations.map((v) => `${v.axis}:${v.dimension}`),
      });
    }
  }
  checks.push({
    invariant: 'CHILD_SUBSET_OF_PARENT',
    passed: parentViolations.length === 0,
    details:
      parentViolations.length === 0
        ? { links_checked: Math.max(0, input.chain.length - 1) }
        : { violations: parentViolations },
  });

  // -- ANCESTRY_COMPLETE ---------------------------------------------------
  //
  // A chain that stops before its root is not proof of anything. If the last
  // lease still names a parent, the traversal did not reach the top -- the row
  // is missing, or RLS hid it, and either way the containment check above
  // covered less than it appears to.
  const deepest = input.chain[input.chain.length - 1];
  const complete = input.chain.length === 0 || deepest!.parent_lease_id === null;
  checks.push({
    invariant: 'ANCESTRY_COMPLETE',
    passed: complete,
    details: complete
      ? { depth: input.chain.length }
      : { deepest_lease_id: deepest!.id, missing_parent_id: deepest!.parent_lease_id },
  });

  // -- LAW 2: the effective grant never exceeds what was granted ------------
  if (acting && input.effectiveGrant) {
    const containment = containsGrant(acting.grant, input.effectiveGrant);
    checks.push({
      invariant: 'EFFECTIVE_SUBSET_OF_GRANTED',
      passed: containment.contained,
      details: containment.contained
        ? { lease_id: acting.id }
        : {
            lease_id: acting.id,
            axes: containment.violations.map((v) => `${v.axis}:${v.dimension}`),
          },
    });
  }

  // -- LAW 3: the execution grant never exceeds the lease -------------------
  if (acting && input.executionGrant) {
    const containment = containsGrant(acting.grant, input.executionGrant);
    checks.push({
      invariant: 'EXECUTION_GRANT_SUBSET_OF_LEASE',
      passed: containment.contained,
      details: containment.contained
        ? { lease_id: acting.id }
        : {
            lease_id: acting.id,
            axes: containment.violations.map((v) => `${v.axis}:${v.dimension}`),
          },
    });
  }

  // -- Liveness ------------------------------------------------------------
  //
  // CONSUMED counts as live: a single-use grant is consumed *by* the execution
  // being verified, and treating that as a violation would make every
  // successful execution unlawful after the fact.
  if (acting) {
    const status = effectiveLeaseStatus(acting, input.now);
    checks.push({
      invariant: 'LEASE_ACTIVE',
      passed: isUsable(status),
      details: { lease_id: acting.id, status },
    });
  }

  const deadAncestors = ancestors
    .map((lease) => ({ lease, status: effectiveLeaseStatus(lease, input.now) }))
    .filter(({ status }) => !isUsable(status));
  if (ancestors.length > 0) {
    checks.push({
      invariant: 'ANCESTORS_ACTIVE',
      passed: deadAncestors.length === 0,
      details:
        deadAncestors.length === 0
          ? { ancestors_checked: ancestors.length }
          : {
              dead: deadAncestors.map(({ lease, status }) => ({
                lease_id: lease.id,
                status,
              })),
            },
    });
  }

  const failed = checks.filter((c) => !c.passed).map((c) => c.invariant);
  return { valid: failed.length === 0, checks, failed };
}

function isUsable(status: LeaseStatus): boolean {
  return status === 'ACTIVE' || status === 'CONSUMED';
}

/**
 * A one-line summary for a log record or an alert subject.
 *
 * Names the laws that broke and nothing else. An alert body is read on a phone
 * at 3am; the full report is one query away.
 */
export function describeInvariantFailure(report: InvariantReport): string {
  if (report.valid) return 'all authority invariants hold';
  return `authority invariant violation: ${report.failed.join(', ')}`;
}
