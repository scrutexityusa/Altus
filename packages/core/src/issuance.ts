import {
  containsGrant,
  type AuthorityGrant,
  type ContainmentViolation,
} from './authority/grant.js';
import type { PolicyDocument } from './policy/schema.js';

/**
 * ============================================================================
 * Issuable authority -- bounding the root of the theorem.
 * ============================================================================
 *
 * The containment lattice already guarantees the middle of the chain:
 *
 *     DelegatedAuthority ⊆ AgentAuthority
 *     EffectiveAuthority ⊆ GrantedAuthority
 *     ExecutionGrant     ⊆ AuthorityLease
 *
 * But a root lease is issued from nothing. It has no parent to be contained
 * by, so every one of those relations hung beneath a root that was bounded
 * only by an API scope: any principal holding `leases:write` could mint any
 * authority at all. The theorem's top line --
 *
 *     HumanAuthority ⊇ AgentAuthority
 *
 * -- was not weakly enforced. It was unmodelled.
 *
 * This module is the missing bound:
 *
 *     RequestedLease ⊆ IssuanceCeiling(role)
 *
 * checked with the same `containsGrant` the delegation path uses. One lattice,
 * one containment relation, one place to get the asymmetry right. A separate
 * comparison here would be a second implementation of "is this within that",
 * and two implementations of that eventually disagree.
 *
 * ## Why ceilings live in the policy
 *
 * The policy document is already immutable, semver'd, content-hashed,
 * dual-control reviewed, atomically activated, and pinned by id *and* hash
 * into every decision record. "Who may grant what" is exactly the question
 * that must not be quietly editable, so it belongs in the artefact that
 * already has those properties -- not in a table a single `UPDATE` can change
 * without review.
 *
 * ## Scopes and authority are different things
 *
 * `leases:write` says the credential may *call* the issuance API. The ceiling
 * says what it may actually grant. Keeping them separate is the point: an API
 * scope protects an endpoint, and organisational authority governs what may
 * come out of it. Collapsing the two makes the scope the ultimate authority
 * model, which is how a treasury system ends up with one boolean between an
 * intern and a $10m wire.
 */

export interface IssuanceProposal {
  /** Roles held by the principal asking to issue. */
  issuer_roles: readonly string[];
  /** The authority being requested. */
  grant: AuthorityGrant;
}

export type IssuanceDecision =
  | {
      ok: true;
      /**
       * The ceiling that admitted the request, recorded in evidence so a
       * later reader can see *which* organisational authority was exercised
       * rather than only that some check passed.
       */
      under_role: string;
    }
  | {
      ok: false;
      reason_code: 'NO_ISSUANCE_CEILING' | 'EXCEEDS_ISSUANCE_CEILING';
      message: string;
      /**
       * Axes that failed against the *closest* ceiling. Named so an operator
       * can fix the request; values omitted because this reaches API responses
       * and logs.
       */
      violations: ContainmentViolation[];
    };

/**
 * Decides whether a principal may issue the authority it is asking for.
 *
 * Pure and total: no clock, no database. The caller supplies the roles and the
 * active policy; this decides. That keeps issuance replayable from evidence
 * for the same reason every other decision in this package is.
 *
 * A principal holding several roles is admitted by the *most permissive* one
 * that covers the whole request -- not by the union of them. Unioning would
 * let someone holding two narrow roles combine them into authority neither
 * grants, which is privilege escalation by set arithmetic. A request must fit
 * inside one ceiling, whole.
 */
export function authorizeIssuance(
  proposal: IssuanceProposal,
  policy: PolicyDocument,
): IssuanceDecision {
  const issuance = policy.issuance;

  // A policy that has not adopted the control yet says so explicitly. There is
  // no implicit opt-out: `enforced` defaults to true, so a policy that simply
  // never mentions issuance denies everything rather than permitting it.
  if (issuance && issuance.enforced === false) {
    return { ok: true, under_role: '*unenforced*' };
  }

  const ceilings = issuance?.ceilings ?? [];
  const applicable = ceilings.filter((c) => proposal.issuer_roles.includes(c.role));

  if (applicable.length === 0) {
    return {
      ok: false,
      reason_code: 'NO_ISSUANCE_CEILING',
      message:
        'no issuance ceiling is declared for any role this principal holds; ' +
        'the active policy must grant a role the authority it is trying to issue',
      violations: [],
    };
  }

  // First ceiling that contains the whole request wins.
  let closest: { role: string; violations: ContainmentViolation[] } | null = null;
  for (const ceiling of applicable) {
    const containment = containsGrant(ceiling.grant, proposal.grant);
    if (containment.contained) {
      return { ok: true, under_role: ceiling.role };
    }
    // "Closest" is the ceiling that failed on the fewest axes -- the most
    // useful one to report, because it is the one the operator is likeliest
    // to have meant.
    if (closest === null || containment.violations.length < closest.violations.length) {
      closest = { role: ceiling.role, violations: containment.violations };
    }
  }

  return {
    ok: false,
    reason_code: 'EXCEEDS_ISSUANCE_CEILING',
    message: `the requested authority exceeds the issuance ceiling for role "${closest!.role}"`,
    violations: closest!.violations,
  };
}

/**
 * The ceilings a set of roles can issue under, for an operator asking "what am
 * I allowed to grant?".
 *
 * Deliberately not exposed to agents: an agent that can enumerate issuance
 * ceilings learns the shape of the organisation's authority model.
 */
export function issuableCeilings(
  roles: readonly string[],
  policy: PolicyDocument,
): { role: string; grant: AuthorityGrant }[] {
  return (policy.issuance?.ceilings ?? []).filter((c) => roles.includes(c.role));
}
