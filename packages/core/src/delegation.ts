import {
  actionMatches,
  containsGrant,
  isWildcardPattern,
  MAX_DELEGATION_DEPTH,
  normalizeGrant,
  type AuthorityGrant,
  type ContainmentViolation,
} from './authority/grant.js';
import { clampExpiry, evaluateChain, type AuthorityLease } from './authority/lease.js';
import type { PolicyDocument } from './policy/schema.js';
import { addSeconds } from './time.js';

/**
 * ============================================================================
 * Delegation (Section 15).
 * ============================================================================
 *
 * One agent handing authority to another is the single most dangerous
 * operation in the platform, because it is the one place where authority is
 * created outside the policy path. Every check here exists to keep one
 * invariant true:
 *
 *     child_authority ⊆ parent_authority
 *
 * and its temporal counterpart:
 *
 *     child_lifetime ⊆ parent_lifetime
 *
 * The request is rejected rather than silently clamped on the authority axis:
 * an agent that asked for more than it holds has a bug or an attacker in it,
 * and quietly granting the intersection would hide both. Lifetime is the one
 * exception -- a TTL longer than the parent's is clamped, because "as long as
 * you can" is a reasonable thing to mean and cannot widen authority.
 */

export interface DelegationProposal {
  issuer_agent_id: string;
  delegate_agent_id: string;
  requested_grant: AuthorityGrant;
  requested_ttl_seconds: number;
}

export interface DelegationRejection {
  code: 'DELEGATION_EXCEEDS_PARENT' | 'STATE_CONFLICT' | 'FORBIDDEN' | 'INVALID_REQUEST';
  reason_code: string;
  message: string;
  violations: ContainmentViolation[];
}

export interface DelegationApproval {
  ok: true;
  child_grant: AuthorityGrant;
  expires_at: Date;
  depth: number;
  /** True when the requested TTL was longer than the parent could support. */
  ttl_clamped: boolean;
}

export type DelegationDecision = DelegationApproval | ({ ok: false } & DelegationRejection);

export interface DelegationContext {
  now: Date;
  parent_lease: AuthorityLease;
  /** Leaf-first ancestry of the parent lease, including the parent itself. */
  parent_chain: AuthorityLease[];
  policy: PolicyDocument;
}

export function authorizeDelegation(
  proposal: DelegationProposal,
  context: DelegationContext,
): DelegationDecision {
  const { now, parent_lease: parent, policy } = context;

  const reject = (
    code: DelegationRejection['code'],
    reason_code: string,
    message: string,
    violations: ContainmentViolation[] = [],
  ): DelegationDecision => ({ ok: false, code, reason_code, message, violations });

  if (proposal.issuer_agent_id === proposal.delegate_agent_id) {
    return reject('INVALID_REQUEST', 'SELF_DELEGATION', 'an agent cannot delegate to itself');
  }

  // Only the holder of a lease may delegate from it. Possessing another
  // agent's credential must not confer that agent's authority (Section 23,
  // confused deputy).
  if (parent.agent_id !== proposal.issuer_agent_id) {
    return reject(
      'FORBIDDEN',
      'NOT_LEASE_HOLDER',
      'the issuing agent does not hold the parent authority lease',
    );
  }

  const chain = evaluateChain(context.parent_chain, now);
  if (!chain.usable) {
    const blocked = chain.blocked_by!;
    return reject(
      'STATE_CONFLICT',
      `PARENT_AUTHORITY_${blocked.status}`,
      `the parent authority chain is not active (lease ${blocked.lease_id} is ${blocked.status})`,
    );
  }

  if (!policy.delegation.enabled) {
    return reject(
      'FORBIDDEN',
      'DELEGATION_DISABLED',
      'the governing policy does not permit delegation',
    );
  }

  const childDepth = parent.depth + 1;
  const maxDepth = Math.min(policy.delegation.max_depth, MAX_DELEGATION_DEPTH);
  if (childDepth > maxDepth) {
    return reject(
      'FORBIDDEN',
      'DELEGATION_DEPTH_EXCEEDED',
      `delegation depth ${childDepth} exceeds the policy maximum of ${maxDepth}`,
    );
  }

  // Some authority is never delegable at any depth, however narrow the ask.
  const blockedActions = proposal.requested_grant.actions.filter((requested) =>
    policy.delegation.non_delegable_actions.some((forbidden) =>
      isWildcardPattern(requested)
        ? requested.slice(0, -1).startsWith(forbidden.replace(/\*$/, '')) ||
          actionMatches(forbidden, requested)
        : actionMatches(forbidden, requested),
    ),
  );
  if (blockedActions.length > 0) {
    return reject(
      'FORBIDDEN',
      'ACTION_NOT_DELEGABLE',
      `policy forbids delegating: ${blockedActions.join(', ')}`,
      blockedActions.map((action) => ({
        axis: 'actions' as const,
        dimension: action,
        message: `action "${action}" is marked non-delegable by policy ${policy.id}`,
        child_value: action,
      })),
    );
  }

  const containment = containsGrant(parent.grant, proposal.requested_grant);
  if (!containment.contained) {
    return reject(
      'DELEGATION_EXCEEDS_PARENT',
      'DELEGATION_EXCEEDS_PARENT',
      'the requested authority is not a subset of the parent authority',
      containment.violations,
    );
  }

  const ttlSeconds = Math.min(proposal.requested_ttl_seconds, policy.delegation.max_ttl_seconds);
  const requestedExpiry = addSeconds(now, ttlSeconds);
  const parentExpiry = new Date(parent.expires_at);
  const expiresAt = clampExpiry(requestedExpiry, parentExpiry);

  if (expiresAt.getTime() <= now.getTime()) {
    return reject(
      'STATE_CONFLICT',
      'PARENT_AUTHORITY_EXPIRING',
      'the parent authority expires too soon to support a delegation',
    );
  }

  return {
    ok: true,
    child_grant: normalizeGrant(proposal.requested_grant),
    expires_at: expiresAt,
    depth: childDepth,
    ttl_clamped: expiresAt.getTime() < requestedExpiry.getTime(),
  };
}
