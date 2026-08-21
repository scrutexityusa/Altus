import { z } from 'zod';
import type { ApprovalRequirement } from './policy/schema.js';
import { isExpired } from './time.js';

/**
 * Human approval is a separate domain object, not a boolean on the decision
 * (Section 17). What is recorded is who approved, what authority they held at
 * that moment, and which requirement their authority satisfied.
 */

export const APPROVAL_VOTES = ['APPROVED', 'REJECTED'] as const;
export type ApprovalVote = (typeof APPROVAL_VOTES)[number];

export const ApprovalSchema = z.object({
  id: z.string(),
  approval_request_id: z.string(),
  approver_user_id: z.string(),
  vote: z.enum(APPROVAL_VOTES),
  /** Roles held at the instant of approval; never re-derived at read time. */
  roles_at_decision: z.array(z.string()),
  satisfied_role: z.string().nullable(),
  comment: z.string().nullable(),
  created_at: z.string(),
});

export type Approval = z.infer<typeof ApprovalSchema>;

export interface ApprovalContext {
  /** The human accountable for the requesting agent, if any. */
  requesting_agent_owner_user_id: string | null;
  expires_at: string;
}

export interface RoleCoverage {
  role: string;
  satisfied: boolean;
  satisfied_by: string | null;
}

export interface ApprovalEvaluation {
  status: 'PENDING' | 'SATISFIED' | 'REJECTED' | 'EXPIRED';
  /** Approvals that actually counted, with the role each one covered. */
  counted: Array<{ approval_id: string; user_id: string; role: string | null }>;
  /** Approvals that were recorded but did not count, and why. */
  discounted: Array<{ approval_id: string; user_id: string; reason: string }>;
  role_coverage: RoleCoverage[];
  quorum_required: number;
  quorum_met: number;
  outstanding_roles: string[];
}

/**
 * Decides whether an approval requirement is satisfied.
 *
 * Deliberately strict:
 *   - one vote per human (enforced by the store as well as here)
 *   - a single rejection is terminal; a rejected escalation does not become
 *     approvable by finding more approvers
 *   - self-approval by the agent's own owner never counts
 *   - a role is only covered by someone who held it at approval time
 *   - role coverage is assigned greedily over a stable ordering, so the same
 *     set of approvals always resolves the same way
 */
export function evaluateApprovals(
  requirement: ApprovalRequirement,
  approvals: readonly Approval[],
  context: ApprovalContext,
  now: Date,
): ApprovalEvaluation {
  const ordered = [...approvals].sort((a, b) =>
    a.created_at === b.created_at ? (a.id < b.id ? -1 : 1) : a.created_at < b.created_at ? -1 : 1,
  );

  const discounted: ApprovalEvaluation['discounted'] = [];
  const eligible: Approval[] = [];

  for (const approval of ordered) {
    if (approval.vote === 'REJECTED') continue; // handled below
    if (
      requirement.forbid_self_approval &&
      context.requesting_agent_owner_user_id !== null &&
      approval.approver_user_id === context.requesting_agent_owner_user_id
    ) {
      discounted.push({
        approval_id: approval.id,
        user_id: approval.approver_user_id,
        reason: 'SELF_APPROVAL_FORBIDDEN',
      });
      continue;
    }
    if (
      requirement.roles.length > 0 &&
      !requirement.roles.some((role) => approval.roles_at_decision.includes(role))
    ) {
      discounted.push({
        approval_id: approval.id,
        user_id: approval.approver_user_id,
        reason: 'APPROVER_HELD_NO_REQUIRED_ROLE',
      });
      continue;
    }
    eligible.push(approval);
  }

  // Greedy role assignment over a stable ordering. Approvers holding the
  // fewest required roles are placed first so a single multi-role approver
  // cannot starve a role only they could cover.
  const outstanding = new Set(requirement.roles);
  const counted: ApprovalEvaluation['counted'] = [];
  const coverage = new Map<string, string | null>(requirement.roles.map((role) => [role, null]));

  const byScarcity = [...eligible].sort((a, b) => {
    const aRoles = requirement.roles.filter((r) => a.roles_at_decision.includes(r)).length;
    const bRoles = requirement.roles.filter((r) => b.roles_at_decision.includes(r)).length;
    return aRoles - bRoles || (a.created_at < b.created_at ? -1 : 1);
  });

  for (const approval of byScarcity) {
    const role =
      requirement.roles.find(
        (candidate) => outstanding.has(candidate) && approval.roles_at_decision.includes(candidate),
      ) ?? null;
    if (role) {
      outstanding.delete(role);
      coverage.set(role, approval.approver_user_id);
    }
    counted.push({ approval_id: approval.id, user_id: approval.approver_user_id, role });
  }

  const rejection = ordered.find((approval) => approval.vote === 'REJECTED');
  const quorumMet = counted.length;
  const rolesCovered = outstanding.size === 0;

  let status: ApprovalEvaluation['status'];
  if (rejection) {
    status = 'REJECTED';
  } else if (quorumMet >= requirement.quorum && rolesCovered) {
    status = 'SATISFIED';
  } else if (isExpired(context.expires_at, now)) {
    status = 'EXPIRED';
  } else {
    status = 'PENDING';
  }

  return {
    status,
    counted,
    discounted,
    role_coverage: requirement.roles.map((role) => ({
      role,
      satisfied: coverage.get(role) !== null,
      satisfied_by: coverage.get(role) ?? null,
    })),
    quorum_required: requirement.quorum,
    quorum_met: quorumMet,
    outstanding_roles: [...outstanding].sort(),
  };
}
