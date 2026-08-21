import { ScrutexityError, newId } from '@scrutexity/core';
import type { PoolClient } from '../db/pool.js';
import { metrics } from '../metrics.js';
import { appendReceipt, type EvidenceKeys } from './evidence.js';
import { reevaluateWithApprovals } from './authorization.js';

/**
 * Human approval (Section 17).
 *
 * An approval is not a boolean set on a decision. It is a record of a named
 * person, the authority they actually held at that instant, the requirement
 * their authority satisfied, and the decision they were answering. Recording
 * one triggers a re-evaluation of the original request, which produces a new
 * decision that supersedes the escalation -- the original decision is never
 * rewritten.
 */

export interface SubmitApprovalInput {
  organizationId: string;
  approvalRequestId: string;
  approverUserId: string;
  vote: 'APPROVED' | 'REJECTED';
  comment?: string | null;
  idempotencyKey?: string | null;
}

export async function submitApproval(
  client: PoolClient,
  keys: EvidenceKeys,
  input: SubmitApprovalInput,
) {
  const requestResult = await client.query(
    'SELECT * FROM scrutexity.approval_requests WHERE id = $1 FOR UPDATE',
    [input.approvalRequestId],
  );
  const approvalRequest = requestResult.rows[0];
  if (!approvalRequest) throw new ScrutexityError('NOT_FOUND', 'approval request not found');

  if (approvalRequest.status !== 'PENDING') {
    throw new ScrutexityError(
      'STATE_CONFLICT',
      `this approval request is already ${approvalRequest.status}`,
    );
  }
  if (approvalRequest.expires_at.getTime() <= Date.now()) {
    await client.query(
      `UPDATE scrutexity.approval_requests SET status = 'EXPIRED', resolved_at = now() WHERE id = $1`,
      [input.approvalRequestId],
    );
    throw new ScrutexityError('STATE_CONFLICT', 'the approval window for this request has closed');
  }

  const userResult = await client.query(
    `SELECT id, roles, status FROM scrutexity.users WHERE id = $1`,
    [input.approverUserId],
  );
  const user = userResult.rows[0] as { id: string; roles: string[]; status: string } | undefined;
  if (!user) throw new ScrutexityError('NOT_FOUND', 'approver not found');
  if (user.status !== 'ACTIVE') {
    throw new ScrutexityError('FORBIDDEN', 'a disabled user may not approve');
  }

  const requirement = approvalRequest.requirement as { roles: string[] };
  const satisfiedRole = requirement.roles.find((role) => user.roles.includes(role)) ?? null;

  const approvalId = newId('approval');
  try {
    await client.query(
      `INSERT INTO scrutexity.approvals
         (id, organization_id, approval_request_id, approver_user_id, vote,
          roles_at_decision, satisfied_role, comment, idempotency_key)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        approvalId,
        input.organizationId,
        input.approvalRequestId,
        input.approverUserId,
        input.vote,
        // Snapshotted: a role granted or removed later must not retroactively
        // change what this approval meant.
        user.roles,
        satisfiedRole,
        input.comment ?? null,
        input.idempotencyKey ?? null,
      ],
    );
  } catch (error) {
    if (isUniqueViolation(error)) {
      throw new ScrutexityError('STATE_CONFLICT', 'this approver has already voted on this request');
    }
    throw error;
  }

  await appendReceipt(client, keys, {
    organizationId: input.organizationId,
    kind: 'APPROVAL',
    subjectId: input.approverUserId,
    requestId: approvalRequest.request_id,
    decisionId: approvalRequest.decision_id,
    payload: {
      approval_id: approvalId,
      approval_request_id: input.approvalRequestId,
      decision_id: approvalRequest.decision_id,
      authorization_request_id: approvalRequest.request_id,
      approver_user_id: input.approverUserId,
      vote: input.vote,
      roles_at_decision: user.roles,
      satisfied_role: satisfiedRole,
      requirement: approvalRequest.requirement,
      comment: input.comment ?? null,
    },
  });

  metrics.approvalsRecorded.inc({ vote: input.vote });

  const reevaluation = await reevaluateWithApprovals(
    client,
    keys,
    input.organizationId,
    input.approvalRequestId,
  );

  return { approval_id: approvalId, satisfied_role: satisfiedRole, reevaluation };
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { code?: string }).code === '23505';
}
