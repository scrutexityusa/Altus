import {
  ScrutexityError,
  compareDecisionContext,
  computeDecisionContextHash,
  isExpired,
  newId,
} from '@scrutexity/core';
import type { PoolClient } from '../db/pool.js';
import { metrics } from '../metrics.js';
import { appendReceipt, type EvidenceKeys } from './evidence.js';
import { currentContextHash } from './context.js';

/**
 * Recording an execution against a decision.
 *
 * An ALLOW is a single-use, time-boxed execution grant, not a standing
 * permission. Presenting it twice is a replay and is refused by a unique
 * constraint on the decision, not by an application-level check that a race
 * could slip past.
 */

export interface RecordExecutionInput {
  organizationId: string;
  decisionId: string;
  agentId: string;
  status: 'SUCCEEDED' | 'FAILED';
  result?: Record<string, unknown>;
  idempotencyKey?: string | null;
}

export async function recordExecution(
  client: PoolClient,
  keys: EvidenceKeys,
  input: RecordExecutionInput,
) {
  const decisionResult = await client.query(
    'SELECT * FROM scrutexity.authorization_decisions WHERE id = $1',
    [input.decisionId],
  );
  const decision = decisionResult.rows[0];
  if (!decision) throw new ScrutexityError('NOT_FOUND', 'authorization decision not found');

  if (decision.agent_id !== input.agentId) {
    // Possessing another agent's decision id must never let this agent act on
    // it (Section 23, confused deputy).
    throw new ScrutexityError('FORBIDDEN', 'this decision was issued to a different agent');
  }
  if (decision.decision !== 'ALLOW') {
    throw new ScrutexityError(
      'POLICY_DENIED',
      `this decision was ${decision.decision}, not ALLOW`,
      {
        internal: { reason_code: decision.reason_code },
      },
    );
  }
  if (decision.expires_at && isExpired(decision.expires_at, new Date())) {
    throw new ScrutexityError(
      'AUTHORITY_EXPIRED',
      'the execution grant conferred by this decision has expired; re-evaluate',
    );
  }

  // -- The TOCTOU control --------------------------------------------------
  //
  // Recompute the fingerprint of the conditions this decision rests on, as
  // they stand *now*, and refuse if it has moved. A fraud signal that arrived
  // after a treasurer approved a wire is exactly the case this exists for: the
  // approval described a world that no longer holds.
  const current = await currentContextHash(client, decision);
  const comparison = compareDecisionContext(
    decision.context_hash,
    current,
    (decision.approval_ids ?? []).length > 0,
  );
  if (!comparison.matches) {
    metrics.contextMismatches.inc({ approved: String(comparison.was_approved) });
    throw new ScrutexityError(
      comparison.was_approved ? 'APPROVAL_CONTEXT_MISMATCH' : 'CONTEXT_CHANGED',
      comparison.was_approved
        ? 'the conditions changed since this action was approved; it must be re-evaluated and re-approved'
        : 'the conditions changed since this action was authorised; re-evaluate',
      {
        disclose: true,
        internal: { expected: comparison.expected, observed: comparison.observed },
      },
    );
  }

  const executionId = newId('execution');
  try {
    await client.query(
      `INSERT INTO scrutexity.execution_attempts
         (id, organization_id, decision_id, agent_id, status, result, idempotency_key)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        executionId,
        input.organizationId,
        input.decisionId,
        input.agentId,
        input.status,
        JSON.stringify(input.result ?? {}),
        input.idempotencyKey ?? null,
      ],
    );
  } catch (error) {
    if (
      typeof error === 'object' &&
      error !== null &&
      (error as { code?: string }).code === '23505'
    ) {
      metrics.replayAttempts.inc({ kind: 'execution_grant' });
      throw new ScrutexityError(
        'REPLAY_DETECTED',
        'this authorization decision has already been executed against',
      );
    }
    throw error;
  }

  // Spend the grant. Guarded on the claim so an execution can only consume
  // the grant that authorised it, and only once.
  if (decision.authority_lease_id) {
    const consumed = await client.query(
      `UPDATE scrutexity.authority_leases
          SET consumed = true, used_at = now()
        WHERE id = $1
          AND grant_type = 'SINGLE_USE'
          AND claimed_by_decision_id = $2
          AND NOT consumed
        RETURNING id`,
      [decision.authority_lease_id, input.decisionId],
    );
    if ((consumed.rowCount ?? 0) > 0) metrics.singleUseGrantsConsumed.inc({});
  }

  const receipt = await appendReceipt(client, keys, {
    organizationId: input.organizationId,
    kind: 'EXECUTION',
    subjectId: input.agentId,
    requestId: decision.request_id,
    decisionId: input.decisionId,
    payload: {
      execution_id: executionId,
      decision_id: input.decisionId,
      authorization_request_id: decision.request_id,
      agent_id: input.agentId,
      status: input.status,
      result: input.result ?? {},
      grant_expired_at: decision.expires_at ? decision.expires_at.toISOString() : null,
      // Recorded so a verifier can confirm the execution happened under the
      // same conditions the decision was made under.
      context_hash: decision.context_hash,
      authority_lease_id: decision.authority_lease_id,
    },
  });

  return { execution_id: executionId, receipt_id: receipt.id };
}
