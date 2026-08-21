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

/**
 * Recomputes the decision's context fingerprint against the world as it stands
 * now: the same request, the same policy version and authority, and every risk
 * signal live at this instant.
 */
async function currentContextHash(
  client: PoolClient,
  decision: {
    request_id: string;
    organization_id: string;
    policy_version_id: string | null;
    policy_hash: string | null;
    authority_lease_id: string | null;
  },
): Promise<string> {
  const request = await client.query(
    `SELECT agent_id, request_hash, resource_id, context
       FROM scrutexity.authorization_requests WHERE id = $1`,
    [decision.request_id],
  );
  const requestRow = request.rows[0] as
    | {
        agent_id: string;
        request_hash: string;
        resource_id: string;
        context: Record<string, unknown>;
      }
    | undefined;
  if (!requestRow) {
    throw new ScrutexityError(
      'NOT_FOUND',
      'the authorization request for this decision is missing',
    );
  }

  const subjects = [
    requestRow.agent_id,
    requestRow.resource_id,
    requestRow.context['counterparty_id'] as string | undefined,
    decision.organization_id,
  ].filter((value): value is string => typeof value === 'string');

  const signals = await client.query(
    `SELECT id, signal_type, subject_id, value
       FROM scrutexity.risk_signals
      WHERE organization_id = $1
        AND superseded_at IS NULL
        AND expires_at > now()
        AND subject_id = ANY($2::text[])
      ORDER BY id ASC
      LIMIT 200`,
    [decision.organization_id, subjects],
  );

  return computeDecisionContextHash({
    request_hash: requestRow.request_hash,
    policy_version_id: decision.policy_version_id,
    policy_hash: decision.policy_hash,
    authority_lease_id: decision.authority_lease_id,
    signals: signals.rows.map((row) => ({
      id: row.id as string,
      signal_type: row.signal_type as string,
      subject_id: row.subject_id as string,
      value: String(row.value),
    })),
  });
}
