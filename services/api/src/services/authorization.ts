import { performance } from 'node:perf_hooks';
import {
  ScrutexityError,
  addSeconds,
  evaluateAuthorization,
  explainDecision,
  hashObject,
  loadPolicyDocument,
  lookupAction,
  newId,
  parseMoney,
  validateActionRequest,
  type Approval,
  type AuthorizationEvaluation,
  type EvaluationSnapshot,
  type LeaseCandidate,
  type PolicyDocument,
  type SignalView,
} from '@scrutexity/core';
import type { PoolClient } from '../db/pool.js';
import { toLease, type AgentRow, type LeaseRow, type SignalRow } from '../db/rows.js';
import { metrics } from '../metrics.js';
import { appendReceipt, type EvidenceKeys } from './evidence.js';

/**
 * ============================================================================
 * The authorization orchestrator -- the Policy Enforcement Point's server side.
 * ============================================================================
 *
 * Its job is to assemble an honest snapshot of the world, hand it to the pure
 * evaluator, and write down what came back. It contains no authorization logic
 * of its own; every branch that decides an outcome lives in @scrutexity/core
 * where it can be replayed. Anything that decided an outcome here would be a
 * decision that could never be reproduced from evidence.
 */

export interface AuthorizeInput {
  organizationId: string;
  agentHandleOrId: string;
  action: string;
  resource: { type: string; id: string };
  context: Record<string, unknown>;
  presentedLeaseId?: string | null;
  nonce?: string | null;
  idempotencyKey?: string | null;
  correlationId?: string | null;
}

export interface AuthorizeResult {
  request_id: string;
  decision_id: string;
  receipt_id: string;
  evaluation: AuthorizationEvaluation;
  approval_request_id: string | null;
}

/** Context keys the control plane derives itself and will not accept from a caller. */
const SERVER_DERIVED_CONTEXT = ['counterparty_known', 'counterparty_status', 'resource_known'] as const;

export async function authorize(
  client: PoolClient,
  keys: EvidenceKeys,
  input: AuthorizeInput,
): Promise<AuthorizeResult> {
  const started = performance.now();
  const now = new Date();

  // -- Agent ----------------------------------------------------------------
  const agentRow = await loadAgent(client, input.agentHandleOrId);
  if (!agentRow) throw new ScrutexityError('NOT_FOUND', 'agent not found');

  // -- Request shape --------------------------------------------------------
  const normalizedContext = normalizeContext(input.context);
  const validation = validateActionRequest(input.action, input.resource.type, normalizedContext);
  if (!validation.ok) {
    throw new ScrutexityError('INVALID_REQUEST', validation.errors.join('; '), {
      details: { errors: validation.errors },
    });
  }

  // Server-derived facts overwrite anything the caller asserted. An agent that
  // could declare its counterparty "known" would have defeated the control by
  // declaring it.
  for (const key of SERVER_DERIVED_CONTEXT) delete normalizedContext[key];
  Object.assign(normalizedContext, await deriveContext(client, input.organizationId, normalizedContext));

  // -- Replay guard ---------------------------------------------------------
  if (input.nonce) {
    const seen = await client.query(
      `SELECT id FROM scrutexity.authorization_requests
        WHERE organization_id = $1 AND agent_id = $2 AND nonce = $3`,
      [input.organizationId, agentRow.id, input.nonce],
    );
    if ((seen.rowCount ?? 0) > 0) {
      metrics.replayAttempts.inc({ kind: 'authorization_nonce' });
      throw new ScrutexityError('REPLAY_DETECTED', 'this authorization request has already been submitted', {
        details: { nonce: input.nonce, original_request_id: seen.rows[0]!.id },
      });
    }
  }

  // -- Persist the request (immutable from here on) -------------------------
  const requestId = newId('authorizationRequest');
  const requestHash = hashObject({
    organization_id: input.organizationId,
    agent_id: agentRow.id,
    action: input.action,
    resource: input.resource,
    context: normalizedContext,
  });

  await client.query(
    `INSERT INTO scrutexity.authorization_requests
       (id, organization_id, agent_id, presented_lease_id, action, resource_type,
        resource_id, context, request_hash, nonce, idempotency_key, correlation_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [
      requestId,
      input.organizationId,
      agentRow.id,
      input.presentedLeaseId ?? null,
      input.action,
      input.resource.type,
      input.resource.id,
      JSON.stringify(normalizedContext),
      requestHash,
      input.nonce ?? null,
      input.idempotencyKey ?? null,
      input.correlationId ?? null,
    ],
  );

  const snapshot = await buildSnapshot(client, {
    now,
    organizationId: input.organizationId,
    requestId,
    agentRow,
    action: input.action,
    resource: input.resource,
    context: normalizedContext,
    presentedLeaseId: input.presentedLeaseId ?? null,
    priorApproval: null,
  });

  const evaluationStarted = performance.now();
  const evaluation = evaluateAuthorization(snapshot);
  metrics.policyEvaluationLatency.observe((performance.now() - evaluationStarted) / 1000);

  const persisted = await persistDecision(client, keys, {
    organizationId: input.organizationId,
    requestId,
    agentId: agentRow.id,
    agentHandle: agentRow.handle,
    evaluation,
    supersedesDecisionId: null,
    startedAt: started,
  });

  return { request_id: requestId, ...persisted, evaluation };
}

/**
 * Re-evaluates an escalated request once approvals have been recorded. The
 * original request is never mutated: this produces a *new* decision that
 * supersedes the escalation, so the evidence shows both what was asked of the
 * humans and what they answered.
 */
export async function reevaluateWithApprovals(
  client: PoolClient,
  keys: EvidenceKeys,
  organizationId: string,
  approvalRequestId: string,
): Promise<AuthorizeResult | null> {
  const started = performance.now();
  const now = new Date();

  const apr = await client.query(
    `SELECT ar.*, d.id AS decision_id
       FROM scrutexity.approval_requests ar
       JOIN scrutexity.authorization_decisions d ON d.id = ar.decision_id
      WHERE ar.id = $1`,
    [approvalRequestId],
  );
  const approvalRequest = apr.rows[0];
  if (!approvalRequest) return null;

  const requestRow = await client.query(
    'SELECT * FROM scrutexity.authorization_requests WHERE id = $1',
    [approvalRequest.request_id],
  );
  const request = requestRow.rows[0];
  if (!request) return null;

  const agentRow = await loadAgent(client, request.agent_id);
  if (!agentRow) return null;

  const approvals = await loadApprovals(client, approvalRequestId);

  const snapshot = await buildSnapshot(client, {
    now,
    organizationId,
    requestId: request.id,
    agentRow,
    action: request.action,
    resource: { type: request.resource_type, id: request.resource_id },
    context: request.context,
    presentedLeaseId: request.presented_lease_id,
    priorApproval: {
      approval_request_id: approvalRequestId,
      requirement: approvalRequest.requirement,
      approvals,
      expires_at: approvalRequest.expires_at.toISOString(),
    },
  });

  const evaluation = evaluateAuthorization(snapshot);

  const persisted = await persistDecision(client, keys, {
    organizationId,
    requestId: request.id,
    agentId: agentRow.id,
    agentHandle: agentRow.handle,
    evaluation,
    supersedesDecisionId: approvalRequest.decision_id,
    startedAt: started,
    // The re-evaluation resolves the escalation; do not open another one.
    suppressApprovalRequest: true,
  });

  const nextStatus =
    evaluation.decision === 'ALLOW'
      ? 'SATISFIED'
      : evaluation.reason_code === 'APPROVAL_REJECTED'
        ? 'REJECTED'
        : evaluation.reason_code === 'APPROVAL_EXPIRED'
          ? 'EXPIRED'
          : 'PENDING';

  if (nextStatus !== 'PENDING') {
    await client.query(
      `UPDATE scrutexity.approval_requests
          SET status = $2, resolved_at = now()
        WHERE id = $1 AND status = 'PENDING'`,
      [approvalRequestId, nextStatus],
    );
    metrics.approvalLatency.observe(
      (now.getTime() - approvalRequest.created_at.getTime()) / 1000,
      { outcome: nextStatus },
    );
  }

  return { request_id: request.id, ...persisted, evaluation };
}

// ---------------------------------------------------------------------------
// Snapshot assembly
// ---------------------------------------------------------------------------

interface SnapshotInput {
  now: Date;
  organizationId: string;
  requestId: string;
  agentRow: AgentRow;
  action: string;
  resource: { type: string; id: string };
  context: Record<string, unknown>;
  presentedLeaseId: string | null;
  priorApproval: EvaluationSnapshot['prior_approval'];
}

async function buildSnapshot(client: PoolClient, input: SnapshotInput): Promise<EvaluationSnapshot> {
  // Sequential, not Promise.all: these share one pooled client, and a pg
  // client cannot execute concurrent queries. Fanning out here would silently
  // serialise anyway today and break outright on pg 9.
  const policy = await loadActivePolicy(client, input.organizationId);
  const candidates = await loadLeaseCandidates(client, input.agentRow.id);
  const signals = await loadLiveSignals(client, input.organizationId, input.now, {
    agentId: input.agentRow.id,
    resourceId: input.resource.id,
    counterpartyId: input.context['counterparty_id'] as string | undefined,
  });
  const attributes = await loadResourceAttributes(client, input.organizationId, input.resource);

  return {
    now: input.now,
    request: {
      id: input.requestId,
      organization_id: input.organizationId,
      agent_id: input.agentRow.id,
      action: input.action,
      resource: { ...input.resource, attributes },
      context: input.context,
      presented_lease_id: input.presentedLeaseId,
    },
    agent: {
      id: input.agentRow.id,
      handle: input.agentRow.handle,
      status: input.agentRow.status,
      owner_user_id: input.agentRow.owner_user_id,
    },
    policy,
    candidates,
    signals,
    prior_approval: input.priorApproval,
    dependencies: {
      policy_available: policy !== null,
      signals_available: true,
      enforcement_available: true,
    },
  };
}

/**
 * Money in a request context is parsed into exact minor units before it can
 * influence anything. A caller that sends `"amount": 0.1` gets an
 * INVALID_REQUEST, not a threshold comparison against a float.
 */
function normalizeContext(context: Record<string, unknown>): Record<string, unknown> {
  const normalized: Record<string, unknown> = { ...context };
  const amount = normalized['amount'];
  const currency = normalized['currency'];
  if (amount !== undefined && amount !== null) {
    if (typeof currency !== 'string') {
      throw new ScrutexityError('INVALID_REQUEST', 'context.amount requires context.currency');
    }
    if (typeof amount !== 'string' && typeof amount !== 'number') {
      throw new ScrutexityError('INVALID_REQUEST', 'context.amount must be a decimal string or an integer');
    }
    try {
      normalized['amount'] = parseMoney(amount, currency);
    } catch (error) {
      throw new ScrutexityError(
        'INVALID_REQUEST',
        error instanceof Error ? error.message : 'invalid amount',
      );
    }
    normalized['currency'] = currency.toUpperCase();
  }
  return normalized;
}

/** Facts the control plane establishes itself from the tenant's own records. */
async function deriveContext(
  client: PoolClient,
  organizationId: string,
  context: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const counterpartyId = context['counterparty_id'];
  if (typeof counterpartyId !== 'string') return {};

  const result = await client.query(
    `SELECT attributes FROM scrutexity.resources
      WHERE organization_id = $1 AND resource_type = 'counterparty' AND external_id = $2`,
    [organizationId, counterpartyId],
  );
  const row = result.rows[0] as { attributes: Record<string, unknown> } | undefined;
  return {
    counterparty_known: row !== undefined,
    counterparty_status: (row?.attributes?.['status'] as string | undefined) ?? 'UNKNOWN',
  };
}

async function loadAgent(client: PoolClient, handleOrId: string): Promise<AgentRow | null> {
  const result = await client.query(
    'SELECT * FROM scrutexity.agents WHERE id = $1 OR handle = $1',
    [handleOrId],
  );
  return (result.rows[0] as AgentRow | undefined) ?? null;
}

/**
 * Loads the agent's leases together with their full ancestry in one recursive
 * pass, so revocation of an ancestor is visible to this decision rather than
 * to the next background sweep.
 */
async function loadLeaseCandidates(client: PoolClient, agentId: string): Promise<LeaseCandidate[]> {
  const own = await client.query(
    `SELECT * FROM scrutexity.authority_leases
      WHERE agent_id = $1 AND status <> 'EXPIRED'
      ORDER BY issued_at DESC
      LIMIT 100`,
    [agentId],
  );
  const leases = own.rows as LeaseRow[];
  if (leases.length === 0) return [];

  const ancestors = await client.query(
    `WITH RECURSIVE chain AS (
       SELECT l.*, l.id AS root_of
         FROM scrutexity.authority_leases l
        WHERE l.id = ANY($1::text[])
       UNION ALL
       SELECT p.*, c.root_of
         FROM scrutexity.authority_leases p
         JOIN chain c ON p.id = c.parent_lease_id
     )
     SELECT * FROM chain`,
    [leases.map((l) => l.id)],
  );

  const byRoot = new Map<string, LeaseRow[]>();
  for (const row of ancestors.rows as (LeaseRow & { root_of: string })[]) {
    const list = byRoot.get(row.root_of) ?? [];
    list.push(row);
    byRoot.set(row.root_of, list);
  }

  return leases.map((lease) => {
    // Leaf-first ordering is what evaluateChain expects.
    const chain = (byRoot.get(lease.id) ?? [lease]).sort((a, b) => b.depth - a.depth);
    return { lease: toLease(lease), chain: chain.map(toLease) };
  });
}

/**
 * Only live signals are loaded. Freshness is enforced here, at the read, so no
 * policy author can forget to check a TTL and no stale signal can suppress
 * authority forever (Section 39).
 */
async function loadLiveSignals(
  client: PoolClient,
  organizationId: string,
  now: Date,
  subjects: { agentId: string; resourceId: string; counterpartyId?: string | undefined },
): Promise<SignalView[]> {
  const ids = [subjects.agentId, subjects.resourceId, subjects.counterpartyId, organizationId].filter(
    (v): v is string => typeof v === 'string',
  );
  const result = await client.query(
    `SELECT id, subject_type, subject_id, signal_type, value, confidence, source, issued_at, expires_at
       FROM scrutexity.risk_signals
      WHERE organization_id = $1
        AND superseded_at IS NULL
        AND expires_at > $2
        AND subject_id = ANY($3::text[])
      ORDER BY issued_at DESC
      LIMIT 200`,
    [organizationId, now, ids],
  );
  return (result.rows as SignalRow[]).map((row) => ({
    id: row.id,
    subject_type: row.subject_type,
    subject_id: row.subject_id,
    signal_type: row.signal_type,
    value: String(row.value),
    confidence: String(row.confidence),
    source: row.source,
    issued_at: row.issued_at.toISOString(),
    expires_at: row.expires_at.toISOString(),
  }));
}

async function loadResourceAttributes(
  client: PoolClient,
  organizationId: string,
  resource: { type: string; id: string },
): Promise<Record<string, unknown>> {
  const result = await client.query(
    `SELECT attributes FROM scrutexity.resources
      WHERE organization_id = $1 AND resource_type = $2 AND external_id = $3`,
    [organizationId, resource.type, resource.id],
  );
  return (result.rows[0]?.attributes as Record<string, unknown> | undefined) ?? {};
}

let policyCache = new Map<string, { hash: string; document: PolicyDocument }>();

export function clearPolicyCache(): void {
  policyCache = new Map();
}

async function loadActivePolicy(
  client: PoolClient,
  organizationId: string,
): Promise<EvaluationSnapshot['policy']> {
  const result = await client.query(
    `SELECT pv.id, pv.policy_id, pv.content, pv.content_hash
       FROM scrutexity.policy_versions pv
      WHERE pv.organization_id = $1 AND pv.status = 'ACTIVE'
      ORDER BY pv.activated_at DESC
      LIMIT 1`,
    [organizationId],
  );
  const row = result.rows[0] as
    | { id: string; policy_id: string; content: unknown; content_hash: string }
    | undefined;
  if (!row) return null;

  // Policy versions are immutable, so caching one by its content hash is safe
  // for as long as the hash matches -- and never longer.
  const cached = policyCache.get(row.id);
  if (cached && cached.hash === row.content_hash) {
    metrics.policyCache.inc({ result: 'hit' });
    return { policy_id: row.policy_id, policy_version_id: row.id, document: cached.document };
  }
  metrics.policyCache.inc({ result: 'miss' });
  const { document, hash } = loadPolicyDocument(row.content);
  if (hash !== row.content_hash) {
    // The stored document no longer hashes to its recorded digest. Something
    // wrote to an immutable row; refuse to evaluate against it.
    metrics.policyEvaluationFailures.inc({ reason: 'policy_hash_mismatch' });
    throw new ScrutexityError('POLICY_UNAVAILABLE', 'stored policy version failed its integrity check', {
      internal: { policy_version_id: row.id, recorded: row.content_hash, recomputed: hash },
    });
  }
  policyCache.set(row.id, { hash, document });
  return { policy_id: row.policy_id, policy_version_id: row.id, document };
}

async function loadApprovals(client: PoolClient, approvalRequestId: string): Promise<Approval[]> {
  const result = await client.query(
    `SELECT id, approval_request_id, approver_user_id, vote, roles_at_decision,
            satisfied_role, comment, created_at
       FROM scrutexity.approvals WHERE approval_request_id = $1 ORDER BY created_at ASC`,
    [approvalRequestId],
  );
  return result.rows.map((row) => ({
    id: row.id,
    approval_request_id: row.approval_request_id,
    approver_user_id: row.approver_user_id,
    vote: row.vote,
    roles_at_decision: row.roles_at_decision,
    satisfied_role: row.satisfied_role,
    comment: row.comment,
    created_at: row.created_at.toISOString(),
  }));
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

interface PersistInput {
  organizationId: string;
  requestId: string;
  agentId: string;
  agentHandle: string;
  evaluation: AuthorizationEvaluation;
  supersedesDecisionId: string | null;
  startedAt: number;
  suppressApprovalRequest?: boolean;
}

async function persistDecision(
  client: PoolClient,
  keys: EvidenceKeys,
  input: PersistInput,
): Promise<{ decision_id: string; receipt_id: string; approval_request_id: string | null }> {
  const { evaluation } = input;
  const decisionId = newId('decision');
  const durationUs = Math.round((performance.now() - input.startedAt) * 1000);

  await client.query(
    `INSERT INTO scrutexity.authorization_decisions
       (id, organization_id, request_id, agent_id, decision, reason_code, policy_id,
        policy_version_id, policy_hash, authority_lease_id, evaluation, approval_requirement,
        failover_behavior, risk_signal_ids, approval_ids, supersedes_decision_id,
        expires_at, decided_at, evaluation_duration_us)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
    [
      decisionId,
      input.organizationId,
      input.requestId,
      input.agentId,
      evaluation.decision,
      evaluation.reason_code,
      evaluation.policy_id,
      evaluation.policy_version_id,
      evaluation.policy_hash,
      evaluation.authority_lease_id,
      JSON.stringify(evaluation.evaluation),
      evaluation.approval_requirement ? JSON.stringify(evaluation.approval_requirement) : null,
      evaluation.failover_behavior,
      evaluation.risk_signal_ids,
      evaluation.approval_state?.counted.map((c) => c.approval_id) ?? [],
      input.supersedesDecisionId,
      evaluation.expires_at,
      evaluation.decision_timestamp,
      durationUs,
    ],
  );

  let approvalRequestId: string | null = null;
  if (
    evaluation.decision === 'ESCALATE' &&
    evaluation.approval_requirement &&
    !input.suppressApprovalRequest
  ) {
    approvalRequestId = newId('approvalRequest');
    await client.query(
      `INSERT INTO scrutexity.approval_requests
         (id, organization_id, decision_id, request_id, requirement, status, expires_at)
       VALUES ($1,$2,$3,$4,$5,'PENDING',$6)`,
      [
        approvalRequestId,
        input.organizationId,
        decisionId,
        input.requestId,
        JSON.stringify(evaluation.approval_requirement),
        addSeconds(new Date(evaluation.decision_timestamp), evaluation.approval_requirement.ttl_seconds),
      ],
    );
  }

  const explanation = explainDecision(evaluation, { agent_handle: input.agentHandle });

  const receipt = await appendReceipt(client, keys, {
    organizationId: input.organizationId,
    kind: 'AUTHORIZATION_DECISION',
    subjectId: input.agentId,
    requestId: input.requestId,
    decisionId,
    payload: {
      decision_id: decisionId,
      authorization_request_id: input.requestId,
      agent_id: input.agentId,
      action: evaluation.action,
      resource: evaluation.resource,
      decision: evaluation.decision,
      reason_code: evaluation.reason_code,
      policy_id: evaluation.policy_id,
      policy_version: evaluation.policy_version,
      policy_hash: evaluation.policy_hash,
      authority_lease_id: evaluation.authority_lease_id,
      risk_signal_ids: evaluation.risk_signal_ids,
      approval_ids: evaluation.approval_state?.counted.map((c) => c.approval_id) ?? [],
      approval_requirement: evaluation.approval_requirement,
      constraints_evaluated: evaluation.constraints_evaluated,
      failover_behavior: evaluation.failover_behavior,
      supersedes_decision_id: input.supersedesDecisionId,
      decision_timestamp: evaluation.decision_timestamp,
      explanation_text: explanation.text,
    },
  });

  metrics.authorizationDecisions.inc({
    decision: evaluation.decision,
    reason: evaluation.reason_code,
  });
  metrics.authorizationLatency.observe((performance.now() - input.startedAt) / 1000, {
    decision: evaluation.decision,
  });
  if (evaluation.reason_code === 'AUTHORITY_EXPIRED') metrics.leasesExpired.inc({});

  return { decision_id: decisionId, receipt_id: receipt.id, approval_request_id: approvalRequestId };
}

export { lookupAction };
