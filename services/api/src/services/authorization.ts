import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import {
  canonicalOperation,
  computeBindingHash,
  computeIntentHash,
  type ExecutionGrantBinding,
  ScrutexityError,
  addSeconds,
  computeCorrectiveActions,
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
  type CorrectiveAction,
  type LeaseCandidate,
  type PolicyDocument,
  type SignalView,
} from '@scrutexity/core';
import type { PoolClient } from '../db/pool.js';
import { toLease, type AgentRow, type LeaseRow, type SignalRow } from '../db/rows.js';
import { metrics } from '../metrics.js';
import { appendReceipt, type EvidenceKeys } from './evidence.js';
import { normalizeContext } from './request-context.js';

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
  /** What the agent says it is doing; bound against policy intents and lease purpose. */
  declaredIntent?: string | null;
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
  /** The next legitimate step, when policy admits one. Empty for an ALLOW. */
  corrective_actions: CorrectiveAction[];
  /**
   * The operation this ALLOW authorises, and the authority it is bound to.
   * Both null unless the decision was an ALLOW -- nothing else authorises an
   * operation, so nothing else has an intent to bind. See ADR-0015.
   */
  exact_intent_hash: string | null;
  binding_hash: string | null;
}

/** Context keys the control plane derives itself and will not accept from a caller. */
const SERVER_DERIVED_CONTEXT = [
  'counterparty_known',
  'counterparty_status',
  'resource_known',
] as const;

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
  Object.assign(
    normalizedContext,
    await deriveContext(client, input.organizationId, normalizedContext),
  );

  // -- Replay guard ---------------------------------------------------------
  if (input.nonce) {
    const seen = await client.query(
      `SELECT id FROM scrutexity.authorization_requests
        WHERE organization_id = $1 AND agent_id = $2 AND nonce = $3`,
      [input.organizationId, agentRow.id, input.nonce],
    );
    if ((seen.rowCount ?? 0) > 0) {
      metrics.replayAttempts.inc({ kind: 'authorization_nonce' });
      throw new ScrutexityError(
        'REPLAY_DETECTED',
        'this authorization request has already been submitted',
        {
          details: { nonce: input.nonce, original_request_id: seen.rows[0]!.id },
        },
      );
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
        resource_id, context, request_hash, nonce, idempotency_key, correlation_id,
        declared_intent)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
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
      input.declaredIntent ?? null,
    ],
  );

  // Serialise contenders for this agent's single-use grants.
  //
  // A per-agent advisory lock rather than SELECT ... FOR UPDATE over the
  // grants themselves. Row locks looked like the obvious tool and deadlocked
  // under load: an agent holding several unspent grants had concurrent
  // transactions acquire overlapping row locks, and ORDER BY does not reliably
  // fix that because the planner is free to lock before it sorts. One lock
  // keyed on the agent has no ordering to get wrong.
  //
  // Taken only when the agent actually holds an unspent single-use grant, so
  // agents working purely from reusable authority stay fully concurrent. The
  // unlocked probe is safe: a grant created after it is by definition
  // unclaimed by this transaction, so it cannot be double-spent here.
  //
  // The lock is transaction-scoped and is always acquired before the evidence
  // chain head, which is the only other lock on this path -- so the two can
  // never form a cycle.
  const hasSingleUse = await client.query(
    `SELECT 1 FROM scrutexity.authority_leases
      WHERE agent_id = $1 AND grant_type = 'SINGLE_USE' AND NOT consumed
      LIMIT 1`,
    [agentRow.id],
  );
  if ((hasSingleUse.rowCount ?? 0) > 0) {
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [agentRow.id]);
  }

  const snapshot = await buildSnapshot(client, {
    now,
    organizationId: input.organizationId,
    requestId,
    requestHash,
    declaredIntent: input.declaredIntent ?? null,
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

  // The approval request id is minted before the corrective handshake is
  // computed, so an escalation can hand the caller the request it must act on
  // rather than a null it has to go and look up.
  const approvalRequestId =
    evaluation.decision === 'ESCALATE' && evaluation.approval_requirement
      ? newId('approvalRequest')
      : null;

  const correctiveActions = await buildCorrectiveActions(client, evaluation, snapshot, {
    approvalRequestId,
  });

  const persisted = await persistDecision(client, keys, {
    organizationId: input.organizationId,
    requestId,
    agentId: agentRow.id,
    agentHandle: agentRow.handle,
    evaluation,
    supersedesDecisionId: null,
    startedAt: started,
    correctiveActions,
    approvalRequestId,
    requestContext: normalizedContext,
  });

  await claimSingleUseGrant(client, evaluation, persisted.decision_id);

  return {
    request_id: requestId,
    ...persisted,
    evaluation,
    corrective_actions: correctiveActions,
  };
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
    requestHash: request.request_hash,
    declaredIntent: request.declared_intent ?? null,
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
  const reevaluationActions = await buildCorrectiveActions(client, evaluation, snapshot, {
    // The escalation is being resolved, not reopened, so there is no new
    // approval request to point at.
    approvalRequestId: null,
  });

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
    correctiveActions: reevaluationActions,
    requestContext: request.context,
    // The fingerprint the approvers were actually shown. Binding it means an
    // execution presented against a different approval fails the binding check
    // even when the operation itself is byte-identical.
    approvedContextHash: approvalRequest.context_hash ?? null,
  });

  await claimSingleUseGrant(client, evaluation, persisted.decision_id);

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
    metrics.approvalLatency.observe((now.getTime() - approvalRequest.created_at.getTime()) / 1000, {
      outcome: nextStatus,
    });
  }

  return {
    request_id: request.id,
    ...persisted,
    evaluation,
    corrective_actions: reevaluationActions,
  };
}

// ---------------------------------------------------------------------------
// Snapshot assembly
// ---------------------------------------------------------------------------

interface SnapshotInput {
  now: Date;
  organizationId: string;
  requestId: string;
  requestHash: string;
  declaredIntent: string | null;
  agentRow: AgentRow;
  action: string;
  resource: { type: string; id: string };
  context: Record<string, unknown>;
  presentedLeaseId: string | null;
  priorApproval: EvaluationSnapshot['prior_approval'];
}

async function buildSnapshot(
  client: PoolClient,
  input: SnapshotInput,
): Promise<EvaluationSnapshot> {
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
      request_hash: input.requestHash,
      declared_intent: input.declaredIntent,
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
  const ids = [
    subjects.agentId,
    subjects.resourceId,
    subjects.counterpartyId,
    organizationId,
  ].filter((v): v is string => typeof v === 'string');
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
    { id: string; policy_id: string; content: unknown; content_hash: string } | undefined;
  if (!row) return null;

  // The integrity check runs on every load, not only on a cache miss. Caching
  // the parsed document is a parsing optimisation; it must never become the
  // reason a tampered policy row goes unnoticed. Hashing the stored JSON is
  // cheap next to the round trip that fetched it.
  const storedHash = hashObject(row.content);
  if (storedHash !== row.content_hash) {
    metrics.policyEvaluationFailures.inc({ reason: 'policy_hash_mismatch' });
    throw new ScrutexityError(
      'POLICY_UNAVAILABLE',
      'stored policy version failed its integrity check',
      {
        internal: { policy_version_id: row.id, recorded: row.content_hash, recomputed: storedHash },
      },
    );
  }

  const cached = policyCache.get(row.id);
  if (cached && cached.hash === storedHash) {
    metrics.policyCache.inc({ result: 'hit' });
    return { policy_id: row.policy_id, policy_version_id: row.id, document: cached.document };
  }
  metrics.policyCache.inc({ result: 'miss' });

  const { document, hash } = loadPolicyDocument(row.content);
  if (hash !== row.content_hash) {
    // The document parses, but not back to the digest it was activated under.
    // Refuse rather than evaluate against something nobody approved.
    metrics.policyEvaluationFailures.inc({ reason: 'policy_reparse_mismatch' });
    throw new ScrutexityError(
      'POLICY_UNAVAILABLE',
      'stored policy version failed its integrity check',
      {
        internal: { policy_version_id: row.id, recorded: row.content_hash, recomputed: hash },
      },
    );
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
  correctiveActions: CorrectiveAction[];
  approvalRequestId?: string | null;
  /**
   * The context the decision was evaluated against, after server-derived facts
   * replaced anything the caller asserted. This -- not the caller's original
   * body -- is what the intent hash is computed from.
   */
  requestContext: Record<string, unknown>;
  /**
   * The TOCTOU fingerprint the approvers were shown, when this decision is a
   * re-evaluation after human approval. Bound into the grant so that an
   * execution presented against a different approval fails even though the
   * operation itself is untouched.
   */
  approvedContextHash?: string | null;
}

async function persistDecision(
  client: PoolClient,
  keys: EvidenceKeys,
  input: PersistInput,
): Promise<{
  decision_id: string;
  receipt_id: string;
  approval_request_id: string | null;
  exact_intent_hash: string | null;
  binding_hash: string | null;
}> {
  const { evaluation } = input;
  const decisionId = newId('decision');
  const durationUs = Math.round((performance.now() - input.startedAt) * 1000);

  // -- Exact intent binding -------------------------------------------------
  //
  // Only an ALLOW gets a binding, because only an ALLOW authorises an
  // operation. Computing one for a DENY would be recording authority that was
  // never granted.
  //
  // The binding is computed *here*, from the evaluated request, and never from
  // anything a caller supplies. That is the whole point: a hash the agent
  // provides proves only that the agent can compute a hash. See ADR-0015.
  const binding =
    evaluation.decision === 'ALLOW'
      ? buildBinding(
          decisionId,
          evaluation,
          input.requestContext,
          input.approvedContextHash ?? null,
        )
      : null;

  await client.query(
    `INSERT INTO scrutexity.authorization_decisions
       (id, organization_id, request_id, agent_id, decision, reason_code, policy_id,
        policy_version_id, policy_hash, authority_lease_id, evaluation, approval_requirement,
        failover_behavior, risk_signal_ids, approval_ids, supersedes_decision_id,
        expires_at, decided_at, evaluation_duration_us, context_hash, intent_evaluation,
        corrective_actions, exact_intent_hash, binding_hash, binding_nonce, authorized_intent)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
             $23,$24,$25,$26)`,
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
      evaluation.context_hash,
      evaluation.intent_evaluation ? JSON.stringify(evaluation.intent_evaluation) : null,
      JSON.stringify(input.correctiveActions),
      binding?.intent_hash ?? null,
      binding?.binding_hash ?? null,
      binding?.binding.nonce ?? null,
      binding ? JSON.stringify(binding.binding.authorized_intent) : null,
    ],
  );

  let approvalRequestId: string | null = null;
  if (
    evaluation.decision === 'ESCALATE' &&
    evaluation.approval_requirement &&
    !input.suppressApprovalRequest
  ) {
    approvalRequestId = input.approvalRequestId ?? newId('approvalRequest');
    await client.query(
      `INSERT INTO scrutexity.approval_requests
         (id, organization_id, decision_id, request_id, requirement, status, expires_at,
          context_hash)
       VALUES ($1,$2,$3,$4,$5,'PENDING',$6,$7)`,
      [
        approvalRequestId,
        input.organizationId,
        decisionId,
        input.requestId,
        JSON.stringify(evaluation.approval_requirement),
        addSeconds(
          new Date(evaluation.decision_timestamp),
          evaluation.approval_requirement.ttl_seconds,
        ),
        // The conditions the approvers are being shown. Recorded here so an
        // approval can be bound to them and execution can verify they held.
        evaluation.context_hash,
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
      // The conditions this decision rests on, so a verifier can tell whether
      // an execution happened under the same facts that were approved.
      context_hash: evaluation.context_hash,
      intent_evaluation: evaluation.intent_evaluation,
      corrective_actions: input.correctiveActions,
      explanation_text: explanation.text,
      // The operation this decision authorised, and its two hashes. A verifier
      // holding only the receipt can recompute both and check them, without
      // access to the database that issued them.
      exact_intent_hash: binding?.intent_hash ?? null,
      binding_hash: binding?.binding_hash ?? null,
      authorized_intent: binding?.binding.authorized_intent ?? null,
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

  return {
    decision_id: decisionId,
    receipt_id: receipt.id,
    approval_request_id: approvalRequestId,
    exact_intent_hash: binding?.intent_hash ?? null,
    binding_hash: binding?.binding_hash ?? null,
  };
}

/**
 * Builds the grant binding for an ALLOW.
 *
 * Every input comes from the evaluated request or from the decision being
 * written. Nothing here is caller-supplied, and nothing here reads the clock
 * beyond the decision timestamp the evaluator already fixed, so the same
 * evaluation always produces the same binding except for the nonce.
 *
 * The nonce is fresh randomness rather than a derivation of the decision id,
 * so that two legitimately identical operations -- the same supplier, the same
 * amount, twice in a day -- cannot produce interchangeable bindings.
 */
function buildBinding(
  decisionId: string,
  evaluation: AuthorizationEvaluation,
  requestContext: Record<string, unknown>,
  approvedContextHash: string | null,
): { intent_hash: string; binding_hash: string; binding: ExecutionGrantBinding } {
  const authorizedIntent = canonicalOperation({
    action: evaluation.action,
    resource: evaluation.resource,
    context: requestContext,
  });
  const binding: ExecutionGrantBinding = {
    authorized_intent: authorizedIntent,
    authorization_context: {
      decision_id: decisionId,
      authority_lease_id: evaluation.authority_lease_id,
      policy_version_id: evaluation.policy_version_id,
      policy_hash: evaluation.policy_hash,
      approved_context_hash: approvedContextHash,
    },
    grant_id: decisionId,
    // An ALLOW always carries an expiry; the schema requires it. The fallback
    // exists so a future decision shape cannot silently bind an eternal grant.
    expires_at: evaluation.expires_at ?? evaluation.decision_timestamp,
    nonce: randomUUID(),
  };
  return {
    intent_hash: computeIntentHash(authorizedIntent),
    binding_hash: computeBindingHash(binding),
    binding,
  };
}

/**
 * Binds a single-use grant to the decision that spent it.
 *
 * The WHERE clause is the exactly-once boundary. The row is already locked for
 * this transaction, so a competing claim cannot be interleaved; the guard is
 * there so that even without the lock the database, not the application,
 * decides who won. Zero rows means someone else got there first, which under
 * the lock can only happen through a bug -- so it is raised rather than
 * swallowed.
 */
async function claimSingleUseGrant(
  client: PoolClient,
  evaluation: AuthorizationEvaluation,
  decisionId: string,
): Promise<void> {
  if (evaluation.decision !== 'ALLOW' || !evaluation.authority_lease_id) return;

  const claimed = await client.query(
    `UPDATE scrutexity.authority_leases
        SET claimed_at = now(), claimed_by_decision_id = $2
      WHERE id = $1
        AND grant_type = 'SINGLE_USE'
        AND NOT consumed
        AND claimed_at IS NULL
      RETURNING id`,
    [evaluation.authority_lease_id, decisionId],
  );

  if ((claimed.rowCount ?? 0) > 0) {
    metrics.singleUseGrantsClaimed.inc({});
    return;
  }

  const grant = await client.query(
    `SELECT grant_type, claimed_by_decision_id FROM scrutexity.authority_leases WHERE id = $1`,
    [evaluation.authority_lease_id],
  );
  const row = grant.rows[0] as
    { grant_type: string; claimed_by_decision_id: string | null } | undefined;
  if (row?.grant_type === 'SINGLE_USE' && row.claimed_by_decision_id !== decisionId) {
    throw new ScrutexityError(
      'STATE_CONFLICT',
      'this single-use authority was claimed concurrently; re-evaluate',
      { internal: { lease: evaluation.authority_lease_id, holder: row.claimed_by_decision_id } },
    );
  }
}

/**
 * Corrective actions are computed by the core policy layer from the decision
 * record itself. This function supplies only the surrounding facts core cannot
 * see: who delegated the authority in play, and which intents policy declares.
 */
async function buildCorrectiveActions(
  client: PoolClient,
  evaluation: AuthorizationEvaluation,
  snapshot: EvaluationSnapshot,
  options: { approvalRequestId: string | null },
): Promise<CorrectiveAction[]> {
  if (evaluation.decision === 'ALLOW') return [];

  let delegatingAgentHandle: string | null = null;
  const selected = snapshot.candidates.find(
    (candidate) => candidate.lease.id === evaluation.authority_lease_id,
  );
  const parentLeaseId = selected?.lease.parent_lease_id ?? null;
  if (parentLeaseId) {
    const issuer = await client.query(
      `SELECT a.handle FROM scrutexity.authority_leases l
         JOIN scrutexity.agents a ON a.id = l.agent_id
        WHERE l.id = $1`,
      [parentLeaseId],
    );
    delegatingAgentHandle = (issuer.rows[0]?.handle as string | undefined) ?? null;
  }

  const actions = computeCorrectiveActions(evaluation, {
    delegating_agent_handle: delegatingAgentHandle,
    approval_request_id: options.approvalRequestId,
    known_intents: snapshot.policy?.document.intents.map((intent) => intent.id) ?? [],
  });

  for (const action of actions) {
    metrics.correctiveActionsReturned.inc({ type: action.type, reason: action.reason });
  }
  if (evaluation.intent_evaluation && !evaluation.intent_evaluation.match) {
    metrics.intentMismatches.inc({ reason: evaluation.intent_evaluation.reason });
  }
  return actions;
}

export { lookupAction };
