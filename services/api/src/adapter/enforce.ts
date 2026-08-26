import {
  ScrutexityError,
  canonicalOperation,
  compareDecisionContext,
  computeBindingHash,
  computeIntentHash,
  diffOperations,
  effectiveLeaseStatus,
  isExpired,
  newId,
  type CanonicalOperation,
  type ErrorCode,
  type ExecutionGrantBinding,
} from '@scrutexity/core';
import type { Database, PoolClient } from '../db/pool.js';
import { securityNow } from '../db/security-clock.js';
import { toLease, type LeaseRow } from '../db/rows.js';
import { metrics } from '../metrics.js';
import { appendReceipt, type EvidenceKeys } from './../services/evidence.js';
import { currentContextHash } from './../services/context.js';
import { normalizeContext } from './../services/request-context.js';
import type { SecurityEventInput } from './../services/security-events.js';
import type { ExecutionProvider, ProviderOutcome, ProviderRegistry } from './provider.js';

/**
 * ============================================================================
 * The execution enforcement boundary.
 * ============================================================================
 *
 * This is the component that makes `ExecutedIntent = AuthorizedIntent` a
 * control rather than a hope. Everything before it decides whether an
 * operation *may* happen. This decides whether the operation in front of it is
 * the one that was authorised, and it is the only thing that can make it
 * happen.
 *
 * ## Why the agent presents the operation at all
 *
 * The boundary reconstructs the authorised operation from its own records --
 * the stored authorization request, not the caller's body. So it could simply
 * execute that and never ask the agent what it thinks it is doing.
 *
 * It asks anyway, and requires an exact match, for one reason: a mutation
 * attempt is a fact worth learning. Reconstructing silently makes mutation
 * *impossible*; requiring the agent to present its intent makes mutation
 * impossible **and detected**. A compromised agent that tries to change a
 * recipient produces a security event and an alert instead of a wire that
 * quietly went to the right place while nobody noticed the attempt.
 *
 * The presented operation is a claim that gets checked. It is never a source
 * of truth: every field the provider receives comes from the reconstruction.
 *
 * ## The order of checks is not arbitrary
 *
 * Cheap and local first, external contact last, and every refusal happens
 * before anything irreversible. In particular the grant is claimed -- an
 * atomic INSERT that a concurrent contender loses -- *before* the provider is
 * called, so the classic
 *
 *     check the grant -> call the bank -> mark the grant used
 *
 * window does not exist. There is no moment at which two requests have both
 * passed the check.
 *
 * ## Two transactions, and why it cannot be one
 *
 * This ran as a single transaction with the provider call inside it, and that
 * was wrong in a way the tests did not catch, because the failure needs a
 * crash to appear:
 *
 *     BEGIN
 *       INSERT claim (EXECUTING)     <- uncommitted
 *       UPDATE lease consumed        <- uncommitted
 *       call the bank                <- money moves
 *       ...crash, or COMMIT fails
 *     ROLLBACK
 *
 * Everything unwinds. The claim never existed, the grant is un-spent, and the
 * money is gone. A retry then finds no claim row, the guarded INSERT succeeds,
 * and it pays a second time -- the exactly-once property defeated by the one
 * failure mode it was built to survive.
 *
 * So the boundary commits before it acts:
 *
 *     T1  checks, claim, spend grant            COMMIT
 *         call the provider                     (no transaction held)
 *     T2  settle claim, attempt, receipt        COMMIT
 *
 * A crash between them leaves a **committed** EXECUTING claim, which is
 * exactly what `GET /v1/executions/unresolved` surfaces and what
 * reconciliation exists to resolve. The window moves from "silent double
 * payment" to "an operator has a row telling them to go and look", which is
 * the difference between a defect and a documented state.
 *
 * Holding no transaction across the call also means a slow provider no longer
 * holds row locks or a pooled connection while it thinks.
 */

/**
 * How long the boundary waits for a provider before recording UNKNOWN.
 *
 * Deliberately generous: a payment provider taking thirty seconds is slow, not
 * broken, and giving up early converts a successful payment into an UNKNOWN
 * that a human then has to reconcile. The bound exists so a hung connection
 * cannot pin a request forever, not to enforce a latency budget.
 */
const PROVIDER_TIMEOUT_MS = 30_000;

/**
 * Who invoked the boundary, as distinct from whose authority it spends.
 *
 * `agentId` answers "whose authority was consumed". This answers "who asked".
 * They coincide when an agent calls `/v1/execute` with its own credential and
 * diverge the moment an operator or an orchestrating service does it on the
 * agent's behalf -- which the route has always allowed. Recording only the
 * first leaves an auditor unable to name the party that acted.
 */
export interface ExecutionInvoker {
  type: 'user' | 'agent' | 'service';
  id: string;
}

export interface EnforceExecutionInput {
  organizationId: string;
  decisionId: string;
  agentId: string;
  /** The principal that called the boundary. Never inferred from the decision. */
  invokedBy: ExecutionInvoker;
  /** What the caller believes it is about to execute. A claim, not an input. */
  presentedOperation: {
    action: string;
    resource: { type: string; id: string };
    context: Record<string, unknown>;
  };
}

export interface EnforceExecutionResult {
  execution_id: string;
  claim_id: string;
  receipt_id: string;
  status: 'EXECUTED' | 'FAILED' | 'UNKNOWN';
  external_reference: string | null;
  provider: string;
  authorized_intent_hash: string;
  executed_intent_hash: string;
  /** Always true here: a mismatch throws rather than returning. */
  intent_verified: true;
  /**
   * True when this is the recorded outcome of an earlier execution rather than
   * a fresh one. The provider was not called. A caller that retries has to be
   * able to tell "it worked" from "it worked, earlier, and I am seeing it
   * again" -- they are the same outcome but not the same event.
   */
  replayed?: boolean;
}

interface DecisionRow {
  id: string;
  organization_id: string;
  request_id: string;
  agent_id: string;
  decision: string;
  reason_code: string;
  policy_version_id: string | null;
  policy_hash: string | null;
  authority_lease_id: string | null;
  context_hash: string | null;
  approval_ids: string[] | null;
  expires_at: Date | null;
  exact_intent_hash: string | null;
  binding_hash: string | null;
  binding_nonce: string | null;
  authorized_intent: CanonicalOperation | null;
}

/**
 * Runs the whole boundary. Either the operation executes and a receipt is
 * written, or a `ScrutexityError` is thrown carrying the security event that
 * refusal deserves.
 *
 * The error path never leaves the external system contacted. That is the
 * property to preserve above all others when editing this function.
 */
export async function enforceExecution(
  db: Database,
  keys: EvidenceKeys,
  providers: ProviderRegistry,
  input: EnforceExecutionInput,
): Promise<EnforceExecutionResult> {
  // -- Phase 1: everything that must be true before anything irreversible ---
  //
  // Committed before the provider is called. That is the whole point of the
  // split: see the note on the two transactions above.
  const prepared = await db.withTenant(input.organizationId, (client) =>
    prepare(client, providers, input),
  );

  // A prior execution already reached a definite outcome. Return it rather
  // than calling the provider again: the caller asking twice must get the
  // same answer, not a second payment.
  if (prepared.kind === 'settled') return prepared.result;

  // -- Phase 2: the external call, holding no transaction -------------------
  const outcome = await callProvider(prepared.provider, {
    operation: prepared.operation,
    idempotencyKey: idempotencyKeyFor(prepared.decision.id),
    decisionId: prepared.decision.id,
    organizationId: input.organizationId,
  });

  // -- Phase 3: record what happened ---------------------------------------
  return db.withTenant(input.organizationId, (client) =>
    settle(client, keys, {
      claimId: prepared.claimId,
      decision: prepared.decision,
      agentId: input.agentId,
      organizationId: input.organizationId,
      provider: prepared.provider,
      operation: prepared.operation,
      executedIntentHash: prepared.executedIntentHash,
      outcome,
      invokedBy: input.invokedBy,
    }),
  );
}

/**
 * What phase 1 concluded.
 *
 * `settled` is the idempotent-replay case: a prior execution against this
 * grant already reached a definite outcome, so the recorded one is returned
 * and the provider is not called again.
 */
type PreparedExecution =
  | {
      kind: 'proceed';
      claimId: string;
      decision: DecisionRow;
      provider: ExecutionProvider;
      operation: CanonicalOperation;
      executedIntentHash: string;
    }
  | { kind: 'settled'; result: EnforceExecutionResult };

/**
 * Every check, the atomic claim, and the grant spend -- in one transaction
 * that commits before the provider is reached.
 */
async function prepare(
  client: PoolClient,
  providers: ProviderRegistry,
  input: EnforceExecutionInput,
): Promise<PreparedExecution> {
  // Authoritative for every expiry judged in this boundary: the grant, the
  // acting lease and every ancestor. An API node with a fast clock must not be
  // able to refuse a live grant, nor a slow one honour a lapsed lease.
  const now = await securityNow(client);

  // -- 1. The grant exists, and belongs to this agent -----------------------
  const decision = await loadDecision(client, input.decisionId);

  if (decision.agent_id !== input.agentId) {
    // Possessing another agent's decision id must never let this agent act on
    // it. This is the confused deputy, and it is a security event rather than
    // a mistake: a caller does not come by another agent's decision id by
    // accident.
    throw refusal('FORBIDDEN', 'this decision was issued to a different agent', {
      organizationId: input.organizationId,
      kind: 'EXECUTION_WRONG_AGENT',
      subjectId: input.agentId,
      detail: { decision_id: decision.id, decision_agent_id: decision.agent_id },
    });
  }

  // -- 2. The grant authorises something ------------------------------------
  if (decision.decision !== 'ALLOW') {
    throw refusal('POLICY_DENIED', `this decision was ${decision.decision}, not ALLOW`, {
      organizationId: input.organizationId,
      kind: 'EXECUTION_AGAINST_NON_ALLOW',
      subjectId: input.agentId,
      detail: { decision_id: decision.id, decision: decision.decision },
    });
  }

  // A binding-less ALLOW predates ADR-0015. It cannot be enforced, because
  // there is nothing to compare against, and letting it through unenforced
  // would defeat the boundary for exactly the records least able to prove
  // themselves. Fail closed.
  if (
    !decision.exact_intent_hash ||
    !decision.binding_hash ||
    !decision.binding_nonce ||
    !decision.authorized_intent
  ) {
    throw refusal(
      'STATE_CONFLICT',
      'this decision carries no intent binding and cannot be executed under enforcement; re-evaluate',
      {
        organizationId: input.organizationId,
        kind: 'EXECUTION_UNBINDABLE_GRANT',
        subjectId: input.agentId,
        detail: { decision_id: decision.id },
      },
    );
  }

  // -- 3. The grant has not lapsed ------------------------------------------
  if (decision.expires_at && isExpired(decision.expires_at, now)) {
    throw refusal(
      'AUTHORITY_EXPIRED',
      'the execution grant conferred by this decision has expired; re-evaluate',
      {
        organizationId: input.organizationId,
        kind: 'EXECUTION_EXPIRED_GRANT',
        subjectId: input.agentId,
        detail: { decision_id: decision.id, expired_at: decision.expires_at.toISOString() },
      },
    );
  }

  // -- 4. The authority behind it is still live -----------------------------
  //
  // A live check, not a re-read of what the grant said when it was issued. A
  // lease revoked one second after the ALLOW must stop this execution, and the
  // only way to know that is to look now. The ancestry is walked too: revoking
  // a parent revokes everything beneath it, with no cache to invalidate.
  await assertAuthorityStillLive(client, decision, input, now);

  // -- 5. Conditions have not moved since the decision ----------------------
  //
  // The TOCTOU control. A fraud signal that arrived after a treasurer approved
  // a wire is exactly the case this exists for.
  const currentContext = await currentContextHash(client, decision);
  const comparison = compareDecisionContext(
    decision.context_hash,
    currentContext,
    (decision.approval_ids ?? []).length > 0,
  );
  if (!comparison.matches) {
    metrics.contextMismatches.inc({ approved: String(comparison.was_approved) });
    throw refusal(
      comparison.was_approved ? 'APPROVAL_CONTEXT_MISMATCH' : 'CONTEXT_CHANGED',
      comparison.was_approved
        ? 'the conditions changed since this action was approved; it must be re-evaluated and re-approved'
        : 'the conditions changed since this action was authorised; re-evaluate',
      {
        organizationId: input.organizationId,
        kind: 'EXECUTION_CONTEXT_CHANGED',
        subjectId: input.agentId,
        detail: {
          decision_id: decision.id,
          was_approved: comparison.was_approved,
          expected: comparison.expected,
          observed: comparison.observed,
        },
      },
      { disclose: true },
    );
  }

  // -- 6. The operation is the one that was authorised ----------------------
  //
  // The heart of it. Both hashes are recomputed here from the canonicaliser in
  // @scrutexity/core -- the same function that produced the recorded values --
  // and neither is taken from the caller.
  const presented = canonicalOperation({
    ...input.presentedOperation,
    // Normalised exactly as the decision path normalised it, because the hash
    // was computed over the normalised form. "25000.00" and 2_500_000 minor
    // units are the same operation, and an honest caller must not be refused
    // for spelling an amount the way the API asked it to.
    context: normalizeContext(input.presentedOperation.context),
  });
  const executedIntentHash = computeIntentHash(presented);

  if (executedIntentHash !== decision.exact_intent_hash) {
    const mutated = diffOperations(decision.authorized_intent, presented);
    metrics.intentBindingMismatches.inc({ kind: 'intent' });
    throw refusal(
      'INTENT_MISMATCH',
      'the operation presented for execution is not the operation that was authorised',
      {
        organizationId: input.organizationId,
        kind: 'EXECUTION_INTENT_MUTATED',
        subjectId: input.agentId,
        detail: {
          decision_id: decision.id,
          // Field names only. This travels into logs and alerts, and a
          // counterparty's account number does not belong in a log
          // aggregator.
          mutated_fields: mutated,
          authorized_intent_hash: decision.exact_intent_hash,
          presented_intent_hash: executedIntentHash,
        },
      },
      {
        disclose: true,
        // The agent is told *which* fields diverged so it can correct itself,
        // and nothing about what policy would have permitted instead.
        details: { mutated_fields: mutated },
      },
    );
  }

  // -- 7. ...and it is bound to *this* authority ----------------------------
  //
  // A distinct question from step 6. An unmutated operation replayed under a
  // different decision passes that check and fails this one.
  const binding: ExecutionGrantBinding = {
    authorized_intent: presented,
    authorization_context: {
      decision_id: decision.id,
      authority_lease_id: decision.authority_lease_id,
      policy_version_id: decision.policy_version_id,
      policy_hash: decision.policy_hash,
      approved_context_hash: await approvedContextHash(client, decision),
    },
    grant_id: decision.id,
    expires_at: decision.expires_at ? decision.expires_at.toISOString() : '',
    nonce: decision.binding_nonce,
  };
  const recomputedBinding = computeBindingHash(binding);
  if (recomputedBinding !== decision.binding_hash) {
    metrics.intentBindingMismatches.inc({ kind: 'binding' });
    throw refusal(
      'INTENT_MISMATCH',
      'this operation is not bound to the authority presented for it',
      {
        organizationId: input.organizationId,
        kind: 'EXECUTION_BINDING_MISMATCH',
        subjectId: input.agentId,
        detail: {
          decision_id: decision.id,
          expected_binding_hash: decision.binding_hash,
          observed_binding_hash: recomputedBinding,
        },
      },
    );
  }

  // -- 8. Something can actually execute it ---------------------------------
  const provider = providers.forAction(presented.operation_type);
  if (!provider) {
    // No provider means nothing can perform this under enforcement. Refusing
    // is the only safe answer: telling the caller to do it itself would hand
    // back exactly the bypass this boundary exists to close.
    throw refusal(
      'ENFORCEMENT_UNAVAILABLE',
      `no execution provider is configured for "${presented.operation_type}"`,
      {
        organizationId: input.organizationId,
        kind: 'EXECUTION_NO_PROVIDER',
        subjectId: input.agentId,
        detail: { decision_id: decision.id, action: presented.operation_type },
      },
      { disclose: true },
    );
  }

  // -- 9. Claim execution rights, atomically --------------------------------
  //
  // Everything above this line is a check. This line is the commitment, and
  // it is a single INSERT guarded by UNIQUE (decision_id): whoever the
  // database lets in has the right to execute, and there is no interval in
  // which two contenders both believe they do.
  const claim = await claimExecution(client, {
    organizationId: input.organizationId,
    decisionId: decision.id,
    agentId: input.agentId,
    provider: provider.name,
    idempotencyKey: idempotencyKeyFor(decision.id),
    exactIntentHash: decision.exact_intent_hash,
    bindingHash: decision.binding_hash,
    invokedBy: input.invokedBy,
  });
  // Somebody else got here first and already finished. Hand back what they
  // got; the grant is spent and the money has moved exactly once.
  if (claim.kind === 'settled') return { kind: 'settled', result: claim.result };
  const claimId = claim.claimId;

  // -- 10. Spend the grant --------------------------------------------------
  //
  // In the same transaction as the claim, and committed together with it
  // before the provider is called. If the process dies mid-flight the grant is
  // gone and the claim reads EXECUTING -- the honest record of "authority was
  // used, outcome unknown", durable because it was committed.
  //
  // Spending afterwards would leave a live grant behind a wire that may
  // already have gone.
  if (decision.authority_lease_id) {
    const consumed = await client.query(
      `UPDATE scrutexity.authority_leases
          SET consumed = true, used_at = now()
        WHERE id = $1
          AND grant_type = 'SINGLE_USE'
          AND claimed_by_decision_id = $2
          AND NOT consumed
        RETURNING id`,
      [decision.authority_lease_id, decision.id],
    );
    if ((consumed.rowCount ?? 0) > 0) metrics.singleUseGrantsConsumed.inc({});
  }

  return {
    kind: 'proceed',
    claimId,
    decision,
    provider,
    operation: presented,
    executedIntentHash,
  };
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

async function loadDecision(client: PoolClient, decisionId: string): Promise<DecisionRow> {
  const result = await client.query(
    'SELECT * FROM scrutexity.authorization_decisions WHERE id = $1',
    [decisionId],
  );
  const row = result.rows[0] as DecisionRow | undefined;
  if (!row) throw new ScrutexityError('NOT_FOUND', 'authorization decision not found');
  return row;
}

/**
 * Confirms the lease behind the grant is still usable, walking the whole
 * ancestry.
 *
 * This is deliberately a fresh read rather than a re-check of the evaluation
 * that was recorded. A revocation between the ALLOW and this moment is the
 * case that matters, and the recorded evaluation cannot know about it.
 */
async function assertAuthorityStillLive(
  client: PoolClient,
  decision: DecisionRow,
  input: EnforceExecutionInput,
  now: Date,
): Promise<void> {
  if (!decision.authority_lease_id) return;

  const chain = await client.query(
    `WITH RECURSIVE ancestry AS (
       SELECT * FROM scrutexity.authority_leases WHERE id = $1
       UNION ALL
       SELECT p.* FROM scrutexity.authority_leases p
         JOIN ancestry c ON p.id = c.parent_lease_id
     ) SELECT * FROM ancestry`,
    [decision.authority_lease_id],
  );
  if (chain.rowCount === 0) {
    throw refusal('AUTHORITY_MISSING', 'the authority behind this grant no longer exists', {
      organizationId: input.organizationId,
      kind: 'EXECUTION_AUTHORITY_MISSING',
      subjectId: input.agentId,
      detail: { decision_id: decision.id, lease_id: decision.authority_lease_id },
    });
  }

  for (const row of chain.rows as LeaseRow[]) {
    const lease = toLease(row);
    const status = effectiveLeaseStatus(lease, now);
    // CONSUMED is expected and fine here: this execution is what consumes it,
    // and the claim in step 9 is what enforces exactly-once. Anything else
    // that is not ACTIVE means the authority is gone.
    if (status === 'ACTIVE' || status === 'CONSUMED') continue;

    const code = status === 'REVOKED' ? 'AUTHORITY_REVOKED' : 'AUTHORITY_EXPIRED';
    throw refusal(
      code,
      lease.id === decision.authority_lease_id
        ? `the authority behind this grant is ${status.toLowerCase()}`
        : `an authority this grant descends from is ${status.toLowerCase()}`,
      {
        organizationId: input.organizationId,
        kind: 'EXECUTION_AUTHORITY_NOT_LIVE',
        subjectId: input.agentId,
        detail: {
          decision_id: decision.id,
          lease_id: lease.id,
          lease_status: status,
          was_ancestor: lease.id !== decision.authority_lease_id,
        },
      },
      { disclose: true },
    );
  }
}

/** The fingerprint the approvers were shown, when this grant came from one. */
async function approvedContextHash(
  client: PoolClient,
  decision: DecisionRow,
): Promise<string | null> {
  const result = await client.query(
    `SELECT ar.context_hash
       FROM scrutexity.approval_requests ar
      WHERE ar.decision_id = $1
      ORDER BY ar.created_at DESC LIMIT 1`,
    [decision.request_id === decision.id ? decision.id : decision.id],
  );
  const direct = result.rows[0]?.context_hash as string | undefined;
  if (direct) return direct;

  // A decision that superseded an escalation carries the approval on the
  // decision it replaced, not on itself.
  const superseded = await client.query(
    `SELECT ar.context_hash
       FROM scrutexity.approval_requests ar
       JOIN scrutexity.authorization_decisions d ON d.supersedes_decision_id = ar.decision_id
      WHERE d.id = $1
      ORDER BY ar.created_at DESC LIMIT 1`,
    [decision.id],
  );
  return (superseded.rows[0]?.context_hash as string | undefined) ?? null;
}

/**
 * The atomic claim.
 *
 * A unique violation is not an error condition to smooth over -- it is the
 * mechanism working. It means another request holds the right to execute this
 * grant, and this one must not proceed.
 */
async function claimExecution(
  client: PoolClient,
  input: {
    organizationId: string;
    decisionId: string;
    agentId: string;
    provider: string;
    idempotencyKey: string;
    exactIntentHash: string;
    bindingHash: string;
    invokedBy: ExecutionInvoker;
  },
): Promise<
  { kind: 'claimed'; claimId: string } | { kind: 'settled'; result: EnforceExecutionResult }
> {
  const claimId = newId('executionClaim');
  // A savepoint, because losing the race is an expected outcome here rather
  // than an error. Postgres aborts the whole transaction on a constraint
  // violation, so without this the follow-up read of the winning claim would
  // fail with "current transaction is aborted" and a 409 would surface as a
  // 500 -- turning a correct refusal into what looks like a broken service.
  await client.query('SAVEPOINT execution_claim');
  try {
    await client.query(
      `INSERT INTO scrutexity.execution_claims
         (id, organization_id, decision_id, agent_id, state, provider, idempotency_key,
          exact_intent_hash, binding_hash, invoked_by_type, invoked_by_id)
       VALUES ($1,$2,$3,$4,'EXECUTING',$5,$6,$7,$8,$9,$10)`,
      [
        claimId,
        input.organizationId,
        input.decisionId,
        input.agentId,
        input.provider,
        input.idempotencyKey,
        input.exactIntentHash,
        input.bindingHash,
        input.invokedBy.type,
        input.invokedBy.id,
      ],
    );
    await client.query('RELEASE SAVEPOINT execution_claim');
  } catch (error) {
    await client.query('ROLLBACK TO SAVEPOINT execution_claim');
    if ((error as { code?: string }).code === '23505') {
      return resolveExistingClaim(client, input);
    }
    throw error;
  }
  metrics.executionsClaimed.inc({ provider: input.provider });
  return { kind: 'claimed', claimId };
}

/**
 * A claim already exists. What that means depends entirely on its state, and
 * collapsing the three cases into one refusal was the shape this used to have.
 *
 *   EXECUTED / FAILED   a definite outcome exists -> return it
 *   RECONCILED          an operator established the outcome -> return it
 *   EXECUTING           the provider was reached and nobody knows the outcome
 *   UNKNOWN             the provider did not answer
 *
 * The last two are the dangerous ones and they are not replays. A replay means
 * "this was already done"; these mean "this may or may not have been done".
 * Answering REPLAY_DETECTED to either would tell a caller the work is
 * finished, when what is actually true is that somebody has to go and ask the
 * bank. So they get their own code, and the provider is not called.
 */
async function resolveExistingClaim(
  client: PoolClient,
  input: { organizationId: string; decisionId: string; provider: string },
): Promise<{ kind: 'settled'; result: EnforceExecutionResult }> {
  const existing = await client.query(
    `SELECT c.id, c.state, c.provider, c.external_reference, c.exact_intent_hash,
            e.id AS execution_id, e.executed_intent_hash
       FROM scrutexity.execution_claims c
       LEFT JOIN scrutexity.execution_attempts e ON e.claim_id = c.id
      WHERE c.decision_id = $1`,
    [input.decisionId],
  );
  const row = existing.rows[0] as
    | {
        id: string;
        state: string;
        provider: string;
        external_reference: string | null;
        exact_intent_hash: string;
        execution_id: string | null;
        executed_intent_hash: string | null;
      }
    | undefined;

  if (!row) {
    // The unique violation says a row exists; not finding it means RLS hid it,
    // which is a tenancy problem and not something to paper over by retrying.
    throw new ScrutexityError('STATE_CONFLICT', 'an execution claim exists but is not readable');
  }

  if (row.state === 'EXECUTING' || row.state === 'UNKNOWN') {
    metrics.executionsUnresolved.inc({ provider: row.provider });
    throw refusal(
      'EXECUTION_UNRESOLVED',
      row.state === 'EXECUTING'
        ? 'an execution against this authorization is in flight or was interrupted; it must be reconciled before anything further is attempted'
        : 'the provider did not answer a previous execution against this authorization; it must be reconciled before anything further is attempted',
      {
        organizationId: input.organizationId,
        kind: 'EXECUTION_RETRY_WHILE_UNRESOLVED',
        detail: { decision_id: input.decisionId, claim_id: row.id, claim_state: row.state },
      },
      { disclose: true, details: { claim_id: row.id, state: row.state } },
    );
  }

  metrics.replayAttempts.inc({ kind: 'execution_claim' });
  return {
    kind: 'settled',
    result: {
      execution_id: row.execution_id ?? row.id,
      claim_id: row.id,
      receipt_id: '',
      status: row.state === 'EXECUTED' ? 'EXECUTED' : row.state === 'FAILED' ? 'FAILED' : 'UNKNOWN',
      external_reference: row.external_reference,
      provider: row.provider,
      authorized_intent_hash: row.exact_intent_hash,
      executed_intent_hash: row.executed_intent_hash ?? row.exact_intent_hash,
      intent_verified: true,
      replayed: true,
    },
  };
}

/**
 * Derived from the grant, so a retry after a timeout is the same request.
 *
 * The decision id is already unique, opaque and traceable -- a provider's
 * support desk can be given one without disclosing anything about the
 * operation. Hashing it would only make that conversation harder.
 */
export function idempotencyKeyFor(decisionId: string): string {
  return `scrutexity:${decisionId}`;
}

/**
 * Calls the provider, converting anything it throws into UNKNOWN rather than
 * FAILED.
 *
 * This is the conservative direction and it is the whole reason UNKNOWN
 * exists. A provider that throws has told us nothing about whether the money
 * moved. Recording that as FAILED would invite a retry, and a retry against a
 * provider that already accepted the request is a double payment.
 */
async function callProvider(
  provider: ExecutionProvider,
  request: Parameters<ExecutionProvider['execute']>[0],
  timeoutMs = PROVIDER_TIMEOUT_MS,
): Promise<ProviderOutcome> {
  try {
    // Bounded. A provider that never answers must not hold the request open
    // forever -- and the timeout resolves to UNKNOWN, not FAILED, because a
    // deadline passing says nothing about whether the money moved.
    return await Promise.race([
      provider.execute(request),
      new Promise<ProviderOutcome>((resolve) =>
        setTimeout(
          () =>
            resolve({
              status: 'UNKNOWN',
              error: `the provider did not answer within ${timeoutMs}ms`,
              detail: { timed_out: true },
            }),
          timeoutMs,
        ).unref(),
      ),
    ]);
  } catch (error) {
    return {
      status: 'UNKNOWN',
      error: error instanceof Error ? error.message : String(error),
      detail: { threw: true },
    };
  }
}

/**
 * Records the outcome: settles the claim, writes the append-only attempt, and
 * appends a receipt carrying both hashes.
 *
 * Both hashes go into evidence rather than a boolean "they matched", so a
 * verifier can check the claim instead of taking it.
 */
async function settle(
  client: PoolClient,
  keys: EvidenceKeys,
  input: {
    claimId: string;
    decision: DecisionRow;
    agentId: string;
    organizationId: string;
    provider: ExecutionProvider;
    operation: CanonicalOperation;
    executedIntentHash: string;
    outcome: ProviderOutcome;
    invokedBy: ExecutionInvoker;
  },
): Promise<EnforceExecutionResult> {
  const { outcome } = input;
  const externalReference = outcome.status === 'EXECUTED' ? outcome.external_reference : null;
  const error = outcome.status === 'EXECUTED' ? null : outcome.error;

  await client.query(
    `UPDATE scrutexity.execution_claims
        SET state = $2, resolved_at = now(), external_reference = $3, last_error = $4
      WHERE id = $1`,
    [input.claimId, outcome.status, externalReference, error],
  );

  const executionId = newId('execution');
  await client.query(
    `INSERT INTO scrutexity.execution_attempts
       (id, organization_id, decision_id, agent_id, status, result, claim_id,
        executed_intent_hash, executed_operation, enforced)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true)`,
    [
      executionId,
      input.organizationId,
      input.decision.id,
      input.agentId,
      // UNKNOWN has no execution_status member and must not be recorded as
      // FAILED, which would assert something nobody knows. RECORDED is the
      // enum's "an attempt happened" value; the claim carries the nuance.
      outcome.status === 'EXECUTED'
        ? 'SUCCEEDED'
        : outcome.status === 'FAILED'
          ? 'FAILED'
          : 'RECORDED',
      JSON.stringify({
        provider: input.provider.name,
        provider_status: outcome.status,
        external_reference: externalReference,
        ...(error ? { error } : {}),
        ...(outcome.detail ? { detail: outcome.detail } : {}),
      }),
      input.claimId,
      input.executedIntentHash,
      JSON.stringify(input.operation),
    ],
  );

  const receipt = await appendReceipt(client, keys, {
    organizationId: input.organizationId,
    kind: 'EXECUTION',
    subjectId: input.agentId,
    requestId: input.decision.request_id,
    decisionId: input.decision.id,
    payload: {
      execution_id: executionId,
      claim_id: input.claimId,
      decision_id: input.decision.id,
      authorization_request_id: input.decision.request_id,
      agent_id: input.agentId,
      // Whose authority was spent, and who spent it. Recorded in the signed
      // artifact rather than only in the claim row, so a verifier holding the
      // receipt can name the acting party without being granted the database.
      invoked_by_type: input.invokedBy.type,
      invoked_by_id: input.invokedBy.id,
      enforced: true,
      provider: input.provider.name,
      provider_idempotent: input.provider.idempotent,
      provider_status: outcome.status,
      external_reference: externalReference,
      // Both sides of the comparison, so a verifier can recompute rather than
      // trust the assertion that they matched.
      authorized_intent_hash: input.decision.exact_intent_hash,
      executed_intent_hash: input.executedIntentHash,
      binding_hash: input.decision.binding_hash,
      executed_operation: input.operation,
      context_hash: input.decision.context_hash,
      authority_lease_id: input.decision.authority_lease_id,
      grant_expired_at: input.decision.expires_at ? input.decision.expires_at.toISOString() : null,
    },
  });

  metrics.executionsSettled.inc({ provider: input.provider.name, status: outcome.status });

  return {
    execution_id: executionId,
    claim_id: input.claimId,
    receipt_id: receipt.id,
    status: outcome.status,
    external_reference: externalReference,
    provider: input.provider.name,
    authorized_intent_hash: input.decision.exact_intent_hash!,
    executed_intent_hash: input.executedIntentHash,
    intent_verified: true,
  };
}

/**
 * Builds a refusal carrying its own security event.
 *
 * The event travels on the error rather than being written here, because this
 * transaction is about to roll back and would take the record with it. The
 * route layer writes it on a fresh connection. That is the invariant "security
 * evidence must survive the transaction that caused it", and this is the only
 * shape that satisfies it -- see services/security-events.ts.
 */
function refusal(
  code: ErrorCode,
  message: string,
  event: SecurityEventInput,
  options: { disclose?: boolean; details?: unknown } = {},
): ScrutexityError {
  return new ScrutexityError(code, message, {
    ...(options.disclose ? { disclose: true } : {}),
    ...(options.details !== undefined ? { details: options.details } : {}),
    internal: { securityEvent: event },
  });
}
