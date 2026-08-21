import {
  ScrutexityError,
  explainDecision,
  effectiveLeaseStatus,
  grantState,
  hashObject,
  loadPolicyDocument,
  loadPolicyYaml,
  newId,
  verifyReceipt,
} from '@scrutexity/core';
import type { FastifyInstance } from 'fastify';
import { SCOPES, requireHuman, requireNonAgent, requireScope, type Principal } from '../auth.js';
import { claimIdempotencyKey, completeIdempotencyKey } from '../idempotency.js';
import type { Database, PoolClient } from '../db/pool.js';
import { securityNow } from '../db/security-clock.js';
import { toLease, type LeaseRow } from '../db/rows.js';
import type { EvidenceKeys } from '../services/evidence.js';
import { fetchReceipt, verifyReceiptWithChain } from '../services/evidence.js';
import { authorize } from '../services/authorization.js';
import { createDelegation, issueLease, revokeLease } from '../services/authority.js';
import { ingestSignal } from '../services/signals.js';
import { submitApproval } from '../services/approvals.js';
import { recordExecution } from '../services/execution.js';
import {
  AuthorizationRequestSchema,
  CreateAgentSchema,
  CreateDelegationSchema,
  CreateLeaseSchema,
  CreatePolicyVersionSchema,
  IngestSignalSchema,
  ExecuteSchema,
  RecordExecutionSchema,
  ReviewPolicyVersionSchema,
  RegisterSignalKeySchema,
  RotateSignalKeySchema,
  RevokeLeaseSchema,
  SubmitApprovalSchema,
} from '../schemas.js';
import { buildDecisionTrace } from '../services/trace.js';
import { recordSecurityEvent, securityEventOf } from '../services/security-events.js';
import { enforceExecution } from '../adapter/enforce.js';
import type { ProviderRegistry } from '../adapter/provider.js';
import { metrics } from '../metrics.js';

export interface RouteDeps {
  db: Database;
  keys: EvidenceKeys;
  /**
   * The execution providers this deployment is configured with. Registered at
   * boot rather than looked up per request, so an operation with no provider
   * is refused deterministically instead of depending on what happens to be
   * reachable at that moment.
   */
  providers: ProviderRegistry;
}

declare module 'fastify' {
  interface FastifyRequest {
    principal: Principal;
  }
}

export async function registerRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db, keys, providers } = deps;

  /**
   * Ordinary reads: an agent's own decisions, leases, traces and receipts.
   *
   * Every GET goes through one of these two. Before this existed the `read`
   * scope was granted by the seed and checked by nothing, which meant an agent
   * credential could fetch the policy document that governs it and the
   * security-event log recording its own attacks. Scopes that are never
   * enforced are worse than absent -- they read as a control in every review.
   */
  function requireRead(principal: Principal): void {
    requireScope(principal, SCOPES.read);
  }

  /**
   * Operator reads: the policy documents, the security event log, signing key
   * metadata, the agent register, unresolved executions.
   *
   * Two independent gates, because either alone would be too weak. The scope
   * keeps out credentials that were never meant to audit; `requireNonAgent`
   * keeps out an agent that was mistakenly granted the scope. The principal
   * whose behaviour this control plane exists to constrain must not be able to
   * read the constraints.
   */
  function requireOperatorRead(principal: Principal): void {
    requireScope(principal, SCOPES.audit);
    requireNonAgent(principal);
  }

  /**
   * An agent may read only the records it is the subject of.
   *
   * Tenancy alone is not enough here. Two agents in one tenant are two
   * principals with different authority, and an id that appears in a URL is
   * guessable, enumerable and frequently logged -- so without this, holding a
   * decision id is the same as being the agent it was issued to.
   *
   * NOT_FOUND rather than FORBIDDEN, deliberately. A 403 confirms the record
   * exists, which turns the endpoint into an oracle an attacker can sweep to
   * map another agent's activity. A prober learns nothing either way.
   *
   * Humans and services are not narrowed: an operator investigating an
   * incident needs to read across agents, and that is what the audit scope and
   * the security event log are for.
   */
  function assertMayReadSubject(principal: Principal, subjectAgentId: string | null): void {
    if (principal.type !== 'agent') return;
    if (subjectAgentId !== null && subjectAgentId === principal.id) return;
    throw new ScrutexityError('NOT_FOUND', 'not found');
  }

  /**
   * Runs a handler in a tenant-scoped transaction, honouring an
   * Idempotency-Key when one is supplied. Claiming the key inside the same
   * transaction as the effect is what makes a retry safe: a duplicate either
   * blocks and replays the stored response, or does the work exactly once.
   */
  async function mutate<T>(
    request: { principal: Principal; headers: Record<string, unknown>; body: unknown },
    endpoint: string,
    handler: (client: PoolClient) => Promise<{ status: number; body: T }>,
  ): Promise<{ status: number; body: T }> {
    const key = request.headers['idempotency-key'];
    const organizationId = request.principal.organization_id;

    return db.withTenant(organizationId, async (client) => {
      if (typeof key === 'string' && key.length > 0) {
        const hit = await claimIdempotencyKey(client, organizationId, endpoint, key, request.body);
        if (hit) return { status: hit.status_code, body: hit.body as T };
        const result = await handler(client);
        await completeIdempotencyKey(
          client,
          organizationId,
          endpoint,
          key,
          result.status,
          result.body,
        );
        return result;
      }
      return handler(client);
    });
  }

  /**
   * Runs `fn`, and if it fails with an error carrying a security event, writes
   * that event on its own transaction before rethrowing. The failing
   * transaction has already rolled back by then, which is exactly why the
   * record cannot be written inside it.
   */
  async function recordingRejections<T>(
    request: { principal: Principal },
    fn: () => Promise<T>,
  ): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      const event = securityEventOf(error);
      if (event) {
        await db
          .withTenant(request.principal.organization_id, (client) =>
            recordSecurityEvent(client, event),
          )
          .catch(() => undefined);
      }
      throw error;
    }
  }

  // ==========================================================================
  // Agents
  // ==========================================================================

  app.post('/v1/agents', async (request, reply) => {
    requireScope(request.principal, SCOPES.adminWrite);
    const body = CreateAgentSchema.parse(request.body);
    const { status, body: payload } = await mutate(
      request as never,
      'POST /v1/agents',
      async (client) => {
        const id = newId('agent');
        try {
          const result = await client.query(
            `INSERT INTO scrutexity.agents
             (id, organization_id, handle, display_name, description, owner_user_id, metadata)
           VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
            [
              id,
              request.principal.organization_id,
              body.handle,
              body.display_name,
              body.description ?? null,
              body.owner_user_id ?? null,
              JSON.stringify(body.metadata),
            ],
          );
          return { status: 201, body: { agent: serializeAgent(result.rows[0]) } };
        } catch (error) {
          if ((error as { code?: string }).code === '23505') {
            throw new ScrutexityError(
              'STATE_CONFLICT',
              `an agent with handle "${body.handle}" already exists`,
            );
          }
          throw error;
        }
      },
    );
    reply.code(status).send(payload);
  });

  app.get('/v1/agents', async (request) => {
    requireOperatorRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        'SELECT * FROM scrutexity.agents ORDER BY created_at DESC LIMIT 200',
      );
      return { agents: result.rows.map(serializeAgent) };
    });
  });

  app.get<{ Params: { id: string } }>('/v1/agents/:id', async (request) => {
    requireOperatorRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const agent = await client.query(
        'SELECT * FROM scrutexity.agents WHERE id = $1 OR handle = $1',
        [request.params.id],
      );
      if (agent.rowCount === 0) throw new ScrutexityError('NOT_FOUND', 'agent not found');
      const agentRow = agent.rows[0];

      // One pooled client executes one query at a time; these run in sequence.
      const leases = await client.query(
        `SELECT * FROM scrutexity.authority_leases WHERE agent_id = $1
          ORDER BY issued_at DESC LIMIT 50`,
        [agentRow.id],
      );
      const delegations = await client.query(
        `SELECT * FROM scrutexity.delegations
          WHERE issuer_agent_id = $1 OR delegate_agent_id = $1
          ORDER BY created_at DESC LIMIT 50`,
        [agentRow.id],
      );
      const signals = await client.query(
        `SELECT id, subject_type, subject_id, signal_type, value, confidence, source,
                issued_at, expires_at
           FROM scrutexity.risk_signals
          WHERE subject_type = 'agent' AND subject_id = $1
            AND superseded_at IS NULL AND expires_at > now()
          ORDER BY issued_at DESC LIMIT 50`,
        [agentRow.id],
      );
      const decisions = await client.query(
        `SELECT d.id, d.decision, d.reason_code, r.action, r.resource_type, r.resource_id, d.decided_at
           FROM scrutexity.authorization_decisions d
           JOIN scrutexity.authorization_requests r ON r.id = d.request_id
          WHERE d.agent_id = $1 ORDER BY d.decided_at DESC LIMIT 20`,
        [agentRow.id],
      );

      return {
        agent: serializeAgent(agentRow),
        authority_leases: (leases.rows as LeaseRow[]).map(toLease),
        delegations: delegations.rows,
        risk_signals: signals.rows.map(serializeSignal),
        recent_decisions: decisions.rows,
      };
    });
  });

  // ==========================================================================
  // Authority
  // ==========================================================================

  app.post('/v1/authority-leases', async (request, reply) => {
    requireScope(request.principal, SCOPES.leaseWrite);
    const body = CreateLeaseSchema.parse(request.body);
    // An attempt to issue beyond the ceiling is a security event, and the
    // transaction that produced it is about to roll back.
    const { status, body: payload } = await recordingRejections(request, () =>
      mutate(request as never, 'POST /v1/authority-leases', async (client) => {
        const result = await issueLease(client, keys, {
          organizationId: request.principal.organization_id,
          agentId: await resolveAgentId(client, body.agent_id),
          grant: body.grant,
          ttlSeconds: body.ttl_seconds,
          issuedByUserId: request.principal.type === 'user' ? request.principal.id : null,
          issuer: { type: request.principal.type, id: request.principal.id },
          revocable: body.revocable,
          grantType: body.grant_type,
          purpose: body.purpose ?? null,
          metadata: body.metadata,
        });
        return {
          status: 201,
          body: { authority_lease: result.lease, receipt_id: result.receipt_id },
        };
      }),
    );
    reply.code(status).send(payload);
  });

  app.get<{ Params: { id: string } }>('/v1/authority-leases/:id', async (request) => {
    requireRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        `WITH RECURSIVE chain AS (
           SELECT * FROM scrutexity.authority_leases WHERE id = $1
           UNION ALL
           SELECT p.* FROM scrutexity.authority_leases p JOIN chain c ON p.id = c.parent_lease_id
         ) SELECT * FROM chain ORDER BY depth ASC`,
        [request.params.id],
      );
      if (result.rowCount === 0)
        throw new ScrutexityError('NOT_FOUND', 'authority lease not found');
      // The same clock an authorization would use. A lease reported ACTIVE
      // here and refused as EXPIRED a moment later by a decision would make
      // this endpoint a liar about the thing it exists to describe.
      const now = await securityNow(client);
      const rows = (result.rows as LeaseRow[]).map(toLease);
      const lease = rows.find((l) => l.id === request.params.id)!;
      assertMayReadSubject(request.principal, lease.agent_id);

      // Whether a claimed grant was ever acted on is not derivable from the
      // lease row alone: a claim with no execution behind it means the agent
      // never came back. Surfaced here so an operator does not have to join it
      // by hand -- see ADR-0013 on why that state is deliberately terminal.
      const execution = await client.query(
        `SELECT e.id, e.status, e.created_at
           FROM scrutexity.execution_attempts e
           JOIN scrutexity.authorization_decisions d ON d.id = e.decision_id
          WHERE d.authority_lease_id = $1
          ORDER BY e.created_at DESC LIMIT 1`,
        [lease.id],
      );

      return {
        authority_lease: {
          ...lease,
          /**
           * What a decision would conclude about this lease right now, on the
           * authoritative clock.
           *
           * `status` is the stored column -- the disposition someone wrote.
           * It says ACTIVE for a lease that has simply run out of time,
           * because nothing goes back to rewrite rows when a clock passes
           * them. Reporting only that would have this endpoint call a lease
           * ACTIVE while an authorization refuses it as EXPIRED, which is a
           * lie about the one thing it exists to describe.
           */
          effective_status: effectiveLeaseStatus(lease, now),
          grant_state: grantState(lease, now),
          execution_outcome: execution.rows[0]
            ? {
                execution_id: execution.rows[0].id,
                status: execution.rows[0].status,
                recorded_at: (execution.rows[0].created_at as Date).toISOString(),
              }
            : null,
        },
        ancestry: rows.map((l) => ({
          ...l,
          effective_status: effectiveLeaseStatus(l, now),
          grant_state: grantState(l, now),
        })),
      };
    });
  });

  app.post<{ Params: { id: string } }>('/v1/authority-leases/:id/revoke', async (request) => {
    requireScope(request.principal, SCOPES.leaseWrite);
    const body = RevokeLeaseSchema.parse(request.body);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const result = await revokeLease(client, keys, {
        organizationId: request.principal.organization_id,
        leaseId: request.params.id,
        revokedByUserId: request.principal.type === 'user' ? request.principal.id : null,
        reason: body.reason,
      });
      return {
        authority_lease: result.lease,
        receipt_id: result.receipt_id,
        already_revoked: result.already_revoked,
      };
    });
  });

  app.post('/v1/delegations', async (request, reply) => {
    requireScope(request.principal, SCOPES.delegate);
    const body = CreateDelegationSchema.parse(request.body);

    // An agent credential may only delegate authority it itself holds.
    if (request.principal.type === 'agent' && request.principal.id !== body.issuer_agent_id) {
      throw new ScrutexityError('FORBIDDEN', 'an agent may only delegate its own authority', {
        internal: {
          credential_principal: request.principal.id,
          claimed_issuer: body.issuer_agent_id,
        },
      });
    }

    const { status, body: payload } = await mutate(
      request as never,
      'POST /v1/delegations',
      async (client) => {
        const result = await createDelegation(client, keys, {
          organizationId: request.principal.organization_id,
          issuerAgentId: await resolveAgentId(client, body.issuer_agent_id),
          delegateAgentHandleOrId: body.delegate_agent_id,
          parentLeaseId: body.parent_lease_id,
          grant: body.grant,
          ttlSeconds: body.ttl_seconds,
        });
        return { status: 201, body: result };
      },
    );
    reply.code(status).send(payload);
  });

  // ==========================================================================
  // Authorization
  // ==========================================================================

  const evaluateHandler = async (
    request: { principal: Principal; headers: Record<string, unknown>; body: unknown },
    endpoint: string,
  ) => {
    requireScope(request.principal, SCOPES.authorize);
    const body = AuthorizationRequestSchema.parse(request.body);

    // A credential issued to one agent must never authorise another.
    if (request.principal.type === 'agent') {
      const claimed = body.agent_id;
      if (claimed !== request.principal.id) {
        await assertHandleBelongsToPrincipal(db, request.principal, claimed);
      }
    }

    // An invariant violation on this path carries a security event, and the
    // transaction that produced it is about to roll back -- so the write has
    // to happen outside it. See services/security-events.ts.
    return recordingRejections(request, () =>
      mutate(request, endpoint, async (client) => {
        const result = await authorize(client, keys, {
          organizationId: request.principal.organization_id,
          agentHandleOrId: body.agent_id,
          action: body.action,
          resource: body.resource,
          context: body.context,
          presentedLeaseId: body.authority_lease_id ?? null,
          declaredIntent: body.declared_intent ?? null,
          nonce: body.nonce ?? null,
          idempotencyKey: (request.headers['idempotency-key'] as string | undefined) ?? null,
          correlationId: body.correlation_id ?? null,
        });
        return {
          // 200 for every evaluated outcome. A DENY is a successful evaluation
          // that answered "no"; returning 4xx would conflate it with a
          // malformed request and break clients that branch on status.
          status: 200,
          body: {
            authorization_request_id: result.request_id,
            decision_id: result.decision_id,
            receipt_id: result.receipt_id,
            approval_request_id: result.approval_request_id,
            decision: result.evaluation.decision,
            reason_code: result.evaluation.reason_code,
            policy_id: result.evaluation.policy_id,
            policy_version: result.evaluation.policy_version,
            policy_hash: result.evaluation.policy_hash,
            authority_lease_id: result.evaluation.authority_lease_id,
            risk_signal_ids: result.evaluation.risk_signal_ids,
            constraints_evaluated: result.evaluation.constraints_evaluated,
            approval_requirement: result.evaluation.approval_requirement,
            // The structured intent verdict. Never prose; the explanation
            // compiler renders this same data as text.
            intent_evaluation: result.evaluation.intent_evaluation,
            // The next legitimate step, when one exists. Computed by the policy
            // layer from this decision -- see packages/core/src/corrective.ts.
            corrective_actions: result.corrective_actions,
            // Fingerprint of the conditions this decision rests on.
            context_hash: result.evaluation.context_hash,
            // The exact operation this ALLOW authorises, bound to this ALLOW.
            // Null for a DENY or an ESCALATE: nothing was authorised, so there
            // is nothing to bind. The caller does not need these to execute --
            // the enforcement boundary recomputes both from its own records --
            // but returning them lets a caller confirm up front that the system
            // understood the operation the same way it did.
            exact_intent_hash: result.exact_intent_hash,
            binding_hash: result.binding_hash,
            failover_behavior: result.evaluation.failover_behavior,
            expires_at: result.evaluation.expires_at,
            decision_timestamp: result.evaluation.decision_timestamp,
          },
        };
      }),
    );
  };

  app.post('/v1/authorization-requests', async (request, reply) => {
    const { status, body } = await evaluateHandler(
      request as never,
      'POST /v1/authorization-requests',
    );
    reply.code(status).send(body);
  });

  // Verb-shaped alias of the endpoint above, sharing one implementation. It
  // exists because SDK callers reach for a verb, not a resource.
  app.post('/v1/authorization/evaluate', async (request, reply) => {
    const { status, body } = await evaluateHandler(
      request as never,
      'POST /v1/authorization/evaluate',
    );
    reply.code(status).send(body);
  });

  /**
   * The why-was-I-allowed API (Section 20). Machine-readable first; the
   * human-readable rendering below it is assembled deterministically from the
   * same structured facts, never generated.
   */
  app.get<{ Params: { id: string } }>('/v1/authorization-decisions/:id', async (request) => {
    requireRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        `SELECT d.*, r.action, r.resource_type, r.resource_id, r.context, r.created_at AS requested_at,
                a.handle AS agent_handle
           FROM scrutexity.authorization_decisions d
           JOIN scrutexity.authorization_requests r ON r.id = d.request_id
           JOIN scrutexity.agents a ON a.id = d.agent_id
          WHERE d.id = $1`,
        [request.params.id],
      );
      if (result.rowCount === 0)
        throw new ScrutexityError('NOT_FOUND', 'authorization decision not found');
      const row = result.rows[0];
      assertMayReadSubject(request.principal, row.agent_id as string);

      // When the acting authority was delegated, name the agent that granted
      // it. The explanation is materially different -- "that authority was
      // delegated by X" is what tells an operator where to look.
      const delegatedBy = row.authority_lease_id
        ? await client.query(
            `SELECT issuer.handle
               FROM scrutexity.authority_leases child
               JOIN scrutexity.authority_leases parent ON parent.id = child.parent_lease_id
               JOIN scrutexity.agents issuer ON issuer.id = parent.agent_id
              WHERE child.id = $1`,
            [row.authority_lease_id],
          )
        : null;

      const approvals = await client.query(
        `SELECT ap.id, ap.approver_user_id, ap.vote, ap.roles_at_decision, ap.satisfied_role,
                ap.comment, ap.created_at, u.display_name, u.email
           FROM scrutexity.approval_requests ar
           JOIN scrutexity.approvals ap ON ap.approval_request_id = ar.id
           JOIN scrutexity.users u ON u.id = ap.approver_user_id
          WHERE ar.decision_id = $1 OR ar.decision_id = $2
          ORDER BY ap.created_at ASC`,
        [row.id, row.supersedes_decision_id],
      );
      const receipt = await client.query(
        'SELECT id, hash, seq FROM scrutexity.receipts WHERE decision_id = $1',
        [row.id],
      );
      const execution = await client.query(
        'SELECT id, status, result, created_at FROM scrutexity.execution_attempts WHERE decision_id = $1',
        [row.id],
      );

      const evaluation = {
        decision: row.decision,
        reason_code: row.reason_code,
        authorization_request_id: row.request_id,
        agent_id: row.agent_id,
        action: row.action,
        resource: { type: row.resource_type, id: row.resource_id },
        policy_id: row.policy_id,
        policy_version_id: row.policy_version_id,
        policy_version: row.evaluation?.policy_outcome?.policy_version ?? null,
        policy_hash: row.policy_hash,
        authority_lease_id: row.authority_lease_id,
        risk_signal_ids: row.risk_signal_ids,
        constraints_evaluated:
          row.evaluation?.authority_findings?.find(
            (f: { lease_id: string }) => f.lease_id === row.authority_lease_id,
          )?.effective_coverage?.constraint_checks ?? [],
        approval_requirement: row.approval_requirement,
        approval_state: null,
        failover_behavior: row.failover_behavior,
        decision_timestamp: row.decided_at.toISOString(),
        expires_at: row.expires_at ? row.expires_at.toISOString() : null,
        evaluation: row.evaluation,
      };

      return {
        decision: {
          id: row.id,
          ...evaluation,
          supersedes_decision_id: row.supersedes_decision_id,
          evaluation_duration_us: row.evaluation_duration_us,
        },
        request: {
          id: row.request_id,
          action: row.action,
          resource: { type: row.resource_type, id: row.resource_id },
          context: row.context,
          requested_at: row.requested_at.toISOString(),
        },
        approvals: approvals.rows,
        receipt: receipt.rows[0] ?? null,
        execution: execution.rows[0] ?? null,
        explanation: explainDecision(evaluation as never, {
          agent_handle: row.agent_handle,
          ...(delegatedBy?.rows[0]
            ? { delegated_by_handle: delegatedBy.rows[0].handle as string }
            : {}),
        }),
      };
    });
  });

  /**
   * The enforcement boundary.
   *
   * Scrutexity performs the operation here. The caller presents what it
   * believes it is executing; the boundary verifies that against the operation
   * the grant was issued for, claims execution rights atomically, calls the
   * provider under a key derived from the grant, and writes evidence naming
   * both hashes.
   *
   * Wrapped in `recordingRejections` because every refusal on this path is a
   * security event, and the transaction that produced it is about to roll back
   * -- see services/security-events.ts.
   */
  app.post('/v1/execute', async (request, reply) => {
    requireScope(request.principal, SCOPES.authorize);
    const body = ExecuteSchema.parse(request.body);
    const { status, body: payload } = await recordingRejections(request, () =>
      mutate(request as never, 'POST /v1/execute', async (client) => {
        const agentId =
          request.principal.type === 'agent'
            ? request.principal.id
            : await decisionAgentId(client, body.decision_id);
        const result = await enforceExecution(client, keys, providers, {
          organizationId: request.principal.organization_id,
          decisionId: body.decision_id,
          agentId,
          presentedOperation: body.operation,
        });
        return { status: 201, body: result };
      }),
    );
    reply.code(status).send(payload);
  });

  /**
   * Everything the boundary started and could not finish.
   *
   * A claim is EXECUTING while the provider call is in flight, and UNKNOWN
   * when the provider did not answer. Either state, once it has been sitting
   * for a while, means authority was spent and nobody in this system knows
   * what happened at the other end. Only the external system can settle that,
   * so this endpoint exists to hand an operator or a reconciliation job the
   * list rather than have it construct one.
   *
   * Deliberately not a background worker inside the API process: with more
   * than one replica that needs leader election, and a reconciliation loop
   * that runs twice is exactly the thing that turns an UNKNOWN into a double
   * payment.
   */
  app.get<{ Querystring: { older_than_seconds?: string } }>(
    '/v1/executions/unresolved',
    async (request) => {
      requireOperatorRead(request.principal);
      const olderThan = Math.min(
        86_400,
        Math.max(0, Number(request.query.older_than_seconds ?? 0) || 0),
      );
      return db.withTenant(request.principal.organization_id, async (client) => {
        const result = await client.query(
          `SELECT c.id, c.decision_id, c.agent_id, c.state, c.provider,
                  c.idempotency_key, c.external_reference, c.last_error,
                  c.claimed_at, c.resolved_at
             FROM scrutexity.execution_claims c
            WHERE c.state IN ('EXECUTING', 'UNKNOWN')
              AND c.claimed_at < now() - make_interval(secs => $1)
            ORDER BY c.claimed_at ASC
            LIMIT 200`,
          [olderThan],
        );
        return {
          unresolved: result.rows.map((row) => ({
            claim_id: row.id,
            decision_id: row.decision_id,
            agent_id: row.agent_id,
            state: row.state,
            provider: row.provider,
            // The key the provider was called under. A reconciliation job asks
            // the provider about *this* key; asking about anything else would
            // be asking about a different request.
            idempotency_key: row.idempotency_key,
            external_reference: row.external_reference,
            last_error: row.last_error,
            claimed_at: (row.claimed_at as Date).toISOString(),
            resolved_at: row.resolved_at ? (row.resolved_at as Date).toISOString() : null,
          })),
        };
      });
    },
  );

  /**
   * The self-report path.
   *
   * The caller performed the operation itself and is telling Scrutexity what
   * happened. Scrutexity records it, spends the grant and writes a receipt --
   * but it verified nothing about the operation, because it never saw one.
   *
   * This is not enforcement and evidence written here says so: the attempt
   * carries `enforced = false`. Kept because an integration that cannot route
   * its side effects through a provider is better off recording them than
   * recording nothing, and removed the moment it stops being true.
   */
  app.post('/v1/executions', async (request, reply) => {
    requireScope(request.principal, SCOPES.authorize);
    const body = RecordExecutionSchema.parse(request.body);
    const { status, body: payload } = await mutate(
      request as never,
      'POST /v1/executions',
      async (client) => {
        const agentId =
          request.principal.type === 'agent'
            ? request.principal.id
            : await decisionAgentId(client, body.decision_id);
        const result = await recordExecution(client, keys, {
          organizationId: request.principal.organization_id,
          decisionId: body.decision_id,
          agentId,
          status: body.status,
          result: body.result,
          idempotencyKey: (request.headers['idempotency-key'] as string | undefined) ?? null,
        });
        return { status: 201, body: result };
      },
    );
    reply.code(status).send(payload);
  });

  // ==========================================================================
  // Signals
  // ==========================================================================

  app.post('/v1/signals', async (request, reply) => {
    requireScope(request.principal, SCOPES.signalWrite);
    const body = IngestSignalSchema.parse(request.body);
    // A rejected signal rolls its transaction back, so any security event
    // written inside it would vanish with it. Recording it out here, on a
    // fresh transaction, is what makes a refusal auditable.
    const { status, body: payload } = await recordingRejections(request, () =>
      mutate(request as never, 'POST /v1/signals', async (client) => {
        const result = await ingestSignal(client, keys, {
          organizationId: request.principal.organization_id,
          subjectType: body.subject.type,
          subjectId: body.subject.id,
          signalType: body.signal_type,
          value: body.value,
          confidence: body.confidence,
          source: body.source,
          ttlSeconds: body.ttl_seconds,
          issuedAt: body.issued_at,
          metadata: body.metadata,
          eventId: body.event_id ?? null,
          signature: body.signature ?? null,
          signingKeyId: body.signing_key_id ?? null,
        });
        return { status: 201, body: result };
      }),
    );
    reply.code(status).send(payload);
  });

  // ==========================================================================
  // Approvals
  // ==========================================================================

  app.get('/v1/approval-requests', async (request) => {
    requireOperatorRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        `SELECT ar.*, d.decision, d.reason_code, d.agent_id, r.action, r.resource_type,
                r.resource_id, r.context, a.handle AS agent_handle
           FROM scrutexity.approval_requests ar
           JOIN scrutexity.authorization_decisions d ON d.id = ar.decision_id
           JOIN scrutexity.authorization_requests r ON r.id = ar.request_id
           JOIN scrutexity.agents a ON a.id = d.agent_id
          WHERE ar.status = 'PENDING'
          ORDER BY ar.created_at DESC LIMIT 100`,
      );
      return { approval_requests: result.rows };
    });
  });

  app.post('/v1/approvals', async (request, reply) => {
    requireScope(request.principal, SCOPES.approve);
    // Only a human approves. An agent holding an approver's credential is
    // exactly the confused-deputy case this control exists to prevent.
    requireHuman(request.principal);
    const body = SubmitApprovalSchema.parse(request.body);

    const { status, body: payload } = await mutate(
      request as never,
      'POST /v1/approvals',
      async (client) => {
        const result = await submitApproval(client, keys, {
          organizationId: request.principal.organization_id,
          approvalRequestId: body.approval_request_id,
          approverUserId: request.principal.id,
          vote: body.vote,
          comment: body.comment ?? null,
          idempotencyKey: (request.headers['idempotency-key'] as string | undefined) ?? null,
        });
        return {
          status: 201,
          body: {
            approval_id: result.approval_id,
            satisfied_role: result.satisfied_role,
            decision: result.reevaluation
              ? {
                  decision_id: result.reevaluation.decision_id,
                  decision: result.reevaluation.evaluation.decision,
                  reason_code: result.reevaluation.evaluation.reason_code,
                  receipt_id: result.reevaluation.receipt_id,
                  expires_at: result.reevaluation.evaluation.expires_at,
                }
              : null,
          },
        };
      },
    );
    reply.code(status).send(payload);
  });

  // ==========================================================================
  // Evidence
  // ==========================================================================

  app.get<{ Params: { id: string } }>('/v1/receipts/:id', async (request) => {
    requireRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const receipt = await fetchReceipt(client, request.params.id);
      if (!receipt) throw new ScrutexityError('NOT_FOUND', 'receipt not found');
      // A receipt's subject is the agent it is about. An agent may hold its own
      // evidence; it may not read the chain entry for another agent's wire.
      assertMayReadSubject(request.principal, receipt.subject_id);
      return { receipt };
    });
  });

  app.post<{ Params: { id: string } }>('/v1/receipts/:id/verify', async (request) =>
    db.withTenant(request.principal.organization_id, async (client) => {
      const result = await verifyReceiptWithChain(client, keys, request.params.id);
      if (!result) throw new ScrutexityError('NOT_FOUND', 'receipt not found');
      return {
        receipt_id: result.receipt.id,
        // Deliberate wording. This attests to integrity and provenance of the
        // evidence -- not to the correctness or lawfulness of the decision it
        // records.
        integrity: result.receipt_verification.intact ? 'INTACT' : 'COMPROMISED',
        attests: 'evidence_integrity_and_provenance',
        receipt_verification: result.receipt_verification,
        chain_verification: result.chain_verification,
      };
    }),
  );

  /** Verifies a receipt supplied by the caller against this tenant's records. */
  app.post('/v1/receipts/verify', async (request) => {
    const supplied = (request.body as { receipt?: unknown } | null)?.receipt;
    if (!supplied || typeof supplied !== 'object') {
      throw new ScrutexityError('INVALID_REQUEST', 'body must contain a `receipt` object');
    }
    const receipt = supplied as Parameters<typeof verifyReceipt>[0];
    const offline = verifyReceipt(receipt, keys.verifier);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const stored = await fetchReceipt(client, receipt.id);
      return {
        receipt_id: receipt.id,
        integrity: offline.intact ? 'INTACT' : 'COMPROMISED',
        attests: 'evidence_integrity_and_provenance',
        receipt_verification: offline,
        matches_stored_record: stored ? stored.hash === receipt.hash : null,
      };
    });
  });

  // ==========================================================================
  // Policy lifecycle
  // ==========================================================================

  app.post('/v1/policy-versions', async (request, reply) => {
    requireScope(request.principal, SCOPES.policyWrite);
    requireHuman(request.principal);
    const body = CreatePolicyVersionSchema.parse(request.body);
    const loaded =
      typeof body.document === 'string'
        ? loadPolicyYaml(body.document)
        : loadPolicyDocument(body.document);

    const { status, body: payload } = await mutate(
      request as never,
      'POST /v1/policy-versions',
      async (client) => {
        const key = body.policy_key ?? loaded.document.id;
        const policyResult = await client.query(
          `INSERT INTO scrutexity.policies (id, organization_id, key, name)
           VALUES ($1,$2,$3,$4)
           ON CONFLICT (organization_id, key) DO UPDATE SET name = EXCLUDED.name
           RETURNING id`,
          [newId('policy'), request.principal.organization_id, key, loaded.document.metadata.title],
        );
        const policyId = policyResult.rows[0]!.id as string;

        const previous = await client.query(
          `SELECT id FROM scrutexity.policy_versions
            WHERE policy_id = $1 ORDER BY created_at DESC LIMIT 1`,
          [policyId],
        );

        const versionId = newId('policyVersion');
        try {
          const inserted = await client.query(
            `INSERT INTO scrutexity.policy_versions
               (id, organization_id, policy_id, version, status, content, content_hash,
                author_user_id, previous_version_id)
             VALUES ($1,$2,$3,$4,'DRAFT',$5,$6,$7,$8) RETURNING *`,
            [
              versionId,
              request.principal.organization_id,
              policyId,
              loaded.document.version,
              JSON.stringify(loaded.document),
              loaded.hash,
              request.principal.id,
              previous.rows[0]?.id ?? null,
            ],
          );
          return {
            status: 201,
            body: { policy_version: serializePolicyVersion(inserted.rows[0]) },
          };
        } catch (error) {
          if ((error as { code?: string }).code === '23505') {
            throw new ScrutexityError(
              'STATE_CONFLICT',
              `version ${loaded.document.version} of policy "${key}" already exists; policy versions are immutable`,
            );
          }
          throw error;
        }
      },
    );
    reply.code(status).send(payload);
  });

  /**
   * Dual control on activation (Section 32). Two distinct humans, neither of
   * them the author, must approve before a policy version can take effect.
   */
  app.post<{ Params: { id: string } }>(
    '/v1/policy-versions/:id/reviews',
    async (request, reply) => {
      requireScope(request.principal, SCOPES.policyWrite);
      requireHuman(request.principal);
      const body = ReviewPolicyVersionSchema.parse(request.body);

      const result = await db.withTenant(request.principal.organization_id, async (client) => {
        const version = await client.query(
          'SELECT * FROM scrutexity.policy_versions WHERE id = $1 FOR UPDATE',
          [request.params.id],
        );
        if (version.rowCount === 0)
          throw new ScrutexityError('NOT_FOUND', 'policy version not found');
        const row = version.rows[0];
        if (!['DRAFT', 'REVIEW'].includes(row.status)) {
          throw new ScrutexityError(
            'STATE_CONFLICT',
            `a ${row.status} policy version cannot be reviewed`,
          );
        }
        if (row.author_user_id === request.principal.id) {
          throw new ScrutexityError(
            'FORBIDDEN',
            'the author of a policy version may not review it',
          );
        }

        try {
          await client.query(
            `INSERT INTO scrutexity.policy_version_reviews
             (id, organization_id, policy_version_id, reviewer_user_id, vote, comment)
           VALUES ($1,$2,$3,$4,$5,$6)`,
            [
              newId('policyReview'),
              request.principal.organization_id,
              row.id,
              request.principal.id,
              body.vote,
              body.comment ?? null,
            ],
          );
        } catch (error) {
          if ((error as { code?: string }).code === '23505') {
            throw new ScrutexityError('STATE_CONFLICT', 'this reviewer has already voted');
          }
          throw error;
        }

        const votes = await client.query(
          'SELECT vote FROM scrutexity.policy_version_reviews WHERE policy_version_id = $1',
          [row.id],
        );
        const approvals = votes.rows.filter((v) => v.vote === 'APPROVED').length;
        const rejected = votes.rows.some((v) => v.vote === 'REJECTED');

        const nextStatus = rejected ? 'DRAFT' : approvals >= 2 ? 'APPROVED' : 'REVIEW';
        await client.query(
          `UPDATE scrutexity.policy_versions
            SET status = $2, approved_at = CASE WHEN $2 = 'APPROVED' THEN now() ELSE NULL END
          WHERE id = $1`,
          [row.id, nextStatus],
        );

        return { policy_version_id: row.id, status: nextStatus, approvals, rejected };
      });

      reply.code(201).send(result);
    },
  );

  app.post<{ Params: { id: string } }>('/v1/policy-versions/:id/activate', async (request) => {
    requireScope(request.principal, SCOPES.policyWrite);
    requireHuman(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const version = await client.query(
        'SELECT * FROM scrutexity.policy_versions WHERE id = $1 FOR UPDATE',
        [request.params.id],
      );
      if (version.rowCount === 0)
        throw new ScrutexityError('NOT_FOUND', 'policy version not found');
      const row = version.rows[0];
      if (row.status !== 'APPROVED') {
        throw new ScrutexityError(
          'STATE_CONFLICT',
          `only an APPROVED policy version may be activated; this one is ${row.status}`,
        );
      }
      // Integrity check before a document takes effect over live money.
      const recomputed = hashObject(loadPolicyDocument(row.content).document);
      if (recomputed !== row.content_hash) {
        throw new ScrutexityError(
          'EVIDENCE_TAMPERED',
          'the policy version failed its integrity check',
        );
      }

      await client.query(
        `UPDATE scrutexity.policy_versions
            SET status = 'DEPRECATED', deprecated_at = now()
          WHERE policy_id = $1 AND status = 'ACTIVE'`,
        [row.policy_id],
      );
      const activated = await client.query(
        `UPDATE scrutexity.policy_versions
            SET status = 'ACTIVE', activated_at = now()
          WHERE id = $1 RETURNING *`,
        [row.id],
      );

      const { appendReceipt } = await import('../services/evidence.js');
      const receipt = await appendReceipt(client, keys, {
        organizationId: request.principal.organization_id,
        kind: 'POLICY_ACTIVATED',
        subjectId: row.policy_id,
        payload: {
          policy_id: row.policy_id,
          policy_version_id: row.id,
          version: row.version,
          content_hash: row.content_hash,
          activated_by_user_id: request.principal.id,
          previous_version_id: row.previous_version_id,
        },
      });

      return {
        policy_version: serializePolicyVersion(activated.rows[0]),
        receipt_id: receipt.id,
      };
    });
  });

  app.get('/v1/policy-versions', async (request) => {
    // The policy document itself. An agent that can read this has every
    // threshold, approver role and decay rule that governs it -- which defeats
    // the leak controls the refusal paths take seriously.
    requireOperatorRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        `SELECT pv.*, p.key AS policy_key FROM scrutexity.policy_versions pv
           JOIN scrutexity.policies p ON p.id = pv.policy_id
          ORDER BY pv.created_at DESC LIMIT 100`,
      );
      return { policy_versions: result.rows.map(serializePolicyVersion) };
    });
  });

  // ==========================================================================
  // Causal evidence
  // ==========================================================================

  /**
   * The root-cause trace: where the authority behind this decision came from,
   * in causal order, oldest cause first. A database traversal -- nothing is
   * summarised or generated, so the same decision always yields the same trace.
   */
  app.get<{ Params: { id: string } }>('/v1/trace/:id', async (request) => {
    requireRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      // Checked before the trace is built, not after. The trace walks policy
      // activations, signal ingestion and the whole authority ancestry -- it is
      // the richest read in the API, and an agent must not be able to obtain
      // one for a decision that was not issued to it.
      const subject = await client.query(
        'SELECT agent_id FROM scrutexity.authorization_decisions WHERE id = $1',
        [request.params.id],
      );
      assertMayReadSubject(
        request.principal,
        (subject.rows[0]?.agent_id as string | undefined) ?? null,
      );

      const started = performance.now();
      const trace = await buildDecisionTrace(client, request.params.id);
      metrics.traceDuration.observe((performance.now() - started) / 1000);
      metrics.traceNodes.observe(trace.trace.length);
      return trace;
    });
  });

  // ==========================================================================
  // Signal signing keys
  // ==========================================================================

  app.post('/v1/signal-keys', async (request, reply) => {
    requireScope(request.principal, SCOPES.adminWrite);
    const body = RegisterSignalKeySchema.parse(request.body);
    const { status, body: payload } = await mutate(
      request as never,
      'POST /v1/signal-keys',
      async (client) => {
        try {
          const result = await client.query(
            `INSERT INTO scrutexity.signal_signing_keys
               (id, organization_id, source, key_id, algorithm, key_material,
                not_before, not_after)
             VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7::timestamptz, now()),$8)
             RETURNING id, source, key_id, algorithm, status, not_before, not_after, created_at`,
            [
              newId('signalKey'),
              request.principal.organization_id,
              body.source,
              body.key_id,
              body.algorithm,
              body.key_material,
              body.not_before ?? null,
              body.not_after ?? null,
            ],
          );
          // The key material is never echoed back, for either algorithm. A
          // caller that just supplied it does not need it returned, and an
          // HMAC secret in a response body is a secret in a log.
          return { status: 201, body: { signal_key: result.rows[0] } };
        } catch (error) {
          if ((error as { code?: string }).code === '23505') {
            throw new ScrutexityError(
              'STATE_CONFLICT',
              `key "${body.key_id}" is already registered for source "${body.source}"`,
            );
          }
          throw error;
        }
      },
    );
    reply.code(status).send(payload);
  });

  app.get('/v1/signal-keys', async (request) => {
    requireOperatorRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        `SELECT id, source, key_id, algorithm, status, not_before, not_after,
                created_at, revoked_at
           FROM scrutexity.signal_signing_keys
          ORDER BY created_at DESC LIMIT 200`,
      );
      return { signal_keys: result.rows };
    });
  });

  /**
   * Retires a key with a grace period rather than revoking it outright. The
   * overlap is what lets a source finish switching over without dropping
   * signals; use revoke when a key is believed compromised and no overlap is
   * acceptable.
   */
  app.post<{ Params: { id: string } }>('/v1/signal-keys/:id/retire', async (request) => {
    requireScope(request.principal, SCOPES.adminWrite);
    const body = RotateSignalKeySchema.parse(request.body ?? {});
    return db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        `UPDATE scrutexity.signal_signing_keys
            SET status = 'RETIRING',
                not_after = now() + make_interval(secs => $2)
          WHERE id = $1 AND status = 'ACTIVE'
          RETURNING id, source, key_id, status, not_after`,
        [request.params.id, body.grace_period_seconds],
      );
      if (result.rowCount === 0) {
        throw new ScrutexityError('NOT_FOUND', 'no active signing key with that id');
      }
      return { signal_key: result.rows[0] };
    });
  });

  app.post<{ Params: { id: string } }>('/v1/signal-keys/:id/revoke', async (request) => {
    requireScope(request.principal, SCOPES.adminWrite);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        `UPDATE scrutexity.signal_signing_keys
            SET status = 'REVOKED', revoked_at = now()
          WHERE id = $1 AND status <> 'REVOKED'
          RETURNING id, source, key_id, status, revoked_at`,
        [request.params.id],
      );
      if (result.rowCount === 0) {
        throw new ScrutexityError('NOT_FOUND', 'no revocable signing key with that id');
      }
      await recordSecurityEvent(client, {
        organizationId: request.principal.organization_id,
        kind: 'SIGNAL_KEY_REVOKED',
        source: result.rows[0]!.source as string,
        detail: { key_id: result.rows[0]!.key_id, revoked_by: request.principal.id },
      });
      return { signal_key: result.rows[0] };
    });
  });

  app.get('/v1/security-events', async (request) => {
    // The forensic record of attacks, including this caller's own. Never an
    // agent.
    requireOperatorRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        `SELECT id, kind, source, subject_id, detail, created_at
           FROM scrutexity.security_events
          ORDER BY created_at DESC LIMIT 200`,
      );
      return { security_events: result.rows };
    });
  });

  // ==========================================================================
  // Dashboard read model
  // ==========================================================================

  app.get('/v1/overview', async (request) => {
    requireOperatorRead(request.principal);
    return db.withTenant(request.principal.organization_id, async (client) => {
      const agents = await client.query(
        'SELECT * FROM scrutexity.agents ORDER BY created_at ASC LIMIT 50',
      );
      const leases = await client.query(
        `SELECT * FROM scrutexity.authority_leases
          WHERE status = 'ACTIVE' AND expires_at > now()
          ORDER BY issued_at DESC LIMIT 50`,
      );
      const approvals = await client.query(
        `SELECT ar.id, ar.requirement, ar.expires_at, ar.created_at, d.reason_code,
                r.action, r.resource_type, r.resource_id, r.context, a.handle AS agent_handle
           FROM scrutexity.approval_requests ar
           JOIN scrutexity.authorization_decisions d ON d.id = ar.decision_id
           JOIN scrutexity.authorization_requests r ON r.id = ar.request_id
           JOIN scrutexity.agents a ON a.id = d.agent_id
          WHERE ar.status = 'PENDING' ORDER BY ar.created_at DESC LIMIT 25`,
      );
      const decisions = await client.query(
        `SELECT d.id, d.decision, d.reason_code, d.decided_at, r.action, r.resource_type,
                r.resource_id, a.handle AS agent_handle
           FROM scrutexity.authorization_decisions d
           JOIN scrutexity.authorization_requests r ON r.id = d.request_id
           JOIN scrutexity.agents a ON a.id = d.agent_id
          ORDER BY d.decided_at DESC LIMIT 25`,
      );
      const signals = await client.query(
        `SELECT id, subject_type, subject_id, signal_type, value, confidence, source,
                issued_at, expires_at
           FROM scrutexity.risk_signals
          WHERE superseded_at IS NULL AND expires_at > now()
          ORDER BY issued_at DESC LIMIT 25`,
      );
      return {
        agents: agents.rows.map(serializeAgent),
        active_leases: (leases.rows as LeaseRow[]).map(toLease),
        pending_approvals: approvals.rows,
        recent_decisions: decisions.rows,
        live_signals: signals.rows.map(serializeSignal),
      };
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function serializeAgent(row: Record<string, unknown>) {
  return {
    id: row.id,
    handle: row.handle,
    display_name: row.display_name,
    description: row.description,
    owner_user_id: row.owner_user_id,
    status: row.status,
    metadata: row.metadata,
    created_at: (row.created_at as Date).toISOString(),
  };
}

function serializeSignal(row: Record<string, unknown>) {
  return {
    id: row.id,
    subject_type: row.subject_type,
    subject_id: row.subject_id,
    signal_type: row.signal_type,
    value: String(row.value),
    confidence: String(row.confidence),
    source: row.source,
    issued_at: (row.issued_at as Date).toISOString(),
    expires_at: (row.expires_at as Date).toISOString(),
  };
}

function serializePolicyVersion(row: Record<string, unknown>) {
  return {
    id: row.id,
    policy_id: row.policy_id,
    policy_key: row.policy_key,
    version: row.version,
    status: row.status,
    content_hash: row.content_hash,
    author_user_id: row.author_user_id,
    previous_version_id: row.previous_version_id,
    approved_at: row.approved_at ? (row.approved_at as Date).toISOString() : null,
    activated_at: row.activated_at ? (row.activated_at as Date).toISOString() : null,
    created_at: (row.created_at as Date).toISOString(),
  };
}

async function resolveAgentId(client: PoolClient, handleOrId: string): Promise<string> {
  const result = await client.query(
    'SELECT id FROM scrutexity.agents WHERE id = $1 OR handle = $1',
    [handleOrId],
  );
  if (result.rowCount === 0) throw new ScrutexityError('NOT_FOUND', 'agent not found');
  return result.rows[0]!.id as string;
}

async function decisionAgentId(client: PoolClient, decisionId: string): Promise<string> {
  const result = await client.query(
    'SELECT agent_id FROM scrutexity.authorization_decisions WHERE id = $1',
    [decisionId],
  );
  if (result.rowCount === 0)
    throw new ScrutexityError('NOT_FOUND', 'authorization decision not found');
  return result.rows[0]!.agent_id as string;
}

async function assertHandleBelongsToPrincipal(
  db: Database,
  principal: Principal,
  claimed: string,
): Promise<void> {
  const owns = await db.withTenant(principal.organization_id, async (client) => {
    const result = await client.query(
      'SELECT id FROM scrutexity.agents WHERE (id = $1 OR handle = $1) AND id = $2',
      [claimed, principal.id],
    );
    return (result.rowCount ?? 0) > 0;
  });
  if (!owns) {
    throw new ScrutexityError('FORBIDDEN', 'this credential may only authorize its own agent', {
      internal: { credential_principal: principal.id, claimed_agent: claimed },
    });
  }
}
