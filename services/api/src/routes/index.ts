import {
  ScrutexityError,
  explainDecision,
  hashObject,
  loadPolicyDocument,
  loadPolicyYaml,
  newId,
  verifyReceipt,
} from '@scrutexity/core';
import type { FastifyInstance } from 'fastify';
import { SCOPES, requireHuman, requireScope, type Principal } from '../auth.js';
import { claimIdempotencyKey, completeIdempotencyKey } from '../idempotency.js';
import type { Database, PoolClient } from '../db/pool.js';
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
  RecordExecutionSchema,
  ReviewPolicyVersionSchema,
  RevokeLeaseSchema,
  SubmitApprovalSchema,
} from '../schemas.js';

export interface RouteDeps {
  db: Database;
  keys: EvidenceKeys;
}

declare module 'fastify' {
  interface FastifyRequest {
    principal: Principal;
  }
}

export async function registerRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db, keys } = deps;

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

  app.get('/v1/agents', async (request) =>
    db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        'SELECT * FROM scrutexity.agents ORDER BY created_at DESC LIMIT 200',
      );
      return { agents: result.rows.map(serializeAgent) };
    }),
  );

  app.get<{ Params: { id: string } }>('/v1/agents/:id', async (request) =>
    db.withTenant(request.principal.organization_id, async (client) => {
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
    }),
  );

  // ==========================================================================
  // Authority
  // ==========================================================================

  app.post('/v1/authority-leases', async (request, reply) => {
    requireScope(request.principal, SCOPES.leaseWrite);
    const body = CreateLeaseSchema.parse(request.body);
    const { status, body: payload } = await mutate(
      request as never,
      'POST /v1/authority-leases',
      async (client) => {
        const result = await issueLease(client, keys, {
          organizationId: request.principal.organization_id,
          agentId: await resolveAgentId(client, body.agent_id),
          grant: body.grant,
          ttlSeconds: body.ttl_seconds,
          issuedByUserId: request.principal.type === 'user' ? request.principal.id : null,
          revocable: body.revocable,
          metadata: body.metadata,
        });
        return {
          status: 201,
          body: { authority_lease: result.lease, receipt_id: result.receipt_id },
        };
      },
    );
    reply.code(status).send(payload);
  });

  app.get<{ Params: { id: string } }>('/v1/authority-leases/:id', async (request) =>
    db.withTenant(request.principal.organization_id, async (client) => {
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
      const rows = (result.rows as LeaseRow[]).map(toLease);
      const lease = rows.find((l) => l.id === request.params.id)!;
      return { authority_lease: lease, ancestry: rows };
    }),
  );

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

    return mutate(request, endpoint, async (client) => {
      const result = await authorize(client, keys, {
        organizationId: request.principal.organization_id,
        agentHandleOrId: body.agent_id,
        action: body.action,
        resource: body.resource,
        context: body.context,
        presentedLeaseId: body.authority_lease_id ?? null,
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
          failover_behavior: result.evaluation.failover_behavior,
          expires_at: result.evaluation.expires_at,
          decision_timestamp: result.evaluation.decision_timestamp,
        },
      };
    });
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
  app.get<{ Params: { id: string } }>('/v1/authorization-decisions/:id', async (request) =>
    db.withTenant(request.principal.organization_id, async (client) => {
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
    }),
  );

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
    const { status, body: payload } = await mutate(
      request as never,
      'POST /v1/signals',
      async (client) => {
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
        });
        return { status: 201, body: result };
      },
    );
    reply.code(status).send(payload);
  });

  // ==========================================================================
  // Approvals
  // ==========================================================================

  app.get('/v1/approval-requests', async (request) =>
    db.withTenant(request.principal.organization_id, async (client) => {
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
    }),
  );

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

  app.get<{ Params: { id: string } }>('/v1/receipts/:id', async (request) =>
    db.withTenant(request.principal.organization_id, async (client) => {
      const receipt = await fetchReceipt(client, request.params.id);
      if (!receipt) throw new ScrutexityError('NOT_FOUND', 'receipt not found');
      return { receipt };
    }),
  );

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

  app.get('/v1/policy-versions', async (request) =>
    db.withTenant(request.principal.organization_id, async (client) => {
      const result = await client.query(
        `SELECT pv.*, p.key AS policy_key FROM scrutexity.policy_versions pv
           JOIN scrutexity.policies p ON p.id = pv.policy_id
          ORDER BY pv.created_at DESC LIMIT 100`,
      );
      return { policy_versions: result.rows.map(serializePolicyVersion) };
    }),
  );

  // ==========================================================================
  // Dashboard read model
  // ==========================================================================

  app.get('/v1/overview', async (request) =>
    db.withTenant(request.principal.organization_id, async (client) => {
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
    }),
  );
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
