import { ScrutexityError } from '@scrutexity/core';
import type { PoolClient } from '../db/pool.js';

/**
 * ============================================================================
 * The root-cause trace.
 * ============================================================================
 *
 * "Why was this allowed" has a good answer already: the decision record says
 * which policy matched and which authority applied. This answers the question
 * behind it -- where did that authority come from, and who set it in motion?
 *
 * The trace walks backwards from a decision to its origin and returns the
 * chain in *causal* order, oldest cause first. Reverse-chronological would be
 * easier to produce and much harder to read: an investigator wants to start at
 * "the CFO activated this policy" and arrive at "so the wire was blocked", not
 * the other way round.
 *
 * It is a database traversal. Nothing is summarised, inferred, or generated;
 * the same decision always produces the same trace, which is what makes it
 * usable as evidence rather than as a narrative.
 */

export const TRACE_NODE_TYPES = [
  'policy_activation',
  'policy_version',
  'authority_lease',
  'delegation',
  'risk_signal',
  'authorization_request',
  'human_approval',
  'authorization_decision',
  'execution',
] as const;

export type TraceNodeType = (typeof TRACE_NODE_TYPES)[number];

/**
 * How a node caused the one that follows it. A closed vocabulary, so a caller
 * can render or reason about the edge without parsing prose.
 */
export const CAUSAL_LINK_TYPES = [
  'origin',
  'admitted_authority',
  'derived_from',
  'delegated_to',
  'issued_under',
  'requested_under',
  'influenced_by',
  'evaluated_to',
  'approved_by',
  'superseded_by',
  'executed_as',
] as const;

export type CausalLinkType = (typeof CAUSAL_LINK_TYPES)[number];

export interface TraceNode {
  step: number;
  type: TraceNodeType;
  id: string;
  /** Short human-facing label. Assembled from fields, never generated. */
  name: string;
  timestamp: string;
  /** The node this one follows from. Null only for the root cause. */
  causal_parent_id: string | null;
  causal_link_type: CausalLinkType;
  /** Type-specific facts, drawn straight from the stored row. */
  detail: Record<string, unknown>;
}

export interface DecisionTrace {
  decision_id: string;
  /** The origin of the authority this decision rested on. */
  root_cause: TraceNode | null;
  trace: TraceNode[];
  /** True when the chain reaches a policy activation rather than stopping short. */
  complete: boolean;
}

interface DecisionRow {
  id: string;
  organization_id: string;
  request_id: string;
  agent_id: string;
  decision: string;
  reason_code: string;
  policy_id: string | null;
  policy_version_id: string | null;
  policy_hash: string | null;
  authority_lease_id: string | null;
  risk_signal_ids: string[];
  supersedes_decision_id: string | null;
  context_hash: string | null;
  intent_evaluation: Record<string, unknown> | null;
  decided_at: Date;
  action: string;
  resource_type: string;
  resource_id: string;
  declared_intent: string | null;
  requested_at: Date;
  agent_handle: string;
}

export async function buildDecisionTrace(
  client: PoolClient,
  decisionId: string,
): Promise<DecisionTrace> {
  const result = await client.query(
    `SELECT d.*, r.action, r.resource_type, r.resource_id, r.declared_intent,
            r.created_at AS requested_at, a.handle AS agent_handle
       FROM scrutexity.authorization_decisions d
       JOIN scrutexity.authorization_requests r ON r.id = d.request_id
       JOIN scrutexity.agents a ON a.id = d.agent_id
      WHERE d.id = $1`,
    [decisionId],
  );
  const decision = result.rows[0] as DecisionRow | undefined;
  if (!decision) throw new ScrutexityError('NOT_FOUND', 'authorization decision not found');

  const nodes: Omit<TraceNode, 'step'>[] = [];

  // -- 1. Where the policy came from ---------------------------------------
  let previousId: string | null = null;
  if (decision.policy_version_id) {
    const policy = await client.query(
      `SELECT pv.id, pv.version, pv.content_hash, pv.activated_at, pv.approved_at,
              pv.created_at, p.key AS policy_key, u.display_name AS author
         FROM scrutexity.policy_versions pv
         JOIN scrutexity.policies p ON p.id = pv.policy_id
         LEFT JOIN scrutexity.users u ON u.id = pv.author_user_id
        WHERE pv.id = $1`,
      [decision.policy_version_id],
    );
    const row = policy.rows[0];
    if (row) {
      // The activation is the true origin: a policy version that was never
      // activated could not have admitted any authority.
      if (row.activated_at) {
        nodes.push({
          type: 'policy_activation',
          id: row.id as string,
          name: `${row.policy_key} v${row.version} activated`,
          timestamp: (row.activated_at as Date).toISOString(),
          causal_parent_id: null,
          causal_link_type: 'origin',
          detail: {
            policy_key: row.policy_key,
            version: row.version,
            content_hash: row.content_hash,
            author: row.author ?? null,
            approved_at: row.approved_at ? (row.approved_at as Date).toISOString() : null,
          },
        });
        previousId = row.id as string;
      }
      nodes.push({
        type: 'policy_version',
        id: row.id as string,
        name: `${row.policy_key} v${row.version}`,
        timestamp: (row.created_at as Date).toISOString(),
        causal_parent_id: previousId,
        causal_link_type: previousId ? 'derived_from' : 'origin',
        detail: { policy_key: row.policy_key, version: row.version, hash: row.content_hash },
      });
      previousId = row.id as string;
    }
  }

  // -- 2. The authority chain, root first -----------------------------------
  if (decision.authority_lease_id) {
    const chain = await client.query(
      `WITH RECURSIVE ancestry AS (
         SELECT l.*, 0 AS distance FROM scrutexity.authority_leases l WHERE l.id = $1
         UNION ALL
         SELECT p.*, a.distance + 1
           FROM scrutexity.authority_leases p
           JOIN ancestry a ON p.id = a.parent_lease_id
       )
       SELECT ancestry.*, ag.handle AS agent_handle
         FROM ancestry
         JOIN scrutexity.agents ag ON ag.id = ancestry.agent_id
        ORDER BY distance DESC`,
      [decision.authority_lease_id],
    );

    for (const lease of chain.rows) {
      // A delegated lease is preceded by the delegation edge that created it,
      // so the trace shows the act of delegating, not just its result.
      if (lease.parent_lease_id) {
        const delegation = await client.query(
          `SELECT d.id, d.created_at, d.expires_at, d.requested_grant,
                  issuer.handle AS issuer_handle, delegate.handle AS delegate_handle
             FROM scrutexity.delegations d
             JOIN scrutexity.agents issuer ON issuer.id = d.issuer_agent_id
             JOIN scrutexity.agents delegate ON delegate.id = d.delegate_agent_id
            WHERE d.child_lease_id = $1`,
          [lease.id],
        );
        const edge = delegation.rows[0];
        if (edge) {
          nodes.push({
            type: 'delegation',
            id: edge.id as string,
            name: `${edge.issuer_handle} delegated to ${edge.delegate_handle}`,
            timestamp: (edge.created_at as Date).toISOString(),
            causal_parent_id: previousId,
            causal_link_type: 'delegated_to',
            detail: {
              issuer: edge.issuer_handle,
              delegate: edge.delegate_handle,
              parent_lease_id: lease.parent_lease_id,
              child_lease_id: lease.id,
              expires_at: (edge.expires_at as Date).toISOString(),
            },
          });
          previousId = edge.id as string;
        }
      }

      nodes.push({
        type: 'authority_lease',
        id: lease.id as string,
        name: `authority held by ${lease.agent_handle}`,
        timestamp: (lease.issued_at as Date).toISOString(),
        causal_parent_id: previousId,
        causal_link_type: lease.parent_lease_id ? 'derived_from' : 'admitted_authority',
        detail: {
          agent: lease.agent_handle,
          depth: lease.depth,
          grant_type: lease.grant_type,
          purpose: lease.purpose,
          status: lease.status,
          actions: lease.actions,
          resources: lease.resources,
          constraints: lease.constraints,
          expires_at: (lease.expires_at as Date).toISOString(),
          consumed: lease.consumed,
        },
      });
      previousId = lease.id as string;
    }
  }

  // -- 3. The request ------------------------------------------------------
  nodes.push({
    type: 'authorization_request',
    id: decision.request_id,
    name: `${decision.agent_handle} requested ${decision.action}`,
    timestamp: decision.requested_at.toISOString(),
    causal_parent_id: previousId,
    causal_link_type: previousId ? 'requested_under' : 'origin',
    detail: {
      agent: decision.agent_handle,
      action: decision.action,
      resource: { type: decision.resource_type, id: decision.resource_id },
      declared_intent: decision.declared_intent,
    },
  });
  previousId = decision.request_id;

  // -- 4. Signals that were actually read ----------------------------------
  if (decision.risk_signal_ids.length > 0) {
    const signals = await client.query(
      `SELECT id, signal_type, subject_type, subject_id, value, confidence, source,
              issued_at, expires_at, authenticated
         FROM scrutexity.risk_signals
        WHERE id = ANY($1::text[])
        ORDER BY issued_at ASC`,
      [decision.risk_signal_ids],
    );
    for (const signal of signals.rows) {
      nodes.push({
        type: 'risk_signal',
        id: signal.id as string,
        name: `${signal.signal_type} = ${String(signal.value)} from ${signal.source}`,
        timestamp: (signal.issued_at as Date).toISOString(),
        causal_parent_id: previousId,
        causal_link_type: 'influenced_by',
        detail: {
          signal_type: signal.signal_type,
          subject: { type: signal.subject_type, id: signal.subject_id },
          value: String(signal.value),
          confidence: String(signal.confidence),
          source: signal.source,
          authenticated: signal.authenticated,
          expires_at: (signal.expires_at as Date).toISOString(),
        },
      });
    }
  }

  // -- 5. The escalation this decision superseded, and the humans in it -----
  if (decision.supersedes_decision_id) {
    const prior = await client.query(
      `SELECT id, decision, reason_code, decided_at
         FROM scrutexity.authorization_decisions WHERE id = $1`,
      [decision.supersedes_decision_id],
    );
    const row = prior.rows[0];
    if (row) {
      nodes.push({
        type: 'authorization_decision',
        id: row.id as string,
        name: `${row.decision} — ${row.reason_code}`,
        timestamp: (row.decided_at as Date).toISOString(),
        causal_parent_id: previousId,
        causal_link_type: 'evaluated_to',
        detail: { decision: row.decision, reason_code: row.reason_code, superseded: true },
      });
      previousId = row.id as string;
    }
  }

  const approvals = await client.query(
    `SELECT ap.id, ap.vote, ap.satisfied_role, ap.roles_at_decision, ap.created_at,
            ap.approved_context_hash, u.display_name, u.email
       FROM scrutexity.approval_requests ar
       JOIN scrutexity.approvals ap ON ap.approval_request_id = ar.id
       JOIN scrutexity.users u ON u.id = ap.approver_user_id
      WHERE ar.decision_id = $1 OR ar.decision_id = $2
      ORDER BY ap.created_at ASC`,
    [decision.id, decision.supersedes_decision_id],
  );
  for (const approval of approvals.rows) {
    nodes.push({
      type: 'human_approval',
      id: approval.id as string,
      name: `${approval.display_name} ${approval.vote === 'APPROVED' ? 'approved' : 'rejected'}`,
      timestamp: (approval.created_at as Date).toISOString(),
      causal_parent_id: previousId,
      causal_link_type: 'approved_by',
      detail: {
        approver: approval.display_name,
        vote: approval.vote,
        satisfied_role: approval.satisfied_role,
        // Roles as held at that instant, never as they stand now.
        roles_at_decision: approval.roles_at_decision,
        approved_context_hash: approval.approved_context_hash,
      },
    });
    previousId = approval.id as string;
  }

  // -- 6. The decision itself, and what was done with it -------------------
  nodes.push({
    type: 'authorization_decision',
    id: decision.id,
    name: `${decision.decision} — ${decision.reason_code}`,
    timestamp: decision.decided_at.toISOString(),
    causal_parent_id: previousId,
    causal_link_type: decision.supersedes_decision_id ? 'superseded_by' : 'evaluated_to',
    detail: {
      decision: decision.decision,
      reason_code: decision.reason_code,
      policy_hash: decision.policy_hash,
      context_hash: decision.context_hash,
      intent_evaluation: decision.intent_evaluation,
    },
  });
  previousId = decision.id;

  const execution = await client.query(
    `SELECT id, status, result, created_at
       FROM scrutexity.execution_attempts WHERE decision_id = $1`,
    [decision.id],
  );
  if (execution.rows[0]) {
    const row = execution.rows[0];
    nodes.push({
      type: 'execution',
      id: row.id as string,
      name: `execution ${row.status}`,
      timestamp: (row.created_at as Date).toISOString(),
      causal_parent_id: previousId,
      causal_link_type: 'executed_as',
      detail: { status: row.status, result: row.result },
    });
  }

  const trace = nodes.map((node, index) => ({ ...node, step: index + 1 }));
  return {
    decision_id: decision.id,
    root_cause: trace[0] ?? null,
    trace,
    complete: trace[0]?.type === 'policy_activation',
  };
}
