import { z } from 'zod';
import { MoneySchema, type Money } from './money.js';
import type { AuthorityGrant } from './authority/grant.js';
import type { AuthorizationEvaluation } from './evaluate.js';

/**
 * ============================================================================
 * The corrective handshake.
 * ============================================================================
 *
 * A denial that only says "no" makes an agent guess. Guessing looks like
 * retrying with a slightly different request until something works, which is
 * indistinguishable from probing and is how integrations become brittle and
 * audit trails become noise.
 *
 * So a refusal carries the next legitimate step, when one exists: ask this
 * agent for a delegation, request a lease covering this action, put it to a
 * human. The agent stops guessing and starts negotiating, and every step it
 * takes is one the control plane named.
 *
 * Three rules govern what may be returned, and they are what keep this from
 * becoming an oracle:
 *
 *  1. Deterministic and policy-derived. Corrective actions are computed from
 *     the same structured decision record that produced the refusal. No model
 *     generates them, and the same decision always yields the same actions.
 *
 *  2. Never a hint about policy internals. Payloads are assembled from the
 *     caller's own request and from the approval requirement it was already
 *     told about. They never carry rule ids, thresholds, or the value that
 *     would have passed -- an agent must not be able to binary-search a policy
 *     by reading its own denials.
 *
 *  3. Hard violations return nothing. A sanctioned destination, an unknown
 *     counterparty, a revoked authority, an action forbidden by the declared
 *     intent: these are answers, not obstacles. Offering a next step would
 *     imply one exists.
 */

export const CORRECTIVE_ACTION_TYPES = [
  /** Ask an authority-issuing principal for a lease covering this action. */
  'REQUEST_LEASE',
  /** Ask a specific agent to delegate a narrowed subset of what it holds. */
  'REQUEST_DELEGATION',
  /** Put the action to a human who holds the required role. */
  'HUMAN_ESCALATION',
  /** Re-submit declaring an intent the policy recognises. */
  'DECLARE_INTENT',
  /** Conditions moved; ask again and act on the fresh answer. */
  'REEVALUATE',
] as const;

export type CorrectiveActionType = (typeof CORRECTIVE_ACTION_TYPES)[number];

export const CorrectiveActionSchema = z
  .object({
    type: z.enum(CORRECTIVE_ACTION_TYPES),
    /** Closed vocabulary. Callers branch on this, never on prose. */
    reason: z.string().regex(/^[a-z][a-z0-9_]{2,63}$/),
    /** The agent that can satisfy a REQUEST_DELEGATION. */
    target_agent: z.string().optional(),
    /** A body the caller can submit, assembled from its own request. */
    payload: z.record(z.string(), z.unknown()).optional(),
    /** Fields a human-facing form can render already filled in. */
    prefilled_approval_form: z.record(z.string(), z.unknown()).optional(),
  })
  .strict();

export type CorrectiveAction = z.infer<typeof CorrectiveActionSchema>;

/**
 * Refusals that are answers rather than obstacles. Nothing an agent does next
 * makes these into a yes, so nothing is offered.
 */
const TERMINAL_REASONS = new Set([
  'SANCTIONED_DESTINATION',
  'UNKNOWN_COUNTERPARTY',
  'AGENT_NOT_ACTIVE',
  'APPROVAL_REJECTED',
  'AUTHORITY_REVOKED',
  'AUTHORITY_SUSPENDED',
  'POLICY_DENIED',
  'NO_RULE_MATCHED',
  'APPROVAL_REQUIREMENT_UNSATISFIABLE',
]);

/** Intent failures where the action itself is out of bounds, not the paperwork. */
const TERMINAL_INTENT_REASONS = new Set([
  'action_in_forbidden_list',
  'action_not_in_allowed_list',
  'purpose_mismatch',
]);

export interface CorrectiveContext {
  /** Handle of the agent that issued the delegated authority in play, if any. */
  delegating_agent_handle?: string | null;
  /** Open approval request created for an escalation. */
  approval_request_id?: string | null;
  /** Intent ids the governing policy declares, for a DECLARE_INTENT step. */
  known_intents?: readonly string[];
}

/**
 * The minimal grant that would cover this exact attempt.
 *
 * Every field comes from the caller's own request, so this reveals nothing the
 * caller did not already send. It is deliberately minimal: an agent asking for
 * authority should ask for the authority it needs, not a comfortable margin.
 */
export function minimalGrantFor(evaluation: AuthorizationEvaluation): AuthorityGrant {
  const context = evaluation.evaluation.request_context ?? {};
  const constraints: Record<string, unknown> = {};

  const amount = MoneySchema.safeParse(context['amount']);
  if (amount.success) {
    constraints['max_amount'] = amount.data satisfies Money;
    constraints['currencies'] = [amount.data.currency];
  }
  const counterparty = context['counterparty_id'];
  if (typeof counterparty === 'string') {
    constraints['allowed_counterparties'] = [counterparty];
  }

  return {
    actions: [evaluation.action],
    resources: { [evaluation.resource.type]: [evaluation.resource.id] },
    constraints: constraints as AuthorityGrant['constraints'],
  };
}

export function computeCorrectiveActions(
  evaluation: AuthorizationEvaluation,
  context: CorrectiveContext = {},
): CorrectiveAction[] {
  if (evaluation.decision === 'ALLOW') return [];

  const intent = evaluation.intent_evaluation;
  if (intent && !intent.match) {
    if (TERMINAL_INTENT_REASONS.has(intent.reason)) return [];
    // The remaining intent failures are protocol errors the caller can fix by
    // declaring itself properly. The list of valid intent ids is part of the
    // interface an agent codes against, in the same way scopes are.
    return [
      {
        type: 'DECLARE_INTENT',
        reason: intent.reason === 'unknown_intent' ? 'unknown_intent' : 'intent_not_declared',
        payload: { known_intents: [...(context.known_intents ?? [])].sort() },
      },
    ];
  }

  if (TERMINAL_REASONS.has(evaluation.reason_code)) return [];

  const actions: CorrectiveAction[] = [];

  switch (evaluation.reason_code) {
    case 'AUTHORITY_MISSING':
    case 'ACTION_NOT_IN_AUTHORITY':
    case 'RESOURCE_NOT_IN_AUTHORITY': {
      // A delegated agent asks the agent that delegated to it; anything else
      // asks whoever issues authority in this tenant.
      if (context.delegating_agent_handle) {
        actions.push({
          type: 'REQUEST_DELEGATION',
          reason: 'authority_does_not_cover_action',
          target_agent: context.delegating_agent_handle,
          payload: { grant: minimalGrantFor(evaluation), ttl_seconds: 600 },
        });
      } else {
        actions.push({
          type: 'REQUEST_LEASE',
          reason: 'no_authority_covers_action',
          payload: { agent_id: evaluation.agent_id, grant: minimalGrantFor(evaluation) },
        });
      }
      break;
    }
    case 'AUTHORITY_EXPIRED':
    case 'AUTHORITY_CONSUMED': {
      actions.push({
        type: 'REQUEST_LEASE',
        reason:
          evaluation.reason_code === 'AUTHORITY_CONSUMED'
            ? 'single_use_grant_already_spent'
            : 'authority_lapsed',
        payload: { agent_id: evaluation.agent_id, grant: minimalGrantFor(evaluation) },
      });
      break;
    }
    case 'APPROVAL_EXPIRED':
    case 'SIGNAL_UNAVAILABLE':
    case 'ENFORCEMENT_UNAVAILABLE':
    case 'POLICY_UNAVAILABLE': {
      actions.push({ type: 'REEVALUATE', reason: 'conditions_were_indeterminate' });
      break;
    }
    default:
      break;
  }

  // An escalation is always resolvable by the humans policy named, so the step
  // is offered whatever else went wrong.
  if (evaluation.decision === 'ESCALATE' && evaluation.approval_requirement) {
    actions.push({
      type: 'HUMAN_ESCALATION',
      reason: 'human_authority_required',
      payload: {
        approval_request_id: context.approval_request_id ?? null,
        // Already returned on the decision; repeating it here keeps the
        // handshake self-contained for a caller acting only on this object.
        required_roles: evaluation.approval_requirement.roles,
        quorum: evaluation.approval_requirement.quorum,
        expires_in_seconds: evaluation.approval_requirement.ttl_seconds,
      },
      prefilled_approval_form: {
        agent_id: evaluation.agent_id,
        action: evaluation.action,
        resource: evaluation.resource,
        decision_id: null,
        requested_at: evaluation.decision_timestamp,
      },
    });
  }

  return actions;
}
