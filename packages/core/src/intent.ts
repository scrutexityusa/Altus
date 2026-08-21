import { z } from 'zod';
import { actionMatches, ACTION_PATTERN } from './authority/grant.js';

/**
 * ============================================================================
 * Intent binding.
 * ============================================================================
 *
 * Authority answers "may this agent do this". Intent answers a different
 * question: "is this what the agent said it was here to do?"
 *
 * They come apart precisely where it matters. An agent asked to reconcile a
 * cash position holds read authority and, plausibly, some payment authority
 * left over from a legitimate earlier task. Executing a wire is inside its
 * authority and outside its purpose. A control plane that only checks
 * authority sees nothing wrong; one that binds the declared objective to the
 * attempted action sees a task that has gone somewhere it was not sent.
 *
 * The evaluation is a set comparison over declared lists. It is not an
 * interpretation of what the agent "meant" -- there is no model in this path,
 * and the output is structured data that the explanation compiler renders,
 * never prose that something generated.
 */

export const INTENT_MISMATCH_REASONS = [
  'action_in_forbidden_list',
  'action_not_in_allowed_list',
  'unknown_intent',
  'intent_not_declared',
  'purpose_mismatch',
] as const;

export type IntentMismatchReason = (typeof INTENT_MISMATCH_REASONS)[number];

export const IntentDeclarationSchema = z
  .object({
    id: z.string().regex(/^[a-z][a-z0-9_]{2,63}$/),
    description: z.string().max(500).optional(),
    /** Empty means "any action not forbidden". */
    allowed_actions: z.array(z.string().regex(ACTION_PATTERN)).default([]),
    /** Always wins over allowed_actions. */
    forbidden_actions: z.array(z.string().regex(ACTION_PATTERN)).default([]),
  })
  .strict();

export type IntentDeclaration = z.infer<typeof IntentDeclarationSchema>;

/**
 * The structured verdict. Every field is a fact, and the reason is drawn from
 * a closed vocabulary so a caller can branch on it.
 */
export interface IntentEvaluation {
  declared_intent: string | null;
  attempted_action: string;
  match: boolean;
  reason: IntentMismatchReason | 'matched' | 'not_enforced';
  /** The intent the policy matched the declaration against, when it found one. */
  policy_intent_id: string | null;
  /** Purpose recorded on the authority lease, when it is purpose-bound. */
  lease_purpose: string | null;
}

export interface IntentEvaluationInput {
  action: string;
  /** What the agent said it was doing, from the authorization request. */
  declared_intent: string | null;
  /** Intents the governing policy declares. Empty means intent is not enforced. */
  policy_intents: readonly IntentDeclaration[];
  /** Whether policy requires every request to declare an intent. */
  require_declaration: boolean;
  /** Purpose bound to the authority being relied on, if any. */
  lease_purpose: string | null;
}

export function evaluateIntent(input: IntentEvaluationInput): IntentEvaluation {
  const base = {
    declared_intent: input.declared_intent,
    attempted_action: input.action,
    policy_intent_id: null as string | null,
    lease_purpose: input.lease_purpose,
  };

  // A purpose-bound grant binds regardless of what policy declares: the
  // authority itself was issued for one objective, and using it for another is
  // a mismatch even under a policy that does not enforce intent at all.
  if (input.lease_purpose !== null && input.declared_intent !== input.lease_purpose) {
    return { ...base, match: false, reason: 'purpose_mismatch' };
  }

  if (input.policy_intents.length === 0) {
    return { ...base, match: true, reason: 'not_enforced' };
  }

  if (input.declared_intent === null) {
    return input.require_declaration
      ? { ...base, match: false, reason: 'intent_not_declared' }
      : { ...base, match: true, reason: 'not_enforced' };
  }

  const declaration = input.policy_intents.find((intent) => intent.id === input.declared_intent);
  if (!declaration) {
    return { ...base, match: false, reason: 'unknown_intent' };
  }

  const matched = { ...base, policy_intent_id: declaration.id };

  // Forbidden wins. An action named in both lists is forbidden, because the
  // safe reading of a contradictory policy is the restrictive one.
  if (declaration.forbidden_actions.some((pattern) => actionMatches(pattern, input.action))) {
    return { ...matched, match: false, reason: 'action_in_forbidden_list' };
  }

  if (
    declaration.allowed_actions.length > 0 &&
    !declaration.allowed_actions.some((pattern) => actionMatches(pattern, input.action))
  ) {
    return { ...matched, match: false, reason: 'action_not_in_allowed_list' };
  }

  return { ...matched, match: true, reason: 'matched' };
}

/** Human-readable rendering, assembled from the structured verdict alone. */
export function describeIntentEvaluation(evaluation: IntentEvaluation): string {
  switch (evaluation.reason) {
    case 'matched':
      return `Action "${evaluation.attempted_action}" is within the declared intent "${evaluation.declared_intent}".`;
    case 'not_enforced':
      return 'The governing policy does not bind actions to a declared intent.';
    case 'purpose_mismatch':
      return `The authority relied on was granted for "${evaluation.lease_purpose}", but the request declared "${evaluation.declared_intent ?? 'no intent'}".`;
    case 'intent_not_declared':
      return 'The governing policy requires every request to declare an intent, and this one declared none.';
    case 'unknown_intent':
      return `"${evaluation.declared_intent}" is not an intent the governing policy declares.`;
    case 'action_in_forbidden_list':
      return `Intent "${evaluation.declared_intent}" explicitly forbids "${evaluation.attempted_action}".`;
    case 'action_not_in_allowed_list':
      return `Intent "${evaluation.declared_intent}" does not extend to "${evaluation.attempted_action}".`;
  }
}
