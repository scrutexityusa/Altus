import { hashObject } from '../canonical.js';
import type { Money } from '../money.js';
import { evaluateCondition, type ConditionTrace, type PolicyValue } from './predicate.js';
import type {
  ApprovalRequirement,
  AuthorityEffect,
  Decision,
  FailoverBehavior,
  PolicyDocument,
  PolicyRule,
} from './schema.js';

/**
 * The Policy Decision Point.
 *
 * Pure: `(document, input) -> outcome`. No I/O, no clock, no randomness. The
 * same document hash and the same input always produce the same outcome, which
 * is what makes `POST /v1/decisions/{id}/replay` meaningful rather than
 * decorative.
 */

export interface SignalView {
  id: string;
  subject_type: 'agent' | 'user' | 'organization' | 'resource' | 'counterparty';
  subject_id: string;
  signal_type: string;
  /** Canonical decimal string. */
  value: string;
  confidence: string;
  source: string;
  issued_at: string;
  expires_at: string;
}

export interface PolicyInput {
  action: string;
  agent: { id: string; handle: string };
  resource: { type: string; id: string; attributes: Record<string, unknown> };
  /** Request context with money already normalised to exact Money records. */
  context: Record<string, unknown>;
  authority: { present: boolean; lease_id: string | null; depth: number | null };
  /** Live (unexpired, unsuperseded) signals visible to this tenant. */
  signals: SignalView[];
}

export interface RuleTrace {
  rule_id: string;
  priority: number;
  matched: boolean;
  decision: Decision;
  reason_code: string;
  condition: ConditionTrace;
}

export interface PolicyOutcome {
  decision: Decision;
  reason_code: string;
  policy_id: string;
  policy_version: string;
  policy_hash: string;
  matched_rule_ids: string[];
  rule_traces: RuleTrace[];
  approval_requirement: ApprovalRequirement | null;
  /** Effects contributed by matched rules, in deterministic rule order. */
  authority_effects: Array<AuthorityEffect & { rule_id: string }>;
  failure_modes: PolicyDocument['failure_modes'];
  execution_grant_ttl_seconds: number;
  /** Ids of the signals the selectors actually read. */
  consulted_signal_ids: string[];
}

const SEVERITY: Record<Decision, number> = { ALLOW: 1, ESCALATE: 2, DENY: 3 };

export function strictest(a: Decision, b: Decision): Decision {
  return SEVERITY[a] >= SEVERITY[b] ? a : b;
}

/** SHA-256 over the canonical policy document. Stable across serialisations. */
export function policyHash(document: PolicyDocument): string {
  return hashObject(document);
}

/**
 * Picks the signal a selector resolves to when several are live for the same
 * subject and type. The most severe live signal wins: a second opinion may
 * raise risk but never silently lower it, and ties break on id so the choice
 * is reproducible.
 */
function selectSignal(candidates: SignalView[]): SignalView | undefined {
  if (candidates.length === 0) return undefined;
  return [...candidates].sort((a, b) => {
    const byValue = Number(b.value) - Number(a.value);
    if (byValue !== 0) return byValue > 0 ? 1 : -1;
    return a.id < b.id ? 1 : -1;
  })[0];
}

function readPath(source: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc === null || typeof acc !== 'object') return undefined;
    return (acc as Record<string, unknown>)[key];
  }, source);
}

function toPolicyValue(value: unknown): PolicyValue {
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isInteger(value) ? String(value) : undefined;
  if (typeof value === 'object') {
    const money = value as Partial<Money>;
    if (typeof money.currency === 'string' && typeof money.amountMinor === 'string') {
      return value as Money;
    }
  }
  return undefined;
}

function buildResolver(input: PolicyInput, consulted: Set<string>) {
  return (selector: string): PolicyValue => {
    if (selector === 'action') return input.action;
    if (selector === 'resource.type') return input.resource.type;
    if (selector === 'resource.id') return input.resource.id;
    if (selector.startsWith('resource.attributes.')) {
      return toPolicyValue(readPath(input.resource.attributes, selector.slice(20)));
    }
    if (selector === 'agent.id') return input.agent.id;
    if (selector === 'agent.handle') return input.agent.handle;
    if (selector.startsWith('context.')) {
      return toPolicyValue(readPath(input.context, selector.slice(8)));
    }
    if (selector === 'authority.present') return input.authority.present;
    if (selector === 'authority.lease_id') return input.authority.lease_id ?? undefined;
    if (selector === 'authority.depth') {
      return input.authority.depth === null ? undefined : String(input.authority.depth);
    }
    if (selector.startsWith('signal.')) {
      const [, signalType, subjectRef, field = 'value'] = selector.split('.');
      if (!signalType || !subjectRef) return undefined;

      const subjectId =
        subjectRef === 'agent'
          ? input.agent.id
          : subjectRef === 'resource'
            ? input.resource.id
            : subjectRef === 'counterparty'
              ? (input.context['counterparty_id'] as string | undefined)
              : undefined; // organization signals match on subject_type alone

      const candidates = input.signals.filter(
        (s) =>
          s.signal_type === signalType &&
          s.subject_type === subjectRef &&
          (subjectRef === 'organization' || (subjectId !== undefined && s.subject_id === subjectId)),
      );
      const chosen = selectSignal(candidates);
      if (!chosen) return undefined;
      consulted.add(chosen.id);
      return field === 'confidence' ? chosen.confidence : chosen.value;
    }
    return undefined;
  };
}

/** Deterministic rule order: priority, then declaration index. */
function orderedRules(document: PolicyDocument): PolicyRule[] {
  return document.rules
    .map((rule, index) => ({ rule, index }))
    .sort((a, b) => a.rule.priority - b.rule.priority || a.index - b.index)
    .map((entry) => entry.rule);
}

/**
 * Merges the approval requirements of every matched escalating rule. Merging
 * is always in the more-demanding direction: the strictest quorum, the union
 * of required roles, the shortest window. Two rules that each demand a human
 * cannot cancel out into demanding none.
 */
export function mergeApprovalRequirements(
  requirements: readonly ApprovalRequirement[],
): ApprovalRequirement | null {
  const active = requirements.filter((r) => r.required);
  if (active.length === 0) return null;
  const roles = new Set<string>();
  for (const requirement of active) for (const role of requirement.roles) roles.add(role);
  return {
    required: true,
    quorum: Math.max(...active.map((r) => r.quorum), roles.size === 0 ? 1 : roles.size),
    roles: [...roles].sort(),
    forbid_self_approval: active.some((r) => r.forbid_self_approval),
    ttl_seconds: Math.min(...active.map((r) => r.ttl_seconds)),
  };
}

export function evaluatePolicy(document: PolicyDocument, input: PolicyInput): PolicyOutcome {
  const consulted = new Set<string>();
  const resolve = buildResolver(input, consulted);
  const traces: RuleTrace[] = [];
  const matched: PolicyRule[] = [];

  // Every rule is evaluated, always. First-match-wins would make the outcome
  // depend on authoring order and would hide the layered thresholds
  // (>=50k and >=1M both apply to a $2M wire) that the evidence record needs.
  for (const rule of orderedRules(document)) {
    const condition = evaluateCondition(rule.when, resolve);
    traces.push({
      rule_id: rule.id,
      priority: rule.priority,
      matched: condition.matched,
      decision: rule.then.decision,
      reason_code: rule.then.reason_code ?? defaultReasonCode(rule.then.decision),
      condition,
    });
    if (condition.matched) matched.push(rule);
  }

  let decision: Decision = document.defaults.decision;
  let reasonCode = document.defaults.reason_code;

  if (matched.length > 0) {
    decision = matched.reduce<Decision>((acc, rule) => strictest(acc, rule.then.decision), 'ALLOW');
    // The reason belongs to the strictest matched rule, and among equals to
    // the *last* one in evaluation order. Later rules carry higher priority
    // numbers and are therefore the more specific ones, so a $2M wire is
    // reported as needing treasurer + CFO rather than as merely over $50k.
    const decisive = [...matched].reverse().find((rule) => rule.then.decision === decision)!;
    reasonCode = decisive.then.reason_code ?? defaultReasonCode(decision);
  }

  const approvalRequirement = mergeApprovalRequirements(
    matched
      .filter((rule) => rule.then.decision === 'ESCALATE')
      .map((rule) => rule.then.approval)
      .filter((r): r is ApprovalRequirement => r !== undefined),
  );

  const authorityEffects = matched
    .filter((rule) => rule.then.authority_effect !== undefined)
    .map((rule) => ({ ...rule.then.authority_effect!, rule_id: rule.id }));

  const failureModes = mergeFailureModes(document, matched);

  return {
    decision,
    reason_code: reasonCode,
    policy_id: document.id,
    policy_version: document.version,
    policy_hash: policyHash(document),
    matched_rule_ids: matched.map((rule) => rule.id),
    rule_traces: traces,
    approval_requirement: approvalRequirement,
    authority_effects: authorityEffects,
    failure_modes: failureModes,
    execution_grant_ttl_seconds: document.defaults.execution_grant_ttl_seconds,
    consulted_signal_ids: [...consulted].sort(),
  };
}

const FAILOVER_SEVERITY: Record<FailoverBehavior, number> = {
  FAIL_OPEN: 1,
  ESCALATE: 2,
  FAIL_CLOSED: 3,
};

/** A rule-level failure mode may only tighten the document-level default. */
function mergeFailureModes(
  document: PolicyDocument,
  matched: readonly PolicyRule[],
): PolicyDocument['failure_modes'] {
  const overrides = matched
    .map((rule) => rule.then.failure_mode)
    .filter((mode): mode is FailoverBehavior => mode !== undefined);
  if (overrides.length === 0) return document.failure_modes;
  const strictestOverride = overrides.reduce((acc, mode) =>
    FAILOVER_SEVERITY[mode] > FAILOVER_SEVERITY[acc] ? mode : acc,
  );
  const tighten = (base: FailoverBehavior): FailoverBehavior =>
    FAILOVER_SEVERITY[strictestOverride] > FAILOVER_SEVERITY[base] ? strictestOverride : base;
  return {
    policy_unavailable: tighten(document.failure_modes.policy_unavailable),
    signal_unavailable: tighten(document.failure_modes.signal_unavailable),
    enforcement_unavailable: tighten(document.failure_modes.enforcement_unavailable),
  };
}

function defaultReasonCode(decision: Decision): string {
  return decision === 'ALLOW'
    ? 'POLICY_ALLOWED'
    : decision === 'DENY'
      ? 'POLICY_DENIED'
      : 'APPROVAL_REQUIRED';
}
