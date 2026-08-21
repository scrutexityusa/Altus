import { formatMoneyWithCurrency, MoneySchema } from './money.js';
import type { AuthorizationEvaluation } from './evaluate.js';

/**
 * ============================================================================
 * The deterministic explanation compiler (Sections 20, 21, 41).
 * ============================================================================
 *
 * No language model is involved and none ever should be. An explanation of why
 * a payment was blocked is evidence; it has to be reproducible from the same
 * decision record forever, and it must never invent a fact that is not in the
 * structured record.
 *
 * The compiler keeps the five questions apart rather than blending them into
 * one paragraph, because "what the policy required" and "what authority
 * existed" are different facts with different owners, and collapsing them is
 * how post-incident reviews go wrong.
 */

export interface ExplanationFacts {
  /** WHAT HAPPENED */
  what: string;
  /** WHAT AUTHORITY EXISTED */
  authority: string;
  /** WHAT POLICY REQUIRED */
  policy: string;
  /** WHAT SIGNALS INFLUENCED THE DECISION */
  signals: string;
  /** WHAT APPROVALS WERE INVOLVED */
  approvals: string;
  /** WHY THE FINAL RESULT OCCURRED */
  why: string;
}

export interface ExplanationSection {
  title: string;
  lines: string[];
}

export interface Explanation {
  decision: string;
  reason_code: string;
  headline: string;
  facts: ExplanationFacts;
  sections: ExplanationSection[];
  /** A plain-text rendering assembled from the sections above. */
  text: string;
}

export interface ExplanationLabels {
  agent_handle?: string;
  /** Present when the acting authority was delegated to this agent. */
  delegated_by_handle?: string;
  policy_key?: string;
  resource_label?: string;
}

const HEADLINES: Record<string, string> = {
  ALLOW: 'ALLOWED',
  DENY: 'DENIED',
  ESCALATE: 'HUMAN APPROVAL REQUIRED',
};

function moneyish(value: unknown): string {
  const parsed = MoneySchema.safeParse(value);
  if (parsed.success) return formatMoneyWithCurrency(parsed.data);
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (Array.isArray(value)) return value.map(moneyish).join(', ');
  return JSON.stringify(value ?? null);
}

export function explainDecision(
  evaluation: AuthorizationEvaluation,
  labels: ExplanationLabels = {},
): Explanation {
  const agent = labels.agent_handle ?? evaluation.agent_id;
  const resource = labels.resource_label ?? `${evaluation.resource.type}:${evaluation.resource.id}`;
  const headline = HEADLINES[evaluation.decision] ?? evaluation.decision;
  const outcome = evaluation.evaluation;

  // -- WHAT HAPPENED --------------------------------------------------------
  const what = `Agent ${agent} requested "${evaluation.action}" on ${resource}.`;

  // -- WHAT AUTHORITY EXISTED ----------------------------------------------
  const selected = outcome.authority_findings.find((f) => f.lease_id === outcome.selected_lease_id);
  let authority: string;
  if (!selected) {
    authority = 'No authority lease covering this action was held by the agent.';
  } else {
    const grant = selected.effective_grant ?? { actions: [], resources: {}, constraints: {} };
    const scope = Object.entries(grant.resources)
      .map(([type, ids]) => `${type}: ${ids.join(', ')}`)
      .join('; ');
    const limits = Object.entries(grant.constraints)
      .map(([name, value]) => `${name} = ${moneyish(value)}`)
      .join('; ');
    const chainStatus = selected.chain.blocked_by
      ? ` The chain is not active: lease ${selected.chain.blocked_by.lease_id} is ${selected.chain.blocked_by.status}.`
      : '';
    const via = labels.delegated_by_handle
      ? ` It was delegated by ${labels.delegated_by_handle} at depth ${selected.depth}.`
      : selected.depth > 0
        ? ` It is a delegated authority at depth ${selected.depth}.`
        : '';
    authority =
      `Lease ${selected.lease_id} granted ${grant.actions.join(', ')}` +
      (scope ? ` over ${scope}` : '') +
      (limits ? `, limited by ${limits}` : '') +
      `.${via}${chainStatus}`;
  }

  // -- WHAT POLICY REQUIRED -------------------------------------------------
  const policyOutcome = outcome.policy_outcome;
  let policy: string;
  if (!policyOutcome) {
    policy = 'The governing policy could not be evaluated, so the system default applied.';
  } else {
    const key = labels.policy_key ?? policyOutcome.policy_id;
    const matched = policyOutcome.matched_rule_ids;
    policy =
      matched.length === 0
        ? `Policy ${key} v${policyOutcome.policy_version} matched no rule; its default decision is ${policyOutcome.decision}.`
        : `Policy ${key} v${policyOutcome.policy_version} matched ${matched.length === 1 ? 'rule' : 'rules'} ${matched.join(', ')}, requiring ${policyOutcome.decision}.`;
    if (evaluation.approval_requirement) {
      const requirement = evaluation.approval_requirement;
      const roles = requirement.roles.length > 0 ? ` from ${requirement.roles.join(' and ')}` : '';
      policy += ` Approval by ${requirement.quorum} ${requirement.quorum === 1 ? 'person' : 'people'}${roles} is required.`;
    }
  }

  // -- WHAT SIGNALS INFLUENCED THE DECISION ---------------------------------
  const consulted = outcome.signals_considered.filter((s) => evaluation.risk_signal_ids.includes(s.id));
  const signals =
    consulted.length === 0
      ? 'No risk signal was read by any matched rule.'
      : consulted
          .map(
            (s) =>
              `${s.signal_type} = ${s.value} (confidence ${s.confidence}) reported by ${s.source} for ${s.subject_type} ${s.subject_id}, valid until ${s.expires_at}`,
          )
          .join('. ') + '.';

  // -- WHAT APPROVALS WERE INVOLVED -----------------------------------------
  const approvalState = evaluation.approval_state;
  let approvals: string;
  if (!approvalState) {
    approvals = evaluation.approval_requirement
      ? 'No approval has been recorded yet.'
      : 'No human approval was required.';
  } else {
    const counted = approvalState.counted
      .map((c) => (c.role ? `${c.user_id} as ${c.role}` : c.user_id))
      .join(', ');
    approvals =
      `${approvalState.quorum_met} of ${approvalState.quorum_required} required approvals recorded` +
      (counted ? ` (${counted})` : '') +
      `; status ${approvalState.status}.`;
    if (approvalState.outstanding_roles.length > 0) {
      approvals += ` Still outstanding: ${approvalState.outstanding_roles.join(', ')}.`;
    }
    for (const discounted of approvalState.discounted) {
      approvals += ` Approval from ${discounted.user_id} did not count (${discounted.reason}).`;
    }
  }

  // -- WHY ------------------------------------------------------------------
  const why = buildWhy(evaluation, agent, labels);

  const sections: ExplanationSection[] = [
    { title: 'What happened', lines: [what] },
    { title: 'What authority existed', lines: [authority] },
    { title: 'What policy required', lines: [policy] },
    { title: 'What signals influenced the decision', lines: [signals] },
    { title: 'What approvals were involved', lines: [approvals] },
    { title: 'Why this result', lines: [why] },
  ];

  const text = [
    headline,
    '',
    ...sections.flatMap((section) => [`${section.title}:`, ...section.lines, '']),
    `Decision:   ${evaluation.decision}`,
    `Reason:     ${evaluation.reason_code}`,
    `Policy:     ${evaluation.policy_id ?? 'n/a'} v${evaluation.policy_version ?? 'n/a'} (${evaluation.policy_hash?.slice(0, 12) ?? 'n/a'})`,
    `Authority:  ${evaluation.authority_lease_id ?? 'none'}`,
    `Decided at: ${evaluation.decision_timestamp}`,
  ]
    .join('\n')
    .trimEnd();

  return {
    decision: evaluation.decision,
    reason_code: evaluation.reason_code,
    headline,
    facts: { what, authority, policy, signals, approvals, why },
    sections,
    text,
  };
}

function buildWhy(
  evaluation: AuthorizationEvaluation,
  agent: string,
  labels: ExplanationLabels,
): string {
  const blocked = evaluation.evaluation.autonomy.blocked_by;

  switch (evaluation.reason_code) {
    case 'AGENT_NOT_ACTIVE':
      return `The agent identity is ${evaluation.evaluation.agent_status}, so no request from it can be authorised.`;
    case 'AUTHORITY_MISSING':
      return `${agent} holds no authority covering "${evaluation.action}" on this resource. Execution blocked.`;
    case 'ACTION_NOT_IN_AUTHORITY': {
      const detail = blocked?.kind === 'ENVELOPE' ? ` ${blocked.detail}.` : '';
      const via = labels.delegated_by_handle
        ? ` The authority ${agent} holds was delegated by ${labels.delegated_by_handle} and does not include this action.`
        : '';
      return `Action "${evaluation.action}" is not present in the authority held by ${agent}.${detail}${via} Execution blocked.`;
    }
    case 'RESOURCE_NOT_IN_AUTHORITY':
      return `The resource ${evaluation.resource.type}:${evaluation.resource.id} lies outside the authority held by ${agent}. Execution blocked.`;
    case 'AUTHORITY_EXPIRED':
      return 'The authority relied on has expired. An expired lease never authorises. Execution blocked.';
    case 'AUTHORITY_REVOKED':
      return 'The authority relied on was revoked. Revocation takes effect on the next decision, with no grace period. Execution blocked.';
    case 'AUTHORITY_SUSPENDED':
      return 'The authority relied on is suspended. Execution blocked.';
    case 'AUTHORITY_DECAYED': {
      const rules = blocked?.kind === 'DECAY' ? blocked.rule_ids.join(', ') : '';
      const detail = blocked?.kind === 'DECAY' ? ` ${blocked.detail}.` : '';
      return `A live risk signal triggered ${rules ? `policy rule ${rules}` : 'a policy rule'}, which narrowed the authority ${agent} may exercise without a human.${detail} The action remains within the agent's role, so it was escalated rather than blocked.`;
    }
    case 'CONSTRAINT_VIOLATION': {
      const detail = blocked?.kind === 'CONSTRAINT' || blocked?.kind === 'DECAY' ? ` ${blocked.detail}.` : '';
      return evaluation.decision === 'ESCALATE'
        ? `The request exceeds what ${agent} may do unsupervised.${detail} A human with sufficient authority must approve it.`
        : `The request falls outside the constraints of the authority held by ${agent}.${detail} No approval path is defined for this case, so it was denied.`;
    }
    case 'APPROVAL_REJECTED':
      return 'A required approver rejected this action. A rejection is terminal; the request cannot be re-approved. Execution blocked.';
    case 'APPROVAL_EXPIRED':
      return 'The approval window closed before the requirement was satisfied. Execution blocked.';
    case 'APPROVAL_REQUIREMENT_UNSATISFIABLE':
      return 'Policy escalated this action but named no approver who could resolve it, so it fails closed. Execution blocked.';
    case 'APPROVED_BY_HUMAN':
      return `The approval requirement was satisfied, and the authority held by ${agent} covers the action. Execution authorised until ${evaluation.expires_at}.`;
    case 'POLICY_UNAVAILABLE':
      return `The governing policy could not be read. The failure mode applied was ${evaluation.failover_behavior}.`;
    case 'SIGNAL_UNAVAILABLE':
      return `Risk signals could not be read and policy declares ${evaluation.failover_behavior} for that case.`;
    case 'ENFORCEMENT_UNAVAILABLE':
      return `The enforcement plane is degraded and policy declares ${evaluation.failover_behavior} for that case.`;
    default:
      break;
  }

  if (evaluation.decision === 'ALLOW') {
    return `Policy permitted the action and the authority held by ${agent} covers it in full. Execution authorised until ${evaluation.expires_at}.`;
  }
  if (evaluation.decision === 'ESCALATE') {
    return 'Policy requires a human decision before this action may proceed.';
  }
  return `Policy denied the action (${evaluation.reason_code}). Execution blocked.`;
}
