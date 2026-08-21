import { lookupAction } from './actions.js';
import {
  coversAttempt,
  normalizeGrant,
  restrictGrant,
  type AttemptDescriptor,
  type AuthorityGrant,
  type ConstraintCheck,
  type CoverageResult,
} from './authority/grant.js';
import {
  evaluateChain,
  type AuthorityLease,
  type ChainEvaluation,
  type LeaseStatus,
} from './authority/lease.js';
import { evaluateApprovals, type Approval, type ApprovalEvaluation } from './approval.js';
import {
  evaluatePolicy,
  strictest,
  type PolicyInput,
  type PolicyOutcome,
  type SignalView,
} from './policy/engine.js';
import type {
  ApprovalRequirement,
  Decision,
  FailoverBehavior,
  PolicyDocument,
} from './policy/schema.js';
import { addSeconds, toIso } from './time.js';

/**
 * ============================================================================
 * The authorization evaluator.
 * ============================================================================
 *
 * Pure and total: it receives a snapshot of every fact the decision depends on
 * and returns the decision plus the reasoning that produced it. Nothing here
 * reads a clock, a database or a network. Replaying an archived snapshot must
 * reproduce the archived decision byte for byte, and that only holds if the
 * function has no hidden inputs.
 *
 * ---------------------------------------------------------------------------
 * The escalation boundary
 * ---------------------------------------------------------------------------
 * Authority has two layers, and they behave differently when they fail:
 *
 *   actions x resources  -- the ENVELOPE. What this agent is for. A failure
 *                           here is terminal: DENY. No approval bridges it,
 *                           because approving would silently redefine the
 *                           agent's role rather than authorise one action.
 *
 *   constraints          -- the AUTONOMY limit. How much of the envelope the
 *                           agent may exercise unsupervised. A failure here is
 *                           what escalation exists for: a human with their own
 *                           authority may supply what the agent lacks, but
 *                           only when policy explicitly names an approval
 *                           requirement. If it does not, the answer is DENY.
 *
 * Authority decay (a risk signal shrinking a live grant) narrows the autonomy
 * layer, never the envelope. That is what makes Scene 7 of the treasury demo
 * read the way it should: after fraud_risk spikes, a wire the agent could do
 * alone yesterday still falls inside its role -- it just needs a human today.
 */

export interface EvaluationRequest {
  id: string;
  organization_id: string;
  agent_id: string;
  action: string;
  resource: { type: string; id: string; attributes: Record<string, unknown> };
  /** Money values already normalised to exact Money records. */
  context: Record<string, unknown>;
  presented_lease_id: string | null;
}

export interface EvaluationAgent {
  id: string;
  handle: string;
  status: 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  owner_user_id: string | null;
}

export interface LeaseCandidate {
  lease: AuthorityLease;
  /** Leaf-first ancestry: [lease, parent, ..., root]. */
  chain: AuthorityLease[];
}

export interface PriorApprovalState {
  approval_request_id: string;
  requirement: ApprovalRequirement;
  approvals: Approval[];
  expires_at: string;
}

export interface DependencyHealth {
  policy_available: boolean;
  signals_available: boolean;
  enforcement_available: boolean;
}

export interface EvaluationSnapshot {
  now: Date;
  request: EvaluationRequest;
  agent: EvaluationAgent;
  policy: {
    policy_id: string;
    policy_version_id: string;
    document: PolicyDocument;
  } | null;
  candidates: LeaseCandidate[];
  signals: SignalView[];
  prior_approval: PriorApprovalState | null;
  dependencies: DependencyHealth;
}

export interface AuthorityFinding {
  lease_id: string;
  depth: number;
  chain: ChainEvaluation;
  usable: boolean;
  envelope_covered: boolean;
  autonomous: boolean;
  base_coverage: CoverageResult;
  effective_coverage: CoverageResult | null;
  effective_grant: AuthorityGrant | null;
}

export interface AuthorizationEvaluation {
  decision: Decision;
  reason_code: string;
  authorization_request_id: string;
  agent_id: string;
  action: string;
  resource: { type: string; id: string };
  policy_id: string | null;
  policy_version_id: string | null;
  policy_version: string | null;
  policy_hash: string | null;
  authority_lease_id: string | null;
  risk_signal_ids: string[];
  constraints_evaluated: ConstraintCheck[];
  approval_requirement: ApprovalRequirement | null;
  approval_state: ApprovalEvaluation | null;
  failover_behavior: FailoverBehavior;
  decision_timestamp: string;
  /** Expiry of the execution grant an ALLOW confers. */
  expires_at: string | null;
  /** Everything needed to replay and to explain, without re-querying. */
  evaluation: {
    agent_status: EvaluationAgent['status'];
    policy_outcome: PolicyOutcome | null;
    authority_findings: AuthorityFinding[];
    selected_lease_id: string | null;
    autonomy: {
      autonomous: boolean;
      blocked_by:
        | { kind: 'NO_LEASE' }
        | { kind: 'LEASE_NOT_USABLE'; status: LeaseStatus; lease_id: string }
        | { kind: 'ENVELOPE'; detail: string }
        | { kind: 'CONSTRAINT'; constraint: string; detail: string }
        | { kind: 'DECAY'; constraint: string; detail: string; rule_ids: string[] }
        | null;
    };
    authority_effects_applied: Array<{ rule_id: string; duration_seconds: number | null }>;
    dependency_health: DependencyHealth;
    signals_considered: Array<
      Pick<
        SignalView,
        | 'id'
        | 'signal_type'
        | 'subject_type'
        | 'subject_id'
        | 'value'
        | 'confidence'
        | 'source'
        | 'expires_at'
      >
    >;
  };
}

const DEFAULT_GRANT_TTL_SECONDS = 300;

/** Applied when the policy itself could not be read, so no policy-defined mode exists. */
const SYSTEM_FALLBACK_FAILOVER: FailoverBehavior = 'FAIL_CLOSED';

export function evaluateAuthorization(snapshot: EvaluationSnapshot): AuthorizationEvaluation {
  const { now, request, agent } = snapshot;
  const timestamp = toIso(now);

  const base = {
    authorization_request_id: request.id,
    agent_id: agent.id,
    action: request.action,
    resource: { type: request.resource.type, id: request.resource.id },
    decision_timestamp: timestamp,
    risk_signal_ids: [] as string[],
    constraints_evaluated: [] as ConstraintCheck[],
    approval_requirement: null,
    approval_state: null,
    expires_at: null,
  };

  const signalsConsidered = snapshot.signals.map((s) => ({
    id: s.id,
    signal_type: s.signal_type,
    subject_type: s.subject_type,
    subject_id: s.subject_id,
    value: s.value,
    confidence: s.confidence,
    source: s.source,
    expires_at: s.expires_at,
  }));

  // -- 0. The control plane's own health ------------------------------------
  // Failure behaviour is policy data, but when the policy is what failed there
  // is nothing to read it from, so the system default applies and is recorded.
  if (!snapshot.policy || !snapshot.dependencies.policy_available) {
    return {
      ...base,
      decision: failoverDecision(SYSTEM_FALLBACK_FAILOVER),
      reason_code: 'POLICY_UNAVAILABLE',
      policy_id: snapshot.policy?.policy_id ?? null,
      policy_version_id: snapshot.policy?.policy_version_id ?? null,
      policy_version: null,
      policy_hash: null,
      authority_lease_id: null,
      failover_behavior: SYSTEM_FALLBACK_FAILOVER,
      evaluation: {
        agent_status: agent.status,
        policy_outcome: null,
        authority_findings: [],
        selected_lease_id: null,
        autonomy: { autonomous: false, blocked_by: null },
        authority_effects_applied: [],
        dependency_health: snapshot.dependencies,
        signals_considered: signalsConsidered,
      },
    };
  }

  const document = snapshot.policy.document;

  // -- 1. Policy evaluation --------------------------------------------------
  const policyInput: PolicyInput = {
    action: request.action,
    agent: { id: agent.id, handle: agent.handle },
    resource: request.resource,
    context: request.context,
    authority: {
      present: snapshot.candidates.length > 0,
      lease_id: request.presented_lease_id,
      depth: null,
    },
    signals: snapshot.dependencies.signals_available ? snapshot.signals : [],
  };
  const policyOutcome = evaluatePolicy(document, policyInput);

  const signalFailover = document.failure_modes.signal_unavailable;
  const enforcementFailover = document.failure_modes.enforcement_unavailable;

  // -- 2. Authority ----------------------------------------------------------
  const actionDefinition = lookupAction(request.action);
  const attempt: AttemptDescriptor = {
    action: request.action,
    resourceType: request.resource.type,
    resourceId: request.resource.id,
    context: request.context,
    // An action outside the catalog binds every dimension: unrecognised means
    // maximally constrained, never unconstrained.
    ...(actionDefinition ? { contextFields: actionDefinition.context_fields } : {}),
  };

  const restriction = {
    remove_actions: policyOutcome.authority_effects.flatMap((e) => e.remove_actions ?? []),
    tighten: policyOutcome.authority_effects.reduce<Record<string, unknown>>(
      (acc, effect) => ({ ...acc, ...(effect.tighten ?? {}) }),
      {},
    ),
  } as Parameters<typeof restrictGrant>[1];
  const hasEffects = policyOutcome.authority_effects.length > 0;

  const findings: AuthorityFinding[] = snapshot.candidates.map((candidate) => {
    const chain = evaluateChain(candidate.chain, now);
    const baseCoverage = coversAttempt(candidate.lease.grant, attempt);
    const envelopeCovered = baseCoverage.action_covered && baseCoverage.resource_covered;
    const effectiveGrant = hasEffects
      ? restrictGrant(candidate.lease.grant, restriction)
      : candidate.lease.grant;
    const effectiveCoverage = coversAttempt(effectiveGrant, attempt);
    return {
      lease_id: candidate.lease.id,
      depth: candidate.lease.depth,
      chain,
      usable: chain.usable,
      envelope_covered: envelopeCovered,
      autonomous: chain.usable && envelopeCovered && effectiveCoverage.covered,
      base_coverage: baseCoverage,
      effective_coverage: effectiveCoverage,
      effective_grant: normalizeGrant(effectiveGrant),
    };
  });

  const selected = selectLease(findings, request.presented_lease_id);
  const autonomy = describeAutonomy(findings, selected, policyOutcome);

  // -- 3. Combine ------------------------------------------------------------
  //
  //   envelope failure  -> DENY, terminal.
  //   autonomy failure  -> ESCALATE if policy names an approver, else DENY.
  //   otherwise         -> whatever policy said.
  //
  let decision: Decision = policyOutcome.decision;
  let reasonCode = policyOutcome.reason_code;
  let approvalRequirement = policyOutcome.approval_requirement;

  const envelopeOk = selected !== null && selected.usable && selected.envelope_covered;

  if (agent.status !== 'ACTIVE') {
    decision = 'DENY';
    reasonCode = 'AGENT_NOT_ACTIVE';
    approvalRequirement = null;
  } else if (policyOutcome.decision === 'DENY') {
    decision = 'DENY';
    approvalRequirement = null;
  } else if (!envelopeOk) {
    decision = 'DENY';
    reasonCode = envelopeReasonCode(findings, selected);
    approvalRequirement = null;
  } else if (!selected.autonomous) {
    if (approvalRequirement) {
      decision = strictest(decision, 'ESCALATE');
      reasonCode =
        autonomy.blocked_by?.kind === 'DECAY'
          ? 'AUTHORITY_DECAYED'
          : policyOutcome.decision === 'ESCALATE'
            ? policyOutcome.reason_code
            : 'CONSTRAINT_VIOLATION';
    } else {
      // Policy was content, but the held authority is not, and nobody is
      // named who could supply the difference. Fail closed.
      decision = 'DENY';
      reasonCode = 'CONSTRAINT_VIOLATION';
    }
  }

  // -- 4. Prior approval -----------------------------------------------------
  let approvalState: ApprovalEvaluation | null = null;
  const approvalIds: string[] = [];
  if (decision === 'ESCALATE' && snapshot.prior_approval && approvalRequirement) {
    approvalState = evaluateApprovals(
      snapshot.prior_approval.requirement,
      snapshot.prior_approval.approvals,
      {
        requesting_agent_owner_user_id: agent.owner_user_id,
        expires_at: snapshot.prior_approval.expires_at,
      },
      now,
    );
    approvalIds.push(...approvalState.counted.map((c) => c.approval_id));
    if (approvalState.status === 'SATISFIED') {
      decision = 'ALLOW';
      reasonCode = 'APPROVED_BY_HUMAN';
    } else if (approvalState.status === 'REJECTED') {
      decision = 'DENY';
      reasonCode = 'APPROVAL_REJECTED';
    } else if (approvalState.status === 'EXPIRED') {
      decision = 'DENY';
      reasonCode = 'APPROVAL_EXPIRED';
    }
  }

  // -- 5. Degraded dependencies ---------------------------------------------
  let failover: FailoverBehavior = 'FAIL_CLOSED';
  if (!snapshot.dependencies.signals_available) {
    failover = signalFailover;
    const degraded = failoverDecision(signalFailover);
    if (degraded !== 'ALLOW') {
      decision = strictest(decision, degraded);
      if (decision === degraded) reasonCode = 'SIGNAL_UNAVAILABLE';
    }
  } else if (!snapshot.dependencies.enforcement_available) {
    failover = enforcementFailover;
    const degraded = failoverDecision(enforcementFailover);
    if (degraded !== 'ALLOW') {
      decision = strictest(decision, degraded);
      if (decision === degraded) reasonCode = 'ENFORCEMENT_UNAVAILABLE';
    }
  } else {
    failover = document.failure_modes.enforcement_unavailable;
  }

  if (decision === 'ESCALATE' && !approvalRequirement) {
    // An escalation nobody can resolve is a denial in disguise. Say so.
    decision = 'DENY';
    reasonCode = 'APPROVAL_REQUIREMENT_UNSATISFIABLE';
  }

  const ttl = policyOutcome.execution_grant_ttl_seconds || DEFAULT_GRANT_TTL_SECONDS;

  return {
    ...base,
    decision,
    reason_code: reasonCode,
    policy_id: snapshot.policy.policy_id,
    policy_version_id: snapshot.policy.policy_version_id,
    policy_version: policyOutcome.policy_version,
    policy_hash: policyOutcome.policy_hash,
    authority_lease_id: selected?.lease_id ?? null,
    risk_signal_ids: policyOutcome.consulted_signal_ids,
    constraints_evaluated:
      selected?.effective_coverage?.constraint_checks ??
      selected?.base_coverage.constraint_checks ??
      [],
    approval_requirement: approvalRequirement,
    approval_state: approvalState,
    failover_behavior: failover,
    expires_at: decision === 'ALLOW' ? toIso(addSeconds(now, ttl)) : null,
    evaluation: {
      agent_status: agent.status,
      policy_outcome: policyOutcome,
      authority_findings: findings,
      selected_lease_id: selected?.lease_id ?? null,
      autonomy,
      authority_effects_applied: policyOutcome.authority_effects.map((effect) => ({
        rule_id: effect.rule_id,
        duration_seconds: effect.duration_seconds ?? null,
      })),
      dependency_health: snapshot.dependencies,
      signals_considered: signalsConsidered,
    },
  };
}

function failoverDecision(behavior: FailoverBehavior): Decision {
  return behavior === 'FAIL_OPEN' ? 'ALLOW' : behavior === 'ESCALATE' ? 'ESCALATE' : 'DENY';
}

/**
 * Deterministic lease selection. An explicitly presented lease wins if it is a
 * candidate at all; otherwise autonomy first, then envelope coverage, then
 * usability, then the youngest lease -- ids are time-sortable, so "youngest"
 * is a total order rather than a coin flip.
 */
function selectLease(
  findings: AuthorityFinding[],
  presentedLeaseId: string | null,
): AuthorityFinding | null {
  if (findings.length === 0) return null;
  if (presentedLeaseId) {
    const presented = findings.find((f) => f.lease_id === presentedLeaseId);
    if (presented) return presented;
  }
  const rank = (f: AuthorityFinding) =>
    (f.autonomous ? 8 : 0) +
    (f.usable && f.envelope_covered ? 4 : 0) +
    (f.envelope_covered ? 2 : 0) +
    (f.usable ? 1 : 0);
  return [...findings].sort((a, b) => rank(b) - rank(a) || (a.lease_id < b.lease_id ? 1 : -1))[0]!;
}

function envelopeReasonCode(
  findings: AuthorityFinding[],
  selected: AuthorityFinding | null,
): string {
  if (!selected) return 'AUTHORITY_MISSING';
  if (!selected.usable) {
    const status = selected.chain.blocked_by?.status;
    return status === 'REVOKED'
      ? 'AUTHORITY_REVOKED'
      : status === 'SUSPENDED'
        ? 'AUTHORITY_SUSPENDED'
        : status === 'EXPIRED'
          ? 'AUTHORITY_EXPIRED'
          : 'AUTHORITY_MISSING';
  }
  const failure = selected.base_coverage.failure;
  if (failure?.kind === 'RESOURCE_NOT_GRANTED') return 'RESOURCE_NOT_IN_AUTHORITY';
  if (failure?.kind === 'ACTION_NOT_GRANTED') return 'ACTION_NOT_IN_AUTHORITY';
  return 'AUTHORITY_MISSING';
}

function describeAutonomy(
  findings: AuthorityFinding[],
  selected: AuthorityFinding | null,
  policyOutcome: PolicyOutcome,
): AuthorizationEvaluation['evaluation']['autonomy'] {
  if (findings.length === 0 || !selected) {
    return { autonomous: false, blocked_by: { kind: 'NO_LEASE' } };
  }
  if (selected.autonomous) return { autonomous: true, blocked_by: null };
  if (!selected.usable) {
    return {
      autonomous: false,
      blocked_by: {
        kind: 'LEASE_NOT_USABLE',
        status: selected.chain.blocked_by?.status ?? 'EXPIRED',
        lease_id: selected.chain.blocked_by?.lease_id ?? selected.lease_id,
      },
    };
  }
  if (!selected.envelope_covered) {
    return {
      autonomous: false,
      blocked_by: {
        kind: 'ENVELOPE',
        detail: selected.base_coverage.failure?.detail ?? 'outside the authority envelope',
      },
    };
  }
  const effectiveFailure = selected.effective_coverage?.failure;
  const baseFailure = selected.base_coverage.failure;

  // The base grant was fine and only the decayed grant is not: the signal did
  // this, and the explanation must name the rules responsible.
  if (effectiveFailure && !baseFailure && policyOutcome.authority_effects.length > 0) {
    return {
      autonomous: false,
      blocked_by: {
        kind: 'DECAY',
        constraint:
          effectiveFailure.kind === 'CONSTRAINT_VIOLATION'
            ? effectiveFailure.constraint
            : 'actions',
        detail: effectiveFailure.detail,
        rule_ids: policyOutcome.authority_effects.map((e) => e.rule_id),
      },
    };
  }
  const failure = baseFailure ?? effectiveFailure;
  return {
    autonomous: false,
    blocked_by: {
      kind: 'CONSTRAINT',
      constraint: failure?.kind === 'CONSTRAINT_VIOLATION' ? failure.constraint : 'unknown',
      detail: failure?.detail ?? 'outside the constraints of the held authority',
    },
  };
}
