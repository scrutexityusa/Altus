/**
 * Server-side access to the control plane.
 *
 * The dashboard is a *rendering of the API's own read model*, never a second
 * implementation of it (Section 34). Every number on a screen came from an
 * endpoint an integrator can call, so the UI and the API cannot disagree about
 * what happened.
 *
 * The credential lives on the server and never reaches the browser.
 */

const BASE_URL = process.env.SCRUTEXITY_API_URL ?? 'http://127.0.0.1:8080';
const TOKEN = process.env.SCRUTEXITY_API_TOKEN ?? '';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(path: string): Promise<T> {
  if (!TOKEN) {
    throw new ApiError(
      500,
      'NOT_CONFIGURED',
      'SCRUTEXITY_API_TOKEN is not set. Run `make seed` and export a token from .seed.local.json.',
    );
  }

  const response = await fetch(`${BASE_URL}${path}`, {
    headers: { authorization: `Bearer ${TOKEN}` },
    // Authority state changes without the dashboard being told. Showing a
    // cached view of it would show revoked authority as live.
    cache: 'no-store',
  });

  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new ApiError(
      response.status,
      body?.error?.code ?? 'UNKNOWN',
      body?.error?.message ?? 'request failed',
    );
  }
  return body as T;
}

export interface Agent {
  id: string;
  handle: string;
  display_name: string;
  description: string | null;
  owner_user_id: string | null;
  status: 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  created_at: string;
}

export interface Lease {
  id: string;
  agent_id: string;
  grant: {
    actions: string[];
    resources: Record<string, string[]>;
    constraints: Record<string, unknown>;
  };
  status: string;
  depth: number;
  parent_lease_id: string | null;
  issued_at: string;
  expires_at: string;
  revocation_reason: string | null;
}

export interface Signal {
  id: string;
  subject_type: string;
  subject_id: string;
  signal_type: string;
  value: string;
  confidence: string;
  source: string;
  issued_at: string;
  expires_at: string;
}

export interface DecisionSummary {
  id: string;
  decision: 'ALLOW' | 'DENY' | 'ESCALATE';
  reason_code: string;
  action: string;
  resource_type: string;
  resource_id: string;
  agent_handle: string;
  decided_at: string;
}

export interface PendingApproval {
  id: string;
  requirement: { quorum: number; roles: string[]; ttl_seconds: number };
  reason_code: string;
  action: string;
  resource_type: string;
  resource_id: string;
  context: Record<string, unknown>;
  agent_handle: string;
  expires_at: string;
  created_at: string;
}

export interface Overview {
  agents: Agent[];
  active_leases: Lease[];
  pending_approvals: PendingApproval[];
  recent_decisions: DecisionSummary[];
  live_signals: Signal[];
}

export interface AgentDetail {
  agent: Agent;
  authority_leases: Lease[];
  delegations: Array<{
    id: string;
    issuer_agent_id: string;
    delegate_agent_id: string;
    parent_lease_id: string;
    child_lease_id: string;
    status: string;
    expires_at: string;
  }>;
  risk_signals: Signal[];
  recent_decisions: DecisionSummary[];
}

export interface DecisionDetail {
  decision: {
    id: string;
    decision: 'ALLOW' | 'DENY' | 'ESCALATE';
    reason_code: string;
    policy_id: string | null;
    policy_version: string | null;
    policy_hash: string | null;
    authority_lease_id: string | null;
    risk_signal_ids: string[];
    constraints_evaluated: Array<{
      constraint: string;
      satisfied: boolean;
      applicable: boolean;
      message: string;
    }>;
    approval_requirement: { quorum: number; roles: string[] } | null;
    failover_behavior: string;
    supersedes_decision_id: string | null;
    expires_at: string | null;
    decision_timestamp: string;
    evaluation_duration_us: number | null;
    evaluation: {
      agent_status: string;
      selected_lease_id: string | null;
      autonomy: { autonomous: boolean; blocked_by: Record<string, unknown> | null };
      policy_outcome: {
        matched_rule_ids: string[];
        rule_traces: Array<{ rule_id: string; matched: boolean; decision: string }>;
      } | null;
      signals_considered: Signal[];
    };
  };
  request: {
    id: string;
    action: string;
    resource: { type: string; id: string };
    context: Record<string, unknown>;
    requested_at: string;
  };
  approvals: Array<{
    id: string;
    approver_user_id: string;
    display_name: string;
    vote: string;
    satisfied_role: string | null;
    roles_at_decision: string[];
    comment: string | null;
    created_at: string;
  }>;
  receipt: { id: string; hash: string; seq: number } | null;
  execution: { id: string; status: string; created_at: string } | null;
  explanation: {
    headline: string;
    facts: Record<string, string>;
    sections: Array<{ title: string; lines: string[] }>;
    text: string;
  };
}
