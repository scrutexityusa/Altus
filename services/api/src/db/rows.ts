import type { AuthorityGrant, AuthorityLease } from '@scrutexity/core';

/** Row shapes as they come back from Postgres, and the mappers into domain types. */

export interface LeaseRow {
  id: string;
  organization_id: string;
  agent_id: string;
  policy_version_id: string;
  actions: string[];
  resources: Record<string, string[]>;
  constraints: Record<string, unknown>;
  status: AuthorityLease['status'];
  grant_type: 'REUSABLE' | 'SINGLE_USE';
  purpose: string | null;
  claimed_at: Date | null;
  claimed_by_decision_id: string | null;
  consumed: boolean;
  used_at: Date | null;
  revocable: boolean;
  parent_lease_id: string | null;
  depth: number;
  issued_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  revocation_reason: string | null;
}

export function toLease(row: LeaseRow): AuthorityLease {
  return {
    id: row.id,
    organization_id: row.organization_id,
    agent_id: row.agent_id,
    policy_version_id: row.policy_version_id,
    grant: {
      actions: row.actions,
      resources: row.resources,
      constraints: row.constraints,
    } as AuthorityGrant,
    status: row.status,
    grant_type: row.grant_type,
    purpose: row.purpose,
    claimed_at: row.claimed_at ? row.claimed_at.toISOString() : null,
    claimed_by_decision_id: row.claimed_by_decision_id,
    consumed: row.consumed,
    used_at: row.used_at ? row.used_at.toISOString() : null,
    revocable: row.revocable,
    parent_lease_id: row.parent_lease_id,
    depth: row.depth,
    issued_at: row.issued_at.toISOString(),
    expires_at: row.expires_at.toISOString(),
    revoked_at: row.revoked_at ? row.revoked_at.toISOString() : null,
    revocation_reason: row.revocation_reason,
  };
}

export interface AgentRow {
  id: string;
  organization_id: string;
  handle: string;
  display_name: string;
  description: string | null;
  owner_user_id: string | null;
  status: 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  public_key: string | null;
  metadata: Record<string, unknown>;
  created_at: Date;
}

export interface SignalRow {
  id: string;
  subject_type: 'agent' | 'user' | 'organization' | 'resource' | 'counterparty';
  subject_id: string;
  signal_type: string;
  value: string;
  confidence: string;
  source: string;
  issued_at: Date;
  expires_at: Date;
  metadata: Record<string, unknown>;
}
