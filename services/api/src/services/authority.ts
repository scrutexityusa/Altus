import {
  GrantSchema,
  ScrutexityError,
  addSeconds,
  authorizeDelegation,
  authorizeIssuance,
  loadPolicyDocument,
  newId,
  normalizeGrant,
  type AuthorityGrant,
} from '@scrutexity/core';
import type { PoolClient } from '../db/pool.js';
import { securityNow } from '../db/security-clock.js';
import { toLease, type LeaseRow } from '../db/rows.js';
import { metrics } from '../metrics.js';
import { appendReceipt, type EvidenceKeys } from './evidence.js';

/** Authority lease issuance, revocation and delegation. */

export interface IssueLeaseInput {
  organizationId: string;
  agentId: string;
  grant: AuthorityGrant;
  ttlSeconds: number;
  issuedByUserId?: string | null;
  revocable?: boolean;
  grantType?: 'REUSABLE' | 'SINGLE_USE';
  purpose?: string | null;
  metadata?: Record<string, unknown>;
  /**
   * The principal asking to issue. Required: issuance is where authority
   * enters the system, and it is the one place with no parent grant to be
   * contained by, so the bound has to come from somewhere else.
   */
  issuer: { type: 'user' | 'agent' | 'service'; id: string };
}

/**
 * The roles the issuing principal holds.
 *
 * Read from the database on every issuance rather than carried on the
 * credential, so revoking someone's role takes effect on their next request
 * instead of whenever their token happens to expire. Issuance is rare and
 * consequential; one extra query is the right trade.
 *
 * A non-user principal holds no organisational role and therefore no issuance
 * ceiling. That is deliberate: a service or an agent minting root authority is
 * exactly the shape this control exists to prevent, and the empty list makes
 * `authorizeIssuance` refuse it by the ordinary path rather than a special
 * case.
 */
async function loadIssuerRoles(
  client: PoolClient,
  issuer: { type: 'user' | 'agent' | 'service'; id: string },
): Promise<string[]> {
  if (issuer.type !== 'user') return [];
  const result = await client.query(
    "SELECT roles FROM scrutexity.users WHERE id = $1 AND status = 'ACTIVE'",
    [issuer.id],
  );
  return (result.rows[0]?.roles as string[] | undefined) ?? [];
}

export async function issueLease(client: PoolClient, keys: EvidenceKeys, input: IssueLeaseInput) {
  const grant = normalizeGrant(GrantSchema.parse(input.grant));

  const agent = await client.query('SELECT id, status FROM scrutexity.agents WHERE id = $1', [
    input.agentId,
  ]);
  if (agent.rowCount === 0) throw new ScrutexityError('NOT_FOUND', 'agent not found');
  if (agent.rows[0]!.status !== 'ACTIVE') {
    throw new ScrutexityError('STATE_CONFLICT', 'authority cannot be issued to a non-active agent');
  }

  const policyVersion = await activePolicyVersion(client, input.organizationId);

  // -- The top of the theorem ----------------------------------------------
  //
  // Every other containment relation has a parent to be checked against. A
  // root lease does not, so without this the whole chain hangs beneath an
  // unbounded root: `leases:write` alone could mint any authority at all.
  const issuerRoles = await loadIssuerRoles(client, input.issuer);
  const issuance = authorizeIssuance(
    { issuer_roles: issuerRoles, grant },
    loadPolicyDocument(policyVersion.content).document,
  );
  if (!issuance.ok) {
    throw new ScrutexityError('DELEGATION_EXCEEDS_PARENT', issuance.message, {
      disclose: true,
      reasonCode: issuance.reason_code,
      // Axes only, matching what the delegation path discloses -- enough for
      // an operator to correct the request, not enough to enumerate the
      // ceiling by probing it.
      details: {
        violations: issuance.violations.map((v) => ({ axis: v.axis, dimension: v.dimension })),
      },
      internal: {
        securityEvent: {
          organizationId: input.organizationId,
          kind: 'ISSUANCE_EXCEEDS_CEILING',
          subjectId: input.issuer.id,
          detail: {
            reason_code: issuance.reason_code,
            issuer_type: input.issuer.type,
            issuer_roles: issuerRoles,
            target_agent_id: input.agentId,
            axes: issuance.violations.map((v) => `${v.axis}:${v.dimension}`),
            policy_version_id: policyVersion.id,
          },
        },
      },
    });
  }

  // Authoritative: the lease's issued_at and expires_at are derived from this,
  // so the row's own lifetime is measured on the same clock that will later
  // judge it.
  const now = await securityNow(client);
  const leaseId = newId('lease');

  const inserted = await client.query(
    `INSERT INTO scrutexity.authority_leases
       (id, organization_id, agent_id, policy_version_id, issued_by_user_id, actions,
        resources, constraints, status, revocable, parent_lease_id, depth,
        issued_at, expires_at, metadata, grant_type, purpose)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'ACTIVE',$9,NULL,0,$10,$11,$12,$13,$14)
     RETURNING *`,
    [
      leaseId,
      input.organizationId,
      input.agentId,
      policyVersion.id,
      input.issuedByUserId ?? null,
      grant.actions,
      JSON.stringify(grant.resources),
      JSON.stringify(grant.constraints),
      input.revocable ?? true,
      now,
      addSeconds(now, input.ttlSeconds),
      JSON.stringify(input.metadata ?? {}),
      input.grantType ?? 'REUSABLE',
      input.purpose ?? null,
    ],
  );

  const lease = toLease(inserted.rows[0] as LeaseRow);
  const receipt = await appendReceipt(client, keys, {
    organizationId: input.organizationId,
    kind: 'LEASE_ISSUED',
    subjectId: input.agentId,
    payload: {
      lease_id: lease.id,
      agent_id: lease.agent_id,
      policy_version_id: lease.policy_version_id,
      grant,
      issued_at: lease.issued_at,
      expires_at: lease.expires_at,
      issued_by_user_id: input.issuedByUserId ?? null,
      depth: 0,
      grant_type: input.grantType ?? 'REUSABLE',
      purpose: input.purpose ?? null,
    },
  });

  metrics.leasesIssued.inc({ depth: '0', grant_type: input.grantType ?? 'REUSABLE' });
  return { lease, receipt_id: receipt.id };
}

export interface RevokeLeaseInput {
  organizationId: string;
  leaseId: string;
  revokedByUserId?: string | null;
  reason: string;
}

/**
 * Revocation is immediate. It flips the stored status inside the transaction,
 * and because the evaluator walks the ancestry of every lease on every
 * decision, descendants stop authorising at the same instant -- there is no
 * cache to invalidate and no cascade job to wait for (Section 40).
 */
export async function revokeLease(client: PoolClient, keys: EvidenceKeys, input: RevokeLeaseInput) {
  const existing = await client.query(
    'SELECT * FROM scrutexity.authority_leases WHERE id = $1 FOR UPDATE',
    [input.leaseId],
  );
  const row = existing.rows[0] as LeaseRow | undefined;
  if (!row) throw new ScrutexityError('NOT_FOUND', 'authority lease not found');
  if (!row.revocable) {
    throw new ScrutexityError('STATE_CONFLICT', 'this authority lease was issued as non-revocable');
  }
  if (row.status === 'REVOKED') {
    // Idempotent by nature: revoking twice is not an error worth failing on.
    return { lease: toLease(row), receipt_id: null, already_revoked: true };
  }

  const updated = await client.query(
    `UPDATE scrutexity.authority_leases
        SET status = 'REVOKED', revoked_at = now(), revoked_by_user_id = $2, revocation_reason = $3
      WHERE id = $1
      RETURNING *`,
    [input.leaseId, input.revokedByUserId ?? null, input.reason],
  );

  const descendants = await client.query(
    `WITH RECURSIVE tree AS (
       SELECT id FROM scrutexity.authority_leases WHERE parent_lease_id = $1
       UNION ALL
       SELECT l.id FROM scrutexity.authority_leases l JOIN tree t ON l.parent_lease_id = t.id
     ) SELECT id FROM tree`,
    [input.leaseId],
  );

  const lease = toLease(updated.rows[0] as LeaseRow);
  const receipt = await appendReceipt(client, keys, {
    organizationId: input.organizationId,
    kind: 'LEASE_REVOKED',
    subjectId: lease.agent_id,
    payload: {
      lease_id: lease.id,
      agent_id: lease.agent_id,
      revoked_at: lease.revoked_at,
      revoked_by_user_id: input.revokedByUserId ?? null,
      reason: input.reason,
      // Recorded for the audit trail; enforcement is by chain walk, not by
      // writing to these rows.
      dependent_lease_ids: descendants.rows.map((r) => r.id as string),
    },
  });

  metrics.leasesRevoked.inc({});
  return { lease, receipt_id: receipt.id, already_revoked: false };
}

export interface CreateDelegationInput {
  organizationId: string;
  issuerAgentId: string;
  delegateAgentHandleOrId: string;
  parentLeaseId: string;
  grant: AuthorityGrant;
  ttlSeconds: number;
}

export async function createDelegation(
  client: PoolClient,
  keys: EvidenceKeys,
  input: CreateDelegationInput,
) {
  const requestedGrant = normalizeGrant(GrantSchema.parse(input.grant));

  const delegate = await client.query(
    'SELECT id, status, handle FROM scrutexity.agents WHERE id = $1 OR handle = $1',
    [input.delegateAgentHandleOrId],
  );
  if (delegate.rowCount === 0) throw new ScrutexityError('NOT_FOUND', 'delegate agent not found');
  const delegateAgent = delegate.rows[0] as { id: string; status: string; handle: string };
  if (delegateAgent.status !== 'ACTIVE') {
    throw new ScrutexityError(
      'STATE_CONFLICT',
      'authority cannot be delegated to a non-active agent',
    );
  }

  // Lock the parent for the duration: a concurrent revocation must not slip
  // between the containment check and the child insert.
  const parentResult = await client.query(
    'SELECT * FROM scrutexity.authority_leases WHERE id = $1 FOR UPDATE',
    [input.parentLeaseId],
  );
  const parentRow = parentResult.rows[0] as LeaseRow | undefined;
  if (!parentRow) throw new ScrutexityError('NOT_FOUND', 'parent authority lease not found');
  const parentLease = toLease(parentRow);

  const chainResult = await client.query(
    `WITH RECURSIVE chain AS (
       SELECT * FROM scrutexity.authority_leases WHERE id = $1
       UNION ALL
       SELECT p.* FROM scrutexity.authority_leases p JOIN chain c ON p.id = c.parent_lease_id
     ) SELECT * FROM chain`,
    [input.parentLeaseId],
  );
  const chain = (chainResult.rows as LeaseRow[]).sort((a, b) => b.depth - a.depth).map(toLease);

  const policyVersion = await activePolicyVersion(client, input.organizationId);
  const { document } = loadPolicyDocument(policyVersion.content);

  const decision = authorizeDelegation(
    {
      issuer_agent_id: input.issuerAgentId,
      delegate_agent_id: delegateAgent.id,
      requested_grant: requestedGrant,
      requested_ttl_seconds: input.ttlSeconds,
    },
    {
      // Delegation containment is a validity decision like any other: the
      // parent chain must be live *now*, on the authoritative clock.
      now: await securityNow(client),
      parent_lease: parentLease,
      parent_chain: chain,
      policy: document,
    },
  );

  if (!decision.ok) {
    metrics.delegationsRejected.inc({ reason: decision.reason_code });
    // The detail here is the caller's own delegation proposal reflected back
    // with the axis that failed, so disclosing it tells them nothing they did
    // not already send -- and it is the difference between a fixable
    // integration and a support ticket.
    throw new ScrutexityError(decision.code, decision.message, {
      reasonCode: decision.reason_code,
      details: { violations: decision.violations },
      disclose: true,
    });
  }

  const childLeaseId = newId('lease');
  const delegationId = newId('delegation');

  const childRow = await client.query(
    `INSERT INTO scrutexity.authority_leases
       (id, organization_id, agent_id, policy_version_id, issued_by_agent_id, actions,
        resources, constraints, status, revocable, parent_lease_id, depth,
        issued_at, expires_at, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'ACTIVE',true,$9,$10,now(),$11,$12)
     RETURNING *`,
    [
      childLeaseId,
      input.organizationId,
      delegateAgent.id,
      parentLease.policy_version_id,
      input.issuerAgentId,
      decision.child_grant.actions,
      JSON.stringify(decision.child_grant.resources),
      JSON.stringify(decision.child_grant.constraints),
      parentLease.id,
      decision.depth,
      decision.expires_at,
      JSON.stringify({ delegation_id: delegationId }),
    ],
  );

  await client.query(
    `INSERT INTO scrutexity.delegations
       (id, organization_id, issuer_agent_id, delegate_agent_id, parent_lease_id,
        child_lease_id, requested_grant, status, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,'ACTIVE',$8)`,
    [
      delegationId,
      input.organizationId,
      input.issuerAgentId,
      delegateAgent.id,
      parentLease.id,
      childLeaseId,
      JSON.stringify(requestedGrant),
      decision.expires_at,
    ],
  );

  const childLease = toLease(childRow.rows[0] as LeaseRow);
  const receipt = await appendReceipt(client, keys, {
    organizationId: input.organizationId,
    kind: 'DELEGATION_CREATED',
    subjectId: delegateAgent.id,
    payload: {
      delegation_id: delegationId,
      issuer_agent_id: input.issuerAgentId,
      delegate_agent_id: delegateAgent.id,
      parent_lease_id: parentLease.id,
      child_lease_id: childLeaseId,
      requested_grant: requestedGrant,
      granted_grant: decision.child_grant,
      depth: decision.depth,
      expires_at: decision.expires_at.toISOString(),
      ttl_clamped_to_parent: decision.ttl_clamped,
      policy_version_id: parentLease.policy_version_id,
    },
  });

  metrics.delegationsCreated.inc({ depth: String(decision.depth) });
  metrics.leasesIssued.inc({ depth: String(decision.depth) });

  return {
    delegation_id: delegationId,
    child_lease: childLease,
    parent_lease_id: parentLease.id,
    ttl_clamped: decision.ttl_clamped,
    receipt_id: receipt.id,
  };
}

async function activePolicyVersion(client: PoolClient, organizationId: string) {
  const result = await client.query(
    `SELECT id, policy_id, content, content_hash FROM scrutexity.policy_versions
      WHERE organization_id = $1 AND status = 'ACTIVE'
      ORDER BY activated_at DESC LIMIT 1`,
    [organizationId],
  );
  const row = result.rows[0] as
    { id: string; policy_id: string; content: unknown; content_hash: string } | undefined;
  if (!row) {
    throw new ScrutexityError(
      'POLICY_UNAVAILABLE',
      'the organization has no active policy version',
    );
  }
  return row;
}
