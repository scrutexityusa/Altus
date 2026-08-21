import { z } from 'zod';
import { GrantSchema, type AuthorityGrant } from './grant.js';
import { isExpired } from '../time.js';

export const LEASE_STATUSES = ['PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED', 'SUSPENDED'] as const;
export type LeaseStatus = (typeof LEASE_STATUSES)[number];

export const AuthorityLeaseSchema = z.object({
  id: z.string(),
  organization_id: z.string(),
  agent_id: z.string(),
  policy_version_id: z.string(),
  grant: GrantSchema,
  status: z.enum(LEASE_STATUSES),
  revocable: z.boolean(),
  parent_lease_id: z.string().nullable(),
  depth: z.number().int().min(0),
  issued_at: z.string(),
  expires_at: z.string(),
  revoked_at: z.string().nullable(),
  revocation_reason: z.string().nullable(),
});

export type AuthorityLease = z.infer<typeof AuthorityLeaseSchema>;

/**
 * Stored status is what an operator set; effective status is what the
 * evaluator must act on. Expiry is derived from server-authoritative time on
 * every read rather than trusted from a background sweep -- a lapsed lease
 * must stop authorising the instant it lapses, not when a cron job notices.
 */
export function effectiveLeaseStatus(lease: AuthorityLease, now: Date): LeaseStatus {
  if (lease.status === 'REVOKED') return 'REVOKED';
  if (lease.status === 'SUSPENDED') return 'SUSPENDED';
  if (isExpired(lease.expires_at, now)) return 'EXPIRED';
  if (lease.status === 'PENDING') return 'PENDING';
  return 'ACTIVE';
}

export function isLeaseUsable(lease: AuthorityLease, now: Date): boolean {
  return effectiveLeaseStatus(lease, now) === 'ACTIVE';
}

export interface ChainFinding {
  lease_id: string;
  depth: number;
  status: LeaseStatus;
  usable: boolean;
}

export interface ChainEvaluation {
  usable: boolean;
  findings: ChainFinding[];
  /** The ancestor that broke the chain, if any. */
  blocked_by?: ChainFinding;
}

/**
 * A delegated lease is only as alive as its weakest ancestor. Revoking a
 * parent must kill every descendant immediately, without a cascade job and
 * without the descendant's own row changing, so the chain is walked on every
 * evaluation.
 *
 * `chain` is ordered leaf-first: [child, parent, ..., root].
 */
export function evaluateChain(chain: readonly AuthorityLease[], now: Date): ChainEvaluation {
  const findings: ChainFinding[] = chain.map((lease) => {
    const status = effectiveLeaseStatus(lease, now);
    return { lease_id: lease.id, depth: lease.depth, status, usable: status === 'ACTIVE' };
  });
  const broken = findings.find((f) => !f.usable);
  return {
    usable: broken === undefined,
    findings,
    ...(broken ? { blocked_by: broken } : {}),
  };
}

/**
 * A child lease may never outlive its parent. Returns the latest expiry a
 * delegation may be granted.
 */
export function clampExpiry(requested: Date, parentExpiry: Date): Date {
  return requested.getTime() <= parentExpiry.getTime() ? requested : parentExpiry;
}

export function leaseGrant(lease: AuthorityLease): AuthorityGrant {
  return lease.grant;
}
