import { z } from 'zod';
import { GrantSchema, type AuthorityGrant } from './grant.js';
import { isExpired } from '../time.js';

/** Operator-set state, as stored. */
export const LEASE_STATUSES = ['PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED', 'SUSPENDED'] as const;
export type StoredLeaseStatus = (typeof LEASE_STATUSES)[number];

/**
 * What the evaluator acts on. CONSUMED is derived, never stored: a spent
 * single-use grant still has status ACTIVE and an unexpired lifetime, and it
 * is precisely the derivation that stops it authorising a second time.
 */
export type LeaseStatus = StoredLeaseStatus | 'CONSUMED';

export const GRANT_TYPES = ['REUSABLE', 'SINGLE_USE'] as const;
export type GrantType = (typeof GRANT_TYPES)[number];

/**
 * The single-use grant state machine.
 *
 *   CREATED --claim--> CLAIMED --execute--> USED
 *      |                  |
 *      +------------------+--expire--> EXPIRED
 *
 * A claim binds the grant to exactly one authorization decision. A grant that
 * was claimed but never executed stays spent: releasing it on expiry would
 * mean an agent could retry indefinitely by letting each grant lapse, which is
 * the opposite of what "single use" promises. Re-authorising requires a new
 * grant, which is a decision someone makes deliberately.
 */
export const GRANT_STATES = ['CREATED', 'CLAIMED', 'USED', 'EXPIRED'] as const;
export type GrantState = (typeof GRANT_STATES)[number];

export const AuthorityLeaseSchema = z.object({
  id: z.string(),
  organization_id: z.string(),
  agent_id: z.string(),
  policy_version_id: z.string(),
  grant: GrantSchema,
  status: z.enum(LEASE_STATUSES),
  grant_type: z.enum(GRANT_TYPES).default('REUSABLE'),
  /** Declared objective this authority was granted for, if it is purpose-bound. */
  purpose: z.string().nullable().default(null),
  claimed_at: z.string().nullable().default(null),
  claimed_by_decision_id: z.string().nullable().default(null),
  consumed: z.boolean().default(false),
  used_at: z.string().nullable().default(null),
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
  // Consumption is checked before expiry so a spent grant reports why it is
  // unusable rather than blaming the clock. Both are terminal; only one is
  // the truth.
  //
  // A *claimed* single-use grant counts as spent too. The claim binds it to
  // one authorization decision, and every later request is a different one --
  // so treating "claimed" as still-available would let an agent spend one
  // grant twice by never executing the first. Exactly-once has to mean the
  // claim, not the execution, because the claim is what the database can
  // serialise.
  if (lease.consumed) return 'CONSUMED';
  if (lease.grant_type === 'SINGLE_USE' && lease.claimed_at !== null) return 'CONSUMED';
  if (isExpired(lease.expires_at, now)) return 'EXPIRED';
  if (lease.status === 'PENDING') return 'PENDING';
  return 'ACTIVE';
}

/** Where a grant sits in its state machine. Reusable leases are always CREATED. */
export function grantState(lease: AuthorityLease, now: Date): GrantState {
  if (lease.grant_type === 'REUSABLE') return 'CREATED';
  if (lease.consumed) return 'USED';
  if (isExpired(lease.expires_at, now)) return 'EXPIRED';
  return lease.claimed_at !== null ? 'CLAIMED' : 'CREATED';
}

/**
 * May this grant be claimed for `decisionId`?
 *
 * Re-claiming by the same decision is allowed so a retried evaluation of one
 * request is idempotent rather than self-blocking; a claim by any other
 * decision is not.
 */
export function isClaimableBy(lease: AuthorityLease, decisionId: string, now: Date): boolean {
  if (lease.grant_type !== 'SINGLE_USE') return true;
  if (lease.consumed) return false;
  if (isExpired(lease.expires_at, now)) return false;
  return lease.claimed_at === null || lease.claimed_by_decision_id === decisionId;
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
