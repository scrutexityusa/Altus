import { describe, expect, it } from 'vitest';
import { addSeconds, isExpired } from '../src/time.js';
import { effectiveLeaseStatus } from '../src/authority/lease.js';
import { verifyAuthorityInvariants } from '../src/invariants.js';
import { parseMoney } from '../src/money.js';
import type { AuthorityLease } from '../src/authority/lease.js';

/**
 * ============================================================================
 * Temporal conformance.
 * ============================================================================
 *
 * `now >= expires_at` is a security decision. It decides whether authority
 * still exists, and every temporal object in the system -- lease, delegation,
 * execution grant, approval, signal, signing key, replay window, credential --
 * is judged by the same predicate.
 *
 * Which means the tie at the boundary matters, and must not be left to
 * intuition. These are the vectors.
 */

const EXPIRY = new Date('2026-01-01T10:00:00.000Z');

describe('the expiry boundary', () => {
  /**
   * Expiry is inclusive: an instant exactly equal to `expires_at` is already
   * expired. A lease must never authorise at the instant it lapses, and a tie
   * has to break the safe way.
   */
  const vectors: [string, string, boolean][] = [
    ['one millisecond before', '2026-01-01T09:59:59.999Z', false],
    ['exactly at the boundary', '2026-01-01T10:00:00.000Z', true],
    ['one millisecond after', '2026-01-01T10:00:00.001Z', true],
    ['a second before', '2026-01-01T09:59:59.000Z', false],
    ['a second after', '2026-01-01T10:00:01.000Z', true],
    ['long before', '2020-01-01T00:00:00.000Z', false],
    ['long after', '2030-01-01T00:00:00.000Z', true],
  ];

  for (const [name, instant, expired] of vectors) {
    it(`${name}: ${expired ? 'EXPIRED' : 'VALID'}`, () => {
      expect(isExpired(EXPIRY, new Date(instant))).toBe(expired);
    });
  }

  it('reads an ISO string and a Date identically', () => {
    // Rows come back as Date; payloads and API bodies carry ISO strings. A
    // predicate that disagreed between the two would make the answer depend on
    // which code path asked.
    const at = new Date('2026-01-01T09:59:59.999Z');
    expect(isExpired(EXPIRY, at)).toBe(isExpired(EXPIRY.toISOString(), at));
  });
});

describe('every temporal object breaks the tie the same way', () => {
  const lease = (expiresAt: Date): AuthorityLease =>
    ({
      id: 'lease_x',
      agent_id: 'agent_x',
      parent_lease_id: null,
      depth: 0,
      grant: {
        actions: ['wire.execute'],
        resources: { bank_account: ['acct_001'] },
        constraints: { max_amount: parseMoney('1000.00', 'USD') },
      },
      status: 'ACTIVE',
      issued_at: new Date('2026-01-01T09:00:00.000Z').toISOString(),
      expires_at: expiresAt.toISOString(),
      revoked_at: null,
      revocable: true,
      grant_type: 'REUSABLE',
      consumed: false,
      claimed_at: null,
      claimed_by_decision_id: null,
      used_at: null,
      purpose: null,
      organization_id: 'org_x',
      policy_version_id: 'polv_x',
      revocation_reason: null,
    }) as AuthorityLease;

  it('a lease is ACTIVE one millisecond before and EXPIRED at the boundary', () => {
    expect(effectiveLeaseStatus(lease(EXPIRY), new Date('2026-01-01T09:59:59.999Z'))).toBe(
      'ACTIVE',
    );
    expect(effectiveLeaseStatus(lease(EXPIRY), EXPIRY)).toBe('EXPIRED');
  });

  it('the invariant verifier agrees with the lease at the same instant', () => {
    // Two components deciding "is this still valid" must not disagree by a
    // millisecond, or a decision can pass one check and fail the next on facts
    // that were true the whole time.
    const before = new Date('2026-01-01T09:59:59.999Z');
    expect(verifyAuthorityInvariants({ now: before, chain: [lease(EXPIRY)] }).valid).toBe(true);
    expect(verifyAuthorityInvariants({ now: EXPIRY, chain: [lease(EXPIRY)] }).failed).toContain(
      'LEASE_ACTIVE',
    );
  });

  it('addSeconds and isExpired round-trip exactly at the TTL', () => {
    // A grant issued with a 300-second TTL is expired at exactly +300s, not
    // at +301. Off-by-one here silently lengthens every grant in the system.
    const issued = new Date('2026-01-01T10:00:00.000Z');
    const expires = addSeconds(issued, 300);
    expect(isExpired(expires, new Date(issued.getTime() + 299_999))).toBe(false);
    expect(isExpired(expires, new Date(issued.getTime() + 300_000))).toBe(true);
  });
});

describe('replay: the same instant always produces the same answer', () => {
  it('is a pure function of its two arguments', () => {
    // The evaluator takes `now` from the snapshot rather than reading a clock,
    // which is what makes a decision replayable years later on a machine whose
    // own clock is irrelevant.
    const at = new Date('2026-01-01T09:59:59.999Z');
    const answers = Array.from({ length: 100 }, () => isExpired(EXPIRY, at));
    expect(new Set(answers).size).toBe(1);
  });
});
