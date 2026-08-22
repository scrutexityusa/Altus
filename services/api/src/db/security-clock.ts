import type { PoolClient } from './pool.js';

/**
 * ============================================================================
 * The security time authority.
 * ============================================================================
 *
 * Authority is valid until an instant. Deciding whether that instant has
 * passed is a security decision, and it was being made by two different clocks
 * at once:
 *
 *     rows written with the database clock   (now())
 *     expiry compared with the API node's    (new Date())
 *
 * For ordinary software a few milliseconds of disagreement is a nuisance. Here
 * it decides whether money may move. A node whose clock runs fast expires
 * authority early; one running slow honours a lease past its lifetime, and the
 * *same* lease gives different answers on different replicas of the same
 * service. That is not a tolerance to widen with NTP — it is two sources of
 * truth for one question.
 *
 * So: **the database is authoritative for every security-relevant validity
 * decision.** It already writes every timestamp; it now also says what time it
 * is when those timestamps are judged.
 *
 * ## Why `now()` and not `clock_timestamp()`
 *
 * Postgres `now()` is `transaction_timestamp()` — fixed at the start of the
 * transaction and stable for its whole duration. That is not a limitation
 * here, it is the property being bought.
 *
 * One decision reads a lease, its ancestors, the live signals and an approval.
 * With a moving clock those reads can disagree: a signal filtered *in* by
 * `expires_at > now()` at one instant can be judged expired by the evaluator a
 * millisecond later, and the decision then rests on a set of facts that never
 * simultaneously held. A transaction-stable instant makes every check inside
 * one decision agree by construction.
 *
 * `clock_timestamp()` would reintroduce exactly the split this module exists
 * to remove, just with a shorter fuse.
 *
 * ## The evaluator stays pure
 *
 * Nothing here reaches into `@scrutexity/core`. The database produces an
 * instant, the caller puts it in the snapshot, and the pure evaluator reads it
 * from there:
 *
 *     database ──> securityNow ──> EvaluationSnapshot.now ──> pure evaluator
 *
 * That is what keeps a decision replayable: feed the same snapshot back in
 * years later and the same instant produces the same answer, with no
 * dependence on the clock of whatever machine is doing the replaying.
 */

/**
 * The authoritative instant for this transaction.
 *
 * Every security-relevant validity decision in a request must use this value
 * and no other. `new Date()` inside a decision path is a bug: see the tests in
 * `services/api/test/temporal.test.ts`, which prove an API node with a skewed
 * clock cannot change any answer.
 *
 * Cheap — a round trip on a connection already held, on a value Postgres has
 * cached since `BEGIN`.
 */
export async function securityNow(client: PoolClient): Promise<Date> {
  const result = await client.query<{ now: Date }>('SELECT now() AS now');
  return result.rows[0]!.now;
}
