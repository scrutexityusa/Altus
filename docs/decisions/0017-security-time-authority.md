# ADR-0017: The database is the security time authority

**Status:** Accepted
**Date:** 2026-08-21

## Context

Authority is valid until an instant. Deciding whether that instant has passed
was being done by two different clocks:

```
rows written with the database clock   now()
expiry compared with the API node's    new Date()
```

Eleven decision sites read `new Date()` or `Date.now()`: lease expiry, grant
expiry, approval expiry, signal freshness, delegation liveness, credential
expiry, and the reported state of a lease.

For ordinary software a few milliseconds of clock disagreement is a nuisance.
Here it decides whether money may move. A node whose clock runs fast expires
authority early; one running slow honours a lease past its lifetime. Worse,
the **same lease gives different answers on different replicas of the same
service**, so whether an agent may pay depends on which machine its request
landed on.

One case was already actively inconsistent _within a single decision_: live
signals were filtered by `expires_at > now()` — the database clock — and then
judged expired by the evaluator using the API clock. A signal could be
filtered in by one and out by the other, leaving the decision resting on a set
of facts that never simultaneously held.

This is not a tolerance to widen with NTP. It is two sources of truth for one
question.

## Decision

**The database is authoritative for every security-relevant validity
decision.** It already writes every timestamp; it now also says what time it is
when those timestamps are judged.

```
database ──> securityNow ──> EvaluationSnapshot.now ──> pure evaluator
```

`securityNow(client)` is a single `SELECT now()` on the connection already
held. Every site that previously read the process clock now takes this value.

### `now()`, not `clock_timestamp()`

Postgres `now()` is `transaction_timestamp()` — fixed at `BEGIN` and stable for
the whole transaction. That is the property being bought, not a limitation.

One decision reads a lease, its ancestors, the live signals and an approval.
With a moving clock those reads can disagree. A transaction-stable instant
makes every check inside one decision agree by construction: **one instant per
decision.** `clock_timestamp()` would reintroduce exactly the split this
decision removes, with a shorter fuse.

### The evaluator stays pure

Nothing in `@scrutexity/core` gained a database handle. The database produces
an instant; the caller puts it in the snapshot; the pure evaluator reads it
from there. That is what keeps a decision replayable — feed the same snapshot
back years later and the same instant produces the same answer, with no
dependence on the clock of whatever machine is replaying it.

### The boundary is inclusive, and now has vectors

`isExpired` uses `<=`: an instant exactly equal to `expires_at` is already
expired. That was already correct; it was never pinned. It is now:

| Instant relative to `expires_at` | Verdict     |
| -------------------------------- | ----------- |
| −1 ms                            | VALID       |
| exactly 0                        | **EXPIRED** |
| +1 ms                            | EXPIRED     |

A lease must never authorise at the instant it lapses, and the tie has to
break the safe way.

## Consequences

`GET /v1/authority-leases/:id` gained `effective_status`. The `status` column
is the stored disposition — what someone wrote — and it says `ACTIVE` for a
lease that has simply run out of time, because nothing goes back to rewrite
rows when a clock passes them. Reporting only that had the endpoint calling a
lease `ACTIVE` while an authorization refused it as `EXPIRED`: a lie about the
one thing it exists to describe. Both are now returned, named for what they
are.

Receipt timestamps are authoritative too. The payload `created_at` is _hashed
into the receipt_ while the column is what an auditor reads; sourcing them from
different clocks let them drift, so a verifier recomputing the hash would be
checking a different fact than the one on screen. They are now one value.

Authentication reads the credential row and the instant it is judged against on
the same connection in the same transaction, so an API node's clock cannot keep
an expired credential alive.

Every request costs one additional round trip on a connection it already holds,
against a value Postgres has cached since `BEGIN`.

## What this does not do

**It does not verify the production clock source.** The decision makes the
database the single authority; whether _that_ clock is correct — synchronised,
monotonic, not silently stepped by a hypervisor — is an operational property of
the deployment, not something this repository can assert. The surface map
records this separately as `Operationally verified: NOT YET`.

**It does not address replication lag.** Every decision here runs on a primary
connection inside one transaction. A future read replica would reintroduce a
second clock and this ADR would need revisiting before that happens.

**It does not make time monotonic.** Postgres `now()` follows the system clock
and can move backwards if the host's clock is stepped. The system fails toward
refusal in that case rather than toward permission, but a large backward step
would honour authority that has lapsed. Bounding that is NTP's job, and it is
the one place where infrastructure hygiene genuinely is the control.

## Alternatives considered

**Widen the tolerance and rely on NTP.** Rejected. It converts a correctness
question into a tuning parameter, and every value of that parameter is wrong in
one direction or the other.

**Pass a clock into the core package.** Rejected. It would make the evaluator
impure, break replay, and put a database handle behind a function whose whole
value is that it has none.

**Compare expiry in SQL at every site.** Rejected. It would scatter the
predicate across a dozen queries, each free to get the boundary wrong
differently, and the evaluator would still need an instant for the checks it
makes in memory.
