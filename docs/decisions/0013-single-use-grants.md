# ADR-0013 — Single-use grants and exactly-once semantics

**Status** Accepted · 2026-08-21

## Problem

A reusable lease answers "may this agent do this kind of thing for the next
hour". For high-consequence actions the better question is "may this agent do
this one thing, once" — and that requires exactly-once semantics under
concurrency, retry, and partial failure.

Exactly-once is where this kind of feature usually goes wrong, so the decision
worth recording is _which event counts as the use_.

## Options

**A — Consume on execution.** The obvious reading of "single use": the grant is
spent when the action happens. It has a hole. An agent can obtain an ALLOW,
never execute, and obtain another — indefinitely. The grant is never spent
because the thing that spends it never occurs, and an attacker who can trigger
authorization but not execution gets unlimited attempts.

**B — Consume on authorization.** Spend the grant when it is claimed by a
decision. Closes the hole: every ALLOW costs the grant, executed or not. The
cost is that a decision the agent never acted on still spends its grant.

## Decision

**B.** The claim is the boundary.

The deciding argument is not which is more intuitive — A is — but which one a
database can enforce. A claim is a row update the database serialises. An
execution is an outcome in someone else's system that we learn about later, and
building exactly-once on an event we only hear about second-hand means building
it on a report rather than on a fact.

So the state machine is:

```
CREATED --claim--> CLAIMED --execute--> USED
   |                  |
   +------------------+--expire--> EXPIRED
```

and `effectiveLeaseStatus` reports a CLAIMED single-use grant as `CONSUMED`.
A grant that was claimed but never executed stays spent. Re-authorising
requires a new grant, which is a decision someone makes deliberately.

## Enforcement

Three layers, so no single mistake is fatal:

1. **A per-agent advisory lock** taken before the grants are read, so
   contenders serialise.
2. **A guarded UPDATE** — `WHERE NOT consumed AND claimed_at IS NULL` — so the
   database refuses a second claim even without the lock.
3. **CHECK constraints** encoding the state machine, so no code path can write
   a row that is consumed-but-never-claimed or used-but-not-consumed.

The advisory lock replaced `SELECT ... FOR UPDATE` over the grants themselves,
which deadlocked under load: an agent holding several unspent grants had
concurrent transactions acquire overlapping row locks. `ORDER BY` does not
reliably fix that, because the planner may lock before it sorts. One lock keyed
on the agent has no ordering to get wrong. The lock is transaction-scoped and
is always acquired before the evidence chain head — the only other lock on that
path — so the two cannot form a cycle.

Proven by ten concurrent requests against one grant: exactly one ALLOW, nine
`AUTHORITY_CONSUMED`, no errors.

## Purpose binding

A grant may carry a `purpose`. A request declaring a different intent is
refused with `INTENT_MISMATCH / purpose_mismatch`, and that binding holds even
under a policy that does not enforce intent at all — the authority itself was
issued for one objective, and using it for another is a mismatch regardless of
what policy says.

## Cost, stated plainly

An agent that obtains an ALLOW and then crashes has burned its grant. That is
the intended direction — fail closed — but it makes grant issuance part of the
retry path for any agent that wants to be resilient, and the corrective
handshake returns `REQUEST_LEASE / single_use_grant_already_spent` precisely so
that path is a named step rather than a guess.

## The three outcomes of a claim, and how to tell them apart

A claim is terminal, so "can I retry?" has to be answerable from evidence
rather than from optimism. A claimed single-use grant is in exactly one of
three states, and `GET /v1/authority-leases/:id` reports which:

| `grant_state` | `execution_outcome` | What happened                                               |
| ------------- | ------------------- | ----------------------------------------------------------- |
| `CLAIMED`     | `null`              | The agent was authorised and never came back.               |
| `USED`        | `SUCCEEDED`         | The operation was attempted and the agent reported success. |
| `USED`        | `FAILED`            | The operation was attempted and the agent reported failure. |

A `FAILED` execution spends the grant exactly as a `SUCCEEDED` one does.
Anything else would let a caller manufacture a retry by reporting its own
failure, which makes the authority reusable by an agent that is willing to lie.
Authority is consumed by the attempt, not by the attempt working.

The honest limit: `FAILED` is what the agent _said_, and it conflates "the
transfer definitely did not happen" with "the bank API timed out and I do not
know". `CLAIMED` with no execution is the same ambiguity in a worse form —
nobody reported anything at all. In both cases the safe answer is the same
(the grant is gone; issue a new one under a fresh decision), but neither state
tells an operator whether money moved. Only the external system knows that.

Closing that gap means a `CREATED → CLAIMED → EXECUTING → SUCCEEDED/FAILED`
lifecycle in which the enforcement boundary — not the agent — records
`EXECUTING` before it contacts the external system, and a reconciliation pass
resolves whatever is left in `EXECUTING` after a crash. That belongs with the
execution adapter, because it is only truthful if the thing writing the state
is the thing making the call. Until then the states above are the whole of
what the system honestly knows, and they are surfaced rather than inferred so
that no operator has to reconstruct them from a join.

## Revisit when

Operators need a claimed-but-unexecuted grant released early, rather than
waiting for expiry. That is a release operation with its own authority
requirement, not a relaxation of the rule.
