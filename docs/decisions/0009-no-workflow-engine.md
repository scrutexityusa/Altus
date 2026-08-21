# ADR-0009 — No durable workflow engine for the first slice

**Status** Accepted · 2026-08-21

## Problem

Approval spans human latency: minutes to hours between escalation and decision.
That shape suggests Temporal or an equivalent.

## Decision

Ordinary transactional logic. No workflow engine.

The whole approval lifecycle is one row and a state transition:

```
ESCALATE → insert approval_request (PENDING, expires_at)
         → human POSTs an approval
         → re-evaluate → superseding decision
         → approval_request → SATISFIED | REJECTED | EXPIRED
```

There is no long-running process to keep alive. State lives in Postgres, where
it is queryable, and expiry is derived from `expires_at` at read time rather
than driven by a timer that could be lost. Nothing here needs durable execution
because nothing here is executing while it waits.

Adding Temporal now would mean a second state store, a second failure mode, and
a second place to look when an approval goes missing — in exchange for a
guarantee we already have from a transaction.

## Revisit when

Approval acquires steps that must survive process death _and_ make progress on
their own: reminder ladders, timed auto-escalation to a second approver,
multi-system compensation when an execution half-fails. The first of those is
the signal to look. The domain objects are already durable, so the engine would
orchestrate them rather than replace them.
