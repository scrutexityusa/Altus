# ADR-0008 — Envelope failures are terminal; constraint failures are escalatable

**Status** Accepted · 2026-08-21

## Problem

Two demo scenes are in apparent contradiction.

- **Scene 3.** TreasuryAgent holds authority to execute wires up to $50,000. It
  requests $250,000. Expected: **ESCALATE**, treasurer approval.
- **Scene 6.** VerificationAgent holds `counterparty.read` only. It attempts
  `wire.modify`. Expected: **DENY**.

Under a single rule — "outside your authority means denied" — Scene 3 must
deny. Under the opposite rule — "policy escalation overrides held authority" —
Scene 6 could escalate, and any escalating rule would become a bypass for the
authority layer.

Both rules are wrong, which usually means the model is missing a distinction.

## Decision

A grant has two layers that fail differently:

| Layer        | Contains            | On failure                                              |
| ------------ | ------------------- | ------------------------------------------------------- |
| **Envelope** | actions × resources | **DENY**, terminal                                      |
| **Autonomy** | constraints         | **ESCALATE** if policy names an approver, else **DENY** |

The envelope is what the agent _is for_. Approving a `wire.modify` for a
verification agent would not authorise one action — it would silently redefine
the agent's role, and no approver in the escalation flow is being asked that
question.

The constraints are how much of that role it may exercise unsupervised. A
treasury agent asked to send $250,000 is doing its own job at a size that needs
a human, and the human supplies the authority the agent lacks from their own.
That is what escalation is.

Two corollaries:

- **Policy permission never substitutes for held authority.** If policy says
  ALLOW and no lease covers the envelope, the answer is DENY. Scene 6's request
  matched an ALLOW rule and was denied anyway.
- **Decay narrows autonomy, not the envelope.** A fraud signal that strips
  `wire.execute` means "not without a human", not "not any more". This is what
  makes Scene 7 escalate rather than read as a broken integration.

## Evidence

`packages/core/test/evaluate.test.ts` covers all five rows of the table, and
`invariants.test.ts` proves over 2,000 randomised lease/request pairs that no
ALLOW is ever issued without autonomous covering authority.

## Revisit when

A customer needs a human to be able to extend an agent's envelope in-flight —
"just this once, let it touch that account". That is a different product
gesture (a scoped, human-issued, single-use lease) and should be built as one,
not by weakening this boundary.
