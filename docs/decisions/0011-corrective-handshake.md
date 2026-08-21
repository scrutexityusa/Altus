# ADR-0011 — The corrective handshake

**Status** Accepted · 2026-08-21

## Problem

A denial that only says "no" leaves an agent with one strategy: try something
slightly different and see. That behaviour is indistinguishable from probing,
it fills the evidence trail with noise, and it makes every integration brittle
in the same way — the agent encodes a guess about what the control plane wants,
and the guess rots the moment policy changes.

Meanwhile the control plane already knows the answer. It knows the agent lacks
a lease, or that a human could supply what the agent cannot, or that the agent
holding the parent authority is one call away. It simply was not saying so.

## Options

**A — Say nothing.** Safest against information leakage, and it is what most
authorization systems do. It also guarantees the retry-until-something-works
loop, which is worse for security in practice than a bounded, named next step.

**B — Return the policy.** Tell the agent the rule it violated and the
threshold it missed. Maximally helpful and unacceptable: an agent could
binary-search a policy by reading its own denials, and a compromised agent
would learn exactly how much it could move without tripping anything.

**C — Return a typed next step, computed from the decision.** Name the action
the agent can legitimately take, assembled from facts the agent already has.

## Decision

**C**, with three constraints that are the whole design:

1. **Policy-derived and deterministic.** Corrective actions are computed by
   `packages/core/src/corrective.ts` from the same structured decision record
   that produced the refusal. The same decision always yields the same actions.
   No model generates them, and none ever will — a suggestion that varies
   between two identical denials is not a control-plane output, it is a guess
   with better grammar.

2. **Never a hint about policy internals.** Payloads are assembled from the
   caller's own request and from the approval requirement it was already told
   about. A `REQUEST_LEASE` payload names the minimal grant covering _this
   attempt_ — derived entirely from what the caller sent, so it reveals
   nothing. There is a test asserting that a `$250,000` refusal under a
   `$50,000` ceiling mentions neither the ceiling, the rule id, nor the
   constraint name.

3. **Hard violations return nothing.** A sanctioned destination, an unknown
   counterparty, revoked authority, an action forbidden by the declared intent:
   these are answers, not obstacles. Returning a next step would imply one
   exists, which is a lie told by omission.

The action types are `REQUEST_LEASE`, `REQUEST_DELEGATION`, `HUMAN_ESCALATION`,
`DECLARE_INTENT` and `REEVALUATE`. The SDK exposes them as
`decision.correctiveActions()` and can act on the machine-actionable ones
through `client.follow(action)`. `HUMAN_ESCALATION` and `DECLARE_INTENT`
deliberately are not followable: one needs a person, the other needs the caller
to decide what it is actually doing, and returning a would-be result for either
would be fiction.

## Why this is a differentiator

Every authorization system can say no. What makes an authority control plane
useful to an autonomous agent is that a refusal is a _turn in a negotiation_
rather than a dead end. The agent stops guessing and starts asking, every step
it takes is one the control plane named, and the offered step is recorded on
the decision — so the audit trail shows not only what was refused but what the
platform said to do instead.

That last part is the piece that is hard to copy. It requires the refusal and
the remedy to come from the same evaluated facts, which requires the decision
function to be pure and its record complete. Bolting suggestions onto a
system whose decisions are not replayable produces advice nobody can audit.

## Revisit when

Corrective actions need to carry constraints a caller cannot already derive —
for instance "this would be allowed at or below some amount". That is a genuine
usability gain and a genuine disclosure, and it should be an explicit,
per-tenant policy setting rather than a default.
