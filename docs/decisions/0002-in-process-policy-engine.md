# ADR-0002 — Evaluate policy in-process rather than running OPA and OpenFGA

**Status** Accepted · 2026-08-21

## Problem

Policy must be versioned, immutable, hashable, testable, reviewable and
deterministic. Relationship and delegation authorization must be sound. Both
OPA (policy decision) and OpenFGA (relationship authorization) are designed for
exactly these jobs, and the brief names them as reference points.

## Options

**A — Run OPA and OpenFGA as services.** Mature engines, familiar to reviewers.
Costs: two network hops on the hot path; authorization semantics split across
three places (Rego, the FGA model, and our own code) with no single artifact
that is the truth; the delegation invariant `child ⊆ parent` expressed twice;
two more things to operate before the first customer.

**B — Embed OPA/WASM.** Removes the hop, keeps Rego. Still splits the semantics,
and makes the decision record depend on a WASM build artifact rather than on
data we control and hash.

**C — Evaluate in-process over a hashed, versioned policy document.** One
artifact is the truth. Costs: we own the evaluator, and Rego expertise does not
transfer.

## Decision

**C.** The evaluator is a pure function over a validated document.

The brief itself gives the deciding reason: _"Do not make either dependency a
hard architectural requirement if the actual MVP can be cleaner without it."_
It is cleaner without them, for one reason that outweighs the rest — a decision
must be **replayable from evidence**. With an in-process evaluator, the decision
record contains the policy hash and every input, and replay is a function call.
With an external engine, replay depends on reconstructing that engine's state
and version, which is a much weaker guarantee than it appears.

Their concepts are kept, deliberately:

| Concept                           | Where it lives here                                                  |
| --------------------------------- | -------------------------------------------------------------------- |
| PDP / PEP separation (OPA)        | `packages/core` is the PDP; `packages/sdk` is the PEP.               |
| Policy as data, not code (OPA)    | Closed selector vocabulary, total operators, no expression language. |
| Agents as principals (OpenFGA)    | `agents` is a first-class principal table.                           |
| Contextual restrictions (OpenFGA) | The constraint dimension registry.                                   |
| Temporal grants (OpenFGA)         | `AuthorityLease` with TTL, revocation and chain walk.                |

We also gain something neither offers off the shelf: **containment is a proven
property of our own type**, tested against 4,000 randomised delegation
proposals. Expressing `child ⊆ parent` as an invariant in a relationship model
is possible; proving it by generative testing over our own algebra is stronger
and much easier to keep true.

## Revisit when

Customers need to author policy in Rego because they already have a corpus of
it; or relationship modelling grows past what the lattice expresses (deep
resource hierarchies, group membership, ownership inheritance). Then OpenFGA
becomes the relationship store behind `coversAttempt` and the interface
`packages/core` presents does not change.
