# ADR-0003 — Model authority as a lattice with a proven containment relation

**Status** Accepted · 2026-08-21

## Problem

Delegation is the one place authority is created outside the policy path. If
`child ⊆ parent` can be violated, every other control is decoration.

## Decision

A grant is a point in a three-axis lattice — actions × resources × constraints
— with two total operations: `containsGrant(parent, child)` and
`coversAttempt(grant, attempt)`. Constraint dimensions live in a registry, each
declaring how it narrows and how it is satisfied, so adding a dimension is a
table entry and a test rather than a new branch in the containment proof.

The asymmetry that makes it safe: **a dimension the parent constrains must also
be constrained by the child; a dimension the child adds is free.** Adding a
constraint can only shrink authority. Therefore omission is never a widening
path — which is the subtle attack this exists to stop, and the one a naive
"child fields override parent fields" merge gets wrong.

Two further rules:

- **Reject, do not clamp.** An agent asking for more than it holds has a bug or
  an attacker in it; granting the intersection silently would hide both.
  Lifetime is the exception, because "as long as you can" cannot widen anything.
- **Decay only narrows.** `restrictGrant` has an absolute contract: the result
  is always contained by the input. Asked to raise a ceiling it keeps the lower
  one; asked to apply an incomparable currency it declines.

## Evidence

Randomised invariant tests in `packages/core/test/invariants.test.ts`:

- 4,000 delegation proposals — containment holds without exception
- 3,000 parent/child pairs — anything the child covers, the parent covers
- 2,000 restrictions — decay never widens
- 2,000 lease/request pairs — no ALLOW without autonomous covering authority

The generator produces plausible narrowings _and_ adversarial mutations; the
suite fails if the success path is not exercised, so the invariant cannot pass
vacuously.

## Consequences

The lattice cannot express hierarchical resources (`acct_*` under a business
unit) or ownership inheritance. Those are the natural first extension and are
what would pull OpenFGA in (ADR-0002).
