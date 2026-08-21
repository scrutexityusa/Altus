# ADR-0007 — Actions are a closed catalog, not free-form strings

**Status** Accepted · 2026-08-21

## Problem

Discovered by a failing test, which is the honest way to find a design gap.

A delegated verification agent was granted `counterparty.read` with a
`max_amount` ceiling of zero — the natural way to say "moves no money". Its
`counterparty.read` request was then **denied**: the money ceiling could not be
evaluated, because the request carried no amount, and an unevaluable ceiling
fails closed.

Failing closed is right for `wire.execute`. It is wrong for an action that has
no amount at all. The underlying problem was that nothing in the system knew
which actions carry money.

## Options considered

**A — Skip a constraint when its value is absent.** Opens exactly the hole the
fail-closed rule exists to shut: a wire with the amount omitted would pass.

**B — Infer money-bearing from the action name prefix.** `wire.*` moves money.
Guessing from strings, in the authorization layer.

**C — Declare it.** Each action states the resource types it applies to, the
context fields it carries, and which are required.

## Decision

**C.** `packages/core/src/actions.ts` holds the catalog. Three properties fall
out, all of which the system needed anyway:

1. **A typo cannot become a bypass.** `wire.exceute` is a `400` at the
   boundary, not a request that matches no rule and takes some default.
2. **A money-bearing action can never reach the decision point without an
   amount.** The ceiling never has to guess what an absent amount means.
3. **A constraint binds only the actions its dimension is defined for.** An
   authority that caps payments at zero does not thereby forbid reading a
   counterparty record.

An action outside the catalog binds **every** dimension: unrecognised means
maximally constrained, never unconstrained.

## Consequences and the debt

The catalog is code, so a new action is a deploy. That is acceptable for one
vertical and unacceptable for a platform. It must become a tenant-scoped table
before the second vertical ships. The shape is already data, and
`applicableDimensions` already takes it as a parameter, so the change is a
loader and a cache — not a redesign.
