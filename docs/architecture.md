# Architecture

## What this system is

Scrutexity answers one question, deterministically, and produces evidence for
the answer:

> Was this agent authorized to perform this action, on this resource, under
> this context, at this exact point in time?

It is a **Policy Decision Point** and an **authority control plane**. It is not
an observability tool, not a compliance dashboard, and not a model wrapper. It
does not watch what agents do; it determines what they are permitted to do.

## The chain

Every consequential action traverses the same chain, and every link is a
first-class, persisted object:

```
Principal → Agent Identity → Intent → Context → Authority → Policy
          → Risk Signals → Authorization Decision → Execution → Evidence
```

If a proposed feature does not strengthen a link in that chain, it does not
belong in the product.

## Shape of the system

```
┌────────────────────────────────────────────────────────────────────────┐
│ Agent runtime                                                          │
│   ┌──────────────────────┐                                             │
│   │ @scrutexity/sdk      │  the Policy Enforcement Point               │
│   │  authorize / guard   │  lives as close to the action as practical  │
│   └──────────┬───────────┘                                             │
└──────────────┼─────────────────────────────────────────────────────────┘
               │ HTTPS, bearer credential
┌──────────────▼─────────────────────────────────────────────────────────┐
│ services/api  — Fastify                                                │
│   authenticate → derive tenant → tenant-scoped transaction             │
│   ┌──────────────────────────────────────────────────────────────┐     │
│   │ orchestrator: assemble snapshot, persist, append evidence    │     │
│   │   (contains no authorization logic of its own)               │     │
│   └───────────────┬──────────────────────────────────────────────┘     │
│                   │ EvaluationSnapshot (pure data)                     │
│   ┌───────────────▼──────────────────────────────────────────────┐     │
│   │ @scrutexity/core — the Policy Decision Point                 │     │
│   │   authority lattice · policy engine · approval algebra       │     │
│   │   receipts · deterministic explanation compiler              │     │
│   │   pure, total, no clock, no I/O, no randomness               │     │
│   └──────────────────────────────────────────────────────────────┘     │
└──────────────┬─────────────────────────────────────────────────────────┘
               │
┌──────────────▼─────────────────────────────────────────────────────────┐
│ PostgreSQL                                                             │
│   FORCE ROW LEVEL SECURITY on every tenant table                       │
│   append-only triggers on all evidence tables                          │
│   per-tenant hash-chained receipts                                     │
└────────────────────────────────────────────────────────────────────────┘
```

## The one architectural commitment that matters

**All authorization logic lives in a pure function.**

`evaluateAuthorization(snapshot) → decision` reads no clock, opens no
connection, and consults no global. Everything it depends on arrives as data.

This is not stylistic. It is what makes four separate promises achievable at
once:

| Promise                              | Why purity delivers it                                                                                                   |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| Replay                               | An archived snapshot reproduces its archived decision exactly.                                                           |
| Testability                          | 142 unit tests, including randomised invariant proofs over 11,000 generated grants, run in two seconds with no database. |
| Consistency across deployment models | SDK, sidecar, gateway and hosted service all call the same function, so they cannot disagree.                            |
| Auditability                         | The decision record contains every input, because the function had no other inputs.                                      |

The corollary is a rule with no exceptions: **if a branch in the service
changes an outcome, it is in the wrong place.** The orchestrator assembles
facts and writes down answers. It never decides.

## Components

| Path            | Responsibility                                                         |
| --------------- | ---------------------------------------------------------------------- |
| `packages/core` | Domain, policy engine, authority lattice, evidence, explanation. Pure. |
| `packages/sdk`  | Typed client and enforcement point. Makes the safe path the easy one.  |
| `services/api`  | HTTP surface, persistence, tenancy, idempotency, observability.        |
| `apps/web`      | Minimal dashboard rendering the API's own read model.                  |
| `db/migrations` | Schema, RLS policies, append-only triggers.                            |
| `policies/`     | The demonstration treasury policy pack.                                |
| `spec/`         | Generated OpenAPI and policy JSON Schema, drift-checked in CI.         |
| `deploy/k8s`    | Sidecar deployment templates.                                          |

## Deliberate omissions

These were considered and left out, with reasons, so nobody has to re-derive
the decision:

- **OPA / OpenFGA** (ADR-0002). Their concepts are the reference points for the
  design; running them as services is not required by this vertical slice and
  would have added a network hop to the hot path plus a second place where
  authorization semantics live.
- **A durable workflow engine.** Approval is one row and a state transition,
  not an orchestration problem. It becomes one when approvals must survive
  multi-day human latency with reminders and escalation ladders; that is when
  Temporal earns its place, and not before.
- **Redis.** The only cacheable thing is an immutable, content-addressed policy
  version, which is small and process-local. A distributed cache would add a
  consistency question to the one place that must never have one.
- **Kubernetes for local development.** `make dev` runs Postgres and the API.

## Where the design will be pushed next

Named honestly, because unnamed debt is the expensive kind:

- **Per-currency ceilings.** A lease is denominated in one currency and refuses
  requests in another. Correct and fail-closed, but a multi-currency treasury
  needs one lease per currency today. See `docs/domain-model.md`.
- **A tenant-extensible action catalog.** The catalog is code (ADR-0007); it
  needs to become a tenant-scoped table before the second vertical.
- **Decay across a delegation chain.** A signal about a parent agent narrows
  that agent's autonomy, not its delegates'. Defensible, but it should become a
  policy choice rather than an implementation default.
- **Evidence anchoring.** The hash chain detects tampering by anyone who cannot
  rewrite the whole chain and re-sign it. Publishing periodic head hashes to an
  external witness closes that gap. See `docs/security-model.md`.
