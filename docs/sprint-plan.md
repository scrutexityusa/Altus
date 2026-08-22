# Delivery plan

Seven two-week sprints. Sprints 1–6 are **delivered** in this repository;
Sprint 7 is scoped below. Each sprint has a definition of done that is
checkable, not narrative.

## Status

| Sprint | Focus                                                           | State          |
| ------ | --------------------------------------------------------------- | -------------- |
| 1      | Repository reset, domain model, schema, contracts, threat model | ✅ Delivered   |
| 2      | Identity and core authorization                                 | ✅ Delivered   |
| 3      | Treasury wire demo, no UI                                       | ✅ Delivered   |
| 4      | Evidence, signals, delegation                                   | ✅ Delivered   |
| 5      | UI, SDK, hardening                                              | ✅ Delivered   |
| 6      | Causal evidence, corrective handshake, single-use grants        | ✅ Delivered   |
| 7      | Hardening for a design partner                                  | ◑ Scoped below |

---

## Sprint 1 — Reset and architecture

**Delivered.** `db/migrations/0001_init.sql`, `0002_rls.sql`, `docs/*`,
`docs/decisions/0001`–`0010`, `spec/openapi.json`, `spec/policy.schema.json`,
`packages/core` primitives (ids, canonical JSON, exact money, decimals, clock,
error taxonomy).

**Done when** — all met:

- [x] Migrations apply to an empty database and are checksum-locked
- [x] Every domain entity has a table, an owner and a lifecycle
- [x] Threat model enumerates attackers, not just controls
- [x] An ADR exists for every choice that would otherwise be re-litigated
- [x] `pnpm typecheck` clean from a fresh checkout

## Sprint 2 — Identity and core authorization

**Delivered.** Organizations, users, agents, credentials; the authority lattice
with proven containment; the policy engine; the composed evaluator; the API
with tenant-scoped transactions.

**Done when** — all met:

- [x] `POST /v1/agents` and `POST /v1/authority-leases` work end to end
- [x] `POST /v1/authorization/evaluate` returns ALLOW / DENY / ESCALATE
- [x] Policy versions are immutable, hashed and integrity-checked on every load
- [x] `child ⊆ parent` proven by randomised testing, not asserted
- [x] Tenant isolation holds at the database layer, tested directly

## Sprint 3 — Treasury wire, no UI

**Delivered.** `policies/treasury-wire.yaml`, the action catalog, approval
requirements and merging, failover behaviour, `scripts/demo.ts`.

**Done when** — all met:

- [x] Scenes 1–3 run from a clean database
- [x] Thresholds are policy data, configurable per tenant
- [x] Failure modes are policy-defined and recorded on the decision
- [x] The demo asserts every scene, so a broken demo fails the build

## Sprint 4 — Evidence, signals, delegation

**Delivered.** Hash-chained signed receipts and verification; the signal plane
with TTL and supersession; authority decay; delegation with clamped lifetimes;
the deterministic explanation compiler.

**Done when** — all met:

- [x] Every consequential action appends a receipt
- [x] Verification detects payload, link and chain tampering
- [x] A fraud signal narrows live authority; its expiry restores it
- [x] Delegated overreach is refused with the axis that failed
- [x] Scenes 4–8 run from a clean database

## Sprint 5 — UI, SDK, hardening

**Delivered.** `packages/sdk`; the dashboard (`apps/web`) over the API's own
read model; `make demo` green from a clean checkout; CI.

**Done when** — all met:

- [x] Dashboard renders the API's read model and nothing of its own
- [x] SDK makes the safe path the easy one: only ALLOW truthy, `guard()`
- [x] Security suite runs the threat model against the real service
- [x] `make demo` green from a clean database

---

## Sprint 6 — Causal evidence and the corrective handshake

**Delivered.**

- **Single-use, purpose-bound grants** (ADR-0013). `CREATED → CLAIMED → USED`,
  spent on claim rather than on execution, enforced by a per-agent advisory
  lock, a guarded UPDATE and CHECK constraints. Ten concurrent requests against
  one grant yield exactly one ALLOW.
- **Approval-to-execution binding.** Decisions are fingerprinted over every
  input they rest on; execution recomputes and refuses on divergence with
  `APPROVAL_CONTEXT_MISMATCH` or `CONTEXT_CHANGED`.
- **Intent binding.** Policies declare intents, requests declare one, and the
  engine returns a structured `intent_evaluation`, denying terminally on
  mismatch.
- **The corrective handshake** (ADR-0011). Typed, policy-derived next steps on
  a refusal; hard violations return nothing; payloads carry no policy internals.
- **Signal authentication** (ADR-0014). Ed25519 and HMAC, per-source keys,
  rotation with a grace period, replay refused on `(source, event_id)`, and a
  security event for every rejection.
- **Root-cause trace** (ADR-0012). `GET /v1/trace/{id}` in causal order, with
  typed edges and a named root cause.
- **Infrastructure.** Per-run test databases, down migrations throughout,
  `tsconfig.test.json`, and `scripts/ci-verify.sh`.

**Done when** — all met:

- [x] 290 tests pass at this milestone, including 10-way concurrency against one
      single-use grant (554 today — see the README)
- [x] Every migration rolls back and reapplies, verified in CI
- [x] The test suite provisions and drops its own database
- [x] Sources _and_ tests typecheck
- [x] Every new endpoint is in the OpenAPI document, drift-checked in CI
- [x] An ADR exists for each architectural change
- [x] `scripts/ci-verify.sh` passes from a clean tree

---

## Sprint 7 — Hardening for a design partner

In priority order. The first two are the ones that would embarrass us in a
security review.

1. **Evidence anchoring** (2d). Publish periodic chain head hashes to an
   external witness. Closes the residual gap in ADR-0006 — today an attacker
   holding both the database and the signing key can rewrite history
   undetectably from inside.
2. **HMAC secret encryption at rest** (2d). `signal_signing_keys.key_material`
   holds HMAC secrets in plaintext. Envelope-encrypt with a key held outside
   the database, or drop HMAC in favour of Ed25519 only. Flagged in
   `0005_signal_authentication.sql`; must not reach a real tenant as is.
3. **Tenant-extensible action catalog** (3d). Move `ACTION_CATALOG` to a
   tenant-scoped table with a cache. Blocks the second vertical (ADR-0007).
4. **Credential lifecycle** (2d). Rotation, expiry enforcement, per-credential
   scope editing, revocation endpoint. Credentials are seeded today.
5. **Python SDK** (3d). The TypeScript SDK ships; most agent runtimes are
   Python. Same semantics: only ALLOW truthy, `guard()`, corrective actions,
   local receipt verification.
6. **Rate limiting and quotas** (2d). Per-credential and per-tenant, at the edge.
7. **Load characterisation** (2d). p50/p95/p99 for
   `/v1/authorization/evaluate` under realistic lease and signal cardinality.
   `evaluation_duration_us` is recorded per decision; nothing has been measured
   under load, and no latency claim should be made until it is.
8. **Per-currency ceilings** (2d). Removes the one-lease-per-currency limitation
   in `docs/domain-model.md`.
9. **Evidence bundle export** (3d). Signed, portable archive of a decision, its
   trace and its chain segment, for an external auditor.
10. **Context-fingerprint tuning** (2d). Any change in the live signal set
    invalidates an unused grant today, including a signal expiring naturally.
    That is the safe direction and it will cause avoidable re-evaluations; the
    fix is a policy-controlled sensitivity setting, not a weaker default.

**Done when:**

- [ ] Chain heads are anchored externally and verification reports anchor status
- [ ] No secret is stored in plaintext anywhere in the schema
- [ ] A tenant can add an action without a deploy
- [ ] Credentials can be rotated and revoked through the API
- [ ] A Python agent can complete the full handshake
- [ ] p50/p95/p99 measured and published as internal engineering targets

---

## Beyond 60 days

In dependency order, not priority order:

- **Sidecar and gateway enforcement points.** The templates exist
  (`deploy/k8s`); the sidecar binary does not. Semantics must remain identical
  across placements — that is what ADR-0002's in-process evaluator buys.
- **Authority graph visualisation.** The data model already answers "who
  authorized this agent", "what policy gave them authority", "who delegated
  what to whom". The linear explanation ships first, deliberately.
- **Policy simulation.** Replay the last N decisions against a draft policy
  version and diff the outcomes, before activation. Cheap, given that
  evaluation is a pure function, and now cheaper still: the decision record
  carries its full context fingerprint and request context, so a replay needs no
  second lookup. Arguably the highest-value item on this list.
- **Authority graph visualisation.** The trace API (ADR-0012) already returns
  the graph in causal order with typed edges; rendering it is presentation
  work over an interface that exists.
- **OpenFGA for relationship modelling**, when resource hierarchies outgrow the
  lattice (ADR-0002).
- **Durable workflow**, when approval acquires reminder ladders and timed
  auto-escalation (ADR-0009).
