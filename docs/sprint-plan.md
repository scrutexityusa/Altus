# 60-day plan

Five two-week sprints. Sprints 1–4 are **delivered** in this repository;
Sprint 5 is partially delivered and the remainder is scoped below. Each sprint
has a definition of done that is checkable, not narrative.

## Status

| Sprint | Focus                                                           | State                                                       |
| ------ | --------------------------------------------------------------- | ----------------------------------------------------------- |
| 1      | Repository reset, domain model, schema, contracts, threat model | ✅ Delivered                                                |
| 2      | Identity and core authorization                                 | ✅ Delivered                                                |
| 3      | Treasury wire demo, no UI                                       | ✅ Delivered                                                |
| 4      | Evidence, signals, delegation                                   | ✅ Delivered                                                |
| 5      | UI, SDK, hardening                                              | ◑ SDK and dashboard delivered; hardening items listed below |

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

**Delivered.** `policies/treasury_wire.yaml`, the action catalog, approval
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

**Delivered:** `packages/sdk`; the dashboard (`apps/web`) over the API's own
read model; 199 tests; `make demo` green from a clean checkout; CI.

**Remaining, in priority order:**

1. **Evidence anchoring** (2d). Publish periodic chain head hashes to an
   external witness. Closes the one residual gap in ADR-0006 — currently an
   attacker with both the database and the signing key can rewrite history
   undetectably from inside.
2. **Tenant-extensible action catalog** (3d). Move `ACTION_CATALOG` to a
   tenant-scoped table with a cache. Blocks the second vertical (ADR-0007).
3. **Credential lifecycle** (2d). Rotation, expiry enforcement, per-credential
   scope editing, and a revocation endpoint. Today credentials are seeded.
4. **Rate limiting and quotas** (2d). Per-credential and per-tenant, at the
   edge.
5. **Concurrency tests** (2d). Parallel evaluations against one lease; racing
   revocation against evaluation; concurrent receipt appends asserting no chain
   fork. The locking is in place; the proof is not.
6. **Load characterisation** (2d). Establish p50/p95/p99 for
   `/v1/authorization/evaluate` under realistic lease and signal cardinality.
   `evaluation_duration_us` is already recorded per decision; nothing has been
   measured under load, and no latency claim should be made until it is.
7. **Per-currency ceilings** (2d). Removes the one-lease-per-currency
   limitation in `docs/domain-model.md`.
8. **Evidence bundle export** (3d). Signed, portable archive of a decision and
   its chain segment for an external auditor.

**Done when:**

- [ ] Chain heads are anchored externally and verification reports anchor status
- [ ] A tenant can add an action without a deploy
- [ ] Credentials can be rotated and revoked through the API
- [ ] Concurrency tests pass under parallel load
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
  evaluation is a pure function — arguably the highest-value item on this list.
- **OpenFGA for relationship modelling**, when resource hierarchies outgrow the
  lattice (ADR-0002).
- **Durable workflow**, when approval acquires reminder ladders and timed
  auto-escalation (ADR-0009).
