# Security surface map

An audit of every place authority is created, changed, checked or consumed, and
of every boundary an attacker can reach. Produced before the design-partner
hardening pass; the gaps at the bottom are what that pass is for.

Method: enumerate the routes, then for each one trace what it can do to
authority, what it persists, how it fails, and which test proves the claim. A
control with no test is listed as a gap, not as a control.

**Status at audit time:** 428 tests, 14 files, clean CI.
**Current:** 621 tests across 24 files; 12/12 adversarial invariants; 3/3 recovery scenarios.

## How to read a gap's status

"Closed" is one word covering five different claims, and collapsing them is how
a system arrives at a design partner with more confidence than evidence. Each
gap carries all five:

| Stage                      | Means                                                                                                    |
| -------------------------- | -------------------------------------------------------------------------------------------------------- |
| **Discovered**             | Someone noticed it. Nothing more.                                                                        |
| **Validated**              | Reproduced — the failure was demonstrated, not inferred from reading.                                    |
| **Fixed**                  | An implementation exists and the intended behaviour was observed once.                                   |
| **Regression-tested**      | An adversarial test fails if the fix is removed. This is the bar that survives a refactor.               |
| **Operationally verified** | Confirmed in a real deployment, against real infrastructure. Nothing in this repository can assert this. |

The last one is the honest limit of what code and tests can prove. A gap can be
**Regression-tested: PASS** and **Operationally verified: NOT YET** at the same
time, and saying so is more useful to a design partner than a green tick.

---

## 1. Credential authentication

|                      |                                                                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **Component**        | `services/api/src/auth.ts`, `db/migrations/0002_rls.sql`                                                                                     |
| **Trust boundary**   | Untrusted → identified. Everything downstream depends on this.                                                                               |
| **Inputs**           | `Authorization: Bearer <prefix>.<secret>`                                                                                                    |
| **Authority impact** | Establishes principal, tenant and scopes. Tenant is derived here and **never** read from a header or body.                                   |
| **Persistent state** | `api_credentials` — secret stored SHA-256, never plaintext.                                                                                  |
| **Failure mode**     | Fails closed (401). Hash is computed even when no row matches, so a wrong prefix and a wrong secret take the same time.                      |
| **Invariants**       | INV-009. Tenant cannot be asserted by the caller.                                                                                            |
| **Tests**            | `security.test.ts` — timing, forged prefix, cross-tenant token, expired credential.                                                          |
| **Gaps**             | **G-1 (bearer token only).** A leaked environment variable is a full agent impersonation with no workload binding and no automatic rotation. |

## 2. Tenant isolation

|                      |                                                                                                                                                                                                                                                                  |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Component**        | `db/pool.ts` `withTenant`, `FORCE ROW LEVEL SECURITY` on every tenant table                                                                                                                                                                                      |
| **Trust boundary**   | Application → database. The database is the second line, as section 44 asks.                                                                                                                                                                                     |
| **Inputs**           | `scrutexity.org_id` GUC, set transaction-locally from the authenticated principal.                                                                                                                                                                               |
| **Authority impact** | Scopes every read and write. A handler that forgets its tenant sees zero rows and writes nothing.                                                                                                                                                                |
| **Persistent state** | All tenant tables.                                                                                                                                                                                                                                               |
| **Failure mode**     | Fails closed — zero rows, not all rows. App connects as a non-owner role so the owner's implicit RLS bypass does not apply.                                                                                                                                      |
| **Invariants**       | INV-009.                                                                                                                                                                                                                                                         |
| **Tests**            | `security.test.ts` — cross-tenant decision, receipt, lease, signal key reads all return empty or 404.                                                                                                                                                            |
| **Gaps**             | None found. `api_credentials` is deliberately RLS-enabled-but-not-forced with **no app-role privileges at all**, reachable only through a `SECURITY DEFINER` prefix probe — because authentication is what _resolves_ the tenant and so cannot be tenant-scoped. |

**Section 44 is already satisfied.** RLS is present, forced, and adversarially
tested. No work needed.

## 3. Authority issuance — `POST /v1/authority-leases`

|                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Trust boundary**   | Human/admin → machine authority. This is where authority **enters** the system.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **Inputs**           | `agent_id`, `grant`, `ttl_seconds`, `grant_type`, `purpose`                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **Authority impact** | **Creates authority from nothing.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **Persistent state** | `authority_leases`, receipt.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **Failure mode**     | Requires `leases:write`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **Invariants**       | Should enforce `RequestedLease ⊆ IssuerAuthority`. It does not.                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **Tests**            | Agent cannot self-issue (no scope) — `security.test.ts`.                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **Gaps**             | **G-2 — CLOSED.** A principal holding `leases:write` could issue **arbitrary** authority: any action, any resource, any ceiling, with the whole containment lattice hanging beneath a root bounded only by an API scope. Now bounded by `issuance.ceilings` in the reviewed policy, per role, and roles are never unioned — a request must fit wholly inside one ceiling. `packages/core/src/issuance.ts`; `security.test.ts` › "issuance is bounded by the role, not by the scope" (9); adversarial **A4**. |

This is the single most important finding. The theorem's top relation —
`HumanAuthority ⊇ AgentAuthority` — is currently **unmodelled**. Everything
below it is enforced; the root is not.

## 4. Delegation — `POST /v1/delegations`

|                      |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | Agent → agent.                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **Inputs**           | `issuer_agent_id`, `delegate_agent_id`, `parent_lease_id`, `grant`, `ttl`                                                                                                                                                                                                                                                                                                                                                        |
| **Authority impact** | Narrows only. `containsGrant(parent, child)` must hold.                                                                                                                                                                                                                                                                                                                                                                          |
| **Persistent state** | `authority_leases` (child, with `parent_lease_id`), `delegations`, receipt.                                                                                                                                                                                                                                                                                                                                                      |
| **Failure mode**     | `422 DELEGATION_EXCEEDS_PARENT`, naming the axis that failed.                                                                                                                                                                                                                                                                                                                                                                    |
| **Invariants**       | INV-001. Also: an agent credential may only delegate **its own** authority.                                                                                                                                                                                                                                                                                                                                                      |
| **Tests**            | `delegation.test.ts` (14), `invariants.test.ts` randomised containment, `security.test.ts` escalation attempts.                                                                                                                                                                                                                                                                                                                  |
| **Gaps**             | **G-3 — CLOSED (via G-4).** Containment was checked at _creation_ only, so a containment bug or a direct database write yielded a child outliving its parent's envelope undetected. `verifyAuthorityInvariants()` now re-verifies the whole ancestry as a postcondition on every ALLOW. `packages/core/src/invariants.ts`; adversarial **A3** mutates a stored child grant directly in the database and the decision is refused. |

## 5. Authorization decision — `POST /v1/authorization/evaluate`

|                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | Agent claim → evaluated decision.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| **Inputs**           | action, resource, context, optional lease, declared intent, nonce                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| **Authority impact** | Selects a lease, applies decay, produces ALLOW/DENY/ESCALATE and — on ALLOW — an execution grant with an intent binding.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **Persistent state** | `authorization_requests`, `authorization_decisions` (append-only), `approval_requests`, receipt.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **Failure mode**     | Policy unavailable → per `failover_behavior`, never implicit ALLOW. Unknown action → 400 (closed catalog). Nonce reuse → 409.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **Invariants**       | INV-002, INV-004, INV-007, INV-008.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **Tests**            | `evaluate.test.ts` (33), `authorization.test.ts` (19), `invariants.test.ts`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| **Gaps**             | **G-4 — CLOSED.** Containment was _computed_ correctly and never _checked_, so a bug in the evaluator produced a wrong ALLOW with no alarm. `verifyAuthorityInvariants()` now runs as a postcondition on every ALLOW, on both the autonomous and post-approval paths, and a failure is `AUTHORITY_INVARIANT_VIOLATION` rather than a policy denial. `authority-invariants.test.ts` (16); adversarial **A3**.<br><br>**G-19 — CLOSED.** A signal could convert a hard DENY into an approvable escalation, so asserting _more_ risk produced a _more_ permissive outcome — a compromised source could summon an approval request for an action the agent's authority never covered. Only decay may now be rescued by a signal's approver. Found by the randomised containment property, not by review. |

Server-derived context (`counterparty_known`, `counterparty_status`,
`resource_known`) is deleted from the caller's body and re-derived from the
tenant's own register — an agent cannot declare its counterparty known.

## 6. Risk signals — `POST /v1/signals`

|                      |                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | External signal source → authority reduction.                                                                                                                                                                                                                                                                                                                                                     |
| **Inputs**           | subject, type, value, confidence, source, TTL, `event_id`, signature, key id                                                                                                                                                                                                                                                                                                                      |
| **Authority impact** | **Subtracts only.** `restrictGrant` cannot widen; a currency-incomparable ceiling leaves the existing one standing.                                                                                                                                                                                                                                                                               |
| **Persistent state** | `risk_signals`, `security_events` on rejection.                                                                                                                                                                                                                                                                                                                                                   |
| **Authentication**   | **Enrolment is mandatory.** Ed25519 only unless a deployment explicitly opts into legacy HMAC, which production cannot. The algorithm rule is enforced at verification, not only at registration, so a key predating the check or restored from a backup does not authenticate. ADR-0018.                                                                                                         |
| **Failure mode**     | Unenrolled source → 403 `SIGNAL_SOURCE_NOT_ENROLLED`. Bad signature → 403. Refused algorithm → 403 `ALGORITHM_NOT_PERMITTED`. Replayed `event_id` → 409. Each writes a durable security event on a transaction that survives the rejection.                                                                                                                                                       |
| **Invariants**       | INV-008, INV-018 (replay).                                                                                                                                                                                                                                                                                                                                                                        |
| **Tests**            | `signals.test.ts` (25) — enrolment, legacy-HMAC migration case with a positive control, containment under a compromised issuer, key-material non-disclosure, production boot refusals, permissive posture. `nextphase.test.ts` key lifecycle on Ed25519. `invariants.test.ts` randomised containment over 1500 signal sets. Adversarial A7.                                                       |
| **Gaps**             | **G-5 — CLOSED.** Three defects under one number: unenrolled sources were trusted, HMAC was the path every test actually exercised, and the algorithm rule was enforced at registration rather than at verification. See the expanded section below. **G-6 — OPEN.** No check that a source is _authorized for that signal type_ — any enrolled key can assert any signal type about any subject. |

## 7. Execution enforcement — `POST /v1/execute`

|                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | **The only path to the external system.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **Inputs**           | `decision_id`, presented `operation`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **Authority impact** | Consumes the grant. Cannot widen anything.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **Persistent state** | `execution_claims` (mutable lifecycle), `execution_attempts` (append-only), `authority_leases.consumed`, receipt.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| **Failure mode**     | Every refusal happens **before** provider contact. Provider throw/timeout → `UNKNOWN`, never `FAILED`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **Invariants**       | INV-003, INV-004, INV-005, INV-006, INV-007, INV-010.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **Tests**            | `enforcement.test.ts` (24) — mutation of amount/counterparty/reference/resource/action, ten-way race, live revocation, revoked ancestor, confused deputy, UNKNOWN, reconciliation listing. INV-010 proven by asserting **no claim row exists** after a refusal.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **Gaps**             | **G-16 — CLOSED (critical).** The claim and the grant consumption sat in the same transaction as the provider call, so a crash rolled both back with the money already gone and a retry paid twice. Now two transactions with the provider call strictly between them. Verified against a **real `SIGKILL`** of a real process at both crash points — `make recovery` **R1**, **R2**, **R3**; adversarial **A9**, **A10**, **A11**.<br><br>**G-7 — partially closed.** `verifyExecution()` now exists on the provider interface, so reconciliation can _resolve_ rather than only surface. It remains operator-driven by design: a reconciliation loop that runs twice is how an `UNKNOWN` becomes a double payment. **G-8 — OPEN.** No `HUMAN_REVIEW_REQUIRED` terminal state. |

## 8. Self-report execution — `POST /v1/executions`

|                      |                                                                                                                                                                        |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | None. The caller performed the action; Scrutexity records the claim.                                                                                                   |
| **Authority impact** | Consumes the grant on an unverified assertion.                                                                                                                         |
| **Invariants**       | Verifies nothing about the operation — it never sees one.                                                                                                              |
| **Tests**            | Marked `enforced = false`; asserted in `enforcement.test.ts`.                                                                                                          |
| **Gaps**             | **G-9.** Retained for integrations that cannot route side effects through a provider. It is a documented non-control and should be removed when that stops being true. |

## 9. Approvals — `POST /v1/approvals`

|                      |                                                                                                                                                                                                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | Human → authority release.                                                                                                                                                                                                                           |
| **Authority impact** | Converts ESCALATE into a new ALLOW decision that supersedes it. Never mutates the original.                                                                                                                                                          |
| **Failure mode**     | `requireHuman` — an agent principal can never approve. Self-approval refused. Expired approval refused.                                                                                                                                              |
| **Invariants**       | INV-007. Approved context is bound into the new grant's `binding_hash` (section 47).                                                                                                                                                                 |
| **Tests**            | `authorization.test.ts`, `security.test.ts` self-approval and agent-approval refusals, `nextphase.test.ts` TOCTOU.                                                                                                                                   |
| **Gaps**             | **G-10 — CLOSED (via G-12).** Approval expiry compared `expires_at` against `Date.now()` on the API node. Every validity comparison now reads one authoritative instant from the database. `services/api/test/temporal.test.ts` approval skew cases. |

## 10. Policy lifecycle

|                      |                                                                                                       |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| **Authority impact** | Defines the rules every decision runs under.                                                          |
| **Persistent state** | `policy_versions`, immutable content + `content_hash`.                                                |
| **Failure mode**     | Only an `APPROVED` version may activate; integrity re-checked before it takes effect; `requireHuman`. |
| **Tests**            | `policy.test.ts` (23), review/activation flows.                                                       |
| **Gaps**             | None material.                                                                                        |

**Section 20 and section 46 are largely already satisfied.** One-active-version
is a **partial unique index** (`policy_versions_one_active_idx ON (policy_id)
WHERE status = 'ACTIVE'`) — enforced by the database, not by application logic,
so the concurrent-activation race cannot produce two active versions. The policy
cache is keyed by version id and re-verified against the stored hash on **every**
load, not only on a miss, so a tampered row is caught while warm and there is no
mutable "latest" key. Decisions pin `policy_version_id` **and** `policy_hash`.

## 11. Evidence

|                      |                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Component**        | `receipts` (per-tenant hash chain, Ed25519), `security_events`, append-only triggers raising `42501`                                                                                                                                                                                                                                                                                                                                                        |
| **Authority impact** | None. Records it.                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **Failure mode**     | Chain head locked `FOR UPDATE`; a gap or a rewrite is detectable.                                                                                                                                                                                                                                                                                                                                                                                           |
| **Invariants**       | INV-011.                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| **Tests**            | `receipts.test.ts` (12), tamper detection, chain continuity.                                                                                                                                                                                                                                                                                                                                                                                                |
| **Gaps**             | **G-11 — OPEN.** No external anchor: an attacker with database write **and** the signing key could rewrite the whole chain consistently. The chain is tamper-**evident**, not tamper-**proof**. **G-13 — OPEN.** No offline-verifiable export bundle; receipts verify one at a time. Both are designed in [ADR-0021](decisions/0021-evidence-anchoring.md) and neither is built — a proposed ADR is not a mitigation, and they ship together or not at all. |

## 12. Time

|               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Component** | Every expiry comparison                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **Gaps**      | **G-12 — CLOSED.** Rows were _written_ with the database clock (`now()`) and every expiry _compared_ against the API node's clock, across eleven decision sites — so a skewed node extended or shortened authority, and the same lease gave different answers on different replicas. `securityNow()` now reads `transaction_timestamp()` once per decision and every validity comparison uses it. 20 tests prove an API node skewed an hour in either direction changes no answer; adversarial **A1**, **A6**.<br><br>**Not operationally verified:** the database host's clock is now a security dependency. NTP step-event alerting and the no-read-replica rule are deployment controls a partner's infrastructure must confirm — see `docs/design-partner/integration-runbook.md` §5. |

---

## Gaps, ranked

Every gap carries all five statuses. They are not the same question, and
collapsing them is how a control ends up believed rather than verified:

| Stage                      | Means                                                                                                      |
| -------------------------- | ---------------------------------------------------------------------------------------------------------- |
| **Discovered**             | Someone noticed it. Nothing more.                                                                          |
| **Validated**              | Reproduced against running code. It is real, not a reading of the source.                                  |
| **Fixed**                  | The code changed.                                                                                          |
| **Regression-tested**      | A named test or adversarial scenario fails if the fix is removed. The bar that survives a refactor.        |
| **Operationally verified** | Confirmed in a deployment that resembles production. Nothing here can reach this without a design partner. |

`—` in the last column is honest rather than pending: it means this project has
no production deployment, so no fix has been operationally verified by anyone.

| #        | Gap                                                                                                        | Severity     | Disc. | Valid. |      Fixed      | Regression-tested                                                                                                                    | Op. verified            |
| -------- | ---------------------------------------------------------------------------------------------------------- | ------------ | :---: | :----: | :-------------: | ------------------------------------------------------------------------------------------------------------------------------------ | ----------------------- |
| G-2      | `leases:write` could issue unbounded authority                                                             | Critical     |  ✅   |   ✅   |       ✅        | `security.test.ts` › "issuance is bounded by the role, not by the scope" (9); adversarial **A4**                                     | —                       |
| G-4      | No runtime invariant assertion before ALLOW                                                                | High         |  ✅   |   ✅   |       ✅        | `authority-invariants.test.ts` (16); `security.test.ts` › "the authority invariants are enforced at runtime" (5); adversarial **A3** | —                       |
| G-14     | `read` scope never enforced; reads not subject-scoped                                                      | High         |  ✅   |   ✅   |       ✅        | `security.test.ts` › "an agent cannot read the control plane" (2) + "…another agent’s records" (6); adversarial **A5**               | —                       |
| G-3      | Containment checked at creation only                                                                       | Medium       |  ✅   |   ✅   |  ✅ (via G-4)   | `invariants.test.ts` containment property (2,000 cases)                                                                              | —                       |
| **G-12** | **Expiry judged on the API clock, rows written on the DB clock**                                           | **High**     |  ✅   |   ✅   |       ✅        | `packages/core/test/temporal.test.ts` + `services/api/test/temporal.test.ts` (20); adversarial **A1**, **A6**                        | **NOT YET — see below** |
| **G-16** | **The execution claim was rolled back with the provider call inside one transaction**                      | **Critical** |  ✅   |   ✅   |       ✅        | `enforcement.test.ts` crash cases; adversarial **A9**, **A10**, **A11**; recovery **R1**, **R2**, **R3** (real SIGKILL)              | **NOT YET — see below** |
| G-5      | HMAC signal secrets in plaintext; unenrolled sources trusted; algorithm rule enforced at registration only | High         |  ✅   |   ✅   |       ✅        | `services/api/test/signals.test.ts` (25); `packages/core/test/nextphase.test.ts`; adversarial **A7**                                 | **NOT YET — see below** |
| G-19     | A signal could make an uncovered request approvable                                                        | High         |  ✅   |   ✅   |       ✅        | `invariants.test.ts` signal containment property (1,500 cases) + named regression (3); `policy-pack.test.ts`                         | —                       |
| G-10     | Approval expiry compared against the API node's clock                                                      | High         |  ✅   |   ✅   |  ✅ (via G-12)  | `services/api/test/temporal.test.ts` approval skew cases                                                                             | —                       |
| G-7      | Reconciliation surfaces UNKNOWN but cannot resolve it                                                      | Medium       |  ✅   |   ✅   |        —        | —                                                                                                                                    | —                       |
| G-6      | Signal source not bound to signal type                                                                     | Medium       |  ✅   |   ✅   |        —        | —                                                                                                                                    | —                       |
| G-15     | No rate limiting anywhere                                                                                  | Medium       |  ✅   |   ✅   |        —        | —                                                                                                                                    | —                       |
| G-11     | No external evidence anchor                                                                                | Medium       |  ✅   |   ✅   |        —        | —                                                                                                                                    | —                       |
| G-1      | Bearer token only; no workload-bound identity                                                              | Medium       |  ✅   |   ✅   |        —        | —                                                                                                                                    | —                       |
| G-8      | No `HUMAN_REVIEW_REQUIRED` state                                                                           | Low          |  ✅   |   ✅   |        —        | —                                                                                                                                    | —                       |
| G-13     | No offline-verifiable evidence export                                                                      | Low          |  ✅   |   ✅   |        —        | —                                                                                                                                    | —                       |
| G-9      | Unenforced self-report path still exists (`POST /v1/executions`)                                           | Low          |  ✅   |   ✅   | n/a — by design | `api-quickstart.md` documents it as not enforcement                                                                                  | —                       |

### The one gap that gates production

**Production key custody is available, and has never been exercised.**
`SECRET_PROVIDER=agent` reads the signing key from a tmpfs projection written by
a secrets agent — the Secrets Store CSI driver, External Secrets Operator, Vault
Agent — which is how AWS, GCP, Azure and Vault are actually consumed by a
container. It adds no cloud SDK, and it is checked rather than declared: the
mount must be tmpfs or ramfs and the file must not be readable beyond its owner,
or the process refuses the key. See `docs/key-management.md` and
`deploy/k8s/secretproviderclass.example.yaml`.

`SECRET_PROVIDER=kms` remains a shape with nothing behind it and throws on every
read. It stays because envelope encryption or signing inside an HSM is a
stronger posture than `agent` and is worth building when a partner asks, not
before.

What has not happened is the part that matters: **no deployment of this code has
ever started in a production posture.** The custody path is implemented and
unit-tested — including that it refuses a persistent mount and a
world-readable key — and it has never held a real key issued by a real manager
in a real cluster. Every "Fixed" and "Regression-tested" above is
established against development and test configurations. Nothing in the
Operationally verified column can change until a design partner's infrastructure
runs it. The seam is no longer a guess, though: it is a `SecretProviderClass`
and two environment variables.

Tracked as a deployment prerequisite, not a gap number, because there is no
defect to fix — there is a decision only a partner can make.

### G-12, and what "operationally verified" would require

The implementation makes the database the single authority for every validity
decision, and twenty tests prove an API node skewed an hour in either direction
cannot change any answer. That is as far as code can go.

What is **not** established, and cannot be from here:

- that the database host's clock is synchronised and not silently stepped by a
  hypervisor or a VM migration;
- that a future read replica has not reintroduced a second clock;
- that `now()` on the production primary is what the deployment believes it is.

Those are checks a design partner's infrastructure has to answer. Recording
them as open is the difference between "we fixed it" and "we fixed the part we
control".

### G-16 — now proven against a real process death

The adversarial suite's A9 and A10 establish that the recovery logic is correct
_given_ the state a crash leaves behind. They construct that state by rewinding
the database, which is fast and is the right shape for a test that runs on
every commit — but it assumes the answer to the question it is asking. Nothing
in it establishes that a real crash produces that state.

`make recovery` establishes it. The API runs as a genuine child process and is
destroyed with SIGKILL — no signal handler, no drain, no opportunity to write
anything — at two instants, and a **different** process is then started against
the same database and asked to do the work again.

The provider's external system is a table in its own schema, on its own
connection, committed as it goes, exactly as a bank's ledger is. That is the
mechanism, not a convenience: a SIGKILL takes every in-memory record with it,
so the only way to know what the outside world saw is to read something that
outlived the process.

| Scenario | Killed                               | Money moved | Retry                    |
| -------- | ------------------------------------ | ----------- | ------------------------ |
| R1       | after the claim, before the payment  | nothing     | 409 EXECUTION_UNRESOLVED |
| R2       | after the payment, before settlement | $25,000     | 409 EXECUTION_UNRESOLVED |
| R3       | not killed (control)                 | $25,000     | 200 replayed             |

R1 and R2 are indistinguishable to Scrutexity, and that is the point: a system
that could tell them apart from its own records would not need reconciliation.
R3 is the control — a settled claim replays rather than refusing, so the 409s
are the crash state speaking and not a blanket refusal to retry.

The grants are single-use, so "the grant is still spent" is an assertion about
durable state rather than about the claim row alone: it proves the consumption
committed in the same transaction as the claim, which is the pair that has to
be atomic for authority not to become spendable again when a process dies.

Falsified rather than assumed: disabling the unresolved refusal makes R1 and R2
fail and R3 still pass.

### G-5, expanded — **closed**, with one thing still not established

Three separate defects sat under one gap number, and only the third was the one
the gap was originally written about.

1. **A source with no registered key was trusted.** `verifySignal` reported
   `no_key_configured` and the caller treated it as non-fatal, so anyone holding
   `signals:write` could assert any signal about any subject from any source
   name they invented. A signal reduces authority, so this was a denial of
   service against a legitimate agent delivered through the control plane.

2. **HMAC was the path everything actually used.** Every integration test, and
   the only end-to-end exercise of the key lifecycle, ran on HMAC. The suite was
   proving the algorithm the product says it prefers not to use, and would not
   have noticed if the Ed25519 path had broken.

3. **The algorithm rule was enforced at registration.** Production refused to
   _register_ an HMAC key. A row written before that check existed, or restored
   from a backup taken before it, still authenticated signals.

All three are closed: enrolment is mandatory, `SIGNAL_LEGACY_HMAC` defaults to
`refused` in development as well as production, and the permitted-algorithm
check runs where every signal passes. ADR-0018 has the reasoning and the
rotation runbook.

**Not established, and not establishable from here:** production requires
`SECRET_PROVIDER=kms`, and `KmsSecretProvider` is a shape with no key manager
behind it. It throws on every read, so a deployment that selects it without
wiring one fails at boot rather than falling back to local custody silently.
That is the correct failure, but it means **no deployment of this code has ever
started in a production posture.** Wiring a specific key manager is a
constructor argument and an SDK dependency, and it happens when a design
partner's infrastructure says which one.

### G-19 — a signal could make an uncovered request approvable — **closed**

Found by the randomised containment property written for G-5, not by review.

A lease denominated in EUR does not cover a USD wire. Policy named no approver
for the ordinary case, so the request was a hard DENY: nobody could supply the
difference. Raising the fraud score above the escalation threshold matched a
rule that _does_ name a treasurer — and the same authority shortfall became
something a treasurer could approve.

Asserting **more** risk produced a **more** permissive outcome. A compromised
signal source could summon an approval request for any action the agent's
authority never covered, and use the approver as a confused deputy.

The fix separates two shortfalls. When the base grant covered the attempt and a
signal shrank it, the human is restoring authority the agent genuinely held, and
an approver named by that signal is legitimate — that is authority decay working
as designed. When the agent's own authority falls short, only an approver policy
would have named _without any signal_ can supply it.

This is the second defect found by a mechanism built to look for a different
one, after G-16. The property is now asserted over 1500 randomised signal sets
in `packages/core/test/invariants.test.ts`, and the specific case is pinned as a
named regression with a positive control proving decay still escalates.

### G-14, expanded — **closed**

`SCOPES.read` was declared in `auth.ts`, granted by the seed to every
credential, and **checked by nothing**. Eleven GET routes called
`db.withTenant(...)` with no scope check at all, so an **agent credential could
read `/v1/policy-versions`** and retrieve the full policy document that governs
it — thresholds, approver roles, decay rules.

That defeated a control the system otherwise takes seriously: refusals are
written not to leak policy internals, and the corrective handshake is
deliberately narrow so a denied agent learns the next legitimate step and
nothing more. An agent that could `GET` the policy had all of it. The same hole
exposed `/v1/security-events` — the forensic record of attacks, including that
agent's own — and `/v1/signal-keys`.

Auditing it surfaced a second, related hole the original sweep had not named:
per-resource reads were tenant-scoped but **not subject-scoped**, so any agent
holding a decision, trace, receipt or lease id could read another agent's
record. That is OWASP API #1, broken object-level authorization, and ids appear
in URLs and logs.

**The fix, in two gates.** `requireOperatorRead` demands the new `audit:read`
scope _and_ refuses agent principals outright — either alone would be too weak,
since the scope keeps out credentials never meant to audit while the type check
survives a misconfigured grant. `assertMayReadSubject` narrows per-resource
reads to the agent that owns them, answering **404 rather than 403** because a
403 confirms the record exists and turns the endpoint into an oracle for
sweeping another agent's activity. Humans and services are not narrowed: an
operator responding to an incident has to read across agents.

Fifteen adversarial tests in `security.test.ts`, including one asserting a
refusal body contains no policy fragment, and one asserting an operator can
still read everything — a control nobody can operate gets turned off.

---

## What the audit did **not** find

Stated explicitly, because a map that only lists problems misleads about where
the system stands:

- Tenant isolation is enforced at the database layer, forced, and adversarially
  tested (section 44 — **done**).
- One-active-policy-version is a database constraint, and the policy cache is
  version-keyed with per-load integrity verification (sections 20, 46 —
  **substantially done**).
- Exactly-once grant consumption is a single guarded `INSERT`, proven under a
  real ten-way race (INV-006 — **done**).
- Intent binding, live revocation including ancestors, and no-provider-contact-
  before-authorization are implemented and adversarially tested (INV-004,
  INV-005, INV-010 — **done**).
- `UNKNOWN` is modelled, never collapsed into `FAILED`, and never auto-retried
  (section 6 — **done**; resolution is G-7).
- The simulated provider is refused at boot in production (section 26 —
  **done**).
- Approved context is bound into the execution grant (section 47 — **done**).

## Claims that must be corrected in the docs

Section 37 says comments are not controls. Two current claims fail that test:

1. ~~`auth.ts` says "agent credentials deliberately cannot administer the
   control plane". True for writes, **false for reads**.~~ **Corrected**: the
   comment now names the two functions and the test file that make it true.
2. Any statement that evidence is tamper-_proof_ rather than tamper-_evident_.
   With database write access and the signing key, the chain can be rewritten
   consistently (G-11). The honest claim is "cryptographically tamper-evident
   and independently verifiable".

---

## Order of work

1. ~~**G-14**~~ — **done.** `audit:read` plus subject scoping; also closed the
   unnamed object-level hole the first sweep missed.
2. ~~**G-4**~~ — **done.** Postcondition on every ALLOW, on both the
   autonomous and the post-approval path; closed G-3 with it.
3. ~~**G-2**~~ — **done.** Ceilings live in the policy, so changing who may
   grant what needs a reviewed, hash-checked, dual-control policy change.
4. ~~**G-12**~~ — **done.** Database time for every expiry comparison, with a
   skew test in both directions.
5. ~~**G-16**~~ — **done.** The execution claim commits before the provider is
   called; found by asking how long the authorization transaction was open.
6. ~~**G-5**~~ — **done.** Mandatory enrolment, Ed25519 by default everywhere,
   the algorithm rule enforced at verification, and a secret provider that
   production cannot satisfy with local custody. Closing it surfaced **G-19**.
7. G-15, G-6, G-7, G-1, G-11, G-13 in that order.
