# Security surface map

An audit of every place authority is created, changed, checked or consumed, and
of every boundary an attacker can reach. Produced before the design-partner
hardening pass; the gaps at the bottom are what that pass is for.

Method: enumerate the routes, then for each one trace what it can do to
authority, what it persists, how it fails, and which test proves the claim. A
control with no test is listed as a gap, not as a control.

**Status at audit time:** 428 tests, 14 files, clean CI.

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

|                      |                                                                                                                                                                                                                                                                             |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | Human/admin → machine authority. This is where authority **enters** the system.                                                                                                                                                                                             |
| **Inputs**           | `agent_id`, `grant`, `ttl_seconds`, `grant_type`, `purpose`                                                                                                                                                                                                                 |
| **Authority impact** | **Creates authority from nothing.**                                                                                                                                                                                                                                         |
| **Persistent state** | `authority_leases`, receipt.                                                                                                                                                                                                                                                |
| **Failure mode**     | Requires `leases:write`.                                                                                                                                                                                                                                                    |
| **Invariants**       | Should enforce `RequestedLease ⊆ IssuerAuthority`. It does not.                                                                                                                                                                                                             |
| **Tests**            | Agent cannot self-issue (no scope) — `security.test.ts`.                                                                                                                                                                                                                    |
| **Gaps**             | **G-2 (critical).** A principal holding `leases:write` can issue **arbitrary** authority: any action, any resource, any ceiling. There is no `IssuerAuthority` to contain it against. The whole containment lattice sits below a root that is bounded only by an API scope. |

This is the single most important finding. The theorem's top relation —
`HumanAuthority ⊇ AgentAuthority` — is currently **unmodelled**. Everything
below it is enforced; the root is not.

## 4. Delegation — `POST /v1/delegations`

|                      |                                                                                                                                                                                                                           |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | Agent → agent.                                                                                                                                                                                                            |
| **Inputs**           | `issuer_agent_id`, `delegate_agent_id`, `parent_lease_id`, `grant`, `ttl`                                                                                                                                                 |
| **Authority impact** | Narrows only. `containsGrant(parent, child)` must hold.                                                                                                                                                                   |
| **Persistent state** | `authority_leases` (child, with `parent_lease_id`), `delegations`, receipt.                                                                                                                                               |
| **Failure mode**     | `422 DELEGATION_EXCEEDS_PARENT`, naming the axis that failed.                                                                                                                                                             |
| **Invariants**       | INV-001. Also: an agent credential may only delegate **its own** authority.                                                                                                                                               |
| **Tests**            | `delegation.test.ts` (14), `invariants.test.ts` randomised containment, `security.test.ts` escalation attempts.                                                                                                           |
| **Gaps**             | **G-3.** Containment is checked at _creation_ only. It is never re-verified at decision or execution time, so a containment bug or a direct database write yields a child that outlives its parent's envelope undetected. |

## 5. Authorization decision — `POST /v1/authorization/evaluate`

|                      |                                                                                                                                                                                                                                                                         |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | Agent claim → evaluated decision.                                                                                                                                                                                                                                       |
| **Inputs**           | action, resource, context, optional lease, declared intent, nonce                                                                                                                                                                                                       |
| **Authority impact** | Selects a lease, applies decay, produces ALLOW/DENY/ESCALATE and — on ALLOW — an execution grant with an intent binding.                                                                                                                                                |
| **Persistent state** | `authorization_requests`, `authorization_decisions` (append-only), `approval_requests`, receipt.                                                                                                                                                                        |
| **Failure mode**     | Policy unavailable → per `failover_behavior`, never implicit ALLOW. Unknown action → 400 (closed catalog). Nonce reuse → 409.                                                                                                                                           |
| **Invariants**       | INV-002, INV-004, INV-007, INV-008.                                                                                                                                                                                                                                     |
| **Tests**            | `evaluate.test.ts` (33), `authorization.test.ts` (19), `invariants.test.ts`.                                                                                                                                                                                            |
| **Gaps**             | **G-4.** No runtime assertion that the produced decision actually satisfies `effective ⊆ granted` before ALLOW is returned. Containment is _computed_ correctly; it is never _checked_ as a postcondition. A bug in the evaluator produces a wrong ALLOW with no alarm. |

Server-derived context (`counterparty_known`, `counterparty_status`,
`resource_known`) is deleted from the caller's body and re-derived from the
tenant's own register — an agent cannot declare its counterparty known.

## 6. Risk signals — `POST /v1/signals`

|                      |                                                                                                                                                                                                                                                                                             |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | External signal source → authority reduction.                                                                                                                                                                                                                                               |
| **Inputs**           | subject, type, value, confidence, source, TTL, `event_id`, signature, key id                                                                                                                                                                                                                |
| **Authority impact** | **Subtracts only.** `restrictGrant` cannot widen; a currency-incomparable ceiling leaves the existing one standing.                                                                                                                                                                         |
| **Persistent state** | `risk_signals`, `security_events` on rejection.                                                                                                                                                                                                                                             |
| **Failure mode**     | Bad signature → 403 + security event. Replayed `event_id` → 409 + security event.                                                                                                                                                                                                           |
| **Invariants**       | INV-008, INV-018 (replay).                                                                                                                                                                                                                                                                  |
| **Tests**            | `nextphase.test.ts` signal auth + rotation, `invariants.test.ts` property test that decay only narrows.                                                                                                                                                                                     |
| **Gaps**             | **G-5.** HMAC shared secrets are stored in plaintext in `signal_signing_keys`. Flagged in the migration itself as requiring resolution before real data. **G-6.** No check that a source is _authorized for that signal type_ — any valid key can assert any signal type about any subject. |

## 7. Execution enforcement — `POST /v1/execute`

|                      |                                                                                                                                                                                                                                                                 |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | **The only path to the external system.**                                                                                                                                                                                                                       |
| **Inputs**           | `decision_id`, presented `operation`                                                                                                                                                                                                                            |
| **Authority impact** | Consumes the grant. Cannot widen anything.                                                                                                                                                                                                                      |
| **Persistent state** | `execution_claims` (mutable lifecycle), `execution_attempts` (append-only), `authority_leases.consumed`, receipt.                                                                                                                                               |
| **Failure mode**     | Every refusal happens **before** provider contact. Provider throw/timeout → `UNKNOWN`, never `FAILED`.                                                                                                                                                          |
| **Invariants**       | INV-003, INV-004, INV-005, INV-006, INV-007, INV-010.                                                                                                                                                                                                           |
| **Tests**            | `enforcement.test.ts` (24) — mutation of amount/counterparty/reference/resource/action, ten-way race, live revocation, revoked ancestor, confused deputy, UNKNOWN, reconciliation listing. INV-010 proven by asserting **no claim row exists** after a refusal. |
| **Gaps**             | **G-7.** `UNKNOWN` has a listing endpoint but no `verifyExecution()` on the provider interface, so reconciliation cannot yet _resolve_ — only surface. **G-8.** No `HUMAN_REVIEW_REQUIRED` terminal state.                                                      |

## 8. Self-report execution — `POST /v1/executions`

|                      |                                                                                                                                                                        |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Trust boundary**   | None. The caller performed the action; Scrutexity records the claim.                                                                                                   |
| **Authority impact** | Consumes the grant on an unverified assertion.                                                                                                                         |
| **Invariants**       | Verifies nothing about the operation — it never sees one.                                                                                                              |
| **Tests**            | Marked `enforced = false`; asserted in `enforcement.test.ts`.                                                                                                          |
| **Gaps**             | **G-9.** Retained for integrations that cannot route side effects through a provider. It is a documented non-control and should be removed when that stops being true. |

## 9. Approvals — `POST /v1/approvals`

|                      |                                                                                                                    |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Trust boundary**   | Human → authority release.                                                                                         |
| **Authority impact** | Converts ESCALATE into a new ALLOW decision that supersedes it. Never mutates the original.                        |
| **Failure mode**     | `requireHuman` — an agent principal can never approve. Self-approval refused. Expired approval refused.            |
| **Invariants**       | INV-007. Approved context is bound into the new grant's `binding_hash` (section 47).                               |
| **Tests**            | `authorization.test.ts`, `security.test.ts` self-approval and agent-approval refusals, `nextphase.test.ts` TOCTOU. |
| **Gaps**             | **G-10.** Approval expiry compares `expires_at` against `Date.now()` on the API node — see G-12.                   |

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

|                      |                                                                                                                                                                                 |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Component**        | `receipts` (per-tenant hash chain, Ed25519), `security_events`, append-only triggers raising `42501`                                                                            |
| **Authority impact** | None. Records it.                                                                                                                                                               |
| **Failure mode**     | Chain head locked `FOR UPDATE`; a gap or a rewrite is detectable.                                                                                                               |
| **Invariants**       | INV-011.                                                                                                                                                                        |
| **Tests**            | `receipts.test.ts` (12), tamper detection, chain continuity.                                                                                                                    |
| **Gaps**             | **G-11.** No external anchor — an attacker with database write **and** the signing key can rewrite the whole chain consistently. **G-13.** No offline-verifiable export bundle. |

## 12. Time

|               |                                                                                                                                                                                                                                                                                                                                                          |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Component** | Every expiry comparison                                                                                                                                                                                                                                                                                                                                  |
| **Gaps**      | **G-12 (real).** Rows are _written_ with the database clock (`now()`), but every expiry is _compared_ against the API node's clock (`new Date()` / `Date.now()`) — in `auth.ts:75`, `approvals.ts:45`, `execution.ts:57`, `enforce.ts:122`, `authorization.ts:89`. A skewed API node extends or shortens authority. No documented maximum skew, no test. |

---

## Gaps, ranked

| #        | Gap                                                                                                                       | Severity     | Section  |
| -------- | ------------------------------------------------------------------------------------------------------------------------- | ------------ | -------- |
| **G-2**  | `leases:write` can issue unbounded authority; no `IssuerAuthority`                                                        | **Critical** | 19       |
| **G-4**  | No runtime invariant assertion before ALLOW                                                                               | **High**     | 11, 12   |
| **G-14** | `SCOPES.read` defined and granted but **never enforced** — every GET open to any authenticated principal, agents included | **High**     | 32, 55   |
| **G-12** | Expiry compared against API-node clock, not database time                                                                 | **High**     | 45       |
| **G-5**  | HMAC signal secrets stored in plaintext                                                                                   | **High**     | 16, 27   |
| **G-3**  | Delegation containment checked at creation only                                                                           | Medium       | 11       |
| **G-7**  | Reconciliation can surface UNKNOWN but not resolve it                                                                     | Medium       | 7        |
| **G-6**  | Signal source not bound to signal type                                                                                    | Medium       | 16       |
| **G-15** | No rate limiting anywhere                                                                                                 | Medium       | 49       |
| **G-11** | No external evidence anchor                                                                                               | Medium       | Threat D |
| **G-1**  | Bearer token only; no workload-bound identity                                                                             | Medium       | 43       |
| **G-8**  | No `HUMAN_REVIEW_REQUIRED` state                                                                                          | Low          | 7        |
| **G-13** | No offline-verifiable evidence export                                                                                     | Low          | 52       |
| **G-9**  | Unenforced self-report path still exists                                                                                  | Low          | —        |

### G-14, expanded

`SCOPES.read` is declared in `auth.ts`, granted by the seed to every
credential, and **checked by nothing**. Eleven GET routes call
`db.withTenant(...)` with no scope check at all. The consequence is that an
**agent credential can read `/v1/policy-versions`** and retrieve the full policy
document that governs it — including thresholds, approver roles and decay
rules.

That directly defeats a control the system otherwise takes seriously: refusals
are carefully written not to leak policy internals, and the corrective handshake
is deliberately constrained so a denied agent learns the next legitimate step
and nothing more. An agent that can simply `GET` the policy has all of it.

The same hole exposes `/v1/security-events` — the forensic record of attacks,
including attacks by that agent — and `/v1/signal-keys` to any agent in the
tenant.

This is OWASP API #5, broken function-level authorization, and it is the
cheapest of the high-severity fixes.

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

1. `auth.ts` says "agent credentials deliberately cannot administer the control
   plane". True for writes, **false for reads** (G-14).
2. Any statement that evidence is tamper-_proof_ rather than tamper-_evident_.
   With database write access and the signing key, the chain can be rewritten
   consistently (G-11). The honest claim is "cryptographically tamper-evident
   and independently verifiable".

---

## Order of work

1. **G-14** — enforce `read`, and split agent-readable from operator-readable.
   Cheapest high-severity fix; one afternoon.
2. **G-4** — `verifyAuthorityInvariants()` as a runtime security boundary with
   `AUTHORITY_INVARIANT_VIOLATION`. Also closes G-3 by re-verifying containment
   per decision rather than only at creation.
3. **G-2** — issuable authority. The largest design change, and the one that
   makes the top of the theorem true rather than assumed.
4. **G-12** — database time for every expiry comparison, with a skew test.
5. **G-5** — Ed25519-only in production; secret provider abstraction.
6. G-15, G-6, G-7, G-1, G-11, G-13 in that order.
