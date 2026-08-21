# Security surface map

An audit of every place authority is created, changed, checked or consumed, and
of every boundary an attacker can reach. Produced before the design-partner
hardening pass; the gaps at the bottom are what that pass is for.

Method: enumerate the routes, then for each one trace what it can do to
authority, what it persists, how it fails, and which test proves the claim. A
control with no test is listed as a gap, not as a control.

**Status at audit time:** 428 tests, 14 files, clean CI.
**Current:** 494 tests, 17 files.

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

| #        | Gap                                                              | Severity | Validated | Fixed        | Regression-tested | Operationally verified  |
| -------- | ---------------------------------------------------------------- | -------- | --------- | ------------ | ----------------- | ----------------------- |
| G-2      | `leases:write` could issue unbounded authority                   | Critical | ✅        | ✅           | ✅ 9 tests        | —                       |
| G-4      | No runtime invariant assertion before ALLOW                      | High     | ✅        | ✅           | ✅ 16 + 5 tests   | —                       |
| G-14     | `read` scope never enforced; reads not subject-scoped            | High     | ✅        | ✅           | ✅ 15 tests       | —                       |
| G-3      | Containment checked at creation only                             | Medium   | ✅        | ✅ (via G-4) | ✅                | —                       |
| **G-12** | **Expiry judged on the API clock, rows written on the DB clock** | **High** | ✅        | ✅           | ✅ 20 tests       | **NOT YET — see below** |
| G-5      | HMAC signal secrets stored in plaintext                          | High     | ✅        | —            | —                 | —                       |
| G-7      | Reconciliation surfaces UNKNOWN but cannot resolve it            | Medium   | ✅        | —            | —                 | —                       |
| G-6      | Signal source not bound to signal type                           | Medium   | ✅        | —            | —                 | —                       |
| G-15     | No rate limiting anywhere                                        | Medium   | ✅        | —            | —                 | —                       |
| G-11     | No external evidence anchor                                      | Medium   | ✅        | —            | —                 | —                       |
| G-1      | Bearer token only; no workload-bound identity                    | Medium   | ✅        | —            | —                 | —                       |
| G-8      | No `HUMAN_REVIEW_REQUIRED` state                                 | Low      | ✅        | —            | —                 | —                       |
| G-13     | No offline-verifiable evidence export                            | Low      | ✅        | —            | —                 | —                       |
| G-9      | Unenforced self-report path still exists                         | Low      | ✅        | n/a          | n/a               | —                       |

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
4. **G-12** — database time for every expiry comparison, with a skew test.
5. **G-5** — Ed25519-only in production; secret provider abstraction.
6. G-15, G-6, G-7, G-1, G-11, G-13 in that order.
