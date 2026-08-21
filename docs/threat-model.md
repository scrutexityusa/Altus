# Threat model

Structured by attacker, because that is how the reasoning actually goes. Every
row marked ✅ has a test in `services/api/test/security.test.ts` or
`packages/core/test/`.

## 1. Compromised agent

The agent's code is running, its credential is valid, and the attacker controls
what it sends.

| Attempt                                      | Outcome                                                   | Tested |
| -------------------------------------------- | --------------------------------------------------------- | ------ |
| Issue itself a broader lease                 | `403 FORBIDDEN` — no `leases:write` scope                 | ✅     |
| Author or activate policy                    | `403 FORBIDDEN` — no `policies:write` scope               | ✅     |
| Approve its own escalation                   | `403 FORBIDDEN` — approval requires a human principal     | ✅     |
| Authorize as another agent                   | `403 FORBIDDEN` — credential binds the principal          | ✅     |
| Execute another agent's ALLOW                | `403 FORBIDDEN` — decision agent compared to caller       | ✅     |
| Reuse an expired lease                       | `DENY / AUTHORITY_EXPIRED` — expiry derived at read       | ✅     |
| Reuse a revoked lease                        | `DENY / AUTHORITY_REVOKED` — no grace period              | ✅     |
| Use a lease whose _parent_ was revoked       | `DENY / AUTHORITY_REVOKED` — ancestry walked per decision | ✅     |
| Replay an authorization request              | `409 REPLAY_DETECTED` — single-use nonce                  | ✅     |
| Replay an execution grant                    | `409 REPLAY_DETECTED` — unique constraint                 | ✅     |
| Present an expired execution grant           | `403 AUTHORITY_EXPIRED`                                   | ✅     |
| Assert `counterparty_known: true`            | Discarded; derived from the tenant register               | ✅     |
| Send `amount` as a float to slip a threshold | `400 INVALID_REQUEST`                                     | ✅     |
| Typo an action to fall through to a default  | `400 INVALID_REQUEST` — closed catalog                    | ✅     |
| Omit `amount` on a money-bearing action      | `400 INVALID_REQUEST`                                     | ✅     |
| Smuggle SQL through `counterparty_id`        | Compared, never executed; parameterised throughout        | ✅     |
| Send a 300KB context                         | `413`                                                     | ✅     |
| Add an unknown request field                 | `400` — strict schemas, no silent ignore                  | ✅     |

## 2. Compromised agent attempting delegation abuse

| Attempt                                                    | Outcome                                                     | Tested |
| ---------------------------------------------------------- | ----------------------------------------------------------- | ------ |
| Delegate a raised amount ceiling                           | `422 DELEGATION_EXCEEDS_PARENT`                             | ✅     |
| Delegate while _dropping_ a constraint                     | `422` — omission is not a widening path                     | ✅     |
| Delegate a wildcard resource against an enumerated parent  | `422`                                                       | ✅     |
| Delegate a resource type the parent never held             | `422`                                                       | ✅     |
| Delegate `wire.execute`                                    | `403 ACTION_NOT_DELEGABLE` — policy forbids it at any depth | ✅     |
| Delegate a ceiling in another currency to dodge comparison | `422` — incomparable, not converted                         | ✅     |
| Delegate from a lease it does not hold                     | `403 NOT_LEASE_HOLDER`                                      | ✅     |
| Delegate from a revoked lease                              | `409 STATE_CONFLICT`                                        | ✅     |
| Request a TTL longer than the parent's                     | Clamped to the parent expiry                                | ✅     |
| Chain delegations to escape depth limits                   | `403 DELEGATION_DEPTH_EXCEEDED`                             | ✅     |
| Any of 4,000 randomised proposals                          | Containment holds without exception                         | ✅     |

## 3. Compromised tenant user

| Attempt                                    | Outcome                                                                    | Tested |
| ------------------------------------------ | -------------------------------------------------------------------------- | ------ |
| Approve an action their agent requested    | Discounted — `SELF_APPROVAL_FORBIDDEN`                                     | ✅     |
| Approve without the required role          | Discounted — `APPROVER_HELD_NO_REQUIRED_ROLE`                              | ✅     |
| Vote twice to reach quorum alone           | Unique constraint on (request, approver)                                   | ✅     |
| Re-approve a rejected escalation           | Rejection is terminal; `409`                                               | ✅     |
| Approve after the window closed            | `409 STATE_CONFLICT`                                                       | ✅     |
| Activate their own policy version          | `403` — the author may not review it                                       | ✅     |
| Activate a version with one review         | Requires two distinct approvals                                            | ✅     |
| Edit an active policy in place             | Versions are immutable; a new version is required                          | ✅     |
| Alter a stored receipt                     | Blocked by append-only trigger; detected by verification if forced past it | ✅     |
| Edit a policy row directly in the database | `503 POLICY_UNAVAILABLE` — integrity checked every load                    | ✅     |

## 4. Compromised integration (signal source)

| Attempt                                      | Outcome                                | Tested         |
| -------------------------------------------- | -------------------------------------- | -------------- |
| Forge a signal to _loosen_ authority         | Not expressible — decay only narrows   | ✅ (invariant) |
| Post-date a signal to outlive its window     | `400`                                  | ✅             |
| Request a year-long TTL                      | `400` — capped at 24h                  | ✅             |
| Keep an agent suppressed with a stale signal | Freshness enforced at read             | ✅             |
| Flood with repeated assertions               | Superseded per (subject, type, source) | ✅             |
| Publish without the scope                    | `403`                                  | ✅             |

## 5. Cross-tenant attacker

| Attempt                                                  | Outcome                           | Tested |
| -------------------------------------------------------- | --------------------------------- | ------ |
| Read another tenant's agent, decision or receipt         | `404` — RLS, not a filter         | ✅     |
| Issue authority into another tenant                      | `404`                             | ✅     |
| Authorize another tenant's agent                         | `404`                             | ✅     |
| Query the database directly as the app role              | Zero rows outside the set tenant  | ✅     |
| Infer another tenant's decision rate from chain sequence | Chains are per-tenant             | ✅     |
| Learn another tenant's ids from an error body            | Generic message; ids only in logs | ✅     |

## 6. Attacker with database access

The honest section.

| Capability                                           | What holds                                                                    | What does not                                                                                        |
| ---------------------------------------------------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Read every row                                       | —                                                                             | Confidentiality. Encryption at rest is a deployment concern.                                         |
| `UPDATE` an evidence row                             | Append-only trigger refuses it                                                | —                                                                                                    |
| Disable the trigger and rewrite                      | Verification detects it: payload digest, link hash and chain linkage all fail | —                                                                                                    |
| Rewrite the whole chain **and** hold the signing key | Every hash from the tampered point changes                                    | Nothing detects it from the database alone. An external witness of head hashes would. **Not built.** |

## 7. Network attacker

TLS termination, mutual TLS between the enforcement point and the control
plane, and rate limiting are deployment-layer concerns. The
`ENFORCEMENT_UNAVAILABLE` path exists so that a client which cannot reach the
control plane fails according to policy rather than inventing an answer: the
SDK raises, and never returns a synthesised ALLOW.
