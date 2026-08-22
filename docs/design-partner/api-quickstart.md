# API quickstart

**Goal: you can try this yourself in an afternoon.** Every command below is
copy-pasteable. The reference tenant is seeded by `make dev` and its credentials
are written to `.seed.local.json` (git-ignored, development only).

## Setup

```bash
git clone <repo> && cd Altus
make dev                                  # Postgres, migrations, seeded tenant
make api                                  # http://127.0.0.1:8080
```

```bash
export ALTUS=http://127.0.0.1:8080
export ADMIN=$(jq -r '.tokens.admin'           .seed.local.json)
export AGENT=$(jq -r '.tokens.treasury_agent'  .seed.local.json)
export TREASURER=$(jq -r '.tokens.treasurer'   .seed.local.json)
export FRAUD=$(jq -r '.tokens.fraud_engine'    .seed.local.json)
```

**Authentication** is `Authorization: Bearer scr_<prefix>.<secret>`. Tokens are
stored as SHA-256 hashes; the plaintext exists only where it was issued. Every
credential carries scopes, and every route checks one:

| Scope                    | Grants                                                                                              |
| ------------------------ | --------------------------------------------------------------------------------------------------- |
| `read`                   | Own decisions, leases, traces, receipts. Held by agents.                                            |
| `authorization:evaluate` | Ask for a decision; execute against a grant.                                                        |
| `delegation:create`      | Sub-delegate authority already held.                                                                |
| `leases:write`           | Issue a lease — bounded by the policy's issuance ceilings.                                          |
| `approvals:write`        | Cast an approval vote. Humans only.                                                                 |
| `signals:write`          | Ingest risk signals.                                                                                |
| `policies:write`         | Author policy versions. Humans only.                                                                |
| `admin:write`            | Register agents and signal keys.                                                                    |
| `audit:read`             | Policy documents, security events, key metadata, unresolved executions. **Never held by an agent.** |

`read` and `audit:read` are separate deliberately. An agent that could fetch the
policy governing it would defeat the careful non-disclosure in every refusal.

---

## 1. Register an agent

```bash
curl -sS -X POST $ALTUS/v1/agents \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{
    "handle": "payments-agent",
    "display_name": "Payments Agent",
    "description": "Vendor payout automation",
    "owner_user_id": "usr_...",
    "metadata": { "runtime": "langgraph" }
  }' | jq
```

`owner_user_id` is the accountable human. An agent is a first-class principal,
not a shared key.

## 2. Issue an authority lease

```bash
curl -sS -X POST $ALTUS/v1/authority-leases \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{
    "agent_id": "treasury-agent",
    "grant": {
      "actions": ["wire.create", "wire.submit", "wire.execute", "counterparty.read"],
      "resources": {
        "bank_account": ["acct_001"],
        "counterparty":  ["cp_100", "cp_101"]
      },
      "constraints": {
        "max_amount": { "currency": "USD", "amountMinor": "5000000" },
        "currencies": ["USD"],
        "allowed_counterparties": ["cp_100", "cp_101"]
      }
    },
    "ttl_seconds": 3600,
    "grant_type": "SINGLE_USE",
    "purpose": "vendor-payout-run-2026-08"
  }' | jq
```

**Money is integer minor units as a string.** `"5000000"` is $50,000.00. Floats
are refused — `0.1 + 0.2` has no place near a payment ceiling. On input you may
also write `{ "currency": "USD", "amount": "50000.00" }`.

`grant_type: SINGLE_USE` spends the grant on claim. It is the safer shape for
high-consequence work; `REUSABLE` is the default only for compatibility.

`purpose` binds against the agent's `declared_intent` at evaluation time.

Issuance is bounded by the policy's `issuance.ceilings` for the caller's role — a
lease that exceeds the ceiling is refused even with `leases:write`. Roles are
never unioned: the request must fit wholly inside **one** ceiling.

## 3. Evaluate an authorization

```bash
curl -sS -X POST $ALTUS/v1/authorization/evaluate \
  -H "authorization: Bearer $AGENT" -H 'content-type: application/json' \
  -d '{
    "agent_id": "treasury-agent",
    "action": "wire.execute",
    "resource": { "type": "bank_account", "id": "acct_001" },
    "context": {
      "amount": "25000.00",
      "currency": "USD",
      "counterparty_id": "cp_100",
      "destination_country": "US"
    },
    "declared_intent": "vendor-payout-run-2026-08",
    "nonce": "req-2026-08-22-0001"
  }' | jq
```

Returns `decision` (`ALLOW` / `ESCALATE` / `DENY`), `reason_code`, the policy
version and hash, the acting lease, the constraint checks, `corrective_actions`
when a next step exists, and on an ALLOW the `exact_intent_hash` and
`binding_hash`.

`nonce` is single-use; reuse is `REPLAY_DETECTED`. `context.counterparty_known`
is **derived by the control plane** from your counterparty register and is never
read from the caller — an agent that could assert its counterparty is known would
have defeated the control by asserting it.

**Gotcha worth knowing before it bites you:** if the lease was issued with a
`purpose`, every evaluation under it must carry a matching `declared_intent`, or
you get `DENY / INTENT_MISMATCH` — not a `CONSTRAINT_VIOLATION`, which is what
most people go looking for. A purpose-bound grant binds even when the policy
declares no intents at all. Omit `purpose` at issuance if you do not want that
binding.

## 4. Execute

There are two paths, and the difference matters.

### `POST /v1/execute` — the enforcement boundary (use this)

Altus performs the operation. It reconstructs the authorized operation from its
own records, compares hashes, claims the grant, and only then contacts the
provider.

```bash
curl -sS -X POST $ALTUS/v1/execute \
  -H "authorization: Bearer $AGENT" -H 'content-type: application/json' \
  -d '{
    "decision_id": "dec_...",
    "operation": {
      "action": "wire.execute",
      "resource": { "type": "bank_account", "id": "acct_001" },
      "context": {
        "amount": "25000.00",
        "currency": "USD",
        "counterparty_id": "cp_100",
        "destination_country": "US"
      }
    }
  }' | jq
```

Change one field and you get `403 INTENT_MISMATCH` with the _names_ of the
mutated fields — never their values — plus a durable security event. The provider
is not contacted.

You present the operation even though Altus could execute from its own records,
because a mutation attempt is a fact worth learning: reconstructing silently
makes mutation impossible, requiring you to present it makes mutation impossible
**and detected**.

Responses: `201` executed, `200` with `replayed: true` for a settled claim,
`409 EXECUTION_UNRESOLVED` for an unresolved one.

### `POST /v1/executions` — self-reported outcome (legacy)

The agent reports what it did. Useful when the agent talks to the provider itself
during evaluation-only integration. **This is not enforcement** — nothing verifies
the reported operation against the authorization.

```bash
curl -sS -X POST $ALTUS/v1/executions \
  -H "authorization: Bearer $AGENT" -H 'content-type: application/json' \
  -d '{ "decision_id": "dec_...", "status": "SUCCEEDED",
        "result": { "wire_reference": "WIRE-2026-0001" } }' | jq
```

Use it in week one to get integrated. Move to `/v1/execute` before any real
money moves.

## 5. Trace a decision

```bash
curl -sS $ALTUS/v1/trace/dec_... -H "authorization: Bearer $ADMIN" | jq
```

Returns `root_cause`, a `trace` array of typed causal nodes with
`causal_link_type` edges (`origin`, `admitted_authority`, `delegated_to`,
`influenced_by`, `evaluated_to`, `approved_by`, `superseded_by`, …), and
`complete`, which is true only when the chain reaches a policy activation.

Subject-scoped: an agent can read its own decisions. Anything else is **404, never
403**, so the endpoint is not an existence oracle.

---

## The policy format

A policy is YAML, versioned, reviewed by two humans, and activated explicitly.
The content hash is recorded on every decision made under it.

```yaml
apiVersion: scrutexity.dev/policy/v1
id: vendor_payouts
version: 1.0.0

metadata:
  title: Vendor payout authorization
  owner: Treasury Operations

defaults:
  decision: DENY # nothing a rule did not permit
  reason_code: NO_RULE_MATCHED
  execution_grant_ttl_seconds: 300

failure_modes:
  policy_unavailable: FAIL_CLOSED
  signal_unavailable: FAIL_CLOSED
  enforcement_unavailable: FAIL_CLOSED

issuance:
  enforced: true
  ceilings:
    - role: treasury_admin
      grant:
        actions: [wire.create, wire.submit, wire.execute, wire.read]
        resources:
          bank_account: [acct_001]
          counterparty: [cp_100, cp_101]
        constraints:
          max_amount: { currency: USD, amount: '500000.00' }
          currencies: [USD]
          allowed_counterparties: [cp_100, cp_101]

delegation:
  enabled: true
  max_depth: 2
  max_ttl_seconds: 3600
  non_delegable_actions: [wire.create, wire.modify, wire.submit, wire.execute]

rules:
  - id: wire_under_ten_thousand
    description: Routine low-value payments run unattended.
    priority: 20
    when:
      action: { prefix: 'wire.' }
      context.amount: { lt: { amount: '10000', currency: USD } }
    then:
      decision: ALLOW
      reason_code: BELOW_AUTONOMOUS_THRESHOLD

  - id: wire_fifty_thousand_and_above
    description: Six-figure payments require the treasurer.
    priority: 30
    when:
      action: { prefix: 'wire.' }
      context.amount: { gte: { amount: '50000', currency: USD } }
    then:
      decision: ESCALATE
      reason_code: TREASURER_APPROVAL_REQUIRED
      approval:
        quorum: 1
        roles: [treasurer]
        forbid_self_approval: true
        ttl_seconds: 3600

  - id: unknown_counterparty
    description: Money never moves to a counterparty we have not registered.
    priority: 50
    when:
      action: { prefix: 'wire.' }
      context.counterparty_known: { eq: false }
    then:
      decision: DENY
      reason_code: UNKNOWN_COUNTERPARTY

  - id: elevated_fraud_risk
    description: A live fraud signal above 0.9 suspends unattended payment authority.
    priority: 60
    when:
      action: { prefix: 'wire.' }
      signal.fraud_risk.agent: { gte: 0.9 }
    then:
      decision: ESCALATE
      reason_code: FRAUD_RISK_HUMAN_REVIEW
      approval: { quorum: 1, roles: [treasurer], forbid_self_approval: true, ttl_seconds: 1800 }
      authority_effect:
        remove_actions: [wire.create, wire.submit, wire.execute, wire.modify]
        duration_seconds: 600
```

**Evaluation semantics you must know:**

- **Every rule is evaluated. There is no first-match-wins.**
- The strictest matched decision wins: `DENY > ESCALATE > ALLOW`.
- Approval requirements from all matched escalations merge in the more-demanding
  direction: max quorum, union of roles, shortest window.
- If no rule matches, `defaults.decision` applies — which is `DENY`.
- `priority` orders reporting and reason-code selection. It does not short-circuit.

The full JSON Schema is at `spec/policy.schema.json`, generated from the code and
drift-tested in CI. A ready-to-edit treasury pack is at `policies/treasury-wire.yaml`
(see `policy-pack-treasury.md`).

Publishing a policy is three calls — create, two independent reviews, activate:

```bash
curl -sS -X POST $ALTUS/v1/policy-versions -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d "$(jq -Rs '{document: .}' < policies/treasury-wire.yaml)" | jq -r .policy_version.id
# then POST /v1/policy-versions/{id}/reviews  (x2, different humans)
# then POST /v1/policy-versions/{id}/activate
```

---

## Register an Ed25519 signal source

Enrolment is mandatory. An unenrolled source is refused with
`SIGNAL_SOURCE_NOT_ENROLLED`, and HMAC is refused by default everywhere.

**1. The source generates its own keypair and keeps the private half.**

```bash
openssl genpkey -algorithm ed25519 -out fraud-engine.key
openssl pkey -in fraud-engine.key -pubout -out fraud-engine.pub
```

**2. Register only the public half.**

```bash
curl -sS -X POST $ALTUS/v1/signal-keys \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d "$(jq -n --arg k "$(cat fraud-engine.pub)" \
    '{source:"external_fraud_engine", key_id:"fraud-2026-08",
      algorithm:"ED25519", key_material:$k}')" | jq
```

**3. Sign the canonical envelope.** These exact fields, canonicalised
(`packages/core/src/signals.ts` — use `signSignalEd25519`, or reimplement against
`canonicalize`):

```json
{
  "organization_id": "...",
  "subject_type": "agent",
  "subject_id": "...",
  "signal_type": "fraud_risk",
  "value": "0.97",
  "confidence": "1",
  "source": "external_fraud_engine",
  "event_id": "evt-0001",
  "issued_at": "2026-08-22T10:00:00.000Z",
  "ttl_seconds": 600
}
```

Signature is base64url over the canonical JSON. `value` and `confidence` are
canonical decimal strings — both sides go through the same function, because two
renderings of `0.97` that disagree look exactly like a forgery.

**4. Send it.**

```bash
curl -sS -X POST $ALTUS/v1/signals \
  -H "authorization: Bearer $FRAUD" -H 'content-type: application/json' \
  -d '{
    "subject": { "type": "agent", "id": "agt_..." },
    "signal_type": "fraud_risk", "value": "0.97", "confidence": "1",
    "source": "external_fraud_engine", "ttl_seconds": 600,
    "issued_at": "2026-08-22T10:00:00.000Z",
    "event_id": "evt-0001",
    "signature": "<base64url>", "signing_key_id": "fraud-2026-08"
  }' | jq
```

`issued_at` must be supplied by the signer — the signature covers it, and a signer
that lets the receiver choose part of the payload is not signing the payload.
`event_id` is the replay boundary: redelivering one is `REPLAY_DETECTED`.

**Rotation** is an overlap, never a swap: register the new key, switch the source
over, then `POST /v1/signal-keys/{id}/retire` with a grace period.
`POST /v1/signal-keys/{id}/revoke` takes effect immediately with no overlap and is
for suspected compromise. See ADR-0018.

---

## Verify a receipt offline

Fetch a receipt, then verify it against the published key without trusting the
running service:

```bash
curl -sS $ALTUS/v1/receipts/rcpt_... -H "authorization: Bearer $ADMIN" > receipt.json

# Verify a receipt you hold. Checks payload digest, link hash and signature
# offline, and separately reports whether it matches the stored record.
curl -sS -X POST $ALTUS/v1/receipts/verify \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d "$(jq '{receipt: .receipt}' receipt.json)" | jq

# Verify a stored receipt and walk its chain segment to genesis.
curl -sS -X POST $ALTUS/v1/receipts/rcpt_.../verify \
  -H "authorization: Bearer $ADMIN" | jq
```

A verification reports `integrity: INTACT | COMPROMISED` and
`attests: evidence_integrity_and_provenance` — that this decision was made under
this policy on these facts and has not been altered. It does not attest that the
decision was correct.

The verification logic is pure and lives in `packages/core/src/receipts.ts`
(`verifyReceipt`, `verifyChain`). It has no database dependency, so an auditor can
run it against an export with only the public key.

---

## Error codes

| Code                                                                    | HTTP | Meaning                                                                                                  |
| ----------------------------------------------------------------------- | ---- | -------------------------------------------------------------------------------------------------------- |
| `UNAUTHORIZED`                                                          | 401  | Missing or invalid credential.                                                                           |
| `FORBIDDEN`                                                             | 403  | Credential lacks the required scope.                                                                     |
| `INVALID_REQUEST`                                                       | 400  | Malformed body. Details are your own input reflected back.                                               |
| `POLICY_DENIED`                                                         | 403  | Policy refused this action.                                                                              |
| `APPROVAL_REQUIRED`                                                     | 202  | Escalated. `approval_request_id` names what is needed.                                                   |
| `AUTHORITY_MISSING`                                                     | 403  | No lease covers this action.                                                                             |
| `AUTHORITY_EXPIRED` / `_REVOKED` / `_SUSPENDED`                         | 403  | The lease is not usable.                                                                                 |
| `CONSTRAINT_VIOLATION`                                                  | 403  | Inside the envelope, outside a constraint (amount, currency, counterparty).                              |
| `AUTHORITY_CONSUMED`                                                    | 403  | Single-use grant already spent.                                                                          |
| `DELEGATION_EXCEEDS_PARENT`                                             | 422  | Law 1. The child grant is not contained by its parent.                                                   |
| `INTENT_MISMATCH`                                                       | 403  | Law 4. The presented operation is not the authorised one. Details name the mutated _fields_.             |
| `APPROVAL_CONTEXT_MISMATCH`                                             | 409  | Conditions changed since a human approved. Re-evaluate and re-approve.                                   |
| `CONTEXT_CHANGED`                                                       | 409  | Conditions changed since the ALLOW. Re-evaluate.                                                         |
| `SIGNAL_SOURCE_NOT_ENROLLED`                                            | 403  | The source has no registered signing key.                                                                |
| `SIGNAL_KEY_UNKNOWN`                                                    | 403  | No usable key matches. Includes a refused algorithm (`ALGORITHM_NOT_PERMITTED`).                         |
| `SIGNAL_SIGNATURE_INVALID`                                              | 403  | The signature did not verify, or none was presented.                                                     |
| `AUTHORITY_INVARIANT_VIOLATION`                                         | 403  | **A law did not hold at runtime.** Not a policy denial. Page someone.                                    |
| `EXECUTION_UNRESOLVED`                                                  | 409  | A prior execution may or may not have happened. Reconcile; do not retry.                                 |
| `REPLAY_DETECTED`                                                       | 409  | This nonce, event, or grant was already used.                                                            |
| `IDEMPOTENCY_CONFLICT`                                                  | 409  | The idempotency key was reused with a different body.                                                    |
| `EVIDENCE_TAMPERED`                                                     | 422  | Receipt integrity verification failed.                                                                   |
| `POLICY_UNAVAILABLE` / `SIGNAL_UNAVAILABLE` / `ENFORCEMENT_UNAVAILABLE` | 503  | A dependency is degraded. Behaviour follows `failure_modes`, which is fail-closed for financial actions. |
| `NOT_FOUND`                                                             | 404  | Not found — **or not yours**. Deliberately indistinguishable.                                            |
| `RATE_LIMITED`                                                          | 429  | Reserved; not yet enforced (gap G-15).                                                                   |

Every error carries `code`, a human `message`, a `request_id`, and often a
`reason_code` naming the specific cause within the code. Security-sensitive
errors return a generic message: a caller cannot map out policy internals by
reading error text.

**The two to alert on:** `AUTHORITY_INVARIANT_VIOLATION` means the system's model
of its own authority is wrong. `EXECUTION_UNRESOLVED` means money may be in an
unknown state.

## Where to go next

- `policy-pack-treasury.md` — a tiered policy to start from and why each rule exists.
- `integration-runbook.md` — connecting a real provider and a real KMS.
- `../security-surface-map.md` — every known gap and its status.
- `spec/openapi.json` — the full generated contract.
