# API contract

The machine-readable contract is [`spec/openapi.json`](../spec/openapi.json),
generated from the Zod schemas the service validates against. CI runs
`pnpm spec:check`, and `spec/test/contracts.test.ts` asserts that every
registered route is documented and every documented route exists. The published
contract cannot quietly stop describing the running service.

This page covers the conventions the spec cannot express.

## Conventions

**Versioning.** `/v1/` from the beginning. Within a major version, fields are
added but never renamed or removed. External agent integrations depend on these
names.

**Tenancy.** Derived from the credential. There is no tenant header and no
tenant field in any body.

**A decision is not an error.** `POST /v1/authorization/evaluate` returns `200`
for ALLOW, DENY and ESCALATE alike. A denial is a successful evaluation that
answered "no". Branch on `decision`; never on status.

**Strict bodies.** Unknown fields are rejected, not ignored.

**Request ids.** Supply `X-Request-Id` or one is generated. It is echoed on the
response and present on every log line for that request.

**Caching.** Never cache a decision. It is valid only for the policy version,
authority lease and signal state it was made under — none of which the client
can observe changing.

## Endpoints

| Method | Path                                               | Scope                    | Idempotent               |
| ------ | -------------------------------------------------- | ------------------------ | ------------------------ |
| POST   | `/v1/agents`                                       | `admin:write`            | key                      |
| GET    | `/v1/agents` · `/v1/agents/{id}`                   | `read`                   | —                        |
| POST   | `/v1/authority-leases`                             | `leases:write`           | key                      |
| GET    | `/v1/authority-leases/{id}`                        | `read`                   | —                        |
| POST   | `/v1/authority-leases/{id}/revoke`                 | `leases:write`           | naturally                |
| POST   | `/v1/delegations`                                  | `delegation:create`      | key                      |
| POST   | `/v1/authorization-requests`                       | `authorization:evaluate` | key + nonce              |
| POST   | `/v1/authorization/evaluate`                       | `authorization:evaluate` | key + nonce              |
| GET    | `/v1/authorization-decisions/{id}`                 | `read`                   | —                        |
| POST   | `/v1/executions`                                   | `authorization:evaluate` | key + single-use grant   |
| POST   | `/v1/signals`                                      | `signals:write`          | key                      |
| GET    | `/v1/approval-requests`                            | `read`                   | —                        |
| POST   | `/v1/approvals`                                    | `approvals:write`, human | key + one vote per human |
| GET    | `/v1/receipts/{id}`                                | `read`                   | —                        |
| POST   | `/v1/receipts/{id}/verify` · `/v1/receipts/verify` | `read`                   | naturally                |
| POST   | `/v1/policy-versions`                              | `policies:write`, human  | key                      |
| POST   | `/v1/policy-versions/{id}/reviews` · `/activate`   | `policies:write`, human  | one vote per reviewer    |
| GET    | `/v1/overview`                                     | `read`                   | —                        |
| GET    | `/health` · `/ready` · `/metrics`                  | public                   | —                        |

`POST /v1/authorization/evaluate` is a verb-shaped alias of
`POST /v1/authorization-requests` sharing one implementation. It exists because
SDK callers reach for a verb rather than a resource.

## The authorization request

```json
{
  "agent_id": "treasury-agent",
  "action": "wire.execute",
  "resource": { "type": "bank_account", "id": "acct_991" },
  "context": {
    "amount": "750000.00",
    "currency": "USD",
    "counterparty_id": "cp_100",
    "destination_country": "US"
  },
  "nonce": "wf_abc-attempt-1",
  "correlation_id": "wf_abc"
}
```

- `action` must be in the catalog (`x-action-catalog` in the spec). A typo is a
  `400`, never a rule that silently never matches.
- `amount` is an exact decimal **string** with a currency. A fractional JSON
  number is refused rather than compared.
- `counterparty_known` and `counterparty_status` are **server-derived**. Send
  them and they are discarded.
- `nonce` is optional and single-use per (organization, agent).

## The decision

```json
{
  "authorization_request_id": "areq_01JBX7…",
  "decision_id": "dec_01JBX7…",
  "receipt_id": "rcpt_01JBX7…",
  "approval_request_id": "apr_01JBX7…",
  "decision": "ESCALATE",
  "reason_code": "TREASURER_APPROVAL_REQUIRED",
  "policy_id": "pol_01JBX7…",
  "policy_version": "1.4.0",
  "policy_hash": "a3f46e1e2e3d…",
  "authority_lease_id": "lease_01JBX7…",
  "risk_signal_ids": [],
  "constraints_evaluated": [
    {
      "constraint": "max_amount",
      "satisfied": false,
      "applicable": true,
      "limit": { "currency": "USD", "amountMinor": "5000000" },
      "observed": { "currency": "USD", "amountMinor": "75000000" },
      "message": "750000.00 USD exceeds the 50000.00 USD ceiling"
    }
  ],
  "approval_requirement": {
    "required": true,
    "quorum": 1,
    "roles": ["treasurer"],
    "forbid_self_approval": true,
    "ttl_seconds": 3600
  },
  "failover_behavior": "FAIL_CLOSED",
  "expires_at": null,
  "decision_timestamp": "2026-03-01T12:00:00.000Z"
}
```

`expires_at` is non-null only for ALLOW: it is the execution grant's lifetime.

## Error taxonomy

Every error carries `code` and, where one applies, `reason_code` from a closed
vocabulary. Branch on those, never on the message.

| Code                                                                    | Status | Meaning                                                  |
| ----------------------------------------------------------------------- | ------ | -------------------------------------------------------- |
| `UNAUTHORIZED`                                                          | 401    | Missing, malformed, revoked or expired credential.       |
| `FORBIDDEN`                                                             | 403    | Authenticated, but not permitted this operation.         |
| `INVALID_REQUEST`                                                       | 400    | Schema, catalog or value error.                          |
| `POLICY_DENIED`                                                         | 403    | Policy refused the action.                               |
| `APPROVAL_REQUIRED`                                                     | 202    | Reserved for asynchronous enforcement points.            |
| `AUTHORITY_MISSING` / `_EXPIRED` / `_REVOKED` / `_SUSPENDED`            | 403    | No usable authority covers the action.                   |
| `CONSTRAINT_VIOLATION`                                                  | 403    | Outside the constraints, with no approval path defined.  |
| `DELEGATION_EXCEEDS_PARENT`                                             | 422    | Containment failed. `details.violations` names the axis. |
| `POLICY_UNAVAILABLE` / `SIGNAL_UNAVAILABLE` / `ENFORCEMENT_UNAVAILABLE` | 503    | A dependency of the decision failed.                     |
| `REPLAY_DETECTED`                                                       | 409    | Reused nonce or execution grant.                         |
| `IDEMPOTENCY_CONFLICT`                                                  | 409    | Key reused with a different body.                        |
| `STATE_CONFLICT`                                                        | 409    | The object is not in a state permitting this.            |
| `EVIDENCE_TAMPERED`                                                     | 422    | Integrity verification failed.                           |
| `NOT_FOUND`                                                             | 404    | Absent, or not visible to this tenant.                   |
| `RATE_LIMITED`                                                          | 429    | Too many requests.                                       |
| `INTERNAL_ERROR`                                                        | 500    | Unexpected. Detail is in the logs under `request_id`.    |

Security-sensitive failures return a generic message. Detail is disclosed only
when it is the caller's own input reflected back.

## Idempotency

Send `Idempotency-Key` on any mutation you might retry. The key is claimed in
the same transaction as the effect: a duplicate blocks on the row and then
replays the stored response rather than doing the work twice.

Reusing a key with a different body returns `IDEMPOTENCY_CONFLICT` rather than
being silently honoured — that is a client bug, and hiding it would hide a lost
write.

Two mutations carry stronger protection than a key alone:

- **Execution.** An ALLOW is a single-use grant; a second execution against the
  same decision is `REPLAY_DETECTED`, enforced by a unique constraint.
- **Approval.** One vote per human per request, enforced by a unique constraint.

## SDK

```ts
const scrutexity = new ScrutexityClient({ baseUrl, token });

const decision = await scrutexity.authorize({
  agentId: 'treasury-agent',
  action: 'wire.execute',
  resource: 'bank_account:acct_991',
  context: { amount: '750000.00', currency: 'USD', counterparty_id: 'cp_100' },
});

if (decision.allowed) {
  await executeWire();
  await scrutexity.recordExecution(decision.decisionId, 'SUCCEEDED');
}
```

Better, because the check and the act cannot drift apart and the evidence is
not something anyone has to remember to write:

```ts
const { decision, result } = await scrutexity.guard(
  {
    agentId: 'treasury-agent',
    action: 'wire.execute',
    resource: 'bank_account:acct_991',
    context: { amount: '750000.00', currency: 'USD', counterparty_id: 'cp_100' },
  },
  async () => executeWire(),
);

if (decision.requiresApproval) {
  notifyTreasurer(decision.approvalRequestId);
}
```

Only `ALLOW` is truthy. `requiresApproval` and `denied` are both falsy for
`allowed`, so `if (decision.allowed)` cannot accidentally treat an escalation
as a yes. An unreachable control plane raises `ENFORCEMENT_UNAVAILABLE`; the
SDK never synthesises an answer.
