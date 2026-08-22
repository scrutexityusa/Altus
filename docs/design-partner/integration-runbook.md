# Integration runbook

**For the engineer standing this up.** Honest about what is wired and what is
not: **no KMS is connected**, and production refuses to start without one. That
is stated up front here because it is the single prerequisite that gates
production, and discovering it in week three would be our failure.

## The two seams

Everything a partner has to build plugs into exactly two interfaces.

| Seam           | Interface           | File                                   | Status                                                    |
| -------------- | ------------------- | -------------------------------------- | --------------------------------------------------------- |
| Money movement | `ExecutionProvider` | `services/api/src/adapter/provider.ts` | Simulated + crash-harness shipped. **Yours to write.**    |
| Key custody    | `SecretProvider`    | `services/api/src/keys/provider.ts`    | `env` / `file` shipped. `kms` throws — **yours to wire.** |

Nothing else in the codebase should need to change to run against your bank and
your key manager.

---

## 1. Connecting an execution provider

### The interface

```ts
export interface ExecutionProvider {
  readonly name: string; // recorded on the claim
  readonly idempotent: boolean;
  readonly actions: readonly string[]; // which actions it handles
  execute(request: ProviderRequest): Promise<ProviderOutcome>;
  verifyExecution?(request: ProviderRequest): Promise<VerificationResult>;
}
```

Deliberately the narrowest interface that can move money: one method, one
operation, one idempotency key. Authority, intent binding, revocation and grant
consumption all happen in the enforcement boundary **before** a provider is
reached. A provider that could evaluate policy would be a second place where "may
this happen" is computed, and two such places eventually disagree.

### `ProviderOutcome` — three states, never two

```ts
| { status: 'EXECUTED'; external_reference: string }   // it happened
| { status: 'FAILED';   error: string }                // it did not happen
| { status: 'UNKNOWN';  error: string }                // nobody knows
```

**`UNKNOWN` must never be collapsed into `FAILED`.** Return it for a timeout, a
dropped connection, or a 5xx _after_ the request was accepted. "The wire did not
go" and "I do not know whether the wire went" call for opposite operator
responses, and reporting the second as the first will eventually cause a double
payment.

The rule for your adapter: return `FAILED` **only** when the provider explicitly
told you the operation did not happen. Everything ambiguous is `UNKNOWN`.

### The idempotency key contract

```
idempotencyKey = "scrutexity:{decision_id}"
```

Derived from the decision id and **never regenerated** — not on retry, not on
reconciliation, not on manual replay by an operator. Any code constructing this
other than via `idempotencyKeyFor` is a bug.

This is what closes the last gap in exactly-once. Scrutexity's `UNIQUE
(decision_id)` stops it issuing a second claim; it does nothing to stop the
_bank_ executing twice when a claim commits, the provider accepts, settlement
fails, and an operator resubmits days later from a different machine. That
resubmission must carry the same key.

**What your adapter must guarantee:** the same key returns the first outcome
rather than performing a second operation, and that must hold across a process
restart. If your bank's idempotency keys expire (many do, at 24h or 7 days),
say so in your adapter's documentation and size your reconciliation SLA inside
that window.

### Writing one

A minimal HTTP adapter:

```ts
// services/api/src/adapter/acme-bank.ts
export class AcmeBankProvider implements ExecutionProvider {
  readonly name = 'acme-bank';
  readonly idempotent = true;
  readonly actions = ['wire.execute', 'wire.submit'] as const;

  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
  ) {}

  async execute(request: ProviderRequest): Promise<ProviderOutcome> {
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/payments`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.token}`,
          'content-type': 'application/json',
          // The contract above. Never a fresh uuid.
          'idempotency-key': request.idempotencyKey,
        },
        body: JSON.stringify({
          amount: request.operation.parameters['amount'],
          counterparty: request.operation.parameters['counterparty_id'],
          source_account: request.operation.resource_id,
        }),
      });
    } catch (error) {
      // The request may or may not have been accepted. UNKNOWN, always.
      return { status: 'UNKNOWN', error: String(error) };
    }

    if (response.ok) {
      const body = await response.json();
      return { status: 'EXECUTED', external_reference: body.payment_id };
    }
    // 4xx means the bank refused and nothing happened. 5xx means it may have
    // accepted and then failed to tell us -- which is not the same thing.
    if (response.status >= 400 && response.status < 500) {
      return { status: 'FAILED', error: await response.text() };
    }
    return { status: 'UNKNOWN', error: `provider returned ${response.status}` };
  }

  async verifyExecution(request: ProviderRequest): Promise<VerificationResult> {
    const response = await fetch(
      `${this.baseUrl}/payments?idempotency_key=${encodeURIComponent(request.idempotencyKey)}`,
      { headers: { authorization: `Bearer ${this.token}` } },
    );
    if (!response.ok) return { status: 'AMBIGUOUS', reason: `lookup failed (${response.status})` };
    const body = await response.json();
    if (body.payments?.length === 0) return { status: 'CONFIRMED_FAILURE', reason: 'no record' };
    return { status: 'CONFIRMED_SUCCESS', external_reference: body.payments[0].payment_id };
  }
}
```

Register it in `services/api/src/adapter/registry.ts` and enable it with
`EXECUTION_PROVIDERS=acme-bank`.

**Implement `verifyExecution`.** It is optional in the type and mandatory in
practice: it is the only safe external operation against an unresolved claim. A
provider that cannot answer "did this key execute?" cannot support exactly-once
external effects, and the correct semantic for its unresolved executions is
"unknown; a human decides", never "retry".

### Simulated → real, exactly

1. **Write the adapter.** Copy `simulated.ts` for shape; it satisfies the whole
   interface honestly, including idempotency.
2. **Test it against your bank's sandbox** — one success, one 4xx refusal, one
   timeout. Assert the timeout produces `UNKNOWN` and not `FAILED`. This is the
   case that matters and the one most adapters get wrong.
3. **Run the recovery harness against it.** Point `CRASH_HARNESS_URL` at your own
   ledger equivalent, or write the four-line variant of
   `crash-harness.ts` that talks to your sandbox. `make recovery` then proves your
   adapter's idempotency survives a real `SIGKILL` mid-payment.
4. **Shadow mode.** `EXECUTION_PROVIDERS=none`. Every enforced execution is
   refused with `ENFORCEMENT_UNAVAILABLE`, and you get real decisions with zero
   external effects. This is week two of the pilot.
5. **One real low-value transaction**, with a human watching, under a
   `SINGLE_USE` lease with a ceiling set to that transaction's amount.
6. **Widen the lease ceiling**, not the code.

Never run `simulated-treasury` in production — the registry refuses to start with
it, because a simulated provider there would emit receipts indistinguishable from
real ones for money that never moved.

---

## 2. Configuring the SecretProvider

### What is wired, and what is not

```ts
export interface SecretProvider {
  readonly kind: 'env' | 'file' | 'kms';
  readonly externallyManaged: boolean; // production requires true
  getSecret(name: string): Promise<Buffer>;
}
```

| Provider | Status                   | Use                                           |
| -------- | ------------------------ | --------------------------------------------- |
| `env`    | Works                    | Local development only                        |
| `file`   | Works                    | Mounted secret; still local custody           |
| `kms`    | **Throws on every read** | The shape production requires. Not connected. |

Production enforces four things at boot, and refuses to start on any of them:

```
SECRET_PROVIDER must be "kms"                     -- env and file are local custody
RECEIPT_SIGNING_KEY_B64 must NOT be set           -- an inline key is local custody
SIGNAL_AUTHENTICATION must be "required"
SIGNAL_LEGACY_HMAC must be "refused"
```

And with `kms` selected but unconnected, the first secret read throws, so the
process **does not start**. That is the correct failure — it is louder than
silently falling back to the environment, and a silent fallback is exactly how
local custody reaches production. It also means, stated plainly: **no deployment
of this code has yet started in a production posture.**

### Wiring your key manager

One file, one constructor argument, one SDK dependency:

```ts
// services/api/src/keys/aws-kms.ts
export class AwsKmsSecretProvider implements SecretProvider {
  readonly kind = 'kms' as const;
  readonly externallyManaged = true;
  constructor(private readonly client: SecretsManagerClient) {}

  async getSecret(name: string): Promise<Buffer> {
    const result = await this.client.send(new GetSecretValueCommand({ SecretId: name }));
    if (!result.SecretString) throw new SecretNotFoundError(name, this.kind);
    return Buffer.from(result.SecretString, 'base64');
  }
}
```

Return it from `loadSecretProvider` in `keys/provider.ts` under `case 'kms'`.
That is the entire change.

**The rule that outranks the interface:** secret material returned here must never
reach a log, an error message, a metric label, a trace attribute, a database row,
an API response, or a receipt. There is no formatting helper on the type on
purpose — a `toString` that redacts is a `toString` somebody eventually trusts.

### Choosing a key manager

| If…                            | Choose                        | Notes                                                                                                           |
| ------------------------------ | ----------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Already on AWS                 | **AWS KMS + Secrets Manager** | Envelope-encrypt the Ed25519 key; store ciphertext in Secrets Manager. CloudTrail gives key-use audit for free. |
| Already on GCP                 | **GCP KMS + Secret Manager**  | Same shape. IAM conditions can scope access to the workload identity.                                           |
| Already on Azure               | **Azure Key Vault**           | Managed HSM tier if your auditor asks for FIPS 140-2 Level 3.                                                   |
| Multi-cloud, or already run it | **HashiCorp Vault (Transit)** | Best story if you want the key never to leave Vault. Costs you an availability dependency in the signing path.  |
| Regulated and asked for an HSM | **CloudHSM / Managed HSM**    | Only if a specific obligation names it. Operationally heavy.                                                    |

**The decision, honestly:** whichever one your security team already operates and
already audits. The differences that matter here are access-control granularity
and audit logging, not cryptography — the key is Ed25519 either way. A key manager
your team knows beats a better one they do not.

Two questions to settle before you pick:

1. **Does the key leave the manager?** Vault Transit and HSM-backed signing can
   keep it inside. The current `SecretProvider` interface _fetches_ material, so a
   never-leaves design needs a signing-oriented interface instead — a real change,
   maybe 100 lines, worth doing if your obligations require it. Tell us and we
   will scope it rather than guess.
2. **What is your rotation cadence, and who holds the previous key?** Receipts
   record the key id they were signed with, so old receipts stay verifiable
   against the old public key — but only if you keep it.

---

## 3. Reconciling UNKNOWN outcomes

Reconciliation is deliberately **not** a background worker in the API process.
With more than one replica that needs leader election, and a reconciliation loop
that runs twice is exactly the thing that turns an `UNKNOWN` into a double
payment.

```bash
curl -sS "$ALTUS/v1/executions/unresolved?older_than_seconds=300" \
  -H "authorization: Bearer $OPERATOR" | jq
```

Returns claims in `EXECUTING` or `UNKNOWN`, with `idempotency_key`,
`external_reference`, `last_error` and `claimed_at`.

**The workflow:**

1. **Ask the provider**, using `verifyExecution` with the claim's
   `idempotency_key`. Not a similar key. Not a new one.
2. **`CONFIRMED_SUCCESS`** → the money moved. Record `RECONCILED` with the external
   reference. Do not retry.
3. **`CONFIRMED_FAILURE`** → nothing happened. The grant is spent, so a fresh
   payment needs a **new authorization**, not a retry of the old one. That is
   correct: the risk picture may have moved since.
4. **`AMBIGUOUS`** → a human decides, with the bank on the phone. There is no
   automated answer, and a system that invents one is a system that double-pays.

**What must never happen:** retrying an unresolved claim. `POST /v1/execute`
against one returns `409 EXECUTION_UNRESOLVED` — never a fresh execution, and
never `REPLAY_DETECTED`, which would falsely tell the caller the work is finished.

**Alert on it.** An `UNKNOWN` older than your provider's settlement window is an
incident, not a queue item. Suggested threshold: 15 minutes for same-day rails.

`make recovery` demonstrates exactly this state, produced by a real `SIGKILL`.

---

## 4. Signal source key rotation

Rotation is an overlap, never a swap. Both keys are valid during the window, so
no signal is dropped while a source switches over.

1. **Generate** a new keypair at the source. The private half never leaves it.
2. **Register** the public half under a new `key_id`. The source now has two
   `ACTIVE` keys.
3. **Switch** the source to sign with the new `key_id`. Confirm signals arrive
   with `authenticated: true` and the new key id recorded.
4. **Retire** the old key with a `grace_period_seconds` covering in-flight
   deliveries. It becomes `RETIRING` and stays usable until `not_after`.
5. **Verify** nothing is still arriving under the old key id.

The grace period is the whole point of `RETIRING`. Skipping it drops signals, and
a dropped fraud signal is authority that should have decayed and did not.

**Compromise is not rotation.** Use `POST /v1/signal-keys/{id}/revoke` — immediate,
no overlap, because the overlap is exactly what an attacker holding the old key
would use. Dropping some legitimate signals is the correct trade.

Both states are enforced at verification against the authoritative database clock,
so a source with a fast clock cannot extend its own window. Full runbook: ADR-0018.

---

## 5. Monitoring and alerting

Prometheus at `GET /metrics`. The names below are exact.

### Page immediately

| Metric / condition                                                                   | Why                                                                                                          |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `scrutexity_authority_invariant_violations_total` **> 0**                            | A law did not hold at runtime. The system's model of its own authority is wrong. This is never routine.      |
| `scrutexity_executions_unresolved_total` increasing, or any claim `UNKNOWN` > 15 min | Money may be in an unknown state.                                                                            |
| `scrutexity_intent_binding_mismatch_total` **> 0**                                   | An agent presented an operation other than the one authorised. Either a bug or a compromise; both need eyes. |
| `/ready` returning 503                                                               | Fail-closed means payments have stopped.                                                                     |

### Alert during business hours

| Metric                                                                  | Why                                               |
| ----------------------------------------------------------------------- | ------------------------------------------------- |
| `scrutexity_signal_invalid_signature_total` rising                      | A source is misconfigured, or someone is probing. |
| `scrutexity_replay_attempts_total` rising                               | Retry storm or replay attempt.                    |
| `scrutexity_security_events_total{kind="EXECUTION_INTENT_MUTATED"}`     | Every occurrence is worth a look.                 |
| `scrutexity_authorization_decisions_total{decision="DENY"}` step change | A policy change did more than intended.           |
| `scrutexity_verification_failures_total` **> 0**                        | Evidence integrity.                               |

### Watch

`scrutexity_authorization_duration_seconds` p99, `scrutexity_approval_latency_seconds`
(how long humans actually take — it is how you size `ttl_seconds`),
`scrutexity_leases_expired_total`, `scrutexity_policy_cache_total`.

### Clock health — not optional

Every validity decision reads `now()` from the database. That makes the database
host's clock a security dependency.

- Alert on `chronyd`/`ntpd` **step events** on the database host, not just drift.
  A step is the dangerous one: it moves time discontinuously and can expire or
  un-expire authority in a single jump.
- Alert on offset > 500ms sustained.
- **Do not add read replicas** for authorization reads. A replica reintroduces a
  second clock into validity decisions, which is precisely what G-12 removed.

### What is not covered

- **No rate limiting** at the API boundary (G-15). Put your gateway in front.
- **No egress detection.** Altus cannot tell whether an agent also holds
  credentials that bypass it. Removing side channels is a deployment control:
  network policy plus rotating any bank credential the agent previously held.
  Verify it as part of the pilot's security review.
- **No workload-bound identity** (G-1). Bearer tokens only; no mTLS or SPIFFE yet.

---

## Deployment prerequisites checklist

- [ ] PostgreSQL 16, single primary, no read replicas for authorization reads
- [ ] The application connects as a **non-owner** role — RLS is FORCEd and the
      table owner bypasses it
- [ ] NTP configured on the database host with step-event alerting
- [ ] A key manager selected, and `AwsKmsSecretProvider` (or equivalent) written
- [ ] `SECRET_PROVIDER=kms`, `RECEIPT_SIGNING_KEY_B64` **unset**
- [ ] `SIGNAL_AUTHENTICATION=required`, `SIGNAL_LEGACY_HMAC=refused`
- [ ] Every signal source enrolled with an Ed25519 public key
- [ ] `EXECUTION_PROVIDERS=none` for shadow mode; a real adapter after
- [ ] Alerting wired for the four page-immediately conditions
- [ ] Any bank credential the agent previously held has been rotated

Reference manifests: `deploy/k8s/`. The `Secret` template deliberately omits
`RECEIPT_SIGNING_KEY_B64` and explains why.
