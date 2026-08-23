# Altus security brief

**For a CISO or CFO. Five minutes. Precision over enthusiasm.**

## What Altus is

Altus is a runtime authority control plane for autonomous agents that take
high-consequence actions — principally moving money. It sits between an agent
and a payment provider. It decides whether an action is authorised, records why,
and is the only path from the agent to the outside world. It is not a fraud
model, an agent framework, or a workflow engine. It answers one question, at the
moment the action is attempted: _does this agent hold the authority to do exactly
this, right now?_

## The authority theorem

```
HumanAuthority ⊇ AgentAuthority ⊇ DelegatedAuthority
              ⊇ EffectiveAuthority ⊇ ExecutionGrant ⊇ ActualExecution

                  ExecutedIntent = AuthorizedIntent
```

In plain language: **authority only ever shrinks as it flows down, and what gets
executed is exactly what was authorised.** No step in the chain can hold more
than the step above it, and the operation that reaches the bank is the same
operation that was approved — not a similar one, not a corrected one.

## The four laws

Checked at runtime as a postcondition on every ALLOW, not asserted in tests
alone. A violation is reported as `AUTHORITY_INVARIANT_VIOLATION`, never as an
ordinary policy denial — the two mean different things and an operator who sees
denials daily would not notice one more.

| Law | Statement                               | Meaning                                            |
| --- | --------------------------------------- | -------------------------------------------------- |
| 1   | `ChildAuthority ⊆ ParentAuthority`      | A delegated grant cannot exceed what delegated it. |
| 2   | `EffectiveAuthority ⊆ GrantedAuthority` | Risk signals only ever subtract authority.         |
| 3   | `ExecutionGrant ⊆ AuthorityLease`       | Executing cannot widen what was held.              |
| 4   | `ExecutedIntent = AuthorizedIntent`     | The operation performed is the one authorised.     |

## What the system guarantees

- **Authority cannot be synthesised.** A lease is bounded by an issuance ceiling
  that lives in the reviewed policy. Two narrow roles are never unioned into a
  broad one.
- **Authority cannot silently drift.** Persisted authority is re-verified at
  decision time. A grant widened by a bug, a migration, or direct database
  access is caught and refused.
- **Authority cannot survive its validity boundary.** Every expiry is judged
  against one authoritative instant read from the database, not from the
  application node's clock. A skewed node changes no answer.
- **Signals cannot forge authority.** Sources must enrol an Ed25519 public key.
  Even a mathematically valid signal from a fully compromised, legitimately
  trusted source cannot turn a DENY into an ALLOW or raise a ceiling.
- **Authority cannot be spent twice.** One execution claim per grant, committed
  before the provider is contacted. Verified against a real `SIGKILL` of a real
  process, mid-payment.
- **Authority cannot leak through reads.** Subject-scoped reads return 404, never
  403, so the API is not an existence oracle. Agents cannot read the control plane.
- **Every decision is replayable.** The decision function is pure — no clock, no
  I/O, no randomness. Given the recorded facts it returns the same answer forever.
- **Evidence is tamper-evident.** A per-tenant hash chain, Ed25519-signed,
  append-only. _Independently verifiable_ — not "immutable".

## What the system does not guarantee

Stated plainly, because a control plane that overstates is worse than one that
does less.

- **It does not detect fraud or anomalies.** It consumes signed assertions from
  systems that do.
- **It does not prevent an agent acting through a channel it does not mediate.**
  If the agent holds bank credentials directly, Altus is not in the path, and
  there is no egress detection to catch that. Removing side channels is the
  partner's work.
- **It does not judge whether a decision was _correct_.** The receipt attests to
  `evidence_integrity_and_provenance` — that this decision was made, under this
  policy, on these facts. Whether the policy was wise is a human question.
- **It does not make the agent safe.** It bounds the consequences of an unsafe one.
- **It is not a compliance product.** It has no certification and maps no control
  framework for you.
- **It does not stop a human with authority from approving a bad payment.** It
  makes it a named human, at a named time, on a specific operation.

## The execution state machine

`POST /v1/execute` is the only path to the provider. It runs as two
transactions with the external call strictly between them.

```
                 ┌───────────┐
   claim ────────► EXECUTING │   claim committed; provider not yet contacted
   (committed     └─────┬─────┘
    before the          │  provider answers
    provider is    ┌────┴────┬──────────────┐
    contacted)     ▼         ▼              ▼
             ┌──────────┐ ┌────────┐ ┌───────────┐
             │ EXECUTED │ │ FAILED │ │  UNKNOWN  │
             └──────────┘ └────────┘ └─────┬─────┘
              it happened   it did not      │ reconciled out of band
                                            ▼
                                     ┌────────────┐
                                     │ RECONCILED │
                                     └────────────┘
```

**`UNKNOWN` is a first-class state and is never collapsed into `FAILED`.** "The
wire did not go" and "I do not know whether the wire went" call for opposite
responses from an operator, and a system that reports the second as the first
will eventually cause a double payment.

A retry against an unresolved claim returns **409 `EXECUTION_UNRESOLVED`** — not
a fresh execution and not `REPLAY_DETECTED`, which would falsely tell the caller
the work is finished. The idempotency key is derived from the decision id and is
never regenerated, so an operator resubmitting during reconciliation days later
reaches the same payment at the provider rather than creating a second one.

## How Ed25519 signals work

A risk signal reduces an agent's authority. That makes forging one a denial of
service against a legitimate agent, and replaying a stale low-risk reading a way
to open a window.

1. The source generates an Ed25519 keypair and registers **only the public half**.
   Altus never holds anything that can produce a signature.
2. Every signal is signed over a canonical envelope covering the tenant, subject,
   type, value, confidence, source, event id, issue time and TTL.
3. Verification checks the key belongs to the claimed source, is within its
   validity window, and is not revoked — all against the database clock.
4. Enrolment is mandatory. An unenrolled source is refused
   (`SIGNAL_SOURCE_NOT_ENROLLED`). HMAC is refused by default everywhere and
   cannot be enabled in production.
5. Replay is refused: the event id is unique per source per tenant.

**The layer that matters more:** all of the above assumes the attacker cannot
sign. Containment assumes they can — even with the real private key, a signal can
only subtract. Asserted over 1,500 randomised signal sets and in the adversarial
suite, using signatures that verify.

That property found a real defect: a signal could convert a hard DENY into an
approvable escalation, so asserting _more_ risk produced a _more_ permissive
outcome. Fixed and regression-tested; G-19 in the security surface map.

## How evidence is verified

Each tenant has a hash chain. Every receipt carries a payload hash, a link to its
predecessor, and an Ed25519 signature. Verification is three independent checks —
payload digest, link hash, signature — plus a chain walk to genesis.

- `POST /v1/receipts/{id}/verify` — verify a stored receipt and its chain segment.
- `POST /v1/receipts/verify` — verify a receipt **you hold**, offline, against
  the published key, and separately report whether it matches the stored record.

A tampered receipt reports `COMPROMISED`. `make demo` tampers with one on
purpose and shows the failure.

## Current production limitations

These are the honest gaps as of this release. None is hidden behind a flag.

1. **No KMS is wired.** Production requires `SECRET_PROVIDER=kms`, and the
   provider throws on every read because no specific key manager is connected.
   The deployment therefore _refuses to start_ rather than falling back to local
   key custody. That is the correct failure, and it means **no deployment of this
   code has yet started in a production posture.** Wiring a partner's chosen
   manager is scoped week-one work.
2. **No external egress detection.** Altus cannot tell whether an agent also
   holds credentials that bypass it. Its guarantees hold over the path it
   mediates. Removing side channels is a deployment control, not a product one.
3. **No workload-bound identity.** Authentication is bearer tokens; there is no
   mTLS or SPIFFE binding yet (gap G-1).
4. **No rate limiting** at the API boundary (G-15).
5. **A signal source is not bound to a signal type.** Any enrolled source can
   assert any type about any subject (G-6). Containment bounds the damage;
   the authorisation is still coarser than it should be.
6. **`UNKNOWN` is surfaced, not auto-resolved.** Reconciliation is a queue plus a
   provider `verifyExecution` call, deliberately not a background worker — a
   reconciliation loop that runs twice is how an `UNKNOWN` becomes a double payment.
7. **Single region, single Postgres.** No read replicas, deliberately: a replica
   would reintroduce a second clock into validity decisions.

## Verify it yourself

```
make ci           # 609 tests, lint, build, demo
make adversarial  # 11 security invariants, mounted as real attacks
make recovery     # SIGKILL the process mid-payment; assert what survived
```

Full threat model and residual risks: `docs/security-surface-map.md` and
`docs/design-partner/red-team-handoff.md`.
