# The four-week pilot

**Purpose:** establish whether a treasury team can bound what an agent is able to
do, and prove it to their own security function — without the founding team in
the room.

The pilot succeeds or fails on evidence, not enthusiasm. Every criterion below is
observable in the system's own records. If a criterion cannot be checked from the
receipts, the metrics, or a `make` target, it is not on the list.

## Before week 1 — the gate

Do not start until all four are true. A pilot that starts without them spends its
first two weeks on procurement instead of on the model.

- [ ] A named workflow with a real amount, and a person who owns it.
- [ ] Security has read `security-brief.md` and agreed to a week-4 review.
- [ ] A PostgreSQL 16 instance and somewhere to run a container, in the partner's
      own account.
- [ ] A payment provider sandbox with API credentials.

## Week 1 — Environment and integration

**Goal: a real decision from a real policy, on the partner's infrastructure.**

| Who              | Work                                                                        |
| ---------------- | --------------------------------------------------------------------------- |
| Partner eng      | Deploy against their Postgres. Run `make demo` themselves.                  |
| Partner eng      | Write the `ExecutionProvider` adapter against the sandbox. Not enabled yet. |
| Partner eng + us | Wire the `SecretProvider` for the chosen key manager.                       |
| Treasury         | Translate their approval matrix into `policies/treasury-wire.yaml`.         |
| Partner eng      | Enrol signal sources with Ed25519 keys.                                     |
| Agent team       | Point the agent at `POST /v1/authorization/evaluate`.                       |

**Exit criteria**

- [ ] `make ci`, `make adversarial`, `make recovery` all green on partner infra
- [ ] The partner's own policy is authored, reviewed by two humans, activated
- [ ] The partner's copy of `policy-pack.test.ts` passes against their thresholds
- [ ] `SECRET_PROVIDER=kms` boots against their key manager
- [ ] At least one authorization decision exists with a verifiable receipt

**The likely blocker:** the KMS wiring. It is one file and one SDK dependency,
but it is also the first time this code has run in a production posture anywhere.
Budget two days, not two hours.

## Week 2 — Shadow mode

**Goal: Altus decides on real traffic and changes nothing.**

`EXECUTION_PROVIDERS=none`. Every enforced execution is refused with
`ENFORCEMENT_UNAVAILABLE`. The agent asks for a decision and continues down its
existing path regardless. Real requests, real policy, zero external effects.

| Who           | Work                                                                                  |
| ------------- | ------------------------------------------------------------------------------------- |
| Agent team    | Every payment attempt calls `evaluate` first; log the decision, act as before         |
| Treasury      | Review the decision log daily. Every ESCALATE: is it right? Every ALLOW: comfortable? |
| Partner eng   | Wire the four page-immediately alerts                                                 |
| Treasury + us | Tune thresholds. Expect at least one policy revision — that is the point              |

**Exit criteria**

- [ ] ≥ 50 real authorization decisions recorded (or one week, whichever is more)
- [ ] Zero unexplained decisions — every ESCALATE and DENY has an accepted reason
- [ ] The decision distribution matches what treasury expected, or the policy was
      changed until it did
- [ ] At least one policy revision has gone through review and activation
- [ ] The team can pull a trace for any decision and read it without help

**The signal to watch for:** the first time treasury says _"wait, why did that
escalate?"_ and the trace answers it in one call. That moment is the pilot's real
outcome; everything else is instrumentation.

## Week 3 — One real transaction

**Goal: money moves through the enforcement boundary, once, watched.**

Only proceed if week 2 exited clean and the partner's own change-approval process
has signed off. Skipping to week 4 is a legitimate outcome.

**The setup, deliberately narrow:**

- A `SINGLE_USE` lease with `max_amount` set to **exactly** that transaction's
  amount
- One counterparty, already registered, previously paid
- A low value the partner would not mind losing entirely
- `POST /v1/execute` — the enforcement boundary, not `/v1/executions`
- A human watching the metrics endpoint while it runs

**The sequence**

1. Evaluate → confirm ALLOW, note the `exact_intent_hash`
2. Execute → `201`, provider contacted once, `EXECUTED`
3. Verify the receipt; confirm the executed intent hash matches
4. Retry the same grant → confirm `409` or `200 replayed`, never a second payment
5. Reconcile the bank statement against the receipt

**Then, deliberately, break something.** With treasury's agreement, attempt one
payment with a mutated amount at the boundary. Confirm `INTENT_MISMATCH`, confirm
the provider was never contacted, confirm the security event.

**Exit criteria**

- [ ] Exactly one payment reached the bank, reconciled against the statement
- [ ] The mutation attempt was refused before provider contact, with an event
- [ ] The receipt verifies, including offline against the public key

## Week 4 — Security review and go/no-go

**Goal: the partner's security team forms an independent opinion.**

| Who                 | Work                                                                                      |
| ------------------- | ----------------------------------------------------------------------------------------- |
| Security            | Work through `red-team-handoff.md`. Run `make adversarial` and `make recovery` themselves |
| Security            | Attempt to answer the review question below                                               |
| Treasury + Security | Review the evidence model: is a receipt what you would want in an incident?               |
| All                 | Go / no-go, in writing                                                                    |

**The question the review must answer:**

> Can this system be made to authorize or execute something that violates its own
> authority model?

A finding is a good outcome. Two of the most serious defects in this codebase
(G-16 and G-19) were found by mechanisms built to look for something else. A
review that finds nothing has either confirmed the model or not tried hard enough,
and the report should say which.

## Success criteria

The pilot succeeds if **all** of these hold. Each names how it is checked.

| #   | Criterion                                                                                                                                                                 | Verified by                                                                                                                    |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| 1   | **No unauthorized execution.** Every external effect traces to an ALLOW whose executed intent hash matches its authorized intent hash.                                    | Every `execution_claims` row joins to a decision; `scrutexity_intent_binding_mismatch_total` shows zero _successful_ mutations |
| 2   | **No authority expansion observed.** No lease, delegation, or signal ever produced authority exceeding its source.                                                        | `scrutexity_authority_invariant_violations_total == 0` across the whole pilot                                                  |
| 3   | **At least one real human escalation occurred correctly.** A payment crossed a threshold, a named human approved or rejected, and the decision superseded the escalation. | The approval record and the causal trace                                                                                       |
| 4   | **At least one `UNKNOWN` was reconciled without a manual retry.** Induced deliberately if it does not occur naturally — a sandbox timeout is enough.                      | The claim moved `UNKNOWN → RECONCILED`; the provider shows one payment for that idempotency key                                |
| 5   | **Security signs off on the evidence model.** In writing: the receipt chain is what they would want in an incident.                                                       | Their written review                                                                                                           |
| 6   | **The CISO can explain the authority theorem to their board.** Unprompted, without notes.                                                                                 | Ask them to, on the go/no-go call                                                                                              |

Criterion 6 is not a soft one. If the model cannot be explained by someone who
did not build it, it is too complicated to be a security control — and that is a
finding about the product, not about the CISO.

**Criterion 4 deserves a note.** An `UNKNOWN` that never occurs has not been
tested. Induce one: point the adapter at a sandbox endpoint that times out, or use
the `crash-harness` provider. A reconciliation path first exercised during a real
incident is a reconciliation path nobody has exercised.

## Explicit non-goals

Stated so nobody is measured against them:

- **Not a performance evaluation.** Authorization is milliseconds and single-node;
  scale work happens when a partner's volume demands it.
- **Not a feature evaluation.** If something is missing, that is data about
  product-market fit, not a work order for week 3.
- **Not a procurement exercise.** No SOC 2 report to hand over, no vendor
  questionnaire. The security artifact is the repository.
- **Not a migration.** The existing payment path stays live throughout. Week 3
  moves one transaction.

## What "no-go" should mean

A no-go is a successful pilot if it produces a specific reason. Useful ones:

- "The authority model does not fit our workflow because X" — the most valuable
  outcome available, and it should change the product.
- "We need Y before production" — a scoped gap, dated.
- "Our agents are not ready" — correct, and not a product problem.

The one to avoid: "we ran out of time". That means the pilot was scoped wrong,
and the fault is ours.

## After

Whatever the outcome, the partner keeps everything: the repository, their policy,
their adapter, their evidence. Nothing is held hostage to a contract. A control
plane for a partner's own money movement should not be a service that can be
switched off from outside.
