# Red team handoff

**For an independent reviewer.** Everything needed to attack this system,
including a map of where we think it is weakest.

## The question

> **Can this system be made to authorize or execute something that violates its
> own authority model?**

Not "is the code good". Not "would you deploy this". One question, and the
answer we most want is a counterexample.

Anything reaching the outside world that was not covered by an ALLOW — or that
differs by even one byte from the ALLOW that covered it — is a finding. So is any
path by which authority ends up wider than its source.

## Threat model summary

**What is being protected:** the authority to move money, and the record of who
authorised it.

**Assumed adversaries, in the order we take them seriously:**

| Adversary                                   | Capability assumed                                                                                                        |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **A compromised agent**                     | Holds valid credentials. Can call every endpoint its scopes allow, in any order, concurrently. **The primary adversary.** |
| **A compromised signal source**             | Holds a real Ed25519 private key that Altus correctly trusts. Can sign anything.                                          |
| **A malicious insider with `leases:write`** | Can attempt to issue authority.                                                                                           |
| **An attacker with direct database access** | Can mutate persisted rows, bypassing every API.                                                                           |
| **An attacker who can move the clock**      | On the API host. (Not on the database host — see out of scope.)                                                           |

**Explicitly out of scope for this review:**

- Compromise of the PostgreSQL primary's clock or superuser role. Both are
  assumed-trusted; if you can set database time arbitrarily you can expire or
  un-expire any authority, and we know it.
- Denial of service. There is no rate limiting (G-15) and we are not claiming any.
- The correctness of the partner's policy. We enforce semantics; we do not author
  them.
- Cryptographic primitives themselves. Ed25519 and SHA-256 are assumed sound.

**What we claim, precisely:**

```
HumanAuthority ⊇ AgentAuthority ⊇ DelegatedAuthority
              ⊇ EffectiveAuthority ⊇ ExecutionGrant ⊇ ActualExecution
                  ExecutedIntent = AuthorizedIntent
```

## The four laws and the flow

```
   POLICY ACTIVATION            two humans review; content hash recorded
        │
        │  issuance ceiling per role — never unioned across roles
        ▼
   AUTHORITY LEASE              actions · resources · constraints · TTL
        │                       revocable; revocation cascades
        │  LAW 1  child ⊆ parent
        ▼
   DELEGATED LEASE              financial actions non-delegable at any scope
        │
        │  LAW 2  effective ⊆ granted        ← signals subtract only
        ▼
   EFFECTIVE AUTHORITY
        │
        │  LAW 3  grant ⊆ lease
        ▼
   EXECUTION GRANT              single-use; bound to one exact operation
        │                       two hashes: exact_intent, binding
        │  LAW 4  executed = authorized      ← hash comparison
        ▼
   ┌────────────────────────────────────────────┐
   │  ENFORCEMENT BOUNDARY  (POST /v1/execute)  │
   │  T1: claim + consume grant  → COMMIT       │
   │      provider call                         │
   │  T2: settle outcome         → COMMIT       │
   └────────────────────────────────────────────┘
        │
        ▼
   ACTUAL EXECUTION             exactly one external effect per grant
```

Laws 1–3 are containment checks in `packages/core/src/invariants.ts`, run as a
**postcondition on every ALLOW**. Law 4 is a hash comparison in
`packages/core/src/operation.ts`. A violation is `AUTHORITY_INVARIANT_VIOLATION`,
never an ordinary policy denial.

## Design decisions worth attacking

Each of these is a place we made a choice. If a choice is wrong, this is where.

1. **The decision function is pure.** No clock, no I/O, no randomness. All facts
   are assembled by the caller into a snapshot. _Attack:_ can the snapshot be made
   to disagree with reality between assembly and use?
2. **Two hashes, deliberately not merged.** `exact_intent_hash` answers "did the
   operation mutate?"; `binding_hash` answers "is this bound to _this_ authority?"
   _Attack:_ find an operation where one holds and the other should not.
3. **The database is the only clock.** `transaction_timestamp()`, one instant per
   decision. _Attack:_ find a validity comparison that still reads the API clock.
4. **The claim commits before the provider is called.** Two transactions with the
   external call between them. _Attack:_ find a path to the provider where the
   claim is not yet externally visible.
5. **Ceilings are never unioned.** A request must fit wholly inside one.
   _Attack:_ find a way to combine two roles' authority.
6. **404, never 403,** for subject-scoped reads. _Attack:_ find an oracle —
   timing, response shape, error text — that distinguishes "exists" from "not yours".
7. **Signals subtract only.** _Attack:_ find any input, from a source holding a
   valid key, that makes an outcome more permissive.

## Already covered

`make adversarial` — 11 invariants, mounted as real attacks against a real
database through the public API. The registry is `test/adversarial-manifest.json`;
a scenario declared there with no implementation fails the run.

| #   | Scenario                           | Attack                                                                                                                   |
| --- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| A1  | Temporal expiry                    | Execute at the expiry instant ±1ms, with the API clock skewed an hour each way                                           |
| A2  | Revocation                         | Revoke an ancestor after the ALLOW, then execute the outstanding grant                                                   |
| A3  | Authority drift                    | Mutate the stored child grant directly in the database, then evaluate                                                    |
| A4  | Privilege synthesis                | Request a lease covered only by the union of two roles' ceilings                                                         |
| A5  | Isolation and enumeration          | Read another subject's decision, trace, receipt, lease; read across tenants                                              |
| A6  | Clock disagreement                 | Same durable state, API clock ±1h                                                                                        |
| A7  | Signal compromise                  | Forged signature, unenrolled source, legacy HMAC; then a **valid** signal crafted to flip DENY→ALLOW and raise a ceiling |
| A8  | Replay and concurrency             | 10 concurrent executions against one grant, then sequential retry                                                        |
| A9  | Crash before the provider          | Retry against a committed claim with no payment                                                                          |
| A10 | Provider success, settlement crash | Retry after the money moved and the record did not                                                                       |
| A11 | Transaction fault injection        | From inside the provider, on an independent connection, assert the claim is already committed                            |

`make recovery` — three scenarios against a **real** `SIGKILL` of a **real** child
process, killed after the claim and before the payment, and after the payment and
before settlement. The provider's ledger is a separate committed table, because a
`SIGKILL` takes memory with it.

Property tests in `packages/core/test/invariants.test.ts`: containment over 2,000
random restrictions, signal containment over 1,500 random signal sets, decision
determinism, and "no ALLOW without covering authority".

## Running it

```bash
git clone <repo> && cd Altus
make dev            # Postgres, migrations, seeded tenant
make ci             # 596 tests, lint, build, demo, adversarial, recovery
make adversarial    # the 11 invariants alone
make recovery       # the SIGKILL harness alone
make demo           # the treasury story, asserted end to end
```

**To confirm a test actually catches its defect,** break the control and re-run.
We do this ourselves — disabling the unresolved-claim refusal makes R1 and R2 fail
and R3 still pass. A test that passes when the control is removed is not a test.

## Known limitations and residual risks

The full register with per-gap status is `docs/security-surface-map.md`. The ones
a reviewer should know before starting:

| Gap                                       | Risk                                                                                                                                                                 | Status                                             |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| **KMS not wired**                         | Production requires `SECRET_PROVIDER=kms` and the provider throws on every read, so the process refuses to start. **No deployment has run in a production posture.** | Interface defined, not operationally verified      |
| **No egress detection**                   | If an agent holds bank credentials directly, Altus is not in the path and cannot tell.                                                                               | Not built. A deployment control, not a product one |
| **G-1: no workload-bound identity**       | Bearer tokens; no mTLS or SPIFFE. A stolen token is the agent.                                                                                                       | Validated, not fixed                               |
| **G-15: no rate limiting**                | No brute-force or enumeration throttling.                                                                                                                            | Validated, not fixed                               |
| **G-6: source not bound to signal type**  | Any enrolled source can assert any signal type about any subject. Containment bounds the damage; the authorization is coarser than it should be.                     | Validated, not fixed                               |
| **G-7: `UNKNOWN` surfaced, not resolved** | Reconciliation is a queue and a `verifyExecution` call, not automation. Deliberate — a loop that runs twice double-pays.                                             | By design, documented                              |
| **G-11: no external evidence anchor**     | The hash chain is tamper-**evident**, not tamper-**proof**. An attacker with database write access and the signing key could rewrite history consistently.           | Validated, not fixed                               |
| **G-13: no offline evidence export**      | Receipts verify offline one at a time; there is no signed bulk export.                                                                                               | Validated, not fixed                               |

**Two defects found by mechanisms built to look for something else,** stated
because they calibrate how much to trust the rest:

- **G-16** — the execution claim was inside the same transaction as the provider
  call, so a crash rolled it back and left the grant spendable with the money
  gone. Found by asking how long the authorization transaction stayed open.
- **G-19** — a signal could convert a hard DENY into an approvable escalation, so
  asserting _more_ risk produced a _more_ permissive outcome. Found by a
  randomised containment property, not by review.

Both are fixed and regression-tested. We expect there are more.

## Code of conduct for the review

**What we ask of you**

- Attack the model, not the deployment. A misconfigured demo instance is not a
  finding; a soundness hole in the authority model is.
- Report findings with a reproduction. A failing test case is ideal, and we will
  add it to the adversarial manifest with attribution if you want it.
- Tell us when a control is theatre. A comment claiming a property nothing
  enforces is a finding, and we would rather hear it from you.
- Say if you found nothing, and say whether that is because the model held or
  because you ran out of time. Both are useful; conflating them is not.

**What we commit to**

- Every finding gets a written response within five business days, with a
  severity we justify rather than assert.
- Confirmed findings go into `docs/security-surface-map.md` with the same status
  taxonomy as everything else, and stay there after they are fixed.
- Nothing is silently downgraded. If we disagree about severity we will say so in
  writing and record your position alongside ours.
- No NDA is required to review the model or run the suites. If your findings touch
  a partner's deployment specifics, we will ask you to scope those separately.
- We will not represent your review as an endorsement. If we quote you, we will
  quote your conclusion and your caveats together, and only with your approval.

**Out of bounds**

- Do not attack a live design partner's environment. Use your own deployment.
- Do not exfiltrate a partner's data if you find a path to it. Report the path.

## Where to start

If you have an hour: read `packages/core/src/invariants.ts` and
`services/api/src/adapter/enforce.ts`. Those two files carry the claim. The
enforcement boundary's comments explain the two-transaction structure and why it
cannot be one — that reasoning is the most load-bearing in the system, and if it
is wrong, everything downstream is.

If you have a day: run `make adversarial` and `make recovery`, then try to write a
twelfth scenario that fails.

**Contact:** {security contact} · **Repository:** {repo}
