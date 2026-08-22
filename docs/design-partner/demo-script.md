# The live demo

**Time: under 10 minutes. Audience: anyone. Prerequisites: Docker or a local
PostgreSQL, and Node with pnpm.**

Everything below is one command. There are no hidden steps, no fixtures loaded
out of band, and no slides. The demo asserts every scene as it runs — if the
output says `ALLOW`, the system returned `ALLOW`, and `make demo` fails the build
if it does not.

## Run it

```bash
git clone <repo> && cd Altus
make dev     # installs, starts Postgres, migrates, seeds the reference tenant
make demo    # the full treasury story, from a clean database
```

`make demo` resets the database itself, so it is repeatable and order-independent.
Set `NO_COLOR=1` for plain output on a projector.

If you have ten minutes and one command, that is the whole demo. The rest of this
document is what to say while it runs.

## What the audience is watching

One organisation, Acme Corporation Treasury. Two agents: `treasury-agent`, which
may move money within limits, and `verification-agent`, which may not. Three
humans: an operations admin who provisions, a treasurer who approves, and a CFO.
One external fraud engine that has enrolled a signing key.

The story is not "here are our features". It is a single claim, demonstrated:
**an agent can only ever do less than the authority it holds, and what reaches
the bank is exactly what was approved.**

---

## Scene by scene

### Scene 1 — Agent identity

Two agents, each with a named human owner.

> "Every agent is a first-class principal with an owner. Not a shared API key.
> When we ask later who authorised something, this is where the answer starts."

### Scene 2 — Authority issuance: a $50,000 lease

An **authority lease** is issued to `treasury-agent`: specific actions, specific
accounts, specific counterparties, a $50,000 ceiling, and an expiry.

> "This is not a role. It is a scoped, time-bounded, revocable grant. Note what
> it does _not_ say — it names no policy thresholds. Policy decides what may be
> done; the lease decides what may be held. Those are separate on purpose."

Point at the ceiling: **$50,000**. Everything after this is that number being
respected.

### Scene 3 — A $25,000 wire → ALLOW

Inside the lease and inside policy. Runs unattended.

The scene then **replays the same execution grant** and it is refused with
`REPLAY_DETECTED`.

> "An ALLOW is not a permission. It is a single-use grant against one operation.
> Using it twice is not a retry, it is a second payment."

### Scene 4 — A $75,000 wire → ESCALATE

Above the policy's $50,000 threshold. The response names the approval
requirement: quorum 1, role `treasurer`, self-approval forbidden.

> "The agent is not told 'no'. It is told exactly what would make this
> proceed — computed by the policy engine from the same facts that produced the
> escalation. No language model generates that."

The constraint check is printed verbatim, showing the ceiling comparison.

### Scene 5 — The treasurer approves

A named human approves. A **new** decision is produced, `APPROVED_BY_HUMAN`; the
escalation is superseded, never rewritten.

The CFO then attempts to approve the same request and is refused with
`STATE_CONFLICT`.

> "The record is append-only. The escalation still exists — you can see it was
> escalated and then approved, by whom, at what time, against which operation."

### Scene 6 — Delegation: verification only

`treasury-agent` delegates to `verification-agent`: `counterparty.read`, a $0
ceiling, one counterparty.

> "The agent is doing the delegating, and it cannot pass on what it does not
> hold. That is Law 1, enforced at creation and re-verified at every decision."

### Scene 7 — The delegated agent reaches beyond its remit

`verification-agent` attempts `wire.execute` → **DENY**.

> "Two independent things refuse this. Its lease has no `wire.execute`, and the
> policy marks money-moving actions non-delegable at any scope. Either alone
> would be enough. Defence in depth is not a slogan here — one of them being
> misconfigured must not be sufficient."

### Scene 8 — Mutation after authorization → refused before the provider

**This is the scene to slow down for.**

The agent asks for a $25,000 wire and is allowed. The authorized intent hash is
printed. The agent then presents a **different amount** — $75,000 — to the
execution boundary, under the same decision id.

```
DENY     INTENT_MISMATCH -- mutated: amount
   . the provider was never contacted; no money moved and none could have
```

Then it presents the operation it was actually authorized for, and that succeeds
with a matching executed intent hash.

> "This is the difference between a policy engine and an authority system. A
> policy engine tells the agent whether it may proceed and then trusts it. Here
> the boundary reconstructs the authorized operation from its own records,
> compares hashes, and refuses **before** anything external is contacted. And
> notice: the agent is required to present what it thinks it is doing. We could
> execute from our own records silently — but then a mutation attempt would be
> impossible _and invisible_. This way it is impossible _and detected_."

### Scene 9 — "WHY?" — the full causal trace

One call, `GET /v1/trace/{decision_id}`, for the approved $75,000 wire:

```
root cause: treasury_wire v1.4.0 activated (policy_activation)
 1. origin              treasury_wire v1.4.0 activated
 2. derived_from        treasury_wire v1.4.0
 3. admitted_authority  authority held by treasury-agent
 4. requested_under     treasury-agent requested wire.execute
 5. evaluated_to        ESCALATE — TREASURER_APPROVAL_REQUIRED
 6. approved_by         Marco Bellini approved
 7. superseded_by       ALLOW — APPROVED_BY_HUMAN
complete -- the chain reaches a policy activation
```

> "That is not a log search. It is a causal chain with typed edges, and it
> terminates at the moment a human activated the policy that admitted the
> authority. `complete` means it actually reached that origin rather than
> stopping short. This is the answer to 'why did the agent do this' — in one
> call, months later."

### Scene 10 — A fraud signal arrives

`fraud_risk = 0.97`, signed by the enrolled source. The **same $25,000 wire that
ran unattended a moment ago** now returns `ESCALATE / AUTHORITY_DECAYED`.

> "Authority narrowed. The agent's role did not change, its lease was not
> rewritten, and nothing was revoked. What changed is what it may do
> _unsupervised_. And this only ever goes one direction — a signal can subtract
> authority and can never add it, even a perfectly valid signal from a source we
> trust completely."

### Scene 11 — Revocation is immediate

The lease is revoked mid-incident. The next request is `AUTHORITY_REVOKED`, with
no grace period — and the **delegated** lease dies with its parent.

> "No cache to wait out. Revocation cascades because every decision walks the
> whole ancestry, live."

### Scene 12 — Evidence

A receipt is verified: payload hash, link hash, signature, and a chain walk to
genesis. Then the demo **tampers with a receipt on purpose** and verification
reports `COMPROMISED`.

> "The wording is deliberate: this attests to `evidence_integrity_and_provenance`.
> It says this decision was made, under this policy, on these facts, and has not
> been altered since. It does not say the decision was correct. And it is
> verifiable by you, offline, against the published key — you do not have to
> trust us to check it."

---

## Coverage map

The requested walkthrough, mapped to what runs:

| #   | Requested step                                    | Scene |
| --- | ------------------------------------------------- | ----- |
| 1   | Issue a $50,000 authority lease to TreasuryAgent  | 2     |
| 2   | $25,000 wire → ALLOW                              | 3     |
| 3   | $75,000 wire → ESCALATE with human approval       | 4, 5  |
| 4   | Delegate verification-only to VerificationAgent   | 6     |
| 5   | VerificationAgent attempts `wire.execute` → DENY  | 7     |
| 6   | Inject `fraud_risk = 0.97`                        | 10    |
| 7   | Authority reduced from autonomous to human-review | 10    |
| 8   | Mutate the execution amount after authorization   | 8     |
| 9   | Refuse before provider contact                    | 8     |
| 10  | "WHY?" — full causal trace                        | 9     |
| 11  | Signed authority verification report              | 12    |

**One ordering note, stated so it is not a surprise:** the mutation scene (8, 9)
runs _before_ the fraud signal rather than after. A live fraud signal decays
`wire.*` authority to `ESCALATE`, so there would be no ALLOW left to mutate. The
demo therefore proves the enforcement boundary first, then decays authority.
Scenes 11 and 12 are not in the requested list; they are kept because revocation
cascade and tamper detection are two of the strongest things to watch.

## If someone asks a question you cannot answer

Say so, and write it down. The honest answer to "can it do X" is very often "no,
and here is why we have not built it" — see the _what we are not_ list in
`outreach/discovery-call.md`. A request for something unbuilt is a signal about
product-market fit, not a work order.

## Going deeper in the same session

If the room wants to see the security work rather than the story:

```bash
make adversarial   # 11 invariants, mounted as real attacks against a real database
make recovery      # SIGKILL the API mid-payment; assert what survived
```

`make recovery` is the one to run for a sceptical engineer. It kills a real
process between the claim and the payment, and again between the payment and the
settlement record, then proves a _different_ process refuses to retry either one.
