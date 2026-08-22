# Cold email templates

Three audiences, three different problems. Do not send the same one twice into a
company — they talk to each other, and identical emails read as a sequence rather
than a conversation.

**Rules for all three:**

- Under 150 words. Nobody reads more from a stranger.
- One specific, falsifiable claim. No adjectives about the category.
- A link to something they can run, not to a landing page.
- No "quick call?" — offer the artifact and let them ask.
- If you do not know their workflow, say so rather than guessing at it.

---

## 1. Head of Treasury

**Subject:** Bounding what a payments agent is able to do

> Hi {Name},
>
> If your team is being asked to let an AI agent initiate payments, the question
> you are probably stuck on is not "is the model good enough" — it is "what,
> exactly, is it able to do if it is wrong or compromised, and can I prove that
> to my auditor?"
>
> We build the layer that answers it. An agent holds a scoped, time-bounded,
> revocable grant — specific accounts, specific counterparties, a ceiling, an
> expiry. Above your thresholds it escalates to a named human. It cannot change
> the amount between approval and execution: the operation that reaches the bank
> is byte-identical to the one that was approved, or nothing reaches the bank.
>
> Every decision produces a signed record that says why, and you can verify it
> yourself without trusting us.
>
> Happy to send a one-page brief your security team can pick apart. No deck.
>
> {Signature}

**Send when:** they have publicly discussed AI in finance ops, or you know they
run agents on reconciliation already.

---

## 2. Head of AI Platform / Engineering

**Subject:** The authorization layer your payments agent is missing

> Hi {Name},
>
> Guessing at your situation: you have an agent that works, and it is not going
> near production because nobody will own the risk of it moving money. The gap
> is not the model. It is that there is no way to say _this agent may move up to
> $50k, to these counterparties, for the next hour_ and have that be enforced
> rather than prompted.
>
> That is what we built. Authority as a scoped, revocable lease; a pure decision
> function you can replay; and an execution boundary that hashes the authorized
> operation and refuses a mutated one **before** the provider is contacted.
>
> The parts worth your scepticism:
>
> - `make adversarial` — 11 security invariants, mounted as real attacks
> - `make recovery` — SIGKILLs the process mid-payment, then proves a different
>   process refuses to retry
>
> Both run from a clean checkout in about a minute. Want the repo?
>
> {Signature}

**Send when:** they have shipped agents anywhere, or posted about agent
guardrails. This is usually the first thread; they become the champion.

---

## 3. CISO / Head of Security

**Subject:** Agents with payment authority — the model, for you to break

> Hi {Name},
>
> Somewhere in your organisation, someone is asking to give an autonomous agent
> the ability to move money. You will be asked to sign off on it.
>
> We built the control plane for that, and the honest pitch is this: here is the
> model, please try to break it.
>
> The claim is one theorem — authority only ever shrinks as it flows down, and
> what executes is exactly what was authorised. Four laws, checked at runtime as
> a postcondition on every allow, not asserted in tests alone. Ed25519-signed
> risk signals that can only ever subtract authority, including from a source
> that is fully compromised. Exactly-once execution, verified against a real
> SIGKILL mid-payment.
>
> Also honest: no KMS is wired yet (production refuses to start without one, by
> design), no egress detection, no workload-bound identity. All of it is written
> down in a gap register with a status per gap.
>
> One page for you, or the repository if you would rather just run the adversarial
> suite. Which?
>
> {Signature}

**Send when:** you have already spoken to engineering, or they have written about
AI risk. Leading with the limitations is not modesty — it is the only thing that
distinguishes this from every other AI-security email in their inbox.
