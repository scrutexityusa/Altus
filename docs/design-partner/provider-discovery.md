# Provider discovery: eight questions before any integration

**For the first conversation with a payment provider, rail, or internal treasury
service. Questions, not a pitch.**

Altus today enforces by sitting in the execution path
([ADR-0022](../decisions/0022-enforcement-model.md), Mode A). The direction is
Mode B: the provider verifies a signed authorization artifact and refuses
without one, so going around Altus fails at the rail instead of succeeding
quietly.

**Whether that is possible on a given rail is their answer, not our design.**
These eight questions determine whether Mode B is straightforward, partially
enforceable, impossible there, or a reason Mode A stays. Nothing about the
attestation should be built before a provider has answered them, because the
answers determine its lifetime, its revocation semantics and whether it is
single-use — and those are the whole design.

## The one sentence to open with

> We already bind the exact execution intent cryptographically — action, amount,
> currency, counterparty, and the authority that permitted it. The open question
> is what revocation semantics your rail requires after issuance.

That is a different conversation from "would you like to integrate our API".

## The questions

**1. Can your API require an external authorization artifact before executing an
action?**
The threshold question. If nothing can be required, Mode B is impossible on this
rail and Mode A is the only enforcement available.

**2. Can you verify Ed25519 signatures, or call a customer-controlled verifier?**
Two acceptable shapes. The second is often easier for a rail that will not add
crypto to its own path, and it keeps the trust anchor with the customer rather
than with us.

**3. Can an authorization artifact be single-use?**
If the rail can burn an artifact on first use, replay stops being our problem.
If not, expiry is the only bound and it has to be short.

**4. What authorization lifetime is acceptable?**
The core number. Thirty seconds and five minutes are different products. Ask for
their reasoning, not just the figure — it exposes what they think the artifact
is protecting against.

**5. How do you handle revocation after an authorization has been issued?**
The hardest question and the one to spend most time on. In Mode A a lease
revoked one second after the ALLOW stops the payment, because the boundary walks
the whole ancestry at execution time. A provider holding a signed artifact
cannot do that. Their options, in descending order of what they preserve:
provider callback for high-value transfers; revocation-list checking; nothing
but short expiry.

**6. Can the provider enforce exact intent binding — action, amount, currency and
counterparty — not just "this customer is authorized"?**
This separates Altus from OAuth. A rail that can only check _who_ is asking has
not enforced authority; it has enforced identity. If the answer is no, say so
plainly in the pilot scope rather than describing it as enforcement.

**7. What happens if the authorization service is unavailable?**
Their answer tells you what they expect of us operationally. It is also the
question where Mode B is genuinely better and worth saying so: a valid unexpired
artifact executes without us, so authority survives our downtime within a
bounded window.

**8. Do you have an idempotency primitive we can bind to `grant_id` or
`decision_id`?**
Usually yes, and usually the cheapest win in the whole integration. Binding
their idempotency key to our grant id makes a double payment structurally
impossible across both systems rather than in one.

## Reading the answers

| Pattern                      | What it means                          | What to do                                                     |
| ---------------------------- | -------------------------------------- | -------------------------------------------------------------- |
| Yes to 1, 2, 3, 6            | Mode B is straightforward on this rail | Build the attestation to their spec — and only theirs          |
| Yes to 1 and 2, no to 6      | Identity enforcement only              | Mode A for intent binding; do not call their check enforcement |
| No to 1                      | Mode B is impossible here              | Mode A, and say why in the pilot scope                         |
| Yes to 5 with a callback     | Best case                              | Revocation semantics survive the move; lifetime can be longer  |
| Long lifetime, no revocation | The risky combination                  | Push for single-use, or keep Mode A for high-value tiers       |

## What not to do in this conversation

- **Do not propose an artifact format.** We have one
  (`ExecutionGrantBinding`); proposing it before question 4 is answered
  pre-commits the lifetime and revocation model to a guess.
- **Do not build a provider adapter to demonstrate intent.** A speculative
  adapter for a rail nobody has committed to is the cost of the meeting paid
  twice.
- **Do not describe Mode A as cryptographic enforcement.** It is enforcement by
  position, it is honest, and overstating it in the room where somebody knows
  the difference costs the whole conversation.
