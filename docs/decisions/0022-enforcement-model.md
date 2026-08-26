# ADR-0022: What Altus enforces, and who is trusted to enforce it

**Status:** Accepted for Mode A; Mode B is the stated direction and is not built
**Date:** 2026-08-24
**Relates to:** [ADR-0015](0015-exact-intent-binding.md), [ADR-0016](0016-execution-enforcement-boundary.md)

## The question this answers

Not "is the decision correct" — the rest of this repository is about that. This
one:

> When Altus says no, what actually stops the payment?

Three answers are possible, they imply different companies, and the difference
is **who has to be trusted**.

## Mode A — Orchestrated enforcement (built)

```
agent → Altus authorize → Altus claims → Altus calls the provider → Altus settles
```

Altus performs the operation. `POST /v1/execute` reconstructs the authorized
operation from its own records, refuses anything that does not match, and is the
only path to the provider. This is what `guard()` does today and what
ADR-0016 describes.

**Who is trusted:** the customer trusts _us_, twice. We hold the provider
credential, and we are on the network path between the agent and the money.

**What actually stops the payment:** our position. Nothing cryptographic. An
agent that can reach the bank directly is not stopped by anything here — it is
merely not using us. That is the honest limit of Mode A, and no amount of
invariant work inside the boundary changes it.

**The burden:** holding a bank credential makes us an execution intermediary.
Every failure mode of a payment orchestrator becomes ours, and "Scrutexity runs
your payments" becomes the company whether or not anyone chose it.

## Mode B — Provider attestation (the direction; not built)

```
agent → Altus authorize → signed attestation → agent → provider verifies → executes
```

Altus signs a short-lived artifact. The provider — a bank, a payment rail, an
internal treasury service — verifies the signature and refuses without a valid
one. Altus never touches the money and holds no provider credential.

**Who is trusted:** the provider trusts _a public key_. Not our uptime, not our
network position, not our operational competence. The customer has to trust us
**less** than in Mode A, and that is the strongest argument for it — stronger
than the moat argument, which is a statement about us rather than about them.

**What actually stops the payment:** the provider, holding a signature it cannot
forge. An agent that goes direct now fails at the rail, which is the position
worth occupying.

### The artifact already exists

This is not a format to design. `ExecutionGrantBinding` in
`packages/core/src/operation.ts` already carries every field the attestation
needs, and `computeBindingHash` already hashes it:

| Field                   | Already present as                                                                              |
| ----------------------- | ----------------------------------------------------------------------------------------------- |
| the exact operation     | `authorized_intent` (canonical: action, resource, amount, currency, counterparty)               |
| the authority behind it | `authorization_context` — decision id, lease id, policy version and hash, approved context hash |
| identity of the grant   | `grant_id`                                                                                      |
| expiry                  | `expires_at` — "a grant with no expiry is not a grant"                                          |
| replay separation       | `nonce`                                                                                         |

What is missing is one step: sign it with the Ed25519 key custody already
provides, and return it to the caller. The work in Mode B is not the artifact.
It is everything below.

### The hard part, named precisely

**A signed attestation is a bearer capability, and Mode A's best property does
not survive the move.**

Today the boundary re-checks liveness at the instant of execution:
`assertAuthorityStillLive` walks the whole lease ancestry, and a lease revoked
one second after the ALLOW stops the payment. A provider holding a signed
artifact cannot do that. Once issued, it is honoured until it expires.

Three ways to narrow the window, none of which closes it:

- **Short expiry.** Seconds, not minutes. Cheap, and it converts revocation
  latency into a bounded number the customer can be told.
- **Provider-side revocation check.** An endpoint the provider calls before
  executing — which reintroduces our availability into the path, partially
  giving back what Mode B bought.
- **Provider-side idempotency on `grant_id`.** Stops replay, not revocation.

The choice among these belongs to the first provider integration, because it is
their operational risk appetite, not ours.

## Mode C — Observe (not built, and dangerous)

Altus evaluates and records; nothing is blocked. It is on the roadmap only as a
rollout aid, and it carries a specific hazard: a dashboard showing DENY
decisions looks identical in Mode C and Mode A. A deployment that believes it is
enforcing when it is observing is worse than one with no control at all, because
somebody has stopped watching.

If it is ever built, the decision record must be explicit in the API response
and in every receipt — the way `unenforced` already marks a self-reported
execution today.

## When Altus is unavailable

The mode determines the answer, which is a further argument for B.

| Situation                                       | Behaviour                                                                                                                                                                   |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A new authorization is requested                | **Fail closed.** No decision, no action. Callers see a refusal, not a timeout that a retry loop reinterprets.                                                               |
| An execution was already claimed                | **Reconciliation.** The committed `EXECUTING` claim is the record; `GET /v1/executions/unresolved` is the queue. Proven under SIGKILL by `make recovery`.                   |
| A valid, unexpired attestation is held (Mode B) | **The provider may execute.** Altus being down does not stop work it already authorized — availability is decoupled from authority.                                         |
| Nothing above applies and money must move       | **Break-glass:** an explicit human procedure, outside Altus, separately audited. Not a flag in this system. If it were a flag, it would be the flag everyone learns to use. |

The third row is the one that matters architecturally. In Mode A, Altus down
means payments stop. In Mode B it does not, and that is a better answer than any
cache or replica.

## The rule underneath all three

**A decision is not automatically an execution capability.**

That gap is the whole product. Mode A bridges it by standing in the path; Mode B
bridges it by turning a narrowly bound grant into something the provider can
verify. A system that closes the gap by _assuming_ it — that answers "yes, this
was allowed" after the money has already moved — is an audit log with opinions,
and it is what Altus becomes if the binding ever stops being enforced at the
moment of execution.

The corollary is the sentence worth defending: **the exact thing being executed
must be cryptographically bound to the authority that permitted it.** The hard
part of that already exists in `ExecutionGrantBinding`. What changes between
modes is only who checks it.

## Two parties, and the vocabulary the schema uses

"Who is trusted to enforce it" turns out to be two questions that were being
answered as one:

- **Whose authority is spent.** The agent holding the lease. `agent_id`.
- **Who invoked the boundary.** The principal that called `/v1/execute`.
  `invoked_by_type` and `invoked_by_id`.

They coincide when an agent executes under its own credential, which made it
easy to record only the first. They part company the moment an operator or an
orchestrating service executes on the agent's behalf — which Mode A has always
permitted, because standing in the path does not mean being the only caller.
Recording only the agent produced a receipt naming a party that did not act.

The enforcement model therefore takes a position: **an execution has exactly
one invoker, and the boundary never infers it.** The agent may be resolved from
the decision; the invoker is read from the authenticated principal and from
nowhere else. In Mode B this survives unchanged — the attestation a provider
verifies should name both parties, because "the bank asked who authorised this"
and "the bank asked who submitted it" are different questions, and a provider
that can only answer the first has an attribution gap of its own.

Rows written before this distinction existed record `unrecorded`, which is
neither party. Backfilling them to the agent would have asserted the one thing
that was never established.

## Decision

1. **Mode A is the reference implementation and the design-partner wedge.** It
   stays. It is how a partner sees enforcement work end to end without asking
   their bank for anything.
2. **Mode B is the product direction.** The claim to build toward is _Altus
   makes authorization a verifiable prerequisite for autonomous action_ — not
   _Altus moves your money_.
3. **Neither is built further until a partner names a provider.** Mode B's open
   questions — expiry, revocation, replay — are answered by a specific rail's
   risk appetite. Guessing produces an attestation format nobody verifies, which
   is the same as no attestation.
4. **Mode C stays unbuilt.**

## Consequences

- The positioning line becomes the one above, and treasury becomes the first
  proving ground rather than the product.
- Mode A's honest limit — enforcement by network position — belongs in the
  security brief, stated as plainly as it is here.
- Nothing in `@scrutexity/core` needs to change for Mode B. The binding is
  already the artifact; the signer already exists. That is a reason to wait
  comfortably, not a reason to start.
- Evidence anchoring ([ADR-0021](0021-evidence-anchoring.md)) matters more in
  Mode B, not less: a provider that verified an attestation will one day want to
  prove which one it verified.
