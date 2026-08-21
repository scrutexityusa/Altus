# ADR-0016: The execution enforcement boundary

**Status:** Accepted
**Date:** 2026-08-21

## Context

ADR-0015 recorded, on every ALLOW, the exact operation it authorises. It said
plainly that nothing enforced it: `POST /v1/executions` accepted
`{decision_id, status}`, the agent reported an outcome, and the system believed
it.

That made Scrutexity a **recorder**. It could prove after the fact what had
been authorised. It could not stop an agent from being authorised to move
$25,000 to cp_100 and moving $250,000 to cp_999 instead, because it never saw
the operation and never touched the bank.

## Decision

Add a component that performs the operation, and give it the only path to the
external system.

```
Agent
  │  AuthorizationRequest
  ▼
Authority engine ──── ALLOW + intent binding (ADR-0015)
  │
  ▼
Enforcement boundary ── verifies, claims, calls
  │
  ▼
Provider ──────────── the external system
```

`POST /v1/execute` is that boundary. The caller presents the operation it
believes it is about to perform, and Scrutexity performs it.

### The agent presents the operation, and the presentation is a claim

The boundary could read the authorised operation out of its own records and
execute that, never asking the agent anything. That makes mutation
_impossible_.

It asks anyway, and requires an exact match, because a mutation attempt is a
fact worth learning. Requiring the agent to present its intent makes mutation
impossible **and detected**. A compromised agent that tries to redirect a wire
produces a security event and an alert, instead of a correct wire going out
while nobody notices the attempt.

The presented operation is never a source of truth. Every field is checked
against the recorded binding before anything is called.

### The order of checks, and why the claim comes before the call

1. The decision exists and belongs to this agent
2. It was an ALLOW
3. It carries an intent binding — a grant without one fails closed
4. It has not expired
5. **The authority is still live**, walking the whole ancestry, read fresh
6. Conditions have not moved since the decision (the TOCTOU fingerprint)
7. The operation matches `exact_intent_hash`
8. The operation is bound to this authority (`binding_hash`)
9. A provider exists for the action
10. **Execution rights are claimed** — one guarded `INSERT`
11. The grant is spent
12. The provider is called
13. The claim is settled and evidence is written

Steps 1–9 are checks and none of them touches an external system. Step 10 is
the commitment.

The classic shape

```
check the grant  ->  call the bank  ->  mark the grant used
```

is vulnerable because two concurrent requests can both pass the check before
either marks. Here the claim _is_ an `INSERT` guarded by `UNIQUE (decision_id)`
on `execution_claims`. The database decides who proceeds, and there is no
interval in which two contenders both believe they may. Proven by ten
simultaneous executions against one grant: one 201, nine `REPLAY_DETECTED`.

The grant is spent at step 11, before the call rather than after. If the
process dies mid-flight the grant is gone and the claim reads `EXECUTING` —
the honest record of "authority was used, outcome unknown". Spending afterwards
would leave a live grant behind a wire that may already have gone.

### UNKNOWN is a first-class outcome

A provider that times out, drops the connection, or throws has told us nothing
about whether the money moved. That is recorded as `UNKNOWN`, never as
`FAILED`.

"The wire did not go" and "I do not know whether the wire went" call for
opposite responses from an operator. A system that reports the second as the
first invites a retry, and a retry against a provider that already accepted
the request is a double payment. Anything a provider throws is converted to
`UNKNOWN` for the same reason.

`GET /v1/executions/unresolved` lists every claim still `EXECUTING` or settled
`UNKNOWN`, with the idempotency key the provider was called under. That is what
a reconciliation job needs, and it is an endpoint rather than a background
worker on purpose: with more than one API replica a worker needs leader
election, and a reconciliation loop that runs twice is precisely the thing that
turns an UNKNOWN into a double payment.

### The idempotency key is derived from the grant

`scrutexity:{decision_id}`. Stable across retries, unique per grant, opaque,
and safe to give a provider's support desk without disclosing anything about
the operation. Two legitimately identical operations get different keys because
they get different grants.

Whether that key does anything is the **provider's** property, not ours. The
interface makes each provider declare `idempotent`, so the guarantee is never
assumed. See the non-guarantees below.

## Consequences

`execution_claims` is a new, mutable table. It has to be separate from
`execution_attempts`, which is append-only by trigger: a lifecycle that
transitions `EXECUTING → EXECUTED` cannot live in a table nothing may update.
The claim holds the in-flight state; the attempt stays the immutable settled
record.

`execution_attempts` gains `enforced`. Evidence must let an operator tell an
enforced execution from a self-report without inference, so the legacy path
writes `enforced = false` and says what it is.

Every refusal on this path carries a security event on the error, written by
`recordingRejections` on a connection the failing transaction cannot roll back.
Field _names_ travel into those events; values do not — a counterparty's
account number does not belong in a log aggregator.

`normalizeContext` moved into a shared module. The intent hash is computed over
the normalised form, so the decision path and the boundary must normalise
identically; if one parsed `"25000.00"` into minor units and the other left it
a string, every honest execution would be refused as a mutation and the control
would have to be switched off to ship.

## Non-guarantees, stated plainly

**Scrutexity guarantees at-most-once _grant consumption_. It does not guarantee
at-most-once _external effect_.** The claim is atomic and the database enforces
it. What happens at the other end of a network call is the provider's property.
A provider that does not honour idempotency keys can be reached twice by a
network that retries beneath us, and no amount of care on this side changes
that. `ExecutionProvider.idempotent` exists so that this is declared rather
than hoped for.

**The boundary is architecturally separable, not separated.** It is a
self-contained module with a provider interface and no agent-reachable bypass,
and moving it to its own process is a deployment change rather than a rewrite.
Today it runs in the API process.

**Scrutexity cannot detect an agent calling the bank directly.** That is a
network property, enforced by not giving the agent a credential and by egress
control (`deploy/k8s/networkpolicy.yaml`), not by anything in this repository.
What is enforced here: the provider credential lives with the boundary, and an
agent credential cannot reach an external system through Scrutexity.

**The simulated provider proves the boundary, not a bank.** It honours
idempotency keys and can fail or time out honestly, but its external system is
a table. It is refused outright in production, because a simulated provider
there would emit receipts indistinguishable from real ones for money that never
moved.

**`/v1/executions` still exists and is not enforcement.** It is kept because an
integration that cannot yet route its side effects through a provider is better
off recording them than recording nothing. It should be removed when that stops
being true.

## Revisit when

A real provider integration lands. The first one will decide whether
`ExecutionProvider` is the right shape, and it is the point at which
`RECONCILED` needs a mechanism rather than only a state.
