# Scrutexity

**Runtime authorization for high-consequence agent actions.**

Scrutexity answers one question, deterministically, and produces verifiable
evidence for the answer:

> Was this agent authorized to perform this action, on this resource, under
> this context, at this exact point in time?

It is not a system that watches what autonomous agents do. It is the system
that determines what they are permitted to do.

The first vertical is treasury and payments. The long-term category is machine
workforce identity and authority.

---

## Quick start

Requires Node 22+, pnpm 10+, and either Docker or a local PostgreSQL 16.

```bash
make dev      # install, start Postgres, migrate, seed the reference tenant
make demo     # the full treasury story, from a clean database, asserting every scene
```

`make demo` is a test, not a slideshow. It runs against a real HTTP server
backed by real Postgres and asserts every outcome, so a broken demo fails the
build.

```bash
make api          # the control plane, with reload
make web          # the dashboard
make test         # 554 tests
make adversarial  # 11 security invariants, mounted as real attacks
make recovery     # SIGKILL the API mid-payment; assert what survived
make ci           # everything above
```

`make adversarial` and `make recovery` are the two worth running if you are
evaluating this rather than developing it. Neither is an alias for a subset of
the unit tests: the first mounts real attacks through the public API against a
real database, and the second destroys a real process between the execution
claim and the payment, then proves a different process refuses to retry.

---

## What the demo shows

| Scene | What happens                                                               | Outcome                                    |
| ----- | -------------------------------------------------------------------------- | ------------------------------------------ |
| 1     | Two agents, each owned by a named human                                    | —                                          |
| 2     | Scoped authority issued: `wire.*` on two accounts, $50,000 ceiling, 1h TTL | —                                          |
| 3     | A $25,000 wire                                                             | **ALLOW**, single-use grant, 300s          |
| 3b    | The same grant presented twice                                             | **REPLAY_DETECTED**                        |
| 4     | A $75,000 wire — inside its role, beyond its discretion                    | **ESCALATE**, treasurer                    |
| 5     | The treasurer approves                                                     | **ALLOW**, superseding decision            |
| 5b    | The CFO tries to approve the same request                                  | **STATE_CONFLICT**                         |
| 6     | Counterparty verification delegated to a second agent                      | depth 1, clamped TTL                       |
| 6b    | Delegating `wire.execute` as well                                          | **ACTION_NOT_DELEGABLE**                   |
| 7     | The delegated agent attempts `wire.modify`                                 | **DENY**, with a full explanation          |
| 8     | The amount is mutated after authorization, at the execution boundary       | **INTENT_MISMATCH**, before the provider   |
| 8b    | The operation it was actually authorized for                               | **EXECUTED**, hashes match                 |
| 9     | `GET /v1/trace/{id}` on the approved wire                                  | causal chain back to the policy activation |
| 10    | `fraud_risk = 0.97` arrives, signed, from an external engine               | authority narrows                          |
| 10b   | The same $25,000 wire that ran unattended a minute ago                     | **ESCALATE**                               |
| 11    | The parent lease is revoked                                                | both agents refused, immediately           |
| 12    | Evidence verified; then a tampered receipt                                 | **INTACT**, then **COMPROMISED**           |

---

## The five ideas

### 1. Authority is an object, not a boolean

```jsonc
// Not this. It cannot expire, cannot be scoped, cannot be traced to a policy,
// cannot be delegated safely, and cannot explain itself.
{ "agent": { "can_execute_wire": true } }
```

An `AuthorityLease` is scoped to actions and resources, constrained, issued
under a named policy version, time-bounded, revocable, and optionally
delegatable. Delegation is governed by a containment relation proven over 4,000
randomised proposals: **child authority never exceeds its parent**, and
omitting a constraint the parent imposed is a violation, not a shortcut.

### 2. Two layers that fail differently

| Layer        | Contains            | On failure                                              |
| ------------ | ------------------- | ------------------------------------------------------- |
| **Envelope** | actions × resources | **DENY**, terminal                                      |
| **Autonomy** | constraints         | **ESCALATE** if policy names an approver, else **DENY** |

The envelope is what the agent _is for_; a verification agent is not one
approval away from being allowed to modify a wire. The constraints are how much
of that role it may exercise unsupervised; a treasury agent asked to send
$250,000 is doing its own job at a size that needs a human.

A fraud signal narrows autonomy, never the envelope — which is why the same
wire escalates rather than reading as a broken integration. See
[ADR-0008](docs/decisions/0008-escalation-boundary.md).

### 3. A refusal carries the next step

A denial that only says "no" leaves an agent guessing, and guessing looks
exactly like probing. So a refusal carries the next legitimate step —
`REQUEST_DELEGATION` addressed to the agent that can grant it, `REQUEST_LEASE`
with the minimal grant, `HUMAN_ESCALATION` with the approval already open.

Computed by the policy engine from the same facts that produced the refusal,
never generated. Hard violations return nothing, and payloads carry no
threshold, rule id, or the value that would have passed — an agent cannot
binary-search a policy by reading its own denials. See
[ADR-0011](docs/decisions/0011-corrective-handshake.md).

### 4. Every decision can be walked back to its origin

`GET /v1/trace/{decision_id}` returns the causal chain, oldest cause first: the
policy activation that admitted the authority, the lease it produced, the
delegation that narrowed it, the request, the signals that were read, the
humans who approved, the decision, and what was done with it. Each node carries
a timestamp and a typed causal edge.

A database traversal over a graph the schema has encoded since the first
migration. Nothing summarised, nothing generated, same answer every time.

### 5. Decisions are pure, so evidence means something

`evaluateAuthorization(snapshot) → decision` reads no clock, opens no
connection, consults no global. Everything it depends on arrives as data, and
all of it is recorded.

That single constraint is what makes replay, testability, cross-deployment
consistency and auditability achievable at once — and it is why no explanation
in this system is generated by a language model. An explanation of why a
payment was blocked is evidence; it is assembled deterministically from the
structured record, and it renders identically forever.

---

## Layout

```
packages/core     pure domain: authority lattice, policy engine, evidence, explanation
packages/sdk      typed client and enforcement point
services/api      HTTP surface, persistence, tenancy, idempotency, observability
apps/web          dashboard over the API's own read model
db/migrations     schema, row level security, append-only triggers
policies/         the canonical treasury policy, used by the demo and by partners alike
spec/             generated OpenAPI and policy JSON Schema, drift-checked in CI
deploy/k8s        deployment and sidecar templates
docs/             architecture, models, threat model, contract, ADRs
docs/design-partner/  the evaluation package: security brief, demo script,
                      API quickstart, policy pack, integration runbook,
                      pilot plan, red team handoff
```

## Using it

```ts
import { ScrutexityClient } from '@scrutexity/sdk';

const scrutexity = new ScrutexityClient({ baseUrl, token });

const { decision, execution } = await scrutexity.guard({
  agentId: 'treasury-agent',
  action: 'wire.execute',
  resource: 'bank_account:acct_991',
  context: { amount: '750000.00', currency: 'USD', counterparty_id: 'cp_100' },
});

if (decision.requiresApproval) {
  notifyTreasurer(decision.approvalRequestId);
}
```

`guard` takes no callback, deliberately. Scrutexity performs the operation
through the enforcement boundary, so there is no moment when the caller holds an
approved decision and an unexecuted side effect — nothing to drift apart, and
the operation that reaches the provider is the one that was authorised or
nothing reaches it at all. Only `ALLOW` is truthy; an escalation cannot be
mistaken for a soft yes.

If a side effect genuinely cannot be routed through a provider,
`recordExternalExecution()` writes a self-reported record instead. It is a
different verb because it means a different thing: Scrutexity verified nothing
about that operation, and the evidence says so.

## Testing

554 tests across 19 files, plus two suites that are not tests of units at all.
`./scripts/ci-verify.sh` runs exactly what CI runs, from a tree with no build
output and no dependencies installed.

The ones that matter most are the invariants:

```
child authority never exceeds parent authority     4,000 randomised proposals
anything a child covers, its parent covers         3,000 randomised pairs
authority decay only ever shrinks                  2,000 randomised restrictions
a signal can only ever subtract authority          1,500 randomised signal sets
no ALLOW without autonomous covering authority     2,000 randomised evaluations
identical inputs produce identical decisions          300 randomised requests
exactly one winner among ten concurrent claimants   a real race, real database
```

The signal containment property found a real defect: a signal could convert a
hard DENY into an approvable escalation, so asserting _more_ risk produced a
_more_ permissive outcome (G-19).

**`make adversarial`** — 11 security invariants, each mounted as a real attack
through the public API against a real database. Temporal expiry at the boundary
instant with a skewed clock, revocation of an ancestor after the ALLOW, a stored
grant widened by direct database write, privilege synthesis across two roles,
cross-subject and cross-tenant enumeration, a compromised-but-trusted signal
issuer, ten concurrent executions against one grant, and three crash states. The
registry is `test/adversarial-manifest.json`; a scenario declared there with no
implementation fails the run.

**`make recovery`** — three scenarios against a **real `SIGKILL`** of a real
child process, killed after the execution claim commits and before the payment,
and again after the payment and before settlement. A different process then
retries against the same database. The provider's ledger is a separate committed
table, because a `SIGKILL` takes memory with it.

The security suite runs the attacks from the threat model against the real
service: tenant breakout (including a direct-to-database probe as the
application role), privilege escalation, confused deputy, forged delegation,
expired and revoked authority cascading through a chain, replay, altered
receipts, tampered policy, and hostile signal input.

## Documentation

| Document                                              | What it covers                                             |
| ----------------------------------------------------- | ---------------------------------------------------------- |
| [architecture.md](docs/architecture.md)               | Shape of the system, and what was deliberately left out    |
| [domain-model.md](docs/domain-model.md)               | Entities, relationships, state machines, exact money       |
| [authorization-model.md](docs/authorization-model.md) | The decision function, in evaluation order                 |
| [data-model.md](docs/data-model.md)                   | Schema choices, constraints as invariants, index rationale |
| [security-model.md](docs/security-model.md)           | Controls, and the threats accepted                         |
| [threat-model.md](docs/threat-model.md)               | Attacks by attacker, each mapped to a test                 |
| [api-contract.md](docs/api-contract.md)               | Conventions the OpenAPI spec cannot express                |
| [sequence-diagrams.md](docs/sequence-diagrams.md)     | The flows, in Mermaid                                      |
| [sprint-plan.md](docs/sprint-plan.md)                 | What shipped, and what is left                             |
| [decisions/](docs/decisions/)                         | Ten ADRs, each with what would make us revisit it          |

## What is not built

Named honestly, because unnamed debt is the expensive kind:

- **External evidence anchoring.** The hash chain detects tampering by anyone
  who cannot rewrite the whole chain _and_ re-sign it. Publishing periodic head
  hashes to an outside witness closes that. See
  [ADR-0006](docs/decisions/0006-evidence-hash-chain.md).
- **A tenant-extensible action catalog.** It is code today; it must be data
  before the second vertical.
- **Credential lifecycle.** Credentials are seeded; rotation and revocation are
  not yet exposed.
- **Rate limiting** and **load characterisation.** No latency claim is made
  because nothing has been measured under load.

## License

MIT.
