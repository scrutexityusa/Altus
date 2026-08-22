# Altus — one page

> Export to PDF with `pandoc one-page-brief.md -o altus-brief.pdf`.
> Fits one side of A4.

## The problem

An autonomous agent that can move money can move the wrong money. The controls
that exist today are prompts, human review of everything, or nothing — and none of
them can answer, after the fact, _what exactly was this agent able to do, and who
said so?_

## What Altus is

A runtime authority control plane. It sits between an agent and a payment
provider, decides whether an action is authorised, records why, and is the only
path out to the external system.

It is **not** a fraud model, an agent framework, or a workflow engine.

## The theorem

```
HumanAuthority ⊇ AgentAuthority ⊇ DelegatedAuthority
              ⊇ EffectiveAuthority ⊇ ExecutionGrant ⊇ ActualExecution

                  ExecutedIntent = AuthorizedIntent
```

**Authority only ever shrinks as it flows down, and what gets executed is exactly
what was authorised.**

## The four laws

Checked at runtime on every allow, not asserted in tests alone.

1. `ChildAuthority ⊆ ParentAuthority` — delegation cannot widen.
2. `EffectiveAuthority ⊆ GrantedAuthority` — risk signals only subtract.
3. `ExecutionGrant ⊆ AuthorityLease` — executing cannot widen.
4. `ExecutedIntent = AuthorizedIntent` — the operation performed is the one approved.

## What it gives a treasury team

|                                      |                                                                                                                                                   |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Scoped authority**                 | Specific actions, accounts, counterparties, a ceiling, an expiry. Revocable, and revocation cascades to delegated authority with no grace period. |
| **Your approval ladder, enforced**   | Tiered thresholds; escalation to named roles; self-approval forbidden; an approval that goes stale is refused rather than honoured.               |
| **Mutation refused before the bank** | Change the amount after approval and the provider is never contacted.                                                                             |
| **Exactly-once execution**           | One claim per grant, committed before the provider is called. `UNKNOWN` is a first-class state, never collapsed into "failed".                    |
| **Evidence you can check**           | Per-tenant Ed25519-signed hash chain. Cryptographically tamper-evident and independently verifiable — offline, without trusting us.               |
| **"Why?" in one call**               | A typed causal chain from the decision back to the human who activated the policy.                                                                |

## What it does not do

- Detect fraud. It consumes signed assertions from systems that do.
- Stop an agent acting through a channel it does not mediate.
- Judge whether a decision was _correct_ — only that it was made, under this
  policy, on these facts, unaltered.
- Make an agent safe. It bounds the consequences of an unsafe one.

## Current limitations, stated plainly

- **No KMS is wired.** Production requires one and refuses to start without it —
  so no deployment has yet run in a production posture. Wiring yours is scoped
  week-one work.
- No egress detection, no workload-bound identity (bearer tokens today), no rate
  limiting.
- Single region, single Postgres. Read replicas are deliberately excluded: a
  replica reintroduces a second clock into validity decisions.

Every known gap is in a public register with a status: discovered, validated,
fixed, regression-tested, operationally verified.

## Verify it yourself

```
make ci           # 596 tests, lint, build, demo
make adversarial  # 11 security invariants, mounted as real attacks
make recovery     # SIGKILL the process mid-payment; assert what survived
```

Self-hosted in your own account. There is no hosted service holding your payment
authority, which shortens the security conversation considerably.

**{contact} · {repo}**
