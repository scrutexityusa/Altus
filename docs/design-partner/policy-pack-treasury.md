# The treasury policy pack

**File:** `policies/treasury-wire.yaml` — the one canonical treasury policy
**Tested by:** `packages/core/test/policy-pack.test.ts` (20 cases)

A ready-to-edit policy for outbound payments. Copy it, change the values marked
`CHANGE ME`, and put it through your own code review.

## One file

`policies/treasury-wire.yaml` is the **only** treasury policy in the repository.
It is simultaneously:

- the reference tenant's policy, loaded by the seed and run by `make demo`;
- the file you copy and edit.

There used to be two — a demo policy and a separate starter pack — and collapsing
them was the right call. Separate files drift, and two examples of "the treasury
ladder" that disagree undermine the thing this product is selling: that
policy-as-code becomes part of your system of record. One canonical artifact, or
the argument does not hold.

Because it is one file, this suite is load-bearing rather than supplementary:
`packages/core/test/policy-pack.test.ts` pins every tier boundary by value, so
moving a threshold names the boundary you changed.

### Why there is no `parameters:` block

The obvious way to get variants without duplicate files is a parameters block
substituted into the rules. Deliberately not done, for two reasons.

**The document that gets hashed onto every decision must be the document that
was reviewed.** A template that renders into a policy means the reviewed artifact
and the enforced artifact are different objects, and the content hash on every
decision would point at the rendered one. That is a meaningful loss for
something whose value is being replayable against exactly the bytes that
produced a decision.

**It would be a policy-language feature during an architecture freeze.** A
schema change plus a substitution engine, built speculatively. Collapsing to one
file removes the need: the demo and the partner use the same policy, so there is
no variant to parameterise.

If a partner turns out to need genuine environment variants — staging thresholds
that differ from production — that is the moment to build it, against a stated
requirement rather than a guess. The tunables are listed in one block at the top
of the file meanwhile, and changed in place, where the diff a reviewer reads is
the change itself.

## The ladder

| Tier | Amount                  | Decision | Reason code                           | Who is involved                        |
| ---- | ----------------------- | -------- | ------------------------------------- | -------------------------------------- |
| 1    | `< $10,000`             | ALLOW    | `BELOW_AUTONOMOUS_THRESHOLD`          | Nobody. The lease still binds.         |
| 2    | `$10,000 – $49,999.99`  | ALLOW    | `WITHIN_LEASED_AUTHORITY`             | Nobody. The lease is what admitted it. |
| 3    | `$50,000 – $999,999.99` | ESCALATE | `TREASURER_APPROVAL_REQUIRED`         | One treasurer, not self.               |
| 4    | `≥ $1,000,000`          | ESCALATE | `TREASURER_AND_CFO_APPROVAL_REQUIRED` | Two, across {treasurer, cfo}.          |

Boundaries are inclusive at the bottom of each tier: `$50,000.00` escalates,
`$49,999.99` does not. Every row above is a test case.

**Why tiers 1 and 2 have the same decision but different reason codes.** The
reason code is what an auditor reads. `BELOW_AUTONOMOUS_THRESHOLD` says policy
waved it through on size. `WITHIN_LEASED_AUTHORITY` says policy did not — the
agent's own ceiling and counterparty list are what admitted it. If you tighten a
lease, tier-2 payments are the ones that stop. Collapsing these into one rule
would lose the distinction exactly where it matters.

**Why tier 4 does not restate tier 3.** Both rules match a $2m wire. Approval
requirements from all matched escalations merge in the more-demanding direction
— max quorum, union of roles, shortest window — so quorum 2 across
{treasurer, cfo} falls out of the merge. Repeating tier 3's terms would be
redundant and would drift.

**Changing a threshold:** edit the `amount` in the relevant rule and adjust its
neighbour so the range stays contiguous. A gap between tiers is not a gap in
coverage — `defaults.decision` is `DENY`, so an amount no rule matches is
refused — but it is almost certainly not what you meant.

## High-risk signal → reduce authority

```yaml
- id: elevated_fraud_risk
  when:
    action: { prefix: 'wire.' }
    signal.fraud_risk.agent: { gte: 0.9 }
  then:
    decision: ESCALATE
    reason_code: FRAUD_RISK_HUMAN_REVIEW
    approval: { quorum: 1, roles: [treasurer], forbid_self_approval: true, ttl_seconds: 1800 }
    authority_effect:
      remove_actions: [wire.create, wire.submit, wire.execute, wire.modify]
      duration_seconds: 600
```

**Why both an effect and an approval.** The effect narrows what the agent may do
_unsupervised_. The approval names who can supply the difference. Without the
effect a high-risk agent keeps full autonomy; without the approval a legitimate
payment during an elevated-risk window has no route forward.

**What this rule cannot do, by construction.** It cannot widen anything. A signal
only subtracts — Law 2, checked at runtime and asserted over randomised signal
sets. A source you trust completely, holding a valid key, cannot turn a DENY into
an ALLOW or raise a ceiling. Nor can it make an otherwise-refused request
approvable: only _decay_, where the base grant covered the attempt, may be
rescued by an approver this rule names. (That distinction is G-19 — a real defect
found by the randomised property, where asserting more risk briefly produced a
more permissive outcome.)

**To modify:** change `gte: 0.9` to your engine's calibration, and
`duration_seconds` to how long you want autonomy suspended after a spike.
Calibrate here, not in the fraud engine — the policy is the reviewed artifact.

The pack also carries `elevated_counterparty_risk` (risk attached to the
counterparty, so no `authority_effect` — narrowing the agent's authority would
punish the wrong principal) and `low_model_confidence` (an agent's self-report,
admissible only because it can only make the outcome stricter).

## Unknown counterparty → DENY

```yaml
- id: unknown_counterparty
  when:
    action: { prefix: 'wire.' }
    context.counterparty_known: { eq: false }
  then: { decision: DENY, reason_code: UNKNOWN_COUNTERPARTY }
```

`context.counterparty_known` is **derived by the control plane** from your
counterparty register. It is never read from the caller — an agent that could
assert its counterparty is known would have defeated the control by asserting it.

**Why DENY rather than ESCALATE.** A new counterparty is the single highest
signal of a compromised or confused agent, and it is also the one case a tired
approver waves through at 6pm. Onboarding a counterparty should be a deliberate
act in your vendor system, not a decision made in an approval queue at the moment
money is trying to move.

**To modify:** if you genuinely need a break-glass path, add a _separate_
narrowly-scoped rule with its own reason code and a quorum-2 approval, rather
than softening this one to ESCALATE. Keep the strict rule visible in the diff.

## Delegation defaults: verification only

```yaml
delegation:
  enabled: true
  max_depth: 2
  max_ttl_seconds: 3600
  non_delegable_actions: [wire.create, wire.modify, wire.submit, wire.execute]
```

Containment already guarantees a child grant never exceeds its parent. What it
does not stop is a money-moving action being handed to an agent nobody reviewed.
So financial actions are non-delegable at **any** scope, however narrowly asked.

The shape this produces: a treasury agent may hand a verification agent the reads
it needs to check a counterparty, and cannot hand it the ability to pay one.
`max_depth: 2` keeps the chain short enough to hold in your head during an
incident.

**To modify:** adding an action to `non_delegable_actions` is always safe.
Removing one means an agent can hand it onward — do that only for reads.

## Fail-open vs fail-closed

```yaml
failure_modes:
  policy_unavailable: FAIL_CLOSED
  signal_unavailable: FAIL_CLOSED
  enforcement_unavailable: FAIL_CLOSED
```

All three. The alternative is that a control-plane outage becomes an
authorization. If the policy cannot be read, the signals cannot be read, or the
enforcement plane is down, the honest answer is "I cannot establish that this is
authorised" — and for money that means no.

**Size the cost honestly:** a Postgres failover means payments queue rather than
proceed. That is the correct trade for outbound money.

`signal_unavailable: FAIL_CLOSED` is the one people push back on, because signals
are an _input to risk_ rather than to authority. Keep it closed anyway: without
signals you cannot tell a normal payment from one during an incident, and the
whole point of decay is that the risk picture is load-bearing.

**To modify:** if you have read-only actions that must survive an outage, put
them in a **separate policy**. Do not weaken this one.

## Approval role configuration

Roles come from your user directory and are matched by name. The pack expects
`treasurer` and `cfo`; the issuance ceilings expect `treasury_admin`.

| Setting                      | Meaning                          | Why it is set this way                                                                                                                                    |
| ---------------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `quorum`                     | How many distinct approvals      | 1 for six figures, 2 for seven                                                                                                                            |
| `roles`                      | Which roles may count            | Union across merged requirements                                                                                                                          |
| `forbid_self_approval: true` | Approver ≠ requester             | The confused-deputy case: an agent acting under a treasurer's delegated authority must not satisfy its own escalation                                     |
| `ttl_seconds`                | How long the approval stays good | An approval is not permanent. If conditions change, the execution boundary refuses with `APPROVAL_CONTEXT_MISMATCH` rather than proceeding on a stale yes |

## Issuance ceilings — the top of the theorem

The most important block in the file and the easiest to skip.

Containment guarantees a delegated grant never exceeds its parent. But a **root**
lease is issued from nothing and has no parent, so without a ceiling the whole
chain hangs beneath an unbounded root: anyone holding `leases:write` could mint
any authority at all.

A scope protects an endpoint. This governs what may come out of it. Keeping them
separate is what stops one boolean sitting between an intern and a $10m wire.

Two properties to preserve when you edit:

1. **A role not named here may issue nothing.** A policy that forgot a role fails
   closed.
2. **Roles are never unioned.** A request must fit wholly inside **one** ceiling,
   so a principal holding two narrow roles cannot combine them into a broad one.

Note the `treasurer` ceiling is read-only with a `$0.00` max. A treasurer
approves; they do not provision. That `$0.00` is the control, not a placeholder —
a compromised treasurer credential cannot mint an agent that pays.

## Publishing it

A policy version is authored, reviewed by **two** independent humans, and
activated explicitly. The content hash is recorded on every decision made under
it, so a decision can always be replayed against the exact bytes that produced it.

```bash
ID=$(curl -sS -X POST $ALTUS/v1/policy-versions \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d "$(jq -Rs '{document: .}' < policies/treasury-wire.yaml)" | jq -r .policy_version.id)

curl -sS -X POST $ALTUS/v1/policy-versions/$ID/reviews \
  -H "authorization: Bearer $REVIEWER_ONE" -H 'content-type: application/json' \
  -d '{"vote":"APPROVED","comment":"Thresholds match the FY26 approval matrix."}'
# ... a second, different reviewer ...

curl -sS -X POST $ALTUS/v1/policy-versions/$ID/activate -H "authorization: Bearer $ADMIN"
```

## Testing your edits

```bash
pnpm exec vitest run packages/core/test/policy-pack.test.ts
```

The suite pins every tier boundary, the counterparty controls, the fail-closed
settings, the non-delegable actions, the `$0.00` treasurer ceiling, and that no
signal can expand authority. Change the expectations to your thresholds when you
change the policy — a policy change that moves a boundary should move a test,
visibly, in the same commit. Since this is the only treasury policy, that suite
also guards the demo: a threshold edit that breaks a tier fails CI rather than
producing a demo that quietly tells a different story.

## What the pack deliberately does not do

- **No per-currency ceilings.** A grant denominated in one currency already
  refuses requests in another, and a ceiling in an incomparable currency cannot
  be proven to narrow — so it is ignored rather than applied. Tracked as a known
  boundary of the v1 constraint model in `docs/domain-model.md`.
- **No time-of-day or velocity rules.** Both are expressible as signals from a
  system that computes them; neither belongs in a policy that must be replayable
  from recorded facts.
- **No sanctions screening.** `sanctioned_destination` is a coarse country
  backstop, not a screening product. Keep your real screening upstream.
