# Authorization model

## The decision function

```
evaluateAuthorization(snapshot) → { decision, reason_code, evidence }
```

Pure and total. Same inputs, same output, forever. The snapshot carries the
request, the agent, the active policy version, every candidate lease with its
full ancestry, every live signal, any prior approval state, and the health of
each dependency. Nothing else influences the result.

## Order of evaluation

```
0. Dependency health   policy unreadable → system default FAIL_CLOSED, recorded
1. Policy              every rule evaluated; strictest matched decision wins
2. Authority envelope  actions × resources on the *base* grant → terminal on failure
2b. Intent             declared intent vs attempted action → terminal on failure
3. Autonomy            constraints on the *decayed* grant → escalatable on failure
4. Approval            prior approvals resolve an escalation into ALLOW or DENY
5. Degradation         signal or enforcement unavailable → policy's failure mode
```

Intent is checked _ahead_ of the envelope: "you were not sent to do this" is a
more specific statement than "you cannot do this", and no approval turns one
task into another. See `docs/security-model.md` for the model, and ADR-0013 for
how a purpose-bound grant binds even under a policy that does not enforce
intent.

## 1. Policy evaluation

**Every rule is evaluated. There is no first-match-wins.** Ordering a policy
file would otherwise change its meaning, and the layered thresholds a treasury
actually has (≥$50k *and* ≥$1M both apply to a $2M wire) would be invisible in
the evidence.

- Rules run in `priority` order, then declaration order — for readability and
  for a stable reason code, not for outcome.
- The **strictest** matched decision wins: `DENY > ESCALATE > ALLOW`.
- The reason code comes from the strictest matched rule, and among equals from
  the _last_ in evaluation order — the more specific one. A $2M wire reports
  `TREASURER_AND_CFO_APPROVAL_REQUIRED`, not merely "over $50k".
- Approval requirements from all matched escalations are merged **in the more
  demanding direction**: maximum quorum, union of roles, shortest window, and
  self-approval forbidden if any rule forbids it. Two rules that each demand a
  human cannot cancel into demanding none.
- No rule matched → `defaults.decision`, which is `DENY`.

### The predicate language

Data, not code. There is no expression language to escape from, no
caller-supplied regular expression to blow up on, and no host-language
callback.

- **Selectors** are a closed vocabulary. An unknown selector fails validation at
  authoring time rather than becoming a rule that silently never matches.
- **Operators** are `eq, neq, in, nin, lt, lte, gt, gte, exists, prefix`. Every
  one is total: an operand of the wrong shape yields `false` and a recorded
  reason, never a coercion and never a throw.
- **Incomparable operands fail closed.** `amount >= $50,000` against a request
  that carried no amount does not pass.
- Numbers are canonical decimal strings compared digit by digit; money is
  compared as exact minor units.

## 2 and 3. The escalation boundary

The rule that makes the demo read correctly and the security model hold:

```
envelope  (actions × resources, on the base grant)
    fail → DENY, terminal. Approval cannot bridge it.

autonomy  (constraints, on the decayed grant)
    fail → ESCALATE if policy names an approver
         → DENY otherwise
```

Worked through the demo:

| Scene                           | Envelope | Autonomy  | Policy              | Outcome                |
| ------------------------------- | -------- | --------- | ------------------- | ---------------------- |
| $25k wire                       | ✓        | ✓         | ALLOW               | **ALLOW**              |
| $250k wire, $50k ceiling        | ✓        | ✗ ceiling | ESCALATE, treasurer | **ESCALATE**           |
| …then treasurer approves        | ✓        | ✗ ceiling | ESCALATE            | **ALLOW**, superseding |
| Delegate attempts `wire.modify` | ✗ action | —         | ALLOW               | **DENY**, terminal     |
| $25k with `fraud_risk = 0.97`   | ✓        | ✗ decayed | ESCALATE, treasurer | **ESCALATE**           |

The fourth row is the one to notice. Policy was content to allow a $5,000 wire;
the agent's envelope was not. Policy permission never substitutes for held
authority.

## Authority decay

A policy rule may attach an `authority_effect` that removes actions or tightens
constraints for a bounded duration. Decay is deterministic — it is a policy
rule reading a signal value, never a model deciding anything.

`restrictGrant` has an absolute contract, proven over 2,000 randomised
restrictions: **the result is always contained by the input.** There is no
operation in the module that widens a grant. Asked to raise a ceiling, it keeps
the lower one. Asked to widen an allowlist, it intersects. Asked to apply a
ceiling in an incomparable currency, it declines rather than assume.

Decay applies to the autonomy layer. The action removal that a fraud signal
triggers means "not without a human", not "not any more".

## 4. Approval

Approval is a distinct domain object, and none of the following is optional:

- One vote per human, enforced by a unique constraint as well as by logic.
- A rejection is **terminal**. A rejected escalation does not become approvable
  by finding more approvers.
- Self-approval by the requesting agent's owner never counts.
- A role is only covered by someone who held it **at approval time**, recorded
  on the approval row. A role granted or removed later cannot retroactively
  change what an approval meant.
- Role coverage is assigned greedily over a stable ordering, approvers holding
  the _fewest_ required roles first, so one multi-role approver cannot consume
  a role only they could have covered.

An approval never mutates the escalated decision. It triggers a re-evaluation
that produces a **new** decision carrying `supersedes_decision_id`. The
evidence shows both what was asked of the humans and what they answered.

## 5. Failure modes

Failover is policy data evaluated per decision, never a global switch.

| Dependency           | Behaviour                          | Source                                                     |
| -------------------- | ---------------------------------- | ---------------------------------------------------------- |
| Policy unreadable    | `FAIL_CLOSED`                      | System default — there is no policy to read the mode from. |
| Signals unreadable   | policy's `signal_unavailable`      | Treasury pack: `FAIL_CLOSED`.                              |
| Enforcement degraded | policy's `enforcement_unavailable` | Treasury pack: `FAIL_CLOSED`.                              |

A rule-level `failure_mode` may only _tighten_ the document-level default. The
behaviour that was applied is recorded on the decision and in the receipt.

An escalation with no approver who could resolve it is a denial in disguise;
the evaluator converts it to `DENY / APPROVAL_REQUIREMENT_UNSATISFIABLE` rather
than leaving a request pending forever.

## Delegation

```
child_authority ⊆ parent_authority        (proven, 4,000 randomised proposals)
child_lifetime  ⊆ parent_lifetime         (clamped, never extended)
```

Containment holds on every axis, and the asymmetry is what makes it safe:

- **Actions.** Every child pattern must be covered by a parent pattern.
  `wire.*` contains `wire.batch.*`; nothing but `*` contains `*`.
- **Resources.** A resource type absent from the parent grants nothing. A child
  wildcard requires a parent wildcard.
- **Constraints.** A dimension the parent constrains **must** be constrained by
  the child, at least as tightly. A dimension the child adds is free, because
  adding a constraint only shrinks. **Omission is therefore never a widening
  path** — which is the attack the whole module exists to stop.
- **Denylists invert.** The child must deny everything the parent denies.

Authority overreach is **rejected, not clamped**. An agent asking for more than
it holds has a bug or an attacker in it, and quietly granting the intersection
would hide both. Lifetime is the one exception: "as long as you can" is a
reasonable thing to mean and cannot widen authority, so it is clamped to the
parent expiry and the policy maximum.

Policy may mark actions **non-delegable** at any depth, however narrow the ask.
The treasury pack marks all of `wire.*`, which is why a delegated agent cannot
be handed payment authority even by an agent that holds it.

## Consistency model for revocation

Revocation takes effect **on the next decision**, with no grace period.

The mechanism is that the evaluator loads each candidate lease together with
its complete ancestry and derives every status from server-authoritative time
at evaluation. There is no decision cache, no lease cache, and no TTL to wait
out. The only cached object is an immutable, content-addressed policy version,
whose integrity is re-verified on every load.

The window between "operator clicks revoke" and "agent is refused" is therefore
one committed transaction — bounded by database commit latency, not by a
polling interval.

An ALLOW already issued remains presentable until `expires_at` (default 300s)
or until consumed, whichever is first. That is deliberate: an execution grant
is a promise the agent may have already acted on. To cut that short too,
revoke and let the grant expire — or shorten
`defaults.execution_grant_ttl_seconds` in policy.

There is a second, sharper bound. Execution recomputes the decision's context
fingerprint and refuses if it has moved, so a revocation that changes nothing
else will still not invalidate an outstanding grant — but a _risk signal_
arriving after the decision will. In practice the window during which a stale
ALLOW can be used is bounded by the grant TTL and by the stability of the risk
picture, whichever gives out first.
