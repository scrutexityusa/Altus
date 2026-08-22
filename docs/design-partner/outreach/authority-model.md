# The authority model

> One page. Export with `pandoc authority-model.md -o authority-model.pdf`.

**Your AI agents can now move money. Who controls what they are allowed to do?**

Altus is the authorization and execution-control layer between your agent and the
action.

---

```
                          COMPANY
                             │
                     HUMAN AUTHORITY          people who may act, and to what limit
                             │
                          POLICY               reviewed by two humans, hash recorded
                             │                 caps what may be issued, per role
                             │
                         AGENT ID              a principal with a named human owner
                             │
                    AUTHORITY LEASE            actions · accounts · counterparties
                             │                 a ceiling · an expiry · revocable
                             │
                       DELEGATION              never wider than its parent
                             │                 financial actions non-delegable
                             │
                      RISK SIGNALS             Ed25519-signed, TTL-bounded
                             │                 subtract only, never add
                             │
                     AUTHORIZATION             ALLOW · ESCALATE · DENY
                             │                 pure function, replayable forever
                             │
                    EXECUTION GRANT            single-use, bound to ONE exact
                             │                 operation by hash
                             │
                       EXECUTION               claim commits BEFORE the provider
                             │                 is contacted; exactly one effect
                             │
                       VERIFIABLE              Ed25519-signed hash chain
                        EVIDENCE               you can check it without us
```

---

## Five rules

|                                     |                                                                                                                                                   |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Authority only narrows.**         | Nothing downstream may hold more than what granted it. Not a delegation, not a policy, not a signal.                                              |
| **Execution must match intent.**    | The operation that reaches the bank is byte-identical to the one authorized, or nothing reaches the bank.                                         |
| **Revocation wins.**                | Immediate, no grace period, cascading to every delegated lease. Every decision walks the whole ancestry, live.                                    |
| **One grant = one claim.**          | Exactly one external effect per authorization. The claim commits before the provider is called, so a crash cannot make authority spendable again. |
| **Signals never create authority.** | A risk signal can subtract and can never add — including a valid signal from a source that is fully compromised.                                  |

---

## The theorem

```
HumanAuthority ⊇ AgentAuthority ⊇ DelegatedAuthority
              ⊇ EffectiveAuthority ⊇ ExecutionGrant ⊇ ActualExecution

                  ExecutedIntent = AuthorizedIntent
```

Checked at runtime as a postcondition on every allow — not asserted in tests
alone. A violation is reported as `AUTHORITY_INVARIANT_VIOLATION`, distinct from
an ordinary policy denial, because it means the system's model of its own
authority is wrong.

---

## Six questions it answers about any action

1. **What authority did the agent have?** The lease, its scope, and its expiry.
2. **What policy applied?** The version, and the content hash it was decided under.
3. **What changed the decision?** Every signal the rules actually read.
4. **Who approved it?** A named human, at a named time, on a specific operation.
5. **What exactly was executed?** The operation hash, matched against the authorized one.
6. **Can I verify the evidence?** Yes — offline, against the published key, without trusting us.

One call: `GET /v1/trace/{decision_id}`.

---

**See it:** `make demo` — the whole flow in under ten minutes, asserted end to end.
**Break it:** `make adversarial` (11 invariants) and `make recovery` (a real
`SIGKILL` mid-payment).

**{contact} · {repo}**
