# Domain model

The domain is explicit. There is no generic "node" table and no
entity-attribute-value store: an `AuthorityLease` is an authority lease, and
the schema says so.

## Entities

| Entity                     | Table                            | What it is                                                         |
| -------------------------- | -------------------------------- | ------------------------------------------------------------------ |
| Organization               | `organizations`                  | Tenant boundary. Every other row belongs to exactly one.           |
| User                       | `users`                          | A human. Carries the org-defined roles approval policy references. |
| Agent                      | `agents`                         | A machine principal, owned by a human or the organization.         |
| Credential                 | `api_credentials`                | A bearer credential bound to one principal. Hash only.             |
| Resource                   | `resources`                      | Something an action is performed on: an account, a counterparty.   |
| Policy / PolicyVersion     | `policies`, `policy_versions`    | The rules, and their immutable, hashed versions.                   |
| AuthorityLease             | `authority_leases`               | Scoped, time-bounded, revocable authority. The core object.        |
| Delegation                 | `delegations`                    | The edge recording one agent narrowing authority to another.       |
| RiskSignal                 | `risk_signals`                   | A time-bounded assertion from an external system.                  |
| AuthorizationRequest       | `authorization_requests`         | What was asked. Immutable.                                         |
| AuthorizationDecision      | `authorization_decisions`        | What was answered, and why. Immutable.                             |
| ApprovalRequest / Approval | `approval_requests`, `approvals` | What was asked of humans, and what they said.                      |
| ExecutionAttempt           | `execution_attempts`             | What was done with an ALLOW. One per decision.                     |
| Receipt                    | `receipts`                       | Hash-chained evidence. Realises `EvidenceRecord`.                  |

Two entities named in the original brief are deliberately absent, rather than
stubbed:

- **EvidenceRecord** is realised by `receipts`. A separate table would have held
  the same bytes under a second name and given two places for evidence to
  disagree.
- **Incident** has no consumer in this slice. Adding it now would have been an
  abstraction without a use, which is the specific thing the brief warns
  against. The receipt kinds already carry what an incident record would join
  on.

## Relationships

```
Organization
  ├── Users ─────────────── approve ──► ApprovalRequests
  ├── Agents
  │     ├── owned_by ─────────────────► User
  │     ├── holds ────────────────────► AuthorityLeases
  │     ├── creates ──────────────────► AuthorizationRequests
  │     ├── is subject of ────────────► RiskSignals
  │     └── issues ───────────────────► Delegations
  ├── Policies ──► PolicyVersions ──► reviewed by Users (two, neither the author)
  └── Resources

AuthorityLease
  ├── issued_to ──────────► Agent
  ├── derived_from ───────► PolicyVersion      (provenance: what admitted it)
  ├── parent_lease_id ────► AuthorityLease     (null at depth 0)
  ├── grant: actions × resources × constraints
  └── issued_at, expires_at, status, revocable

AuthorizationDecision
  ├── answers ────────────► AuthorizationRequest
  ├── under ──────────────► PolicyVersion (+ policy_hash, pinned at decision time)
  ├── relying on ─────────► AuthorityLease
  ├── influenced by ──────► RiskSignal[]
  ├── satisfied by ───────► Approval[]
  ├── supersedes ─────────► AuthorizationDecision   (re-evaluation after approval)
  └── produces ───────────► Receipt
```

The database can walk this as a graph — `authority_leases.parent_lease_id` and
`delegations.(issuer, delegate)` are indexed for traversal in both directions —
while the application keeps thinking in named entities.

## Authority is not a permission

The thing this platform exists to model is authority, and authority is not a
boolean.

```jsonc
// Wrong. This cannot expire, cannot be scoped, cannot be traced to a policy,
// cannot be delegated safely, and cannot explain itself.
{ "agent": { "can_execute_wire": true } }
```

```jsonc
// An AuthorityLease.
{
  "id": "lease_01JBX7Q8N2K3M4P5R6S7T8V9W0",
  "agent_id": "agent_treasury_01",
  "policy_version_id": "polv_treasury_140", // what admitted this authority
  "grant": {
    "actions": ["wire.create", "wire.submit", "wire.execute"],
    "resources": { "bank_account": ["acct_001", "acct_002"], "counterparty": ["cp_100", "cp_101"] },
    "constraints": {
      "max_amount": { "currency": "USD", "amountMinor": "5000000" },
      "currencies": ["USD"],
      "allowed_counterparties": ["cp_100", "cp_101"],
    },
  },
  "issued_at": "2026-03-01T12:00:00.000Z",
  "expires_at": "2026-03-01T13:00:00.000Z",
  "revocable": true,
  "parent_lease_id": null,
  "depth": 0,
  "status": "ACTIVE",
}
```

Authority is scoped, time-bounded, revocable, attributable, policy-derived,
optionally delegatable, and constrained by context. Every one of those is a
column or a computed property, not a convention.

## The two layers of a grant, and why they differ

This is the single most important distinction in the model.

| Layer        | Contains                | On failure                                                              |
| ------------ | ----------------------- | ----------------------------------------------------------------------- |
| **Envelope** | `actions` × `resources` | **DENY, terminal.** No approval bridges it.                             |
| **Autonomy** | `constraints`           | **ESCALATE**, when policy names an approver. **DENY** when it does not. |

The envelope is what the agent _is for_. A verification agent that was never
granted `wire.modify` is not one approval away from being allowed to modify a
wire — approving that would silently redefine its role rather than authorise a
single action.

The constraints are how much of that role it may exercise _unsupervised_. A
treasury agent with a $50,000 ceiling asked to send $250,000 is doing its own
job, at a size that needs a human. That is precisely what escalation is for,
and the human supplies the authority the agent lacks from their own.

Authority decay narrows the autonomy layer, never the envelope. That is why a
fraud signal turns a routine wire into one needing review, rather than into a
denial that reads as a broken integration.

## Lifetimes and state machines

```
AuthorityLease   PENDING ──► ACTIVE ──► EXPIRED        (derived from server time)
                                └────► REVOKED         (immediate, no grace period)
                                └────► SUSPENDED

ApprovalRequest  PENDING ──► SATISFIED
                         ├─► REJECTED    (terminal; cannot be re-approved)
                         ├─► EXPIRED
                         └─► CANCELLED

PolicyVersion    DRAFT ──► REVIEW ──► APPROVED ──► ACTIVE ──► DEPRECATED
                   ▲                                              │
                   └──── one rejection returns it to DRAFT ────────┘

Authorization    REQUESTED ──► EVALUATED ──► ALLOW | DENY | ESCALATE
                                                      │
                                        approval ─────┴──► superseding decision
```

Two properties are enforced rather than assumed:

- **Expiry is derived at read time** from server-authoritative time, not
  written by a sweep. A lapsed lease stops authorizing the instant it lapses,
  not when a cron job notices. `isExpired` treats the boundary instant as
  already expired, because the tie has to break the safe way.
- **Revocation propagates by chain walk.** The evaluator walks a lease's full
  ancestry on every decision, so revoking a parent kills every descendant
  immediately, with no cascade job and no cache to invalidate.

## Money

Amounts are integer minor units with an explicit currency, parsed from exact
decimal strings. A fractional JSON number is refused at the boundary rather
than compared, because `0.1 + 0.2` has no business anywhere near a payment
threshold.

Cross-currency comparison raises rather than converting: Scrutexity holds no
exchange rates, and inventing one would silently move an authorization
threshold.

**Known boundary.** A lease carries one `max_amount`, denominated in one
currency, and refuses requests in any other. This is correct and fail-closed,
but a treasury operating in several currencies needs one lease per currency
today. Per-currency ceilings are the natural fix and would not disturb the
containment algebra: the dimension registry in `authority/grant.ts` exists so a
new dimension is a table entry and a test rather than a rewrite.
