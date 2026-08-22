# Sequence diagrams

Mermaid. Every flow below is exercised by `make demo` and by the test suite.

## 1. The complete treasury wire flow

```mermaid
sequenceDiagram
    autonumber
    actor Ops as Treasury operator
    participant Agent as TreasuryAgent
    participant SDK as @scrutexity/sdk (PEP)
    participant API as Control plane
    participant PDP as @scrutexity/core (PDP)
    participant DB as PostgreSQL
    participant UI as Approval UI
    actor T as Treasurer

    rect rgb(245,245,245)
    note over Ops,DB: Agent identity, then authority issuance
    Ops->>API: POST /v1/agents
    API->>DB: insert agent (owner = a named human)
    Ops->>API: POST /v1/authority-leases
    note right of Ops: actions × resources × constraints,<br/>TTL 1h, derived from policy v1.4.0
    API->>DB: insert lease, append LEASE_ISSUED receipt
    API-->>Ops: lease_… expires 13:00Z
    end

    rect rgb(240,248,240)
    note over Agent,DB: A $25,000 wire — inside the agent discretion
    Agent->>SDK: authorize(wire.execute, acct_001, $25,000)
    SDK->>API: POST /v1/authorization/evaluate
    API->>DB: BEGIN; SET LOCAL scrutexity.org_id
    API->>DB: resolve agent · derive counterparty_known
    API->>DB: insert authorization_request (immutable)
    API->>DB: load policy version + verify content hash
    API->>DB: load leases WITH RECURSIVE ancestry
    API->>DB: load live signals (expires_at > now)
    API->>PDP: evaluateAuthorization(snapshot)
    PDP-->>API: ALLOW · WITHIN_LEASED_AUTHORITY
    API->>DB: insert decision · append receipt (chain head locked)
    API->>DB: COMMIT
    API-->>SDK: 200 ALLOW, expires_at +300s
    SDK->>Agent: proceed
    Agent->>SDK: wire sent
    SDK->>API: POST /v1/executions (single-use)
    API->>DB: insert execution · append EXECUTION receipt
    end

    rect rgb(255,250,235)
    note over Agent,T: A $75,000 wire — beyond discretion; the treasurer approves
    Agent->>SDK: authorize(wire.execute, acct_001, $75,000)
    SDK->>API: POST /v1/authorization/evaluate
    API->>PDP: evaluateAuthorization(snapshot)
    note right of PDP: envelope ✓ · ceiling ✗<br/>policy: ESCALATE, treasurer
    PDP-->>API: ESCALATE · TREASURER_APPROVAL_REQUIRED
    API->>DB: insert decision · insert approval_request · append receipt
    API-->>SDK: 200 ESCALATE (no execution grant)
    SDK-->>Agent: not allowed; approval pending
    API-->>UI: appears in GET /v1/approval-requests
    T->>UI: review
    T->>API: POST /v1/approvals {APPROVED}
    API->>DB: insert approval (roles snapshotted) · append APPROVAL receipt
    API->>PDP: re-evaluate with prior approvals
    PDP-->>API: ALLOW · APPROVED_BY_HUMAN
    API->>DB: insert superseding decision · append receipt
    note over DB: the escalated decision is never rewritten
    API-->>T: 201 · decision now ALLOW
    end

    rect rgb(250,240,240)
    note over Ops,DB: Evidence
    Ops->>API: POST /v1/receipts/{id}/verify
    API->>DB: read receipt + preceding chain segment
    API->>PDP: verifyReceipt · verifyChain
    PDP-->>API: payload digest ✓ link hash ✓ signature ✓ linkage ✓
    API-->>Ops: INTACT · attests evidence_integrity_and_provenance
    end
```

## 2. Delegation, and the violation it prevents

```mermaid
sequenceDiagram
    autonumber
    participant TA as TreasuryAgent
    participant API as Control plane
    participant DEL as core/delegation
    participant DB as PostgreSQL
    participant VA as VerificationAgent

    TA->>API: POST /v1/delegations<br/>counterparty.read on cp_100, cp_101 · TTL 600s
    API->>DB: SELECT parent lease FOR UPDATE
    API->>DB: WITH RECURSIVE parent ancestry
    API->>DEL: authorizeDelegation(proposal, context)

    note right of DEL: 1 issuer holds the parent lease?<br/>2 whole ancestry ACTIVE?<br/>3 delegation enabled, depth ≤ max?<br/>4 actions delegable by policy?<br/>5 child ⊆ parent on every axis?<br/>6 TTL clamped to parent expiry

    DEL-->>API: ok · child grant · depth 1 · expiry clamped
    API->>DB: insert child lease (parent_lease_id set)
    API->>DB: insert delegation edge
    API->>DB: append DELEGATION_CREATED receipt
    API-->>TA: 201

    rect rgb(255,240,240)
    note over TA,DB: overreach is rejected, never clamped
    TA->>API: POST /v1/delegations + wire.execute
    API->>DEL: authorizeDelegation
    DEL-->>API: rejected · ACTION_NOT_DELEGABLE
    API-->>TA: 403 · policy marks wire.* non-delegable
    end

    rect rgb(240,248,240)
    VA->>API: evaluate counterparty.read on cp_100
    API-->>VA: 200 ALLOW · READ_ONLY_ACTION
    end

    rect rgb(255,240,240)
    VA->>API: evaluate wire.modify on acct_001
    note right of API: envelope check on the *base* grant:<br/>action not present → terminal
    API-->>VA: 200 DENY · ACTION_NOT_IN_AUTHORITY
    note over VA: no approval path is offered:<br/>this is outside the agent's role,<br/>not merely beyond its discretion
    end
```

## 3. Authority decay from a risk signal

```mermaid
sequenceDiagram
    autonumber
    participant FE as External fraud engine
    participant API as Control plane
    participant DB as PostgreSQL
    participant Agent as TreasuryAgent
    participant PDP as core/evaluate

    note over Agent,PDP: before — the same request runs unattended
    Agent->>API: evaluate wire.execute $25,000
    API->>PDP: snapshot (no live signals)
    PDP-->>API: ALLOW · WITHIN_LEASED_AUTHORITY

    FE->>API: POST /v1/signals<br/>fraud_risk = 0.97 · confidence 0.91 · ttl 600s
    API->>DB: insert signal
    API->>DB: supersede prior signals from this source
    API->>DB: append SIGNAL_INGESTED receipt

    Agent->>API: evaluate wire.execute $25,000
    API->>DB: load live signals (expires_at > now)
    API->>PDP: snapshot (fraud_risk = 0.97)

    note right of PDP: rule elevated_fraud_risk matches<br/>→ ESCALATE, treasurer<br/>→ authority_effect removes wire.*<br/><br/>base grant → envelope ✓<br/>decayed grant → autonomy ✗
    PDP-->>API: ESCALATE · AUTHORITY_DECAYED
    API-->>Agent: 200 ESCALATE · approval required

    note over DB,PDP: 600 seconds later
    Agent->>API: evaluate wire.execute $25,000
    API->>DB: load live signals → none (TTL lapsed)
    API->>PDP: snapshot (no live signals)
    PDP-->>API: ALLOW · authority restored, no action taken
```

## 4. Revocation propagating through a delegation chain

```mermaid
sequenceDiagram
    autonumber
    actor Ops as Security operator
    participant API as Control plane
    participant DB as PostgreSQL
    participant VA as VerificationAgent (depth 1)

    Ops->>API: POST /v1/authority-leases/{parent}/revoke
    API->>DB: UPDATE status = REVOKED, revoked_at = now()
    API->>DB: append LEASE_REVOKED receipt (descendants recorded)
    note over DB: descendant rows are NOT modified

    VA->>API: evaluate counterparty.read (child lease still ACTIVE)
    API->>DB: WITH RECURSIVE ancestry of the child lease
    note right of API: evaluateChain walks leaf → root;<br/>the root reads REVOKED,<br/>so the whole chain is unusable
    API-->>VA: 200 DENY · AUTHORITY_REVOKED

    note over Ops,VA: no cascade job, no cache to invalidate.<br/>the window is one committed transaction.
```

## 5. Policy lifecycle under dual control

```mermaid
stateDiagram-v2
    [*] --> DRAFT: POST /v1/policy-versions<br/>(validated, hashed, immutable)
    DRAFT --> REVIEW: first review APPROVED<br/>(reviewer ≠ author)
    REVIEW --> APPROVED: second review APPROVED<br/>(distinct reviewer)
    REVIEW --> DRAFT: any review REJECTED
    DRAFT --> DRAFT: any review REJECTED
    APPROVED --> ACTIVE: activate<br/>(hash re-verified first)
    ACTIVE --> DEPRECATED: superseded by a newer activation
    ACTIVE --> REVOKED: emergency withdrawal
    DEPRECATED --> ACTIVE: rollback by activating again
    REVOKED --> [*]
```

## 6. Deployment models the semantics must survive

```mermaid
flowchart LR
    subgraph Models["Enforcement point placement"]
        direction TB
        A["SDK in-process"]
        B["Sidecar container"]
        C["API gateway filter"]
        D["Service middleware"]
    end
    A --> PDP
    B --> PDP
    C --> PDP
    D --> PDP
    PDP["Authorization service<br/>(Policy Decision Point)"] --> CORE["@scrutexity/core<br/>evaluateAuthorization"]
    CORE --> OUT{"ALLOW · DENY · ESCALATE"}
    OUT -->|ALLOW| TARGET["Target API<br/>(the payment rail)"]
    OUT -->|ESCALATE| HUMAN["Approval UI"]
    OUT -->|DENY| BLOCKED["Blocked · receipt written"]

    style CORE fill:#eef,stroke:#446
    style OUT fill:#ffe,stroke:#a80
```

The point of the diagram: every placement calls the _same_ pure function.
Moving the enforcement point closer to or further from the action changes
latency and blast radius. It never changes the answer.
