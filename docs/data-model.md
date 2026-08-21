# Data model

The authoritative artifact is [`db/migrations/0001_init.sql`](../db/migrations/0001_init.sql)
and [`0002_rls.sql`](../db/migrations/0002_rls.sql). This page explains the
choices a reader of the DDL would otherwise have to infer.

## Shape

19 tables in the `scrutexity` schema. Every tenant-scoped table carries
`organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE`
and is protected by `FORCE ROW LEVEL SECURITY` (ADR-0005).

```
organizations
├── users                    roles TEXT[]  — the vocabulary approval policy references
├── agents                   owner_user_id — a machine principal has a human owner
├── api_credentials          token_hash BYTEA; the secret is never stored
├── resources                (type, external_id) — accounts, counterparties
├── policies → policy_versions → policy_version_reviews
├── authority_leases         self-referencing via parent_lease_id
├── delegations              the (issuer, delegate) edge over (parent, child) leases
├── risk_signals             self-referencing via superseded_by_id
├── authorization_requests   ─┐
├── authorization_decisions   │ append-only
├── approvals                 │ (UPDATE and DELETE raise 42501)
├── execution_attempts        │
├── receipts                 ─┘
├── approval_requests        status mutates: PENDING → SATISFIED | REJECTED | EXPIRED
├── receipt_chain_heads      one row per tenant, locked FOR UPDATE on append
└── idempotency_keys         (organization_id, endpoint, key)
```

## Choices worth explaining

**Prefixed TEXT primary keys** with `CHECK` constraints on the prefix
(ADR-0004). A malformed id cannot be written.

**JSONB for grants, constraints, context, evaluation and receipt payloads.**
These are validated by Zod on the way in and hashed on the way out; a column
per constraint dimension would make adding one a migration rather than a table
entry. The parts that must be queried — actions, resources — are additionally
GIN-indexed.

**Money as `(amount_minor BIGINT, currency CHAR(3))`.** Never `float`, never
`numeric` for amounts. Signal values are `NUMERIC(12,6)` read as strings by a
type parser override in `db/pool.ts`, so Postgres numerics never become JS
floats on their way into a decision.

**Enumerated types** for every status. Critical business state is never a
free-form string.

**Immutability is structural, not conventional.** `authorization_decisions` has
no mutable column: consumption is tracked by a row in `execution_attempts` with
`UNIQUE (decision_id)`, which is also what makes an execution grant single-use
without an application-level check a race could slip past.

## Constraints that encode invariants

| Constraint                         | Invariant                                           |
| ---------------------------------- | --------------------------------------------------- |
| `authority_leases_ttl_positive`    | `expires_at > issued_at`. No zero-length authority. |
| `authority_leases_revoked_shape`   | `status = REVOKED` ⇔ `revoked_at IS NOT NULL`.      |
| `authority_leases_root_depth`      | `parent_lease_id IS NULL` ⇔ `depth = 0`.            |
| `delegations_no_self`              | An agent cannot delegate to itself.                 |
| `execution_attempts_single_use`    | One execution per decision.                         |
| `policy_versions_one_active_idx`   | At most one ACTIVE version per policy.              |
| `approval_requests_open_idx`       | At most one PENDING request per decision.           |
| `approvals (request, approver)`    | One vote per human.                                 |
| `authorization_requests_nonce_idx` | A nonce is single-use per (org, agent).             |
| `receipts (organization_id, seq)`  | The chain cannot fork.                              |
| `content_hash ~ '^[0-9a-f]{64}$'`  | A digest column holds a digest.                     |

Several are partial unique indexes rather than triggers: the database enforces
them under concurrency without a race the application could lose.

## Indexes, and what each is for

**Hot path — the authorization decision.**

```sql
authority_leases_lookup_idx  (organization_id, agent_id, status, expires_at DESC)
risk_signals_live_idx        (organization_id, subject_type, subject_id,
                              signal_type, expires_at DESC) WHERE superseded_at IS NULL
policy_versions_one_active_idx (policy_id) WHERE status = 'ACTIVE'
```

**DAG traversal**, in both directions, because "who did this agent delegate to"
and "who delegated to this agent" are both questions the authority graph must
answer:

```sql
delegations_edge_idx        (issuer_agent_id, delegate_agent_id)
delegations_edge_rev_idx    (delegate_agent_id, issuer_agent_id)
delegations_lease_edge_idx  (parent_lease_id, child_lease_id)
authority_leases_parent_idx (parent_lease_id)
```

**Time-based, for expiry and revocation sweeps.** Partial, so they index only
the rows a sweep would visit:

```sql
authority_leases_expiry_idx (expires_at) WHERE status IN ('ACTIVE','PENDING','SUSPENDED')
risk_signals_expiry_idx     (expires_at) WHERE superseded_at IS NULL
approval_requests_expiry_idx(expires_at) WHERE status = 'PENDING'
delegations_expiry_idx      (expires_at) WHERE status = 'ACTIVE'
```

Expiry is **derived at read time**, so these support reporting and cleanup —
never correctness. A lease is expired because the clock says so, not because a
sweep has run.

**Foreign-key and evidence lookups** on `agent_id`, `organization_id`,
`policy_version_id`, `authority_lease_id`, `decision_id`, and
`receipts (organization_id, seq DESC)` for chain verification.

## Migrations

`scripts/migrate.ts` applies `db/migrations/*.sql` in lexical order, one
transaction each, recording a SHA-256 of the file. Re-running is a no-op.
**Editing an applied migration is an error**, not a silent divergence: a schema
whose history nobody can reconstruct is a schema nobody can reason about.
