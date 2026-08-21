-- =============================================================================
-- Scrutexity :: 0001_init
-- Machine Authority Control Plane -- core schema.
--
-- Conventions
--   * Primary keys are prefixed, lexicographically sortable TEXT ids
--     (e.g. lease_01JBX7Q...). Readable in receipts, logs and traces; no dual
--     identity (see ADR-0004).
--   * Every tenant-scoped table carries organization_id and is protected by
--     FORCE ROW LEVEL SECURITY keyed on the `scrutexity.org_id` GUC.
--   * Evidence tables (authorization_requests, authorization_decisions,
--     approvals, receipts, execution_attempts) are append-only, enforced by
--     trigger, not convention.
--   * Money is stored as (amount_minor BIGINT, currency CHAR(3)). Never float.
-- =============================================================================


CREATE SCHEMA IF NOT EXISTS scrutexity;
SET search_path = scrutexity, public;

-- -----------------------------------------------------------------------------
-- Enumerations. Critical state is never a free-form string.
-- -----------------------------------------------------------------------------
CREATE TYPE agent_status            AS ENUM ('ACTIVE','SUSPENDED','RETIRED');
CREATE TYPE credential_status       AS ENUM ('ACTIVE','REVOKED');
CREATE TYPE principal_type          AS ENUM ('user','agent','service');
CREATE TYPE lease_status            AS ENUM ('PENDING','ACTIVE','EXPIRED','REVOKED','SUSPENDED');
CREATE TYPE delegation_status       AS ENUM ('ACTIVE','EXPIRED','REVOKED');
CREATE TYPE policy_version_status   AS ENUM ('DRAFT','REVIEW','APPROVED','ACTIVE','DEPRECATED','REVOKED');
CREATE TYPE authorization_decision_t AS ENUM ('ALLOW','DENY','ESCALATE');
CREATE TYPE approval_request_status AS ENUM ('PENDING','SATISFIED','REJECTED','EXPIRED','CANCELLED');
CREATE TYPE approval_vote           AS ENUM ('APPROVED','REJECTED');
CREATE TYPE execution_status        AS ENUM ('RECORDED','SUCCEEDED','FAILED','BLOCKED');
CREATE TYPE failover_behavior       AS ENUM ('FAIL_OPEN','FAIL_CLOSED','ESCALATE');
CREATE TYPE subject_type            AS ENUM ('agent','user','organization','resource','counterparty');
CREATE TYPE receipt_kind            AS ENUM (
  'AUTHORIZATION_DECISION','APPROVAL','EXECUTION','LEASE_ISSUED','LEASE_REVOKED',
  'DELEGATION_CREATED','SIGNAL_INGESTED','POLICY_ACTIVATED');

-- -----------------------------------------------------------------------------
-- Append-only enforcement
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION scrutexity.deny_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'table %.% is append-only: % is not permitted',
    TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
    USING ERRCODE = '42501';
END;
$$;

-- =============================================================================
-- TENANCY & IDENTITY
-- =============================================================================

CREATE TABLE organizations (
  id            TEXT PRIMARY KEY CHECK (id LIKE 'org\_%'),
  slug          TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id              TEXT PRIMARY KEY CHECK (id LIKE 'user\_%'),
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email           TEXT NOT NULL,
  display_name    TEXT NOT NULL,
  -- Organization-defined role names (treasurer, cfo, admin, ...). Approval
  -- policy references these; Scrutexity does not fix the vocabulary.
  roles           TEXT[] NOT NULL DEFAULT '{}',
  status          TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (organization_id, email)
);
CREATE INDEX users_org_idx        ON users (organization_id);
CREATE INDEX users_org_roles_idx  ON users USING GIN (roles);

CREATE TABLE agents (
  id              TEXT PRIMARY KEY CHECK (id LIKE 'agent\_%'),
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  -- Caller-facing stable handle, unique per tenant (e.g. "treasury-agent-42").
  handle          TEXT NOT NULL,
  display_name    TEXT NOT NULL,
  description     TEXT,
  -- Human/organization accountability for the machine principal.
  owner_user_id   TEXT REFERENCES users(id) ON DELETE RESTRICT,
  status          agent_status NOT NULL DEFAULT 'ACTIVE',
  -- Optional Ed25519 public key (base64url) for agent-signed requests.
  public_key      TEXT,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (organization_id, handle)
);
CREATE INDEX agents_org_idx        ON agents (organization_id);
CREATE INDEX agents_owner_idx      ON agents (owner_user_id);
CREATE INDEX agents_org_status_idx ON agents (organization_id, status);

-- Bearer credentials for agents and users. Only the hash is stored.
CREATE TABLE api_credentials (
  id                TEXT PRIMARY KEY CHECK (id LIKE 'cred\_%'),
  organization_id   TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  principal_type    principal_type NOT NULL,
  principal_id      TEXT NOT NULL,
  -- Non-secret lookup prefix; the secret half is never persisted.
  token_prefix      TEXT NOT NULL UNIQUE,
  token_hash        BYTEA NOT NULL,
  scopes            TEXT[] NOT NULL DEFAULT '{}',
  status            credential_status NOT NULL DEFAULT 'ACTIVE',
  last_used_at      TIMESTAMPTZ,
  expires_at        TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX api_credentials_org_idx       ON api_credentials (organization_id);
CREATE INDEX api_credentials_principal_idx ON api_credentials (organization_id, principal_type, principal_id);

-- Protected resources: bank accounts, counterparties, ledgers.
CREATE TABLE resources (
  id              TEXT PRIMARY KEY CHECK (id LIKE 'res\_%'),
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  resource_type   TEXT NOT NULL,
  -- Caller-facing id used in authorization requests (e.g. "acct_991").
  external_id     TEXT NOT NULL,
  display_name    TEXT NOT NULL,
  -- Attributes readable by policy under the `resource.attributes.*` selector.
  attributes      JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (organization_id, resource_type, external_id)
);
CREATE INDEX resources_org_type_idx ON resources (organization_id, resource_type);

-- =============================================================================
-- POLICY
-- =============================================================================

CREATE TABLE policies (
  id              TEXT PRIMARY KEY CHECK (id LIKE 'pol\_%'),
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  key             TEXT NOT NULL,
  name            TEXT NOT NULL,
  description     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (organization_id, key)
);
CREATE INDEX policies_org_idx ON policies (organization_id);

CREATE TABLE policy_versions (
  id                  TEXT PRIMARY KEY CHECK (id LIKE 'polv\_%'),
  organization_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  policy_id           TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  version             TEXT NOT NULL,                    -- semver, e.g. 1.4.0
  status              policy_version_status NOT NULL DEFAULT 'DRAFT',
  -- Immutable policy document (validated against the policy JSON Schema).
  content             JSONB NOT NULL,
  -- SHA-256 over the RFC 8785-style canonical JSON of `content`.
  content_hash        TEXT NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
  author_user_id      TEXT REFERENCES users(id) ON DELETE SET NULL,
  previous_version_id TEXT REFERENCES policy_versions(id) ON DELETE RESTRICT,
  approved_at         TIMESTAMPTZ,
  activated_at        TIMESTAMPTZ,
  deprecated_at       TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (policy_id, version)
);
CREATE INDEX policy_versions_org_idx        ON policy_versions (organization_id);
CREATE INDEX policy_versions_policy_idx     ON policy_versions (policy_id, created_at DESC);
CREATE INDEX policy_versions_hash_idx       ON policy_versions (content_hash);
-- At most one ACTIVE version per policy: enforced, not hoped for.
CREATE UNIQUE INDEX policy_versions_one_active_idx
  ON policy_versions (policy_id) WHERE status = 'ACTIVE';

-- Dual-control review trail for policy activation (Section 32).
CREATE TABLE policy_version_reviews (
  id                 TEXT PRIMARY KEY CHECK (id LIKE 'polr\_%'),
  organization_id    TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  policy_version_id  TEXT NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
  reviewer_user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  vote               approval_vote NOT NULL,
  comment            TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (policy_version_id, reviewer_user_id)
);
CREATE INDEX policy_version_reviews_pv_idx ON policy_version_reviews (policy_version_id);

-- =============================================================================
-- AUTHORITY
-- =============================================================================

CREATE TABLE authority_leases (
  id                 TEXT PRIMARY KEY CHECK (id LIKE 'lease\_%'),
  organization_id    TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  -- Machine principal the authority is issued to.
  agent_id           TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  -- Provenance: which policy version admitted this authority.
  policy_version_id  TEXT NOT NULL REFERENCES policy_versions(id) ON DELETE RESTRICT,
  issued_by_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
  issued_by_agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
  -- Grant scope. actions: exact ids or single trailing-* patterns ("wire.*").
  actions            TEXT[] NOT NULL CHECK (cardinality(actions) > 0),
  -- {"bank_account":["acct_991"],"counterparty":["*"]}
  resources          JSONB NOT NULL DEFAULT '{}'::jsonb,
  -- {"max_amount":{"currency":"USD","amount_minor":"5000000"}, ...}
  constraints        JSONB NOT NULL DEFAULT '{}'::jsonb,
  status             lease_status NOT NULL DEFAULT 'ACTIVE',
  revocable          BOOLEAN NOT NULL DEFAULT true,
  -- Delegation chain. depth 0 == root authority issued from policy.
  parent_lease_id    TEXT REFERENCES authority_leases(id) ON DELETE RESTRICT,
  depth              INTEGER NOT NULL DEFAULT 0 CHECK (depth >= 0),
  issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at         TIMESTAMPTZ NOT NULL,
  revoked_at         TIMESTAMPTZ,
  revoked_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  revocation_reason  TEXT,
  metadata           JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT authority_leases_ttl_positive CHECK (expires_at > issued_at),
  CONSTRAINT authority_leases_revoked_shape CHECK (
    (status = 'REVOKED') = (revoked_at IS NOT NULL)),
  CONSTRAINT authority_leases_root_depth CHECK (
    (parent_lease_id IS NULL) = (depth = 0))
);
CREATE INDEX authority_leases_org_idx          ON authority_leases (organization_id);
CREATE INDEX authority_leases_agent_idx        ON authority_leases (agent_id);
CREATE INDEX authority_leases_policy_ver_idx   ON authority_leases (policy_version_id);
CREATE INDEX authority_leases_parent_idx       ON authority_leases (parent_lease_id);
-- Hot path: "active authority for this agent, right now".
CREATE INDEX authority_leases_lookup_idx
  ON authority_leases (organization_id, agent_id, status, expires_at DESC);
-- Expiry sweep / TTL scans.
CREATE INDEX authority_leases_expiry_idx
  ON authority_leases (expires_at) WHERE status IN ('ACTIVE','PENDING','SUSPENDED');
CREATE INDEX authority_leases_actions_idx      ON authority_leases USING GIN (actions);
CREATE INDEX authority_leases_resources_idx    ON authority_leases USING GIN (resources jsonb_path_ops);

CREATE TABLE delegations (
  id                  TEXT PRIMARY KEY CHECK (id LIKE 'dlg\_%'),
  organization_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  issuer_agent_id     TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  delegate_agent_id   TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  parent_lease_id     TEXT NOT NULL REFERENCES authority_leases(id) ON DELETE RESTRICT,
  child_lease_id      TEXT NOT NULL UNIQUE REFERENCES authority_leases(id) ON DELETE RESTRICT,
  -- The narrowing the issuer asked for, retained verbatim as evidence.
  requested_grant     JSONB NOT NULL,
  status              delegation_status NOT NULL DEFAULT 'ACTIVE',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at          TIMESTAMPTZ NOT NULL,
  revoked_at          TIMESTAMPTZ,
  CONSTRAINT delegations_no_self CHECK (issuer_agent_id <> delegate_agent_id)
);
CREATE INDEX delegations_org_idx        ON delegations (organization_id);
-- DAG traversal: "who delegated to whom", both directions.
CREATE INDEX delegations_edge_idx       ON delegations (issuer_agent_id, delegate_agent_id);
CREATE INDEX delegations_edge_rev_idx   ON delegations (delegate_agent_id, issuer_agent_id);
CREATE INDEX delegations_lease_edge_idx ON delegations (parent_lease_id, child_lease_id);
CREATE INDEX delegations_expiry_idx     ON delegations (expires_at) WHERE status = 'ACTIVE';

-- =============================================================================
-- SIGNAL PLANE
-- =============================================================================

CREATE TABLE risk_signals (
  id               TEXT PRIMARY KEY CHECK (id LIKE 'sig\_%'),
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  subject_type     subject_type NOT NULL,
  -- Agent id, resource external id or counterparty id, depending on subject_type.
  subject_id       TEXT NOT NULL,
  signal_type      TEXT NOT NULL,
  value            NUMERIC(12,6) NOT NULL,
  confidence       NUMERIC(6,5) NOT NULL DEFAULT 1.0
                     CHECK (confidence >= 0 AND confidence <= 1),
  source           TEXT NOT NULL,
  metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
  issued_at        TIMESTAMPTZ NOT NULL,
  expires_at       TIMESTAMPTZ NOT NULL,
  received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Set when a newer signal for the same (subject, type, source) arrives.
  superseded_at    TIMESTAMPTZ,
  superseded_by_id TEXT REFERENCES risk_signals(id) ON DELETE SET NULL,
  CONSTRAINT risk_signals_ttl_positive CHECK (expires_at > issued_at)
);
CREATE INDEX risk_signals_org_idx ON risk_signals (organization_id);
-- Hot path: live signals for a subject.
CREATE INDEX risk_signals_live_idx
  ON risk_signals (organization_id, subject_type, subject_id, signal_type, expires_at DESC)
  WHERE superseded_at IS NULL;
CREATE INDEX risk_signals_expiry_idx ON risk_signals (expires_at) WHERE superseded_at IS NULL;

-- =============================================================================
-- AUTHORIZATION (append-only)
-- =============================================================================

CREATE TABLE authorization_requests (
  id                TEXT PRIMARY KEY CHECK (id LIKE 'areq\_%'),
  organization_id   TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  agent_id          TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
  -- The lease the caller presented, if it presented one explicitly.
  presented_lease_id TEXT REFERENCES authority_leases(id) ON DELETE RESTRICT,
  action            TEXT NOT NULL,
  resource_type     TEXT NOT NULL,
  resource_id       TEXT NOT NULL,
  context           JSONB NOT NULL DEFAULT '{}'::jsonb,
  -- Canonical hash of the semantic request; used for replay/idempotency.
  request_hash      TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
  -- Caller-supplied single-use nonce; reuse is REPLAY_DETECTED.
  nonce             TEXT,
  idempotency_key   TEXT,
  correlation_id    TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX authorization_requests_org_idx     ON authorization_requests (organization_id, created_at DESC);
CREATE INDEX authorization_requests_agent_idx   ON authorization_requests (agent_id, created_at DESC);
CREATE INDEX authorization_requests_res_idx     ON authorization_requests (organization_id, resource_type, resource_id);
CREATE UNIQUE INDEX authorization_requests_nonce_idx
  ON authorization_requests (organization_id, agent_id, nonce) WHERE nonce IS NOT NULL;
CREATE TRIGGER authorization_requests_append_only
  BEFORE UPDATE OR DELETE ON authorization_requests
  FOR EACH ROW EXECUTE FUNCTION scrutexity.deny_mutation();

CREATE TABLE authorization_decisions (
  id                    TEXT PRIMARY KEY CHECK (id LIKE 'dec\_%'),
  organization_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  request_id            TEXT NOT NULL REFERENCES authorization_requests(id) ON DELETE RESTRICT,
  agent_id              TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
  decision              authorization_decision_t NOT NULL,
  -- Machine-readable primary reason (see ErrorCode / ReasonCode union).
  reason_code           TEXT NOT NULL,
  policy_id             TEXT REFERENCES policies(id) ON DELETE RESTRICT,
  policy_version_id     TEXT REFERENCES policy_versions(id) ON DELETE RESTRICT,
  policy_hash           TEXT,
  authority_lease_id    TEXT REFERENCES authority_leases(id) ON DELETE RESTRICT,
  -- Structured evaluation record: matched rules, constraint checks, authority
  -- findings, effective (post-decay) grant. Replayable input to the explainer.
  evaluation            JSONB NOT NULL,
  approval_requirement  JSONB,
  failover_behavior     failover_behavior NOT NULL,
  risk_signal_ids       TEXT[] NOT NULL DEFAULT '{}',
  approval_ids          TEXT[] NOT NULL DEFAULT '{}',
  -- A re-evaluation after approval supersedes the escalated decision.
  supersedes_decision_id TEXT REFERENCES authorization_decisions(id) ON DELETE RESTRICT,
  -- An ALLOW is an execution grant with its own short TTL.
  expires_at            TIMESTAMPTZ,
  decided_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  evaluation_duration_us INTEGER
);
CREATE INDEX authorization_decisions_org_idx      ON authorization_decisions (organization_id, decided_at DESC);
CREATE INDEX authorization_decisions_request_idx  ON authorization_decisions (request_id);
CREATE INDEX authorization_decisions_agent_idx    ON authorization_decisions (agent_id, decided_at DESC);
CREATE INDEX authorization_decisions_lease_idx    ON authorization_decisions (authority_lease_id);
CREATE INDEX authorization_decisions_polver_idx   ON authorization_decisions (policy_version_id);
CREATE INDEX authorization_decisions_outcome_idx  ON authorization_decisions (organization_id, decision, decided_at DESC);
CREATE INDEX authorization_decisions_supersedes_idx ON authorization_decisions (supersedes_decision_id);
CREATE TRIGGER authorization_decisions_append_only
  BEFORE UPDATE OR DELETE ON authorization_decisions
  FOR EACH ROW EXECUTE FUNCTION scrutexity.deny_mutation();

-- =============================================================================
-- HUMAN APPROVAL
-- =============================================================================

CREATE TABLE approval_requests (
  id                TEXT PRIMARY KEY CHECK (id LIKE 'apr\_%'),
  organization_id   TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  decision_id       TEXT NOT NULL REFERENCES authorization_decisions(id) ON DELETE RESTRICT,
  request_id        TEXT NOT NULL REFERENCES authorization_requests(id) ON DELETE RESTRICT,
  -- {"quorum":2,"roles":["treasurer","cfo"],"distinct_users":true,
  --  "forbid_self_approval":true}
  requirement       JSONB NOT NULL,
  status            approval_request_status NOT NULL DEFAULT 'PENDING',
  expires_at        TIMESTAMPTZ NOT NULL,
  resolved_at       TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX approval_requests_org_idx      ON approval_requests (organization_id, status, created_at DESC);
CREATE INDEX approval_requests_decision_idx ON approval_requests (decision_id);
CREATE INDEX approval_requests_expiry_idx   ON approval_requests (expires_at) WHERE status = 'PENDING';
-- One open approval request per decision.
CREATE UNIQUE INDEX approval_requests_open_idx
  ON approval_requests (decision_id) WHERE status = 'PENDING';

CREATE TABLE approvals (
  id                  TEXT PRIMARY KEY CHECK (id LIKE 'apv\_%'),
  organization_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  approval_request_id TEXT NOT NULL REFERENCES approval_requests(id) ON DELETE RESTRICT,
  approver_user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  vote                approval_vote NOT NULL,
  -- Roles the approver actually held at approval time -- never re-derived later.
  roles_at_decision   TEXT[] NOT NULL,
  -- The role the requirement was satisfied by, for the evidence record.
  satisfied_role      TEXT,
  comment             TEXT,
  idempotency_key     TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- One vote per human per approval request.
  UNIQUE (approval_request_id, approver_user_id)
);
CREATE INDEX approvals_org_idx     ON approvals (organization_id, created_at DESC);
CREATE INDEX approvals_request_idx ON approvals (approval_request_id);
CREATE INDEX approvals_user_idx    ON approvals (approver_user_id, created_at DESC);
CREATE TRIGGER approvals_append_only
  BEFORE UPDATE OR DELETE ON approvals
  FOR EACH ROW EXECUTE FUNCTION scrutexity.deny_mutation();

-- =============================================================================
-- EXECUTION
-- =============================================================================

CREATE TABLE execution_attempts (
  id                TEXT PRIMARY KEY CHECK (id LIKE 'exec\_%'),
  organization_id   TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  decision_id       TEXT NOT NULL REFERENCES authorization_decisions(id) ON DELETE RESTRICT,
  agent_id          TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
  status            execution_status NOT NULL,
  result            JSONB NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key   TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- An ALLOW decision is a single-use execution grant. This is the enforcement
  -- point for "one authorization, one wire".
  CONSTRAINT execution_attempts_single_use UNIQUE (decision_id)
);
CREATE INDEX execution_attempts_org_idx   ON execution_attempts (organization_id, created_at DESC);
CREATE INDEX execution_attempts_agent_idx ON execution_attempts (agent_id, created_at DESC);
CREATE TRIGGER execution_attempts_append_only
  BEFORE UPDATE OR DELETE ON execution_attempts
  FOR EACH ROW EXECUTE FUNCTION scrutexity.deny_mutation();

-- =============================================================================
-- EVIDENCE :: hash-chained receipts (one chain per tenant)
-- =============================================================================

CREATE TABLE receipt_chain_heads (
  organization_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  seq             BIGINT NOT NULL DEFAULT 0,
  head_hash       TEXT NOT NULL,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE receipts (
  id               TEXT PRIMARY KEY CHECK (id LIKE 'rcpt\_%'),
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  seq              BIGINT NOT NULL,
  kind             receipt_kind NOT NULL,
  -- Denormalised anchors so evidence stays queryable without joins.
  subject_id       TEXT,
  request_id       TEXT REFERENCES authorization_requests(id) ON DELETE RESTRICT,
  decision_id      TEXT REFERENCES authorization_decisions(id) ON DELETE RESTRICT,
  -- The signed body. Canonicalised before hashing (see core/canonical.ts).
  payload          JSONB NOT NULL,
  payload_hash     TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  previous_hash    TEXT NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
  hash             TEXT NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  -- Ed25519 detached signature over `hash` (base64url), with the key id used.
  signature        TEXT,
  signing_key_id   TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (organization_id, seq),
  UNIQUE (organization_id, hash)
);
CREATE INDEX receipts_org_idx      ON receipts (organization_id, seq DESC);
CREATE INDEX receipts_decision_idx ON receipts (decision_id);
CREATE INDEX receipts_request_idx  ON receipts (request_id);
CREATE INDEX receipts_kind_idx     ON receipts (organization_id, kind, created_at DESC);
CREATE TRIGGER receipts_append_only
  BEFORE UPDATE OR DELETE ON receipts
  FOR EACH ROW EXECUTE FUNCTION scrutexity.deny_mutation();

-- =============================================================================
-- IDEMPOTENCY
-- =============================================================================

CREATE TABLE idempotency_keys (
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  endpoint        TEXT NOT NULL,
  key             TEXT NOT NULL,
  -- Guards key reuse with a different body (a client bug worth surfacing).
  request_hash    TEXT NOT NULL,
  status_code     INTEGER,
  response_body   JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at    TIMESTAMPTZ,
  PRIMARY KEY (organization_id, endpoint, key)
);
CREATE INDEX idempotency_keys_created_idx ON idempotency_keys (created_at);
