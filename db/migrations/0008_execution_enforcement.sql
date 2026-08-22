-- =============================================================================
-- 0008 :: the execution enforcement boundary
-- =============================================================================
--
-- Until now `execution_attempts` recorded what an agent *said* it did. This
-- table records what the enforcement boundary is *doing*, which is a different
-- thing and needs a different shape.
--
-- The distinction that forces a new table: execution_attempts is append-only,
-- because an immutable record of a completed attempt is the point of it. A
-- lifecycle that transitions EXECUTING -> EXECUTED cannot live there. So this
-- table is mutable and holds the in-flight state; execution_attempts stays
-- append-only and holds the settled record.
--
-- The lifecycle exists to make one specific antipattern impossible:
--
--     check the grant  ->  call the bank  ->  mark the grant used
--
-- Two concurrent requests both pass the check before either marks. Here the
-- claim IS the insert, and UNIQUE (decision_id) means the database decides who
-- won before anyone contacts an external system. There is no window.

SET search_path = scrutexity, public;

CREATE TYPE execution_claim_state AS ENUM (
  -- Claimed, and the external call is in flight or about to be.
  'EXECUTING',
  -- The provider confirmed the operation happened.
  'EXECUTED',
  -- The provider confirmed the operation did not happen.
  'FAILED',
  -- The provider did not answer, or answered in a way that does not say
  -- whether the operation happened. This is the honest state and it is
  -- deliberately not collapsed into FAILED: "the wire did not go" and "I do
  -- not know whether the wire went" call for opposite responses.
  'UNKNOWN',
  -- Reconciliation established the outcome of an UNKNOWN out of band.
  'RECONCILED'
);

CREATE TABLE execution_claims (
  id                  TEXT PRIMARY KEY CHECK (id LIKE 'xclaim\_%'),
  organization_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  -- One claim per grant. This unique constraint is the exactly-once boundary
  -- for grant consumption; everything else is bookkeeping.
  decision_id         TEXT NOT NULL UNIQUE
                        REFERENCES authorization_decisions(id) ON DELETE RESTRICT,
  agent_id            TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
  state               execution_claim_state NOT NULL DEFAULT 'EXECUTING',

  -- Which provider was asked, and the key it was asked under. The key is
  -- derived from the grant and never regenerated, so a retry after a timeout
  -- reaches the provider as the same request rather than a second one.
  provider            TEXT NOT NULL,
  idempotency_key     TEXT NOT NULL,

  -- What the boundary verified before it made the call. Recorded so a later
  -- reader can see that the check happened, not merely that it passed.
  exact_intent_hash   TEXT NOT NULL CHECK (exact_intent_hash ~ '^[0-9a-f]{64}$'),
  binding_hash        TEXT NOT NULL CHECK (binding_hash ~ '^[0-9a-f]{64}$'),

  -- The provider's own handle for the operation, once it gives one.
  external_reference  TEXT,
  -- Provider-reported failure detail. Never contains credentials: the adapter
  -- is responsible for what it puts here.
  last_error          TEXT,
  attempts            INTEGER NOT NULL DEFAULT 1 CHECK (attempts >= 1),

  claimed_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at         TIMESTAMPTZ,

  -- A settled claim has a resolution time; an in-flight one does not. Without
  -- this an EXECUTING row could carry a resolved_at and read as finished.
  CONSTRAINT execution_claims_resolution CHECK (
    (state = 'EXECUTING' AND resolved_at IS NULL)
    OR (state <> 'EXECUTING' AND resolved_at IS NOT NULL)
  )
);

CREATE INDEX execution_claims_org_idx ON execution_claims (organization_id, claimed_at DESC);
-- The reconciliation query: what is still in flight, or ended without an
-- answer. An operator and a reconciliation worker both start here.
CREATE INDEX execution_claims_unresolved_idx
  ON execution_claims (organization_id, claimed_at)
  WHERE state IN ('EXECUTING', 'UNKNOWN');

ALTER TABLE execution_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON execution_claims
  USING (organization_id = scrutexity.current_org_id())
  WITH CHECK (organization_id = scrutexity.current_org_id());
GRANT SELECT, INSERT, UPDATE ON execution_claims TO scrutexity_app;

-- =============================================================================
-- What the boundary actually executed
-- =============================================================================
--
-- execution_attempts gains the hash the boundary computed from the operation
-- it was given, alongside the one recorded at authorization time. Storing both
-- rather than only "they matched" means a verifier can check the claim rather
-- than take it.

ALTER TABLE execution_attempts
  ADD COLUMN executed_intent_hash TEXT
    CHECK (executed_intent_hash IS NULL OR executed_intent_hash ~ '^[0-9a-f]{64}$'),
  ADD COLUMN executed_operation JSONB,
  ADD COLUMN claim_id TEXT REFERENCES execution_claims(id) ON DELETE RESTRICT,
  -- False for the legacy self-report path, where the caller performed the
  -- operation itself and Scrutexity only recorded the outcome. An operator
  -- reading evidence must be able to tell the two apart without inference.
  ADD COLUMN enforced BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX execution_attempts_claim_idx ON execution_attempts (claim_id)
  WHERE claim_id IS NOT NULL;
