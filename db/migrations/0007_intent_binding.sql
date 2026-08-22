-- =============================================================================
-- 0007 :: exact intent binding
-- =============================================================================
--
-- Until now an ALLOW said an agent *may* move $25,000 to cp_100, and nothing
-- recorded what "that operation" was in a form anyone could compare against
-- later. The agent reported an outcome; the system believed it.
--
-- These columns are what makes the comparison possible. They are written when
-- the grant is issued and are never rewritten -- the table is append-only, so
-- the database enforces that rather than the application promising it.
--
-- Two hashes, deliberately not merged. See docs/canonicalization-spec.md.
--   exact_intent_hash -- "did the operation mutate?"
--   binding_hash      -- "is this operation bound to *this* decision?"

SET search_path = scrutexity, public;

ALTER TABLE authorization_decisions
  -- SHA-256 over the canonical operation, projected onto the action catalog.
  -- Null for a DENY or an ESCALATE: there is no authorised operation to bind.
  ADD COLUMN exact_intent_hash TEXT
    CHECK (exact_intent_hash IS NULL OR exact_intent_hash ~ '^[0-9a-f]{64}$'),
  -- SHA-256 over the operation plus the authority that authorised it.
  ADD COLUMN binding_hash TEXT
    CHECK (binding_hash IS NULL OR binding_hash ~ '^[0-9a-f]{64}$'),
  -- Single-use randomness, so two legitimately identical operations bind
  -- differently. Stored because the binding cannot be recomputed without it.
  ADD COLUMN binding_nonce TEXT,
  -- The canonical operation itself, so the enforcement boundary can name the
  -- fields that changed rather than only reporting that a hash moved, and so
  -- a verifier can recompute the hash from the recorded facts.
  ADD COLUMN authorized_intent JSONB;

-- An ALLOW must carry a complete binding or none of it. A half-written
-- binding is worse than no binding: it looks like a control and is not one.
ALTER TABLE authorization_decisions
  ADD CONSTRAINT authorization_decisions_binding_complete CHECK (
    (exact_intent_hash IS NULL AND binding_hash IS NULL
       AND binding_nonce IS NULL AND authorized_intent IS NULL)
    OR
    (exact_intent_hash IS NOT NULL AND binding_hash IS NOT NULL
       AND binding_nonce IS NOT NULL AND authorized_intent IS NOT NULL)
  );

-- Finding an execution's grant by what it claims to be doing, for the
-- verification report and the root-cause trace.
CREATE INDEX authorization_decisions_intent_idx
  ON authorization_decisions (organization_id, exact_intent_hash)
  WHERE exact_intent_hash IS NOT NULL;
