-- =============================================================================
-- 0003 :: single-use, purpose-bound authority grants
--
-- A reusable lease answers "may this agent do this kind of thing for the next
-- hour". A single-use grant answers "may this agent do this one thing, once".
-- The second is the safer default for high-consequence actions, and it needs
-- exactly-once semantics under concurrency and retry -- which means the
-- database, not the application, decides who won.
--
-- Backward compatible: every existing lease becomes REUSABLE, which is the
-- behaviour it already had.
-- =============================================================================
SET search_path = scrutexity, public;

CREATE TYPE grant_type AS ENUM ('REUSABLE', 'SINGLE_USE');

ALTER TABLE authority_leases
  ADD COLUMN grant_type grant_type NOT NULL DEFAULT 'REUSABLE',
  -- The declared objective this authority was granted for. Compared against
  -- the intent an agent declares at request time (see 0004 and the policy
  -- engine's intent evaluation).
  ADD COLUMN purpose TEXT,
  -- CLAIMED: an ALLOW decision has bound this grant and no other may.
  ADD COLUMN claimed_at TIMESTAMPTZ,
  ADD COLUMN claimed_by_decision_id TEXT,
  -- USED: the claim was executed against. Terminal.
  ADD COLUMN consumed BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN used_at TIMESTAMPTZ;

-- The state machine, enforced by the database rather than by convention:
--   CREATED  claimed_at IS NULL AND NOT consumed
--   CLAIMED  claimed_at IS NOT NULL AND NOT consumed
--   USED     consumed AND used_at IS NOT NULL AND claimed_at IS NOT NULL
-- Nothing may be consumed without first having been claimed, and nothing may
-- record a use without being consumed.
ALTER TABLE authority_leases
  ADD CONSTRAINT authority_leases_grant_state CHECK (
    (NOT consumed AND used_at IS NULL)
    OR (consumed AND used_at IS NOT NULL AND claimed_at IS NOT NULL)
  ),
  ADD CONSTRAINT authority_leases_claim_shape CHECK (
    (claimed_at IS NULL) = (claimed_by_decision_id IS NULL)
  ),
  -- A reusable lease is never claimed or consumed; the columns exist for one
  -- grant type only and the constraint says so out loud.
  ADD CONSTRAINT authority_leases_reusable_never_claimed CHECK (
    grant_type = 'SINGLE_USE' OR (claimed_at IS NULL AND NOT consumed)
  );

-- At most one live claim per single-use grant. This is the exactly-once
-- guarantee: a second concurrent claim cannot be recorded, whatever the
-- application believes.
CREATE UNIQUE INDEX authority_leases_single_claim_idx
  ON authority_leases (id)
  WHERE grant_type = 'SINGLE_USE' AND claimed_at IS NOT NULL;

CREATE INDEX authority_leases_claimed_by_idx
  ON authority_leases (claimed_by_decision_id)
  WHERE claimed_by_decision_id IS NOT NULL;

-- Locating unspent single-use grants for an agent, which is the hot path when
-- one is presented.
CREATE INDEX authority_leases_unspent_idx
  ON authority_leases (organization_id, agent_id, expires_at DESC)
  WHERE grant_type = 'SINGLE_USE' AND NOT consumed;
