-- Reverses 0003. Existing single-use grants lose their spent/claimed state and
-- become indistinguishable from reusable leases, so do not roll this back with
-- live grants outstanding: a spent grant would become spendable again.
SET search_path = scrutexity, public;

DROP INDEX IF EXISTS authority_leases_unspent_idx;
DROP INDEX IF EXISTS authority_leases_claimed_by_idx;
DROP INDEX IF EXISTS authority_leases_single_claim_idx;

ALTER TABLE authority_leases
  DROP CONSTRAINT IF EXISTS authority_leases_reusable_never_claimed,
  DROP CONSTRAINT IF EXISTS authority_leases_claim_shape,
  DROP CONSTRAINT IF EXISTS authority_leases_grant_state;

ALTER TABLE authority_leases
  DROP COLUMN IF EXISTS used_at,
  DROP COLUMN IF EXISTS consumed,
  DROP COLUMN IF EXISTS claimed_by_decision_id,
  DROP COLUMN IF EXISTS claimed_at,
  DROP COLUMN IF EXISTS purpose,
  DROP COLUMN IF EXISTS grant_type;

DROP TYPE IF EXISTS grant_type;
