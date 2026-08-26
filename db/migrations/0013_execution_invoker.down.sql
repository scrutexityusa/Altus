SET search_path = scrutexity, public;

DROP INDEX IF EXISTS scrutexity.execution_claims_invoked_by_idx;

ALTER TABLE execution_claims
  DROP CONSTRAINT IF EXISTS execution_claims_invoker_complete;

ALTER TABLE execution_claims
  DROP COLUMN IF EXISTS invoked_by_id,
  DROP COLUMN IF EXISTS invoked_by_type;

DROP TYPE IF EXISTS execution_invoker;
