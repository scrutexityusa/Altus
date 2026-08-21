SET search_path = scrutexity, public;

DROP INDEX IF EXISTS execution_attempts_claim_idx;
ALTER TABLE execution_attempts
  DROP COLUMN IF EXISTS enforced,
  DROP COLUMN IF EXISTS claim_id,
  DROP COLUMN IF EXISTS executed_operation,
  DROP COLUMN IF EXISTS executed_intent_hash;

DROP TABLE IF EXISTS execution_claims;
DROP TYPE IF EXISTS execution_claim_state;
