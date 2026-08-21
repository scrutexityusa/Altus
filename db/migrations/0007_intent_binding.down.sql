SET search_path = scrutexity, public;

DROP INDEX IF EXISTS authorization_decisions_intent_idx;
ALTER TABLE authorization_decisions
  DROP CONSTRAINT IF EXISTS authorization_decisions_binding_complete;
ALTER TABLE authorization_decisions
  DROP COLUMN IF EXISTS authorized_intent,
  DROP COLUMN IF EXISTS binding_nonce,
  DROP COLUMN IF EXISTS binding_hash,
  DROP COLUMN IF EXISTS exact_intent_hash;
