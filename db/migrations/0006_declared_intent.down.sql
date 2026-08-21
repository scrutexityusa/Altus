-- Reverses 0006.
SET search_path = scrutexity, public;

DROP INDEX IF EXISTS authorization_requests_intent_idx;
ALTER TABLE authorization_decisions DROP COLUMN IF EXISTS corrective_actions;
ALTER TABLE authorization_decisions DROP COLUMN IF EXISTS intent_evaluation;
ALTER TABLE authorization_requests DROP COLUMN IF EXISTS declared_intent;
