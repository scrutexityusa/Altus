-- =============================================================================
-- 0006 :: the intent an agent declared when it made a request
--
-- Stored on the request rather than derived at read time, because the whole
-- point of intent binding is that it is a claim the agent made at a moment in
-- time. Reconstructing it later from anything else would be inventing it.
-- =============================================================================
SET search_path = scrutexity, public;

ALTER TABLE authorization_requests ADD COLUMN declared_intent TEXT;

-- The structured intent verdict, so a decision can be re-read and explained
-- without re-running the evaluator.
ALTER TABLE authorization_decisions ADD COLUMN intent_evaluation JSONB;

-- Corrective actions offered with a refusal. Recorded as evidence: what the
-- control plane told the agent to do next is part of the audit trail.
ALTER TABLE authorization_decisions ADD COLUMN corrective_actions JSONB;

CREATE INDEX authorization_requests_intent_idx
  ON authorization_requests (organization_id, declared_intent)
  WHERE declared_intent IS NOT NULL;
