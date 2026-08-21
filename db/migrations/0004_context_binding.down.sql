-- Reverses 0004. Rolling back removes the TOCTOU binding: executions will no
-- longer verify that conditions are unchanged since approval.
SET search_path = scrutexity, public;

DROP INDEX IF EXISTS authorization_decisions_context_idx;
ALTER TABLE approvals DROP COLUMN IF EXISTS approved_context_hash;
ALTER TABLE approval_requests DROP COLUMN IF EXISTS context_hash;
ALTER TABLE authorization_decisions DROP COLUMN IF EXISTS context_hash;
