-- =============================================================================
-- 0004 :: binding a decision to the conditions it was made under
--
-- A human approves a wire under a particular set of facts: this request, this
-- policy version, this authority, these live risk signals. If any of those
-- change before the wire is released, the approval no longer describes what is
-- about to happen. That gap between check and use is the classic TOCTOU
-- window, and for a payment it is the difference between an approved transfer
-- and an approved-looking one.
--
-- The fix is to fingerprint the decision's inputs, record the fingerprint on
-- the decision and on every approval, and recompute it at execution.
-- =============================================================================
SET search_path = scrutexity, public;

ALTER TABLE authorization_decisions
  -- SHA-256 over the canonical decision context: the request hash, the policy
  -- hash, the authority lease, and the live signal fingerprint. Nullable only
  -- so that decisions written before this migration remain readable; the
  -- execution path refuses to proceed when it is absent.
  ADD COLUMN context_hash TEXT
    CHECK (context_hash IS NULL OR context_hash ~ '^[0-9a-f]{64}$');

ALTER TABLE approval_requests
  ADD COLUMN context_hash TEXT
    CHECK (context_hash IS NULL OR context_hash ~ '^[0-9a-f]{64}$');

ALTER TABLE approvals
  -- What this approver actually saw and agreed to. Recorded per approval
  -- rather than derived from the request, so a later change cannot rewrite
  -- what an approval meant.
  ADD COLUMN approved_context_hash TEXT
    CHECK (approved_context_hash IS NULL OR approved_context_hash ~ '^[0-9a-f]{64}$');

CREATE INDEX authorization_decisions_context_idx
  ON authorization_decisions (context_hash)
  WHERE context_hash IS NOT NULL;
