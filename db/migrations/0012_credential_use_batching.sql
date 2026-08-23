-- ===========================================================================
-- 0012  Recording credential use stops costing a transaction per request
-- ===========================================================================
--
-- `touch_credential(id)` ran on its own `BEGIN`/`COMMIT` in front of every
-- authenticated request. Measured: one authorize cost ~3.6 database commits,
-- and this was one of them -- an fsync, per request, for a telemetry column.
--
-- The coarsening was already there (five minutes) but it was applied *inside*
-- the statement, so every request still paid for the round trip and the commit
-- to discover it had nothing to write.
--
-- The API now buffers credential ids in memory and flushes them here on an
-- interval, so the cost is one transaction per flush rather than one per
-- request. The five-minute clause is gone with it: the buffer already dedupes
-- within an interval, and re-applying a time filter would only reintroduce the
-- work this exists to remove.
--
-- ## This is a cross-tenant write, deliberately, and it is the narrowest one
--
-- Every other SECURITY DEFINER function in migration 0010 compares against
-- `current_org_id()` and refuses otherwise. This one cannot: the flush happens
-- outside any request, so there is no tenant context, and one buffer holds
-- credentials from every tenant the node served.
--
-- What that is safe to grant rests on the function's shape rather than on a
-- check:
--
--   * it writes exactly one column, `last_used_at`, and nothing else;
--   * it sets it to `transaction_timestamp()` -- the caller cannot choose a
--     value, so it cannot be used to backdate a credential and make it look
--     unused;
--   * it returns void. A count would say how many of the supplied ids exist,
--     which is a membership oracle over credential ids, and telemetry is not
--     worth an oracle;
--   * it can only reach rows whose id the caller already holds.
--
-- The function it replaces had the same absence of a tenant check for the same
-- reason, so this is not new surface -- but the reasoning was never written
-- down, and an unexplained cross-tenant primitive is one nobody can review.

SET search_path = scrutexity, public;

CREATE FUNCTION scrutexity.touch_credentials(p_ids TEXT[])
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = scrutexity, public AS $$
  UPDATE scrutexity.api_credentials
     SET last_used_at = transaction_timestamp()
   WHERE id = ANY(p_ids)
$$;
REVOKE ALL ON FUNCTION scrutexity.touch_credentials(TEXT[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scrutexity.touch_credentials(TEXT[]) TO scrutexity_app;

-- Dropped rather than left in place. An unused SECURITY DEFINER function is a
-- privilege the application role holds and nothing exercises, which is exactly
-- the kind of thing that survives a review by being invisible.
DROP FUNCTION IF EXISTS scrutexity.touch_credential(TEXT);
