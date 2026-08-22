-- Reverses 0002_rls.
--
-- Dropping the tenant isolation policies leaves the tables readable by any
-- role holding table privileges. That is only acceptable while rolling back to
-- a schema nobody is serving traffic from; never run this against a live
-- tenant database.
SET search_path = scrutexity, public;

DROP FUNCTION IF EXISTS scrutexity.resolve_credential(TEXT);

DO $$
DECLARE
  t TEXT;
  protected_tables TEXT[] := ARRAY[
    'users','agents','api_credentials','resources','policies','policy_versions',
    'policy_version_reviews','authority_leases','delegations','risk_signals',
    'authorization_requests','authorization_decisions','approval_requests',
    'approvals','execution_attempts','receipts','receipt_chain_heads',
    'idempotency_keys','organizations'
  ];
BEGIN
  FOREACH t IN ARRAY protected_tables LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON scrutexity.%I', t);
    EXECUTE format('ALTER TABLE scrutexity.%I NO FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE scrutexity.%I DISABLE ROW LEVEL SECURITY', t);
  END LOOP;
END
$$;

DROP FUNCTION IF EXISTS scrutexity.current_org_id();

REVOKE ALL ON ALL TABLES IN SCHEMA scrutexity FROM scrutexity_app;
REVOKE USAGE ON SCHEMA scrutexity FROM scrutexity_app;
