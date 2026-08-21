-- =============================================================================
-- Scrutexity :: 0002_rls
-- Tenant isolation enforced by the database, not only by application code.
--
-- The API connects as `scrutexity_app`, which is NOT the table owner and is
-- subject to FORCE ROW LEVEL SECURITY. Every transaction begins with
--   SET LOCAL scrutexity.org_id = '<org from authenticated identity>'
-- A query that forgets to set it sees zero rows and can insert nothing.
-- =============================================================================

BEGIN;
SET search_path = scrutexity, public;

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'scrutexity_app') THEN
    CREATE ROLE scrutexity_app LOGIN;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA scrutexity TO scrutexity_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA scrutexity TO scrutexity_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA scrutexity
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO scrutexity_app;

-- Current tenant, or NULL when unset. NULL never matches, so the default
-- posture of an unscoped connection is "no data".
CREATE OR REPLACE FUNCTION scrutexity.current_org_id() RETURNS TEXT
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('scrutexity.org_id', true), '')
$$;

DO $$
DECLARE
  t TEXT;
  tenant_tables TEXT[] := ARRAY[
    'users','agents','api_credentials','resources','policies','policy_versions',
    'policy_version_reviews','authority_leases','delegations','risk_signals',
    'authorization_requests','authorization_decisions','approval_requests',
    'approvals','execution_attempts','receipts','receipt_chain_heads',
    'idempotency_keys'
  ];
BEGIN
  FOREACH t IN ARRAY tenant_tables LOOP
    EXECUTE format('ALTER TABLE scrutexity.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE scrutexity.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON scrutexity.%I
        USING (organization_id = scrutexity.current_org_id())
        WITH CHECK (organization_id = scrutexity.current_org_id())
    $f$, t);
  END LOOP;
END
$$;

-- The organizations table itself: a tenant may read only its own row. Tenant
-- provisioning happens out-of-band as the owner role.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organizations
  USING (id = scrutexity.current_org_id());

-- Credential lookup happens before a tenant is known: authentication resolves
-- the tenant from the token, so it cannot itself be tenant-scoped. It is
-- restricted to a hash equality probe over a dedicated SECURITY DEFINER
-- function rather than opening the table.
CREATE OR REPLACE FUNCTION scrutexity.resolve_credential(p_prefix TEXT)
RETURNS TABLE (
  id TEXT, organization_id TEXT, principal_type scrutexity.principal_type,
  principal_id TEXT, token_hash BYTEA, scopes TEXT[],
  status scrutexity.credential_status, expires_at TIMESTAMPTZ)
LANGUAGE sql SECURITY DEFINER SET search_path = scrutexity, public STABLE AS $$
  SELECT c.id, c.organization_id, c.principal_type, c.principal_id,
         c.token_hash, c.scopes, c.status, c.expires_at
  FROM scrutexity.api_credentials c
  WHERE c.token_prefix = p_prefix
$$;
REVOKE ALL ON FUNCTION scrutexity.resolve_credential(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scrutexity.resolve_credential(TEXT) TO scrutexity_app;

COMMIT;
