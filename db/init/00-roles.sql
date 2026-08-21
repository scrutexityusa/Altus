-- Creates the non-owner application role the API connects as.
--
-- Tenant isolation depends on this role NOT being the table owner: the owner
-- bypasses row level security unless FORCE is set, and even with FORCE the
-- SECURITY DEFINER path for credential lookup needs an owner that can read
-- api_credentials. See ADR-0005 and db/migrations/0002_rls.sql.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'scrutexity_app') THEN
    CREATE ROLE scrutexity_app LOGIN PASSWORD 'scrutexity';
  END IF;
END
$$;
