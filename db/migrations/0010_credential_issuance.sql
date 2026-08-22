-- Issuing and revoking credentials through the API.
--
-- `api_credentials` is the one table the application role has no privileges on
-- at all. That is deliberate and predates this migration: authentication is
-- what *resolves* the tenant, so credential lookup happens before a tenant is
-- known and cannot be tenant-scoped like everything else. The application role
-- reaches it only through `resolve_credential`, a single-row prefix probe.
--
-- Writes need the same shape, for the same reason: an administrator has to be
-- able to issue a credential to their treasurer through the API, and the
-- application role cannot be handed INSERT on this table without also handing
-- it the ability to read every credential in every tenant.
--
-- So: three narrow SECURITY DEFINER functions, each doing exactly one thing.
--
-- ## The tenant check is inside the function, not in RLS
--
-- RLS on this table is ENABLED but not FORCEd, which means a SECURITY DEFINER
-- function -- running as the table owner -- bypasses the tenant policy. That is
-- what makes authentication possible and it is also what makes these functions
-- dangerous if written carelessly: without an internal check, `issue_credential`
-- would be a cross-tenant write primitive granted to the application role.
--
-- Every function below therefore compares against `current_org_id()` itself and
-- raises otherwise. The caller's tenant context comes from `db.withTenant`,
-- which comes from the authenticated credential, so the chain is:
--
--     authenticated credential -> resolved organization -> transaction tenant
--     context -> application role -> function that refuses any other tenant
--
-- ## Principal validation rides on FORCE RLS rather than duplicating it
--
-- `users` and `agents` are FORCE RLS'd, and FORCE applies to the owner too --
-- so the existence check inside these functions is already filtered to
-- `current_org_id()`. A principal from another tenant is not merely rejected;
-- it is invisible. That is the one place where FORCE working against us
-- elsewhere works for us here.

SET search_path = scrutexity, public;

-- When a credential was revoked, distinct from when it was created. `status`
-- alone cannot answer "when did this stop working", which is the first question
-- asked during an incident.
ALTER TABLE api_credentials ADD COLUMN revoked_at TIMESTAMPTZ;
ALTER TABLE api_credentials
  ADD CONSTRAINT api_credentials_revoked_shape
  CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL));

-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION scrutexity.issue_credential(
  p_id              TEXT,
  p_organization_id TEXT,
  p_principal_type  scrutexity.principal_type,
  p_principal_id    TEXT,
  p_token_prefix    TEXT,
  p_token_hash      BYTEA,
  p_scopes          TEXT[],
  p_expires_at      TIMESTAMPTZ
) RETURNS TABLE (
  id TEXT, principal_type scrutexity.principal_type, principal_id TEXT,
  token_prefix TEXT, scopes TEXT[], status scrutexity.credential_status,
  expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = scrutexity, public AS $$
DECLARE
  v_exists BOOLEAN;
BEGIN
  IF p_organization_id IS DISTINCT FROM scrutexity.current_org_id() THEN
    -- Not merely a permission failure. A caller reaching this has passed
    -- authentication and is asking to write into a tenant that is not theirs.
    RAISE EXCEPTION 'credential issuance outside the caller''s tenant'
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  -- The principal must exist in this tenant. FORCE RLS on users and agents
  -- means "in this tenant" is already the only thing visible here.
  IF p_principal_type = 'user' THEN
    SELECT EXISTS (SELECT 1 FROM scrutexity.users u WHERE u.id = p_principal_id)
      INTO v_exists;
  ELSIF p_principal_type = 'agent' THEN
    SELECT EXISTS (SELECT 1 FROM scrutexity.agents a WHERE a.id = p_principal_id)
      INTO v_exists;
  ELSE
    -- 'service' principals name an external system rather than a stored row.
    v_exists := TRUE;
  END IF;

  IF NOT v_exists THEN
    RAISE EXCEPTION 'principal % does not exist in this organization', p_principal_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;

  RETURN QUERY
  INSERT INTO scrutexity.api_credentials
    (id, organization_id, principal_type, principal_id,
     token_prefix, token_hash, scopes, expires_at)
  VALUES
    (p_id, p_organization_id, p_principal_type, p_principal_id,
     p_token_prefix, p_token_hash, p_scopes, p_expires_at)
  RETURNING api_credentials.id, api_credentials.principal_type,
            api_credentials.principal_id, api_credentials.token_prefix,
            api_credentials.scopes, api_credentials.status,
            api_credentials.expires_at, api_credentials.created_at;
END;
$$;
REVOKE ALL ON FUNCTION scrutexity.issue_credential(
  TEXT, TEXT, scrutexity.principal_type, TEXT, TEXT, BYTEA, TEXT[], TIMESTAMPTZ) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scrutexity.issue_credential(
  TEXT, TEXT, scrutexity.principal_type, TEXT, TEXT, BYTEA, TEXT[], TIMESTAMPTZ) TO scrutexity_app;

-- ---------------------------------------------------------------------------

-- Operational metadata only. `token_hash` is not in the return type, so a
-- future caller cannot accidentally select it: the shape of the function is
-- the control, not the discipline of whoever writes the query.
CREATE OR REPLACE FUNCTION scrutexity.list_credentials()
RETURNS TABLE (
  id TEXT, principal_type scrutexity.principal_type, principal_id TEXT,
  token_prefix TEXT, scopes TEXT[], status scrutexity.credential_status,
  last_used_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ)
LANGUAGE sql SECURITY DEFINER SET search_path = scrutexity, public STABLE AS $$
  SELECT c.id, c.principal_type, c.principal_id, c.token_prefix, c.scopes,
         c.status, c.last_used_at, c.expires_at, c.revoked_at, c.created_at
  FROM scrutexity.api_credentials c
  WHERE c.organization_id = scrutexity.current_org_id()
  ORDER BY c.created_at DESC
  LIMIT 500
$$;
REVOKE ALL ON FUNCTION scrutexity.list_credentials() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scrutexity.list_credentials() TO scrutexity_app;

-- ---------------------------------------------------------------------------

-- Revocation takes effect on the next request: `authenticate` reads status on
-- every call and there is no credential cache to wait out.
CREATE OR REPLACE FUNCTION scrutexity.revoke_credential(p_id TEXT)
RETURNS TABLE (
  id TEXT, principal_type scrutexity.principal_type, principal_id TEXT,
  token_prefix TEXT, scopes TEXT[], status scrutexity.credential_status,
  last_used_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ)
LANGUAGE sql SECURITY DEFINER SET search_path = scrutexity, public AS $$
  UPDATE scrutexity.api_credentials c
     SET status = 'REVOKED', revoked_at = COALESCE(c.revoked_at, now())
   WHERE c.id = p_id
     AND c.organization_id = scrutexity.current_org_id()
  RETURNING c.id, c.principal_type, c.principal_id, c.token_prefix, c.scopes,
            c.status, c.last_used_at, c.expires_at, c.revoked_at, c.created_at
$$;
REVOKE ALL ON FUNCTION scrutexity.revoke_credential(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scrutexity.revoke_credential(TEXT) TO scrutexity_app;

-- ---------------------------------------------------------------------------

-- `last_used_at` has existed on this table since the first migration and has
-- never been written. Exposing it in the listing without populating it would be
-- worse than omitting it: an operator reading "never used" would conclude a
-- credential is safe to revoke, when it might be in constant use.
--
-- Called AFTER the token hash is verified, never before. Touching on a prefix
-- match alone would record a use for a credential someone presented the wrong
-- secret for -- which is both untrue and a signal that the prefix was real.
--
-- Coarse on purpose. Authentication happens on every request; a write per
-- request would put a row update in front of every authorization decision for a
-- field whose only question is "is this credential still in use". Five-minute
-- granularity answers that and lets the vast majority of calls match no row.
CREATE OR REPLACE FUNCTION scrutexity.touch_credential(p_id TEXT)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = scrutexity, public AS $$
  UPDATE scrutexity.api_credentials
     SET last_used_at = now()
   WHERE id = p_id
     AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')
$$;
REVOKE ALL ON FUNCTION scrutexity.touch_credential(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scrutexity.touch_credential(TEXT) TO scrutexity_app;
