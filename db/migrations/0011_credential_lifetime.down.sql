SET search_path = scrutexity, public;

DROP FUNCTION IF EXISTS scrutexity.issue_credential(
  TEXT, TEXT, scrutexity.principal_type, TEXT, TEXT, BYTEA, TEXT[], INTEGER);

ALTER TABLE api_credentials DROP CONSTRAINT IF EXISTS api_credentials_lifetime;
ALTER TABLE api_credentials ALTER COLUMN expires_at DROP NOT NULL;

DROP FUNCTION IF EXISTS scrutexity.max_credential_lifetime();

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
    RAISE EXCEPTION 'credential issuance outside the caller''s tenant'
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  IF p_principal_type = 'user' THEN
    SELECT EXISTS (SELECT 1 FROM scrutexity.users u WHERE u.id = p_principal_id)
      INTO v_exists;
  ELSIF p_principal_type = 'agent' THEN
    SELECT EXISTS (SELECT 1 FROM scrutexity.agents a WHERE a.id = p_principal_id)
      INTO v_exists;
  ELSE
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
