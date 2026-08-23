-- ===========================================================================
-- 0011  A credential that never expires is not representable
-- ===========================================================================
--
-- `expires_at` was nullable, and NULL meant "until somebody revokes it". That
-- is an immortal bearer token, and it is the first thing a partner's security
-- team asks about. Documenting it would have been honest and would still have
-- been a negative mark; the gap is cheap to close, so it is closed here rather
-- than described.
--
-- The rule is enforced in three places on purpose, in decreasing order of how
-- much an attacker would have to already own to reach them:
--
--   the API schema      refuses a request with no expires_in_seconds
--   this function       refuses a lifetime outside the permitted range
--   these constraints   refuse the row itself, whatever wrote it
--
-- Only the last one holds against somebody with a database connection, which
-- is the reason it exists. The first two produce a good error message.
--
-- ## Why the database computes the timestamp
--
-- ADR-0017 makes `transaction_timestamp()` the authoritative instant for every
-- security judgement, because an API node with a skewed clock must not be able
-- to extend or shorten a credential. Expiry was already *checked* against
-- database time; it was *computed* from `Date.now()` on the API node, so a
-- node running two hours fast minted credentials that lived two hours longer
-- than they should have. The function now takes seconds and does the addition
-- itself, so both ends of the credential's life are measured by one clock.

SET search_path = scrutexity, public;

-- The maximum any credential may live. Ninety days is short enough that
-- rotation has to be a practised procedure rather than a plan, and long enough
-- that it is not a weekly interruption.
CREATE OR REPLACE FUNCTION scrutexity.max_credential_lifetime()
RETURNS INTERVAL LANGUAGE sql IMMUTABLE AS $$ SELECT INTERVAL '90 days' $$;

-- Existing rows predate the rule. They are given the maximum lifetime from
-- their own creation rather than from now, so a credential minted three months
-- ago is expired by this migration rather than silently renewed by it.
UPDATE api_credentials
   SET expires_at = created_at + scrutexity.max_credential_lifetime()
 WHERE expires_at IS NULL;

ALTER TABLE api_credentials ALTER COLUMN expires_at SET NOT NULL;

ALTER TABLE api_credentials
  ADD CONSTRAINT api_credentials_lifetime
  CHECK (
    expires_at > created_at
    AND expires_at <= created_at + scrutexity.max_credential_lifetime()
  );

-- ---------------------------------------------------------------------------

-- Replaced rather than altered: the argument list changes from a timestamp to
-- a duration, so the old signature must go or a caller could still reach it.
DROP FUNCTION IF EXISTS scrutexity.issue_credential(
  TEXT, TEXT, scrutexity.principal_type, TEXT, TEXT, BYTEA, TEXT[], TIMESTAMPTZ);

CREATE FUNCTION scrutexity.issue_credential(
  p_id                 TEXT,
  p_organization_id    TEXT,
  p_principal_type     scrutexity.principal_type,
  p_principal_id       TEXT,
  p_token_prefix       TEXT,
  p_token_hash         BYTEA,
  p_scopes             TEXT[],
  p_expires_in_seconds INTEGER
) RETURNS TABLE (
  id TEXT, principal_type scrutexity.principal_type, principal_id TEXT,
  token_prefix TEXT, scopes TEXT[], status scrutexity.credential_status,
  expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = scrutexity, public AS $$
DECLARE
  v_exists BOOLEAN;
  v_max    INTEGER := EXTRACT(EPOCH FROM scrutexity.max_credential_lifetime())::INTEGER;
BEGIN
  IF p_organization_id IS DISTINCT FROM scrutexity.current_org_id() THEN
    -- Not merely a permission failure. A caller reaching this has passed
    -- authentication and is asking to write into a tenant that is not theirs.
    RAISE EXCEPTION 'credential issuance outside the caller''s tenant'
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  -- `check_violation` rather than a generic error, so the route can map this
  -- to INVALID_CREDENTIAL_TTL and say what the rule is instead of returning a
  -- 500 for a caller who simply asked for too long.
  IF p_expires_in_seconds IS NULL THEN
    RAISE EXCEPTION 'a credential lifetime is required'
      USING ERRCODE = 'check_violation', CONSTRAINT = 'api_credentials_lifetime';
  END IF;
  IF p_expires_in_seconds < 60 OR p_expires_in_seconds > v_max THEN
    RAISE EXCEPTION 'credential lifetime % is outside 60..% seconds',
      p_expires_in_seconds, v_max
      USING ERRCODE = 'check_violation', CONSTRAINT = 'api_credentials_lifetime';
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
     token_prefix, token_hash, scopes, created_at, expires_at)
  VALUES
    (p_id, p_organization_id, p_principal_type, p_principal_id,
     p_token_prefix, p_token_hash, p_scopes,
     -- One clock for both ends of the credential's life. `created_at` is
     -- named explicitly rather than left to its default so that the CHECK
     -- comparing the two cannot be tripped by them landing on different
     -- statement timestamps.
     transaction_timestamp(),
     transaction_timestamp() + make_interval(secs => p_expires_in_seconds))
  RETURNING api_credentials.id, api_credentials.principal_type,
            api_credentials.principal_id, api_credentials.token_prefix,
            api_credentials.scopes, api_credentials.status,
            api_credentials.expires_at, api_credentials.created_at;
END;
$$;
REVOKE ALL ON FUNCTION scrutexity.issue_credential(
  TEXT, TEXT, scrutexity.principal_type, TEXT, TEXT, BYTEA, TEXT[], INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION scrutexity.issue_credential(
  TEXT, TEXT, scrutexity.principal_type, TEXT, TEXT, BYTEA, TEXT[], INTEGER) TO scrutexity_app;
