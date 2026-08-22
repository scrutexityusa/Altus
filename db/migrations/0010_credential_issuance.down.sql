SET search_path = scrutexity, public;

DROP FUNCTION IF EXISTS scrutexity.touch_credential(TEXT);
DROP FUNCTION IF EXISTS scrutexity.revoke_credential(TEXT);
DROP FUNCTION IF EXISTS scrutexity.list_credentials();
DROP FUNCTION IF EXISTS scrutexity.issue_credential(
  TEXT, TEXT, scrutexity.principal_type, TEXT, TEXT, BYTEA, TEXT[], TIMESTAMPTZ);
ALTER TABLE api_credentials DROP CONSTRAINT IF EXISTS api_credentials_revoked_shape;
ALTER TABLE api_credentials DROP COLUMN IF EXISTS revoked_at;
