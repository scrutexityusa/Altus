SET search_path = scrutexity, public;

DROP FUNCTION IF EXISTS scrutexity.touch_credentials(TEXT[]);

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
