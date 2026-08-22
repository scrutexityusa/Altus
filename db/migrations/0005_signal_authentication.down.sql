-- Reverses 0005. Rolling back removes signal authentication entirely: any
-- caller holding the signals:write scope can assert any risk value again.
SET search_path = scrutexity, public;

DROP TABLE IF EXISTS security_events;
DROP INDEX IF EXISTS risk_signals_event_idx;

ALTER TABLE risk_signals
  DROP COLUMN IF EXISTS authenticated,
  DROP COLUMN IF EXISTS signing_key_id,
  DROP COLUMN IF EXISTS signature,
  DROP COLUMN IF EXISTS event_id;

DROP TABLE IF EXISTS signal_signing_keys;
DROP TYPE IF EXISTS signal_key_status;
DROP TYPE IF EXISTS signal_key_algorithm;
