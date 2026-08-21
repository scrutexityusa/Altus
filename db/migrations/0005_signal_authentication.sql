-- =============================================================================
-- 0005 :: authenticated risk signals
--
-- A signal can shrink an agent's authority. An attacker who can forge one
-- cannot therefore grant themselves anything -- but they can suppress a
-- competitor's agent, or, more subtly, replay an old low-risk reading to
-- displace a current high-risk one. Both are attacks on availability and on
-- the accuracy of the risk picture, so signals are authenticated.
--
-- Ed25519 is the preferred algorithm: only a public key is stored, so a
-- database disclosure yields nothing an attacker can sign with. HMAC-SHA256 is
-- supported for sources that cannot manage a keypair, and its shared secret is
-- stored in this table.
--
-- HUMAN REVIEW: HMAC secrets are stored as-is. Before any deployment holding
-- real customer data, this column must be encrypted at rest with a key held
-- outside the database (KMS envelope encryption), or HMAC support dropped in
-- favour of Ed25519 only. Tracked in docs/sprint-plan.md.
-- =============================================================================
SET search_path = scrutexity, public;

CREATE TYPE signal_key_algorithm AS ENUM ('ED25519', 'HMAC_SHA256');
CREATE TYPE signal_key_status AS ENUM ('ACTIVE', 'RETIRING', 'REVOKED');

CREATE TABLE signal_signing_keys (
  id               TEXT PRIMARY KEY CHECK (id LIKE 'sigkey\_%'),
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  -- The signal source this key authenticates, e.g. "external_fraud_engine".
  source           TEXT NOT NULL,
  -- Caller-facing key identifier, carried in the signal envelope so the
  -- verifier knows which key to check without trial decryption.
  key_id           TEXT NOT NULL,
  algorithm        signal_key_algorithm NOT NULL,
  -- Ed25519: SPKI PEM public key. HMAC: the shared secret (see note above).
  key_material     TEXT NOT NULL,
  status           signal_key_status NOT NULL DEFAULT 'ACTIVE',
  -- Rotation window. A RETIRING key stays valid until not_after, which is the
  -- grace period that lets a source finish switching over without dropping
  -- signals on the floor.
  not_before       TIMESTAMPTZ NOT NULL DEFAULT now(),
  not_after        TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at       TIMESTAMPTZ,
  UNIQUE (organization_id, source, key_id),
  CONSTRAINT signal_signing_keys_window CHECK (not_after IS NULL OR not_after > not_before),
  CONSTRAINT signal_signing_keys_revoked_shape CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);
CREATE INDEX signal_signing_keys_lookup_idx
  ON signal_signing_keys (organization_id, source, key_id);
CREATE INDEX signal_signing_keys_active_idx
  ON signal_signing_keys (organization_id, source) WHERE status <> 'REVOKED';

ALTER TABLE risk_signals
  -- Source-assigned unique id for this observation. Two deliveries of the same
  -- event are the same event, however many times the network retries.
  ADD COLUMN event_id      TEXT,
  ADD COLUMN signature     TEXT,
  ADD COLUMN signing_key_id TEXT,
  -- False only for signals accepted from a source with no key configured,
  -- which policy may treat differently from an authenticated one.
  ADD COLUMN authenticated BOOLEAN NOT NULL DEFAULT false;

-- Replay prevention: a source cannot deliver the same event twice, and cannot
-- resurrect an old reading under a new timestamp without a new event id.
CREATE UNIQUE INDEX risk_signals_event_idx
  ON risk_signals (organization_id, source, event_id)
  WHERE event_id IS NOT NULL;

-- Security events: rejected signatures, replays, and other things an operator
-- should be able to see without reading application logs. Append-only, like
-- every other evidence table.
CREATE TABLE security_events (
  id               TEXT PRIMARY KEY CHECK (id LIKE 'sec\_%'),
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind             TEXT NOT NULL,
  source           TEXT,
  subject_id       TEXT,
  detail           JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX security_events_org_idx ON security_events (organization_id, created_at DESC);
CREATE INDEX security_events_kind_idx ON security_events (organization_id, kind, created_at DESC);
CREATE TRIGGER security_events_append_only
  BEFORE UPDATE OR DELETE ON security_events
  FOR EACH ROW EXECUTE FUNCTION scrutexity.deny_mutation();

-- Both new tables are tenant-scoped like everything else.
ALTER TABLE signal_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE signal_signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON signal_signing_keys
  USING (organization_id = scrutexity.current_org_id())
  WITH CHECK (organization_id = scrutexity.current_org_id());

ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON security_events
  USING (organization_id = scrutexity.current_org_id())
  WITH CHECK (organization_id = scrutexity.current_org_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON signal_signing_keys, security_events TO scrutexity_app;
