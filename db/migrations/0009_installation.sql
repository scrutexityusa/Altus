-- Installation state: has this deployment been bootstrapped?
--
-- Bootstrap creates the first organization, the first administrator and the
-- first credential. It is an installation ceremony run once against the owner
-- connection, not an API capability -- so "has it already run" is a property of
-- the *installation*, not of any tenant.
--
-- That distinction is why this table exists rather than a count over
-- organizations. `organizations` has FORCE ROW LEVEL SECURITY with
-- `USING (id = current_org_id())`, so a count taken before a tenant is known
-- returns zero whether or not organizations exist. A guard written that way
-- passes silently on an already-bootstrapped installation and then fails on a
-- unique index -- or worse, succeeds, because a second organization with a
-- different name has a different slug. The check has to be something RLS
-- cannot filter.
--
-- So the invariant is enforced by the shape of the table instead of by a query:
-- the primary key is a boolean constrained to true, which permits exactly one
-- row, ever. A second bootstrap is a primary key violation inside the same
-- transaction that would have created the tenant. There is no window and no
-- read to get wrong.

SET search_path = scrutexity, public;

CREATE TABLE installation (
  -- Exactly one row. `true` is the only value the CHECK admits and the primary
  -- key admits it once.
  singleton        BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
  organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  admin_user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  bootstrapped_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Free-form: the version that ran the ceremony, who ran it, anything an
  -- operator wants to find later. Never secret material.
  metadata         JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- ON DELETE RESTRICT above, deliberately. Deleting the bootstrap organization
-- would otherwise cascade this row away and make a second bootstrap possible,
-- turning tenant deletion into a way to re-acquire an administrative
-- credential.

-- Row level security is enabled but NOT forced, and the application role is
-- granted nothing at all -- the same treatment as api_credentials, for the same
-- reason. This is installation state that exists before any tenant is
-- resolved, so it cannot be tenant-scoped; and since nothing in the request
-- path ever reads it, the application role has no reason to reach it.
ALTER TABLE installation ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON installation FROM scrutexity_app;
