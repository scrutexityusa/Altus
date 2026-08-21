# ADR-0005 — Enforce tenant isolation in PostgreSQL with FORCE ROW LEVEL SECURITY

**Status** Accepted · 2026-08-21

## Problem

"Never allow cross-tenant authorization evaluation." Application-layer scoping
holds until one handler forgets a `WHERE organization_id = $1`.

## Decision

Defence in depth, with the database as the layer that does not forget.

1. The tenant is derived from the authenticated credential. There is no tenant
   header and no tenant field in any body.
2. Every request runs in a transaction that begins with
   `SET LOCAL scrutexity.org_id`.
3. Every tenant table has `FORCE ROW LEVEL SECURITY` with a policy keyed on
   that setting. A query that forgets its tenant sees zero rows and writes
   nothing — the default posture of an unscoped connection is "no data".
4. The API connects as `scrutexity_app`, which is **not** the table owner, so
   the owner's implicit bypass does not apply.
5. The org id is validated against a strict pattern before `set_config`.

## The exception, and why it is one

`api_credentials` cannot be tenant-scoped: authentication is what _resolves_
the tenant. It is handled differently — RLS enabled but not forced, the
application role granted **no privileges on the table at all**, and the only
access path a single-row prefix probe through a `SECURITY DEFINER` function.

This was found the hard way. `SECURITY DEFINER` does **not** escape `FORCE ROW
LEVEL SECURITY`: forcing that table made authentication itself impossible,
because the definer's own query saw zero rows. The trap is recorded in
`db/migrations/0002_rls.sql` so nobody re-adds the table to the forced list.

## Evidence

`services/api/test/security.test.ts` connects directly as `scrutexity_app` with
tenant A set and confirms tenant B's rows are invisible — testing the database
guarantee itself, not the application's use of it.

## Consequences

Every code path must go through `withTenant`. Platform operations that
legitimately span tenants use the owner connection explicitly, which is
auditable precisely because it is unusual.
