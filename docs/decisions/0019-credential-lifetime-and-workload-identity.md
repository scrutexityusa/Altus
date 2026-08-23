# ADR-0019: Every credential expires, and bearer tokens are the interim mechanism

**Status:** Accepted
**Date:** 2026-08-23

## Context

`api_credentials.expires_at` was nullable, and NULL meant "until somebody
revokes it". `expires_in_seconds` was optional on `POST /v1/credentials`, so
the default credential — the one a partner gets by following the shortest path
through the API — was immortal.

Nothing was wrong with the rest of the mechanism. Tokens are SHA-256 hashed at
rest and compared in constant time against a dummy hash, so a missing prefix
and a wrong secret take the same time. Credentials carry scopes, name a
principal, record last use, and revoke with effect on the next request. The
expiry check already read database time rather than the API node's clock.

The gap was that the strongest link had an off switch, and the off switch was
the default.

It also had a smaller sibling: `expires_at` was **checked** against
`transaction_timestamp()` but **computed** from `Date.now()` on the API node,
so a node running two hours fast minted credentials that lived two hours longer
than were asked for. One end of a credential's life was measured by an
authority the other end did not trust.

Meanwhile the direction everyone points at for machine credentials is
federation — OIDC workload identity, SPIFFE — where an agent proves what it is
rather than what it holds. Building that now would mean building against an
identity provider no partner has named.

## Decision

**A credential with no expiry is not representable.** `expires_in_seconds` is
required, bounded to `60 .. 7776000` seconds, and enforced at three layers:
the request schema, `scrutexity.issue_credential()`, and a `NOT NULL` column
with a `CHECK` against `scrutexity.max_credential_lifetime()`. Only the last
holds against a caller with a database connection; the first two exist to
produce `INVALID_CREDENTIAL_TTL` and state the rule.

**The database computes the expiry.** `issue_credential` takes seconds and does
the addition with `transaction_timestamp()`, stamping `created_at` explicitly
from the same call. Both ends of a credential's life are now measured by the
clock ADR-0017 made authoritative.

**`EXPIRED` is not a stored status.** `credential_status` keeps exactly
`ACTIVE` and `REVOKED`. Lapsing is derived at every authentication from
database time against `expires_at`, so there is no sweeper to fall behind and
no window in which a lapsed credential is still `ACTIVE` in the eyes of the
authenticator. It also keeps two different operator facts distinguishable:
"nobody rotated it" and "somebody pulled it".

**The bootstrap credential lives seven days.** It is minted outside the API by
a process holding the owner connection, so it is the one credential the estate
cannot account for. Onboarding spends it in under a minute and revokes it at
the end; the fixed lifetime is for the installation that is bootstrapped on a
Friday and forgotten.

**Bearer credentials remain the interim mechanism, and workload identity
federation is the stated direction.** Nothing is built for it here. When a
partner names an identity provider, the shape is: a short-lived Altus
credential minted in exchange for a verified workload assertion (an OIDC ID
token from the partner's IdP, or a SPIFFE SVID), with the scopes derived from
the workload's identity rather than chosen by whoever ran the curl.

## Consequences

- Every existing credential is now on a clock. Migration 0011 backfills
  `expires_at` as `created_at + 90 days`, so a credential minted three months
  ago is expired by the migration rather than silently renewed by it.
- Rotation has to be a practised procedure. `docs/credentials-rotation.md` has
  it: issue, deploy, confirm `last_used_at` moved, revoke. Overlapping validity
  means no downtime and no coordination window.
- An operator whose bootstrap window lapses before issuing a working credential
  is locked out and needs the owner connection again. This is deliberate. The
  recovery is documented, not exposed as a command, because a convenient path
  to minting an unaccountable administrative credential is the thing the
  ceremony exists to avoid.
- Ninety days is not a number anybody negotiated. It is short enough to force
  the procedure and long enough not to be a weekly interruption. A partner with
  a shorter standard can set a shorter lifetime per credential; there is no way
  to set a longer one.
- This does not close the shared-secret problem. A bearer token is still
  something a human copies into a deployment system. That is what ADR-0019's
  federation direction is for, and it stays unbuilt until there is an IdP to
  build against.
