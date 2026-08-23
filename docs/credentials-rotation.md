# Credentials: lifetime and rotation

Every Altus credential expires. There is no value, anywhere in the API, that
means "never" — `expires_in_seconds` is required, and the maximum is **90 days**
(`7776000`).

That rule is enforced three times, in decreasing order of what an attacker
would have to already own to reach the layer:

| layer                                   | refuses                                         | holds against                       |
| --------------------------------------- | ----------------------------------------------- | ----------------------------------- |
| `IssueCredentialSchema`                 | a request with no lifetime, or one over the cap | a caller with a token               |
| `scrutexity.issue_credential()`         | a lifetime outside `60 .. 7776000` seconds      | a caller with the application role  |
| `api_credentials_lifetime` + `NOT NULL` | the row itself, whatever wrote it               | a caller with a database connection |

Only the last one matters in a compromise. The first two exist so an operator
following a runbook gets `INVALID_CREDENTIAL_TTL` and the rule, rather than a
constraint violation.

## Expired is not revoked

`credential_status` has exactly two values, `ACTIVE` and `REVOKED`. There is no
`EXPIRED`, and there is no job that writes one.

Expiry is **derived at every authentication**, comparing `expires_at` against
`transaction_timestamp()` on the same connection that read the row (ADR-0017).
A credential that lapsed a second ago fails the next request with no sweeper
having run, and an API node with a skewed clock cannot keep it alive or kill it
early. The same clock stamps `expires_at` at issuance, so both ends of a
credential's life are measured by one authority.

The two facts stay distinguishable in `GET /v1/credentials`:

|         | `status`  | `revoked_at` | `expires_at`  |
| ------- | --------- | ------------ | ------------- |
| live    | `ACTIVE`  | `null`       | in the future |
| lapsed  | `ACTIVE`  | `null`       | in the past   |
| revoked | `REVOKED` | set          | either        |

An operator answering "why did this stop working" needs to tell "nobody rotated
it" apart from "somebody pulled it", and a single collapsed status could not.

## Rotating a credential

No downtime, no coordination window. Issue the new one, cut over, revoke the
old one. Both are valid in between, which is the whole point.

```bash
# 1. Issue the replacement. Same principal, same scopes, new secret.
NEW=$(curl -sS -X POST $ALTUS/v1/credentials \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"principal_type":"agent","principal_id":"payments-agent",
       "scopes":["read","authorization:evaluate"],
       "expires_in_seconds":7776000}')

echo "$NEW" | jq -r .token          # the secret, shown exactly once
NEW_ID=$(echo "$NEW" | jq -r .credential.id)

# 2. Deploy it. Both credentials work; nothing is racing.

# 3. Confirm the new one is actually carrying traffic before you cut the old.
curl -sS $ALTUS/v1/credentials -H "authorization: Bearer $ADMIN" \
  | jq -r '.credentials[] | select(.principal_id=="payments-agent")
           | [.id, .status, .last_used_at, .expires_at] | @tsv'

# 4. Revoke the old one. Effective on its next request -- there is no cache.
curl -sS -X POST $ALTUS/v1/credentials/$OLD_ID/revoke \
  -H "authorization: Bearer $ADMIN" | jq -c '.credential | {status, revoked_at}'
```

Step 3 is the one people skip. `last_used_at` is written on every successful
authentication (coarsened to five minutes, so it is not a row update in front
of every request), and it is how you tell that the deploy in step 2 actually
took. Revoking on faith is how a rotation becomes an incident.

## Deciding what to rotate

```bash
curl -sS $ALTUS/v1/credentials -H "authorization: Bearer $ADMIN" \
  | jq -r '.credentials[]
           | select(.status=="ACTIVE")
           | [.id, .principal_type, .principal_id, .expires_at, .last_used_at]
           | @tsv' | sort -k4
```

Two things worth acting on in that listing:

- **Expiring soonest first.** Rotate on your schedule rather than at 3am.
- **`last_used_at` null or stale.** A credential nothing has used is a
  credential nothing will miss. Revoke it; if that was wrong, issuing another
  takes fifteen seconds and now you know what it was for.

## The bootstrap credential

`altus bootstrap` mints one credential outside the API, using the database
owner connection. It lives **seven days**, and it is the one credential in the
estate the estate cannot account for — no named issuer, no request record.

Onboarding spends it in under a minute: it can provision, and it deliberately
cannot act (no `authorization:evaluate`, no `approvals:write`, no
`signals:write`). The last step of onboarding revokes it.

**If the seven days lapse before you issued a working credential**, you are
locked out: re-running the ceremony is refused by the `installation` primary
key, by design. Recovery needs the owner connection again — the same access the
ceremony required in the first place:

1. Read the installation row to find the tenant and its administrator:

   ```sql
   SELECT organization_id, admin_user_id, bootstrapped_at FROM scrutexity.installation;
   ```

2. Mint a replacement credential for that user. The token format is
   `scr_<16 hex prefix>.<secret>`, and the stored `token_hash` is a SHA-256 of
   the **whole** token string — see `issueToken()` and `hashToken()` in
   `services/api/src/auth.ts`. Generating it by hand is error-prone; write a
   short script that imports those two functions rather than reimplementing
   them, and insert with the same shape `scripts/bootstrap.ts` uses.

Treat this as an incident to write down, not a routine. Making the path
convenient would be worse than making the window survive a weekend, which is
why it is documented here rather than exposed as a command.

## What this is not

Bearer credentials are the interim mechanism. They are hashed at rest
(SHA-256, compared in constant time against a dummy hash so a missing prefix
and a wrong secret take the same time), scoped, revocable, expiring, and
attributable to a named principal — and they are still a shared secret that a
human copies into a deployment system.

The direction is workload identity federation, so that an agent proves what it
is rather than what it holds. See ADR-0019. Nothing is built against it yet,
because it needs a partner's identity provider to be built against and no
partner has named one.
