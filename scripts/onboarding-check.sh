#!/usr/bin/env bash
#
# Runs the onboarding guide the way a stranger would.
#
# `docs/design-partner/onboarding.md` is the first thing a design partner
# touches, and it is the only artefact here that no test covered: the suite
# exercises the *endpoints* through an in-process harness, which is exactly why
# it never noticed that `pnpm altus bootstrap --json > bootstrap.json` writes
# pnpm's own run banner to stdout ahead of the JSON, so every `jq -r .token`
# after it failed with "Invalid numeric literal". The guide was broken from
# step 2 onward and 609 passing tests said nothing.
#
# So this runs the commands as written -- shell, curl, jq, a real server on a
# real port -- and fails if any of them does. It is deliberately not a
# rewriting of the guide into something more testable: the point is that the
# text a partner copies is the text that runs.
#
# The counterpart is `docs/design-partner/cold-room-transcript.md`, which is a
# human account of doing this by hand. That is still worth having, and it is
# no longer the only thing standing between a broken guide and a partner.

set -euo pipefail

ADMIN_URL="${DATABASE_ADMIN_URL:-postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity}"
APP_URL="${DATABASE_URL:-postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity}"
PORT="${ONBOARDING_PORT:-8099}"
ALTUS="http://127.0.0.1:${PORT}"
WORK="$(mktemp -d)"
API_PID=""

cleanup() {
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '  %s\n' "$1"; }
fail() { printf '\n  FAILED: %s\n\n' "$1" >&2; exit 1; }

printf '\nONBOARDING GUIDE -- run as written\n\n'

# -- 1. Schema --------------------------------------------------------------
step '1. applying the schema'
DATABASE_ADMIN_URL="$ADMIN_URL" pnpm exec tsx scripts/migrate.ts --reset >/dev/null \
  || fail 'migrations'

# -- 2. The installation ceremony -------------------------------------------
#
# `--silent` is the assertion, not decoration. Without it this file is not JSON
# and every step below it fails. Do not "fix" a failure here by piping through
# tail or grep: the guide tells a partner to run exactly this.
step '2. installation ceremony'
ALTUS_BOOTSTRAP_DATABASE_URL="$ADMIN_URL" \
  pnpm --silent altus bootstrap \
    --org-name    "Example Treasury" \
    --admin-name  "Jane Smith" \
    --admin-email "jane@example.com" \
    --json > "$WORK/bootstrap.json" || fail 'bootstrap'

BOOTSTRAP=$(jq -er .token "$WORK/bootstrap.json") \
  || fail 'bootstrap.json is not parseable JSON -- pnpm banner on stdout?'
ADMIN_USER_ID=$(jq -er .admin_user_id "$WORK/bootstrap.json")
BOOTSTRAP_CRED_ID=$(jq -er .credential_id "$WORK/bootstrap.json")

DATABASE_URL="$APP_URL" PORT="$PORT" pnpm exec tsx services/api/src/server.ts \
  > "$WORK/api.log" 2>&1 &
API_PID=$!

for _ in $(seq 1 30); do
  curl -sS "$ALTUS/ready" >/dev/null 2>&1 && break
  sleep 1
done
curl -sSf "$ALTUS/ready" >/dev/null || { cat "$WORK/api.log" >&2; fail 'the API never became ready'; }

# -- 3. The administrator's role and working credential ---------------------
step '3. administrator role and working credential'
curl -sS -X PATCH "$ALTUS/v1/users/$ADMIN_USER_ID" \
  -H "authorization: Bearer $BOOTSTRAP" -H 'content-type: application/json' \
  -d '{"roles":["admin","policy_author","treasury_admin"]}' | jq -e .user.roles >/dev/null \
  || fail 'assigning treasury_admin'

ADMIN=$(curl -sS -X POST "$ALTUS/v1/credentials" \
  -H "authorization: Bearer $BOOTSTRAP" -H 'content-type: application/json' \
  -d "{\"principal_type\":\"user\",\"principal_id\":\"$ADMIN_USER_ID\",
       \"scopes\":[\"read\",\"audit:read\",\"admin:write\",\"leases:write\",\"policies:write\"],
       \"expires_in_seconds\":7776000}" | jq -er .token) \
  || fail 'issuing the working credential'

# -- 4. Two reviewers who are not the author --------------------------------
step '4. two reviewers'
create_human() {
  local uid
  uid=$(curl -sS -X POST "$ALTUS/v1/users" \
    -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"display_name\":\"$2\",\"roles\":[\"$3\"]}" | jq -er .user.id) || return 1
  curl -sS -X POST "$ALTUS/v1/credentials" \
    -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
    -d "{\"principal_type\":\"user\",\"principal_id\":\"$uid\",\"scopes\":$4,
         \"expires_in_seconds\":7776000}" | jq -er .token
}
REVIEWER_ONE=$(create_human reviewer.one@example.com "Reviewer One" policy_reviewer \
  '["read","policies:write"]') || fail 'reviewer one'
REVIEWER_TWO=$(create_human reviewer.two@example.com "Reviewer Two" policy_reviewer \
  '["read","policies:write"]') || fail 'reviewer two'

# -- 5. Accounts and counterparties -----------------------------------------
step '5. accounts and counterparties'
curl -sS -X POST "$ALTUS/v1/resources" -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"resource_type":"bank_account","external_id":"acct_001",
       "display_name":"Operating Account","attributes":{"currency":"USD","region":"US"}}' \
  | jq -e .resource >/dev/null || fail 'registering the account'
curl -sS -X POST "$ALTUS/v1/resources" -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"resource_type":"counterparty","external_id":"cp_100",
       "display_name":"Supplier Ltd","attributes":{"status":"VERIFIED","country":"US"}}' \
  | jq -e .resource >/dev/null || fail 'registering the counterparty'

# -- 6. Policy through its real lifecycle -----------------------------------
step '6. policy: draft, two reviews, activate'
VERSION=$(curl -sS -X POST "$ALTUS/v1/policy-versions" -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d "$(jq -Rs '{document: .}' < policies/treasury-wire.yaml)" | jq -er .policy_version.id) \
  || fail 'uploading the policy'
for T in "$REVIEWER_ONE" "$REVIEWER_TWO"; do
  curl -sS -X POST "$ALTUS/v1/policy-versions/$VERSION/reviews" \
    -H "authorization: Bearer $T" -H 'content-type: application/json' \
    -d '{"vote":"APPROVED","comment":"Matches our approval matrix."}' \
    | jq -e .status >/dev/null || fail 'policy review'
done
STATUS=$(curl -sS -X POST "$ALTUS/v1/policy-versions/$VERSION/activate" \
  -H "authorization: Bearer $ADMIN" | jq -er .policy_version.status)
[ "$STATUS" = ACTIVE ] || fail "policy did not activate (status $STATUS)"

# -- 7. The agent -----------------------------------------------------------
step '7. agent and its credential'
curl -sS -X POST "$ALTUS/v1/agents" -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d "{\"handle\":\"payments-agent\",\"display_name\":\"Payments Agent\",
       \"owner_user_id\":\"$ADMIN_USER_ID\"}" | jq -e .agent >/dev/null || fail 'creating the agent'
AGENT=$(curl -sS -X POST "$ALTUS/v1/credentials" -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"principal_type":"agent","principal_id":"payments-agent",
       "scopes":["read","authorization:evaluate"],
       "expires_in_seconds":7776000}' | jq -er .token) || fail 'agent credential'

# -- 8. Authority -----------------------------------------------------------
step '8. authority'
curl -sS -X POST "$ALTUS/v1/authority-leases" -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"agent_id":"payments-agent",
       "grant":{"actions":["wire.execute"],
                "resources":{"bank_account":["acct_001"],"counterparty":["cp_100"]},
                "constraints":{"max_amount":{"currency":"USD","amountMinor":"5000000"},
                               "currencies":["USD"],"allowed_counterparties":["cp_100"]}},
       "ttl_seconds":3600,"grant_type":"SINGLE_USE"}' \
  | jq -e .authority_lease.id >/dev/null || fail 'issuing authority'

# -- 9. One governed execution ----------------------------------------------
step '9. one governed execution'
DECISION=$(curl -sS -X POST "$ALTUS/v1/authorization/evaluate" \
  -H "authorization: Bearer $AGENT" -H 'content-type: application/json' \
  -d '{"agent_id":"payments-agent","action":"wire.execute",
       "resource":{"type":"bank_account","id":"acct_001"},
       "context":{"amount":"25000.00","currency":"USD",
                  "counterparty_id":"cp_100","destination_country":"US"},
       "nonce":"first-real-request"}')
[ "$(echo "$DECISION" | jq -r .decision)" = ALLOW ] \
  || fail "expected ALLOW, got $(echo "$DECISION" | jq -c '{decision,reason_code}')"
DECISION_ID=$(echo "$DECISION" | jq -er .decision_id)

EXECUTION=$(curl -sS -X POST "$ALTUS/v1/execute" \
  -H "authorization: Bearer $AGENT" -H 'content-type: application/json' \
  -d "{\"decision_id\":\"$DECISION_ID\",
       \"operation\":{\"action\":\"wire.execute\",
         \"resource\":{\"type\":\"bank_account\",\"id\":\"acct_001\"},
         \"context\":{\"amount\":\"25000.00\",\"currency\":\"USD\",
                      \"counterparty_id\":\"cp_100\",\"destination_country\":\"US\"}}}")
[ "$(echo "$EXECUTION" | jq -r .status)" = EXECUTED ] \
  || fail "execution did not succeed: $(echo "$EXECUTION" | jq -c .)"
RECEIPT_ID=$(echo "$EXECUTION" | jq -er .receipt_id)

# -- 10. Evidence -----------------------------------------------------------
step '10. evidence'
INTEGRITY=$(curl -sS -X POST "$ALTUS/v1/receipts/$RECEIPT_ID/verify" \
  -H "authorization: Bearer $ADMIN" | jq -er .integrity)
[ "$INTEGRITY" = INTACT ] || fail "receipt verification returned $INTEGRITY"
COMPLETE=$(curl -sS "$ALTUS/v1/trace/$DECISION_ID" -H "authorization: Bearer $ADMIN" \
  | jq -er .complete)
[ "$COMPLETE" = true ] || fail 'the causal trace does not reach a human decision'

# -- 11. Retire the ceremony credential -------------------------------------
step '11. retire the ceremony credential'
REVOKED=$(curl -sS -X POST "$ALTUS/v1/credentials/$BOOTSTRAP_CRED_ID/revoke" \
  -H "authorization: Bearer $ADMIN" | jq -er .credential.status)
[ "$REVOKED" = REVOKED ] || fail "revocation returned $REVOKED"
curl -sS -o /dev/null -w '%{http_code}' "$ALTUS/v1/agents" \
  -H "authorization: Bearer $BOOTSTRAP" | grep -q 401 \
  || fail 'the revoked ceremony credential still authenticates'

printf '\n  THE GUIDE RUNS AS WRITTEN: 11 steps, bootstrap through revocation\n\n'
