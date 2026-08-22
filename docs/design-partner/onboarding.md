# Onboarding: your tenant, from an empty database

**Time: about 30 minutes. No source edits, no database client, no fixture
credentials.**

Every command below is copy-pasteable and was run against a live server before
being written down. When you finish, the organization, the people, the accounts
and the counterparties are yours — the word "Acme" appears nowhere.

---

## Before you start: the minimum set of humans

**You need three people, not one.** This surprises everyone, so it is the first
thing on the page rather than something you discover through a denial.

| Person               | Role                           | Why                                            |
| -------------------- | ------------------------------ | ---------------------------------------------- |
| 1. **Administrator** | `admin`, plus `treasury_admin` | Provisions everything. Authors the policy.     |
| 2. **Reviewer**      | `policy_reviewer`              | Approves the policy. **Cannot be the author.** |
| 3. **Reviewer**      | `policy_reviewer`              | Second approval. Also not the author.          |

Activating a policy requires **two approvals from humans who did not write it**.
That is dual control and it is deliberate — the author of a policy may not
approve it, and there is no flag to turn that off.

In a real deployment these are three real people. For a pilot they can be three
accounts one person holds credentials for; the system records who approved what
either way.

**A fourth thing to know up front:** the bootstrap administrator holds the
`admin` role, and the starter policy's issuance ceilings name `treasury_admin`.
A role the policy does not name may issue **nothing**, so until you assign
`treasury_admin` to whoever issues authority, they will hold `leases:write` and
still be refused. That is the correct fail-closed direction, and step 3 below
does the assignment.

---

## 1. Start the database and apply the schema

```bash
git clone <repo> && cd Altus
pnpm install

docker compose up -d          # PostgreSQL 16 on 127.0.0.1:5432
pnpm altus migrate
```

**Pointing at a PostgreSQL you already run.** Every command takes its
connection from the environment, and the defaults assume the compose database.
For anything else, set both — the owner connection applies migrations, the
application connection is what the service runs as and is subject to row level
security:

```bash
export DATABASE_ADMIN_URL=postgres://owner:pass@your-host:5432/your-db
export DATABASE_URL=postgres://app:pass@your-host:5432/your-db
```

The application role must **not** be the table owner. RLS is FORCEd and the
owner bypasses it, so tenant isolation depends on the service connecting as
someone else. `db/init/00-roles.sql` creates both roles.

## 2. The installation ceremony

```bash
ALTUS_BOOTSTRAP_DATABASE_URL=postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity \
  pnpm altus bootstrap \
    --org-name  "Example Treasury" \
    --admin-name  "Jane Smith" \
    --admin-email "jane@example.com"
```

This creates your organization, your first administrator, and one credential.
It is the **only** step that uses the database owner connection, it runs once,
and it refuses to run again — the installation is marked in a table whose
primary key permits exactly one row.

The token is printed once and cannot be recovered. Save it:

```bash
export ALTUS=http://127.0.0.1:8080
export BOOTSTRAP=scr_...          # from the output above
```

Start the API in another terminal:

```bash
pnpm altus migrate && pnpm exec tsx services/api/src/server.ts
```

**What this credential can and cannot do.** It provisions: `admin:write`,
`leases:write`, `policies:write`, `read`, `audit:read`. It deliberately cannot
evaluate authorizations, approve payments, or ingest signals. The ceremony
establishes ownership and administration; it does not become the thing used for
governed actions.

## 3. Give the administrator the role that can issue authority

```bash
# Your own user id is in the bootstrap output.
curl -sS -X PATCH $ALTUS/v1/users/user_... \
  -H "authorization: Bearer $BOOTSTRAP" -H 'content-type: application/json' \
  -d '{"roles":["admin","policy_author","treasury_admin"]}' | jq
```

Then issue yourself a working credential and stop using the bootstrap one:

```bash
export ADMIN=$(curl -sS -X POST $ALTUS/v1/credentials \
  -H "authorization: Bearer $BOOTSTRAP" -H 'content-type: application/json' \
  -d '{"principal_type":"user","principal_id":"user_...",
       "scopes":["read","audit:read","admin:write","leases:write","policies:write"]}' \
  | jq -r .token)
```

## 4. Create the two reviewers

```bash
for N in one two; do
  UID=$(curl -sS -X POST $ALTUS/v1/users \
    -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
    -d "{\"email\":\"reviewer.$N@example.com\",\"display_name\":\"Reviewer $N\",
         \"roles\":[\"policy_reviewer\"]}" | jq -r .user.id)
  curl -sS -X POST $ALTUS/v1/credentials \
    -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
    -d "{\"principal_type\":\"user\",\"principal_id\":\"$UID\",
         \"scopes\":[\"read\",\"policies:write\"]}" | jq -r '.token'
done
```

Save both tokens as `$REVIEWER_ONE` and `$REVIEWER_TWO`. Each is shown once.

## 5. Register your accounts and counterparties

**This is the step that decides whether real payments work.**
`counterparty_known` is derived from the _existence_ of a row here and never
from anything a caller asserts — so an unregistered counterparty produces
`DENY / UNKNOWN_COUNTERPARTY` on every wire, no matter how valid the rest of the
request is. Registering a counterparty is the act that makes money movable to it.

```bash
curl -sS -X POST $ALTUS/v1/resources \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"resource_type":"bank_account","external_id":"acct_001",
       "display_name":"Operating Account — USD",
       "attributes":{"currency":"USD","region":"US"}}' | jq -c .resource

curl -sS -X POST $ALTUS/v1/resources \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"resource_type":"counterparty","external_id":"cp_100",
       "display_name":"Your Actual Supplier Ltd",
       "attributes":{"status":"VERIFIED","country":"US"}}' | jq -c .resource
```

An agent cannot do this. If it could, it could authorise its own destination.

## 6. Author, review and activate your policy

Copy `policies/treasury-wire.yaml`, change the values marked `CHANGE ME` — your
thresholds, your accounts, your counterparties, your approval roles — and put it
through your own code review first. Then:

```bash
VERSION=$(curl -sS -X POST $ALTUS/v1/policy-versions \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d "$(jq -Rs '{document: .}' < policies/treasury-wire.yaml)" \
  | jq -r .policy_version.id)

# Two approvals, from the two reviewers. Not from the author.
for T in $REVIEWER_ONE $REVIEWER_TWO; do
  curl -sS -X POST $ALTUS/v1/policy-versions/$VERSION/reviews \
    -H "authorization: Bearer $T" -H 'content-type: application/json' \
    -d '{"vote":"APPROVED","comment":"Matches our approval matrix."}' | jq -c
done

curl -sS -X POST $ALTUS/v1/policy-versions/$VERSION/activate \
  -H "authorization: Bearer $ADMIN" | jq -c .policy_version
```

The first review moves the version to `REVIEW`; the second moves it to
`APPROVED`. Only then can it be activated. If you try to review your own
version you get a `403`, which is the control working.

**Your issuance ceilings must name your roles and your resources.** The starter
pack's ceilings list `treasury_admin` with example accounts and counterparties.
A lease that mentions anything outside them is refused with
`DELEGATION_EXCEEDS_PARENT` _before_ it is issued — so edit the ceilings in the
same pass as the thresholds.

## 7. Register your agent and give it a credential

```bash
curl -sS -X POST $ALTUS/v1/agents \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"handle":"payments-agent","display_name":"Payments Agent",
       "owner_user_id":"user_..."}' | jq -c .agent

export AGENT=$(curl -sS -X POST $ALTUS/v1/credentials \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"principal_type":"agent","principal_id":"payments-agent",
       "scopes":["read","authorization:evaluate"]}' | jq -r .token)
```

Every agent has a named human owner. When you later ask who authorised
something, that is where the answer starts.

## 8. Issue authority

```bash
curl -sS -X POST $ALTUS/v1/authority-leases \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"agent_id":"payments-agent",
       "grant":{
         "actions":["wire.execute"],
         "resources":{"bank_account":["acct_001"],"counterparty":["cp_100"]},
         "constraints":{
           "max_amount":{"currency":"USD","amountMinor":"5000000"},
           "currencies":["USD"],
           "allowed_counterparties":["cp_100"]}},
       "ttl_seconds":3600,
       "grant_type":"SINGLE_USE"}' | jq -c .authority_lease
```

`"5000000"` is $50,000.00 — money is integer minor units as a string, and floats
are refused.

## 9. One governed execution

```bash
DECISION=$(curl -sS -X POST $ALTUS/v1/authorization/evaluate \
  -H "authorization: Bearer $AGENT" -H 'content-type: application/json' \
  -d '{"agent_id":"payments-agent","action":"wire.execute",
       "resource":{"type":"bank_account","id":"acct_001"},
       "context":{"amount":"25000.00","currency":"USD",
                  "counterparty_id":"cp_100","destination_country":"US"},
       "nonce":"first-real-request"}')
echo "$DECISION" | jq -c '{decision,reason_code}'

curl -sS -X POST $ALTUS/v1/execute \
  -H "authorization: Bearer $AGENT" -H 'content-type: application/json' \
  -d "{\"decision_id\":\"$(echo "$DECISION" | jq -r .decision_id)\",
       \"operation\":{\"action\":\"wire.execute\",
         \"resource\":{\"type\":\"bank_account\",\"id\":\"acct_001\"},
         \"context\":{\"amount\":\"25000.00\",\"currency\":\"USD\",
                      \"counterparty_id\":\"cp_100\",\"destination_country\":\"US\"}}}" \
  | jq -c '{status,provider,intent_verified}'
```

## 10. Verify the evidence

```bash
curl -sS -X POST $ALTUS/v1/receipts/rcpt_.../verify \
  -H "authorization: Bearer $ADMIN" | jq -c '{integrity,attests}'

curl -sS $ALTUS/v1/trace/dec_... -H "authorization: Bearer $ADMIN" \
  | jq -c '{root_cause:.root_cause.name, steps:(.trace|length), complete}'
```

---

## The order, and why it is this order

```
  altus migrate                 schema
        │
  altus bootstrap               organization + first administrator
        │                       (owner connection, once, never again)
        ▼
  PATCH  /v1/users/{id}         give the administrator treasury_admin
  POST   /v1/credentials        issue yourself a working credential
        │
  POST   /v1/users        ×2    the two reviewers
  POST   /v1/credentials  ×2    their tokens
        │
  POST   /v1/resources          accounts and counterparties
        │                       ← without this, every wire is DENY
        ▼
  POST   /v1/policy-versions    author
  POST   .../reviews      ×2    two humans who are not the author
  POST   .../activate
        │
  POST   /v1/agents             the machine
  POST   /v1/credentials        its token
  POST   /v1/authority-leases   what it may do
        │                       ← needs treasury_admin, not just leases:write
        ▼
  POST   /v1/authorization/evaluate  →  POST /v1/execute
```

## Four things that will look like bugs and are not

| What you see                                                        | Why                                                                                                             | What to do                                                          |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `403` reviewing your own policy                                     | The author may not approve it. Dual control.                                                                    | Use a different human.                                              |
| `DELEGATION_EXCEEDS_PARENT` issuing a lease, holding `leases:write` | Issuance ceilings key on the **user's role**, not the scope. A role the policy does not name may issue nothing. | Assign `treasury_admin`, or add your role to the policy's ceilings. |
| `DELEGATION_EXCEEDS_PARENT` naming a real counterparty              | The starter ceilings list example ids.                                                                          | Edit `issuance.ceilings` to your accounts and counterparties.       |
| `DENY / UNKNOWN_COUNTERPARTY` on a valid-looking wire               | The counterparty is not registered. Derived from row existence, never asserted.                                 | `POST /v1/resources`.                                               |

## What "done" looks like

You have completed onboarding when all of these are true and none of them
involved editing source, querying the database, or copying a credential out of a
fixture file:

- [ ] `pnpm altus bootstrap` refuses to run a second time
- [ ] Your organization's name appears in `GET /v1/users`, and "Acme" does not
- [ ] Your policy is `ACTIVE`, approved by two humans who did not author it
- [ ] Your counterparty is registered and a wire to it is authorized
- [ ] One execution went through `POST /v1/execute` with `intent_verified: true`
- [ ] Its receipt verifies `INTACT`
- [ ] `GET /v1/trace/{decision_id}` returns `complete: true`

If any step required knowledge that is not on this page, that is a defect in
this page. Tell us which one.
