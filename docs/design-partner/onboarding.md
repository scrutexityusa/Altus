# Onboarding: your tenant, from an empty database

**Time: about 30 minutes. No source edits, no database client, no fixture
credentials.**

Every block below is copy-pasteable **in sequence**. Each one exports what the
next one needs, so nothing has to be reconstructed from earlier output. When you
finish, the organization, the people, the accounts and the counterparties are
yours — the word "Acme" appears nowhere.

Work in **one terminal** for the setup and a **second** for the running API. The
blocks say which.

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

**Terminal 1.** The repository URL is in your onboarding packet.

```bash
git clone <repo-url> altus && cd altus
pnpm install
```

### If you are using the bundled Docker Compose

```bash
docker compose up -d

# PostgreSQL accepts connections a moment after the container starts.
until docker compose exec -T postgres pg_isready -U scrutexity_owner -q; do sleep 1; done

export DATABASE_ADMIN_URL=postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity
export DATABASE_URL=postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity
```

**Both roles already exist** — compose runs `db/init/00-roles.sql` on first
start. There is nothing for you to create.

### If you are using a PostgreSQL 16 you already run

Create the two roles from `db/init/00-roles.sql`, then:

```bash
export DATABASE_ADMIN_URL=postgres://owner:pass@your-host:5432/your-db
export DATABASE_URL=postgres://app:pass@your-host:5432/your-db
```

**Why two roles:** row level security is `FORCE`d, and a table owner bypasses
it. Tenant isolation depends on the service connecting as someone who is _not_
the owner. The owner connection applies migrations; the application connection
is what the service runs as.

### Apply the schema

```bash
pnpm altus migrate
```

The first `altus` command compiles the workspace packages if they are not built
yet. That takes a few seconds and happens once.

---

## 2. The installation ceremony

**Terminal 1.**

```bash
ALTUS_BOOTSTRAP_DATABASE_URL="$DATABASE_ADMIN_URL" \
  pnpm altus bootstrap \
    --org-name    "Example Treasury" \
    --admin-name  "Jane Smith" \
    --admin-email "jane@example.com" \
    --json > bootstrap.json

cat bootstrap.json
```

This creates your organization, your first administrator, and one credential.
It is the **only** step that uses the database owner connection, it runs once,
and it refuses to run again — the installation is marked in a table whose
primary key permits exactly one row.

Capture both values it produced. **The token is printed once and cannot be
recovered**, which is why this writes it to a file rather than asking you to
copy it out of a terminal:

```bash
export BOOTSTRAP=$(jq -r .token bootstrap.json)
export ADMIN_USER_ID=$(jq -r .admin_user_id bootstrap.json)
export BOOTSTRAP_CRED_ID=$(jq -r .credential_id bootstrap.json)
echo "administrator: $ADMIN_USER_ID"
```

Capture the credential id too. The working credential you issue in step 3 has
the same scopes, so once both exist the listing cannot tell you which is which —
and you are going to want to revoke exactly one of them at the end.

> `bootstrap.json` holds a live credential. Delete it once step 3 has issued you
> a working one: `rm bootstrap.json`.

**What this credential can and cannot do.** It provisions: `admin:write`,
`leases:write`, `policies:write`, `read`, `audit:read`. It deliberately **cannot**
evaluate authorizations, approve payments, or ingest signals. The ceremony
establishes ownership and administration; it does not become the thing used for
governed actions.

### Start the API

**Terminal 2**, from the same directory. It needs `DATABASE_URL`, so export it
here too:

```bash
export DATABASE_URL=postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity
pnpm exec tsx services/api/src/server.ts
```

It listens on **8080** by default; set `PORT` to change it. Back in
**terminal 1**:

```bash
export ALTUS=http://127.0.0.1:8080
curl -sS $ALTUS/ready          # {"status":"ready"}
```

---

## 3. Give the administrator the role that can issue authority

**Terminal 1**, for the rest of this guide.

```bash
curl -sS -X PATCH $ALTUS/v1/users/$ADMIN_USER_ID \
  -H "authorization: Bearer $BOOTSTRAP" -H 'content-type: application/json' \
  -d '{"roles":["admin","policy_author","treasury_admin"]}' | jq -c '.user.roles'
```

Then issue yourself a working credential:

```bash
export ADMIN=$(curl -sS -X POST $ALTUS/v1/credentials \
  -H "authorization: Bearer $BOOTSTRAP" -H 'content-type: application/json' \
  -d "{\"principal_type\":\"user\",\"principal_id\":\"$ADMIN_USER_ID\",
       \"scopes\":[\"read\",\"audit:read\",\"admin:write\",\"leases:write\",\"policies:write\"]}" \
  | jq -r .token)

rm bootstrap.json
```

**Why replace a credential that has almost the same scopes?** Because of where
it came from, not what it can do. The bootstrap token was minted by a process
holding the database owner connection, outside the API, with no record of who
asked for it. Every credential after it is issued _through_ the control plane,
by a named principal, and appears in `GET /v1/credentials` with a prefix,
scopes, and a last-used time. Keeping the ceremony token in daily use would
leave one credential in your estate that the estate cannot account for.

Revoking it is the last step of onboarding — see the end of this page.

---

## 4. Create the two reviewers

A policy needs two approvals from humans who did not author it, and you are the
author.

```bash
create_human() {   # email  display-name  role  scopes-json  →  prints a token
  local uid
  uid=$(curl -sS -X POST $ALTUS/v1/users \
    -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"display_name\":\"$2\",\"roles\":[\"$3\"]}" \
    | jq -er .user.id) || { echo "creating $1 failed" >&2; return 1; }
  curl -sS -X POST $ALTUS/v1/credentials \
    -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
    -d "{\"principal_type\":\"user\",\"principal_id\":\"$uid\",\"scopes\":$4}" \
    | jq -er .token
}

export REVIEWER_ONE=$(create_human reviewer.one@example.com "Reviewer One" \
  policy_reviewer '["read","policies:write"]')
export REVIEWER_TWO=$(create_human reviewer.two@example.com "Reviewer Two" \
  policy_reviewer '["read","policies:write"]')

test -n "$REVIEWER_ONE" -a -n "$REVIEWER_TWO" && echo "two reviewers ready"
```

Each credential's secret is returned exactly once. There is no endpoint that can
produce it again.

---

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

**Keep `acct_001` and `cp_100` for this walkthrough** even though the names are
placeholders — the starter policy's issuance ceilings name exactly those ids, and
changing one without the other is the most common way to get stuck. Step 6
explains how to move to your real ids.

---

## 6. Author, review and activate your policy

The starter pack is `policies/treasury-wire.yaml`. It carries **six `CHANGE ME`
markers**; for this walkthrough you need **none of them** — it works as shipped
against `acct_001` and `cp_100`.

**For your own ids, two of the six are mandatory** and the rest are judgement:

| Marker                                          | Needed for the walkthrough?               | What it is                                                             |
| ----------------------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------- |
| `issuance.ceilings` accounts and counterparties | **Yes, if you changed the ids in step 5** | A lease naming anything outside these is refused _before_ it is issued |
| Amount thresholds                               | No — defaults are $10k / $50k / $1M       | Your approval ladder                                                   |
| `metadata.owner`                                | No                                        | Your team's name                                                       |
| Sanctions list                                  | No                                        | A coarse country backstop                                              |
| Fraud threshold and decay duration              | No                                        | Your engine's calibration                                              |
| The header note on evaluation semantics         | No                                        | Explanatory                                                            |

The approval roles the policy names (`treasurer`, `cfo`) do **not** need to
match the two reviewers you created in step 4 — reviewers approve the _policy_,
those roles approve _payments_. Two different things.

```bash
export POLICY_FILE=policies/treasury-wire.yaml
# Edit $POLICY_FILE in place, or point this at your own copy. The command below
# uploads whatever this variable names — a copy you edited under a different
# filename will not be picked up unless you set it here.

export VERSION=$(curl -sS -X POST $ALTUS/v1/policy-versions \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d "$(jq -Rs '{document: .}' < "$POLICY_FILE")" | jq -er .policy_version.id)
echo "draft: $VERSION"
```

Two approvals, from the two reviewers. Not from you:

```bash
for T in "$REVIEWER_ONE" "$REVIEWER_TWO"; do
  curl -sS -X POST $ALTUS/v1/policy-versions/$VERSION/reviews \
    -H "authorization: Bearer $T" -H 'content-type: application/json' \
    -d '{"vote":"APPROVED","comment":"Matches our approval matrix."}' \
  | jq -e '{status,approvals}' || { echo "review failed — stopping" >&2; break; }
done

curl -sS -X POST $ALTUS/v1/policy-versions/$VERSION/activate \
  -H "authorization: Bearer $ADMIN" | jq -c '.policy_version | {status}'
```

The first review moves the version to `REVIEW`; the second to `APPROVED`. Only
then can it be activated. Reviewing your own version returns `403`, which is the
control working.

---

## 7. Register your agent and give it a credential

```bash
curl -sS -X POST $ALTUS/v1/agents \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d "{\"handle\":\"payments-agent\",\"display_name\":\"Payments Agent\",
       \"owner_user_id\":\"$ADMIN_USER_ID\"}" | jq -c '.agent | {id,handle}'

export AGENT=$(curl -sS -X POST $ALTUS/v1/credentials \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"principal_type":"agent","principal_id":"payments-agent",
       "scopes":["read","authorization:evaluate"]}' | jq -er .token)
```

`owner_user_id` is the accountable human — here, yourself. Every agent has one;
when you later ask who authorised something, that is where the answer starts.

**Handles work anywhere an agent id does.** `principal_id`, `agent_id` in a
lease, and `agent_id` in an authorization request all accept either
`payments-agent` or `agent_01...`. Use whichever you have in front of you.

---

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
       "grant_type":"SINGLE_USE"}' | jq -c '.authority_lease.id // .error'
```

`"5000000"` is $50,000.00 — money is integer minor units as a string, and floats
are refused. `SINGLE_USE` means the grant is spent on the first claim.

---

## 9. One governed execution

```bash
DECISION=$(curl -sS -X POST $ALTUS/v1/authorization/evaluate \
  -H "authorization: Bearer $AGENT" -H 'content-type: application/json' \
  -d '{"agent_id":"payments-agent","action":"wire.execute",
       "resource":{"type":"bank_account","id":"acct_001"},
       "context":{"amount":"25000.00","currency":"USD",
                  "counterparty_id":"cp_100","destination_country":"US"},
       "nonce":"first-real-request"}')

export DECISION_ID=$(echo "$DECISION" | jq -er .decision_id)
echo "$DECISION" | jq -c '{decision,reason_code}'
```

Then execute it. The operation must be **the one that was authorized** — the
boundary recomputes it from its own records and compares hashes, so a changed
amount produces `INTENT_MISMATCH` and the provider is never contacted:

```bash
EXECUTION=$(curl -sS -X POST $ALTUS/v1/execute \
  -H "authorization: Bearer $AGENT" -H 'content-type: application/json' \
  -d "{\"decision_id\":\"$DECISION_ID\",
       \"operation\":{\"action\":\"wire.execute\",
         \"resource\":{\"type\":\"bank_account\",\"id\":\"acct_001\"},
         \"context\":{\"amount\":\"25000.00\",\"currency\":\"USD\",
                      \"counterparty_id\":\"cp_100\",\"destination_country\":\"US\"}}}")

export RECEIPT_ID=$(echo "$EXECUTION" | jq -er .receipt_id)
echo "$EXECUTION" | jq -c '{status,provider,intent_verified}'
```

---

## 10. Verify the evidence

```bash
curl -sS -X POST $ALTUS/v1/receipts/$RECEIPT_ID/verify \
  -H "authorization: Bearer $ADMIN" | jq -c '{integrity,attests}'

curl -sS $ALTUS/v1/trace/$DECISION_ID -H "authorization: Bearer $ADMIN" \
  | jq -c '{root_cause:.root_cause.name, steps:(.trace|length), complete}'
```

`INTACT` means the receipt's payload digest, link hash and signature all verify
and the chain reaches genesis. `complete: true` means the causal trace reaches
the moment a human activated the policy that admitted this authority.

---

## 11. Retire the ceremony credential

```bash
curl -sS -X POST $ALTUS/v1/credentials/$BOOTSTRAP_CRED_ID/revoke \
  -H "authorization: Bearer $ADMIN" | jq -c '.credential | {status,revoked_at}'

# Everything that remains, and when each was last used.
curl -sS $ALTUS/v1/credentials -H "authorization: Bearer $ADMIN" \
  | jq -c '.credentials[] | {id,principal_type,scopes,status,last_used_at}'
```

Revocation is immediate — the next request with that token is a `401`. There is
no credential cache to wait out.

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
- [ ] The bootstrap credential is `REVOKED`

If any step required knowledge that is not on this page, that is a defect in
this page. Tell us which one, and what you had to go and find out.
