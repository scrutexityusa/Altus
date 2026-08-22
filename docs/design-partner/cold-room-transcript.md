# Cold-room transcript

**A recorded run of [`onboarding.md`](onboarding.md) from a fresh clone and an
empty database, following only what that document says.**

The point is not the time. It is the failure criteria: a run that needs an
undocumented prerequisite, a manual database query, a source edit, or a
credential copied out of a fixture has not established anything, however fast it
was.

## Conditions

|                      |                                          |
| -------------------- | ---------------------------------------- |
| Repository           | `git clone --depth 1`, never built       |
| Database             | A freshly created, empty database        |
| `.seed.local.json`   | Absent                                   |
| Signing keys, `.env` | Absent                                   |
| Prior state          | None. No tenant, no migration history    |
| Instructions used    | `docs/design-partner/onboarding.md` only |

## Result

**2 minutes 40 seconds**, clock started before the first command.

```
15:49:49  START
15:49:51  pnpm install
15:49:54  pnpm altus migrate                     10 migrations applied
15:51:10  pnpm altus bootstrap                   organization + admin + credential
15:51:36  api listening, /ready 200
15:51:54  PATCH user roles; issue admin credential; create 2 reviewers
15:52:10  register acct_001 + cp_100; policy REVIEW -> APPROVED -> ACTIVE
15:52:29  lease issued; ALLOW; EXECUTED; receipt INTACT; trace complete
15:52:29  STOP
```

Verbatim output of the last four steps:

```
--- step 8: issue authority
"lease_01M0N2RV6WPQ0C2GVBZ2GE75YX"
--- step 9: governed execution
{"decision":"ALLOW","reason_code":"WITHIN_LEASED_AUTHORITY"}
{"status":"EXECUTED","provider":"simulated-treasury","intent_verified":true}
--- step 10: evidence
{"integrity":"INTACT","attests":"evidence_integrity_and_provenance"}
{"root_cause":"treasury_wire v1.5.0 activated","steps":6,"complete":true}
```

## Checklist

- [x] `altus bootstrap` refuses a second run
- [x] The organization is "Example Treasury"; the string "Acme" appears nowhere
- [x] Policy `ACTIVE`, approved by two humans who did not author it
- [x] Counterparty registered through the API; the wire to it is authorized
- [x] One execution through `POST /v1/execute`, `intent_verified: true`
- [x] Receipt verifies `INTACT`
- [x] `GET /v1/trace/{id}` returns `complete: true`

## Failure criteria

| Criterion                         | Result                             |
| --------------------------------- | ---------------------------------- |
| Undocumented prerequisite         | **FAILED, then fixed** — see below |
| Manual database query             | Not needed                         |
| Editing source                    | Not needed                         |
| Acme or fixture credentials       | Not used; none existed             |
| Copying a secret from a fixture   | Not needed                         |
| Knowledge not in the instructions | **One gap, fixed** — see below     |

### What the run found

**1. The documented flow was broken on a fresh clone.**

`pnpm altus bootstrap` died with a module-resolution stack trace:

```
Error [ERR_MODULE_NOT_FOUND]: Cannot find module
  '.../node_modules/@scrutexity/core/dist/index.js'
  imported from '.../scripts/bootstrap.ts'
```

`scripts/*` import `@scrutexity/core` through its package entry point, which is
compiled output. `pnpm altus migrate` worked because it imports no workspace
package; `bootstrap` does. So the second of three documented commands failed on
every clean checkout, and nothing said to build first.

Fixed in `scripts/altus.ts` rather than by adding a step: the dispatcher builds
the workspace when `dist` is absent, once. A stranger following the guide should
not have to know which subcommands happen to need compiled output.

**2. The guide assumed the compose database.**

Every command reads its connection from the environment and the defaults point
at `docker compose`. Running against an existing PostgreSQL required knowing to
set `DATABASE_ADMIN_URL` and `DATABASE_URL`, which the guide did not mention.
Now documented in step 1, along with the reason the application role must not be
the table owner.

## What this does and does not establish

**Does:** the documented path works end to end from nothing, and the two defects
above are gone.

**Does not:** that a _stranger_ can do it. This run was performed by someone who
wrote the system, which is exactly the bias the exercise exists to expose and
cannot itself remove. The two findings are evidence the exercise works, not that
the result is now safe to assume — an unfamiliar reader will find things a
familiar one walks past.

The next honest version of this test is someone else holding the stopwatch.

## Reproducing it

Follow `onboarding.md`. If any step needs knowledge that is not on that page,
that is a defect in the page — say which one.
