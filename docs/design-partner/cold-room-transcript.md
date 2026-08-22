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

Two runs. The second is the one that counts, because the guide was rewritten
between them after an independent cold read of the document.

### Run 2 — after the cold-read rewrite

**42 seconds** for steps 1–11 in a single terminal session, pasted verbatim with
no improvisation and no reconstruction of state from earlier output. (Dependency
install was already warm in this clone; run 1 measured it at 2 seconds.)

```
16:18:22  START
16:18:22  pnpm altus migrate                     10 migrations applied
16:18:2x  pnpm altus bootstrap                   organization + admin + credential
16:18:38  api listening, /ready 200
16:18:40  roles patched; admin credential issued; two reviewers created
16:18:40  acct_001 + cp_100 registered; policy REVIEW -> APPROVED -> ACTIVE
16:19:04  agent + credential; lease; ALLOW; EXECUTED; INTACT; trace complete
16:19:04  STOP
```

Verbatim output of the last five steps:

```
{"id":"agent_01M0N49G5B4Z84AR3ZHB2K41EC","handle":"payments-agent"}
"lease_01M0N49G6WRPB1Z5EK6BY1XSHF"
{"decision":"ALLOW","reason_code":"WITHIN_LEASED_AUTHORITY"}
{"status":"EXECUTED","provider":"simulated-treasury","intent_verified":true}
{"integrity":"INTACT","attests":"evidence_integrity_and_provenance"}
{"root_cause":"treasury_wire v1.5.0 activated","steps":6,"complete":true}
{"status":"REVOKED","revoked_at":"2026-08-22T16:19:43.832Z"}
```

Every credential in the final listing carried a non-null `last_used_at`, which
is the field that was decorative until this milestone.

### Run 1 — the first version of the guide

**2 minutes 40 seconds**, and it found two defects (below). The guide was
mechanically discontinuous in ways this run did not expose, because the person
running it knew what the next step needed.

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

### What run 1 found

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
the workspace when `dist` is absent, once.

**2. The guide assumed the compose database.**

Running against an existing PostgreSQL required knowing to set
`DATABASE_ADMIN_URL` and `DATABASE_URL`, which the guide did not mention.

### What the cold read found, between the runs

Someone who had not written the code read the guide without opening the
repository and reported six hesitations and three stop-and-ask points. Five were
mechanical: the guide taught `DATABASE_ADMIN_URL` in step 1 and then hardcoded a
different connection string in step 2; it never captured the administrator's user
id, the reviewer tokens, the decision id or the receipt id, so later steps
referenced values the reader no longer had; and it said "copy the policy file"
beside a command that uploaded the original.

The common shape: **the guide switched from automation to manual bookkeeping
halfway through, and only someone who already knew what the next step needed
could carry state across the gap.** Run 1 did not catch a single one of these,
because the person running it was that someone.

Every block now exports what the next block consumes.

### What run 2 found

One, introduced by the rewrite itself: the final step told the reader to revoke
"the bootstrap credential" from a listing in which it is **indistinguishable
from the working credential** — same principal, same scopes. Step 2 now captures
`BOOTSTRAP_CRED_ID` alongside the token.

## What this does and does not establish

**Does:** the documented path works end to end from nothing, verbatim, in a
single session, and the defects above are gone.

**Does not:** that a _stranger_ can do it. This run was performed by someone who
wrote the system, which is exactly the bias the exercise exists to expose and
cannot itself remove. The two findings are evidence the exercise works, not that
the result is now safe to assume — an unfamiliar reader will find things a
familiar one walks past.

The next honest version of this test is someone else holding the stopwatch.

## Reproducing it

Follow `onboarding.md`. If any step needs knowledge that is not on that page,
that is a defect in the page — say which one.
