# ADR-0020: A claim is verified where it is authoritative, not where it was authored

**Status:** Accepted
**Date:** 2026-08-24
**Type:** Postmortem, and the rule it produced

## What happened

Every one of the first fourteen GitHub Actions runs this repository had failed,
`main` included. Throughout that period, commit messages and status reports in
this repository said `make ci` was green. Both statements were true. They were
about different machines.

The break was in the first job. `Core (no database)` runs
`vitest run packages` in a container with no PostgreSQL service, and the single
vitest configuration's `globalSetup` provisioned a database unconditionally. The
job died on connect before collecting a test. `integration` and `build` both
declare `needs: core`, so they were **skipped** — not failed, skipped, which
reads as absence rather than as breakage.

The consequence is the part worth sitting with. The 609 tests, the twelve
adversarial invariants, the recovery harness that kills a process mid-payment,
the treasury demo, and the container image had **never executed on a clean
runner**. Only typecheck, formatting and two drift checks had ever passed
remotely. Every claim about the security suite rested on one developer machine.

## What it hid

Fixing the first job made two more defects reachable, both of which had been
latent for as long as the jobs had been skipped.

**A one-way door in the migrations.** Replaying the integration job's steps by
hand found:

```
migrate --down 3 && migrate
→ check constraint "api_credentials_revoked_shape" is violated by some row
```

Migration 0010's down drops `api_credentials.revoked_at`; its up re-adds the
column empty and then adds a `CHECK` requiring every `REVOKED` row to carry one.
Any database on which somebody had revoked a credential could not roll forward.

Note _why the existing check missed it_. CI creates a database, migrates it,
rolls back three, rolls forward, and drops it. That database has no revoked rows
— it has no rows at all — so the constraint had nothing to refuse. The check
that exists precisely to catch one-way doors was testing the DDL rather than the
migration, because **a migration's job is to carry existing rows across a schema
change, and there were none.**

**A container image that could not build.** `COPY --from=build
/app/packages/sdk/dist` referred to output the build stage never produces: it
runs `tsc -b services/api`, which does not reference the SDK, because the control
plane imports nothing from it.

## The pattern, stated once

This is the third instance in this repository of one shape:

|              | The claim            | Where it was true     | Where it was not             |
| ------------ | -------------------- | --------------------- | ---------------------------- |
| `make lint`  | "types check"        | locally, sources only | CI, which also checks tests  |
| `make ci`    | "everything CI runs" | locally               | the workflow, which ran less |
| the workflow | "CI is green"        | nowhere               | GitHub Actions, all 14 runs  |

**An artefact verified where it was authored is not verified.** Local runs
inherit a warm database, a populated cache, an installed toolchain, an
already-built `dist`, and — as the migration defect shows — historical data that
the authoritative environment does not have. Each of those can make a broken
thing look whole, and one of them can make a whole thing look broken.

The same rule already applied elsewhere here and was simply not extended to the
pipeline: the onboarding guide is run as written (`make onboarding`) rather than
described, and the demo is asserted rather than narrated.

## Decision

**"Green" means the latest completed run on the authoritative branch concluded
`success`.** Not a local suite. Reports cite the run URL.

Four things enforce it rather than describe it:

1. **A badge on the README**, so the remote state is visible without asking.
2. **`make ci-status`** (`scripts/ci-status.sh`), which asks the GitHub API for
   the run for the current branch, prints its URL, and exits non-zero when it is
   red, unfinished or absent. All four paths are exercised against recorded
   payloads via `CI_STATUS_PAYLOAD`.
3. **The workflow invokes the Make targets** for the adversarial, recovery and
   onboarding suites instead of restating their commands, so the local and
   remote definitions of "everything" cannot drift apart again.
4. **The vitest split is structural.** `vitest.unit.config.ts` has no
   `globalSetup` and includes only `packages/**`, so "needs no database" is
   enforced by the configuration the no-database job actually uses, rather than
   asserted in a job name.

Two of those needed correcting within the hour, which is worth recording
rather than quietly fixing:

- `ci-status` reported **green for the previous commit**. "The latest run on
  this branch is green" and "your commit is green" are different claims, and
  the gap between them is minutes wide on every push. It now compares the run's
  SHA against local `HEAD` and refuses rather than answering a question nobody
  asked.
- The workflow fired on `pull_request` and on pushes to `main` only. When this
  branch's pull request merged, pushes to it stopped triggering anything at
  all — so the branch became unverifiable at exactly the moment the tooling for
  verifying it was written. `push` now covers every branch. PR'd branches run
  twice as a result, which buys coverage of both the branch head and the merge
  result.

And, for the class the migration defect belongs to:

5. **Migration replay is tested against data, not against emptiness.**
   `services/api/test/migrations.test.ts` provisions its own database, seeds the
   historical shape that broke it — a tenant, a user, and a revoked credential —
   then performs the rollback and reapply, and separately tears the schema down
   to zero and rebuilds it. Removing 0010's backfill fails the seeded test and
   leaves the empty one passing, which is the whole finding in one line.

## Consequences

- Reporting a state now costs an API call. That is the correct price.
- `make ci` keeps its meaning — "the suite passes here" — and stops being
  offered as evidence of anything else.
- The backfill records `revoked_at = now()` for rows that predate the column.
  The original instant is gone, so the choice is which direction to be wrong in:
  "revoked no later than this" never understates how long a credential was live,
  where backdating to `created_at` would claim it was dead during a window
  nobody can prove.
- Three defects were found by running the pipeline once. There is no reason to
  believe that is the last of them, which is an argument for the badge rather
  than against it.
- This ADR does not add a process. It adds a definition and four mechanisms that
  make the definition checkable, because a rule nobody can check is the thing
  that failed here in the first place.
