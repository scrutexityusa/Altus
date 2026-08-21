# ADR-0001 — Reset the repository and build greenfield

**Status** Accepted · 2026-08-21

## Context

Phase 0 called for inspecting the repository, identifying reusable
infrastructure and removing obsolete product code.

The repository contained one file: `LICENSE` (MIT, © 2026 scrutexityusa). No
source, no build configuration, no CI, no deployment manifests, no dependency
manifest, no history beyond the initial commit.

## Decision

There is nothing to preserve and nothing to remove. The MIT license is kept.
Everything else is new.

The layout is a pnpm workspace with a hard separation between the pure domain
and everything that touches the outside world:

```
packages/core   pure domain — no I/O, no clock, no randomness
packages/sdk    typed client and enforcement point
services/api    HTTP, persistence, tenancy, observability
apps/web        minimal dashboard over the API's own read model
db/migrations   schema, RLS, append-only triggers
policies/       the demonstration treasury pack
spec/           generated contracts, drift-checked in CI
deploy/k8s      sidecar templates
```

## Consequences

No migration burden and no inherited abstractions. The reset is documented here
so a future reader does not go looking for the code that was removed — there
was none.
