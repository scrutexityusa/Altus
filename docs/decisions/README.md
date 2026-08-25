# Architecture decision records

One record per decision that would otherwise be re-litigated. Each states the
problem, the options considered, the choice, and — most importantly — what
would make us revisit it.

| ADR                                                       | Decision                                                                 | Status   |
| --------------------------------------------------------- | ------------------------------------------------------------------------ | -------- |
| [0001](0001-repository-reset.md)                          | Reset the repository; build the monorepo greenfield                      | Accepted |
| [0002](0002-in-process-policy-engine.md)                  | Evaluate policy in-process rather than running OPA/OpenFGA               | Accepted |
| [0003](0003-authority-lattice.md)                         | Model authority as a lattice with a proven containment relation          | Accepted |
| [0004](0004-prefixed-text-ids.md)                         | Prefixed, time-sortable TEXT primary keys                                | Accepted |
| [0005](0005-tenant-isolation-rls.md)                      | Enforce tenant isolation in PostgreSQL with FORCE RLS                    | Accepted |
| [0006](0006-evidence-hash-chain.md)                       | Per-tenant hash chain, Ed25519 signatures, append-only tables            | Accepted |
| [0007](0007-closed-action-catalog.md)                     | Actions are a closed catalog, not free-form strings                      | Accepted |
| [0008](0008-escalation-boundary.md)                       | Envelope failures are terminal; constraint failures are escalatable      | Accepted |
| [0009](0009-no-workflow-engine.md)                        | No durable workflow engine for the first slice                           | Accepted |
| [0010](0010-exact-money.md)                               | Money is integer minor units; floats are refused                         | Accepted |
| [0011](0011-corrective-handshake.md)                      | Corrective actions are policy-derived, never generated                   | Accepted |
| [0012](0012-root-cause-api.md)                            | The trace names a root cause rather than listing events                  | Accepted |
| [0013](0013-single-use-grants.md)                         | A single-use grant is spent on claim, not on execution                   | Accepted |
| [0014](0014-signal-authentication.md)                     | Signals are authenticated; Ed25519 preferred over HMAC                   | Accepted |
| [0015](0015-exact-intent-binding.md)                      | An ALLOW records the exact operation it authorises, and its binding      | Accepted |
| [0016](0016-execution-enforcement-boundary.md)            | Scrutexity performs the operation; the boundary is the only path out     | Accepted |
| [0017](0017-security-time-authority.md)                   | The database is the single authority for every validity decision         | Accepted |
| [0018](0018-signal-key-custody.md)                        | Signal sources must enrol an Ed25519 key; HMAC is refused by default     | Accepted |
| [0019](0019-credential-lifetime-and-workload-identity.md) | Every credential expires; bearer tokens are the interim mechanism        | Accepted |
| [0020](0020-verify-where-it-is-authoritative.md)          | A claim is verified where it is authoritative, not where it was authored | Accepted |
