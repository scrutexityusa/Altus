# Latency

Altus sits inline on the payment path. An agent that waits 8ms for permission
is a different product from one that waits 300ms, so the cost is a product
property rather than an engineering curiosity, and it belongs in a document
with numbers in it.

Reproduce with `make bench` (`scripts/bench.ts`). Every number below came from
that command.

## What was measured

| path                                          |      p50 |      p95 |      p99 |      max |
| --------------------------------------------- | -------: | -------: | -------: | -------: |
| `decide` — the pure decision function         |  0.16 ms |  0.25 ms |  1.16 ms |  3.73 ms |
| `POST /v1/authorization/evaluate` → ALLOW     | 11.06 ms | 14.95 ms | 18.39 ms | 26.01 ms |
| `POST /v1/authorization/evaluate` → ESCALATE  | 10.78 ms | 13.00 ms | 14.71 ms | 67.91 ms |
| `POST /v1/authorization/evaluate` → DENY      | 10.06 ms | 13.01 ms | 14.63 ms | 50.00 ms |
| `POST /v1/execute` — the enforcement boundary |  8.81 ms | 11.68 ms | 14.75 ms | 18.44 ms |

Sequential, one client, real HTTP over loopback, real PostgreSQL 16. 400
samples each after 60 warmup iterations; 20,000 samples for the pure function.
Percentiles are nearest-rank on the sorted samples — an interpolated p99
reports a latency no request actually experienced, which is the wrong kind of
number to hand somebody deciding whether to put this in their payment path.

Run-to-run variance across four runs was roughly ±10% at p50 and ±25% at p99.

## What the numbers say

**The policy engine is not the cost.** `decide` is 1.4% of the ALLOW endpoint.
The other 98.6% is PostgreSQL and a socket. Optimising the evaluator would be
optimising the wrong end of the system, and any claim that the authorization
logic is "too slow to sit inline" is not supported by the measurement.

**One authorize costs ~3.6 database commits.** Each commit is an fsync, and
fsync is the unit the write path is priced in. Two of those commits are the
authentication hook: `services/api/src/auth.ts` resolves the credential and
touches its last-used timestamp, each inside its own `BEGIN`/`COMMIT`, before
the handler starts. They are read-mostly work paying for a write transaction.

**DENY is not meaningfully cheaper than ALLOW.** A refusal still writes a
request, a decision and a receipt, because a refusal is evidence. This is
deliberate; it is also why there is no cheap path to abuse.

**Enforced execution is cheaper than authorization**, at 8.81 ms against a
provider that is an in-memory ledger. It performs two committed transactions
and a provider call. Against a real bank the provider dominates and this
number stops being ours.

## Concurrency, and a real bottleneck

| load                                    |      p50 |       p95 |       p99 | sustained |
| --------------------------------------- | -------: | --------: | --------: | --------: |
| 16 concurrent, one tenant               | 73.93 ms | 136.33 ms | 164.49 ms | 201 req/s |
| 16 concurrent, split across two tenants | 61.06 ms |  88.45 ms | 146.14 ms | 247 req/s |

The same offered load, split over two tenants instead of one, raises
throughput ~20% and cuts tail latency. That difference has a specific cause.

Every decision appends a receipt, and every receipt upserts one row in
`receipt_chain_heads` keyed by `organization_id`, holding that row's lock until
commit. **A tenant's decisions serialize on a single row.** The hash chain is
what makes evidence tamper-evident, and a chain has an order, so this is
inherent to the design rather than an oversight — but it is a per-tenant
ceiling and it should be stated rather than discovered by a design partner
under load.

Raising `DATABASE_POOL_MAX` from 10 to 24 and 48 moved sustained throughput by
less than 6%, so the ceiling is not connection starvation.

## What these numbers are not

- **Not an SLO.** They are a floor measured on one developer machine.
- **Not representative hardware.** Measured inside a shared cloud container
  with no tuning, on a co-located database. Absolute values will differ, likely
  favourably, on a provisioned instance.
- **Not a real provider.** `SimulatedTreasuryProvider` is an in-memory ledger.
  It proves the enforcement boundary works. It proves nothing about a bank.
- **Not network-inclusive.** Loopback has no network. A partner's agent adds
  its round trip to us on top of every number here.
- **Not a multi-node result.** One API process, one PostgreSQL instance. No
  claim is made about horizontal scaling, because none has been measured.

## The levers, in the order they are worth pulling

1. **Stop paying for two write transactions in the authentication hook.** The
   credential lookup is a read; the last-used touch is already coarsened to
   five minutes and does not need a transaction of its own.
2. **Decide whether receipts must be appended synchronously.** They currently
   are, inside the decision's transaction, which is what makes the evidence
   and the decision atomic. Relaxing that buys per-tenant concurrency and costs
   an invariant. It is a trade to make deliberately, with a design partner's
   actual load in hand, not speculatively.
3. **Measure a provisioned instance.** Half of these numbers are this
   container.

None of these are worth doing before a design partner's load is known. The
measurement exists so that the conversation starts from numbers.
