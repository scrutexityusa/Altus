/**
 * Latency baseline.
 *
 * A machine authority system sits inline on the payment path, so its latency
 * is a product property rather than an engineering curiosity: an agent that
 * must wait 300ms for permission is a different product from one that waits
 * 8ms. This measures what it actually costs, against a real HTTP server and a
 * real database, and prints numbers rather than adjectives.
 *
 * What is measured, in order of how much of the system each includes:
 *
 *   decide      the pure decision function alone, no IO, no clock, no server
 *   authorize   POST /v1/authorization/evaluate over the loopback interface
 *   execute     POST /v1/execute -- the enforcement boundary, two committed
 *               transactions with a provider call between them
 *
 * `decide` is the interesting denominator. If the policy engine is 20us and
 * the endpoint is 6ms, then the endpoint is a database and a socket, and
 * optimising the evaluator would be optimising 0.3% of the answer.
 *
 * Honest limits, which belong next to any number this prints:
 *   - the provider is SimulatedTreasuryProvider: an in-memory ledger, not a
 *     bank. Real provider latency dominates the enforced path and is not ours.
 *   - loopback has no network. A partner's agent will add their RTT to us.
 *   - one process, one machine, a cold-ish cache. This is a floor, not a SLO.
 */
import { execSync } from 'node:child_process';
import { Client } from 'pg';
import { evaluateAuthorization } from '../packages/core/src/evaluate.js';
import { snapshot } from '../packages/core/test/fixtures.js';
import { buildApp } from '../services/api/src/app.js';
import { seed, type SeedResult } from './seed.js';

const ADMIN_URL =
  process.env['DATABASE_ADMIN_URL'] ??
  'postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity';
const APP_URL =
  process.env['DATABASE_URL'] ?? 'postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity';

const ITERATIONS = Number(process.env['BENCH_ITERATIONS'] ?? 400);
const WARMUP = Number(process.env['BENCH_WARMUP'] ?? 60);
const CONCURRENCY = Number(process.env['BENCH_CONCURRENCY'] ?? 16);

interface Sample {
  name: string;
  note: string;
  count: number;
  ms: number[];
}

/**
 * Percentiles by nearest-rank on the sorted samples.
 *
 * Deliberately not interpolated. An interpolated p99 reports a latency that no
 * request actually experienced, which is the wrong kind of number to put in
 * front of somebody deciding whether to put this in their payment path.
 */
function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) return Number.NaN;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))]!;
}

function summarise(sample: Sample) {
  const sorted = [...sample.ms].sort((a, b) => a - b);
  return {
    name: sample.name,
    note: sample.note,
    n: sample.count,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    max: sorted[sorted.length - 1]!,
  };
}

const fixed = (value: number) => (value < 1 ? value.toFixed(3) : value.toFixed(2));

function table(rows: ReturnType<typeof summarise>[]): void {
  const head = ['path', 'n', 'p50 ms', 'p95 ms', 'p99 ms', 'max ms'];
  const body = rows.map((r) => [
    r.name,
    String(r.n),
    fixed(r.p50),
    fixed(r.p95),
    fixed(r.p99),
    fixed(r.max),
  ]);
  const widths = head.map((h, i) => Math.max(h.length, ...body.map((row) => row[i]!.length)));
  const line = (cells: string[]) =>
    cells.map((c, i) => (i === 0 ? c.padEnd(widths[i]!) : c.padStart(widths[i]!))).join('  ');
  process.stdout.write(`\n${line(head)}\n${widths.map((w) => '-'.repeat(w)).join('  ')}\n`);
  for (const row of body) process.stdout.write(`${line(row)}\n`);
  process.stdout.write('\n');
  for (const r of rows) process.stdout.write(`  ${r.name}: ${r.note}\n`);
}

async function main(): Promise<void> {
  process.stdout.write('\nScrutexity -- latency baseline\n');

  // -- The pure decision function -------------------------------------------
  //
  // Measured first and separately because it is the only part of the system
  // with no excuse: no IO, no clock read, no allocation it did not choose.
  const pureSnapshot = snapshot();
  const pure: number[] = [];
  for (let i = 0; i < 5_000; i += 1) evaluateAuthorization(pureSnapshot);
  for (let i = 0; i < 20_000; i += 1) {
    const started = performance.now();
    evaluateAuthorization(pureSnapshot);
    pure.push(performance.now() - started);
  }

  process.stdout.write('resetting the database and seeding the reference tenant\n');
  execSync('pnpm exec tsx scripts/migrate.ts --reset', {
    stdio: 'ignore',
    env: { ...process.env, DATABASE_ADMIN_URL: ADMIN_URL },
  });
  const fixtures: SeedResult = await seed(ADMIN_URL);

  const app = await buildApp({
    NODE_ENV: 'development',
    DATABASE_URL: APP_URL,
    LOG_LEVEL: 'silent',
    EXECUTION_PROVIDERS: 'simulated-treasury',
  });
  await app.server.listen({ port: 0, host: '127.0.0.1' });
  const port = (app.server.addresses()[0] as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;

  const call = async (method: string, path: string, token: string, body?: unknown) => {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
  };

  const issueLease = async (adminToken: string) => {
    const response = await call('POST', '/v1/authority-leases', adminToken, {
      agent_id: 'treasury-agent',
      grant: {
        actions: ['wire.execute', 'wire.read', 'counterparty.read'],
        resources: { bank_account: ['acct_001'], counterparty: ['cp_100'] },
        constraints: {
          max_amount: { currency: 'USD', amountMinor: '5000000' },
          currencies: ['USD'],
          allowed_counterparties: ['cp_100'],
        },
      },
      ttl_seconds: 3600,
    });
    if (response.status !== 201) {
      throw new Error(`lease issuance failed: ${JSON.stringify(response.body)}`);
    }
  };

  const t = fixtures.tokens;
  const agentToken = t['treasury_agent']!;
  await issueLease(t['admin']!);

  let sequence = 0;
  const authorizeBody = (amount: string, accountId = 'acct_001') => ({
    agent_id: 'treasury-agent',
    action: 'wire.execute',
    resource: { type: 'bank_account', id: accountId },
    context: {
      amount,
      currency: 'USD',
      counterparty_id: 'cp_100',
      destination_country: 'US',
    },
    // Fresh every call: a replayed nonce is refused, and refusals are cheap in
    // a way that would flatter the numbers.
    nonce: `bench-${process.pid}-${(sequence += 1)}`,
  });

  const measure = async (
    name: string,
    note: string,
    expected: (result: { status: number; body: any }) => boolean,
    run: () => Promise<{ status: number; body: any; elapsed?: number }>,
    iterations = ITERATIONS,
  ): Promise<Sample> => {
    for (let i = 0; i < WARMUP; i += 1) {
      const result = await run();
      if (!expected(result)) {
        throw new Error(`${name}: warmup produced ${JSON.stringify(result.body)}`);
      }
    }
    const ms: number[] = [];
    for (let i = 0; i < iterations; i += 1) {
      const started = performance.now();
      const result = await run();
      const outer = performance.now() - started;
      // A benchmark that silently measures a 400 is measuring the error path.
      if (!expected(result)) throw new Error(`${name}: ${JSON.stringify(result.body)}`);
      // `elapsed` lets a step exclude its own setup -- see the enforced path,
      // which must authorize before it can execute.
      ms.push(result.elapsed ?? outer);
    }
    process.stdout.write(`  ${name}: ${iterations} samples\n`);
    return { name, note, count: iterations, ms };
  };

  // Commits per request. Each commit is an fsync, and fsync is the unit the
  // write path is actually priced in -- so this is the number that says
  // whether the endpoint is doing too much work or simply doing it durably.
  const stats = new Client(ADMIN_URL);
  await stats.connect();
  const commits = async (): Promise<number> => {
    const result = await stats.query(
      `SELECT xact_commit FROM pg_stat_database WHERE datname = current_database()`,
    );
    return Number(result.rows[0]?.['xact_commit'] ?? 0);
  };

  const samples: Sample[] = [];
  try {
    process.stdout.write('\nmeasuring\n');

    const commitsBefore = await commits();
    samples.push(
      await measure(
        'authorize (ALLOW)',
        'inside agent discretion; issues an execution grant',
        (r) => r.body?.decision === 'ALLOW',
        () => call('POST', '/v1/authorization/evaluate', agentToken, authorizeBody('25000.00')),
      ),
    );

    const commitsPerAuthorize = ((await commits()) - commitsBefore) / (ITERATIONS + WARMUP);

    samples.push(
      await measure(
        'authorize (ESCALATE)',
        'above discretion; computes the approval requirement',
        (r) => r.body?.decision === 'ESCALATE',
        () => call('POST', '/v1/authorization/evaluate', agentToken, authorizeBody('75000.00')),
      ),
    );

    samples.push(
      await measure(
        'authorize (DENY)',
        'a resource no lease covers; refused with no approval that could rescue it',
        (r) => r.body?.decision === 'DENY',
        () =>
          call(
            'POST',
            '/v1/authorization/evaluate',
            agentToken,
            authorizeBody('25000.00', 'acct_002'),
          ),
      ),
    );

    // The enforced path. Each iteration needs its own grant, because a grant
    // that could be spent twice would be the bug this boundary exists to
    // prevent -- so the authorize is paid for outside the timed region.
    samples.push(
      await measure(
        'execute (enforced)',
        'two committed transactions with the provider call between them',
        (r) => r.status === 201,
        async () => {
          const authorized = await call(
            'POST',
            '/v1/authorization/evaluate',
            agentToken,
            authorizeBody('25000.00'),
          );
          const context = authorized.body.authorized_intent?.context ?? {
            amount: '25000.00',
            currency: 'USD',
            counterparty_id: 'cp_100',
            destination_country: 'US',
          };
          const started = performance.now();
          const executed = await call('POST', '/v1/execute', agentToken, {
            decision_id: authorized.body.decision_id,
            operation: {
              action: 'wire.execute',
              resource: { type: 'bank_account', id: 'acct_001' },
              context,
            },
          });
          // Timed here rather than by the outer loop, so the authorize that
          // had to set up a fresh grant is excluded.
          return { ...executed, elapsed: performance.now() - started };
        },
        Math.min(ITERATIONS, 200),
      ),
    );

    // -- Under concurrency --------------------------------------------------
    //
    // Sequential p99 hides queueing. This is the number that changes when a
    // partner points ten agents at one node.
    const concurrentMs: number[] = [];
    const perWorker = Math.ceil(ITERATIONS / CONCURRENCY);
    const startedAll = performance.now();
    await Promise.all(
      Array.from({ length: CONCURRENCY }, async () => {
        for (let i = 0; i < perWorker; i += 1) {
          const started = performance.now();
          const result = await call(
            'POST',
            '/v1/authorization/evaluate',
            agentToken,
            authorizeBody('25000.00'),
          );
          if (result.body?.decision !== 'ALLOW') {
            throw new Error(`concurrent authorize: ${JSON.stringify(result.body)}`);
          }
          concurrentMs.push(performance.now() - started);
        }
      }),
    );
    const wallSeconds = (performance.now() - startedAll) / 1000;
    samples.push({
      name: `authorize @${CONCURRENCY} concurrent`,
      note: `${(concurrentMs.length / wallSeconds).toFixed(0)} req/s sustained on one node`,
      count: concurrentMs.length,
      ms: concurrentMs,
    });

    // -- Is the ceiling per tenant or global? -------------------------------
    //
    // Every authorize appends a receipt, and every receipt upserts one row in
    // receipt_chain_heads keyed by organization_id, holding that row's lock
    // until commit. If that is the ceiling, then two tenants have two locks
    // and throughput roughly doubles. If it does not move, the bottleneck is
    // somewhere all tenants share. The measurement decides; a guess would not.
    const second = await seed(ADMIN_URL, { additionalTenant: true });
    await issueLease(second.tokens['admin']!);
    const tenants = [agentToken, second.tokens['treasury_agent']!];

    const splitMs: number[] = [];
    const splitStarted = performance.now();
    await Promise.all(
      Array.from({ length: CONCURRENCY }, async (_unused, worker) => {
        const token = tenants[worker % tenants.length]!;
        for (let i = 0; i < perWorker; i += 1) {
          const started = performance.now();
          const result = await call(
            'POST',
            '/v1/authorization/evaluate',
            token,
            authorizeBody('25000.00'),
          );
          if (result.body?.decision !== 'ALLOW') {
            throw new Error(`two-tenant authorize: ${JSON.stringify(result.body)}`);
          }
          splitMs.push(performance.now() - started);
        }
      }),
    );
    const splitSeconds = (performance.now() - splitStarted) / 1000;
    const splitRps = splitMs.length / splitSeconds;
    samples.push({
      name: `authorize @${CONCURRENCY} across 2 tenants`,
      note: `${splitRps.toFixed(0)} req/s -- the same load split over two receipt chains`,
      count: splitMs.length,
      ms: splitMs,
    });

    const rows = [
      {
        ...summarise({
          name: 'decide (pure function)',
          note: 'no IO, no clock, no server -- the policy engine alone',
          count: pure.length,
          ms: pure,
        }),
      },
      ...samples.map(summarise),
    ];
    table(rows);

    const decideP50 = rows[0]!.p50;
    const authorizeP50 = rows[1]!.p50;
    process.stdout.write(
      `  the policy engine is ${((decideP50 / authorizeP50) * 100).toFixed(2)}% of the ` +
        `authorize endpoint; the rest is Postgres and the socket\n\n`,
    );
    process.stdout.write(
      `  one authorize costs ${commitsPerAuthorize.toFixed(2)} database commits\n\n`,
    );
    process.stdout.write(
      '  measured against SimulatedTreasuryProvider over loopback on one node.\n' +
        '  a real provider dominates the enforced path; a partner adds their RTT.\n' +
        '  this is a floor, not an SLO.\n\n',
    );

    if (process.env['BENCH_JSON']) {
      const { writeFileSync } = await import('node:fs');
      writeFileSync(process.env['BENCH_JSON'], `${JSON.stringify(rows, null, 2)}\n`);
      process.stdout.write(`  wrote ${process.env['BENCH_JSON']}\n\n`);
    }
  } finally {
    await stats.end();
    await app.close();
  }
}

main().catch((error) => {
  process.stderr.write(`\nbenchmark failed: ${error instanceof Error ? error.stack : error}\n`);
  process.exitCode = 1;
});
