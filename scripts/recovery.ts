/**
 * ============================================================================
 * The kill-and-restart recovery harness.
 * ============================================================================
 *
 * The adversarial suite's A9 and A10 simulate a crash by rewinding database
 * state to what a crash would have left behind. That proves the recovery logic
 * is correct given a state; it does not prove that a real crash produces that
 * state.
 *
 * This does. The API runs as a genuine child process. It is destroyed with
 * SIGKILL -- no signal handler, no drain, no chance to write anything -- at
 * two instants that matter, and then a *different* process is started against
 * the same database and asked to do the work again.
 *
 * Everything asserted afterwards is read from durable state written by a
 * process that no longer exists. That is the only way to establish it.
 *
 *   R1  killed after the claim committed, before any money moved.
 *   R2  killed after the money moved, before settlement was recorded.
 *
 * The distinction is invisible to Scrutexity, and that is the point: both must
 * refuse to retry, because a system that could tell them apart from its own
 * records would not need reconciliation in the first place.
 *
 *   R3  the control. No kill. The same path completes, settles, and replays on
 *       retry -- so a failure in R1 or R2 cannot be the harness simply never
 *       having worked.
 *
 * ## Why the provider writes to a database
 *
 * A SIGKILL takes every in-memory record with it. The provider's "external
 * system" is therefore a table in its own schema, on its own connection,
 * committed as it goes -- exactly as a bank's ledger is, and readable from
 * outside the process being killed. See
 * services/api/src/adapter/crash-harness.ts.
 */
import { execSync, spawn, type ChildProcess } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { seed, type SeedResult } from './seed.js';
import { bold, dim, green, red } from './console.js';
import {
  CRASH_HARNESS_SCHEMA,
  type CrashPoint,
} from '../services/api/src/adapter/crash-harness.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const ADMIN_URL =
  process.env['DATABASE_ADMIN_URL'] ??
  'postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity';
const APP_URL =
  process.env['DATABASE_URL'] ?? 'postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity';

const PORT = Number(process.env['RECOVERY_PORT'] ?? 8099);
const BASE = `http://127.0.0.1:${PORT}`;

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// ---------------------------------------------------------------------------
// The provider's ledger, which outlives the process being killed
// ---------------------------------------------------------------------------

async function asAdmin<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: ADMIN_URL });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

async function createProviderLedger(): Promise<void> {
  await asAdmin(async (client) => {
    // Deliberately outside the `scrutexity` schema and outside the migrations.
    // This is the *provider's* store, not Scrutexity's, and conflating the two
    // would be the harness quietly proving something about itself.
    await client.query(`DROP SCHEMA IF EXISTS ${CRASH_HARNESS_SCHEMA} CASCADE`);
    await client.query(`CREATE SCHEMA ${CRASH_HARNESS_SCHEMA}`);
    await client.query(
      `CREATE TABLE ${CRASH_HARNESS_SCHEMA}.ledger (
         idempotency_key    TEXT PRIMARY KEY,
         decision_id        TEXT NOT NULL,
         status             TEXT NOT NULL,
         amount_minor       TEXT NOT NULL,
         account            TEXT NOT NULL,
         external_reference TEXT,
         reached_count      INTEGER NOT NULL DEFAULT 1,
         reached_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
         executed_at        TIMESTAMPTZ
       )`,
    );
  });
}

interface LedgerRow {
  status: string;
  reached_count: number;
  external_reference: string | null;
  amount_minor: string;
}

const ledgerFor = (decisionId: string) =>
  asAdmin(async (client) => {
    const rows = await client.query<LedgerRow>(
      `SELECT status, reached_count, external_reference, amount_minor
         FROM ${CRASH_HARNESS_SCHEMA}.ledger WHERE decision_id = $1`,
      [decisionId],
    );
    return rows.rows;
  });

// ---------------------------------------------------------------------------
// The API, as a real process
// ---------------------------------------------------------------------------

class ApiProcess {
  #child: ChildProcess | null = null;
  #stderr = '';

  async start(crashPoint: CrashPoint): Promise<void> {
    this.#stderr = '';
    const child = spawn('pnpm', ['exec', 'tsx', 'services/api/src/server.ts'], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      // Its own process group, so the SIGKILL below can take the whole tree.
      // `pnpm exec tsx` is a wrapper around the process that actually holds the
      // socket; killing only the wrapper would leave a live server bound to the
      // port and the "crash" would not have happened. Without `detached` the
      // child shares this process's group and a group kill would kill the
      // harness.
      detached: true,
      env: {
        ...process.env,
        NODE_ENV: 'development',
        DATABASE_URL: APP_URL,
        LOG_LEVEL: 'silent',
        PORT: String(PORT),
        HOST: '127.0.0.1',
        EXECUTION_PROVIDERS: 'crash-harness',
        CRASH_HARNESS_URL: ADMIN_URL,
        CRASH_HARNESS_POINT: crashPoint,
      },
    });
    this.#child = child;
    // Captured rather than inherited: a silent child that failed to boot is
    // the hardest thing to diagnose in a harness like this.
    child.stderr?.on('data', (chunk) => (this.#stderr += String(chunk)));
    child.stdout?.on('data', (chunk) => (this.#stderr += String(chunk)));

    const deadline = Date.now() + 90_000;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) {
        throw new Error(`the api process exited during boot (${child.exitCode}): ${this.#stderr}`);
      }
      try {
        const response = await fetch(`${BASE}/ready`);
        if (response.status === 200) return;
      } catch {
        // Not listening yet.
      }
      await sleep(200);
    }
    throw new Error(`the api process did not become ready: ${this.#stderr}`);
  }

  /**
   * SIGKILL, never SIGTERM.
   *
   * The server installs handlers for SIGTERM and SIGINT that drain in-flight
   * requests before exiting -- which is right in production and would defeat
   * this entirely. A graceful shutdown gives the in-flight execution a chance
   * to finish and settle, and then nothing has crashed. SIGKILL cannot be
   * caught, so the process stops between two instructions with no opportunity
   * to write anything.
   *
   * `pnpm exec tsx` means the child is a shell wrapper around the process that
   * holds the socket, so the whole process group is killed rather than the
   * wrapper alone -- killing only the parent would leave a live server bound
   * to the port and the "crash" would not have happened.
   */
  async kill(): Promise<void> {
    const child = this.#child;
    if (!child) return;
    this.#child = null;
    try {
      if (child.pid) process.kill(-child.pid, 'SIGKILL');
    } catch {
      child.kill('SIGKILL');
    }
    child.kill('SIGKILL');
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) return resolve();
      child.on('exit', () => resolve());
    });
    // The replacement cannot bind the port until nothing is listening on it.
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline) {
      try {
        await fetch(`${BASE}/health`);
      } catch {
        return;
      }
      await sleep(100);
    }
    throw new Error('something is still listening after SIGKILL');
  }
}

// ---------------------------------------------------------------------------
// Driving the control plane
// ---------------------------------------------------------------------------

async function call(method: string, path: string, token: string, body?: unknown) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

let nonceCounter = 0;

const wireContext = () => ({
  amount: '25000.00',
  currency: 'USD',
  counterparty_id: 'cp_100',
  destination_country: 'US',
});

/** Issues a lease and takes one wire request all the way to an ALLOW. */
async function authorizeAWire(fixtures: SeedResult) {
  const lease = await call('POST', '/v1/authority-leases', fixtures.tokens['admin']!, {
    agent_id: 'treasury-agent',
    grant: {
      actions: ['wire.create', 'wire.submit', 'wire.execute', 'counterparty.read', 'account.read'],
      resources: { bank_account: ['acct_001'], counterparty: ['cp_100'] },
      constraints: {
        max_amount: { currency: 'USD', amountMinor: '5000000' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    },
    ttl_seconds: 3600,
    // Single-use, so "the grant is spent" is a real assertion about durable
    // state rather than a statement about the claim row alone. This is the
    // case that matters: a reusable lease surviving a crash proves the claim's
    // UNIQUE (decision_id) held, while a single-use one also proves the
    // consumption committed in the same transaction as the claim -- which is
    // the pair that has to be atomic for the grant not to become spendable
    // again when the process dies.
    grant_type: 'SINGLE_USE',
  });
  assert(lease.status === 201, `lease issuance failed: ${JSON.stringify(lease.body)}`);

  const decision = await call(
    'POST',
    '/v1/authorization/evaluate',
    fixtures.tokens['treasury_agent']!,
    {
      agent_id: 'treasury-agent',
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: wireContext(),
      nonce: `recovery-${(nonceCounter += 1)}`,
      authority_lease_id: lease.body.authority_lease.id,
    },
  );
  assert(
    decision.body.decision === 'ALLOW',
    `expected ALLOW, got ${decision.body.decision} (${decision.body.reason_code})`,
  );
  return {
    decisionId: decision.body.decision_id as string,
    operation: {
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: wireContext(),
    },
  };
}

/**
 * Fires an execution that is expected never to return, and resolves once the
 * provider's ledger shows it arrived.
 *
 * The request is deliberately not awaited: the provider blocks forever, so
 * awaiting it would deadlock the harness. What is awaited is the *external*
 * evidence that the provider was reached, read on a connection that cannot see
 * anything the API process has left uncommitted. So the kill lands at an
 * instant the harness chose rather than one it raced for.
 */
async function executeUntilProviderReached(
  fixtures: SeedResult,
  decisionId: string,
  operation: unknown,
): Promise<void> {
  // Losing this response is the expected outcome; the process is about to die.
  void call('POST', '/v1/execute', fixtures.tokens['treasury_agent']!, {
    decision_id: decisionId,
    operation,
  }).catch(() => undefined);

  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if ((await ledgerFor(decisionId)).length > 0) return;
    await sleep(100);
  }
  throw new Error('the provider was never reached');
}

interface ClaimRow {
  state: string;
  idempotency_key: string;
  consumed: boolean;
}

const claimFor = (fixtures: SeedResult, decisionId: string) =>
  asAdmin(async (client) => {
    await client.query('SELECT set_config($1,$2,false)', [
      'scrutexity.org_id',
      fixtures.organization_id,
    ]);
    const rows = await client.query<ClaimRow>(
      `SELECT c.state, c.idempotency_key, l.consumed
         FROM scrutexity.execution_claims c
         JOIN scrutexity.authorization_decisions d ON d.id = c.decision_id
         JOIN scrutexity.authority_leases l ON l.id = d.authority_lease_id
        WHERE c.decision_id = $1`,
      [decisionId],
    );
    return rows.rows;
  });

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

interface Result {
  id: string;
  title: string;
  passed: boolean;
  moneyMoved: string;
  detail: string;
}

async function crashScenario(
  api: ApiProcess,
  fixtures: SeedResult,
  crashPoint: Exclude<CrashPoint, 'none'>,
) {
  await api.start(crashPoint);
  const { decisionId, operation } = await authorizeAWire(fixtures);

  await executeUntilProviderReached(fixtures, decisionId, operation);

  // The provider is blocked. Whatever it was going to do, it has already done.
  const beforeKill = await ledgerFor(decisionId);
  assert(beforeKill.length === 1, `expected one ledger row, got ${beforeKill.length}`);
  const moneyMoved = beforeKill[0]!.status === 'EXECUTED';
  assert(
    moneyMoved === (crashPoint === 'after_payment'),
    `the provider was in the wrong state for ${crashPoint}: ${beforeKill[0]!.status}`,
  );

  // The claim must already be committed and externally visible. This is G-16
  // re-proven against a real process rather than a rewind: were the claim still
  // uncommitted here, the kill below would roll it back and the grant would be
  // spendable again -- with the money, in R2, already gone.
  const claimBefore = await claimFor(fixtures, decisionId);
  assert(claimBefore.length === 1, 'the claim was not committed before the provider was reached');
  assert(
    claimBefore[0]!.state === 'EXECUTING',
    `expected an EXECUTING claim, got ${claimBefore[0]!.state}`,
  );
  assert(claimBefore[0]!.consumed, 'the grant was not consumed before the provider call');
  const originalKey = claimBefore[0]!.idempotency_key;

  await api.kill();

  // -- A different process, same database ------------------------------------
  await api.start(crashPoint);

  const retry = await call('POST', '/v1/execute', fixtures.tokens['treasury_agent']!, {
    decision_id: decisionId,
    operation,
  });

  assert(
    retry.status === 409,
    `the retry was not refused: ${retry.status} ${JSON.stringify(retry.body)}`,
  );
  assert(
    // REPLAY_DETECTED would tell the caller the work is finished. In R1 that is
    // false; in R2 nobody knows -- which is the same answer to the caller.
    retry.body.error.code === 'EXECUTION_UNRESOLVED',
    `expected EXECUTION_UNRESOLVED, got ${retry.body.error.code}`,
  );

  const ledgerAfter = await ledgerFor(decisionId);
  assert(
    ledgerAfter[0]!.reached_count === 1,
    `the provider was contacted again on retry (${ledgerAfter[0]!.reached_count} times)`,
  );
  assert(
    ledgerAfter[0]!.status === beforeKill[0]!.status,
    'the external system changed state on a refused retry',
  );

  const claimAfter = await claimFor(fixtures, decisionId);
  assert(claimAfter.length === 1, 'the claim did not survive the kill');
  assert(claimAfter[0]!.consumed, 'the grant became spendable again after the crash');
  assert(
    claimAfter[0]!.idempotency_key === originalKey,
    'the idempotency key changed; a reconciling operator would create a second payment',
  );

  // It has to be findable. An unresolved claim nobody can list is an
  // unresolved claim nobody reconciles.
  const unresolved = await call('GET', '/v1/executions/unresolved', fixtures.tokens['admin']!);
  assert(
    unresolved.body.unresolved.some(
      (row: { decision_id: string; idempotency_key: string }) =>
        row.decision_id === decisionId && row.idempotency_key === originalKey,
    ),
    'the claim was not surfaced for reconciliation under its original key',
  );

  await api.kill();

  return {
    moneyMoved: moneyMoved ? `${beforeKill[0]!.amount_minor} minor units` : 'nothing',
    detail: '409 EXECUTION_UNRESOLVED, provider contacted once, grant spent, key preserved',
  };
}

async function controlScenario(api: ApiProcess, fixtures: SeedResult) {
  await api.start('none');
  const { decisionId, operation } = await authorizeAWire(fixtures);

  const executed = await call('POST', '/v1/execute', fixtures.tokens['treasury_agent']!, {
    decision_id: decisionId,
    operation,
  });
  assert(
    executed.status === 201,
    `the uninterrupted path did not complete: ${executed.status} ${JSON.stringify(executed.body)}`,
  );
  assert(executed.body.status === 'EXECUTED', `expected EXECUTED, got ${executed.body.status}`);

  const claim = await claimFor(fixtures, decisionId);
  assert(claim[0]!.state === 'EXECUTED', `expected a settled claim, got ${claim[0]!.state}`);

  // A retry against a *settled* claim replays rather than refusing, so the 409s
  // above are the crash state speaking and not a blanket refusal to retry.
  const replay = await call('POST', '/v1/execute', fixtures.tokens['treasury_agent']!, {
    decision_id: decisionId,
    operation,
  });
  assert(replay.status === 200, `expected a replay, got ${replay.status}`);
  assert(replay.body.replayed === true, 'the replay was not marked as one');

  const ledger = await ledgerFor(decisionId);
  assert(ledger[0]!.reached_count === 1, 'the provider was contacted twice for one grant');

  await api.kill();
  return {
    moneyMoved: `${ledger[0]!.amount_minor} minor units`,
    detail: '201 EXECUTED, then 200 replayed; the provider was contacted once',
  };
}

// ---------------------------------------------------------------------------

const titleOf = (
  manifest: { scenarios: { scenario_id: string; title: string }[] },
  id: string,
): string => {
  const entry = manifest.scenarios.find((scenario) => scenario.scenario_id === id);
  if (!entry) throw new Error(`scenario ${id} is implemented but not declared in the manifest`);
  return entry.title;
};

async function main() {
  process.stdout.write(`\n${bold('ALTUS RECOVERY HARNESS')}\n\n`);
  process.stdout.write(dim('  provisioning a clean database\n'));
  execSync('pnpm exec tsx scripts/migrate.ts --reset', {
    stdio: 'ignore',
    env: { ...process.env, DATABASE_ADMIN_URL: ADMIN_URL },
  });
  await createProviderLedger();
  const fixtures = await seed(ADMIN_URL);

  const api = new ApiProcess();
  const results: Result[] = [];

  // The manifest is the contract. A scenario listed there with no
  // implementation here fails the run, so the registry a reviewer reads cannot
  // drift away from what actually executes.
  const manifest = JSON.parse(readFileSync(join(root, 'test/recovery-manifest.json'), 'utf8')) as {
    scenarios: { scenario_id: string; title: string }[];
  };

  const scenarios = [
    {
      id: 'R1',
      title: titleOf(manifest, 'R1'),
      run: () => crashScenario(api, fixtures, 'before_payment'),
    },
    {
      id: 'R2',
      title: titleOf(manifest, 'R2'),
      run: () => crashScenario(api, fixtures, 'after_payment'),
    },
    {
      id: 'R3',
      title: titleOf(manifest, 'R3'),
      run: () => controlScenario(api, fixtures),
    },
  ];

  const declared = manifest.scenarios.map((entry) => entry.scenario_id);
  const implemented = scenarios.map((entry) => entry.id);
  const missing = declared.filter((id) => !implemented.includes(id));
  if (missing.length > 0) {
    throw new Error(
      `the manifest declares scenarios with no implementation: ${missing.join(', ')}`,
    );
  }

  process.stdout.write('\n');
  for (const scenario of scenarios) {
    const label = `  [${scenario.id}] ${scenario.title}`.padEnd(58, '.');
    try {
      const outcome = await scenario.run();
      results.push({ id: scenario.id, title: scenario.title, passed: true, ...outcome });
      process.stdout.write(`${label} ${green('PASS')}\n`);
    } catch (error) {
      await api.kill().catch(() => undefined);
      const detail = error instanceof Error ? error.message : String(error);
      results.push({
        id: scenario.id,
        title: scenario.title,
        passed: false,
        moneyMoved: 'unknown',
        detail,
      });
      process.stdout.write(`${label} ${red('FAIL')}\n`);
      process.stdout.write(`       ${red(detail)}\n`);
    }
  }

  process.stdout.write(`\n  ${bold('SCENARIO')}  ${bold('RESULT')}  ${bold('MONEY MOVED')}\n`);
  for (const result of results) {
    process.stdout.write(
      `  ${result.id.padEnd(9)} ${(result.passed ? 'PASS' : 'FAIL').padEnd(7)} ` +
        `${result.moneyMoved.padEnd(22)} ${dim(result.detail)}\n`,
    );
  }

  const passed = results.filter((r) => r.passed).length;
  const line =
    passed === results.length
      ? `RESULT: ${passed}/${results.length} RECOVERY INVARIANTS HOLD ACROSS A REAL PROCESS DEATH`
      : `RESULT: ${results.length - passed}/${results.length} FAILED`;
  process.stdout.write(
    `\n  ${passed === results.length ? green(bold(line)) : red(bold(line))}\n\n`,
  );
  if (passed !== results.length) process.exitCode = 1;
}

await main();
