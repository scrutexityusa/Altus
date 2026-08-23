/**
 * ============================================================================
 * Altus adversarial conformance.
 * ============================================================================
 *
 * Eleven system-level security invariants, run end to end against a real
 * database and a recording provider. Not a subset of the unit suite with
 * dramatic names: each scenario mounts an actual attack through the public
 * API and reports whether the invariant held, whether the provider was
 * contacted, and whether evidence was produced.
 *
 * The registry is `test/adversarial-manifest.json`. A scenario declared there
 * and not implemented here fails the run -- the manifest is the contract, not
 * a wish list.
 *
 *   make adversarial
 *
 * Exits non-zero if any invariant fails, so CI can gate on it.
 */
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { buildApp } from '../services/api/src/app.js';
import { newId, signSignalHmac } from '@scrutexity/core';
import { seed, type SeedResult } from './seed.js';
import { signedSignal } from './signal-source.js';
import { bold, dim, green, red } from './console.js';
import {
  ProviderRegistry,
  type ExecutionProvider,
  type ProviderOutcome,
  type ProviderRequest,
} from '../services/api/src/adapter/provider.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const ADMIN_URL =
  process.env['DATABASE_ADMIN_URL'] ??
  'postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity';
const APP_URL =
  process.env['DATABASE_URL'] ?? 'postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity';

// ---------------------------------------------------------------------------
// The recording provider
// ---------------------------------------------------------------------------

/**
 * Wraps execution so every scenario can answer "was the provider contacted?"
 * without inferring it from a side effect.
 *
 * `observe` runs at the moment `execute` is called, on a connection that has
 * nothing to do with the request. That is what makes A11 a real assertion
 * rather than a claim: an independent connection cannot see uncommitted work,
 * so if it sees the claim, the claim was committed before the provider was
 * reached.
 */
class RecordingProvider implements ExecutionProvider {
  readonly name = 'adversarial-recorder';
  readonly idempotent = true;
  readonly actions = ['wire.execute', 'wire.submit', 'wire.create'] as const;

  calls: ProviderRequest[] = [];
  /** What an outside observer could see at the instant execute() was entered. */
  observations: { decisionId: string; claimVisible: boolean; grantConsumed: boolean | null }[] = [];
  mode: 'succeed' | 'timeout' | 'fail' = 'succeed';
  #settled = new Map<string, ProviderOutcome>();

  reset() {
    this.calls = [];
    this.observations = [];
    this.mode = 'succeed';
    this.#settled.clear();
  }

  async execute(request: ProviderRequest): Promise<ProviderOutcome> {
    this.calls.push(request);
    await this.#observe(request);

    const settled = this.#settled.get(request.idempotencyKey);
    if (settled) return settled;

    if (this.mode === 'timeout') {
      return { status: 'UNKNOWN', error: 'simulated timeout', detail: { simulated: true } };
    }
    if (this.mode === 'fail') {
      const outcome: ProviderOutcome = {
        status: 'FAILED',
        error: 'simulated rejection',
        detail: { simulated: true },
      };
      this.#settled.set(request.idempotencyKey, outcome);
      return outcome;
    }
    const outcome: ProviderOutcome = {
      status: 'EXECUTED',
      external_reference: `adv-${request.idempotencyKey.slice(-10)}`,
      detail: { simulated: true },
    };
    this.#settled.set(request.idempotencyKey, outcome);
    return outcome;
  }

  async #observe(request: ProviderRequest) {
    const client = new pg.Client({ connectionString: ADMIN_URL });
    await client.connect();
    try {
      await client.query('SELECT set_config($1,$2,false)', [
        'scrutexity.org_id',
        request.organizationId,
      ]);
      const claim = await client.query(
        `SELECT c.state, l.consumed
           FROM scrutexity.execution_claims c
           JOIN scrutexity.authorization_decisions d ON d.id = c.decision_id
           LEFT JOIN scrutexity.authority_leases l ON l.id = d.authority_lease_id
          WHERE c.decision_id = $1`,
        [request.decisionId],
      );
      this.observations.push({
        decisionId: request.decisionId,
        claimVisible: (claim.rowCount ?? 0) > 0,
        grantConsumed: (claim.rows[0]?.consumed as boolean | null) ?? null,
      });
    } finally {
      await client.end();
    }
  }
}

const provider = new RecordingProvider();

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface Ctx {
  call: (
    method: string,
    path: string,
    token: string,
    body?: unknown,
  ) => Promise<{ status: number; body: any }>;
  asOwner: (fn: (client: pg.Client) => Promise<void>) => Promise<void>;
  t: Record<string, string>;
  fixtures: SeedResult;
  provider: RecordingProvider;
}

interface Outcome {
  id: string;
  title: string;
  passed: boolean;
  providerContacted: boolean;
  evidence: string;
  detail: string;
}

let nonceCounter = 0;
const nonce = (prefix: string) => `adv-${prefix}-${(nonceCounter += 1)}`;

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

async function main() {
  process.stdout.write(`\n${bold('ALTUS ADVERSARIAL CONFORMANCE')}\n\n`);
  process.stdout.write(dim('  provisioning a clean database\n'));
  execSync('pnpm exec tsx scripts/migrate.ts --reset', {
    stdio: 'ignore',
    env: { ...process.env, DATABASE_ADMIN_URL: ADMIN_URL },
  });
  const fixtures: SeedResult = await seed(ADMIN_URL);

  const app = await buildApp(
    { NODE_ENV: 'development', DATABASE_URL: APP_URL, LOG_LEVEL: 'silent' },
    // The recorder replaces the simulated treasury, so every scenario can see
    // exactly what reached the outside world rather than inferring it.
    new ProviderRegistry([provider]),
  );

  await app.server.listen({ port: 0, host: '127.0.0.1' });
  const address = app.server.addresses()[0]!;
  const base = `http://127.0.0.1:${address.port}`;

  const call: Ctx['call'] = async (method, path, token, body) => {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
  };

  const asOwner: Ctx['asOwner'] = async (fn) => {
    const client = new pg.Client({ connectionString: ADMIN_URL });
    await client.connect();
    try {
      await client.query('SELECT set_config($1,$2,false)', [
        'scrutexity.org_id',
        fixtures.organization_id,
      ]);
      await fn(client);
    } finally {
      await client.end();
    }
  };

  const ctx: Ctx = { call, asOwner, t: fixtures.tokens, fixtures, provider };

  const manifest = JSON.parse(
    readFileSync(join(root, 'test/adversarial-manifest.json'), 'utf8'),
  ) as { scenarios: { scenario_id: string; title: string }[] };

  const scenarios: Record<string, (c: Ctx) => Promise<{ evidence: string; detail: string }>> = {
    A1: temporalExpiry,
    A2: revocation,
    A3: authorityDrift,
    A4: privilegeSynthesis,
    A5: isolationAndEnumeration,
    A6: clockDisagreement,
    A7: signalContainment,
    A8: replayAndConcurrency,
    A9: crashBeforeProvider,
    A10: providerSuccessSettlementCrash,
    A11: transactionFaultInjection,
    A12: omission,
  };

  const results: Outcome[] = [];
  for (const declared of manifest.scenarios) {
    const run = scenarios[declared.scenario_id];
    provider.reset();
    if (!run) {
      results.push({
        id: declared.scenario_id,
        title: declared.title,
        passed: false,
        providerContacted: false,
        evidence: '-',
        detail: 'declared in the manifest but not implemented',
      });
      continue;
    }
    try {
      const { evidence, detail } = await run(ctx);
      results.push({
        id: declared.scenario_id,
        title: declared.title,
        passed: true,
        providerContacted: provider.calls.length > 0,
        evidence,
        detail,
      });
    } catch (error) {
      results.push({
        id: declared.scenario_id,
        title: declared.title,
        passed: false,
        providerContacted: provider.calls.length > 0,
        evidence: '-',
        detail: error instanceof Error ? error.message : String(error),
      });
    }
  }

  report(results);
  await app.db.close();
  await app.server.close();
  process.exit(results.every((r) => r.passed) ? 0 : 1);
}

function report(results: Outcome[]) {
  process.stdout.write('\n');
  for (const r of results) {
    const label = `[${r.id}] ${r.title}`.padEnd(40, '.');
    const verdict = r.passed ? green('PASS') : red('FAIL');
    process.stdout.write(`  ${label} ${verdict}\n`);
    if (!r.passed) process.stdout.write(`       ${red(r.detail)}\n`);
  }

  const held = results.filter((r) => r.passed).length;
  process.stdout.write('\n');
  process.stdout.write(
    `  ${bold('SCENARIO')}  ${bold('RESULT')}  ${bold('PROVIDER')}  ${bold('EVIDENCE')}\n`,
  );
  for (const r of results) {
    process.stdout.write(
      `  ${r.id.padEnd(9)} ${(r.passed ? 'PASS' : 'FAIL').padEnd(7)} ` +
        `${(r.providerContacted ? 'contacted' : 'not called').padEnd(9)} ${r.evidence}\n`,
    );
  }

  const line = `RESULT: ${held}/${results.length} SECURITY INVARIANTS HOLD`;
  process.stdout.write(`\n  ${held === results.length ? green(bold(line)) : red(bold(line))}\n\n`);
}

// ---------------------------------------------------------------------------
// A12 -- the omission attack class
// ---------------------------------------------------------------------------

/**
 * Every other scenario here attacks by *changing* something. This one attacks
 * by taking something away, which is the axis the suite was blind on and the
 * axis that produced both holes found so far:
 *
 *   signal plane          a signature against an unenrolled source was
 *                         ignored rather than refused, so attaching any bytes
 *                         at all was equivalent to attaching none
 *   evidence chain        verification skipped the signature check whenever
 *                         `signature` was null, so a forger with database
 *                         write access deleted the signature they could not
 *                         mint and the chain reported intact
 *
 * The shape both share: a control written as `if (field) { check(field) }` is
 * not a control, because the attacker chooses whether `field` is there.
 *
 * So rather than a handful of hand-written cases, this generates them. For
 * each security-bearing field of each request, it sends six corruptions and
 * requires a refusal for all of them.
 */
const OMISSION_VARIANTS = [
  { name: 'absent', apply: (): typeof ABSENT => ABSENT },
  { name: 'null', apply: () => null },
  { name: 'empty string', apply: () => '' },
  { name: 'empty array', apply: () => [] },
  { name: 'empty object', apply: () => ({}) },
  // Not omission strictly, but the same family: the field is present and
  // carries nothing the checker can use. A validator that reaches for
  // `.length` or `.type` on this is one that was never asked the question.
  //
  // `true` rather than `0`, because `0` is a legitimate spelling of an amount
  // -- the API accepts an integer number of major units and normalises it the
  // same way it normalises "0.00". A boolean is a value no field here takes.
  { name: 'wrong type', apply: () => true },
] as const;

/** Sentinel meaning "delete this key" rather than "set it to undefined". */
const ABSENT = Symbol('absent');

function corrupt(body: unknown, path: string, value: unknown): unknown {
  const clone = structuredClone(body) as Record<string, unknown>;
  const segments = path.split('.');
  let cursor: Record<string, unknown> = clone;
  for (const segment of segments.slice(0, -1)) {
    const next = cursor[segment];
    if (typeof next !== 'object' || next === null) return clone;
    cursor = next as Record<string, unknown>;
  }
  const leaf = segments[segments.length - 1]!;
  if (value === ABSENT) delete cursor[leaf];
  else cursor[leaf] = value;
  return clone;
}

interface OmissionTarget {
  name: string;
  path: string;
  token: (c: Ctx) => string;
  /** A body that is known to succeed, rebuilt per call so nothing is reused. */
  body: (c: Ctx) => Promise<Record<string, unknown>>;
  /** Dot paths whose corruption must be refused. */
  required: readonly string[];
  /**
   * Dot paths a caller may legitimately omit, and why.
   *
   * This list is the point of the exercise as much as the assertions are: it
   * is the complete, reviewed set of things a request is allowed to leave out.
   * A field belongs here only with a reason somebody would defend out loud.
   */
  optional: Readonly<Record<string, string>>;
  /**
   * What counts as the attack having worked.
   *
   * Not simply `status < 400`. `POST /v1/authorization/evaluate` answers a
   * refusal with **200 and `decision: DENY`** -- the request was well-formed
   * and the answer is no. Treating that as acceptance was the first thing this
   * generator got wrong, and it reported five holes that were not there.
   */
  accepted: (response: { status: number; body: any }) => boolean;
}

const acceptedByStatus = (response: { status: number }) => response.status < 400;

async function omission(c: Ctx) {
  const targets: OmissionTarget[] = [
    {
      name: 'POST /v1/authorization/evaluate',
      path: '/v1/authorization/evaluate',
      token: (ctx) => ctx.t['treasury_agent']!,
      body: async (ctx) => {
        await issueLease(ctx);
        return wire({ nonce: nonce('a12-eval') });
      },
      required: [
        'agent_id',
        'action',
        'resource',
        'resource.type',
        'resource.id',
        'context',
        'context.amount',
        'context.currency',
        'context.counterparty_id',
      ],
      // An ALLOW is the only outcome that hands out authority. A DENY at 200 is
      // the control working, and an ESCALATE issues no execution grant.
      accepted: (response) => response.status < 400 && response.body?.decision === 'ALLOW',
      optional: {
        nonce:
          'client-side replay protection; omitting it forgoes the caller’s own idempotency and grants nothing',
        'context.destination_country':
          'a policy input, not an identity: absent means the sanctions condition does not match, which is the fail-closed direction',
      },
    },
    {
      name: 'POST /v1/execute',
      path: '/v1/execute',
      token: (ctx) => ctx.t['treasury_agent']!,
      body: async (ctx) => {
        const { decision, operation } = await allow(ctx, 'a12-exec');
        return { decision_id: decision.decision_id, operation };
      },
      required: [
        'decision_id',
        'operation',
        'operation.action',
        'operation.resource',
        'operation.resource.type',
        'operation.resource.id',
        'operation.context',
        'operation.context.amount',
        'operation.context.currency',
        'operation.context.counterparty_id',
      ],
      optional: {},
      accepted: acceptedByStatus,
    },
    {
      name: 'POST /v1/authority-leases',
      path: '/v1/authority-leases',
      token: (ctx) => ctx.t['admin']!,
      body: async () => ({
        agent_id: 'treasury-agent',
        grant: {
          actions: ['wire.execute'],
          resources: { bank_account: ['acct_001'], counterparty: ['cp_100'] },
          constraints: {
            max_amount: { currency: 'USD', amount: '50000.00' },
            currencies: ['USD'],
            allowed_counterparties: ['cp_100'],
          },
        },
        ttl_seconds: 3600,
      }),
      required: ['agent_id', 'grant', 'grant.actions', 'ttl_seconds'],
      optional: {
        'grant.constraints':
          'a grant with no constraints is still bounded by its actions and resources, and the issuance ceiling is checked either way',
        'grant.resources':
          'absent means NO resources, not all of them -- proved by resourcelessLeaseAuthorisesNothing below rather than asserted here',
      },
      accepted: acceptedByStatus,
    },
    {
      name: 'POST /v1/signals',
      path: '/v1/signals',
      token: (ctx) => ctx.t['fraud_engine']!,
      body: async (ctx) =>
        signedSignal(ctx.fixtures, {
          subject: { type: 'agent', id: ctx.fixtures.agents['treasury']! },
          signal_type: 'fraud_risk',
          value: '0.01',
          source: 'external_fraud_engine',
          ttl_seconds: 600,
          event_id: nonce('a12-signal'),
        }) as unknown as Record<string, unknown>,
      required: [
        'source',
        'subject',
        'subject.type',
        'subject.id',
        'signal_type',
        'value',
        'signature',
        'signing_key_id',
      ],
      accepted: acceptedByStatus,
      optional: {
        ttl_seconds:
          'a signal with no stated lifetime takes the policy’s default, which is shorter than any caller would choose',
      },
    },
    {
      name: 'POST /v1/credentials',
      path: '/v1/credentials',
      token: (ctx) => ctx.t['admin']!,
      body: async (ctx) => ({
        principal_type: 'user',
        principal_id: ctx.fixtures.users['treasurer']!,
        scopes: ['read'],
        expires_in_seconds: 3600,
      }),
      required: ['principal_type', 'principal_id', 'scopes', 'expires_in_seconds'],
      optional: {},
      accepted: acceptedByStatus,
    },
  ];

  let checked = 0;
  const failures: string[] = [];

  for (const target of targets) {
    // The control. Without this the whole scenario passes vacuously the moment
    // a body stops being valid for an unrelated reason -- every corruption is
    // refused, and so is the thing they were corruptions of.
    const control = await c.call('POST', target.path, target.token(c), await target.body(c));
    if (control.status >= 400) {
      failures.push(
        `${target.name}: the uncorrupted control was refused (${control.status} ` +
          `${JSON.stringify(control.body)}), so nothing below proves anything`,
      );
      continue;
    }

    for (const field of target.required) {
      for (const variant of OMISSION_VARIANTS) {
        const body = corrupt(await target.body(c), field, variant.apply());
        const response = await c.call('POST', target.path, target.token(c), body);
        checked += 1;
        if (target.accepted(response)) {
          failures.push(
            `${target.name}: ${field} = ${variant.name} was ACCEPTED ` +
              `(${response.status} ${response.body?.decision ?? ''})`,
          );
        }
      }
    }
  }

  checked += await resourcelessLeaseAuthorisesNothing(c, failures);

  assert(failures.length === 0, failures.join('; '));
  return {
    // The count is in the summary rather than buried in a failure message: a
    // generator that silently stopped generating would otherwise still read as
    // a pass.
    evidence: `${checked} refusals`,
    detail: `${checked} corruptions across ${targets.length} endpoints, all refused`,
  };
}

/**
 * The one omission the lease endpoint accepts, held to what it must mean.
 *
 * A grant with no `resources` is issued. That is only safe if absent means
 * *no* resources rather than *all* of them -- the difference between a useless
 * lease and unbounded authority conjured out of a missing key. Exempting the
 * field in the `optional` list would assert that in a comment; this proves it.
 */
async function resourcelessLeaseAuthorisesNothing(c: Ctx, failures: string[]): Promise<number> {
  const issued = await c.call('POST', '/v1/authority-leases', c.t['admin']!, {
    agent_id: 'verification-agent',
    grant: {
      actions: ['wire.execute'],
      constraints: {
        max_amount: { currency: 'USD', amount: '50000.00' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    },
    ttl_seconds: 3600,
  });
  if (issued.status !== 201) {
    // Refusing to issue it is also a correct answer, and a stricter one.
    return 1;
  }

  // A second agent with no other lease, so nothing else can be the source of
  // an ALLOW. Under the resource-less grant, every resource must be refused.
  for (const account of ['acct_001', 'acct_002', 'acct_999']) {
    const decision = await c.call(
      'POST',
      '/v1/authorization/evaluate',
      c.t['verification_agent']!,
      {
        agent_id: 'verification-agent',
        action: 'wire.execute',
        resource: { type: 'bank_account', id: account },
        context: {
          amount: '25000.00',
          currency: 'USD',
          counterparty_id: 'cp_100',
          destination_country: 'US',
        },
        nonce: nonce(`a12-resourceless-${account}`),
      },
    );
    if (decision.body?.decision === 'ALLOW') {
      failures.push(
        `a lease with no grant.resources authorised ${account}: ` +
          'an omitted field granted more than any present value could',
      );
    }
  }
  return 3;
}

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const wire = (over: Record<string, unknown> = {}) => ({
  agent_id: 'treasury-agent',
  action: 'wire.execute',
  resource: { type: 'bank_account', id: 'acct_001' },
  context: {
    amount: '25000.00',
    currency: 'USD',
    counterparty_id: 'cp_100',
    destination_country: 'US',
  },
  ...over,
});

const operationOf = (request: ReturnType<typeof wire>) => ({
  action: request.action,
  resource: request.resource,
  context: request.context,
});

async function issueLease(c: Ctx, over: Record<string, unknown> = {}) {
  const response = await c.call('POST', '/v1/authority-leases', c.t['admin']!, {
    agent_id: 'treasury-agent',
    grant: {
      actions: ['wire.create', 'wire.submit', 'wire.execute', 'counterparty.read', 'account.read'],
      resources: { bank_account: ['acct_001', 'acct_002'], counterparty: ['cp_100', 'cp_101'] },
      constraints: {
        max_amount: { currency: 'USD', amount: '50000.00' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100', 'cp_101'],
      },
    },
    ttl_seconds: 3600,
    ...over,
  });
  assert(response.status === 201, `lease issuance failed: ${JSON.stringify(response.body)}`);
  return response.body.authority_lease;
}

async function allow(c: Ctx, tag: string, over: Record<string, unknown> = {}) {
  await issueLease(c);
  const request = wire({ nonce: nonce(tag), ...over });
  const decision = await c.call(
    'POST',
    '/v1/authorization/evaluate',
    c.t['treasury_agent']!,
    request,
  );
  assert(
    decision.body.decision === 'ALLOW',
    `expected ALLOW, got ${decision.body.decision} (${decision.body.reason_code})`,
  );
  return { decision: decision.body, operation: operationOf(request) };
}

async function countSecurityEvents(c: Ctx, kind: string): Promise<number> {
  let n = 0;
  await c.asOwner(async (client) => {
    const row = await client.query(
      'SELECT count(*)::int AS n FROM scrutexity.security_events WHERE kind = $1',
      [kind],
    );
    n = row.rows[0].n as number;
  });
  return n;
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

async function temporalExpiry(c: Ctx) {
  const lease = await issueLease(c);
  await c.asOwner(async (client) => {
    await client.query(
      `UPDATE scrutexity.authority_leases
          SET issued_at = now() - interval '2 hours', expires_at = now() - interval '1 second'
        WHERE id = $1`,
      [lease.id],
    );
  });
  const decision = await c.call('POST', '/v1/authorization/evaluate', c.t['treasury_agent']!, {
    ...wire({ nonce: nonce('a1') }),
    authority_lease_id: lease.id,
  });
  assert(decision.body.decision === 'DENY', `expected DENY, got ${decision.body.decision}`);
  assert(
    decision.body.reason_code === 'AUTHORITY_EXPIRED',
    `expected AUTHORITY_EXPIRED, got ${decision.body.reason_code}`,
  );
  assert(provider.calls.length === 0, 'the provider was contacted for expired authority');

  let claims = 0;
  await c.asOwner(async (client) => {
    const row = await client.query('SELECT count(*)::int AS n FROM scrutexity.execution_claims');
    claims = row.rows[0].n as number;
  });
  assert(claims === 0, 'an execution claim was created for expired authority');
  return { evidence: 'decision', detail: 'DENY / AUTHORITY_EXPIRED, no claim, no provider call' };
}

async function revocation(c: Ctx) {
  const parent = await issueLease(c);
  const request = wire({ nonce: nonce('a2'), authority_lease_id: parent.id });
  const decision = await c.call(
    'POST',
    '/v1/authorization/evaluate',
    c.t['treasury_agent']!,
    request,
  );
  assert(decision.body.decision === 'ALLOW', 'baseline ALLOW failed');

  // The grant is outstanding. Revoke the authority behind it.
  const revoked = await c.call('POST', `/v1/authority-leases/${parent.id}/revoke`, c.t['admin']!, {
    reason: 'adversarial A2',
  });
  assert(revoked.status === 200, 'revocation failed');

  const executed = await c.call('POST', '/v1/execute', c.t['treasury_agent']!, {
    decision_id: decision.body.decision_id,
    operation: operationOf(request),
  });
  assert(executed.status === 403, `expected 403, got ${executed.status}`);
  assert(
    executed.body.error.code === 'AUTHORITY_REVOKED',
    `expected AUTHORITY_REVOKED, got ${executed.body.error.code}`,
  );
  assert(provider.calls.length === 0, 'the provider was contacted after revocation');
  return {
    evidence: 'security event',
    detail: 'an outstanding grant conferred nothing once its authority was revoked',
  };
}

async function authorityDrift(c: Ctx) {
  const parent = await issueLease(c);
  const delegation = await c.call('POST', '/v1/delegations', c.t['treasury_agent']!, {
    issuer_agent_id: c.fixtures.agents['treasury'],
    delegate_agent_id: 'verification-agent',
    parent_lease_id: parent.id,
    grant: {
      actions: ['counterparty.read'],
      resources: { counterparty: ['cp_100'] },
      constraints: {
        max_amount: { currency: 'USD', amount: '0.00' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    },
    ttl_seconds: 3600,
  });
  assert(delegation.status === 201, `delegation failed: ${JSON.stringify(delegation.body)}`);

  const before = await countSecurityEvents(c, 'AUTHORITY_INVARIANT_VIOLATION');

  // Widen the child directly in the database, bypassing every creation API.
  await c.asOwner(async (client) => {
    await client.query(
      `UPDATE scrutexity.authority_leases
          SET actions = ARRAY['wire.modify','counterparty.read'] WHERE id = $1`,
      [delegation.body.child_lease.id],
    );
  });

  const decision = await c.call('POST', '/v1/authorization/evaluate', c.t['verification_agent']!, {
    agent_id: 'verification-agent',
    action: 'counterparty.read',
    resource: { type: 'counterparty', id: 'cp_100' },
    context: { counterparty_id: 'cp_100' },
    authority_lease_id: delegation.body.child_lease.id,
    nonce: nonce('a3'),
  });
  assert(decision.status === 403, `expected 403, got ${decision.status}`);
  assert(
    decision.body.error.code === 'AUTHORITY_INVARIANT_VIOLATION',
    `expected AUTHORITY_INVARIANT_VIOLATION, got ${decision.body.error.code}`,
  );
  assert(
    !JSON.stringify(decision.body).includes('CHILD_SUBSET_OF_PARENT'),
    'the response disclosed which law broke',
  );

  const after = await countSecurityEvents(c, 'AUTHORITY_INVARIANT_VIOLATION');
  assert(after > before, 'no durable security event was written');
  return {
    evidence: 'security event',
    detail: 'drift detected at runtime, event survived rollback',
  };
}

async function privilegeSynthesis(c: Ctx) {
  // The treasurer's ceiling is read-only. Their scope permits the call; the
  // role does not permit the authority.
  const refused = await c.call('POST', '/v1/authority-leases', c.t['treasurer']!, {
    agent_id: 'treasury-agent',
    grant: {
      actions: ['wire.execute'],
      resources: { bank_account: ['acct_001'] },
      constraints: {
        max_amount: { currency: 'USD', amount: '10000.00' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    },
    ttl_seconds: 3600,
  });
  assert(refused.status === 422, `expected 422, got ${refused.status}`);
  assert(
    refused.body.error.reason_code === 'EXCEEDS_ISSUANCE_CEILING',
    `expected EXCEEDS_ISSUANCE_CEILING, got ${refused.body.error.reason_code}`,
  );

  // Positive control: the refusal is about the authority, not about the role
  // being a treasurer.
  const admitted = await c.call('POST', '/v1/authority-leases', c.t['treasurer']!, {
    agent_id: 'treasury-agent',
    grant: {
      actions: ['counterparty.read', 'account.read'],
      resources: { counterparty: ['cp_100'], bank_account: ['acct_001'] },
      constraints: {
        max_amount: { currency: 'USD', amount: '0.00' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100'],
      },
    },
    ttl_seconds: 3600,
  });
  assert(admitted.status === 201, `positive control failed: ${JSON.stringify(admitted.body)}`);
  return {
    evidence: 'security event',
    detail: 'ceilings are not unioned; a covering ceiling still admits',
  };
}

async function isolationAndEnumeration(c: Ctx) {
  const { decision } = await allow(c, 'a5');

  const stolen = await c.call(
    'GET',
    `/v1/authorization-decisions/${decision.decision_id}`,
    c.t['verification_agent']!,
  );
  assert(stolen.status === 404, `cross-subject read returned ${stolen.status}, expected 404`);

  const missing = await c.call(
    'GET',
    '/v1/authorization-decisions/dec_01ZZZZZZZZZZZZZZZZZZZZZZZZ',
    c.t['verification_agent']!,
  );
  assert(
    missing.status === stolen.status,
    'existing and non-existing records are distinguishable by status',
  );

  const policy = await c.call('GET', '/v1/policy-versions', c.t['treasury_agent']!);
  assert(policy.status === 403, `an agent read the policy list (${policy.status})`);
  assert(
    !JSON.stringify(policy.body).includes('max_amount'),
    'the policy leaked through a refusal',
  );

  const events = await c.call('GET', '/v1/security-events', c.t['treasury_agent']!);
  assert(events.status === 403, 'an agent read the security event log');
  return { evidence: 'none required', detail: '404 not 403; existence is not observable' };
}

async function clockDisagreement(c: Ctx) {
  const lease = await issueLease(c);
  const realNow = Date.now;
  const results: string[] = [];
  for (const skew of [-3_600_000, 3_600_000]) {
    Date.now = () => realNow.call(Date) + skew;
    try {
      const decision = await c.call('POST', '/v1/authorization/evaluate', c.t['treasury_agent']!, {
        ...wire({ nonce: nonce('a6') }),
        authority_lease_id: lease.id,
      });
      results.push(decision.body.decision);
    } finally {
      Date.now = realNow;
    }
  }
  assert(
    results[0] === results[1],
    `the API clock changed the answer: ${results[0]} vs ${results[1]}`,
  );
  assert(results[0] === 'ALLOW', `expected ALLOW under both skews, got ${results[0]}`);
  return { evidence: 'decision', detail: `identical result under +/-1h skew (${results[0]})` };
}

async function signalContainment(c: Ctx) {
  await issueLease(c);

  // -- The cryptographic layer ---------------------------------------------
  // 1. A forged signature against an enrolled source.
  const forged = await c.call('POST', '/v1/signals', c.t['fraud_engine']!, {
    subject: { type: 'agent', id: c.fixtures.agents['treasury'] },
    signal_type: 'fraud_risk',
    value: '0.01',
    source: 'external_fraud_engine',
    ttl_seconds: 600,
    event_id: nonce('a7-forged'),
    signature: 'AAAA'.repeat(16),
    signing_key_id: 'nonexistent-key',
  });
  assert(forged.status >= 400, `a forged signature was accepted (${forged.status})`);

  // 2. An unenrolled source. No implicit trust: a source nothing can be
  //    attributed to influences nothing.
  const unenrolled = await c.call('POST', '/v1/signals', c.t['fraud_engine']!, {
    subject: { type: 'agent', id: c.fixtures.agents['treasury'] },
    signal_type: 'fraud_risk',
    value: '0.01',
    source: 'unenrolled_engine',
    ttl_seconds: 600,
    event_id: nonce('a7-unenrolled'),
  });
  assert(
    unenrolled.body?.error?.code === 'SIGNAL_SOURCE_NOT_ENROLLED',
    `an unenrolled source was not refused as such: ${JSON.stringify(unenrolled.body)}`,
  );

  // 3. A legacy HMAC key written straight to the table, exactly as one that
  //    predates the registration check would appear. The signature below is
  //    mathematically correct for that key and is refused anyway, because the
  //    algorithm rule is enforced where every signal passes rather than at the
  //    one moment a key happens to be created.
  const legacySecret = 'a-shared-secret-of-adequate-length';
  await c.asOwner(async (client) => {
    await client.query(
      `INSERT INTO scrutexity.signal_signing_keys
         (id, organization_id, source, key_id, algorithm, key_material, not_before)
       VALUES ($1,$2,'legacy_engine','legacy-k1','HMAC_SHA256',$3, now())
       ON CONFLICT DO NOTHING`,
      [newId('signalKey'), c.fixtures.organization_id, legacySecret],
    );
  });
  const legacyIssuedAt = new Date(Date.now() - 1000).toISOString();
  const legacyEventId = nonce('a7-legacy');
  const legacy = await c.call('POST', '/v1/signals', c.t['fraud_engine']!, {
    subject: { type: 'agent', id: c.fixtures.agents['treasury'] },
    signal_type: 'fraud_risk',
    value: '0.01',
    confidence: '1',
    source: 'legacy_engine',
    ttl_seconds: 600,
    issued_at: legacyIssuedAt,
    event_id: legacyEventId,
    signature: signSignalHmac(
      {
        organization_id: c.fixtures.organization_id,
        subject_type: 'agent',
        subject_id: c.fixtures.agents['treasury']!,
        signal_type: 'fraud_risk',
        value: '0.01',
        confidence: '1',
        source: 'legacy_engine',
        event_id: legacyEventId,
        issued_at: legacyIssuedAt,
        ttl_seconds: 600,
      },
      legacySecret,
    ),
    signing_key_id: 'legacy-k1',
  });
  assert(
    legacy.body?.error?.reason_code === 'ALGORITHM_NOT_PERMITTED',
    `a legacy HMAC signature was not refused on its algorithm: ${JSON.stringify(legacy.body)}`,
  );

  // -- The containment layer ------------------------------------------------
  // Everything below is signed with the real key. This is the fully
  // compromised issuer: no forgery, every signature verifies, and it still
  // cannot manufacture authority.
  const overCeiling = { ...wire().context, amount: '75000.00' };
  const beforeCeiling = await c.call('POST', '/v1/authorization/evaluate', c.t['treasury_agent']!, {
    ...wire({ nonce: nonce('a7-base'), context: overCeiling }),
  });
  assert(
    beforeCeiling.body.decision !== 'ALLOW',
    'the baseline above the ceiling was already an ALLOW; the scenario proves nothing',
  );

  for (const [index, reading] of [
    { signal_type: 'fraud_risk', value: '0.00' },
    { signal_type: 'model_confidence', value: '1' },
    { signal_type: 'counterparty_risk', value: '0.00' },
  ].entries()) {
    const ingested = await c.call(
      'POST',
      '/v1/signals',
      c.t['fraud_engine']!,
      signedSignal(c.fixtures, {
        subject: { type: 'agent', id: c.fixtures.agents['treasury']! },
        ...reading,
        confidence: '1',
        source: 'external_fraud_engine',
        ttl_seconds: 600,
        event_id: nonce(`a7-valid-${index}`),
      }),
    );
    assert(
      ingested.status === 201,
      `a correctly signed signal was rejected: ${JSON.stringify(ingested.body)}`,
    );
    assert(
      ingested.body.signal.authenticated === true,
      'a correctly signed signal was not recorded as authenticated',
    );
  }

  const afterSignal = await c.call('POST', '/v1/authorization/evaluate', c.t['treasury_agent']!, {
    ...wire({ nonce: nonce('a7-after'), context: overCeiling }),
  });
  assert(
    afterSignal.body.decision === beforeCeiling.body.decision,
    `a signal changed the decision from ${beforeCeiling.body.decision} to ${afterSignal.body.decision}`,
  );
  assert(afterSignal.body.decision !== 'ALLOW', 'a signal turned a non-ALLOW into an ALLOW');

  // The durable authority did not move either. A decision that stayed the same
  // while the grant behind it widened is a defect waiting for the next request.
  await c.asOwner(async (client) => {
    const rows = await client.query(
      `SELECT constraints FROM scrutexity.authority_leases
        WHERE organization_id = $1 AND status = 'ACTIVE'`,
      [c.fixtures.organization_id],
    );
    for (const row of rows.rows) {
      const ceiling = (row.constraints as { max_amount?: { amountMinor?: string } }).max_amount;
      assert(
        ceiling === undefined || BigInt(ceiling.amountMinor ?? '0') <= 5_000_000n,
        `a signal raised a stored ceiling to ${JSON.stringify(ceiling)}`,
      );
    }
  });

  return {
    evidence: 'security event',
    detail:
      'forged, unenrolled and legacy-HMAC refused; a valid signal from a trusted source could not expand authority',
  };
}

async function replayAndConcurrency(c: Ctx) {
  const { decision, operation } = await allow(c, 'a8');
  const attempts = await Promise.all(
    Array.from({ length: 10 }, () =>
      c.call('POST', '/v1/execute', c.t['treasury_agent']!, {
        decision_id: decision.decision_id,
        operation,
      }),
    ),
  );
  const created = attempts.filter((a) => a.status === 201);
  assert(created.length === 1, `expected exactly one 201, got ${created.length}`);

  let claims = 0;
  let executions = 0;
  await c.asOwner(async (client) => {
    const rows = await client.query(
      `SELECT
         (SELECT count(*)::int FROM scrutexity.execution_claims WHERE decision_id = $1) AS claims,
         (SELECT count(*)::int FROM scrutexity.execution_attempts WHERE decision_id = $1) AS attempts`,
      [decision.decision_id],
    );
    claims = rows.rows[0].claims as number;
    executions = rows.rows[0].attempts as number;
  });
  assert(claims === 1, `expected one claim row, got ${claims}`);
  assert(executions === 1, `expected one execution attempt, got ${executions}`);
  assert(provider.calls.length === 1, `the provider was called ${provider.calls.length} times`);
  return { evidence: 'receipt', detail: '10 concurrent, 1 claim, 1 attempt, 1 provider call' };
}

/** Rewinds a settled claim to the state a crash leaves behind. */
async function rewindToCrashed(c: Ctx, decisionId: string, removeAttempt: boolean) {
  await c.asOwner(async (client) => {
    if (removeAttempt) {
      await client.query(
        'ALTER TABLE scrutexity.execution_attempts DISABLE TRIGGER execution_attempts_append_only',
      );
      await client.query('DELETE FROM scrutexity.execution_attempts WHERE decision_id = $1', [
        decisionId,
      ]);
      await client.query(
        'ALTER TABLE scrutexity.execution_attempts ENABLE TRIGGER execution_attempts_append_only',
      );
    }
    await client.query(
      `UPDATE scrutexity.execution_claims
          SET state = 'EXECUTING', resolved_at = NULL, external_reference = NULL
        WHERE decision_id = $1`,
      [decisionId],
    );
  });
}

async function crashBeforeProvider(c: Ctx) {
  const { decision, operation } = await allow(c, 'a9');
  const first = await c.call('POST', '/v1/execute', c.t['treasury_agent']!, {
    decision_id: decision.decision_id,
    operation,
  });
  assert(first.status === 201, 'baseline execution failed');
  await rewindToCrashed(c, decision.decision_id, true);

  const callsBefore = provider.calls.length;
  const retry = await c.call('POST', '/v1/execute', c.t['treasury_agent']!, {
    decision_id: decision.decision_id,
    operation,
  });
  assert(retry.status === 409, `expected 409, got ${retry.status}`);
  assert(
    retry.body.error.code === 'EXECUTION_UNRESOLVED',
    `expected EXECUTION_UNRESOLVED, got ${retry.body.error.code}`,
  );
  assert(provider.calls.length === callsBefore, 'the provider was contacted on the retry');

  const unresolved = await c.call('GET', '/v1/executions/unresolved', c.t['admin']!);
  const row = unresolved.body.unresolved.find(
    (u: { decision_id: string }) => u.decision_id === decision.decision_id,
  );
  assert(row !== undefined, 'the crashed execution was not surfaced');
  assert(
    row.idempotency_key === `scrutexity:${decision.decision_id}`,
    'the original idempotency key was not preserved',
  );
  return { evidence: 'unresolved claim', detail: '409 EXECUTION_UNRESOLVED, key preserved' };
}

async function providerSuccessSettlementCrash(c: Ctx) {
  const lease = await issueLease(c, { grant_type: 'SINGLE_USE' });
  const request = wire({ nonce: nonce('a10'), authority_lease_id: lease.id });
  const decision = await c.call(
    'POST',
    '/v1/authorization/evaluate',
    c.t['treasury_agent']!,
    request,
  );
  assert(decision.body.decision === 'ALLOW', 'baseline ALLOW failed');

  const executed = await c.call('POST', '/v1/execute', c.t['treasury_agent']!, {
    decision_id: decision.body.decision_id,
    operation: operationOf(request),
  });
  assert(executed.status === 201, 'baseline execution failed');
  assert(executed.body.status === 'EXECUTED', 'the provider did not report success');

  // The money moved and settlement never ran.
  await rewindToCrashed(c, decision.body.decision_id, true);

  const callsBefore = provider.calls.length;
  const retry = await c.call('POST', '/v1/execute', c.t['treasury_agent']!, {
    decision_id: decision.body.decision_id,
    operation: operationOf(request),
  });
  assert(retry.status === 409, `expected 409, got ${retry.status}`);
  assert(
    retry.body.error.code === 'EXECUTION_UNRESOLVED',
    `expected EXECUTION_UNRESOLVED, got ${retry.body.error.code}`,
  );
  assert(provider.calls.length === callsBefore, 'the provider was contacted again after the crash');

  const read = await c.call('GET', `/v1/authority-leases/${lease.id}`, c.t['admin']!);
  assert(read.body.authority_lease.consumed === true, 'the grant was returned by the crash');
  return {
    evidence: 'unresolved claim',
    detail: 'no second payment; grant stays spent; awaits reconciliation',
  };
}

async function transactionFaultInjection(c: Ctx) {
  const lease = await issueLease(c, { grant_type: 'SINGLE_USE' });
  const request = wire({ nonce: nonce('a11'), authority_lease_id: lease.id });
  const decision = await c.call(
    'POST',
    '/v1/authorization/evaluate',
    c.t['treasury_agent']!,
    request,
  );
  assert(decision.body.decision === 'ALLOW', 'baseline ALLOW failed');

  const executed = await c.call('POST', '/v1/execute', c.t['treasury_agent']!, {
    decision_id: decision.body.decision_id,
    operation: operationOf(request),
  });
  assert(executed.status === 201, `execution failed: ${JSON.stringify(executed.body)}`);

  // The observation was taken from an independent connection at the instant
  // execute() was entered. It cannot see uncommitted work, so seeing the claim
  // and the consumed grant proves both were committed before the provider was
  // reached.
  const observed = provider.observations.find((o) => o.decisionId === decision.body.decision_id);
  if (observed === undefined) {
    throw new Error('the provider was never called, so nothing was observed');
  }
  assert(
    observed.claimVisible,
    'the provider was reached while the execution claim was still uncommitted',
  );
  assert(
    observed.grantConsumed === true,
    'the provider was reached while the authority consumption was still uncommitted',
  );
  return {
    evidence: 'external observation',
    detail: 'claim and grant consumption both committed before execute() ran',
  };
}

await main();
