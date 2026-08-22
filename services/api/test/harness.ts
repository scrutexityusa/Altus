import { execSync } from 'node:child_process';
import type { App } from '../src/app.js';
import { buildApp } from '../src/app.js';
import { seed, type SeedResult } from '../../../scripts/seed.js';

/**
 * Integration harness. These tests run against a real PostgreSQL with row
 * level security enabled and the application connecting as the non-owner role,
 * because the isolation guarantees under test are database guarantees -- a
 * mocked store would prove nothing about them.
 */

export const ADMIN_URL =
  process.env['DATABASE_ADMIN_URL'] ??
  'postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity';
export const APP_URL =
  process.env['DATABASE_URL'] ?? 'postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity';

export function resetDatabase(): void {
  execSync('pnpm exec tsx scripts/migrate.ts --reset', {
    stdio: 'ignore',
    cwd: new URL('../../../', import.meta.url).pathname,
    env: { ...process.env, DATABASE_ADMIN_URL: ADMIN_URL },
  });
}

export interface Harness {
  app: App;
  tenant: SeedResult;
  /** A second, unrelated tenant. Its existence is the point of most of these tests. */
  other: SeedResult;
  call(
    method: string,
    path: string,
    token: string | null,
    body?: unknown,
    headers?: Record<string, string>,
  ): Promise<{ status: number; body: any }>;
  close(): Promise<void>;
}

export async function startHarness(options: { reset?: boolean } = {}): Promise<Harness> {
  if (options.reset !== false) resetDatabase();
  const tenant = await seed(ADMIN_URL);
  // A second tenant, to prove isolation between them. Not a second
  // installation: the ceremony happens once and this is provisioned onto it.
  const other = await seed(ADMIN_URL, { additionalTenant: true });

  const app = await buildApp({
    NODE_ENV: 'test',
    DATABASE_URL: APP_URL,
    LOG_LEVEL: process.env['TEST_LOG_LEVEL'] ?? 'silent',
  });

  return {
    app,
    tenant,
    other,
    async call(method, path, token, body, headers = {}) {
      const response = await app.server.inject({
        method: method as never,
        url: path,
        headers: {
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          'content-type': 'application/json',
          ...headers,
        },
        ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
      });
      return {
        status: response.statusCode,
        body: response.body ? JSON.parse(response.body) : null,
      };
    },
    close: () => app.close(),
  };
}

/** Issues the standard treasury lease used by most scenarios. */
export async function issueTreasuryLease(
  harness: Harness,
  tenant: SeedResult = harness.tenant,
  overrides: Record<string, unknown> = {},
) {
  const response = await harness.call('POST', '/v1/authority-leases', tenant.tokens['admin']!, {
    agent_id: 'treasury-agent',
    grant: {
      actions: ['wire.create', 'wire.submit', 'wire.execute', 'counterparty.read', 'account.read'],
      resources: { bank_account: ['acct_001', 'acct_002'], counterparty: ['cp_100', 'cp_101'] },
      constraints: {
        max_amount: { currency: 'USD', amountMinor: '5000000' },
        currencies: ['USD'],
        allowed_counterparties: ['cp_100', 'cp_101'],
      },
    },
    ttl_seconds: 3600,
    ...overrides,
  });
  if (response.status !== 201) {
    throw new Error(`lease issuance failed: ${JSON.stringify(response.body)}`);
  }
  return response.body.authority_lease;
}

/**
 * Signing a signal the way a real source would. Lives in scripts/ so the demo
 * and the adversarial runner sign identically -- two implementations of "what
 * bytes get signed" eventually disagree, and the disagreement looks exactly
 * like a forged signal.
 */
export { signedSignal, type SignalRequest } from '../../../scripts/signal-source.js';

export function wireRequest(overrides: Record<string, unknown> = {}) {
  return {
    agent_id: 'treasury-agent',
    action: 'wire.execute',
    resource: { type: 'bank_account', id: 'acct_001' },
    context: {
      amount: '25000.00',
      currency: 'USD',
      counterparty_id: 'cp_100',
      destination_country: 'US',
    },
    ...overrides,
  };
}
