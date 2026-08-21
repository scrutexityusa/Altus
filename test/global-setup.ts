/**
 * Per-run test database.
 *
 * Every `vitest run` provisions its own PostgreSQL database, migrates it, and
 * drops it afterwards. Tests never touch the development database.
 *
 * This is not tidiness. The suite deliberately exercises destructive and
 * adversarial paths -- it disables append-only triggers to prove that
 * verification still catches forced writes, resets the schema between files,
 * and tampers with stored policy rows. Pointing that at a shared database
 * would eventually destroy someone's work, and worse, a leftover row from a
 * previous run could make an isolation test pass for the wrong reason.
 */
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const root = fileURLToPath(new URL('../', import.meta.url));

/** Connection to the cluster's maintenance database, for CREATE/DROP DATABASE. */
function maintenanceUrl(adminUrl: string): string {
  const url = new URL(adminUrl);
  url.pathname = '/postgres';
  return url.toString();
}

function withDatabase(baseUrl: string, database: string): string {
  const url = new URL(baseUrl);
  url.pathname = `/${database}`;
  return url.toString();
}

export default async function setup() {
  const baseAdminUrl =
    process.env['DATABASE_ADMIN_URL'] ??
    'postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity';
  const baseAppUrl =
    process.env['DATABASE_URL'] ?? 'postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity';

  // An explicit opt-out for anyone who genuinely wants to run against a
  // database they prepared themselves. Off by default, because the safe
  // behaviour should not be the one you have to remember to ask for.
  if (process.env['SCRUTEXITY_TEST_USE_EXISTING_DB'] === '1') {
    return () => undefined;
  }

  const database = `scrutexity_test_${randomBytes(6).toString('hex')}`;
  const maintenance = new pg.Client({ connectionString: maintenanceUrl(baseAdminUrl) });
  await maintenance.connect();
  try {
    // The name is generated from crypto random hex, so it cannot contain an
    // identifier-breaking character; quoted anyway because CREATE DATABASE
    // takes no parameters.
    await maintenance.query(`CREATE DATABASE "${database}"`);
  } finally {
    await maintenance.end();
  }

  const adminUrl = withDatabase(baseAdminUrl, database);
  const appUrl = withDatabase(baseAppUrl, database);

  execFileSync('pnpm', ['exec', 'tsx', 'scripts/migrate.ts'], {
    cwd: root,
    stdio: 'ignore',
    env: { ...process.env, DATABASE_ADMIN_URL: adminUrl },
  });

  // Worker processes are forked after globalSetup returns, so they inherit
  // these. Set on the parent deliberately rather than passed through `provide`,
  // so that code reading process.env directly -- the migration runner the
  // harness shells out to, for instance -- sees the isolated database too.
  process.env['DATABASE_ADMIN_URL'] = adminUrl;
  process.env['DATABASE_URL'] = appUrl;
  process.env['SCRUTEXITY_TEST_DATABASE'] = database;

  return async function teardown() {
    if (process.env['SCRUTEXITY_TEST_KEEP_DB'] === '1') {
      process.stdout.write(`\n  test database kept: ${database}\n`);
      return;
    }
    const client = new pg.Client({ connectionString: maintenanceUrl(baseAdminUrl) });
    await client.connect();
    try {
      await client.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`,
        [database],
      );
      await client.query(`DROP DATABASE IF EXISTS "${database}"`);
    } finally {
      await client.end();
    }
  };
}
