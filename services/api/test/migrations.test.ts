import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_URL } from './harness.js';

/**
 * ============================================================================
 * Migrations must roll forward over data that already exists.
 * ============================================================================
 *
 * CI checks `migrate --down 3 && migrate` on a database it created seconds
 * earlier and never wrote to. That check passed for months while migration
 * 0010 could not roll forward over any database anybody had actually used:
 *
 *   0010 down   drops api_credentials.revoked_at
 *   0010 up     re-adds it empty, then adds a CHECK requiring every REVOKED
 *               row to carry one
 *
 * An empty database has no REVOKED rows, so the constraint had nothing to
 * refuse. A real one does, and the migration failed outright -- discovered by
 * replaying the CI steps by hand against a development database with a
 * revoked credential in it, not by the check that exists for this.
 *
 * A migration test that runs against an empty database is testing the DDL. It
 * is not testing the migration, because a migration's whole job is to carry
 * existing rows across a schema change. So this one seeds the rows first.
 *
 * It uses a database of its own: rolling the schema back three times is not
 * something to do to the database the rest of the suite is using.
 */

const root = fileURLToPath(new URL('../../../', import.meta.url));

function withDatabase(base: string, database: string): string {
  const url = new URL(base);
  url.pathname = `/${database}`;
  return url.toString();
}

const baseAdminUrl = process.env['DATABASE_ADMIN_URL'] ?? ADMIN_URL;
const database = `scrutexity_migrations_${randomBytes(6).toString('hex')}`;
const adminUrl = withDatabase(baseAdminUrl, database);

function migrate(...args: string[]): void {
  execFileSync('pnpm', ['exec', 'tsx', 'scripts/migrate.ts', ...args], {
    cwd: root,
    stdio: 'pipe',
    env: { ...process.env, DATABASE_ADMIN_URL: adminUrl },
  });
}

async function asOwner<T>(fn: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

beforeAll(async () => {
  const maintenance = new pg.Client({ connectionString: withDatabase(baseAdminUrl, 'postgres') });
  await maintenance.connect();
  try {
    await maintenance.query(`CREATE DATABASE "${database}"`);
  } finally {
    await maintenance.end();
  }
  migrate();
}, 120_000);

afterAll(async () => {
  const maintenance = new pg.Client({ connectionString: withDatabase(baseAdminUrl, 'postgres') });
  await maintenance.connect();
  try {
    await maintenance.query(`DROP DATABASE IF EXISTS "${database}" WITH (FORCE)`);
  } finally {
    await maintenance.end();
  }
});

describe('migrations roll forward over data that already exists', () => {
  it('carries a revoked credential across a rollback and reapply', async () => {
    // The historical shape that broke it: a tenant, a human, and a credential
    // somebody has revoked. Written directly because the point is the state,
    // not the route that produced it -- and because a real database reaching
    // this migration got there over months of ordinary use.
    await asOwner(async (client) => {
      await client.query('SELECT set_config($1, $2, false)', [
        'scrutexity.org_id',
        'org_01ARZ3NDEKTSV4RRFFQ69G5FAV',
      ]);
      await client.query(
        `INSERT INTO scrutexity.organizations (id, slug, name)
         VALUES ('org_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'historic', 'Historic Tenant')`,
      );
      await client.query(
        `INSERT INTO scrutexity.users (id, organization_id, email, display_name, roles)
         VALUES ('user_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV',
                 'historic@example.com', 'Historic User', ARRAY['admin'])`,
      );
      await client.query(
        `INSERT INTO scrutexity.api_credentials
           (id, organization_id, principal_type, principal_id, token_prefix, token_hash,
            scopes, status, revoked_at, created_at, expires_at)
         VALUES ('cred_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'org_01ARZ3NDEKTSV4RRFFQ69G5FAV',
                 'user', 'user_01ARZ3NDEKTSV4RRFFQ69G5FAV', 'aaaaaaaaaaaaaaaa',
                 decode(repeat('ab', 32), 'hex'), ARRAY['read'], 'REVOKED', now(),
                 now(), now() + INTERVAL '30 days')`,
      );
    });

    // The same round trip CI performs -- 0012, 0011, 0010 down, then all three
    // forward again. Before the backfill this threw
    // `api_credentials_revoked_shape is violated by some row`.
    expect(() => {
      migrate('--down', '3');
      migrate();
    }).not.toThrow();

    const row = await asOwner(async (client) => {
      await client.query('SELECT set_config($1, $2, false)', [
        'scrutexity.org_id',
        'org_01ARZ3NDEKTSV4RRFFQ69G5FAV',
      ]);
      const result = await client.query(
        `SELECT status, revoked_at, expires_at FROM scrutexity.api_credentials
          WHERE id = 'cred_01ARZ3NDEKTSV4RRFFQ69G5FAV'`,
      );
      return result.rows[0] as
        { status: string; revoked_at: Date | null; expires_at: Date | null } | undefined;
    });

    expect(row).toBeDefined();
    // Still revoked, and still carrying an instant. The original one is gone --
    // the column was dropped -- and the backfill records the migration's own
    // time, which is the conservative direction: "revoked no later than this"
    // never understates how long the credential was live.
    expect(row!.status).toBe('REVOKED');
    expect(row!.revoked_at).not.toBeNull();
    expect(row!.expires_at).not.toBeNull();
  }, 120_000);

  it('survives a full teardown to zero and a rebuild', async () => {
    // The other direction nobody checks: every down migration in sequence.
    // A down that only works as the newest one is a down that does not work.
    expect(() => {
      migrate('--down', '12');
      migrate();
    }).not.toThrow();

    const tables = await asOwner(async (client) => {
      const result = await client.query(
        `SELECT count(*)::int AS n FROM information_schema.tables
          WHERE table_schema = 'scrutexity'`,
      );
      return result.rows[0].n as number;
    });
    expect(tables).toBeGreaterThan(0);
  }, 120_000);
});
