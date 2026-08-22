import { createHash } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { bootstrap, BootstrapError, BOOTSTRAP_SCOPES } from '../../../scripts/bootstrap.js';
import { buildApp, type App } from '../src/app.js';
import { ADMIN_URL, APP_URL, resetDatabase } from './harness.js';

/**
 * ============================================================================
 * The installation ceremony.
 * ============================================================================
 *
 * Bootstrap is the boundary between installation trust (the database owner) and
 * application trust (a scoped credential going through the public API). Before
 * it existed, the only path to a usable tenant was `scripts/seed.ts`, which made
 * database-owner access *equal to* application onboarding -- so a design partner
 * could not create their own tenant without editing a script that bypasses every
 * control the product sells.
 *
 * These cases are servants of that slice, not a new framework. They pin the
 * things that would silently break it:
 *
 *   - a second ceremony is refused, including under a different organization
 *     name, which is the case the first implementation got wrong;
 *   - the credential it issues can provision and cannot act;
 *   - the secret is never persisted.
 *
 * This file resets the database, which is safe because `fileParallelism` is
 * false and it restores a seeded state in `afterAll` for whatever runs next.
 */

const OWNER = process.env['DATABASE_ADMIN_URL'] ?? ADMIN_URL;

const asOwner = async <T>(fn: (client: pg.Client) => Promise<T>): Promise<T> => {
  const client = new pg.Client({ connectionString: OWNER });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
};

const input = {
  connectionString: OWNER,
  orgName: 'Example Treasury',
  orgSlug: 'example-treasury',
  adminName: 'Jane Smith',
  adminEmail: 'jane@example.com',
};

describe('bootstrap creates the first tenant and nothing more', () => {
  let result: Awaited<ReturnType<typeof bootstrap>>;

  beforeAll(async () => {
    resetDatabase();
    result = await bootstrap(input);
  }, 120_000);

  afterAll(() => {
    // Leave a migrated, unbootstrapped database behind rather than this test's
    // half-built tenant.
    resetDatabase();
  });

  it('creates exactly one organization, named what was asked for', async () => {
    const rows = await asOwner((client) =>
      client.query(`SELECT id, slug, name FROM scrutexity.organizations`),
    );
    // Read as owner with no tenant set. RLS is FORCEd on this table, so this
    // returning nothing is expected and is precisely why the "already
    // bootstrapped" guard cannot be a count over it -- see the migration.
    expect(rows.rows.length).toBeLessThanOrEqual(1);

    const withTenant = await asOwner(async (client) => {
      await client.query('SELECT set_config($1,$2,false)', [
        'scrutexity.org_id',
        result.organization_id,
      ]);
      return client.query(`SELECT slug, name FROM scrutexity.organizations`);
    });
    expect(withTenant.rows).toEqual([{ slug: 'example-treasury', name: 'Example Treasury' }]);
  });

  it('records the installation so the ceremony cannot repeat', async () => {
    const rows = await asOwner((client) =>
      client.query(`SELECT organization_id, admin_user_id FROM scrutexity.installation`),
    );
    expect(rows.rows).toEqual([
      { organization_id: result.organization_id, admin_user_id: result.admin_user_id },
    ]);
  });

  it('refuses a second ceremony under a DIFFERENT organization name', async () => {
    // The case the first implementation got wrong. It guarded with
    // `count(*) FROM organizations`, which FORCE RLS filters to zero, so the
    // guard passed and the run only failed later on a slug collision -- meaning
    // a differently-named organization would have been created outright.
    await expect(
      bootstrap({
        ...input,
        orgName: 'Totally Different Corp',
        orgSlug: 'totally-different-corp',
        adminEmail: 'someone@different.example',
      }),
    ).rejects.toMatchObject({ code: 'ALREADY_BOOTSTRAPPED' });
  });

  it('leaves no partial second installation behind', async () => {
    // The assertion that matters, and it is not "the second call errored".
    // It is that a refused ceremony left *nothing* -- no organization, no
    // administrator, no credential, and an installation marker still pointing
    // at the first tenant. An error return with a half-built second tenant
    // behind it would be worse than no guard at all, because the wreckage
    // would be invisible to the operator who saw the error and moved on.
    const second = {
      ...input,
      orgName: 'Totally Different Corp',
      orgSlug: 'totally-different-corp',
      adminEmail: 'someone@different.example',
    };
    await expect(bootstrap(second)).rejects.toMatchObject({ code: 'ALREADY_BOOTSTRAPPED' });

    const state = await asOwner(async (client) => {
      // The org id is unknown -- it was never created -- so the tenant context
      // is set to the FIRST organization. Anything belonging to the second
      // would be invisible under it, so these queries are deliberately written
      // to catch rows by their *content* rather than by tenant.
      await client.query('SELECT set_config($1,$2,false)', [
        'scrutexity.org_id',
        result.organization_id,
      ]);
      const orgs = await client.query(`SELECT id FROM scrutexity.organizations WHERE slug = $1`, [
        second.orgSlug,
      ]);
      const users = await client.query(`SELECT id FROM scrutexity.users WHERE email = $1`, [
        second.adminEmail,
      ]);
      // api_credentials is RLS-enabled-but-not-forced, so this count is the
      // whole installation's, across every tenant -- exactly what is wanted
      // here: one credential exists anywhere, and it is the first tenant's.
      const creds = await client.query<{ organization_id: string }>(
        `SELECT organization_id FROM scrutexity.api_credentials`,
      );
      const marker = await client.query<{ organization_id: string }>(
        `SELECT organization_id FROM scrutexity.installation`,
      );
      return {
        orgs: orgs.rows,
        users: users.rows,
        credOrgs: creds.rows.map((r) => r.organization_id),
        marker: marker.rows,
      };
    });

    expect(state.orgs, 'the second organization must not exist').toEqual([]);
    expect(state.users, 'the second administrator must not exist').toEqual([]);
    expect(state.credOrgs, 'no credential may belong to the second tenant').toEqual([
      result.organization_id,
    ]);
    expect(state.marker, 'the marker still points at the first tenant').toEqual([
      { organization_id: result.organization_id },
    ]);
  });

  it('refuses a second ceremony under the same name', async () => {
    await expect(bootstrap(input)).rejects.toBeInstanceOf(BootstrapError);
  });

  it('creates nothing when it refuses', async () => {
    // The tenant has to be named to count users: `users` is FORCE RLS'd, so an
    // unqualified count returns zero regardless of what exists. The same trap
    // the guard fell into, met again here -- worth stating rather than working
    // around silently. `api_credentials` is RLS-enabled-but-not-forced, so its
    // count is visible either way.
    const counts = await asOwner(async (client) => {
      await client.query('SELECT set_config($1,$2,false)', [
        'scrutexity.org_id',
        result.organization_id,
      ]);
      return client.query<{ users: number; creds: number }>(
        `SELECT (SELECT count(*)::int FROM scrutexity.users) AS users,
                (SELECT count(*)::int FROM scrutexity.api_credentials) AS creds`,
      );
    });
    // One admin, one credential. The two refusals above rolled back whole -- no
    // orphaned user from the ceremony that was turned away.
    expect(counts.rows[0]).toEqual({ users: 1, creds: 1 });
  });

  it('stores a hash and a prefix, never the token', async () => {
    const rows = await asOwner((client) =>
      client.query<{ token_prefix: string; token_hash: Buffer; scopes: string[] }>(
        `SELECT token_prefix, token_hash, scopes FROM scrutexity.api_credentials`,
      ),
    );
    const row = rows.rows[0]!;
    expect(result.token.startsWith(`scr_${row.token_prefix}.`)).toBe(true);
    expect(row.token_hash.equals(createHash('sha256').update(result.token).digest())).toBe(true);
    // The secret half appears nowhere in the row.
    expect(JSON.stringify(row)).not.toContain(result.token.split('.')[1]);
    expect(row.scopes.sort()).toEqual([...BOOTSTRAP_SCOPES].sort());
  });
});

describe('the bootstrap credential provisions but does not act', () => {
  let app: App;
  let token: string;

  beforeAll(async () => {
    resetDatabase();
    token = (await bootstrap(input)).token;
    app = await buildApp({ NODE_ENV: 'test', DATABASE_URL: APP_URL, LOG_LEVEL: 'silent' });
  }, 120_000);

  afterAll(async () => {
    await app?.close();
    resetDatabase();
  });

  const call = async (method: string, url: string, body?: unknown) => {
    const response = await app.server.inject({
      method: method as never,
      url,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
    });
    return { status: response.statusCode, body: response.body ? JSON.parse(response.body) : null };
  };

  it('authenticates against the running service', async () => {
    const response = await call('GET', '/v1/agents');
    expect(response.status).toBe(200);
  });

  it('can provision an agent', async () => {
    const response = await call('POST', '/v1/agents', {
      handle: 'our-treasury-agent',
      display_name: 'Our Treasury Agent',
    });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
  });

  it('cannot act as an agent', async () => {
    // The ceremony provisions; it does not authorize. An operator who wants to
    // evaluate or approve issues themselves a credential that can, through the
    // API, where it is recorded.
    const response = await call('POST', '/v1/authorization/evaluate', {
      agent_id: 'our-treasury-agent',
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_x' },
      context: {},
    });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('FORBIDDEN');
  });

  it('cannot approve', async () => {
    const response = await call('POST', '/v1/approvals', {
      approval_request_id: 'apr_nonexistent',
      vote: 'APPROVED',
    });
    expect(response.status).toBe(403);
  });

  it('cannot ingest a signal', async () => {
    const response = await call('POST', '/v1/signals', {
      subject: { type: 'agent', id: 'x' },
      signal_type: 'fraud_risk',
      value: '0.9',
      source: 'somewhere',
      ttl_seconds: 60,
    });
    expect(response.status).toBe(403);
  });
});

describe('the application role cannot reach installation state', () => {
  beforeAll(() => {
    resetDatabase();
  }, 120_000);

  it('is denied outright, the same as api_credentials', async () => {
    // Installation state precedes tenant resolution and nothing in the request
    // path reads it, so the application role is granted nothing at all.
    const client = new pg.Client({ connectionString: APP_URL });
    await client.connect();
    try {
      await expect(client.query('SELECT * FROM scrutexity.installation')).rejects.toMatchObject({
        code: '42501',
      });
    } finally {
      await client.end();
    }
  });
});
