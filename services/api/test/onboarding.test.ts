import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { bootstrap } from '../../../scripts/bootstrap.js';
import { buildApp, type App } from '../src/app.js';
import { ADMIN_URL, APP_URL, resetDatabase } from './harness.js';

/**
 * ============================================================================
 * A tenant a partner owns.
 * ============================================================================
 *
 * The whole point of this slice, walked end to end: bootstrap, then create the
 * humans, the credentials, the agent and the accounts through the public API
 * with no owner connection and no `.seed.local.json` in sight.
 *
 * The case that matters most is the last one. `counterparty_known` is derived
 * from a row in `scrutexity.resources`, which before this slice could only be
 * written by the seed script -- so a design partner's real counterparties were
 * unrepresentable, and every wire to one was refused with UNKNOWN_COUNTERPARTY.
 * That was the adoption blocker, and the test proves the write path removes it:
 * the same otherwise-valid request is DENIED before registration and proceeds
 * through policy after.
 *
 * Everything below goes through the boring path a real partner request takes:
 *
 *     authenticated credential -> resolved organization -> transaction tenant
 *     context -> application role -> RLS-enforced write
 */

let app: App;
let admin: string;

const call = async (method: string, url: string, token: string, body?: unknown) => {
  const response = await app.server.inject({
    method: method as never,
    url,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
  });
  return { status: response.statusCode, body: response.body ? JSON.parse(response.body) : null };
};

/**
 * A connection as the database owner, for the handful of assertions that have
 * to reach past the API to check that the *storage* refuses something rather
 * than that a route does. `api_credentials` is RLS-enabled but not FORCEd --
 * authentication resolves the tenant, so credential lookup necessarily happens
 * before a tenant is known -- so the owner needs no tenant context here.
 */
async function asOwner(fn: (client: pg.Client) => Promise<void>) {
  const client = new pg.Client({
    connectionString: process.env['DATABASE_ADMIN_URL'] ?? ADMIN_URL,
  });
  await client.connect();
  try {
    await fn(client);
  } finally {
    await client.end();
  }
}

beforeAll(async () => {
  resetDatabase();
  admin = (
    await bootstrap({
      connectionString: process.env['DATABASE_ADMIN_URL'] ?? ADMIN_URL,
      orgName: 'Example Treasury',
      orgSlug: 'example-treasury',
      adminName: 'Jane Smith',
      adminEmail: 'jane@example.com',
    })
  ).token;
  app = await buildApp({
    NODE_ENV: 'test',
    DATABASE_URL: APP_URL,
    LOG_LEVEL: process.env['TEST_LOG_LEVEL'] ?? 'silent',
  });
}, 120_000);

afterAll(async () => {
  await app?.close();
  resetDatabase();
});

describe('users', () => {
  it('creates a treasurer with the tenant’s own role vocabulary', async () => {
    const response = await call('POST', '/v1/users', admin, {
      email: 'Marco@Example.com',
      display_name: 'Marco Bellini',
      roles: ['treasurer'],
    });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    // Normalised, so an approval matched by email is not defeated by casing.
    expect(response.body.user.email).toBe('marco@example.com');
    expect(response.body.user.roles).toEqual(['treasurer']);
    expect(response.body.user.status).toBe('ACTIVE');
  });

  it('refuses a duplicate email in the same organization', async () => {
    const response = await call('POST', '/v1/users', admin, {
      email: 'marco@example.com',
      display_name: 'Marco Again',
      roles: [],
    });
    expect(response.status).toBe(409);
    expect(response.body.error.code).toBe('STATE_CONFLICT');
  });

  it('lists them', async () => {
    const response = await call('GET', '/v1/users', admin);
    expect(response.status).toBe(200);
    expect(response.body.users.map((u: { email: string }) => u.email).sort()).toEqual([
      'jane@example.com',
      'marco@example.com',
    ]);
  });
});

describe('credentials', () => {
  let treasurerToken: string;
  let treasurerCredentialId: string;

  it('issues one to the treasurer, returning the secret exactly once', async () => {
    const users = await call('GET', '/v1/users', admin);
    const marco = users.body.users.find((u: { email: string }) => u.email === 'marco@example.com');

    const response = await call('POST', '/v1/credentials', admin, {
      principal_type: 'user',
      principal_id: marco.id,
      scopes: ['read', 'approvals:write'],
      expires_in_seconds: 3600,
    });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    expect(response.body.token).toMatch(/^scr_[0-9a-f]{16}\./);
    expect(response.body.credential.scopes.sort()).toEqual(['approvals:write', 'read']);

    treasurerToken = response.body.token;
    treasurerCredentialId = response.body.credential.id;
  });

  it('authenticates with it', async () => {
    const response = await call('GET', '/v1/approval-requests', treasurerToken);
    // Not 401. The credential resolved a principal and a tenant.
    expect(response.status).not.toBe(401);
  });

  it('never exposes the secret again, anywhere', async () => {
    const secret = treasurerToken.split('.')[1]!;
    const listing = await call('GET', '/v1/credentials', admin);
    expect(listing.status).toBe(200);
    const serialised = JSON.stringify(listing.body);
    expect(serialised).not.toContain(secret);
    expect(serialised).not.toContain('token_hash');
    // Operational metadata only, and every field an operator needs to decide
    // whether a credential can be retired.
    expect(Object.keys(listing.body.credentials[0]).sort()).toEqual([
      'created_at',
      'expires_at',
      'id',
      'last_used_at',
      'principal_id',
      'principal_type',
      'revoked_at',
      'scopes',
      'status',
      'token_prefix',
    ]);
  });

  it('does not write last_used_at on the request path', async () => {
    // Pinning the trade deliberately rather than leaving it to be rediscovered.
    // The credential authenticated in the test above; nothing has flushed yet,
    // so the column is still null. If this test ever fails because the value
    // is present, somebody has put a write back in front of every request --
    // which is what migration 0012 removed and what the latency baseline
    // measured at roughly a fifth of an authorize's commits.
    const listing = await call('GET', '/v1/credentials', admin);
    const row = listing.body.credentials.find(
      (c: { id: string }) => c.id === treasurerCredentialId,
    );
    expect(row.last_used_at).toBeNull();
  });

  it('records that the credential has been used', async () => {
    // Last-used tracking is buffered off the request path (migration 0012), so
    // the write happens on a flush rather than inside the request. Flushing
    // here rather than sleeping past the interval keeps the test honest about
    // what it is asserting: that a use is eventually recorded, not that it is
    // recorded synchronously -- which is exactly the property that was traded
    // away for a transaction per request.
    await app.credentialUse.flush();

    // `last_used_at` was a column nothing ever wrote. Exposing it unpopulated
    // would tell an operator a credential in daily use had never been used --
    // which is exactly the fact they would revoke on.
    const listing = await call('GET', '/v1/credentials', admin);
    const row = listing.body.credentials.find(
      (c: { id: string }) => c.id === treasurerCredentialId,
    );
    expect(row.last_used_at).not.toBeNull();
  });

  it('refuses an unknown scope', async () => {
    const users = await call('GET', '/v1/users', admin);
    const response = await call('POST', '/v1/credentials', admin, {
      principal_type: 'user',
      principal_id: users.body.users[0].id,
      scopes: ['wire:everything'],
      expires_in_seconds: 3600,
    });
    expect(response.status).toBe(400);
    expect(response.body.error.message).toContain('unknown scope');
  });

  it('refuses a principal that does not exist in this organization', async () => {
    const response = await call('POST', '/v1/credentials', admin, {
      principal_type: 'user',
      principal_id: 'user_does_not_exist',
      scopes: ['read'],
      expires_in_seconds: 3600,
    });
    expect(response.status).toBe(400);
  });

  it('refuses issuance with no lifetime at all', async () => {
    // The gap this closes: `expires_in_seconds` used to be optional, and
    // absent meant "until somebody revokes it" -- an immortal bearer token,
    // which is the first thing a security review asks about.
    const users = await call('GET', '/v1/users', admin);
    const response = await call('POST', '/v1/credentials', admin, {
      principal_type: 'user',
      principal_id: users.body.users[0].id,
      scopes: ['read'],
    });
    expect(response.status).toBe(400);
  });

  it('refuses a lifetime beyond the ninety-day cap', async () => {
    const users = await call('GET', '/v1/users', admin);
    const response = await call('POST', '/v1/credentials', admin, {
      principal_type: 'user',
      principal_id: users.body.users[0].id,
      scopes: ['read'],
      expires_in_seconds: 7_776_001,
    });
    expect(response.status).toBe(400);
  });

  it('will not represent a credential without an expiry, whatever writes it', async () => {
    // The schema and the function both refuse; this is the layer underneath
    // them, and the only one that holds against somebody with a connection
    // rather than a token.
    await expect(
      asOwner(async (client) => {
        await client.query(
          `INSERT INTO scrutexity.api_credentials
             (id, organization_id, principal_type, principal_id, token_prefix,
              token_hash, scopes, expires_at)
           SELECT 'cred_immortalZZZZZZZZZZZZZZZZZ', organization_id, principal_type,
                  principal_id, 'scr_ffffffffffffffff', token_hash, scopes, NULL
             FROM scrutexity.api_credentials LIMIT 1`,
        );
      }),
    ).rejects.toThrow(/null value|not-null|violates/i);
  });

  it('stamps an expiry from database time, not the API node clock', async () => {
    const users = await call('GET', '/v1/users', admin);
    const response = await call('POST', '/v1/credentials', admin, {
      principal_type: 'user',
      principal_id: users.body.users[0].id,
      scopes: ['read'],
      expires_in_seconds: 3600,
    });
    expect(response.status).toBe(201);

    // Both ends measured by one clock, so the difference is exactly what was
    // asked for regardless of how far this process's clock has drifted.
    const created = Date.parse(response.body.credential.created_at);
    const expires = Date.parse(response.body.credential.expires_at);
    expect(expires - created).toBe(3600 * 1000);
  });

  it('refuses an expired credential without revoking it', async () => {
    const users = await call('GET', '/v1/users', admin);
    const issued = await call('POST', '/v1/credentials', admin, {
      principal_type: 'user',
      principal_id: users.body.users[0].id,
      scopes: ['read'],
      expires_in_seconds: 60,
    });
    expect(issued.status).toBe(201);

    // EXPIRED is not a stored status -- there is no such value in the enum.
    // It is derived at every authentication from database time against
    // expires_at, so moving the row's expiry into the past is enough.
    await asOwner(async (client) => {
      await client.query(
        `UPDATE scrutexity.api_credentials
            SET created_at = transaction_timestamp() - INTERVAL '2 hours',
                expires_at = transaction_timestamp() - INTERVAL '1 hour'
          WHERE id = $1`,
        [issued.body.credential.id],
      );
    });

    expect((await call('GET', '/v1/agents', issued.body.token)).status).toBe(401);

    const listing = await call('GET', '/v1/credentials', admin);
    const row = listing.body.credentials.find(
      (c: { id: string }) => c.id === issued.body.credential.id,
    );
    // Still ACTIVE and unrevoked. Expiry and revocation are different facts,
    // and an operator reading this listing must be able to tell them apart.
    expect(row.status).toBe('ACTIVE');
    expect(row.revoked_at).toBeNull();
  });

  it('revokes, and the same token fails on the very next request', async () => {
    const before = await call('GET', '/v1/approval-requests', treasurerToken);
    expect(before.status).not.toBe(401);

    const revoked = await call(
      'POST',
      `/v1/credentials/${treasurerCredentialId}/revoke`,
      admin,
      {},
    );
    expect(revoked.status).toBe(200);
    expect(revoked.body.credential.status).toBe('REVOKED');
    expect(revoked.body.credential.revoked_at).not.toBeNull();

    // No cache to wait out. The next request is the one that fails.
    const after = await call('GET', '/v1/approval-requests', treasurerToken);
    expect(after.status).toBe(401);
  });
});

describe('policy activation through the API', () => {
  // `POST /v1/policy-versions/{id}/reviews` was published in the OpenAPI
  // contract, required for any partner to activate their first policy, and had
  // never been executed by anything: the seed writes reviews with direct SQL.
  // It was broken -- a parameter used as both an enum and a text literal in one
  // statement, failing with 42P08. Nothing could have caught that except
  // walking the flow, so the flow is now walked on every CI run.
  let versionId: string;
  let reviewerOne: string;
  let reviewerTwo: string;

  beforeAll(async () => {
    reviewerOne = await createUserWithCredential(
      'flow.reviewer.one@example.com',
      'Flow Reviewer One',
      ['policy_reviewer'],
      ['read', 'policies:write'],
    );
    reviewerTwo = await createUserWithCredential(
      'flow.reviewer.two@example.com',
      'Flow Reviewer Two',
      ['policy_reviewer'],
      ['read', 'policies:write'],
    );
    const created = await call('POST', '/v1/policy-versions', admin, { document: readPolicy() });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    versionId = created.body.policy_version.id;
    expect(created.body.policy_version.status).toBe('DRAFT');
  }, 120_000);

  it('refuses to let the author review their own version', async () => {
    // Dual control, and the reason the smallest tenant that can activate a
    // policy has three humans in it. Not friction to route around -- it is the
    // governance model.
    const response = await call('POST', `/v1/policy-versions/${versionId}/reviews`, admin, {
      vote: 'APPROVED',
      comment: 'Approving my own work.',
    });
    expect(response.status).toBe(403);
  });

  it('moves to REVIEW after one non-author approval, not to APPROVED', async () => {
    const response = await call('POST', `/v1/policy-versions/${versionId}/reviews`, reviewerOne, {
      vote: 'APPROVED',
      comment: 'First review.',
    });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    expect(response.body.status).toBe('REVIEW');
    expect(response.body.approvals).toBe(1);
  });

  it('refuses the same reviewer voting twice', async () => {
    const response = await call('POST', `/v1/policy-versions/${versionId}/reviews`, reviewerOne, {
      vote: 'APPROVED',
    });
    expect(response.status).toBe(409);
  });

  it('reaches APPROVED only on a second, distinct non-author approval', async () => {
    const response = await call('POST', `/v1/policy-versions/${versionId}/reviews`, reviewerTwo, {
      vote: 'APPROVED',
      comment: 'Second review.',
    });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
    expect(response.body.status).toBe('APPROVED');
    expect(response.body.approvals).toBe(2);
  });

  it('activates', async () => {
    const response = await call('POST', `/v1/policy-versions/${versionId}/activate`, admin, {});
    expect(response.status, JSON.stringify(response.body)).toBe(200);
  });

  it('decides against the activated version, by hash', async () => {
    // The point of the whole lifecycle: a decision records the exact policy
    // version and content hash it was made under, so it can be replayed against
    // the bytes that produced it.
    const activated = await call('GET', `/v1/policy-versions`, admin);
    const active = activated.body.policy_versions.find(
      (v: { status: string }) => v.status === 'ACTIVE',
    );
    expect(active.id).toBe(versionId);

    const agent = await call('POST', '/v1/agents', admin, {
      handle: 'flow-probe-agent',
      display_name: 'Flow Probe',
    });
    expect(agent.status).toBe(201);
    const probe = await createAgentCredential('flow-probe-agent');

    const decision = await call('POST', '/v1/authorization/evaluate', probe, {
      agent_id: 'flow-probe-agent',
      action: 'wire.execute',
      resource: { type: 'bank_account', id: 'acct_001' },
      context: {
        amount: '100.00',
        currency: 'USD',
        counterparty_id: 'cp_100',
        destination_country: 'US',
      },
      nonce: 'flow-probe-1',
    });
    expect(decision.status).toBe(200);
    // No lease, so DENY -- but decided *under the activated policy*, which is
    // what this asserts. POLICY_UNAVAILABLE here would mean activation failed.
    expect(decision.body.reason_code).not.toBe('POLICY_UNAVAILABLE');
    expect(decision.body.policy_version_id ?? decision.body.policy_id).toBeTruthy();
    expect(decision.body.policy_hash).toBe(active.content_hash);
  });
});

describe('the tenant a request writes to is never the caller’s to choose', () => {
  it('has no field for it in any request schema', async () => {
    // `scrutexity.org_id` is set in exactly one place -- `db.withTenant` in
    // pool.ts -- from `request.principal.organization_id`, which comes from the
    // authenticated credential. The SECURITY DEFINER credential functions each
    // re-assert equality against `current_org_id()`, so none of them can become
    // a cross-tenant write primitive even though they bypass the tenant policy.
    //
    // The property this pins is the one that would break first: an endpoint
    // that accepts an organization id from a caller.
    const response = await call('POST', '/v1/users', admin, {
      email: 'smuggler@example.com',
      display_name: 'Smuggler',
      roles: [],
      organization_id: 'org_someone_else',
    });
    // Every request schema is `.strict()`, so an unknown field is a 400 rather
    // than a silently ignored one.
    expect(response.status).toBe(400);
  });
});

describe('resources, and the counterparty that could not be registered', () => {
  let agentToken: string;

  beforeAll(async () => {
    const agent = await call('POST', '/v1/agents', admin, {
      handle: 'our-treasury-agent',
      display_name: 'Our Treasury Agent',
    });
    expect(agent.status).toBe(201);

    const credential = await call('POST', '/v1/credentials', admin, {
      principal_type: 'agent',
      // By handle, which is what an operator has in front of them.
      principal_id: 'our-treasury-agent',
      scopes: ['read', 'authorization:evaluate'],
      expires_in_seconds: 3600,
    });
    expect(credential.status, JSON.stringify(credential.body)).toBe(201);
    agentToken = credential.body.token;

    // The account it may pay from. The counterparty is deliberately NOT
    // registered yet -- that is the case this whole block exists to prove.
    //
    // Note cp_100 rather than an arbitrary id: the starter policy's issuance
    // ceiling names specific counterparties, so a lease mentioning one outside
    // that list is refused with DELEGATION_EXCEEDS_PARENT before it can even be
    // issued. Being inside the ceiling and unregistered is the state that
    // produces UNKNOWN_COUNTERPARTY, and it is the state a partner is actually
    // in on their first day.
    await call('POST', '/v1/resources', admin, {
      resource_type: 'bank_account',
      external_id: 'acct_001',
      display_name: 'Operating Account — USD',
      attributes: { currency: 'USD', region: 'US' },
    });

    // The policy is already ACTIVE: the previous block took it through the
    // real lifecycle -- author, two distinct non-author reviews, activation.
    // Asserting that here rather than creating a second version keeps this
    // block on the same sequence a partner actually follows.
    const versions = await call('GET', '/v1/policy-versions', admin);
    expect(
      versions.body.policy_versions.some((v: { status: string }) => v.status === 'ACTIVE'),
      'the policy activation block must run first',
    ).toBe(true);

    // The bootstrap admin holds `leases:write` and still cannot issue this
    // lease: issuance ceilings are keyed on the *user's role*, and the starter
    // policy names `treasury_admin`, not `admin`. A role the policy does not
    // name may issue nothing -- which is the correct fail-closed direction and
    // the third thing a partner discovers on their first afternoon.
    //
    // So do what a partner does: create the provisioning role the policy
    // actually recognises. Baking `treasury_admin` into bootstrap would push a
    // treasury assumption into a generic installation ceremony.
    const provisioner = await createUserWithCredential(
      'treasury.ops@example.com',
      'Treasury Operations',
      ['treasury_admin'],
      ['read', 'leases:write'],
    );

    const refused = await call('POST', '/v1/authority-leases', admin, {
      agent_id: 'our-treasury-agent',
      grant: {
        actions: ['wire.execute'],
        resources: { bank_account: ['acct_001'], counterparty: ['cp_100'] },
        constraints: {
          max_amount: { currency: 'USD', amountMinor: '5000000' },
          currencies: ['USD'],
          allowed_counterparties: ['cp_100'],
        },
      },
      ttl_seconds: 3600,
    });
    expect(refused.status, 'the admin role is not in the policy ceilings').toBe(422);
    expect(refused.body.error.code).toBe('DELEGATION_EXCEEDS_PARENT');
    expect(refused.body.error.message).toContain('issuance ceiling');

    const lease = await call('POST', '/v1/authority-leases', provisioner, {
      agent_id: 'our-treasury-agent',
      grant: {
        actions: ['wire.execute'],
        resources: { bank_account: ['acct_001'], counterparty: ['cp_100'] },
        constraints: {
          max_amount: { currency: 'USD', amountMinor: '5000000' },
          currencies: ['USD'],
          allowed_counterparties: ['cp_100'],
        },
      },
      ttl_seconds: 3600,
    });
    expect(lease.status, JSON.stringify(lease.body)).toBe(201);
  }, 120_000);

  const wire = (nonce: string) => ({
    agent_id: 'our-treasury-agent',
    action: 'wire.execute',
    resource: { type: 'bank_account', id: 'acct_001' },
    context: {
      amount: '5000.00',
      currency: 'USD',
      counterparty_id: 'cp_100',
      destination_country: 'US',
    },
    nonce,
  });

  it('DENIES a wire to an unregistered counterparty', async () => {
    // The adoption blocker, reproduced. Everything else about this request is
    // valid: the lease covers the action, the account and the counterparty, and
    // the amount is inside every ceiling.
    const response = await call(
      'POST',
      '/v1/authorization/evaluate',
      agentToken,
      wire('before-registration'),
    );
    expect(response.status).toBe(200);
    expect(response.body.decision).toBe('DENY');
    expect(response.body.reason_code).toBe('UNKNOWN_COUNTERPARTY');
  });

  it('registers the counterparty through the API', async () => {
    const response = await call('POST', '/v1/resources', admin, {
      resource_type: 'counterparty',
      external_id: 'cp_100',
      display_name: 'Our Actual Supplier Ltd',
      attributes: { status: 'VERIFIED', country: 'US' },
    });
    expect(response.status, JSON.stringify(response.body)).toBe(201);
  });

  it('ALLOWS the same otherwise-valid request afterwards', async () => {
    // Same agent, same lease, same policy, same amount. The only thing that
    // changed is that the counterparty is now registered -- and registering it
    // is an act an administrator performs through the API, not an attribute the
    // agent can assert about itself.
    const response = await call(
      'POST',
      '/v1/authorization/evaluate',
      agentToken,
      wire('after-registration'),
    );
    expect(response.status).toBe(200);
    expect(response.body.decision, JSON.stringify(response.body)).toBe('ALLOW');
  });

  it('refuses to register the same counterparty twice', async () => {
    const response = await call('POST', '/v1/resources', admin, {
      resource_type: 'counterparty',
      external_id: 'cp_100',
      display_name: 'Duplicate',
    });
    expect(response.status).toBe(409);
  });

  it('does not let an agent register its own counterparty', async () => {
    // Registering a counterparty is what makes money movable to it. An agent
    // that could do this could authorise its own destination.
    const response = await call('POST', '/v1/resources', agentToken, {
      resource_type: 'counterparty',
      external_id: 'cp_888',
      display_name: 'Somewhere The Agent Chose',
    });
    expect(response.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------

function readPolicy(): string {
  // The canonical treasury policy, the same file the demo and a partner use.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { readFileSync } = require('node:fs') as typeof import('node:fs');
  const { fileURLToPath } = require('node:url') as typeof import('node:url');
  return readFileSync(
    fileURLToPath(new URL('../../../policies/treasury-wire.yaml', import.meta.url)),
    'utf8',
  );
}

/** A human plus the credential they act with -- the two-call pattern a partner uses. */
async function createUserWithCredential(
  email: string,
  name: string,
  roles: string[],
  scopes: string[],
): Promise<string> {
  const user = await call('POST', '/v1/users', admin, { email, display_name: name, roles });
  expect(user.status, JSON.stringify(user.body)).toBe(201);
  const credential = await call('POST', '/v1/credentials', admin, {
    principal_type: 'user',
    principal_id: user.body.user.id,
    scopes,
    expires_in_seconds: 3600,
  });
  expect(credential.status, JSON.stringify(credential.body)).toBe(201);
  return credential.body.token;
}

/** An agent's own credential, by handle -- the two-call pattern again. */
async function createAgentCredential(handle: string): Promise<string> {
  const credential = await call('POST', '/v1/credentials', admin, {
    principal_type: 'agent',
    principal_id: handle,
    scopes: ['read', 'authorization:evaluate'],
    expires_in_seconds: 3600,
  });
  expect(credential.status, JSON.stringify(credential.body)).toBe(201);
  return credential.body.token;
}

/** A human who can review a policy: not its author, holding policies:write. */
const createReviewer = (email: string, name: string) =>
  createUserWithCredential(email, name, ['policy_reviewer'], ['read', 'policies:write']);
