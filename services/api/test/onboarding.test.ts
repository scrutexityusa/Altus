import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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

  it('records that the credential has been used', async () => {
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
    });
    expect(response.status).toBe(400);
    expect(response.body.error.message).toContain('unknown scope');
  });

  it('refuses a principal that does not exist in this organization', async () => {
    const response = await call('POST', '/v1/credentials', admin, {
      principal_type: 'user',
      principal_id: 'user_does_not_exist',
      scopes: ['read'],
    });
    expect(response.status).toBe(400);
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

    const policy = await call('POST', '/v1/policy-versions', admin, {
      document: readPolicy(),
    });
    expect(policy.status, JSON.stringify(policy.body)).toBe(201);
    const versionId = policy.body.policy_version.id;

    // TWO approvals, from TWO humans who are not the author. The bootstrap
    // admin authored this version, so it cannot review it -- which means the
    // smallest tenant that can activate a policy has three humans in it, not
    // one. That is correct dual control and it is also an onboarding fact a
    // partner has to know before they start; it is documented in the
    // onboarding guide because discovering it here would waste their afternoon.
    for (const [index, email] of ['review.one@example.com', 'review.two@example.com'].entries()) {
      const reviewer = await createReviewer(email, `Reviewer ${index + 1}`);
      const review = await call('POST', `/v1/policy-versions/${versionId}/reviews`, reviewer, {
        vote: 'APPROVED',
        comment: 'Matches our approval matrix.',
      });
      expect(review.status, JSON.stringify(review.body)).toBe(201);
    }

    const activated = await call('POST', `/v1/policy-versions/${versionId}/activate`, admin, {});
    expect(activated.status, JSON.stringify(activated.body)).toBe(200);

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
    expect(refused.status, 'the admin role is not in the policy ceilings').not.toBe(201);

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
  });
  expect(credential.status, JSON.stringify(credential.body)).toBe(201);
  return credential.body.token;
}

/** A human who can review a policy: not its author, holding policies:write. */
const createReviewer = (email: string, name: string) =>
  createUserWithCredential(email, name, ['policy_reviewer'], ['read', 'policies:write']);
