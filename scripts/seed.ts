/**
 * ============================================================================
 * Seeds the reference tenant: Acme Corporation Treasury.
 * ============================================================================
 *
 * Everything the demo needs and nothing it does not -- one organization, the
 * humans who can approve, the two agents, the accounts and counterparties they
 * act on, and the treasury policy pack taken through its real lifecycle.
 *
 * ## It is a client of the control plane, not a writer to its database
 *
 * This used to be nine `INSERT` statements against the owner connection. That
 * made database-owner access equal to application onboarding, and it hid a
 * whole class of defect: `POST /v1/policy-versions/{id}/reviews` was published
 * in the OpenAPI contract, required for any partner to activate a policy, and
 * broken -- because the seed wrote reviews with direct SQL and nothing else
 * ever called the route.
 *
 * So the seed now does exactly what a design partner does:
 *
 *     altus bootstrap        the installation ceremony, once
 *            |
 *     POST /v1/users         the humans
 *     POST /v1/credentials   their tokens, and the agents'
 *     POST /v1/agents        the machines
 *     POST /v1/resources     the accounts and counterparties
 *     POST /v1/policy-versions + reviews + activate
 *     POST /v1/signal-keys   the enrolled signal source
 *
 * The rule this file now holds to: it may orchestrate the public API and it may
 * invoke bootstrap, but it may not mutate application state directly. The
 * moment it does, the next broken onboarding route hides behind that SQL again.
 *
 * The one exception is the signal source's private key, which the seed
 * generates because it is standing up both ends -- the tenant and the fixture
 * source that signs for it. Scrutexity only ever receives the public half,
 * through the API, like any source.
 */
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildApp, type App } from '../services/api/src/app.js';
import { bootstrap, provisionAdditionalTenant } from './bootstrap.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const adminUrl =
  process.env['DATABASE_ADMIN_URL'] ??
  'postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity';
const appUrl =
  process.env['DATABASE_URL'] ?? 'postgres://scrutexity_app:scrutexity@127.0.0.1:5432/scrutexity';

export interface SeedResult {
  organization_id: string;
  users: Record<string, string>;
  agents: Record<string, string>;
  tokens: Record<string, string>;
  policy_version_id: string;
  /**
   * The private halves of the enrolled signal sources' keys, by source name.
   *
   * These belong to the *source*, not to Scrutexity: a real fraud engine
   * generates its own keypair and registers only the public half. The seed
   * holds both ends because it is standing up both ends.
   */
  signal_source_keys: Record<string, { key_id: string; private_key_pem: string }>;
}

/** The signal sources the reference tenant trusts. Enrolment is mandatory. */
const SIGNAL_SOURCES = ['external_fraud_engine', 'agent_self_report'] as const;

/**
 * The humans.
 *
 * Note who holds what. `treasury_admin` is the role the policy's issuance
 * ceiling names, and it is what actually permits issuing a lease -- the
 * `leases:write` scope only permits calling the endpoint. Being an org admin is
 * not by itself authority to provision paying agents.
 *
 * Note also that the policy author is not a reviewer: a policy needs two
 * approvals from humans who did not write it, so the smallest tenant that can
 * activate one has three people in it.
 */
const USERS = [
  {
    key: 'admin',
    email: 'ops.admin@acme.example',
    name: 'Dana Okafor',
    roles: ['admin', 'policy_author', 'treasury_admin'],
    scopes: [
      'read',
      'audit:read',
      'admin:write',
      'leases:write',
      'policies:write',
      'signals:write',
      'authorization:evaluate',
    ],
  },
  {
    key: 'reviewer',
    email: 'risk.reviewer@acme.example',
    name: 'Priya Raman',
    roles: ['admin', 'policy_reviewer'],
    scopes: ['read', 'audit:read', 'policies:write'],
  },
  {
    key: 'treasurer',
    email: 'treasurer@acme.example',
    name: 'Marco Bellini',
    roles: ['treasurer', 'policy_reviewer'],
    // leases:write is deliberate, and it is the point of the issuance ceiling:
    // a treasurer may provision read-only agents, and the scope alone does not
    // let them mint a paying one. The scope opens the endpoint; the role bounds
    // what may come out of it.
    scopes: ['read', 'audit:read', 'approvals:write', 'policies:write', 'leases:write'],
  },
  {
    key: 'cfo',
    email: 'cfo@acme.example',
    name: 'Aiko Tanaka',
    roles: ['cfo', 'treasurer'],
    scopes: ['read', 'audit:read', 'approvals:write'],
  },
  {
    key: 'agent_owner',
    email: 'treasury.ops@acme.example',
    name: 'Sam Whitfield',
    roles: ['operator'],
    scopes: ['read'],
  },
] as const;

const AGENTS = [
  {
    key: 'treasury',
    handle: 'treasury-agent',
    name: 'Treasury Payments Agent',
    description: 'Prepares, submits and executes outbound wires within its authority.',
    scopes: ['read', 'authorization:evaluate', 'delegation:create'],
  },
  {
    key: 'verification',
    handle: 'verification-agent',
    name: 'Counterparty Verification Agent',
    description: 'Verifies counterparty records. Holds no payment authority of its own.',
    // May sub-delegate the reads it holds. Scope grants the ability to ask;
    // containment is what stops it passing on authority it never had.
    scopes: ['read', 'authorization:evaluate', 'delegation:create'],
  },
] as const;

const RESOURCES = [
  {
    resource_type: 'bank_account',
    external_id: 'acct_001',
    display_name: 'Operating Account — USD',
    attributes: { currency: 'USD', region: 'US' },
  },
  {
    resource_type: 'bank_account',
    external_id: 'acct_002',
    display_name: 'Payroll Account — USD',
    attributes: { currency: 'USD', region: 'US' },
  },
  {
    resource_type: 'bank_account',
    external_id: 'acct_003',
    display_name: 'Reserve Account — USD',
    attributes: { currency: 'USD', region: 'US', restricted: true },
  },
  {
    resource_type: 'counterparty',
    external_id: 'cp_100',
    display_name: 'Northwind Logistics',
    attributes: { status: 'VERIFIED', country: 'US' },
  },
  {
    resource_type: 'counterparty',
    external_id: 'cp_101',
    display_name: 'Helvetica Components AG',
    attributes: { status: 'VERIFIED', country: 'CH' },
  },
  {
    resource_type: 'counterparty',
    external_id: 'cp_102',
    display_name: 'Marlow Facilities Ltd',
    attributes: { status: 'PROVISIONAL', country: 'GB' },
  },
];

class SeedError extends Error {}

export interface SeedOptions {
  /**
   * Provision onto an installation that has already had its ceremony.
   *
   * The test harness seeds two tenants to prove isolation between them. The
   * second is not a second installation, so it does not get a second bootstrap.
   */
  additionalTenant?: boolean;
}

export async function seed(
  connectionString = adminUrl,
  options: SeedOptions = {},
): Promise<SeedResult> {
  // The installation ceremony. The only step that uses the owner connection,
  // and the last time it appears in this file.
  const ceremony = options.additionalTenant ? provisionAdditionalTenant : bootstrap;
  const installation = await ceremony({
    connectionString,
    orgName: 'Acme Corporation Treasury',
    orgSlug: `acme-treasury-${Date.now().toString(36)}`,
    adminName: 'Dana Okafor',
    adminEmail: 'ops.admin@acme.example',
  });

  // An in-process server, so seeding needs no separately running API. Every
  // call below goes through the same routes, scopes and RLS a partner's curl
  // would.
  const app: App = await buildApp({
    NODE_ENV: 'development',
    DATABASE_URL: appUrl,
    LOG_LEVEL: 'silent',
  });

  try {
    const api = requester(app, installation.token);

    const users: Record<string, string> = { admin: installation.admin_user_id };
    const tokens: Record<string, string> = {};

    // The bootstrap admin already exists as a user; give them the roles the
    // policy's issuance ceilings name. `treasury_admin` is what actually
    // permits issuing a lease -- the `leases:write` scope only permits calling
    // the endpoint.
    await api('PATCH', `/v1/users/${installation.admin_user_id}`, {
      roles: [...USERS[0].roles],
    });

    // Then issue the admin a working credential and stop using the bootstrap
    // one. This is what a partner does: the ceremony credential is a foothold
    // that can provision and deliberately cannot act, so the first thing it is
    // used for is issuing a credential that can.
    const adminCredential = await api('POST', '/v1/credentials', {
      principal_type: 'user',
      principal_id: installation.admin_user_id,
      scopes: [...USERS[0].scopes],
    });
    tokens['admin'] = adminCredential.token;

    for (const spec of USERS.slice(1)) {
      const user = await api('POST', '/v1/users', {
        email: spec.email,
        display_name: spec.name,
        roles: [...spec.roles],
      });
      users[spec.key] = user.user.id;
      const credential = await api('POST', '/v1/credentials', {
        principal_type: 'user',
        principal_id: user.user.id,
        scopes: [...spec.scopes],
      });
      tokens[spec.key] = credential.token;
    }

    const agents: Record<string, string> = {};
    for (const spec of AGENTS) {
      const agent = await api('POST', '/v1/agents', {
        handle: spec.handle,
        display_name: spec.name,
        description: spec.description,
        owner_user_id: users['agent_owner'],
      });
      agents[spec.key] = agent.agent.id;
      const credential = await api('POST', '/v1/credentials', {
        principal_type: 'agent',
        principal_id: spec.handle,
        scopes: [...spec.scopes],
      });
      tokens[`${spec.key}_agent`] = credential.token;
    }

    for (const resource of RESOURCES) {
      await api('POST', '/v1/resources', resource);
    }

    // -- Policy, through its real lifecycle ---------------------------------
    // Draft, two approvals from humans who did not author it, then activation.
    // This is the path that was broken and undetected while the seed wrote
    // reviews with SQL.
    const version = await api('POST', '/v1/policy-versions', {
      document: readFileSync(join(root, 'policies', 'treasury-wire.yaml'), 'utf8'),
    });
    const versionId = version.policy_version.id as string;

    for (const reviewer of ['reviewer', 'treasurer'] as const) {
      await requester(app, tokens[reviewer]!)('POST', `/v1/policy-versions/${versionId}/reviews`, {
        vote: 'APPROVED',
        comment:
          'Thresholds and approval chain reviewed against the treasury delegation of authority.',
      });
    }
    await api('POST', `/v1/policy-versions/${versionId}/activate`, {});

    // -- Signal source enrolment --------------------------------------------
    // Ed25519 only. The source generates its own keypair; Scrutexity receives
    // the public half through the same endpoint an operator would use.
    const signalSourceKeys: SeedResult['signal_source_keys'] = {};
    for (const source of SIGNAL_SOURCES) {
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      const keyId = `${source}-2026-01`;
      signalSourceKeys[source] = {
        key_id: keyId,
        private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      };
      await api('POST', '/v1/signal-keys', {
        source,
        key_id: keyId,
        algorithm: 'ED25519',
        key_material: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      });
    }

    // The fraud engine's own credential, so it can post signals as a service.
    const fraudCredential = await api('POST', '/v1/credentials', {
      principal_type: 'service',
      principal_id: 'svc_fraud_engine',
      scopes: ['signals:write'],
    });
    tokens['fraud_engine'] = fraudCredential.token;

    return {
      organization_id: installation.organization_id,
      users,
      agents,
      tokens,
      policy_version_id: versionId,
      signal_source_keys: signalSourceKeys,
    };
  } finally {
    await app.close();
  }
}

/**
 * Calls the API the way a partner would, and refuses to continue quietly.
 *
 * A seed that swallows a non-2xx produces a half-built tenant and a confusing
 * failure three steps later. Every call is checked.
 */
function requester(app: App, token: string) {
  return async (method: string, url: string, body?: unknown) => {
    const response = await app.server.inject({
      method: method as never,
      url,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { payload: JSON.stringify(body) }),
    });
    const parsed = response.body ? JSON.parse(response.body) : null;
    if (response.statusCode >= 300) {
      throw new SeedError(`${method} ${url} -> ${response.statusCode}: ${JSON.stringify(parsed)}`);
    }
    return parsed;
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const result = await seed();
  const outputPath = join(root, '.seed.local.json');
  writeFileSync(outputPath, JSON.stringify(result, null, 2));
  process.stdout.write(
    [
      `seeded organization ${result.organization_id}`,
      `  agents:    ${Object.entries(result.agents)
        .map(([k, v]) => `${k}=${v}`)
        .join(', ')}`,
      `  policy:    ${result.policy_version_id} (ACTIVE)`,
      `  signals:   ${Object.entries(result.signal_source_keys)
        .map(([source, key]) => `${source} (${key.key_id}, ED25519)`)
        .join(', ')}`,
      `  tokens written to ${outputPath} (git-ignored; development only)`,
      '',
    ].join('\n'),
  );
}
