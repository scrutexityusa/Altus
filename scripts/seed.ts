/**
 * Seeds the reference tenant: Acme Corporation Treasury.
 *
 * Everything the demo needs and nothing it does not -- one organization, the
 * humans who can approve, the two agents, the accounts and counterparties they
 * act on, and the treasury policy pack taken through its real lifecycle
 * (draft -> two independent reviews -> activation) rather than inserted as
 * ACTIVE behind the control that exists to prevent exactly that.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { loadPolicyYaml, newId } from '@scrutexity/core';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const adminUrl =
  process.env['DATABASE_ADMIN_URL'] ??
  'postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity';

function issueToken() {
  const prefix = randomBytes(10).toString('hex').slice(0, 16);
  const secret = randomBytes(32).toString('base64url');
  const token = `scr_${prefix}.${secret}`;
  return { token, prefix, hash: createHash('sha256').update(token).digest() };
}

export interface SeedResult {
  organization_id: string;
  users: Record<string, string>;
  agents: Record<string, string>;
  tokens: Record<string, string>;
  policy_version_id: string;
}

export async function seed(connectionString = adminUrl): Promise<SeedResult> {
  const client = new pg.Client({ connectionString });
  await client.connect();

  try {
    await client.query('BEGIN');

    const orgId = newId('organization');
    // Row-level security is FORCEd, so even the owner role must name the
    // tenant it is writing. The seed is not exempt from tenant isolation.
    await client.query('SELECT set_config($1, $2, true)', ['scrutexity.org_id', orgId]);

    await client.query(
      `INSERT INTO scrutexity.organizations (id, slug, name, metadata)
       VALUES ($1, $2, $3, $4)`,
      [orgId, `acme-treasury-${orgId.slice(-6).toLowerCase()}`, 'Acme Corporation Treasury', '{}'],
    );

    const users: Record<string, string> = {};
    const userSpecs = [
      {
        key: 'admin',
        email: 'ops.admin@acme.example',
        name: 'Dana Okafor',
        roles: ['admin', 'policy_author'],
      },
      {
        key: 'reviewer',
        email: 'risk.reviewer@acme.example',
        name: 'Priya Raman',
        roles: ['admin', 'policy_reviewer'],
      },
      {
        key: 'treasurer',
        email: 'treasurer@acme.example',
        name: 'Marco Bellini',
        roles: ['treasurer', 'policy_reviewer'],
      },
      { key: 'cfo', email: 'cfo@acme.example', name: 'Aiko Tanaka', roles: ['cfo', 'treasurer'] },
      {
        key: 'agent_owner',
        email: 'treasury.ops@acme.example',
        name: 'Sam Whitfield',
        roles: ['operator'],
      },
    ];
    for (const spec of userSpecs) {
      const id = newId('user');
      users[spec.key] = id;
      await client.query(
        `INSERT INTO scrutexity.users (id, organization_id, email, display_name, roles)
         VALUES ($1,$2,$3,$4,$5)`,
        [id, orgId, spec.email, spec.name, spec.roles],
      );
    }

    const agents: Record<string, string> = {};
    const agentSpecs = [
      {
        key: 'treasury',
        handle: 'treasury-agent',
        name: 'Treasury Payments Agent',
        description: 'Prepares, submits and executes outbound wires within its authority.',
      },
      {
        key: 'verification',
        handle: 'verification-agent',
        name: 'Counterparty Verification Agent',
        description: 'Verifies counterparty records. Holds no payment authority of its own.',
      },
    ];
    for (const spec of agentSpecs) {
      const id = newId('agent');
      agents[spec.key] = id;
      await client.query(
        `INSERT INTO scrutexity.agents
           (id, organization_id, handle, display_name, description, owner_user_id)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [id, orgId, spec.handle, spec.name, spec.description, users['agent_owner']],
      );
    }

    const resourceSpecs = [
      {
        type: 'bank_account',
        external: 'acct_001',
        name: 'Operating Account — USD',
        attrs: { currency: 'USD', region: 'US' },
      },
      {
        type: 'bank_account',
        external: 'acct_002',
        name: 'Payroll Account — USD',
        attrs: { currency: 'USD', region: 'US' },
      },
      {
        type: 'bank_account',
        external: 'acct_003',
        name: 'Reserve Account — USD',
        attrs: { currency: 'USD', region: 'US', restricted: true },
      },
      {
        type: 'counterparty',
        external: 'cp_100',
        name: 'Northwind Logistics',
        attrs: { status: 'VERIFIED', country: 'US' },
      },
      {
        type: 'counterparty',
        external: 'cp_101',
        name: 'Helvetica Components AG',
        attrs: { status: 'VERIFIED', country: 'CH' },
      },
      {
        type: 'counterparty',
        external: 'cp_102',
        name: 'Marlow Facilities Ltd',
        attrs: { status: 'PROVISIONAL', country: 'GB' },
      },
    ];
    for (const spec of resourceSpecs) {
      await client.query(
        `INSERT INTO scrutexity.resources
           (id, organization_id, resource_type, external_id, display_name, attributes)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [newId('resource'), orgId, spec.type, spec.external, spec.name, JSON.stringify(spec.attrs)],
      );
    }

    // -- Policy, through its real lifecycle ---------------------------------
    const policySource = readFileSync(join(root, 'policies', 'treasury_wire.yaml'), 'utf8');
    const { document, hash } = loadPolicyYaml(policySource);

    const policyId = newId('policy');
    await client.query(
      `INSERT INTO scrutexity.policies (id, organization_id, key, name, description)
       VALUES ($1,$2,$3,$4,$5)`,
      [
        policyId,
        orgId,
        document.id,
        document.metadata.title,
        document.metadata.description ?? null,
      ],
    );

    const policyVersionId = newId('policyVersion');
    await client.query(
      `INSERT INTO scrutexity.policy_versions
         (id, organization_id, policy_id, version, status, content, content_hash, author_user_id)
       VALUES ($1,$2,$3,$4,'DRAFT',$5,$6,$7)`,
      [
        policyVersionId,
        orgId,
        policyId,
        document.version,
        JSON.stringify(document),
        hash,
        users['admin'],
      ],
    );

    for (const reviewer of ['reviewer', 'treasurer'] as const) {
      await client.query(
        `INSERT INTO scrutexity.policy_version_reviews
           (id, organization_id, policy_version_id, reviewer_user_id, vote, comment)
         VALUES ($1,$2,$3,$4,'APPROVED',$5)`,
        [
          newId('policyReview'),
          orgId,
          policyVersionId,
          users[reviewer],
          'Thresholds and approval chain reviewed against the treasury delegation of authority.',
        ],
      );
    }
    await client.query(
      `UPDATE scrutexity.policy_versions
          SET status = 'ACTIVE', approved_at = now(), activated_at = now()
        WHERE id = $1`,
      [policyVersionId],
    );

    // -- Credentials --------------------------------------------------------
    const tokens: Record<string, string> = {};
    const credentialSpecs = [
      {
        key: 'admin',
        type: 'user' as const,
        principal: users['admin']!,
        scopes: [
          'read',
          'admin:write',
          'leases:write',
          'policies:write',
          'signals:write',
          'authorization:evaluate',
        ],
      },
      {
        key: 'treasurer',
        type: 'user' as const,
        principal: users['treasurer']!,
        scopes: ['read', 'approvals:write'],
      },
      {
        key: 'cfo',
        type: 'user' as const,
        principal: users['cfo']!,
        scopes: ['read', 'approvals:write'],
      },
      {
        key: 'treasury_agent',
        type: 'agent' as const,
        principal: agents['treasury']!,
        scopes: ['read', 'authorization:evaluate', 'delegation:create'],
      },
      {
        key: 'verification_agent',
        type: 'agent' as const,
        principal: agents['verification']!,
        scopes: ['read', 'authorization:evaluate'],
      },
      {
        key: 'fraud_engine',
        type: 'service' as const,
        principal: 'svc_fraud_engine',
        scopes: ['signals:write'],
      },
    ];
    for (const spec of credentialSpecs) {
      const { token, prefix, hash: tokenHash } = issueToken();
      tokens[spec.key] = token;
      await client.query(
        `INSERT INTO scrutexity.api_credentials
           (id, organization_id, principal_type, principal_id, token_prefix, token_hash, scopes)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [newId('credential'), orgId, spec.type, spec.principal, prefix, tokenHash, spec.scopes],
      );
    }

    await client.query('COMMIT');

    return {
      organization_id: orgId,
      users,
      agents,
      tokens,
      policy_version_id: policyVersionId,
    };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    await client.end();
  }
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
      `  tokens written to ${outputPath} (git-ignored; development only)`,
      '',
    ].join('\n'),
  );
}
