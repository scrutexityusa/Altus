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
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
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
  /**
   * The private halves of the enrolled signal sources' keys, by source name.
   *
   * These belong to the *source*, not to Scrutexity: in a real deployment the
   * fraud engine generates its own keypair and registers only the public half,
   * and Scrutexity never sees this value at all. The seed holds both ends
   * because it is standing up both ends -- the tenant and the fixture source
   * that signs for it -- and they are written to a git-ignored development
   * file.
   */
  signal_source_keys: Record<string, { key_id: string; private_key_pem: string }>;
}

/**
 * The signal sources the reference tenant trusts.
 *
 * Enrolment is not optional and there is no implicit trust: a source with no
 * registered key can assert nothing, because nothing it says is attributable
 * to it. The seed enrols this one for the same reason a real operator would --
 * so that its signals are accepted -- and not as a convenience that makes the
 * demo work.
 */
const SIGNAL_SOURCES = ['external_fraud_engine', 'agent_self_report'] as const;

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
        // treasury_admin is what the policy's issuance ceiling names. Being
        // an org admin is not by itself authority to provision paying agents:
        // the scope lets them call the endpoint, the role bounds what may
        // come out of it.
        roles: ['admin', 'policy_author', 'treasury_admin'],
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
          'audit:read',
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
        // audit:read so an approver can see the security event log and the
        // policy they are approving under. Never granted to an agent.
        //
        // leases:write is deliberate, and it is the point of the issuance
        // ceiling: a treasurer may provision read-only agents, and the scope
        // alone does not let them mint a paying one. The scope opens the
        // endpoint; the role bounds what may come out of it.
        scopes: ['read', 'audit:read', 'approvals:write', 'leases:write'],
      },
      {
        key: 'cfo',
        type: 'user' as const,
        principal: users['cfo']!,
        scopes: ['read', 'audit:read', 'approvals:write'],
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
        // May sub-delegate the reads it holds. Scope grants the ability to ask;
        // containment is what stops it passing on authority it never had.
        scopes: ['read', 'authorization:evaluate', 'delegation:create'],
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

    // -- Signal source enrolment ------------------------------------------
    // Ed25519 only. An HMAC key would mean this database holds the secret that
    // manufactures signals reducing the treasury agent's authority, so a
    // disclosure of the tenant's data would also be a forgery capability. With
    // a keypair, only the public half is stored and a disclosure yields
    // nothing signable. Production refuses to register anything else.
    const signalSourceKeys: SeedResult['signal_source_keys'] = {};
    for (const source of SIGNAL_SOURCES) {
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      const keyId = `${source}-2026-01`;
      signalSourceKeys[source] = {
        key_id: keyId,
        private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      };
      await client.query(
        `INSERT INTO scrutexity.signal_signing_keys
           (id, organization_id, source, key_id, algorithm, key_material, not_before)
         VALUES ($1,$2,$3,$4,'ED25519',$5, now())`,
        [
          newId('signalKey'),
          orgId,
          source,
          keyId,
          publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        ],
      );
    }

    await client.query('COMMIT');

    return {
      organization_id: orgId,
      users,
      agents,
      tokens,
      policy_version_id: policyVersionId,
      signal_source_keys: signalSourceKeys,
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
      `  signals:   ${Object.entries(result.signal_source_keys)
        .map(([source, key]) => `${source} (${key.key_id}, ED25519)`)
        .join(', ')}`,
      `  tokens written to ${outputPath} (git-ignored; development only)`,
      '',
    ].join('\n'),
  );
}
