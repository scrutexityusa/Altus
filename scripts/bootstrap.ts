/**
 * ============================================================================
 * Installation ceremony: the first tenant and the first administrative
 * foothold.
 * ============================================================================
 *
 * This is the boundary between two different kinds of trust, and it exists as
 * its own command because those two things must not be reachable by the same
 * credential:
 *
 *     INSTALLATION TRUST      the database owner. Can create anything, bypasses
 *            │                row level security, and has no business existing
 *            │                in the normal operating story.
 *         BOOTSTRAP           one organization, one admin, one credential.
 *            │                Runs once, at install time.
 *            ▼
 *     APPLICATION TRUST       everything after: users, credentials, resources,
 *                             policy, agents, leases -- all through the public
 *                             API, all subject to RLS and scope checks.
 *
 * Before this existed, the only path to a usable tenant was `scripts/seed.ts`,
 * which connects as the owner and creates a hard-coded fictional organization.
 * That made database-owner access *equal to* application onboarding, so a
 * design partner could not create their own tenant without editing a script
 * that bypasses every control the product sells. The two concepts are now
 * separate, and the owner connection disappears from the story after this
 * command returns.
 *
 * ## Why this is not `migrate --bootstrap`
 *
 * Migration is a schema lifecycle operation. This creates principals and
 * issues a credential. Folding them together would make the migration runner
 * -- which any operator runs on any deploy -- capable of minting an
 * administrative credential, and would force it to understand application
 * concerns like which scopes an admin needs. They stay separate and explicit.
 *
 * ## Why it refuses to run twice
 *
 * A bootstrap credential is an installation ceremony, not an API capability.
 * If this became a convenient way to create tenant number two, it would be a
 * tenant-provisioning API that happens to be a CLI and happens to bypass every
 * authorization check. So: zero organizations means create one; anything else
 * means refuse and say so.
 */
import { createHash, randomBytes } from 'node:crypto';
import pg from 'pg';
import { newId } from '@scrutexity/core';

/**
 * The privileged connection, and deliberately not `DATABASE_ADMIN_URL`.
 *
 * A distinct name means an operator cannot reach this by having the migration
 * runner's environment already loaded. Discovering an owner connection through
 * the normal runtime configuration is exactly the silent path this command
 * exists to remove, so there is no fallback: absent means refuse.
 */
const BOOTSTRAP_URL_VAR = 'ALTUS_BOOTSTRAP_DATABASE_URL';

/**
 * What the first credential can do, and nothing more.
 *
 * Enough to take over from the ceremony -- create the humans, issue their
 * credentials, register the accounts and counterparties, and publish the first
 * policy. Deliberately *not* `authorization:evaluate`, `approvals:write` or
 * `signals:write`: the installation credential provisions, it does not act.
 * An operator who wants to approve a payment issues themselves a credential
 * that can, through the API, where it is recorded.
 */
const BOOTSTRAP_SCOPES = ['read', 'audit:read', 'admin:write', 'leases:write', 'policies:write'];

const USAGE = `
altus bootstrap -- create the first organization and its administrator

  Runs once, at install time, against the database owner connection. Every
  subsequent principal, credential and resource is created through the public
  API using the credential this prints.

USAGE
  ${BOOTSTRAP_URL_VAR}=postgres://owner:pass@host:5432/db \\
    pnpm altus bootstrap --org-name "Example Treasury" \\
                         --admin-name "Jane Smith" \\
                         --admin-email "jane@example.com"

REQUIRED
  --org-name    <name>    Display name of the organization
  --admin-name  <name>    Display name of the first administrator
  --admin-email <email>   Their email; unique within the organization

OPTIONAL
  --org-slug    <slug>    URL-safe identifier. Derived from --org-name if absent
  --json                  Machine-readable output on stdout
  --help                  This text

ENVIRONMENT
  ${BOOTSTRAP_URL_VAR}    Required. The database OWNER connection. There is no
                          fallback to DATABASE_URL or DATABASE_ADMIN_URL: this
                          step uses elevated credentials and saying so out loud
                          is the point.

NOTES
  The credential secret is printed exactly once and never stored. Scrutexity
  keeps only a SHA-256 hash and a non-secret lookup prefix.

  This command refuses to run against an installation that already has an
  organization. It is an installation ceremony, not a tenant-provisioning API.
`;

class BootstrapError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly remedy?: string,
  ) {
    super(message);
    this.name = 'BootstrapError';
  }
}

function flag(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  // `--org-name --json` is a missing value, not a value of "--json".
  if (value === undefined || value.startsWith('--')) {
    throw new BootstrapError('MISSING_ARGUMENT_VALUE', `--${name} requires a value`);
  }
  return value;
}

function required(name: string): string {
  const value = flag(name);
  if (value === undefined || value.trim() === '') {
    throw new BootstrapError('MISSING_ARGUMENT', `--${name} is required`, USAGE);
  }
  return value.trim();
}

/** Lowercase, hyphenated, no leading or trailing separators. */
function slugify(name: string): string {
  const slug = name
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  if (slug === '') {
    throw new BootstrapError(
      'ORG_SLUG_UNDERIVABLE',
      'could not derive a slug from --org-name; pass --org-slug explicitly',
    );
  }
  return slug;
}

/**
 * `scr_<prefix>.<secret>`. Only the prefix and a SHA-256 of the whole token are
 * stored, so a database disclosure does not yield a usable credential. Same
 * construction the seed uses, because two token formats would eventually
 * disagree about which half is the lookup key.
 */
function issueToken() {
  const prefix = randomBytes(10).toString('hex').slice(0, 16);
  const secret = randomBytes(32).toString('base64url');
  const token = `scr_${prefix}.${secret}`;
  return { token, prefix, hash: createHash('sha256').update(token).digest() };
}

export interface BootstrapInput {
  connectionString: string;
  orgName: string;
  orgSlug: string;
  adminName: string;
  adminEmail: string;
}

export interface BootstrapResult {
  organization_id: string;
  organization_slug: string;
  admin_user_id: string;
  credential_id: string;
  /** Printed once. Never persisted, never returned by any API. */
  token: string;
  scopes: string[];
}

/**
 * Preflight, then the ceremony, in one transaction.
 *
 * The organization count is read inside the transaction that would create one,
 * so two operators racing this cannot both pass the check. The unique index on
 * `organizations.slug` is the second line of defence; the count is what
 * produces the readable error.
 */
export async function bootstrap(input: BootstrapInput): Promise<BootstrapResult> {
  const client = new pg.Client({ connectionString: input.connectionString });
  await client.connect();

  try {
    await preflight(client);
    await client.query('BEGIN');

    const orgId = newId('organization');
    // Row level security is FORCEd, so even the owner must name the tenant it
    // is writing. The ceremony is not exempt from tenant isolation.
    await client.query('SELECT set_config($1, $2, true)', ['scrutexity.org_id', orgId]);

    await client.query(
      `INSERT INTO scrutexity.organizations (id, slug, name, metadata)
       VALUES ($1, $2, $3, $4)`,
      [orgId, input.orgSlug, input.orgName, JSON.stringify({ bootstrapped: true })],
    );

    const userId = newId('user');
    await client.query(
      `INSERT INTO scrutexity.users (id, organization_id, email, display_name, roles)
       VALUES ($1, $2, $3, $4, $5)`,
      // `admin` is the platform role this credential's scopes reflect.
      // Business roles -- treasurer, cfo -- are the tenant's vocabulary and are
      // created through the API, not assumed here.
      [userId, orgId, input.adminEmail, input.adminName, ['admin']],
    );

    const credentialId = newId('credential');
    const { token, prefix, hash } = issueToken();
    await client.query(
      `INSERT INTO scrutexity.api_credentials
         (id, organization_id, principal_type, principal_id, token_prefix, token_hash, scopes)
       VALUES ($1, $2, 'user', $3, $4, $5, $6)`,
      [credentialId, orgId, userId, prefix, hash, BOOTSTRAP_SCOPES],
    );

    // The gate, and deliberately the LAST statement rather than the first.
    //
    // `installation` permits exactly one row by construction, so a second
    // bootstrap fails here on the primary key -- inside the transaction that
    // would have created the tenant, which then rolls back whole. There is no
    // window between checking and creating, because there is no check.
    //
    // The first version of this read `count(*) FROM organizations` before
    // inserting. That count is filtered by FORCE ROW LEVEL SECURITY and returns
    // zero whether or not organizations exist, so the guard passed silently on
    // an already-bootstrapped installation and the run failed later on a slug
    // collision -- or would have succeeded outright for a differently-named
    // organization. A security check that RLS can filter is not a check.
    await client.query(
      `INSERT INTO scrutexity.installation (organization_id, admin_user_id, metadata)
       VALUES ($1, $2, $3)`,
      [orgId, userId, JSON.stringify({ org_slug: input.orgSlug })],
    );

    await client.query('COMMIT');

    return {
      organization_id: orgId,
      organization_slug: input.orgSlug,
      admin_user_id: userId,
      credential_id: credentialId,
      token,
      scopes: BOOTSTRAP_SCOPES,
    };
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    // 23505 on `installation` is the single-row invariant refusing a second
    // ceremony. Reported as what it means rather than as a constraint name.
    if ((error as { code?: string }).code === '23505') {
      const prior = await priorInstallation(client).catch(() => null);
      throw new BootstrapError(
        'ALREADY_BOOTSTRAPPED',
        prior
          ? `this installation was bootstrapped at ${prior.bootstrapped_at} ` +
              `(organization ${prior.organization_id})`
          : 'this installation has already been bootstrapped',
        'Bootstrap establishes the first administrative foothold only. Create further\n' +
          'principals, credentials and resources through the API with an existing admin\n' +
          'credential:\n\n' +
          '  POST /v1/users        POST /v1/credentials        POST /v1/resources\n\n' +
          'To start over in development:  pnpm altus migrate --reset',
      );
    }
    throw error;
  } finally {
    await client.end();
  }
}

/** Reads the installation row for a useful error. Never part of the guard. */
async function priorInstallation(
  client: pg.Client,
): Promise<{ organization_id: string; bootstrapped_at: string } | null> {
  const result = await client.query<{ organization_id: string; bootstrapped_at: Date }>(
    'SELECT organization_id, bootstrapped_at FROM scrutexity.installation',
  );
  const row = result.rows[0];
  return row
    ? { organization_id: row.organization_id, bootstrapped_at: row.bootstrapped_at.toISOString() }
    : null;
}

/**
 * Fail with something actionable rather than a driver error.
 *
 * An operator running this for the first time is the least-oriented person who
 * will ever touch the system. "relation scrutexity.organizations does not
 * exist" is true and useless; "run pnpm altus migrate first" is neither.
 */
async function preflight(client: pg.Client): Promise<void> {
  const schema = await client.query(
    `SELECT 1 FROM information_schema.schemata WHERE schema_name = 'scrutexity'`,
  );
  if (schema.rowCount === 0) {
    throw new BootstrapError(
      'SCHEMA_NOT_MIGRATED',
      'the scrutexity schema does not exist',
      'Run the migrations first:  pnpm altus migrate',
    );
  }

  const table = await client.query(
    `SELECT 1 FROM information_schema.tables
      WHERE table_schema = 'scrutexity' AND table_name IN ('organizations', 'installation')
     GROUP BY 1 HAVING count(*) = 2`,
  );
  if (table.rowCount === 0) {
    throw new BootstrapError(
      'SCHEMA_INCOMPLETE',
      'the scrutexity schema exists but is missing tables bootstrap depends on',
      'Migrations are partially applied. Run:  pnpm altus migrate',
    );
  }
}

// ---------------------------------------------------------------------------

function report(result: BootstrapResult, json: boolean): void {
  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  const ESC = String.fromCharCode(27);
  const paint = (code: string, text: string) =>
    process.env['NO_COLOR'] ? text : `${ESC}[${code}m${text}${ESC}[0m`;
  const bold = (t: string) => paint('1', t);
  const dim = (t: string) => paint('2', t);
  const green = (t: string) => paint('32', t);

  process.stdout.write(
    [
      '',
      green(bold('  Bootstrapped.')),
      '',
      `  organization  ${bold(result.organization_id)}  ${dim(`(${result.organization_slug})`)}`,
      `  administrator ${bold(result.admin_user_id)}`,
      `  credential    ${bold(result.credential_id)}`,
      `  scopes        ${result.scopes.join(', ')}`,
      '',
      bold('  This token is shown once and is not recoverable:'),
      '',
      `    ${green(result.token)}`,
      '',
      dim('  Everything from here goes through the API with that credential:'),
      dim('    POST /v1/users        the humans who approve'),
      dim('    POST /v1/credentials  their tokens, and your agents’'),
      dim('    POST /v1/resources    your accounts and counterparties'),
      dim('    POST /v1/policy-versions   your approval ladder'),
      '',
      dim('  The owner connection is not needed again.'),
      '',
    ].join('\n'),
  );
}

async function main(): Promise<void> {
  if (process.argv.includes('--help') || process.argv.includes('-h')) {
    process.stdout.write(USAGE);
    return;
  }

  const connectionString = process.env[BOOTSTRAP_URL_VAR];
  if (!connectionString || connectionString.trim() === '') {
    throw new BootstrapError(
      'BOOTSTRAP_DATABASE_URL_REQUIRED',
      `${BOOTSTRAP_URL_VAR} is required and has no fallback`,
      'This step uses the database OWNER connection. Naming it explicitly is\n' +
        'deliberate: it must not be reachable by whatever happened to be in the\n' +
        'environment already.\n\n' +
        `  ${BOOTSTRAP_URL_VAR}=postgres://owner:pass@host:5432/db pnpm altus bootstrap ...`,
    );
  }

  const orgName = required('org-name');
  const result = await bootstrap({
    connectionString,
    orgName,
    orgSlug: flag('org-slug')?.trim() || slugify(orgName),
    adminName: required('admin-name'),
    adminEmail: required('admin-email').toLowerCase(),
  });
  report(result, process.argv.includes('--json'));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    await main();
  } catch (error) {
    const ESC = String.fromCharCode(27);
    const red = (t: string) => (process.env['NO_COLOR'] ? t : `${ESC}[31m${t}${ESC}[0m`);
    if (error instanceof BootstrapError) {
      process.stderr.write(`\n  ${red(error.code)}\n  ${error.message}\n`);
      if (error.remedy) process.stderr.write(`\n${error.remedy.replace(/^/gm, '  ')}\n`);
      process.stderr.write('\n');
    } else {
      process.stderr.write(`\n  ${red('BOOTSTRAP_FAILED')}\n  ${String(error)}\n\n`);
    }
    process.exitCode = 1;
  }
}

export { BootstrapError, BOOTSTRAP_SCOPES, BOOTSTRAP_URL_VAR };
