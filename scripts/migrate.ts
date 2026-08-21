/**
 * Migration runner.
 *
 * Applies db/migrations/*.sql in lexical order inside a transaction each, and
 * records the file's SHA-256. Re-running is a no-op; editing an applied
 * migration is an error, because a schema that silently diverges from its
 * recorded history is a schema nobody can reason about.
 */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const migrationsDir = join(root, 'db', 'migrations');

const adminUrl =
  process.env['DATABASE_ADMIN_URL'] ??
  'postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity';

const reset = process.argv.includes('--reset');

const client = new pg.Client({ connectionString: adminUrl });
await client.connect();

try {
  if (reset) {
    process.stdout.write('dropping schema scrutexity\n');
    await client.query('DROP SCHEMA IF EXISTS scrutexity CASCADE');
  }

  await client.query(`
    CREATE SCHEMA IF NOT EXISTS scrutexity;
    CREATE TABLE IF NOT EXISTS scrutexity.schema_migrations (
      filename    TEXT PRIMARY KEY,
      checksum    TEXT NOT NULL,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  const applied = new Map<string, string>(
    (await client.query('SELECT filename, checksum FROM scrutexity.schema_migrations')).rows.map(
      (row: { filename: string; checksum: string }) => [row.filename, row.checksum],
    ),
  );

  const files = readdirSync(migrationsDir)
    .filter((name) => name.endsWith('.sql'))
    .sort();

  for (const filename of files) {
    const source = readFileSync(join(migrationsDir, filename), 'utf8');
    const checksum = createHash('sha256').update(source).digest('hex');
    const previous = applied.get(filename);

    if (previous === checksum) {
      process.stdout.write(`  = ${filename}\n`);
      continue;
    }
    if (previous && previous !== checksum) {
      throw new Error(
        `migration ${filename} has changed since it was applied (recorded ${previous.slice(0, 12)}, now ${checksum.slice(0, 12)}). Add a new migration instead of editing an applied one.`,
      );
    }

    process.stdout.write(`  + ${filename}\n`);
    await client.query('BEGIN');
    try {
      await client.query(source);
      await client.query(
        'INSERT INTO scrutexity.schema_migrations (filename, checksum) VALUES ($1, $2)',
        [filename, checksum],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw new Error(`migration ${filename} failed: ${String(error)}`);
    }
  }
  process.stdout.write('migrations up to date\n');
} finally {
  await client.end();
}
