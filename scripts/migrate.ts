/**
 * Migration runner.
 *
 * Applies db/migrations/*.sql in lexical order inside a transaction each, and
 * records the file's SHA-256. Re-running is a no-op; editing an applied
 * migration is an error, because a schema that silently diverges from its
 * recorded history is a schema nobody can reason about.
 *
 * Migration files must NOT open their own transaction. The runner wraps each
 * one together with its bookkeeping row, so a failure leaves neither the DDL
 * nor the record of it behind. A file with its own BEGIN/COMMIT would commit
 * the DDL independently and defeat that.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const migrationsDir = join(root, 'db', 'migrations');

const adminUrl =
  process.env['DATABASE_ADMIN_URL'] ??
  'postgres://scrutexity_owner:scrutexity@127.0.0.1:5432/scrutexity';

const reset = process.argv.includes('--reset');
const downIndex = process.argv.indexOf('--down');
/** `--down` rolls back the newest migration; `--down N` rolls back N. */
const downCount = downIndex === -1 ? 0 : Math.max(1, Number(process.argv[downIndex + 1] ?? 1) || 1);

/**
 * Every migration `NNNN_name.sql` may have a sibling `NNNN_name.down.sql`.
 * Rolling back is deliberately explicit rather than inferred: a generated
 * inverse of a DDL statement is a guess, and guessing at the shape of the
 * table that holds authorization evidence is not acceptable.
 */
function downFileFor(filename: string): string {
  return filename.replace(/\.sql$/, '.down.sql');
}

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
    .filter((name) => name.endsWith('.sql') && !name.endsWith('.down.sql'))
    .sort();

  if (downCount > 0) {
    const rollback = (
      await client.query(
        `SELECT filename FROM scrutexity.schema_migrations
          ORDER BY filename DESC LIMIT $1`,
        [downCount],
      )
    ).rows.map((row: { filename: string }) => row.filename);

    if (rollback.length === 0) {
      process.stdout.write('nothing to roll back\n');
    }
    for (const filename of rollback) {
      const downPath = join(migrationsDir, downFileFor(filename));
      if (!existsSync(downPath)) {
        throw new Error(
          `cannot roll back ${filename}: ${downFileFor(filename)} does not exist. ` +
            'A migration without a down migration is a one-way door; write one before rolling back.',
        );
      }
      process.stdout.write(`  - ${filename}\n`);
      await client.query('BEGIN');
      try {
        // The bookkeeping row goes first. A down migration is allowed to drop
        // the schema that holds schema_migrations, and deleting afterwards
        // would fail against a table that no longer exists. Both statements
        // are in one transaction, so a failing rollback restores the row.
        await client.query('DELETE FROM scrutexity.schema_migrations WHERE filename = $1', [
          filename,
        ]);
        await client.query(readFileSync(downPath, 'utf8'));
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw new Error(`rollback of ${filename} failed: ${String(error)}`);
      }
    }
    process.stdout.write('rollback complete\n');
    process.exit(0);
  }

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
