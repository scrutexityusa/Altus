import pg from 'pg';
import { ScrutexityError } from '@scrutexity/core';
import type { Config } from '../config.js';

const { Pool } = pg;
export type PoolClient = pg.PoolClient;

/**
 * Postgres NUMERIC must not become a JS float on its way into an
 * authorization decision. Signal values and confidences arrive as exact
 * decimal strings and stay that way.
 */
pg.types.setTypeParser(1700, (value) => value);
/** int8: read as string; the only int8 in the schema is a receipt sequence. */
pg.types.setTypeParser(20, (value) => value);

export interface Database {
  /**
   * Runs `fn` inside a transaction scoped to one tenant. The organization id
   * is set as a transaction-local GUC, which every row-level security policy
   * keys on: a query that forgets its tenant sees nothing and writes nothing.
   */
  withTenant<T>(organizationId: string, fn: (client: PoolClient) => Promise<T>): Promise<T>;
  /** Unscoped access, for authentication and platform administration only. */
  withoutTenant<T>(fn: (client: PoolClient) => Promise<T>): Promise<T>;
  close(): Promise<void>;
  readonly pool: pg.Pool;
}

export function createDatabase(config: Config): Database {
  const pool = new Pool({
    connectionString: config.DATABASE_URL,
    max: config.DATABASE_POOL_MAX,
    application_name: 'scrutexity-api',
    // A control plane that hangs is a control plane that fails open by
    // accident. Bound every wait.
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
    statement_timeout: 10_000,
    query_timeout: 10_000,
  });

  async function run<T>(
    organizationId: string | null,
    fn: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      if (organizationId !== null) {
        if (!/^org_[0-9A-HJKMNP-TV-Z]{26}$/.test(organizationId)) {
          // set_config takes a literal; refusing anything but a well-formed id
          // removes the question of injection entirely.
          throw new ScrutexityError('INTERNAL_ERROR', 'malformed organization id', {
            internal: { organizationId },
          });
        }
        await client.query('SELECT set_config($1, $2, true)', ['scrutexity.org_id', organizationId]);
      }
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  return {
    pool,
    withTenant: (organizationId, fn) => run(organizationId, fn),
    withoutTenant: (fn) => run(null, fn),
    close: () => pool.end(),
  };
}
