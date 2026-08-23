import { defineConfig } from 'vitest/config';
import { common, resolve } from './vitest.shared.js';

/**
 * The whole suite: pure domain, integration, security and contracts.
 *
 * Needs a reachable PostgreSQL cluster. `vitest.unit.config.ts` is the half
 * that does not.
 */
export default defineConfig({
  resolve,
  test: {
    ...common,
    include: ['packages/**/*.test.ts', 'services/**/*.test.ts', 'spec/**/*.test.ts'],
    // Provisions and drops a database for this run. Tests never touch the
    // development database -- they disable append-only triggers and reset
    // schemas, which is not something to point at data anyone cares about.
    globalSetup: ['./test/global-setup.ts'],
    // Integration tests share one Postgres database; running files in parallel
    // would interleave tenant fixtures. Correctness beats a faster suite.
    fileParallelism: false,
  },
});
