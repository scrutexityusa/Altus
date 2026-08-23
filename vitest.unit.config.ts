import { defineConfig } from 'vitest/config';
import { common, resolve } from './vitest.shared.js';

/**
 * The pure domain: no database, no server, no network.
 *
 * Deliberately has **no `globalSetup`**. That is the whole point of this file
 * -- these tests must be runnable on a machine with no PostgreSQL at all, and
 * CI's first job proves it by running them in a container that has none.
 *
 * If a test under `packages/` starts needing a database, the right answer is
 * to move it to `services/`, not to add setup here.
 */
export default defineConfig({
  resolve,
  test: {
    ...common,
    include: ['packages/**/*.test.ts'],
  },
});
