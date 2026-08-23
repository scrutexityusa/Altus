import { fileURLToPath } from 'node:url';

const src = (path: string) => fileURLToPath(new URL(path, import.meta.url));

/**
 * Settings both configurations share.
 *
 * There are two because the suite has two halves with genuinely different
 * requirements, and pretending otherwise broke CI for every run the repository
 * has ever had: the `Core (no database)` job runs `vitest run packages` with no
 * PostgreSQL service, and the single configuration's `globalSetup` provisioned
 * a database unconditionally. The job failed on connect before collecting a
 * test, and because the integration job `needs: core`, it never ran at all.
 *
 * So the split is structural rather than a flag somebody has to remember. A
 * database-dependent test placed under `packages/` now fails loudly in the unit
 * configuration instead of being carried by a setup that should not be there.
 */
export const resolve = {
  /**
   * Workspace packages resolve to their TypeScript source, not to `dist`.
   *
   * Two reasons, both learned the hard way. A build artifact is stale by
   * default: a test suite that imports `dist` can pass against code that no
   * longer exists in `src`, which is precisely the failure an authorization
   * test suite must never have. And it makes the suite hermetic -- `vitest
   * run` works on a clean checkout with no build step, so CI cannot fail for
   * a reason that has nothing to do with the code under test.
   *
   * `dist` remains the right entry point for real consumers: the container
   * image runs compiled JavaScript, and package.json exports point there.
   */
  alias: {
    '@scrutexity/core': src('./packages/core/src/index.ts'),
    '@scrutexity/sdk': src('./packages/sdk/src/index.ts'),
  },
};

export const common = {
  environment: 'node' as const,
  testTimeout: 30_000,
  hookTimeout: 30_000,
};
