import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const src = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  resolve: {
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
  },
  test: {
    include: ['packages/**/*.test.ts', 'services/**/*.test.ts', 'spec/**/*.test.ts'],
    environment: 'node',
    // Integration tests share one Postgres database; running files in parallel
    // would interleave tenant fixtures. Correctness beats a faster suite.
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
