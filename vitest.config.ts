import { defineConfig } from 'vitest/config';

export default defineConfig({
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
