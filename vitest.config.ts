import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    exclude: ['tests/e2e/**', 'node_modules/**'],
    // The integration suite builds and starts the playground once.
    hookTimeout: 300_000,
    // Integration suites each build the same playground; run files one at a time.
    fileParallelism: false,
    testTimeout: 30_000,
  },
})
