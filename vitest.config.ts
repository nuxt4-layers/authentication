import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    // The integration suite builds and starts the playground once.
    hookTimeout: 300_000,
    testTimeout: 30_000,
  },
})
