import { defineConfig, devices } from '@playwright/test'
import { IDP_PORT, ORIGIN, PORT } from './tests/e2e/constants'

/**
 * Browser tests of the default pages against the built playground (with Theme
 * Manager styles), a disposable PostgreSQL database and a mock OIDC provider.
 * Requires AUTHENTICATION_TEST_DATABASE_URL. Set PLAYWRIGHT_CHROMIUM_EXECUTABLE
 * to use a preinstalled Chromium instead of the one Playwright downloads.
 */
const database = new URL(process.env.AUTHENTICATION_TEST_DATABASE_URL ?? 'postgres://postgres@localhost:5432/postgres')
database.pathname = '/authentication_e2e'

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? 'github' : 'list',
  globalSetup: './tests/e2e/global-setup.ts',
  timeout: 60_000,
  use: {
    baseURL: ORIGIN,
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome'],
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } : {},
  },
  webServer: {
    command: 'node tests/e2e/prepare-database.mjs && node playground/.output/server/index.mjs',
    url: `${ORIGIN}/api/authentication/policy`,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      PORT: String(PORT),
      AUTHENTICATION_DATABASE_URL: database.toString(),
      AUTHENTICATION_PLAYGROUND_TEST: '1',
      AUTHENTICATION_PLAYGROUND_MFA: 'required',
      NUXT_AUTHENTICATION_SECRET: 'e2e-test-secret-that-is-long-enough-0123456789abcdef',
      NUXT_AUTHENTICATION_BASE_URL: ORIGIN,
      NUXT_AUTHENTICATION_PROVIDERS_OIDC_NAME: 'Test IdP',
      NUXT_AUTHENTICATION_PROVIDERS_OIDC_DISCOVERY_URL: `http://localhost:${IDP_PORT}/.well-known/openid-configuration`,
      NUXT_AUTHENTICATION_PROVIDERS_OIDC_CLIENT_ID: 'e2e-client',
      NUXT_AUTHENTICATION_PROVIDERS_OIDC_CLIENT_SECRET: 'e2e-client-secret',
    },
  },
})
