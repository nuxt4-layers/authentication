/**
 * Nuxt layer entry point for `@nuxt4-layers/authentication`.
 *
 * Hosts compose this layer by package name from `extends` and supply the
 * required ports from a Nitro plugin. See docs/composition-contract.md.
 */
export default defineNuxtConfig({
  compatibilityDate: '2026-06-30',

  runtimeConfig: {
    // Server-only. Supplied through deployment secret management, never committed.
    authentication: {
      // NUXT_AUTHENTICATION_SECRET: signing/encryption secret, at least 32 random bytes.
      secret: '',
      // NUXT_AUTHENTICATION_BASE_URL: canonical external origin, e.g. https://example.com
      baseUrl: '',
    },
  },
})
