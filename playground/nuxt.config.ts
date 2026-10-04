export default defineNuxtConfig({
  // Composed as a host would: the authentication layer and Theme Manager as peers.
  extends: ['..', '@nuxt4-layers/theme-manager'],
  compatibilityDate: '2026-06-30',
})
