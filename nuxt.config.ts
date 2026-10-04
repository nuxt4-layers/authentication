/**
 * Nuxt layer entry point for `@nuxt4-layers/authentication`.
 *
 * Hosts compose this layer by package name from `extends` and supply the
 * required ports from a Nitro plugin. See docs/composition-contract.md.
 */
import { fileURLToPath } from 'node:url'

export default defineNuxtConfig({
  compatibilityDate: '2026-06-30',

  // Presentation (default pages and form components), registered only when
  // `authentication.presentation` is true. The core below never depends on it.
  modules: [fileURLToPath(new URL('./modules/presentation', import.meta.url))],

  runtimeConfig: {
    // Server-only. Supplied through deployment secret management, never committed.
    authentication: {
      // NUXT_AUTHENTICATION_SECRET: signing/encryption secret, at least 32 random bytes.
      secret: '',
      // NUXT_AUTHENTICATION_BASE_URL: canonical external origin, e.g. https://example.com
      baseUrl: '',
      // NUXT_AUTHENTICATION_TRUST_PROXY: read the client IP from X-Forwarded-For.
      // Enable only behind a proxy that overwrites that header.
      trustProxy: false,
      // Identity providers. Each is enabled only when its client ID and secret are set,
      // e.g. NUXT_AUTHENTICATION_PROVIDERS_GOOGLE_CLIENT_ID / _CLIENT_SECRET.
      // Register <base URL>/api/authentication/federation/callback/<id> with the provider.
      providers: {
        google: { clientId: '', clientSecret: '' },
        microsoft: { clientId: '', clientSecret: '', tenantId: 'common' },
        github: { clientId: '', clientSecret: '' },
        facebook: { clientId: '', clientSecret: '' },
        oidc: { name: '', discoveryUrl: '', clientId: '', clientSecret: '' },
      },
    },
    public: {
      authentication: {
        // BCP 47 locale passed to the mailer for rendering.
        locale: 'en-GB',
        // Name shown in authenticator apps and passkey prompts; defaults to the base URL's host.
        appName: '',
        // Application routes the layer links or redirects to. Hosts override these.
        routes: {
          signIn: '/sign-in',
          afterSignIn: '/',
          afterSignOut: '/',
          resetPassword: '/reset-password',
          signUp: '/sign-up',
          forgotPassword: '/forgot-password',
          security: '/account/security',
          // Where the `authenticated` middleware sends sessions that must enrol
          // a second factor or step up to aal2.
          mfa: '/mfa',
        },
      },
    },
  },
})
