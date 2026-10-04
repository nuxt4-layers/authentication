import { createResolver, defineNuxtModule, extendPages } from '@nuxt/kit'

/**
 * Registers the layer's default pages at host-chosen paths (build time) and
 * keeps the runtime route configuration in step, so links, redirects and
 * emails point at the pages that exist.
 *
 * Hosts configure it in nuxt.config.ts:
 *   authentication: { pages: { enabled: true, paths: { signIn: '/login' } } }
 * or set `enabled: false` and build their own pages from the public form components.
 */
export interface AuthenticationPagePaths {
  signIn: string
  signUp: string
  forgotPassword: string
  resetPassword: string
  mfa: string
  security: string
}

export interface AuthenticationModuleOptions {
  pages: {
    enabled: boolean
    paths: AuthenticationPagePaths
  }
}

const PAGES: { key: keyof AuthenticationPagePaths, file: string }[] = [
  { key: 'signIn', file: 'SignInPage.vue' },
  { key: 'signUp', file: 'SignUpPage.vue' },
  { key: 'forgotPassword', file: 'ForgotPasswordPage.vue' },
  { key: 'resetPassword', file: 'ResetPasswordPage.vue' },
  { key: 'mfa', file: 'MfaPage.vue' },
  { key: 'security', file: 'SecurityPage.vue' },
]

export default defineNuxtModule<AuthenticationModuleOptions>({
  meta: { name: '@nuxt4-layers/authentication/pages', configKey: 'authentication' },
  defaults: {
    pages: {
      enabled: true,
      paths: {
        signIn: '/sign-in',
        signUp: '/sign-up',
        forgotPassword: '/forgot-password',
        resetPassword: '/reset-password',
        mfa: '/mfa',
        security: '/account/security',
      },
    },
  },
  setup(options, nuxt) {
    if (!options.pages.enabled) return
    for (const [key, path] of Object.entries(options.pages.paths)) {
      if (!path.startsWith('/') || path.startsWith('//')) {
        throw new Error(`authentication.pages.paths.${key} must be an absolute path, got '${path}'.`)
      }
    }
    const runtimeRoutes = (nuxt.options.runtimeConfig.public as { authentication: { routes: Record<string, string> } }).authentication.routes
    Object.assign(runtimeRoutes, options.pages.paths)

    // The pages handle credentials and one-time tokens: never framed (clickjacking),
    // never cached, and never leaking the reset token in a Referer header. Headers
    // a host sets for the same path take precedence.
    const routeRules = (nuxt.options.routeRules ??= {}) as Record<string, { headers?: Record<string, string> }>
    for (const path of Object.values(options.pages.paths)) {
      const rule = (routeRules[path] ??= {})
      rule.headers = {
        'Content-Security-Policy': "frame-ancestors 'none'",
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-store',
        ...rule.headers,
      }
    }

    const { resolve } = createResolver(import.meta.url)
    extendPages((pages) => {
      for (const page of PAGES) {
        pages.push({
          name: `authentication-${page.key}`,
          path: options.pages.paths[page.key],
          file: resolve('../app/authentication-pages', page.file),
        })
      }
    })
  },
})
