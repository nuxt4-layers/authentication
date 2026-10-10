import { addComponentsDir, addImportsDir, createResolver, defineNuxtModule, extendPages } from '@nuxt/kit'

/**
 * Registers the layer's presentation: the default pages, the `Authentication*`
 * form components and the presentation auto-imports (`useAuthenticationText`,
 * `useAuthenticationForm`, `authenticationClasses`). The core (server, client
 * API and route middleware) never depends on any of it.
 *
 * Hosts configure it in nuxt.config.ts:
 *   authentication: { pages: { paths: { signIn: '/login' } } }  // move the pages
 *   authentication: { pages: { enabled: false } }               // own pages, keep the components
 *   authentication: { presentation: false }                     // core only: register nothing here
 */
export interface AuthenticationPagePaths {
  signIn: string
  signUp: string
  forgotPassword: string
  resetPassword: string
  mfa: string
  security: string
  breakGlassEnrol: string
}

export interface AuthenticationModuleOptions {
  /** `false` registers no pages, components or presentation auto-imports. */
  presentation: boolean
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
  { key: 'breakGlassEnrol', file: 'BreakGlassEnrolPage.vue' },
]

export default defineNuxtModule<AuthenticationModuleOptions>({
  meta: { name: '@nuxt4-layers/authentication/presentation', configKey: 'authentication' },
  defaults: {
    presentation: true,
    pages: {
      enabled: true,
      paths: {
        signIn: '/sign-in',
        signUp: '/sign-up',
        forgotPassword: '/forgot-password',
        resetPassword: '/reset-password',
        mfa: '/mfa',
        security: '/account/security',
        breakGlassEnrol: '/break-glass/enrol',
      },
    },
  },
  setup(options, nuxt) {
    if (!options.presentation) return

    const { resolve } = createResolver(import.meta.url)
    addComponentsDir({ path: resolve('../presentation/components'), prefix: 'Authentication', pathPrefix: false })
    addImportsDir([resolve('../presentation/composables'), resolve('../presentation/utils')])
    // Type-check the presentation sources with the host's app code.
    nuxt.hook('prepare:types', ({ tsConfig }) => {
      const include = (tsConfig.include ??= [])
      include.push(resolve('../presentation/**/*'))
    })

    if (!options.pages.enabled) return
    for (const [key, path] of Object.entries(options.pages.paths)) {
      if (!path.startsWith('/') || path.startsWith('//')) {
        throw new Error(`authentication.pages.paths.${key} must be an absolute path, got '${path}'.`)
      }
    }
    // Route configuration belongs to the core; the pages tell it where they are,
    // so the core's links, redirects and emails point at pages that exist.
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

    extendPages((pages) => {
      for (const page of PAGES) {
        pages.push({
          name: `authentication-${page.key}`,
          path: options.pages.paths[page.key],
          file: resolve('../presentation/pages', page.file),
        })
      }
    })
  },
})
