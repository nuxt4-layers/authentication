import { defineNuxtRouteMiddleware, navigateTo, useRuntimeConfig } from '#imports'
import { useAuthentication } from '../composables/useAuthentication'

/**
 * PUBLIC named route middleware: `definePageMeta({ middleware: 'authenticated' })`.
 * Sends anonymous visitors to sign-in and sessions below the policy's required
 * assurance to `routes.mfa`. A UX guard only; the page's server data must
 * still use requireAuthenticatedPrincipal.
 */
export default defineNuxtRouteMiddleware(async (to) => {
  const { isAuthenticated, needsSecondFactor, ready, refresh } = useAuthentication()
  if (!ready.value) await refresh()
  const { signIn, mfa } = useRuntimeConfig().public.authentication.routes
  if (!isAuthenticated.value) {
    return navigateTo({ path: signIn, query: { redirect: to.fullPath } })
  }
  // Signed in below the required assurance: enrol a second factor or step up first.
  if (needsSecondFactor.value && to.path !== mfa) {
    return navigateTo({ path: mfa, query: { redirect: to.fullPath } })
  }
})
