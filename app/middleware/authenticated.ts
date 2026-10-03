import { defineNuxtRouteMiddleware, navigateTo, useRuntimeConfig } from '#imports'
import { useAuthentication } from '../composables/useAuthentication'

/**
 * PUBLIC named route middleware: `definePageMeta({ middleware: 'authenticated' })`.
 * A UX guard only; the page's server data must still use requireAuthenticatedPrincipal.
 */
export default defineNuxtRouteMiddleware(async (to) => {
  const { isAuthenticated, ready, refresh } = useAuthentication()
  if (!ready.value) await refresh()
  if (!isAuthenticated.value) {
    const { signIn } = useRuntimeConfig().public.authentication.routes
    return navigateTo({ path: signIn, query: { redirect: to.fullPath } })
  }
})
