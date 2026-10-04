import { defineNuxtRouteMiddleware, navigateTo, useRuntimeConfig } from '#imports'
import { useAuthentication } from '../composables/useAuthentication'

/**
 * PUBLIC named middleware: any signed-in session, including one below the
 * required assurance (used by the MFA page, where such sessions step up).
 */
export default defineNuxtRouteMiddleware(async (to) => {
  const { isAuthenticated, ready, refresh } = useAuthentication()
  if (!ready.value) await refresh()
  if (!isAuthenticated.value) {
    return navigateTo({ path: useRuntimeConfig().public.authentication.routes.signIn, query: { redirect: to.fullPath } })
  }
})
