import { defineNuxtRouteMiddleware, navigateTo, useRuntimeConfig } from '#imports'
import { safeRedirectPath } from '../../contracts'
import { useAuthentication } from '../composables/useAuthentication'

/** PUBLIC named route middleware for sign-in and sign-up pages: signed-in users are sent on. */
export default defineNuxtRouteMiddleware(async (to) => {
  const { isAuthenticated, ready, refresh } = useAuthentication()
  if (!ready.value) await refresh()
  if (isAuthenticated.value) {
    const { afterSignIn } = useRuntimeConfig().public.authentication.routes
    return navigateTo(safeRedirectPath(to.query.redirect, afterSignIn))
  }
})
