import { defineEventHandler, getQuery, sendRedirect } from 'h3'
import { forwardCookies, requestHeaders, safeRedirectPath, translateEngineError } from '../../../../internal/http'
import { routeProvider } from '../../../../internal/federation'
import { useAuthenticationRuntime } from '../../../../internal/nitro'

/**
 * Starts sign-in with an identity provider: redirects the browser to it with
 * state and PKCE bound to this browser by a short-lived cookie.
 */
export default defineEventHandler(async (event) => {
  const runtime = await useAuthenticationRuntime()
  const provider = routeProvider(event, runtime)
  const target = safeRedirectPath(getQuery(event).redirect, runtime.routes.afterSignIn)
  try {
    const result = await runtime.engine.api.signInSocial({
      body: {
        provider: provider.id,
        callbackURL: `${runtime.baseUrl}${target}`,
        errorCallbackURL: `${runtime.baseUrl}${runtime.routes.signIn}`,
        disableRedirect: true,
      },
      headers: requestHeaders(event),
      returnHeaders: true,
    })
    forwardCookies(event, result.headers)
    return sendRedirect(event, (result.response as { url: string }).url, 302)
  }
  catch (error) {
    throw translateEngineError(error)
  }
})
