import { appendResponseHeader, defineEventHandler, getQuery, getRouterParam, sendRedirect } from 'h3'
import { authenticationError, clientInfo, requestHeaders, sessionTokenFromCookies } from '../../../../internal/http'
import { federationOutcome, isFederationProvider } from '../../../../internal/federation'
import { trustProxy, useAuthenticationRuntime } from '../../../../internal/nitro'
import { systemEvent } from '../../../../internal/runtime'
import { completeSignIn, previousSessionToken } from '../../../../internal/sign-in'

/**
 * Return point from an identity provider (registered with the provider as the
 * redirect URI). Completes a sign-in or a link, then redirects to the page the
 * flow started from, with `?federation=<outcome>` on failure.
 */
export default defineEventHandler(async (event) => {
  const runtime = await useAuthenticationRuntime()
  const id = getRouterParam(event, 'provider') ?? ''
  if (!isFederationProvider(id) || !runtime.providers.some(provider => provider.id === id)) {
    throw authenticationError('validation-failed')
  }
  const headers = requestHeaders(event)
  const client = clientInfo(event, trustProxy())
  const previousToken = await previousSessionToken(runtime, headers)

  const query = Object.fromEntries(Object.entries(getQuery(event)).map(([key, value]) => [key, String(value)]))
  const response = await runtime.engine.api.callbackOAuth({ params: { id }, query, headers, asResponse: true }) as Response
  const engineHeaders = new Headers()
  for (const cookie of response.headers.getSetCookie()) engineHeaders.append('set-cookie', cookie)

  const location = new URL(response.headers.get('location') ?? `${runtime.baseUrl}${runtime.routes.signIn}`, runtime.baseUrl)
  const engineError = location.searchParams.get('error')
  if (engineError) {
    for (const cookie of engineHeaders.getSetCookie()) appendResponseHeader(event, 'set-cookie', cookie)
    const outcome = federationOutcome(engineError)
    await runtime.emit(systemEvent('authentication.sign-in-failed', null, { method: 'federated', reason: `${id}:${outcome}`, client }))
    // Back to the page the flow started from; the engine's own error page and
    // any off-site location fall back to the sign-in route.
    const back = location.origin === runtime.baseUrl && !location.pathname.startsWith('/api/')
      ? location.pathname
      : runtime.routes.signIn
    const redirect = new URL(back, runtime.baseUrl)
    redirect.searchParams.set('federation', outcome)
    return sendRedirect(event, `${redirect.pathname}${redirect.search}`, 302)
  }

  // Never redirect off-site, whatever the engine returned.
  const target = location.origin === runtime.baseUrl ? `${location.pathname}${location.search}` : runtime.routes.afterSignIn
  const sessionToken = sessionTokenFromCookies(engineHeaders)
  if (sessionToken && sessionToken !== previousToken) {
    const context = await runtime.engine.$context
    const session = await context.internalAdapter.findSession(sessionToken)
    if (session) {
      await completeSignIn(event, runtime, {
        engineHeaders,
        sessionToken,
        userId: session.user.id,
        methods: ['federated'],
        previousToken,
        account: null,
        client,
      })
      return sendRedirect(event, target, 302)
    }
  }
  // A link to the signed-in account: no new session.
  for (const cookie of engineHeaders.getSetCookie()) appendResponseHeader(event, 'set-cookie', cookie)
  return sendRedirect(event, target, 302)
})
