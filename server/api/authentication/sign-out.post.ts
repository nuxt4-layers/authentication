import { defineEventHandler } from 'h3'
import { clientInfo, forwardCookies, requestHeaders } from '../../internal/http'
import { forgetPrincipal, resolvePrincipal, trustProxy, useAuthenticationRuntime } from '../../internal/nitro'
import { systemEvent } from '../../internal/runtime'

/** Ends the current session server-side and clears the cookie. Always succeeds. */
export default defineEventHandler(async (event) => {
  const runtime = await useAuthenticationRuntime()
  const principal = await resolvePrincipal(event)
  if (principal) {
    const result = await runtime.engine.api.signOut({ headers: requestHeaders(event), returnHeaders: true })
    forwardCookies(event, result.headers)
    forgetPrincipal(event)
    await runtime.emit(systemEvent('authentication.signed-out', principal.principalId, {
      sessionId: principal.sessionId,
      client: clientInfo(event, trustProxy()),
    }))
  }
  return { status: 'signed-out' as const }
})
