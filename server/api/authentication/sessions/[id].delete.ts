import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { authenticationError, clientInfo, forwardCookies, requestHeaders } from '../../../internal/http'
import { forgetPrincipal, trustProxy, useAuthenticationRuntime } from '../../../internal/nitro'
import { systemEvent } from '../../../internal/runtime'
import { requireAuthenticatedPrincipal } from '../../../utils/authentication-principal'

/** Revokes one of the principal's own sessions. Revoking the current one signs out. */
export default defineEventHandler(async (event) => {
  const principal = await requireAuthenticatedPrincipal(event)
  const id = getRouterParam(event, 'id')
  const runtime = await useAuthenticationRuntime()
  const headers = requestHeaders(event)
  const sessions = await runtime.engine.api.listSessions({ headers })
  // Only the principal's own sessions are listed, so another principal's id is simply not found.
  const target = sessions.find(session => session.id === id)
  if (!target) throw authenticationError('validation-failed')

  if (target.id === principal.sessionId) {
    const result = await runtime.engine.api.signOut({ headers, returnHeaders: true })
    forwardCookies(event, result.headers)
    forgetPrincipal(event)
  }
  else {
    await runtime.engine.api.revokeSession({ body: { token: target.token }, headers })
  }

  await runtime.emit(systemEvent('authentication.session-revoked', principal.principalId, {
    sessionId: target.id,
    reason: 'owner-revoked',
    client: clientInfo(event, trustProxy()),
  }))
  setResponseStatus(event, 204)
  return null
})
