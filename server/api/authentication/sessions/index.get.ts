import { defineEventHandler, setResponseHeader } from 'h3'
import { requestHeaders } from '../../../internal/http'
import { useAuthenticationRuntime } from '../../../internal/nitro'
import { absoluteExpiry } from '../../../internal/principal'
import { toSessionSummary } from '../../../internal/sessions'
import { requireAuthenticatedPrincipal } from '../../../utils/authentication-principal'

/** The signed-in principal's active sessions, newest first. */
export default defineEventHandler(async (event) => {
  const principal = await requireAuthenticatedPrincipal(event)
  const runtime = await useAuthenticationRuntime()
  const lifetime = runtime.policy.session.absoluteLifetimeSeconds
  const sessions = await runtime.engine.api.listSessions({ headers: requestHeaders(event) })
  setResponseHeader(event, 'cache-control', 'no-store')
  return {
    sessions: sessions
      .filter(session => absoluteExpiry(session, lifetime) > new Date())
      .map(session => toSessionSummary(session, principal.sessionId, lifetime))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
  }
})
