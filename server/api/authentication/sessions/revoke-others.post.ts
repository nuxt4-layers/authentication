import { defineEventHandler } from 'h3'
import { clientInfo, requestHeaders } from '../../../internal/http'
import { trustProxy, useAuthenticationRuntime } from '../../../internal/nitro'
import { systemEvent } from '../../../internal/runtime'
import { requireAuthenticatedPrincipal } from '../../../utils/authentication-principal'

/** Revokes every session except the current one. */
export default defineEventHandler(async (event) => {
  const principal = await requireAuthenticatedPrincipal(event)
  const runtime = await useAuthenticationRuntime()
  await runtime.engine.api.revokeOtherSessions({ headers: requestHeaders(event) })
  await runtime.emit(systemEvent('authentication.session-revoked', principal.principalId, {
    sessionId: null,
    reason: 'owner-revoked-others',
    client: clientInfo(event, trustProxy()),
  }))
  return { status: 'revoked' as const }
})
