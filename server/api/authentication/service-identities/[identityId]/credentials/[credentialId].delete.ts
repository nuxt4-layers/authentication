import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { currentTime } from '../../../../../internal/clock'
import { authenticationError, clientInfo } from '../../../../../internal/http'
import { trustProxy } from '../../../../../internal/nitro'
import { credentialEvent, requireServiceCredentialAccess } from '../../../../../internal/service-endpoints'

/**
 * Revokes one of a service identity's active credentials, ending every token
 * issued with it at once. Needs the same as issuing. Writes
 * `authentication.service-credential-revoked`.
 */
export default defineEventHandler(async (event) => {
  const { principal, identityId, runtime } = await requireServiceCredentialAccess(event, true)
  const revoked = await runtime.serviceCredentials.revoke(identityId, getRouterParam(event, 'credentialId') ?? '', currentTime())
  if (!revoked) throw authenticationError('validation-failed')
  await runtime.emit(credentialEvent('authentication.service-credential-revoked', revoked, {
    endedHow: 'revoked',
    actorId: principal.principalId,
    sessionId: principal.sessionId,
    client: clientInfo(event, trustProxy()),
  }))
  setResponseStatus(event, 204)
  return null
})
