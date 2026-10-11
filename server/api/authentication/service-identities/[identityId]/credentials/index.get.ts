import { defineEventHandler } from 'h3'
import { currentTime } from '../../../../../internal/clock'
import { requireServiceCredentialAccess } from '../../../../../internal/service-endpoints'

/**
 * A service identity's active credentials, for a person who may manage it
 * (the host's service-governance port). Never a secret; only a key's
 * thumbprint.
 */
export default defineEventHandler(async (event) => {
  const { identityId, runtime } = await requireServiceCredentialAccess(event, false)
  return { credentials: await runtime.serviceCredentials.list(identityId, currentTime()) }
})
