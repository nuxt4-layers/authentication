import { defineEventHandler, setResponseStatus } from 'h3'
import { z } from 'zod'
import { parsePublicKey } from '../../../../../internal/client-assertion'
import { currentTime } from '../../../../../internal/clock'
import { authenticationError, clientInfo } from '../../../../../internal/http'
import { readBodyAs } from '../../../../../internal/input'
import { trustProxy } from '../../../../../internal/nitro'
import { credentialEvent, requireServiceCredentialAccess } from '../../../../../internal/service-endpoints'
import { ServiceCredentialLimit } from '../../../../../internal/service-credentials'

const body = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('secret') }).strict(),
  z.object({ kind: z.literal('public-key'), publicKey: z.record(z.string(), z.unknown()) }).strict(),
])

const DAY = 86_400_000

/**
 * Issues a client secret, returned this once, or registers a public key, for
 * a service identity. Needs a person who may manage it, after a
 * phishing-resistant authentication within fifteen minutes; no second
 * approver. At most two credentials are active at once
 * (`credential-limit-reached`). Writes `authentication.service-credential-issued`
 * for the host to tell the owning group's owners.
 */
export default defineEventHandler(async (event) => {
  const { principal, identityId, runtime } = await requireServiceCredentialAccess(event, true)
  const request = await readBodyAs(event, body)
  const at = currentTime()
  const expiresAt = new Date(at.getTime() + runtime.policy.serviceCredentials.credentialDays * DAY)
  let issued
  try {
    if (request.kind === 'secret') {
      issued = await runtime.serviceCredentials.issueSecret(identityId, at, expiresAt)
    }
    else {
      const publicKey = parsePublicKey(request.publicKey)
      if (!publicKey) throw authenticationError('validation-failed')
      issued = await runtime.serviceCredentials.registerKey(identityId, publicKey, at, expiresAt)
    }
  }
  catch (error) {
    if (error instanceof ServiceCredentialLimit) throw authenticationError('credential-limit-reached')
    throw error
  }
  await runtime.emit(credentialEvent('authentication.service-credential-issued', issued.credential, {
    actorId: principal.principalId,
    sessionId: principal.sessionId,
    client: clientInfo(event, trustProxy()),
  }))
  setResponseStatus(event, 201)
  return issued
})
