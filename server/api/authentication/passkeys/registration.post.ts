import { defineEventHandler } from 'h3'
import { requireAccess } from '../../../internal/guards'
import { authenticationError, clientInfo, requestHeaders, translateEngineError } from '../../../internal/http'
import { passkeyRegistrationBody, readBodyAs } from '../../../internal/input'
import { registrationUserVerified } from '../../../internal/mfa'
import { trustProxy, useAuthenticationRuntime } from '../../../internal/nitro'
import { systemEvent } from '../../../internal/runtime'

/**
 * Verifies and stores a new passkey. Authenticators that did not verify the
 * user (PIN or biometric) are refused, so every passkey counts as two factors.
 */
export default defineEventHandler(async (event) => {
  const principal = await requireAccess(event, 'enrolment')
  const { response, name } = await readBodyAs(event, passkeyRegistrationBody)
  if (!registrationUserVerified(response)) throw authenticationError('insufficient-assurance')
  const runtime = await useAuthenticationRuntime()
  try {
    await runtime.engine.api.verifyPasskeyRegistration({ body: { response: response as never, name }, headers: requestHeaders(event) })
  }
  catch (error) {
    throw translateEngineError(error)
  }
  const context = await runtime.engine.$context
  const owner = await context.internalAdapter.findUserById(principal.principalId)
  await runtime.emit(systemEvent('authentication.mfa-enrolled', principal.principalId, { method: 'passkey', client: clientInfo(event, trustProxy()) }))
  if (owner) await runtime.notify(owner.email, 'authentication.mfa-enrolled')
  return { status: 'passkey-registered' as const }
})
