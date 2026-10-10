import { defineEventHandler } from 'h3'
import { verifyRegistrationResponse } from '@simplewebauthn/server'
import { enrolmentBody, enrolmentGuard, engineRelyingParty, readEnrolmentBody } from '../../../internal/break-glass-enrolment'
import { currentTime } from '../../../internal/clock'
import { registrationUserVerified } from '../../../internal/mfa'
import { useAuthenticationRuntime } from '../../../internal/nitro'
import { systemEvent } from '../../../internal/runtime'

/**
 * Registers a break-glass account's passkey with its one-time enrolment token
 * and consumes the token. The challenge is used once, whatever the outcome.
 * Authenticators that did not verify the user are refused. It signs nobody in
 * and ends nothing else. Every refusal answers `invalid-or-expired-token`.
 */
/** The authenticator's transports as the engine stores them: comma-separated. */
function transportsOf(response: Record<string, unknown>): string {
  const transports = response.transports
  return Array.isArray(transports) ? transports.filter(transport => typeof transport === 'string').join(',') : ''
}

export default defineEventHandler(async (event) => {
  const runtime = await useAuthenticationRuntime()
  const guard = await enrolmentGuard(event, runtime)
  const body = await readEnrolmentBody(event, enrolmentBody)
  if (!body) return guard.refuse()

  const now = currentTime()
  const ceremony = await runtime.breakGlass.takeChallenge(body.token, now)
  if (!ceremony) return guard.refuse()
  // The engine verifies no user verification itself; every passkey here must.
  if (!registrationUserVerified(body.response)) return guard.refuse()

  const { rpID, origin } = engineRelyingParty(runtime)
  let verification
  try {
    verification = await verifyRegistrationResponse({
      response: body.response as never,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    })
  }
  catch {
    return guard.refuse()
  }
  if (!verification.verified || !verification.registrationInfo) return guard.refuse()

  const { credential, credentialDeviceType, credentialBackedUp, aaguid } = verification.registrationInfo
  const context = await runtime.engine.$context
  // Stored as the engine stores passkeys, so its passkey sign-in finds it.
  const passkey = await context.adapter.create<Record<string, unknown>, { id: string }>({
    model: 'passkey',
    data: {
      name: body.name ?? null,
      userId: ceremony.principalId,
      credentialID: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64'),
      counter: credential.counter,
      deviceType: credentialDeviceType,
      transports: transportsOf(body.response.response),
      backedUp: credentialBackedUp,
      createdAt: now,
      aaguid,
    },
  })
  // The token is consumed after the passkey exists: if it was replaced (a
  // rotation) or used meanwhile, the passkey is withdrawn and nothing counts.
  if (!await runtime.breakGlass.consume(body.token, ceremony.principalId, now)) {
    await context.adapter.delete({ model: 'passkey', where: [{ field: 'id', value: passkey.id }] })
    return guard.refuse()
  }

  await runtime.emit(systemEvent('authentication.break-glass-enrolled', ceremony.principalId, { method: 'passkey', client: guard.client }))
  const owner = await context.internalAdapter.findUserById(ceremony.principalId)
  if (owner) await runtime.notify(owner.email, 'authentication.break-glass-enrolled')
  return { status: 'passkey-registered' as const }
})
