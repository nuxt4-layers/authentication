import { defineEventHandler } from 'h3'
import { generateRegistrationOptions } from '@simplewebauthn/server'
import { enrolmentGuard, enrolmentOptionsBody, engineRelyingParty, readEnrolmentBody } from '../../../internal/break-glass-enrolment'
import { currentTime } from '../../../internal/clock'
import { useAuthenticationRuntime } from '../../../internal/nitro'

/**
 * WebAuthn creation options for a break-glass account's passkey, gated by its
 * one-time enrolment token (no session). The challenge is held server-side,
 * bound to the token, until the enrolment uses it once. Every refusal answers
 * `invalid-or-expired-token`.
 */
export default defineEventHandler(async (event) => {
  const runtime = await useAuthenticationRuntime()
  const guard = await enrolmentGuard(event, runtime)
  const body = await readEnrolmentBody(event, enrolmentOptionsBody)
  if (!body) return guard.refuse()

  const now = currentTime()
  const context = await runtime.engine.$context
  const principalId = await runtime.breakGlass.live(body.token, now)
  const user = principalId ? await context.internalAdapter.findUserById(principalId) : null
  if (!principalId || !user) return guard.refuse()

  const passkeys = await context.adapter.findMany<{ credentialID: string, transports: string | null }>({
    model: 'passkey',
    where: [{ field: 'userId', value: principalId }],
  })
  const { rpID, rpName } = engineRelyingParty(runtime)
  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: user.email,
    userDisplayName: user.email,
    attestationType: 'none',
    excludeCredentials: passkeys.map(passkey => ({
      id: passkey.credentialID,
      transports: passkey.transports ? passkey.transports.split(',') as never : undefined,
    })),
    // A discoverable credential that verifies the operator: it signs in with nothing else.
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
  })
  if (await runtime.breakGlass.challenge(body.token, options.challenge, now) !== principalId) return guard.refuse()
  return options
})
