import { defineEventHandler } from 'h3'
import { requireAccess } from '../../../../internal/guards'
import { authenticationError, clientInfo, forwardCookies, requestHeaders, sessionTokenFromCookies, translateEngineError } from '../../../../internal/http'
import { readBodyAs, totpCodeBody } from '../../../../internal/input'
import { acceptTotpOnce, mergeMethods, recordSessionAuthentication } from '../../../../internal/mfa'
import { forgetPrincipal, trustProxy, useAuthenticationRuntime } from '../../../../internal/nitro'
import { systemEvent } from '../../../../internal/runtime'

/** Activates TOTP with a first code. The session is rotated and now counts the TOTP factor. */
export default defineEventHandler(async (event) => {
  const principal = await requireAccess(event, 'enrolment')
  const { code } = await readBodyAs(event, totpCodeBody)
  const runtime = await useAuthenticationRuntime()

  if (!await acceptTotpOnce(runtime, principal.principalId, code)) throw authenticationError('invalid-mfa-code')

  let rotatedToken: string | null
  try {
    const result = await runtime.engine.api.verifyTOTP({ body: { code }, headers: requestHeaders(event), returnHeaders: true })
    forwardCookies(event, result.headers)
    rotatedToken = sessionTokenFromCookies(result.headers)
  }
  catch (error) {
    throw translateEngineError(error)
  }
  // Enabling TOTP rotates the session; the new one counts the TOTP factor just proven.
  if (rotatedToken) {
    await recordSessionAuthentication(runtime, rotatedToken, mergeMethods(principal.assurance.methods, ['totp']))
  }
  forgetPrincipal(event)

  const context = await runtime.engine.$context
  const owner = await context.internalAdapter.findUserById(principal.principalId)
  await runtime.emit(systemEvent('authentication.mfa-enrolled', principal.principalId, { method: 'totp', client: clientInfo(event, trustProxy()) }))
  if (owner) await runtime.notify(owner.email, 'authentication.mfa-enrolled')
  return { status: 'totp-enabled' as const }
})
