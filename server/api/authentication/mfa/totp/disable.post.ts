import { defineEventHandler } from 'h3'
import { requireAccess } from '../../../../internal/guards'
import { clientInfo, forwardCookies, requestHeaders, sessionTokenFromCookies, translateEngineError } from '../../../../internal/http'
import { passwordOnlyBody, readBodyAs } from '../../../../internal/input'
import { recordSessionAuthentication } from '../../../../internal/mfa'
import { forgetPrincipal, trustProxy, useAuthenticationRuntime } from '../../../../internal/nitro'
import { systemEvent } from '../../../../internal/runtime'

/** Removes TOTP and its backup codes. Requires a recent authentication and the password. */
export default defineEventHandler(async (event) => {
  const principal = await requireAccess(event, 'sensitive')
  const { password } = await readBodyAs(event, passwordOnlyBody)
  const runtime = await useAuthenticationRuntime()
  try {
    const result = await runtime.engine.api.disableTwoFactor({ body: { password }, headers: requestHeaders(event), returnHeaders: true })
    forwardCookies(event, result.headers)
    const token = sessionTokenFromCookies(result.headers)
    // The rotated session keeps the methods it was authenticated with.
    if (token) await recordSessionAuthentication(runtime, token, principal.assurance.methods)
  }
  catch (error) {
    throw translateEngineError(error)
  }
  forgetPrincipal(event)
  const context = await runtime.engine.$context
  const owner = await context.internalAdapter.findUserById(principal.principalId)
  await runtime.emit(systemEvent('authentication.mfa-removed', principal.principalId, { method: 'totp', client: clientInfo(event, trustProxy()) }))
  if (owner) await runtime.notify(owner.email, 'authentication.mfa-removed')
  return { status: 'totp-disabled' as const }
})
