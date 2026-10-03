import { defineEventHandler } from 'h3'
import { requireAccess } from '../../internal/guards'
import { authenticationError, clientInfo, engineErrorCode, requestHeaders, translateEngineError } from '../../internal/http'
import { readBodyAs, reauthenticateBody } from '../../internal/input'
import { acceptTotpOnce, mergeMethods, recordSessionAuthentication } from '../../internal/mfa'
import { currentSessionToken, forgetPrincipal, trustProxy, useAuthenticationRuntime } from '../../internal/nitro'
import { systemEvent } from '../../internal/runtime'
import { accountKey } from '../../internal/throttle'

/**
 * Step-up: proves presence again with the password or a TOTP code, refreshing
 * `authenticatedAt`. A TOTP code also adds the factor, raising a password
 * session to aal2. (Passkeys re-authenticate through `POST /passkeys/authentication`.)
 */
export default defineEventHandler(async (event) => {
  const principal = await requireAccess(event, 'step-up')
  const body = await readBodyAs(event, reauthenticateBody)
  const runtime = await useAuthenticationRuntime()
  const token = currentSessionToken(event)!
  const context = await runtime.engine.$context
  const owner = await context.internalAdapter.findUserById(principal.principalId)
  if (!owner) throw authenticationError('unauthenticated')
  const key = accountKey(owner.email)
  const { maxFailedAttempts } = runtime.policy.signInThrottle

  if (await runtime.throttle.isBlocked(key, maxFailedAttempts)) throw authenticationError('invalid-credentials')

  if (body.method === 'password') {
    try {
      await runtime.engine.api.verifyPassword({ body: { password: body.password }, headers: requestHeaders(event) })
    }
    catch (error) {
      if (engineErrorCode(error) === 'invalid-credentials') await runtime.throttle.recordFailure(key, maxFailedAttempts)
      throw translateEngineError(error)
    }
  }
  else if (!await acceptTotpOnce(runtime, principal.principalId, body.code)) {
    await runtime.throttle.recordFailure(key, maxFailedAttempts)
    throw authenticationError('invalid-mfa-code')
  }

  await recordSessionAuthentication(runtime, token, mergeMethods(principal.assurance.methods, [body.method]))
  forgetPrincipal(event)
  await runtime.emit(systemEvent('authentication.reauthenticated', principal.principalId, {
    sessionId: principal.sessionId,
    method: body.method,
    client: clientInfo(event, trustProxy()),
  }))
  return { status: 'reauthenticated' as const }
})
