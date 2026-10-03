import { defineEventHandler } from 'h3'
import { authenticationError, clientInfo, engineErrorCode, forwardCookies, requestHeaders, translateEngineError } from '../../../internal/http'
import { changePasswordBody, readBodyAs } from '../../../internal/input'
import { forgetPrincipal, trustProxy, useAuthenticationRuntime } from '../../../internal/nitro'
import { assertAcceptablePassword } from '../../../internal/passwords'
import { systemEvent } from '../../../internal/runtime'
import { accountKey } from '../../../internal/throttle'
import { requireAuthenticatedPrincipal } from '../../../utils/authentication-principal'

/**
 * Changes the password. The current password re-authenticates the request.
 * Every other session is revoked and the current one is rotated.
 */
export default defineEventHandler(async (event) => {
  const principal = await requireAuthenticatedPrincipal(event)
  const { currentPassword, newPassword } = await readBodyAs(event, changePasswordBody)
  const runtime = await useAuthenticationRuntime()
  const context = await runtime.engine.$context
  const owner = await context.internalAdapter.findUserById(principal.principalId)
  if (!owner) throw authenticationError('unauthenticated')

  const key = accountKey(owner.email)
  if (await runtime.throttle.isBlocked(key, runtime.policy.signInThrottle.maxFailedAttempts)) {
    throw authenticationError('invalid-credentials')
  }
  await assertAcceptablePassword(runtime, newPassword)

  try {
    const result = await runtime.engine.api.changePassword({
      body: { currentPassword, newPassword, revokeOtherSessions: true },
      headers: requestHeaders(event),
      returnHeaders: true,
    })
    forwardCookies(event, result.headers)
    forgetPrincipal(event)
  }
  catch (error) {
    if (engineErrorCode(error) === 'invalid-credentials') {
      await runtime.throttle.recordFailure(key, runtime.policy.signInThrottle.maxFailedAttempts)
    }
    throw translateEngineError(error)
  }

  await runtime.throttle.clear(key)
  await runtime.emit(systemEvent('authentication.password-changed', principal.principalId, {
    sessionId: principal.sessionId,
    client: clientInfo(event, trustProxy()),
  }))
  await runtime.notify(owner.email, 'authentication.password-changed')
  return { status: 'password-changed' as const }
})
