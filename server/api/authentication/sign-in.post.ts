import { defineEventHandler } from 'h3'
import { authenticationError, clientInfo, engineErrorCode, forwardCookies, requestHeaders, translateEngineError } from '../../internal/http'
import { credentialsBody, readBodyAs } from '../../internal/input'
import { forgetPrincipal, trustProxy, useAuthenticationRuntime } from '../../internal/nitro'
import { systemEvent } from '../../internal/runtime'
import { accountKey, clientKey } from '../../internal/throttle'

/**
 * Email and password sign-in with per-account lockout and per-client throttling.
 * Locked, unknown and wrong-password attempts all answer `invalid-credentials`.
 */
export default defineEventHandler(async (event) => {
  const { email, password } = await readBodyAs(event, credentialsBody)
  const runtime = await useAuthenticationRuntime()
  const { throttle, policy } = runtime
  const client = clientInfo(event, trustProxy())
  const account = accountKey(email)
  const clientThrottle = client.ipAddress ? clientKey(client.ipAddress) : null
  const failed = (reason: string, principalId: string | null = null) =>
    runtime.emit(systemEvent('authentication.sign-in-failed', principalId, { method: 'password', reason, client }))

  if (clientThrottle && await throttle.isBlocked(clientThrottle, policy.signInThrottle.maxFailedAttemptsPerClient)) {
    await failed('rate-limited')
    throw authenticationError('rate-limited')
  }
  if (await throttle.isBlocked(account, policy.signInThrottle.maxFailedAttempts)) {
    await failed('account-locked')
    throw authenticationError('invalid-credentials')
  }

  const headers = requestHeaders(event)
  const previous = await runtime.engine.api.getSession({ headers }).catch(() => null)

  try {
    const result = await runtime.engine.api.signInEmail({ body: { email, password }, headers, returnHeaders: true })
    forwardCookies(event, result.headers)
    await throttle.clear(account)
    // Session fixation: the request's previous session does not survive a new sign-in.
    if (previous?.session.token) {
      const context = await runtime.engine.$context
      await context.internalAdapter.deleteSession(previous.session.token)
    }
    forgetPrincipal(event)
    await runtime.emit(systemEvent('authentication.signed-in', result.response.user.id, { method: 'password', client }))
    return { status: 'signed-in' as const }
  }
  catch (error) {
    const code = engineErrorCode(error)
    if (code === 'invalid-credentials') {
      const locked = await throttle.recordFailure(account, policy.signInThrottle.maxFailedAttempts)
      if (clientThrottle) await throttle.recordFailure(clientThrottle, policy.signInThrottle.maxFailedAttemptsPerClient)
      await failed('invalid-credentials')
      if (locked) {
        const context = await runtime.engine.$context
        const owner = await context.internalAdapter.findUserByEmail(email.toLowerCase())
        await runtime.emit(systemEvent('authentication.account-locked', owner?.user.id ?? null, { client }))
        if (owner) await runtime.notify(owner.user.email, 'authentication.account-locked')
      }
    }
    if (code === 'email-not-verified') {
      // The password was correct; the engine has re-sent the verification email.
      await throttle.clear(account)
    }
    throw translateEngineError(error)
  }
})
