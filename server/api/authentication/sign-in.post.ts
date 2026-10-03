import { defineEventHandler } from 'h3'
import { authenticationError, clientInfo, engineErrorCode, forwardCookies, requestHeaders, translateEngineError } from '../../internal/http'
import { credentialsBody, readBodyAs } from '../../internal/input'
import { trustProxy, useAuthenticationRuntime } from '../../internal/nitro'
import { systemEvent } from '../../internal/runtime'
import { completeSignIn, previousSessionToken } from '../../internal/sign-in'
import { accountKey, clientKey } from '../../internal/throttle'

/**
 * Email and password sign-in with per-account lockout and per-client throttling.
 * Locked, unknown and wrong-password attempts all answer `invalid-credentials`.
 * Accounts with TOTP answer `second-factor-required`; no session exists until
 * `POST /mfa/verify` succeeds.
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
  const previousToken = await previousSessionToken(runtime, headers)

  try {
    const result = await runtime.engine.api.signInEmail({ body: { email, password }, headers, returnHeaders: true })
    const response = result.response as { token?: string | null, twoFactorRedirect?: boolean, user?: { id: string, twoFactorEnabled?: boolean } }

    if (response.twoFactorRedirect) {
      // Password correct; the engine has set a short-lived interim cookie only.
      forwardCookies(event, result.headers)
      await throttle.clear(account)
      return { status: 'second-factor-required' as const, methods: ['totp', 'backup-code'] as const }
    }

    const user = response.user!
    // A user with TOTP who skipped the second factor did so on a remembered device.
    const methods = user.twoFactorEnabled ? ['password', 'remembered-device'] as const : ['password'] as const
    await completeSignIn(event, runtime, {
      engineHeaders: result.headers,
      sessionToken: response.token!,
      userId: user.id,
      methods,
      previousToken,
      account,
      client,
    })
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
