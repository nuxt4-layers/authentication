import { defineEventHandler } from 'h3'
import { authenticationError, clientInfo, engineErrorCode, requestHeaders, translateEngineError } from '../../../internal/http'
import { readBodyAs, secondFactorBody } from '../../../internal/input'
import { acceptTotpOnce } from '../../../internal/mfa'
import { trustProxy, useAuthenticationRuntime } from '../../../internal/nitro'
import { systemEvent } from '../../../internal/runtime'
import { completeSignIn, previousSessionToken } from '../../../internal/sign-in'
import { clientKey } from '../../../internal/throttle'
import { hashBackupCode } from '../../../internal/engine-options'

/**
 * Completes a sign-in that answered `second-factor-required`, with a TOTP code
 * or a single-use backup code. Repeated failures lock the second factor.
 */
export default defineEventHandler(async (event) => {
  const { method, code, rememberDevice } = await readBodyAs(event, secondFactorBody)
  const runtime = await useAuthenticationRuntime()
  const { throttle, policy } = runtime
  const client = clientInfo(event, trustProxy())
  const clientThrottle = client.ipAddress ? clientKey(client.ipAddress) : null
  const failed = (reason: string, principalId: string | null = null) =>
    runtime.emit(systemEvent('authentication.sign-in-failed', principalId, { method, reason, client }))

  if (clientThrottle && await throttle.isBlocked(clientThrottle, policy.signInThrottle.maxFailedAttemptsPerClient)) {
    await failed('rate-limited')
    throw authenticationError('rate-limited')
  }

  const headers = requestHeaders(event)
  const previousToken = await previousSessionToken(runtime, headers)
  const trustDevice = rememberDevice === true && policy.rememberedDevice.days > 0

  let result: { headers: Headers, response: { token: string, user: { id: string } } }
  try {
    result = method === 'totp'
      ? await runtime.engine.api.verifyTOTP({ body: { code, trustDevice }, headers, returnHeaders: true }) as typeof result
      : await runtime.engine.api.verifyBackupCode({ body: { code: hashBackupCode(runtime.secret, code), trustDevice }, headers, returnHeaders: true }) as typeof result
  }
  catch (error) {
    const contractCode = engineErrorCode(error)
    if (contractCode === 'invalid-mfa-code' && clientThrottle) {
      await throttle.recordFailure(clientThrottle, policy.signInThrottle.maxFailedAttemptsPerClient)
    }
    await failed(contractCode)
    throw translateEngineError(error)
  }

  const { token, user } = result.response
  // The engine does not prevent TOTP replay; reject a code whose time step was already used.
  if (method === 'totp' && !await acceptTotpOnce(runtime, user.id, code)) {
    const context = await runtime.engine.$context
    await context.internalAdapter.deleteSession(token)
    await failed('totp-replayed', user.id)
    throw authenticationError('invalid-mfa-code')
  }

  await completeSignIn(event, runtime, {
    engineHeaders: result.headers,
    sessionToken: token,
    userId: user.id,
    methods: ['password', method],
    previousToken,
    account: null,
    client,
  })
  if (method === 'backup-code') {
    const context = await runtime.engine.$context
    const owner = await context.internalAdapter.findUserById(user.id)
    await runtime.emit(systemEvent('authentication.backup-code-used', user.id, { method, client }))
    if (owner) await runtime.notify(owner.email, 'authentication.backup-code-used')
  }
  return { status: 'signed-in' as const }
})
