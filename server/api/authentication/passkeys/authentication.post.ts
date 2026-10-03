import { defineEventHandler } from 'h3'
import { authenticationError, clientInfo, engineErrorCode, requestHeaders, translateEngineError } from '../../../internal/http'
import { passkeyAuthenticationBody, readBodyAs } from '../../../internal/input'
import { assertionUserVerified } from '../../../internal/mfa'
import { trustProxy, useAuthenticationRuntime } from '../../../internal/nitro'
import { systemEvent } from '../../../internal/runtime'
import { completeSignIn, previousSessionToken } from '../../../internal/sign-in'
import { clientKey } from '../../../internal/throttle'

/**
 * Signs in with a passkey: phishing resistant and aal2 on its own. Also serves
 * as step-up re-authentication, since it replaces the current session.
 */
export default defineEventHandler(async (event) => {
  const { response } = await readBodyAs(event, passkeyAuthenticationBody)
  const runtime = await useAuthenticationRuntime()
  const { throttle, policy } = runtime
  const client = clientInfo(event, trustProxy())
  const clientThrottle = client.ipAddress ? clientKey(client.ipAddress) : null
  const failed = (reason: string) =>
    runtime.emit(systemEvent('authentication.sign-in-failed', null, { method: 'passkey', reason, client }))

  if (clientThrottle && await throttle.isBlocked(clientThrottle, policy.signInThrottle.maxFailedAttemptsPerClient)) {
    await failed('rate-limited')
    throw authenticationError('rate-limited')
  }
  // The engine verifies the signature but does not require user verification.
  if (!assertionUserVerified(response)) {
    await failed('user-not-verified')
    throw authenticationError('insufficient-assurance')
  }

  const headers = requestHeaders(event)
  const previousToken = await previousSessionToken(runtime, headers)
  let result: { headers: Headers, response: { session: { token: string }, user: { id: string } } }
  try {
    result = await runtime.engine.api.verifyPasskeyAuthentication({ body: { response: response as never }, headers, returnHeaders: true }) as typeof result
  }
  catch (error) {
    const code = engineErrorCode(error)
    if (clientThrottle) await throttle.recordFailure(clientThrottle, policy.signInThrottle.maxFailedAttemptsPerClient)
    await failed(code)
    throw translateEngineError(error)
  }

  await completeSignIn(event, runtime, {
    engineHeaders: result.headers,
    sessionToken: result.response.session.token,
    userId: result.response.user.id,
    methods: ['passkey'],
    previousToken,
    account: null,
    client,
  })
  return { status: 'signed-in' as const }
})
