import { defineEventHandler } from 'h3'
import { forwardCookies, requestHeaders, translateEngineError } from '../../../internal/http'
import { useAuthenticationRuntime } from '../../../internal/nitro'

/** WebAuthn request options for signing in (or re-authenticating) with a passkey. */
export default defineEventHandler(async (event) => {
  const runtime = await useAuthenticationRuntime()
  try {
    const result = await runtime.engine.api.generatePasskeyAuthenticationOptions({ headers: requestHeaders(event), returnHeaders: true })
    forwardCookies(event, result.headers)
    return result.response
  }
  catch (error) {
    throw translateEngineError(error)
  }
})
