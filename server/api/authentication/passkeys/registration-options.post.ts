import { defineEventHandler } from 'h3'
import { refuseBreakGlass, requireAccess } from '../../../internal/guards'
import { forwardCookies, requestHeaders, translateEngineError } from '../../../internal/http'
import { useAuthenticationRuntime } from '../../../internal/nitro'

/** WebAuthn creation options for registering a passkey on the signed-in account. */
export default defineEventHandler(async (event) => {
  // A break-glass account's passkeys come only from one-time enrolment tokens.
  await refuseBreakGlass(await requireAccess(event, 'enrolment'))
  const runtime = await useAuthenticationRuntime()
  try {
    const result = await runtime.engine.api.generatePasskeyRegistrationOptions({ headers: requestHeaders(event), returnHeaders: true })
    forwardCookies(event, result.headers)
    return result.response
  }
  catch (error) {
    throw translateEngineError(error)
  }
})
