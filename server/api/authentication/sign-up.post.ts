import { defineEventHandler, setResponseStatus } from 'h3'
import { requestHeaders, translateEngineError } from '../../internal/http'
import { credentialsBody, readBodyAs } from '../../internal/input'
import { useAuthenticationRuntime } from '../../internal/nitro'
import { assertAcceptablePassword } from '../../internal/passwords'

/**
 * Registers an email and password account. The response is identical whether
 * or not the address already has an account, so it cannot be used to enumerate.
 */
export default defineEventHandler(async (event) => {
  const { email, password } = await readBodyAs(event, credentialsBody)
  const runtime = await useAuthenticationRuntime()
  await assertAcceptablePassword(runtime, password)

  try {
    await runtime.engine.api.signUpEmail({ body: { email, password, name: '' }, headers: requestHeaders(event) })
  }
  catch (error) {
    throw translateEngineError(error)
  }

  setResponseStatus(event, 202)
  return { status: 'accepted' as const }
})
