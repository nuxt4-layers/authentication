import { defineEventHandler, setResponseStatus } from 'h3'
import { requestHeaders, translateEngineError } from '../../internal/http'
import { readBodyAs, signUpBody } from '../../internal/input'
import { useAuthenticationRuntime } from '../../internal/nitro'
import { assertAcceptablePassword } from '../../internal/passwords'
import { signUpInvitation } from '../../internal/standing'

/**
 * Registers an email and password account. The response is identical whether
 * or not the address already has an account, so it cannot be used to enumerate.
 */
export default defineEventHandler(async (event) => {
  const { email, password, invitationToken } = await readBodyAs(event, signUpBody)
  const runtime = await useAuthenticationRuntime()
  await assertAcceptablePassword(runtime, password)

  try {
    // The token reaches only the identity port's reserve, for the inviting tenant.
    await signUpInvitation.run({ invitationToken: invitationToken ?? null }, () =>
      runtime.engine.api.signUpEmail({ body: { email, password, name: '' }, headers: requestHeaders(event) }))
  }
  catch (error) {
    throw translateEngineError(error)
  }

  setResponseStatus(event, 202)
  return { status: 'accepted' as const }
})
