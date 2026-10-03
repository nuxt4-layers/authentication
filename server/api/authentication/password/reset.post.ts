import { defineEventHandler } from 'h3'
import { translateEngineError } from '../../../internal/http'
import { readBodyAs, resetBody } from '../../../internal/input'
import { useAuthenticationRuntime } from '../../../internal/nitro'
import { assertAcceptablePassword } from '../../../internal/passwords'

/** Completes a reset with the single-use token. Revokes every existing session. */
export default defineEventHandler(async (event) => {
  const { token, password } = await readBodyAs(event, resetBody)
  const runtime = await useAuthenticationRuntime()
  await assertAcceptablePassword(runtime, password)
  try {
    await runtime.engine.api.resetPassword({ body: { token, newPassword: password } })
  }
  catch (error) {
    throw translateEngineError(error)
  }
  return { status: 'password-reset' as const }
})
