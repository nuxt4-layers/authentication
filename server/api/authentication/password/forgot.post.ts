import { defineEventHandler, setResponseStatus } from 'h3'
import { emailBody, readBodyAs } from '../../../internal/input'
import { useAuthenticationRuntime } from '../../../internal/nitro'
import { resetKey } from '../../../internal/throttle'

/** Maximum reset emails per address per throttle window. */
const RESET_EMAILS_PER_WINDOW = 3

/**
 * Requests a password-reset email. The response is identical whether or not the
 * address has an account, and repeated requests are silently capped.
 */
export default defineEventHandler(async (event) => {
  const { email } = await readBodyAs(event, emailBody)
  const runtime = await useAuthenticationRuntime()
  const key = resetKey(email)

  if (!await runtime.throttle.isBlocked(key, RESET_EMAILS_PER_WINDOW)) {
    await runtime.throttle.recordFailure(key, RESET_EMAILS_PER_WINDOW)
    try {
      await runtime.engine.api.requestPasswordReset({ body: { email } })
    }
    catch (error) {
      console.error('[authentication] password reset request failed:', error instanceof Error ? error.message : error)
    }
  }

  setResponseStatus(event, 202)
  return { status: 'accepted' as const }
})
