import { defineEventHandler, getQuery, sendRedirect } from 'h3'
import { useAuthenticationRuntime } from '../../internal/nitro'

/** Target of the verification link. Redirects to the sign-in route with the outcome. */
export default defineEventHandler(async (event) => {
  const runtime = await useAuthenticationRuntime()
  const token = getQuery(event).token
  let outcome = 'failed'
  if (typeof token === 'string' && token.length > 0 && token.length <= 4096) {
    try {
      await runtime.engine.api.verifyEmail({ query: { token } })
      outcome = 'success'
    }
    catch {
      outcome = 'failed'
    }
  }
  return sendRedirect(event, `${runtime.routes.signIn}?verification=${outcome}`, 303)
})
