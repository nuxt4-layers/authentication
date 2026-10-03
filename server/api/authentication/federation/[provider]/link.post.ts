import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { requireAccess } from '../../../../internal/guards'
import { forwardCookies, requestHeaders, safeRedirectPath, translateEngineError } from '../../../../internal/http'
import { readBodyAs } from '../../../../internal/input'
import { routeProvider } from '../../../../internal/federation'
import { useAuthenticationRuntime } from '../../../../internal/nitro'

const linkBody = z.object({ redirect: z.string().max(2048).optional() }).strict()

/**
 * Starts linking an identity provider to the signed-in account. Requires a
 * recent authentication. Returns the provider URL for the browser to visit.
 */
export default defineEventHandler(async (event) => {
  await requireAccess(event, 'sensitive')
  const runtime = await useAuthenticationRuntime()
  const provider = routeProvider(event, runtime)
  const { redirect } = await readBodyAs(event, linkBody)
  const target = safeRedirectPath(redirect, runtime.routes.afterSignIn)
  try {
    const result = await runtime.engine.api.linkSocialAccount({
      body: {
        provider: provider.id,
        callbackURL: `${runtime.baseUrl}${target}`,
        errorCallbackURL: `${runtime.baseUrl}${target}`,
        disableRedirect: true,
      },
      headers: requestHeaders(event),
      returnHeaders: true,
    })
    forwardCookies(event, result.headers)
    return { url: (result.response as { url: string }).url }
  }
  catch (error) {
    throw translateEngineError(error)
  }
})
