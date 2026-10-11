import { defineEventHandler, getRequestHeader, getRequestURL } from 'h3'
import { useRuntimeConfig } from '#imports'
import { authenticationError } from '../internal/http'

/**
 * CSRF defence for the layer's state-changing endpoints: the request must carry
 * an Origin (or, failing that, Referer) matching the configured base URL.
 * Combined with SameSite=Lax cookies and JSON-only bodies.
 *
 * The service token endpoint is exempt: a service calls it from no browser,
 * with no cookie, and it reads none, so there is nothing to forge.
 */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const NO_COOKIE = new Set(['/api/authentication/service-token'])

export default defineEventHandler((event) => {
  if (!getRequestURL(event).pathname.startsWith('/api/authentication/')) return
  if (SAFE_METHODS.has(event.method)) return
  if (NO_COOKIE.has(getRequestURL(event).pathname)) return

  const expected = new URL(useRuntimeConfig().authentication.baseUrl).origin
  const origin = getRequestHeader(event, 'origin')
  const referer = getRequestHeader(event, 'referer')
  let actual: string | null = null
  try {
    actual = origin ? new URL(origin).origin : referer ? new URL(referer).origin : null
  }
  catch {
    actual = null
  }
  if (actual !== expected) throw authenticationError('origin-rejected')
})
