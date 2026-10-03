import { defineEventHandler, getRequestHeader, getRequestURL } from 'h3'
import { useRuntimeConfig } from '#imports'
import { authenticationError } from '../internal/http'

/**
 * CSRF defence for the layer's state-changing endpoints: the request must carry
 * an Origin (or, failing that, Referer) matching the configured base URL.
 * Combined with SameSite=Lax cookies and JSON-only bodies.
 */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export default defineEventHandler((event) => {
  if (!getRequestURL(event).pathname.startsWith('/api/authentication/')) return
  if (SAFE_METHODS.has(event.method)) return

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
