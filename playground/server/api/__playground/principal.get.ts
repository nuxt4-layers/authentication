import type { PlaygroundRecorder } from '../../plugins/composition'

/**
 * Test-only: the principal a host route sees, as the host's own API would
 * resolve it, a service's bearer token included. Absent (404) outside test
 * mode.
 */
export default defineEventHandler(async (event) => {
  const recorder = (globalThis as { __authenticationPlayground?: PlaygroundRecorder }).__authenticationPlayground
  if (!recorder) throw createError({ statusCode: 404 })
  return { principal: await getAuthenticatedPrincipal(event) }
})
