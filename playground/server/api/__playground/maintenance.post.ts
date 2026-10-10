import type { PlaygroundRecorder } from '../../plugins/composition'

/**
 * Test-only: runs `runAuthenticationMaintenance`, as a host's scheduler
 * would. Absent (404) outside test mode; a host never exposes maintenance
 * over HTTP.
 */
export default defineEventHandler(async () => {
  const recorder = (globalThis as { __authenticationPlayground?: PlaygroundRecorder }).__authenticationPlayground
  if (!recorder) throw createError({ statusCode: 404 })
  return runAuthenticationMaintenance()
})
