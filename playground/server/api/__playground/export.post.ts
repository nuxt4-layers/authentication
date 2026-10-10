import type { PlaygroundRecorder } from '../../plugins/composition'

/**
 * Test-only: runs `exportAuthenticationData` for a principal, as
 * iam-integration's coordination adapter would for Profile. Absent (404)
 * outside test mode; a host never exposes the export over HTTP.
 */
export default defineEventHandler(async (event) => {
  const recorder = (globalThis as { __authenticationPlayground?: PlaygroundRecorder }).__authenticationPlayground
  if (!recorder) throw createError({ statusCode: 404 })
  const body = await readBody<{ principalId?: string }>(event)
  if (typeof body.principalId !== 'string') throw createError({ statusCode: 400 })
  return { export: await exportAuthenticationData({ principalId: body.principalId, correlationId: '01a00000-0000-4000-8000-000000000000' }) }
})
