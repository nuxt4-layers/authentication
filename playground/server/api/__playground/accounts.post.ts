import type { PlaygroundRecorder } from '../../plugins/composition'

/**
 * Test-only: what a host does on Identity's events, `revokeAuthenticationSessions`
 * (suspended) and `deleteAuthenticationAccount` (closed). Absent (404)
 * outside test mode; a host never exposes them over HTTP.
 */
export default defineEventHandler(async (event) => {
  const recorder = (globalThis as { __authenticationPlayground?: PlaygroundRecorder }).__authenticationPlayground
  if (!recorder) throw createError({ statusCode: 404 })
  const body = await readBody<{ action?: string, principalId?: string }>(event)
  if (typeof body.principalId !== 'string') throw createError({ statusCode: 400 })
  if (body.action === 'revoke-sessions') return { ended: await revokeAuthenticationSessions(body.principalId) }
  if (body.action === 'delete') return { deleted: await deleteAuthenticationAccount(body.principalId) }
  throw createError({ statusCode: 400 })
})
