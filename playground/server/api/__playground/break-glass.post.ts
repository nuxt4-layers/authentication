import type { PlaygroundRecorder } from '../../plugins/composition'

/**
 * Test-only: runs `provisionAuthenticationBreakGlass` or
 * `rotateAuthenticationBreakGlass`, as a host's operator procedure (or its
 * handler of Identity's `break-glass.used`) would. Absent (404) outside test
 * mode; a host never exposes these over HTTP.
 */
export default defineEventHandler(async (event) => {
  const recorder = (globalThis as { __authenticationPlayground?: PlaygroundRecorder }).__authenticationPlayground
  if (!recorder) throw createError({ statusCode: 404 })
  const body = await readBody<{ action?: string, identityId?: string, address?: string }>(event)
  const correlationId = '01a00000-0000-4000-8000-00000000b6a5'
  if (body.action === 'provision') {
    return provisionAuthenticationBreakGlass({ identityId: body.identityId as string, address: body.address as string, correlationId })
  }
  if (body.action === 'rotate') {
    return rotateAuthenticationBreakGlass({ identityId: body.identityId as string, correlationId })
  }
  throw createError({ statusCode: 400 })
})
