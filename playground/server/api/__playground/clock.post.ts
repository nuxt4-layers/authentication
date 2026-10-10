import type { PlaygroundClock } from '../../plugins/composition'

/**
 * Test-only: moves the playground's clock forward, or makes it fail. Absent
 * (404) outside test mode; a host never lets a request move its clock.
 */
export default defineEventHandler(async (event) => {
  const clock = (globalThis as { __authenticationPlaygroundClock?: PlaygroundClock }).__authenticationPlaygroundClock
  if (!clock) throw createError({ statusCode: 404 })
  const body = await readBody<{ advanceSeconds?: number, failing?: boolean }>(event)
  if (typeof body.advanceSeconds === 'number') {
    // Forward only, as iam-integration requires of a test clock.
    if (!Number.isFinite(body.advanceSeconds) || body.advanceSeconds < 0) throw createError({ statusCode: 400 })
    clock.offsetMs += body.advanceSeconds * 1000
  }
  if (typeof body.failing === 'boolean') clock.failing = body.failing
  return { offsetMs: clock.offsetMs }
})
