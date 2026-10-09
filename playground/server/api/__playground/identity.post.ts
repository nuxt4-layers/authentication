import type { PlaygroundIdentity } from '../../plugins/composition'

/** Test-only: sets an account's standing, or makes the stand-in identity port fail. Absent (404) unless it is on. */
export default defineEventHandler(async (event) => {
  const identity = (globalThis as { __authenticationPlaygroundIdentity?: PlaygroundIdentity }).__authenticationPlaygroundIdentity
  if (!identity) throw createError({ statusCode: 404 })
  const body = await readBody<{ principalId?: string, standing?: PlaygroundIdentity['standings'][string]['standing'], passkeyOnly?: boolean, failing?: boolean }>(event)
  if (typeof body.failing === 'boolean') identity.failing = body.failing
  if (body.principalId && body.standing) identity.standings[body.principalId] = { standing: body.standing, passkeyOnly: body.passkeyOnly === true }
  return { status: 'ok' }
})
