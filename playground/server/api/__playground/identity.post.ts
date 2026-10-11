import type { PlaygroundIdentity } from '../../plugins/composition'

/**
 * Test-only: sets an account's or service identity's standing, who may
 * manage a service identity, or makes the stand-in ports fail. Absent (404)
 * unless they are on.
 */
export default defineEventHandler(async (event) => {
  const identity = (globalThis as { __authenticationPlaygroundIdentity?: PlaygroundIdentity }).__authenticationPlaygroundIdentity
  if (!identity) throw createError({ statusCode: 404 })
  const body = await readBody<{ principalId?: string, standing?: PlaygroundIdentity['standings'][string]['standing'], passkeyOnly?: boolean, failing?: boolean, serviceIdentityId?: string, managers?: string[] }>(event)
  if (typeof body.failing === 'boolean') identity.failing = body.failing
  if (body.principalId && body.standing) identity.standings[body.principalId] = { standing: body.standing, passkeyOnly: body.passkeyOnly === true }
  if (body.serviceIdentityId && Array.isArray(body.managers)) identity.managers[body.serviceIdentityId] = body.managers
  return { status: 'ok' }
})
