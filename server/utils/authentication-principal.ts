import type { H3Event } from 'h3'
import type { AuthenticatedPrincipal, AuthenticationRequirement } from '../../contracts'
import { authenticationError } from '../internal/http'
import { resolvePrincipal, startMigrations } from '../internal/nitro'
import { evaluateRequirement } from '../internal/principal'

/**
 * PUBLIC server helpers (auto-imported for the host's server code).
 */

/** The current principal, or null when the request has no valid session. */
export function getAuthenticatedPrincipal(event: H3Event): Promise<AuthenticatedPrincipal | null> {
  return resolvePrincipal(event)
}

/**
 * The current principal, or a contract error:
 * `unauthenticated` (401), `insufficient-assurance` (403) or `reauthentication-required` (401).
 */
export async function requireAuthenticatedPrincipal(
  event: H3Event,
  requirement?: AuthenticationRequirement,
): Promise<AuthenticatedPrincipal> {
  const principal = await resolvePrincipal(event)
  if (!principal) throw authenticationError('unauthenticated')
  const failure = evaluateRequirement(principal, requirement)
  if (failure) throw authenticationError(failure)
  return principal
}

/**
 * Applies pending migrations to the capability schema. Call once from the host's
 * Nitro plugin after `provideAuthenticationDatabase`; authentication requests
 * wait for it to finish. Safe to run concurrently from several instances.
 */
export function migrateAuthenticationDatabase(): Promise<string[]> {
  return startMigrations()
}
