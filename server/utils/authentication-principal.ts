import type { H3Event } from 'h3'
import type { AuthenticatedPrincipal, AuthenticationAssuranceLevel, AuthenticationRequirement } from '../../contracts'
import { currentTime } from '../internal/clock'
import { authenticationError } from '../internal/http'
import { resolvePrincipal, startMigrations } from '../internal/nitro'
import { evaluateRequirement } from '../internal/principal'
import { useAuthenticationPolicy } from './authentication-composition'

/**
 * PUBLIC server helpers (auto-imported for the host's server code).
 */

/** The assurance level the policy demands by default: aal2 when MFA is required. */
export function requiredAssuranceLevel(): AuthenticationAssuranceLevel {
  return useAuthenticationPolicy().mfa === 'required' ? 'aal2' : 'aal1'
}

/** The current principal, or null when the request has no valid session. */
export function getAuthenticatedPrincipal(event: H3Event): Promise<AuthenticatedPrincipal | null> {
  return resolvePrincipal(event)
}

/**
 * The current principal, or a contract error:
 * `unauthenticated` (401), `insufficient-assurance` (403) or `reauthentication-required` (401).
 *
 * `minimumLevel` defaults to the policy's required level: `aal2` while
 * `mfa: 'required'` (the default), so sessions that have not completed a second
 * factor are refused. Pass `{ minimumLevel: 'aal1' }` to accept them explicitly.
 */
export async function requireAuthenticatedPrincipal(
  event: H3Event,
  requirement?: AuthenticationRequirement,
): Promise<AuthenticatedPrincipal> {
  const principal = await resolvePrincipal(event)
  if (!principal) throw authenticationError('unauthenticated')
  // Whether the authentication is recent is judged by the layer's clock.
  const failure = evaluateRequirement(principal, { minimumLevel: requiredAssuranceLevel(), ...requirement }, currentTime())
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
