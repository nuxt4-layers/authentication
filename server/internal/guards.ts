import type { H3Event } from 'h3'
import type { AuthenticatedPrincipal } from '../../contracts'
import { useAuthenticationPolicy } from '../utils/authentication-composition'
import { requireAuthenticatedPrincipal } from '../utils/authentication-principal'

/**
 * PRIVATE. Access levels for the layer's own endpoints.
 *
 * - `enrolment`: any signed-in session (aal1 accepted) that authenticated
 *   recently. Lets enrol-only sessions add their first second factor.
 * - `step-up`: any signed-in session; used to raise assurance.
 * - `standard`: the policy's required level.
 * - `sensitive`: the policy's required level and a recent authentication.
 */
export type AccessLevel = 'enrolment' | 'step-up' | 'standard' | 'sensitive'

export function requireAccess(event: H3Event, level: AccessLevel): Promise<AuthenticatedPrincipal> {
  const maxAge = useAuthenticationPolicy().reauthentication.maxAgeSeconds
  switch (level) {
    case 'enrolment': return requireAuthenticatedPrincipal(event, { minimumLevel: 'aal1', maxAuthenticationAgeSeconds: maxAge })
    case 'step-up': return requireAuthenticatedPrincipal(event, { minimumLevel: 'aal1' })
    case 'standard': return requireAuthenticatedPrincipal(event)
    case 'sensitive': return requireAuthenticatedPrincipal(event, { maxAuthenticationAgeSeconds: maxAge })
  }
}
