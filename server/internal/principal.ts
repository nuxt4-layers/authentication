import type {
  AuthenticatedPrincipal,
  AuthenticationAssuranceLevel,
  AuthenticationMethod,
  AuthenticationRequirement,
} from '../../contracts'
import type { AuthenticationErrorCode } from '../../contracts'

/** PRIVATE. Maps engine session records to the public principal and evaluates requirements. */

export interface EngineSessionRecord {
  id: string
  token: string
  userId: string
  createdAt: Date | string
  expiresAt: Date | string
  authenticatedAt?: Date | string | null
  authenticationMethods?: string | null
}

const KNOWN_METHODS: readonly AuthenticationMethod[] = ['password', 'totp', 'backup-code', 'passkey', 'federated', 'remembered-device']
const SECOND_FACTORS: readonly AuthenticationMethod[] = ['totp', 'backup-code', 'passkey', 'remembered-device']

export function parseMethods(value: string | null | undefined): AuthenticationMethod[] {
  return (value ?? '')
    .split(',')
    .map(method => method.trim())
    .filter((method): method is AuthenticationMethod => (KNOWN_METHODS as readonly string[]).includes(method))
}

export function assuranceLevel(methods: readonly AuthenticationMethod[]): AuthenticationAssuranceLevel {
  // A passkey is multi-factor on its own (possession plus user verification).
  if (methods.includes('passkey')) return 'aal2'
  // Otherwise aal2 needs a primary method (password or identity provider) plus a second factor.
  const primary = methods.includes('password') || methods.includes('federated')
  return primary && methods.some(method => SECOND_FACTORS.includes(method)) ? 'aal2' : 'aal1'
}

const toDate = (value: Date | string) => (value instanceof Date ? value : new Date(value))

/**
 * Absolute expiry: the earlier of the sliding expiry and createdAt + absolute
 * lifetime. Session lifetime is the engine's, judged on the system clock.
 */
export function absoluteExpiry(session: EngineSessionRecord, absoluteLifetimeSeconds: number): Date {
  const absolute = new Date(toDate(session.createdAt).getTime() + absoluteLifetimeSeconds * 1000)
  const sliding = toDate(session.expiresAt)
  return absolute < sliding ? absolute : sliding
}

export function toPrincipal(session: EngineSessionRecord, absoluteLifetimeSeconds: number, standing: AuthenticatedPrincipal['standing'] = 'allowed'): AuthenticatedPrincipal {
  const methods = parseMethods(session.authenticationMethods)
  return {
    principalId: session.userId,
    sessionId: session.id,
    authenticatedAt: toDate(session.authenticatedAt ?? session.createdAt).toISOString(),
    expiresAt: absoluteExpiry(session, absoluteLifetimeSeconds).toISOString(),
    assurance: {
      level: assuranceLevel(methods),
      methods,
      phishingResistant: methods.includes('passkey'),
    },
    standing,
  }
}

/**
 * Returns the failing contract code, or null when the principal satisfies the
 * requirement. `now` is the layer's clock time, which judges freshness.
 */
export function evaluateRequirement(
  principal: AuthenticatedPrincipal,
  requirement: AuthenticationRequirement,
  now: Date,
): AuthenticationErrorCode | null {
  if (principal.standing !== 'allowed' && !(requirement.allowStandings ?? []).includes(principal.standing)) return 'account-restricted'
  if (requirement.minimumLevel === 'aal2' && principal.assurance.level !== 'aal2') return 'insufficient-assurance'
  if (requirement.phishingResistant && !principal.assurance.phishingResistant) return 'insufficient-assurance'
  if (requirement.maxAuthenticationAgeSeconds !== undefined) {
    const age = (now.getTime() - new Date(principal.authenticatedAt).getTime()) / 1000
    if (age > requirement.maxAuthenticationAgeSeconds) return 'reauthentication-required'
  }
  return null
}
