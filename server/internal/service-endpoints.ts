import type { H3Event } from 'h3'
import { getRouterParam, setResponseHeader } from 'h3'
import type { AuthenticatedPrincipal, AuthenticationEvent, AuthenticationServiceCredential } from '../../contracts'
import { useAuthenticationServiceGovernance } from '../utils/authentication-composition'
import { requireAuthenticatedPrincipal } from '../utils/authentication-principal'
import { authenticationError } from './http'
import { useAuthenticationRuntime } from './nitro'
import type { AuthenticationRuntime } from './runtime'
import { systemEvent } from './runtime'

/**
 * PRIVATE. The guard of the service-credential endpoints (iam-integration's
 * service identities process, "Credentials"): a signed-in person whom the
 * host's service-governance port allows to manage the service identity now.
 * Issuing and revoking also need a phishing-resistant authentication within
 * the policy's reauthentication age, at most fifteen minutes. Without the
 * port, or when it says no, `forbidden`, whether or not the identity exists;
 * when it fails, `unavailable`.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const STEP_UP_SECONDS = 900

export interface ServiceCredentialAccess {
  principal: AuthenticatedPrincipal
  identityId: string
  runtime: AuthenticationRuntime
}

export async function requireServiceCredentialAccess(event: H3Event, change: boolean): Promise<ServiceCredentialAccess> {
  const runtime = await useAuthenticationRuntime()
  const principal = await requireAuthenticatedPrincipal(event, change
    ? { phishingResistant: true, maxAuthenticationAgeSeconds: Math.min(runtime.policy.reauthentication.maxAgeSeconds, STEP_UP_SECONDS) }
    : {})
  // Credentials are a person's to manage, never another service's (the layer's endpoints read no bearer token, so this is defence in depth).
  if (principal.kind !== 'person') throw authenticationError('forbidden')
  const identityId = getRouterParam(event, 'identityId') ?? ''
  if (!UUID.test(identityId)) throw authenticationError('forbidden')
  const governance = useAuthenticationServiceGovernance()
  if (!governance) throw authenticationError('forbidden')
  let allowed: unknown
  try {
    allowed = await governance.mayManage({ principal, serviceIdentityId: identityId })
  }
  catch {
    throw authenticationError('unavailable')
  }
  if (allowed !== true) throw authenticationError('forbidden')
  // A credential's answer is never cached.
  setResponseHeader(event, 'cache-control', 'no-store')
  return { principal, identityId, runtime }
}

/** A service-credential event: the identity, the credential (never its secret or key) and, when a person acted, who. */
export function credentialEvent(
  type: Extract<AuthenticationEvent['type'], `authentication.service-${string}`>,
  credential: AuthenticationServiceCredential,
  extra: Partial<AuthenticationEvent> & { endedHow?: NonNullable<AuthenticationEvent['credential']>['endedHow'] } = {},
): AuthenticationEvent {
  const { endedHow, ...rest } = extra
  return systemEvent(type, credential.identityId, {
    ...rest,
    credential: { credentialId: credential.credentialId, kind: credential.kind, expiresAt: credential.expiresAt, ...(endedHow ? { endedHow } : {}) },
  })
}
