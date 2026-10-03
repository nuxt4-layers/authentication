import type { H3Event } from 'h3'
import { getRouterParam } from 'h3'
import { authenticationError } from './http'
import { FEDERATION_PROVIDER_IDS, type EnabledProvider, type FederationProviderId } from './federation-config'
import type { AuthenticationRuntime } from './runtime'

/** PRIVATE. Shared federation helpers. */

/**
 * Outcome codes added to the redirect after a provider round trip, as
 * `?federation=<outcome>`. Deliberately coarse: every reason a provider identity
 * cannot sign in to a new or existing account answers `link-required`, so the
 * redirect never reveals whether an account exists for an email address.
 */
export type FederationOutcome = 'cancelled' | 'link-required' | 'link-failed' | 'failed'

const LINK_REQUIRED = new Set([
  'account_not_linked', 'unable_to_link_account', 'email_not_verified', 'unable_to_create_user',
  'email_not_found', 'signup_disabled', 'user_not_found',
])
const LINK_FAILED = new Set(['account_already_linked_to_different_user', 'email_does_not_match'])

export function federationOutcome(engineError: string): FederationOutcome {
  if (engineError === 'access_denied') return 'cancelled'
  if (LINK_REQUIRED.has(engineError)) return 'link-required'
  if (LINK_FAILED.has(engineError)) return 'link-failed'
  return 'failed'
}

/** The enabled provider named in the route, or a `validation-failed` error. */
export function routeProvider(event: H3Event, runtime: AuthenticationRuntime): EnabledProvider {
  const id = getRouterParam(event, 'provider')
  const provider = runtime.providers.find(candidate => candidate.id === id)
  if (!provider || !(FEDERATION_PROVIDER_IDS as readonly string[]).includes(id!)) throw authenticationError('validation-failed')
  return provider
}

export function isFederationProvider(value: string): value is FederationProviderId {
  return (FEDERATION_PROVIDER_IDS as readonly string[]).includes(value)
}
