import type { AuthenticationCredentialRecovery, AuthenticationCredentialRecoveryPage } from '../../contracts'
import { useAuthenticationRuntime } from '../internal/nitro'

/**
 * PUBLIC server helpers for credential recovery (auto-imported for the host's
 * server code). The host relays `authentication.credentials-recovered` to
 * Identity, and reconciles from these records so that a lost event never
 * skips Identity's recovery hold.
 */

/** When the principal's credentials were last recovered, and how; null if never. */
export async function getAuthenticationCredentialRecovery(principalId: string): Promise<AuthenticationCredentialRecovery | null> {
  return (await useAuthenticationRuntime()).recoveries.get(principalId)
}

/**
 * Recoveries in the order they happened. Pass the previous page's `next` as
 * `after` to continue; a principal recovered again moves to a later page.
 */
export async function listAuthenticationCredentialRecoveries(input: { after?: string | null, limit?: number } = {}): Promise<AuthenticationCredentialRecoveryPage> {
  return (await useAuthenticationRuntime()).recoveries.list(input)
}
