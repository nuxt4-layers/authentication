import { currentTime } from '../internal/clock'
import { useAuthenticationRuntime } from '../internal/nitro'
import { systemEvent } from '../internal/runtime'
import { credentialEvent } from '../internal/service-endpoints'

/**
 * PUBLIC server helpers for the host's handling of Identity's events
 * (auto-imported). Access never depends on them, since every request reads
 * the account's standing, but they end sessions and remove accounts promptly.
 */

/**
 * Ends every session of the principal, e.g. on `identity.paused`,
 * `identity.suspended` or `identity.closure-requested`, and every token of a
 * service identity (its credentials stay, for reinstatement). Returns how
 * many ended.
 */
export async function revokeAuthenticationSessions(principalId: string): Promise<number> {
  const runtime = await useAuthenticationRuntime()
  const context = await runtime.engine.$context
  const tokens = await runtime.serviceCredentials.endTokens(principalId)
  const sessions = await context.internalAdapter.listSessions(principalId)
  if (sessions.length > 0) await context.internalAdapter.deleteUserSessions(principalId)
  const ended = sessions.length + tokens
  if (ended > 0) await runtime.emit(systemEvent('authentication.session-revoked', principalId, { reason: 'identity-standing' }))
  return ended
}

/**
 * Removes an account whose sign-in identifier was never verified, on
 * `identity.provisioning-expired`. A verified account is kept. Returns whether
 * one was removed.
 */
export async function discardAuthenticationAccount(principalId: string): Promise<boolean> {
  const runtime = await useAuthenticationRuntime()
  const context = await runtime.engine.$context
  const user = await context.internalAdapter.findUserById(principalId)
  if (!user || user.emailVerified) return false
  await context.internalAdapter.deleteUser(principalId)
  await runtime.emit(systemEvent('authentication.account-deleted', principalId, { reason: 'provisioning-expired' }))
  return true
}

/**
 * Deletes an account with its credentials, sessions and sign-in identifier,
 * on `identity.closed` (iam-integration's account closure), or a closed
 * service identity's credentials and tokens, writing
 * `authentication.service-credential-revoked` (`identity-closed`) for each
 * that was active. Returns whether anything was deleted.
 */
export async function deleteAuthenticationAccount(principalId: string): Promise<boolean> {
  const runtime = await useAuthenticationRuntime()
  const context = await runtime.engine.$context
  const ended = await runtime.serviceCredentials.forget(principalId, currentTime())
  for (const credential of ended) {
    await runtime.emit(credentialEvent('authentication.service-credential-revoked', credential, { endedHow: 'identity-closed' }))
  }
  const user = await context.internalAdapter.findUserById(principalId)
  if (!user) return ended.length > 0
  await context.internalAdapter.deleteUserSessions(principalId)
  await context.internalAdapter.deleteUser(principalId)
  await runtime.emit(systemEvent('authentication.account-deleted', principalId, { reason: 'identity-closed' }))
  return true
}
