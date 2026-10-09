import { useAuthenticationRuntime } from '../internal/nitro'
import { systemEvent } from '../internal/runtime'

/**
 * PUBLIC server helpers for the host's handling of Identity's events
 * (auto-imported). Access never depends on them, since every request reads
 * the account's standing, but they end sessions and remove accounts promptly.
 */

/**
 * Ends every session of the principal, e.g. on `identity.paused`,
 * `identity.suspended` or `identity.closure-requested`. Returns how many ended.
 */
export async function revokeAuthenticationSessions(principalId: string): Promise<number> {
  const runtime = await useAuthenticationRuntime()
  const context = await runtime.engine.$context
  const sessions = await context.internalAdapter.listSessions(principalId)
  if (sessions.length === 0) return 0
  await context.internalAdapter.deleteUserSessions(principalId)
  await runtime.emit(systemEvent('authentication.session-revoked', principalId, { reason: 'identity-standing' }))
  return sessions.length
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
 * on `identity.closed` (iam-integration's account closure). Returns whether
 * one was deleted.
 */
export async function deleteAuthenticationAccount(principalId: string): Promise<boolean> {
  const runtime = await useAuthenticationRuntime()
  const context = await runtime.engine.$context
  const user = await context.internalAdapter.findUserById(principalId)
  if (!user) return false
  await context.internalAdapter.deleteUserSessions(principalId)
  await context.internalAdapter.deleteUser(principalId)
  await runtime.emit(systemEvent('authentication.account-deleted', principalId, { reason: 'identity-closed' }))
  return true
}
