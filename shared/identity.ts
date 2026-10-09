/**
 * The identity port: how Authentication learns who an account belongs to and
 * whether it may hold a session. Re-exported from the public contract.
 *
 * Authentication declares the port in its own language; the host supplies it,
 * normally through iam-integration's reference adapter over Identity's
 * provisioning port. Without it, Authentication runs on its own: the engine
 * issues account identifiers and every account is `allowed`.
 */

/**
 * Whether an account may hold a session, decided by its owner (Identity):
 *
 * - `allowed` — signs in and uses the platform;
 * - `resume-only` — paused: may sign in only to view and resume;
 * - `cancel-closure-only` — closing: may sign in only to cancel the closure;
 * - `verification-only` — not yet confirmed: may only complete verification;
 * - `refused` — suspended, closed or unknown: no session at all.
 */
export const AUTHENTICATION_STANDINGS = ['allowed', 'resume-only', 'cancel-closure-only', 'verification-only', 'refused'] as const

export type AuthenticationStanding = typeof AUTHENTICATION_STANDINGS[number]

export interface AuthenticationAccountStanding {
  standing: AuthenticationStanding
  /** True for break-glass accounts (ADR-0007): a passkey is the only way in. */
  passkeyOnly: boolean
}

/** Optional port. Every call must fail by rejecting; Authentication then fails closed. */
export interface AuthenticationIdentity {
  /**
   * Issues the principal identifier for an account about to be created, before
   * its sign-in identifier is verified. Receives no personal data. With an
   * invitation token (sign-up through an invitation), the owner resolves the
   * inviting tenant on the server.
   */
  reserve(input: { invitationToken: string | null }): Promise<{ principalId: string }>
  /** The account's sign-in identifier is verified. Idempotent. */
  confirm(principalId: string): Promise<void>
  /** The account's standing now, never from a cache. Null when unknown (treated as `refused`). */
  standing(principalId: string): Promise<AuthenticationAccountStanding | null>
}
