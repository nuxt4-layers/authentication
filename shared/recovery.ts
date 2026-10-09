/**
 * Credential recovery records. Re-exported from the public contract.
 *
 * Authentication keeps, for each principal, when their credentials were last
 * recovered and how. Identity holds governance changes requested soon after a
 * recovery (iam-integration's recovery process); the host relays
 * `authentication.credentials-recovered` to it, and reconciles from these
 * records so that a lost event never skips the hold.
 */

/**
 * - `password-reset` — the password was reset through the sign-in identifier.
 * - `backup-code` — a second factor was replaced by a single-use backup code.
 */
export const AUTHENTICATION_RECOVERY_METHODS = ['password-reset', 'backup-code'] as const

export type AuthenticationRecoveryMethod = typeof AUTHENTICATION_RECOVERY_METHODS[number]

export interface AuthenticationCredentialRecovery {
  principalId: string
  /** ISO 8601 timestamp of the latest recovery. */
  recoveredAt: string
  method: AuthenticationRecoveryMethod
}

/** A page of recoveries in the order they happened, for a host's reconciliation. */
export interface AuthenticationCredentialRecoveryPage {
  recoveries: AuthenticationCredentialRecovery[]
  /** Pass as `after` to read the next page; null when there is no more. */
  next: string | null
}
