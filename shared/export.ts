import type { AuthenticationRecoveryMethod } from './recovery'

/**
 * Authentication's part of a data-subject access request
 * (iam-integration's data-subject request process): what it holds for one
 * principal, for Profile to assemble into the person's archive. Never a
 * secret, token, code, key or address of another person: factors appear by
 * kind and time only, sessions by time and coarse client only. It holds no
 * profile data to export: names and pictures are Profile's.
 */
export interface AuthenticationDataExport {
  principalId: string
  exportedAt: string
  correlationId: string
  /** The sign-in identifier: the account's email address, and whether it was verified. */
  signInIdentifiers: { kind: 'email', value: string, verified: boolean, createdAt: string }[]
  /** Whether a password is set; never the password or its hash. */
  password: { set: boolean }
  /** Linked identity providers, by provider identifier; never their tokens. */
  providers: { provider: string, linkedAt: string }[]
  /** Passkeys by the name the person gave them and when they were added; never a key. */
  passkeys: { name: string | null, createdAt: string | null, backedUp: boolean }[]
  /** Whether an authenticator app is enrolled, and how many backup codes remain; never a secret or a code. */
  totp: { enabled: boolean, backupCodesRemaining: number }
  /** Sessions in force, newest first: times and a coarse client description only; never a token or address. */
  sessions: { createdAt: string, lastActiveAt: string, expiresAt: string, clientDescription: string | null }[]
  /** The latest credential recovery, by method code. */
  credentialRecovery: { recoveredAt: string, method: AuthenticationRecoveryMethod } | null
}
