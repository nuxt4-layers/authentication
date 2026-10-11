import type { AuthenticationMethod } from './principal'
import type { AuthenticationServiceCredentialEnding, AuthenticationServiceCredentialKind } from './service-credentials'

/**
 * Facts emitted after security-relevant authentication events, for audit and
 * logging capabilities.
 *
 * Events MUST NOT carry credentials, codes, tokens, session secrets or email
 * addresses. Consumers correlate by `principalId` and `sessionId`.
 */
export const AUTHENTICATION_EVENT_TYPES = [
  'authentication.account-registered',
  'authentication.email-verified',
  'authentication.signed-in',
  'authentication.sign-in-failed',
  'authentication.signed-out',
  'authentication.account-locked',
  'authentication.password-changed',
  'authentication.password-reset-requested',
  'authentication.password-reset-completed',
  'authentication.mfa-enrolled',
  'authentication.mfa-removed',
  'authentication.backup-codes-regenerated',
  'authentication.backup-code-used',
  'authentication.credentials-recovered',
  'authentication.account-deleted',
  'authentication.reauthenticated',
  'authentication.session-revoked',
  'authentication.federated-identity-linked',
  'authentication.federated-identity-unlinked',
  'authentication.break-glass-provisioned',
  'authentication.break-glass-enrolled',
  'authentication.break-glass-rotated',
  'authentication.retention-applied',
  'authentication.service-credential-issued',
  'authentication.service-credential-revoked',
  'authentication.service-credential-expiring',
  'authentication.service-token-issued',
] as const

export type AuthenticationEventType = typeof AUTHENTICATION_EVENT_TYPES[number]

/**
 * Client context for an event. IP address and user agent are personal data;
 * the event sink owner is responsible for their retention.
 */
export interface AuthenticationEventClient {
  ipAddress: string | null
  userAgent: string | null
}

export interface AuthenticationEvent {
  type: AuthenticationEventType
  /** ISO 8601 timestamp. */
  occurredAt: string
  /** Null when no principal could be attributed, e.g. a failed sign-in for an unknown account. */
  principalId: string | null
  sessionId: string | null
  /** Method involved, where one applies. */
  method: AuthenticationMethod | null
  /** Machine-readable reason, e.g. `invalid-credentials` for a failed sign-in. */
  reason: string | null
  client: AuthenticationEventClient | null
  /** `authentication.retention-applied` only: how many records of each kind the run deleted. */
  counts?: AuthenticationRetentionCounts
  /**
   * Service-credential events only: which credential (never its secret or
   * key), its kind and expiry, and why it ended. `principalId` is the
   * service identity.
   */
  credential?: AuthenticationEventCredential
  /** A service credential issued or revoked by a person: that person's principal identifier. */
  actorId?: string
}

export interface AuthenticationEventCredential {
  credentialId: string
  kind: AuthenticationServiceCredentialKind
  expiresAt: string
  /** `authentication.service-credential-revoked` only. */
  endedHow?: AuthenticationServiceCredentialEnding
}

/** Records deleted by one maintenance run, by kind. Counts only, never identifiers. */
export interface AuthenticationRetentionCounts {
  sessions: number
  credentialRecoveries: number
  enrolmentTokens: number
  verifications: number
  /** Service tokens expired more than `retention.tokenDays` ago. */
  serviceTokens: number
  /** Service credentials revoked or expired more than `retention.tokenDays` ago. */
  serviceCredentials: number
}
