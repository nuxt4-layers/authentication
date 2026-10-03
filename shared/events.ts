import type { AuthenticationMethod } from './principal'

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
  'authentication.reauthenticated',
  'authentication.session-revoked',
  'authentication.federated-identity-linked',
  'authentication.federated-identity-unlinked',
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
}
