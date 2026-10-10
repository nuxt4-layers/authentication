import type { AuthenticationEvent } from './events'

/**
 * Structural shape of a PostgreSQL connection pool, as provided by the `pg`
 * driver's `Pool`. Declared structurally so the public contract does not
 * depend on a driver package.
 */
export interface PostgresPoolLike {
  query(text: string, values?: readonly unknown[]): Promise<unknown>
  connect(): Promise<unknown>
  end(): Promise<void>
}

/**
 * Persistence port (ADR-0002). The host owns the pool's lifecycle, credentials,
 * TLS and pooling mode; the layer owns everything inside its schema.
 */
export interface AuthenticationDatabase {
  dialect: 'postgres'
  pool: PostgresPoolLike
  /** Schema owned by this capability. Defaults to `authentication`. */
  schema?: string
}

export const AUTHENTICATION_MESSAGE_KINDS = [
  'email-verification',
  'password-reset',
  'email-change-confirmation',
  'security-notification',
] as const

export type AuthenticationMessageKind = typeof AUTHENTICATION_MESSAGE_KINDS[number]

/**
 * A message the layer needs delivered. The host renders and sends it, so
 * branding and delivery provider stay with the application.
 *
 * `actionUrl` contains a single-use secret. Mailers MUST NOT log it.
 */
export interface AuthenticationMessage {
  kind: AuthenticationMessageKind
  to: string
  /** BCP 47 locale for rendering, e.g. `en-GB`. */
  locale: string
  actionUrl: string | null
  /** ISO 8601 expiry of `actionUrl`, when present. */
  expiresAt: string | null
  /** For `security-notification`: the event that triggered it. */
  eventType: AuthenticationEvent['type'] | null
}

/** Mail delivery port. Required for verification, password reset and notifications. */
export interface AuthenticationMailer {
  send(message: AuthenticationMessage): Promise<void>
}

/**
 * Optional event port for audit and logging capabilities.
 *
 * Delivery is best effort: a sink failure is reported but never changes the
 * outcome of the authentication operation that produced the event.
 */
export interface AuthenticationEventSink {
  emit(event: AuthenticationEvent): void | Promise<void>
}

/**
 * Clock port (iam-integration's architecture, "Time"). Every time the layer
 * keeps or judges (when something happened, and whether an authentication is
 * recent) comes from `now()`. The host supplies the suite's one clock, or
 * none, and the layer uses the system clock.
 *
 * A clock is trusted like a key: only the host composes it, from server code.
 * A clock that throws or answers anything but a valid `Date` fails the
 * operation closed (`unavailable`); the layer never falls back to another time.
 */
export interface AuthenticationClock {
  now(): Date
}
