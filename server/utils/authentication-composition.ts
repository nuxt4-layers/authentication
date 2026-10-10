import type {
  AuthenticationClock,
  AuthenticationDatabase,
  AuthenticationEvent,
  AuthenticationEventSink,
  AuthenticationIdentity,
  AuthenticationLegalHolds,
  AuthenticationMailer,
  AuthenticationPolicy,
  AuthenticationPolicyInput,
} from '../../contracts'
import { AuthenticationCompositionError, resolveAuthenticationPolicy } from '../../contracts'

/**
 * Composition registry. The host application calls the `provide*` functions
 * from a Nitro plugin; the layer's server code calls the `use*` functions.
 *
 * Required ports fail closed: using one before it is supplied throws
 * `AuthenticationCompositionError` instead of falling back to an implicit store.
 */

let database: AuthenticationDatabase | null = null
let mailer: AuthenticationMailer | null = null
let eventSink: AuthenticationEventSink | null = null
let policy: AuthenticationPolicy | null = null
let identity: AuthenticationIdentity | null = null
let clock: AuthenticationClock | null = null
let legalHolds: AuthenticationLegalHolds | null = null

const SYSTEM_CLOCK: AuthenticationClock = Object.freeze({ now: () => new Date() })

export function provideAuthenticationDatabase(next: AuthenticationDatabase): void {
  if (next?.dialect !== 'postgres' || typeof next.pool?.query !== 'function') {
    throw new TypeError('provideAuthenticationDatabase expects { dialect: \'postgres\', pool } with a pg-compatible pool.')
  }
  const schema = next.schema ?? 'authentication'
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) {
    throw new TypeError(`Invalid authentication schema name '${schema}'.`)
  }
  database = { ...next, schema }
}

export function provideAuthenticationMailer(next: AuthenticationMailer): void {
  if (typeof next?.send !== 'function') {
    throw new TypeError('provideAuthenticationMailer expects an object with a send(message) function.')
  }
  mailer = next
}

export function provideAuthenticationEventSink(next: AuthenticationEventSink): void {
  if (typeof next?.emit !== 'function') {
    throw new TypeError('provideAuthenticationEventSink expects an object with an emit(event) function.')
  }
  eventSink = next
}

/**
 * Optional identity port (normally iam-integration's adapter over Identity).
 * With it, Identity issues account identifiers and decides each account's
 * standing; without it, the engine issues them and every account is `allowed`.
 */
export function provideAuthenticationIdentity(next: AuthenticationIdentity): void {
  if (typeof next?.reserve !== 'function' || typeof next.confirm !== 'function' || typeof next.standing !== 'function') {
    throw new TypeError('provideAuthenticationIdentity expects an object with reserve, confirm and standing functions.')
  }
  identity = next
}

/** The identity port, or null when the host supplies none. */
export function useAuthenticationIdentity(): AuthenticationIdentity | null {
  return identity
}

/**
 * Optional clock port: the suite's one clock (iam-integration's architecture,
 * "Time"). Every time the layer keeps or judges comes from it; the engine's
 * own times (session lifetime, rate limits, TOTP steps, email-link expiry)
 * stay on the system clock. Trusted like a key: compose it from server code
 * only, and never a movable clock outside tests.
 */
export function provideAuthenticationClock(next: AuthenticationClock): void {
  if (typeof next?.now !== 'function') {
    throw new TypeError('provideAuthenticationClock expects an object with a now() function.')
  }
  clock = next
}

/** The host's clock, or the system clock when the host supplies none. */
export function useAuthenticationClock(): AuthenticationClock {
  return clock ?? SYSTEM_CLOCK
}

/**
 * Optional legal-hold port (normally iam-integration's `legalHoldsFromMembers`
 * with the `authentication` part). Without it, maintenance keeps every
 * credential-recovery record, and still deletes expired sessions and tokens,
 * which no hold covers.
 */
export function provideAuthenticationLegalHolds(next: AuthenticationLegalHolds): void {
  if (typeof next?.covers !== 'function') {
    throw new TypeError('provideAuthenticationLegalHolds expects an object with a covers(subject) function.')
  }
  legalHolds = next
}

/** The legal-hold port, or null when the host supplies none. */
export function useAuthenticationLegalHolds(): AuthenticationLegalHolds | null {
  return legalHolds
}

/** Validates and stores the host's policy overrides. Invalid policy throws at startup. */
export function provideAuthenticationPolicy(input: AuthenticationPolicyInput): void {
  policy = resolveAuthenticationPolicy(input)
}

export function useAuthenticationDatabase(): AuthenticationDatabase & { schema: string } {
  if (!database) throw new AuthenticationCompositionError('AuthenticationDatabase')
  return database as AuthenticationDatabase & { schema: string }
}

export function useAuthenticationMailer(): AuthenticationMailer {
  if (!mailer) throw new AuthenticationCompositionError('AuthenticationMailer')
  return mailer
}

/** The effective policy: host overrides when supplied, otherwise the secure defaults. */
export function useAuthenticationPolicy(): AuthenticationPolicy {
  if (!policy) policy = resolveAuthenticationPolicy()
  return policy
}

/**
 * Emits an event to the host's sink, if one is supplied. Never throws: audit
 * delivery must not change the outcome of the operation that produced it.
 */
export async function emitAuthenticationEvent(event: AuthenticationEvent): Promise<void> {
  if (!eventSink) return
  try {
    await eventSink.emit(event)
  }
  catch (error) {
    console.error(`[authentication] event sink failed for '${event.type}':`, error instanceof Error ? error.message : error)
  }
}

/** Test helper: removes every supplied port. */
export function clearAuthenticationComposition(): void {
  database = null
  mailer = null
  eventSink = null
  policy = null
  identity = null
  clock = null
  legalHolds = null
}
