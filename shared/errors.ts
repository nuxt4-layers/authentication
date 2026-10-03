/**
 * Documented failure categories at the authentication boundary.
 *
 * Messages are deliberately generic. In particular, `invalid-credentials`
 * covers unknown accounts, wrong passwords and disabled accounts alike so that
 * responses cannot be used to enumerate accounts.
 */
export const AUTHENTICATION_ERROR_CODES = [
  'invalid-credentials',
  'mfa-required',
  'invalid-mfa-code',
  'email-not-verified',
  'reauthentication-required',
  'insufficient-assurance',
  'unauthenticated',
  'session-expired',
  'rate-limited',
  'validation-failed',
  'unavailable',
] as const

export type AuthenticationErrorCode = typeof AUTHENTICATION_ERROR_CODES[number]

/** HTTP status used when an error code crosses the HTTP boundary. */
export const AUTHENTICATION_ERROR_STATUS: Readonly<Record<AuthenticationErrorCode, number>> = {
  'invalid-credentials': 401,
  'mfa-required': 401,
  'invalid-mfa-code': 401,
  'email-not-verified': 403,
  'reauthentication-required': 401,
  'insufficient-assurance': 403,
  'unauthenticated': 401,
  'session-expired': 401,
  'rate-limited': 429,
  'validation-failed': 400,
  'unavailable': 503,
}

/** JSON body returned by the layer's HTTP endpoints on failure. */
export interface AuthenticationErrorBody {
  code: AuthenticationErrorCode
  /** Localisation key for the user-facing message, e.g. `authentication.error.invalid-credentials`. */
  messageKey: string
}

export function isAuthenticationErrorCode(value: unknown): value is AuthenticationErrorCode {
  return typeof value === 'string' && (AUTHENTICATION_ERROR_CODES as readonly string[]).includes(value)
}

/**
 * Raised when the host application has not supplied a required port.
 *
 * This is a deployment fault, not a user-facing error. The layer fails closed:
 * the operation is refused rather than falling back to an implicit store.
 */
export class AuthenticationCompositionError extends Error {
  override readonly name = 'AuthenticationCompositionError'

  constructor(public readonly port: string) {
    super(`Authentication port '${port}' has not been supplied by the composition root.`)
  }
}
