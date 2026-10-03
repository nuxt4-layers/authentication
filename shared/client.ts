import type { AuthenticationErrorCode } from './errors'

/** Outcome of a `useAuthentication()` action: data on success, a contract error code on failure. */
export type AuthenticationResult<T = undefined> =
  | { ok: true, data: T }
  | { ok: false, code: AuthenticationErrorCode }
