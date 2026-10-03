import type { H3Event } from 'h3'
import { appendResponseHeader, createError, getRequestHeader, getRequestHeaders, getRequestIP } from 'h3'
import type { AuthenticationErrorBody, AuthenticationErrorCode, AuthenticationEventClient } from '../../contracts'
import { AUTHENTICATION_ERROR_STATUS } from '../../contracts'

/** PRIVATE. HTTP boundary helpers shared by the layer's endpoints. */

export function authenticationError(code: AuthenticationErrorCode) {
  const data: AuthenticationErrorBody = { code, messageKey: `authentication.error.${code}` }
  return createError({ statusCode: AUTHENTICATION_ERROR_STATUS[code], statusMessage: code, data })
}

/** Engine error codes translated to contract codes. Anything unknown becomes `unavailable`. */
const ENGINE_ERROR_CODES: Record<string, AuthenticationErrorCode> = {
  INVALID_EMAIL_OR_PASSWORD: 'invalid-credentials',
  INVALID_EMAIL: 'invalid-credentials',
  INVALID_PASSWORD: 'invalid-credentials',
  CREDENTIAL_ACCOUNT_NOT_FOUND: 'invalid-credentials',
  EMAIL_NOT_VERIFIED: 'email-not-verified',
  PASSWORD_TOO_SHORT: 'password-rejected',
  PASSWORD_TOO_LONG: 'password-rejected',
  INVALID_TOKEN: 'invalid-or-expired-token',
  TOKEN_EXPIRED: 'invalid-or-expired-token',
  USER_NOT_FOUND: 'invalid-or-expired-token',
  SESSION_EXPIRED: 'session-expired',
  SESSION_NOT_FRESH: 'reauthentication-required',
  UNAUTHORIZED: 'unauthenticated',
}

export function engineErrorCode(error: unknown): AuthenticationErrorCode {
  const body = (error as { body?: { code?: unknown } } | null)?.body
  const code = typeof body?.code === 'string' ? body.code : undefined
  return (code && ENGINE_ERROR_CODES[code]) || 'unavailable'
}

/** Translates any thrown engine error into a contract error, logging unexpected ones without detail leakage. */
export function translateEngineError(error: unknown) {
  const code = engineErrorCode(error)
  if (code === 'unavailable') {
    console.error('[authentication] unexpected engine failure:', error instanceof Error ? error.message : error)
  }
  return authenticationError(code)
}

export function requestHeaders(event: H3Event): Headers {
  const headers = new Headers()
  for (const [name, value] of Object.entries(getRequestHeaders(event))) {
    if (typeof value === 'string') headers.set(name, value)
  }
  return headers
}

/** Copies the engine's Set-Cookie headers onto the h3 response. */
export function forwardCookies(event: H3Event, headers: Headers | undefined | null): void {
  if (!headers) return
  for (const cookie of headers.getSetCookie()) appendResponseHeader(event, 'set-cookie', cookie)
}

export function clientInfo(event: H3Event, trustProxy: boolean): AuthenticationEventClient {
  return {
    ipAddress: getRequestIP(event, { xForwardedFor: trustProxy }) ?? null,
    userAgent: getRequestHeader(event, 'user-agent') ?? null,
  }
}

const BROWSERS: [RegExp, string][] = [
  [/Edg\//, 'Edge'], [/OPR\//, 'Opera'], [/Firefox\//, 'Firefox'], [/Chrome\//, 'Chrome'], [/Safari\//, 'Safari'],
]
const SYSTEMS: [RegExp, string][] = [
  [/Android/, 'Android'], [/iPhone|iPad|iOS/, 'iOS'], [/Windows/, 'Windows'], [/Mac OS X|Macintosh/, 'macOS'], [/CrOS/, 'ChromeOS'], [/Linux/, 'Linux'],
]

/** Coarse, user-presentable description such as "Firefox on Linux". Never returns the raw user agent. */
export function describeClient(userAgent: string | null | undefined): string | null {
  if (!userAgent) return null
  const browser = BROWSERS.find(([pattern]) => pattern.test(userAgent))?.[1]
  const system = SYSTEMS.find(([pattern]) => pattern.test(userAgent))?.[1]
  if (browser && system) return `${browser} on ${system}`
  return browser ?? system ?? null
}

export { safeRedirectPath } from '../../shared/redirect'
