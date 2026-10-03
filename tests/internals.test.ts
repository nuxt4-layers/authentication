import { createHash } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import type { AuthenticatedPrincipal } from '../contracts'
import { resolveAuthenticationPolicy } from '../contracts'
import { createHibpCheck } from '../server/internal/compromised-password'
import { buildEngineOptions } from '../server/internal/engine-options'
import { describeClient, engineErrorCode, safeRedirectPath } from '../server/internal/http'
import { absoluteExpiry, assuranceLevel, evaluateRequirement, parseMethods, toPrincipal } from '../server/internal/principal'
import { validateRuntimeConfig } from '../server/internal/runtime'

describe('engine error translation', () => {
  it.each([
    ['INVALID_EMAIL_OR_PASSWORD', 'invalid-credentials'],
    ['EMAIL_NOT_VERIFIED', 'email-not-verified'],
    ['PASSWORD_TOO_SHORT', 'password-rejected'],
    ['INVALID_TOKEN', 'invalid-or-expired-token'],
    ['USER_NOT_FOUND', 'invalid-or-expired-token'],
    ['SESSION_NOT_FRESH', 'reauthentication-required'],
  ])('maps %s to %s', (engineCode, contractCode) => {
    expect(engineErrorCode({ body: { code: engineCode } })).toBe(contractCode)
  })

  it('maps anything unknown to unavailable, never leaking engine detail', () => {
    expect(engineErrorCode({ body: { code: 'SOMETHING_NEW' } })).toBe('unavailable')
    expect(engineErrorCode(new Error('boom'))).toBe('unavailable')
    expect(engineErrorCode(null)).toBe('unavailable')
  })
})

describe('client description', () => {
  it.each([
    ['Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0', 'Firefox on Linux'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36 Edg/128.0', 'Edge on Windows'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1', 'Safari on iOS'],
    ['curl/8.0', null],
    [null, null],
  ])('describes %s as %s', (userAgent, expected) => {
    expect(describeClient(userAgent)).toBe(expected)
  })
})

describe('redirect safety', () => {
  it.each([
    ['/account', '/account'],
    ['/account?tab=security#sessions', '/account?tab=security#sessions'],
    ['//evil.example/path', '/'],
    ['https://evil.example', '/'],
    ['/\\evil.example', '/'],
    ['javascript:alert(1)', '/'],
    [42, '/'],
  ])('maps %s to %s', (candidate, expected) => {
    expect(safeRedirectPath(candidate, '/')).toBe(expected)
  })
})

describe('principal and assurance', () => {
  const session = {
    id: 's1',
    token: 'secret-token',
    userId: 'u1',
    createdAt: new Date('2026-10-03T10:00:00Z'),
    expiresAt: new Date('2026-10-03T11:30:00Z'),
    authenticatedAt: new Date('2026-10-03T10:00:00Z'),
    authenticationMethods: 'password',
  }

  it('ignores unknown method names', () => {
    expect(parseMethods('password, totp,nonsense')).toEqual(['password', 'totp'])
    expect(parseMethods(null)).toEqual([])
  })

  it.each([
    [['password'], 'aal1'],
    [['password', 'totp'], 'aal2'],
    [['password', 'backup-code'], 'aal2'],
    [['passkey'], 'aal2'],
    [['totp'], 'aal1'],
    [['federated'], 'aal1'],
  ] as const)('rates %j as %s', (methods, level) => {
    expect(assuranceLevel(methods)).toBe(level)
  })

  it('caps expiry at the absolute lifetime', () => {
    expect(absoluteExpiry(session, 3600).toISOString()).toBe('2026-10-03T11:00:00.000Z')
    expect(absoluteExpiry(session, 86_400).toISOString()).toBe('2026-10-03T11:30:00.000Z')
  })

  it('maps a session to the public principal without the token', () => {
    const principal = toPrincipal(session, 86_400)
    expect(principal).toEqual({
      principalId: 'u1',
      sessionId: 's1',
      authenticatedAt: '2026-10-03T10:00:00.000Z',
      expiresAt: '2026-10-03T11:30:00.000Z',
      assurance: { level: 'aal1', methods: ['password'], phishingResistant: false },
    })
    expect(JSON.stringify(principal)).not.toContain('secret-token')
  })

  it('evaluates requirements', () => {
    const principal: AuthenticatedPrincipal = toPrincipal(session, 86_400)
    const now = new Date('2026-10-03T10:10:00Z')
    expect(evaluateRequirement(principal, {}, now)).toBeNull()
    expect(evaluateRequirement(principal, { minimumLevel: 'aal2' }, now)).toBe('insufficient-assurance')
    expect(evaluateRequirement(principal, { phishingResistant: true }, now)).toBe('insufficient-assurance')
    expect(evaluateRequirement(principal, { maxAuthenticationAgeSeconds: 900 }, now)).toBeNull()
    expect(evaluateRequirement(principal, { maxAuthenticationAgeSeconds: 300 }, now)).toBe('reauthentication-required')
  })
})

describe('runtime configuration', () => {
  const valid = { secret: 's'.repeat(32), baseUrl: 'https://example.com', production: true }

  it('accepts a strong secret and an https base URL', () => {
    expect(validateRuntimeConfig(valid).origin).toBe('https://example.com')
  })

  it('rejects a short or missing secret', () => {
    expect(() => validateRuntimeConfig({ ...valid, secret: 'short' })).toThrow(/at least 32/)
    expect(() => validateRuntimeConfig({ ...valid, secret: '' })).toThrow()
  })

  it('rejects a missing or relative base URL', () => {
    expect(() => validateRuntimeConfig({ ...valid, baseUrl: '' })).toThrow(/absolute URL/)
    expect(() => validateRuntimeConfig({ ...valid, baseUrl: '/app' })).toThrow(/absolute URL/)
  })

  it('requires https in production except for loopback', () => {
    expect(() => validateRuntimeConfig({ ...valid, baseUrl: 'http://example.com' })).toThrow(/https/)
    expect(validateRuntimeConfig({ ...valid, baseUrl: 'http://127.0.0.1:3000' }).origin).toBe('http://127.0.0.1:3000')
    expect(validateRuntimeConfig({ ...valid, baseUrl: 'http://example.com', production: false }).origin).toBe('http://example.com')
  })
})

describe('compromised-password check (HIBP k-anonymity)', () => {
  const password = 'password123'
  const digest = createHash('sha1').update(password).digest('hex').toUpperCase()

  it('sends only the 5-character prefix and requests padding', async () => {
    const fetchMock = vi.fn(async () => new Response(`${digest.slice(5)}:42\r\nABCDEF:0`))
    expect(await createHibpCheck(fetchMock as unknown as typeof fetch)(password)).toBe(true)
    const [requestUrl, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(requestUrl).toBe(`https://api.pwnedpasswords.com/range/${digest.slice(0, 5)}`)
    expect(requestUrl).not.toContain(digest.slice(5))
    expect((init.headers as Record<string, string>)['Add-Padding']).toBe('true')
  })

  it('ignores padding entries with a zero count', async () => {
    const fetchMock = vi.fn(async () => new Response(`${digest.slice(5)}:0`))
    expect(await createHibpCheck(fetchMock as unknown as typeof fetch)(password)).toBe(false)
  })

  it('fails open, with a warning, when the service is unavailable', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const fetchMock = vi.fn(async () => { throw new Error('network down') })
    expect(await createHibpCheck(fetchMock as unknown as typeof fetch)(password)).toBe(false)
    expect(warn).toHaveBeenCalledOnce()
    warn.mockRestore()
  })
})

describe('engine security configuration', () => {
  const options = buildEngineOptions({
    pool: { query: vi.fn(), connect: vi.fn(), end: vi.fn() },
    schema: 'authentication',
    secret: 'x'.repeat(40),
    baseUrl: 'https://example.com',
    policy: resolveAuthenticationPolicy(),
  })

  it('disables telemetry and client IP tracking', () => {
    expect(options.telemetry?.enabled).toBe(false)
    expect(options.advanced?.ipAddress?.disableIpTracking).toBe(true)
  })

  it('stores verification tokens hashed and never caches sessions in cookies', () => {
    expect(options.verification?.storeIdentifier).toBe('hashed')
    expect(options.session?.cookieCache?.enabled).toBe(false)
  })

  it('uses secure, HttpOnly, SameSite=Lax cookies over https', () => {
    expect(options.advanced?.useSecureCookies).toBe(true)
    expect(options.advanced?.defaultCookieAttributes).toMatchObject({ httpOnly: true, sameSite: 'lax' })
  })

  it('applies the policy: verification, lengths, idle timeout, reset revocation', () => {
    expect(options.emailAndPassword).toMatchObject({
      requireEmailVerification: true,
      autoSignIn: false,
      minPasswordLength: 15,
      maxPasswordLength: 128,
      revokeSessionsOnPasswordReset: true,
    })
    expect(options.session?.expiresIn).toBe(3_600)
    expect(options.session?.freshAge).toBe(900)
  })

  it('keeps every engine table in the capability schema', () => {
    expect((options.database as { schemaName?: string }).schemaName).toBe('authentication')
  })
})
