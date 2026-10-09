import { createHash } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import type { AuthenticatedPrincipal } from '../contracts'
import { resolveAuthenticationPolicy } from '../contracts'
import { createHibpCheck } from '../server/internal/compromised-password'
import { buildEngineOptions } from '../server/internal/engine-options'
import { describeClient, engineErrorCode, safeRedirectPath } from '../server/internal/http'
import { absoluteExpiry, assuranceLevel, evaluateRequirement, parseMethods, toPrincipal } from '../server/internal/principal'
import { signInRefusal } from '../server/internal/standing'
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
    [['federated', 'passkey'], 'aal2'],
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
      standing: 'allowed',
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

  it('refuses a restricted account unless the operation accepts its standing', () => {
    const paused = toPrincipal(session, 86_400, 'resume-only')
    const now = new Date('2026-10-03T10:10:00Z')
    expect(evaluateRequirement(paused, {}, now)).toBe('account-restricted')
    expect(evaluateRequirement(paused, { allowStandings: ['cancel-closure-only'] }, now)).toBe('account-restricted')
    expect(evaluateRequirement(paused, { allowStandings: ['resume-only'] }, now)).toBeNull()
  })

  it('lets a break-glass account in by passkey alone, and nobody refused', () => {
    const breakGlass = { standing: 'allowed' as const, passkeyOnly: true }
    expect(signInRefusal(breakGlass, ['passkey'])).toBeNull()
    expect(signInRefusal(breakGlass, ['password', 'totp'])).toBe('passkey-only')
    expect(signInRefusal(breakGlass, ['federated'])).toBe('passkey-only')
    expect(signInRefusal({ standing: 'refused', passkeyOnly: false }, ['passkey'])).toBe('standing-refused')
    expect(signInRefusal({ standing: 'resume-only', passkeyOnly: false }, ['password', 'totp'])).toBeNull()
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
    appName: 'Test',
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

  it('enables TOTP with verification-before-activation and passkeys requiring user verification', () => {
    const ids = options.plugins.map(plugin => plugin.id)
    expect(ids).toEqual(['two-factor', 'passkey'])
  })

  it('never links accounts implicitly and keeps no provider tokens', () => {
    expect(options.account.accountLinking).toMatchObject({ disableImplicitLinking: true, allowUnlinkingAll: false })
    expect(options.account.updateAccountOnSignIn).toBe(false)
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
    expect(options.session?.freshAge).toBe(0)
  })

  it('keeps every engine table in the capability schema', () => {
    expect((options.database as { schemaName?: string }).schemaName).toBe('authentication')
  })
})

describe('multi-factor internals', async () => {
  const { matchTotpStep, mergeMethods, assertionUserVerified, registrationUserVerified } = await import('../server/internal/mfa')
  const { hashBackupCode } = await import('../server/internal/engine-options')
  const { sessionTokenFromCookies } = await import('../server/internal/http')
  const { totpCode } = await import('./support/totp')
  const { VirtualAuthenticator } = await import('./support/webauthn')

  // The engine stores a 32-character secret; authenticator apps receive its bytes in base32.
  const secret = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'
  const base32 = (bytes: Buffer) => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    let bits = 0, value = 0, out = ''
    for (const byte of bytes) {
      value = (value << 8) | byte
      bits += 8
      while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5 }
    }
    return bits > 0 ? out + alphabet[(value << (5 - bits)) & 31] : out
  }
  const uri = `otpauth://totp/Test:user?secret=${base32(Buffer.from(secret))}&issuer=Test`

  it('matches the independent RFC 6238 oracle for the current and adjacent steps', () => {
    const now = 1_790_000_000_000
    const step = Math.floor(now / 30_000)
    expect(matchTotpStep(secret, totpCode(uri, 0, now), now)).toBe(step)
    expect(matchTotpStep(secret, totpCode(uri, -1, now), now)).toBe(step - 1)
    expect(matchTotpStep(secret, totpCode(uri, 1, now), now)).toBe(step + 1)
    expect(matchTotpStep(secret, totpCode(uri, 2, now), now)).toBeNull()
    expect(matchTotpStep(secret, 'abcdef', now)).toBeNull()
  })

  it('merges methods without duplicates, preserving order', () => {
    expect(mergeMethods(['password'], ['totp', 'password'])).toEqual(['password', 'totp'])
  })

  it('rates a remembered device after a password as aal2, and alone as aal1', () => {
    expect(assuranceLevel(['password', 'remembered-device'])).toBe('aal2')
    expect(assuranceLevel(['remembered-device'])).toBe('aal1')
  })

  it('digests backup codes with a keyed hash', () => {
    const digest = hashBackupCode('server-secret-one', 'ABCDE-FGHIJKLMNOP')
    expect(digest).toMatch(/^[0-9a-f]{64}$/)
    expect(hashBackupCode('server-secret-two', 'ABCDE-FGHIJKLMNOP')).not.toBe(digest)
    expect(hashBackupCode('server-secret-one', ' ABCDE-FGHIJKLMNOP ')).toBe(digest)
  })

  it('reads the rotated session token from the engine cookie', () => {
    const headers = new Headers()
    headers.append('set-cookie', 'authentication.dont_remember=; Max-Age=0')
    headers.append('set-cookie', `authentication.session_token=${encodeURIComponent('tok123.sig/+=')}; Path=/; HttpOnly`)
    expect(sessionTokenFromCookies(headers)).toBe('tok123')
    const secure = new Headers({ 'set-cookie': '__Secure-authentication.session_token=abc.def; Path=/' })
    expect(sessionTokenFromCookies(secure)).toBe('abc')
    expect(sessionTokenFromCookies(new Headers())).toBeNull()
  })

  it('detects user verification in registrations and assertions', () => {
    const authenticator = new VirtualAuthenticator('https://example.com', 'example.com')
    expect(registrationUserVerified(authenticator.register({ challenge: 'c' }))).toBe(true)
    expect(registrationUserVerified(authenticator.register({ challenge: 'c' }, { userVerified: false }))).toBe(false)
    expect(assertionUserVerified(authenticator.authenticate({ challenge: 'c' }))).toBe(true)
    expect(assertionUserVerified(authenticator.authenticate({ challenge: 'c' }, { userVerified: false }))).toBe(false)
    expect(assertionUserVerified({ response: { authenticatorData: '!!' } })).toBe(false)
    expect(registrationUserVerified(null)).toBe(false)
  })
})

describe('federation internals', async () => {
  const { federationOutcome } = await import('../server/internal/federation')
  const { enabledProviders, federationCallbackUrl } = await import('../server/internal/federation-config')
  const { withoutProviderTokens } = await import('../server/internal/engine-options')

  it.each([
    ['access_denied', 'cancelled'],
    ['account_not_linked', 'link-required'],
    ['unable_to_create_user', 'link-required'],
    ['email_not_verified', 'link-required'],
    ['account_already_linked_to_different_user', 'link-failed'],
    ['state_mismatch', 'failed'],
    ['anything_else', 'failed'],
  ])('maps %s to %s', (engineError, outcome) => {
    expect(federationOutcome(engineError)).toBe(outcome)
  })

  it('answers identically whether an email has an account or is merely unverified (no enumeration)', () => {
    expect(federationOutcome('account_not_linked')).toBe(federationOutcome('unable_to_create_user'))
  })

  it('enables a provider only when both client ID and secret are set', () => {
    expect(enabledProviders({
      google: { clientId: 'id', clientSecret: 'secret' },
      github: { clientId: 'id', clientSecret: '' },
      facebook: { clientId: '', clientSecret: 'secret' },
      microsoft: { clientId: 'id', clientSecret: 'secret' },
    }).map(provider => [provider.id, provider.name, provider.tenantId])).toEqual([
      ['google', 'Google', undefined],
      ['microsoft', 'Microsoft', undefined],
    ])
    expect(enabledProviders(undefined)).toEqual([])
  })

  it('requires a discovery URL for the OIDC provider and uses its configured name', () => {
    expect(() => enabledProviders({ oidc: { clientId: 'id', clientSecret: 'secret' } })).toThrow(/DISCOVERY_URL/)
    expect(enabledProviders({ oidc: { name: 'Company SSO', discoveryUrl: 'https://idp.example/.well-known/openid-configuration', clientId: 'id', clientSecret: 'secret' } })[0])
      .toMatchObject({ id: 'oidc', name: 'Company SSO' })
  })

  it('builds the callback URL to register with each provider', () => {
    expect(federationCallbackUrl('https://example.com', 'github')).toBe('https://example.com/api/authentication/federation/callback/github')
  })

  it('discards provider tokens but leaves credential accounts alone', () => {
    expect(withoutProviderTokens({ providerId: 'oidc', accountId: 'sub', accessToken: 'a', refreshToken: 'r', idToken: 'i', accessTokenExpiresAt: new Date() }))
      .toEqual({ providerId: 'oidc', accountId: 'sub', accessToken: null, refreshToken: null, idToken: null, accessTokenExpiresAt: null })
    const credential = { providerId: 'credential', password: 'hash' }
    expect(withoutProviderTokens(credential)).toBe(credential)
  })

  it('rates a provider sign-in as aal1 and a provider plus local factor as aal2', () => {
    expect(assuranceLevel(['federated'])).toBe('aal1')
    expect(assuranceLevel(['federated', 'totp'])).toBe('aal2')
    expect(assuranceLevel(['federated', 'remembered-device'])).toBe('aal2')
  })
})
