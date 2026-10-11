import { describe, expect, it } from 'vitest'
import { AUTHENTICATION_RETENTION_BOUNDS, AUTHENTICATION_SERVICE_CREDENTIAL_BOUNDS, DEFAULT_AUTHENTICATION_POLICY, resolveAuthenticationPolicy } from '../contracts'

describe('Authentication policy', () => {
  it('defaults to secure values', () => {
    const policy = resolveAuthenticationPolicy()
    expect(policy).toEqual(DEFAULT_AUTHENTICATION_POLICY)
    expect(policy.password.minLength).toBe(15)
    expect(policy.password.maxLength).toBeGreaterThanOrEqual(64)
    expect(policy.password.compromisedCheck).toBe('hibp-range')
    expect(policy.mfa).toBe('required')
    expect(policy.emailVerification).toBe('required')
    expect(policy.rememberedDevice.days).toBe(0)
    expect(policy.session).toEqual({ idleTimeoutSeconds: 3_600, absoluteLifetimeSeconds: 86_400 })
    expect(policy.breakGlass).toEqual({ enrolmentTokenMinutes: 60 })
    expect(policy.retention).toEqual({ sessionDays: 90, recoveryDays: 365, tokenDays: 30, riskTreatment: null })
    expect(policy.serviceCredentials).toEqual({ credentialDays: 90, tokenMinutes: 15, riskTreatment: null })
  })

  it('freezes the defaults so they cannot be weakened by mutation', () => {
    expect(Object.isFrozen(DEFAULT_AUTHENTICATION_POLICY)).toBe(true)
    expect(Object.isFrozen(DEFAULT_AUTHENTICATION_POLICY.password)).toBe(true)
  })

  it('merges partial overrides onto the defaults', () => {
    const policy = resolveAuthenticationPolicy({ password: { minLength: 20 }, mfa: 'optional' })
    expect(policy.password).toEqual({ ...DEFAULT_AUTHENTICATION_POLICY.password, minLength: 20 })
    expect(policy.mfa).toBe('optional')
    expect(policy.signInThrottle).toEqual(DEFAULT_AUTHENTICATION_POLICY.signInThrottle)
  })

  it.each([
    ['password shorter than 8', { password: { minLength: 7 } }],
    ['maximum length below 64', { password: { maxLength: 32 } }],
    ['non-integer length', { password: { minLength: 12.5 } }],
    ['throttle allowing too few attempts', { signInThrottle: { maxFailedAttempts: 1 } }],
    ['per-client limit too low for shared addresses', { signInThrottle: { maxFailedAttemptsPerClient: 5 } }],
    ['re-authentication window over an hour', { reauthentication: { maxAgeSeconds: 7_200 } }],
    ['idle timeout longer than absolute lifetime', { session: { idleTimeoutSeconds: 90_000 } }],
    ['remembered devices beyond 30 days', { rememberedDevice: { days: 31 } }],
    ['break-glass enrolment tokens shorter than 5 minutes', { breakGlass: { enrolmentTokenMinutes: 4 } }],
    ['break-glass enrolment tokens longer than a day', { breakGlass: { enrolmentTokenMinutes: 1_441 } }],
    ['sessions kept under 30 days, even with a risk treatment', { retention: { sessionDays: 29, riskTreatment: 'RT-1' } }],
    ['recovery records kept over 2 years', { retention: { recoveryDays: 731 } }],
    ['tokens kept over a year', { retention: { tokenDays: 366 } }],
    ['a shorter period without a risk treatment', { retention: { recoveryDays: 30 } }],
    ['an empty risk treatment', { retention: { tokenDays: 1, riskTreatment: '' } }],
    ['service credentials valid over a year', { serviceCredentials: { credentialDays: 366, riskTreatment: 'RT-1' } }],
    ['service credentials valid under a day', { serviceCredentials: { credentialDays: 0 } }],
    ['service tokens valid over an hour', { serviceCredentials: { tokenMinutes: 61, riskTreatment: 'RT-1' } }],
    ['service tokens valid under 5 minutes', { serviceCredentials: { tokenMinutes: 4 } }],
    ['longer service credentials without a risk treatment', { serviceCredentials: { credentialDays: 180 } }],
    ['longer service tokens without a risk treatment', { serviceCredentials: { tokenMinutes: 30 } }],
  ])('rejects %s', (_label, input) => {
    expect(() => resolveAuthenticationPolicy(input as never)).toThrow()
  })

  it('keeps every retention period within the shared bounds, and outlasts Identity\'s longest recovery hold', () => {
    for (const bounds of Object.values(AUTHENTICATION_RETENTION_BOUNDS)) {
      expect(bounds.min).toBeLessThanOrEqual(bounds.default)
      expect(bounds.default).toBeLessThanOrEqual(bounds.max)
      expect(bounds.max).toBeLessThanOrEqual(7 * 365)
    }
    expect(AUTHENTICATION_RETENTION_BOUNDS.recoveryDays.min).toBeGreaterThan(14)
  })

  it('accepts a shorter retention period only with a risk treatment, and a longer one freely', () => {
    expect(resolveAuthenticationPolicy({ retention: { sessionDays: 365, recoveryDays: 730 } }).retention)
      .toEqual({ sessionDays: 365, recoveryDays: 730, tokenDays: 30, riskTreatment: null })
    expect(resolveAuthenticationPolicy({ retention: { tokenDays: 1, riskTreatment: 'RT-7' } }).retention)
      .toMatchObject({ tokenDays: 1, riskTreatment: 'RT-7' })
  })

  it('accepts a longer service credential or token only with a risk treatment, and a shorter one freely', () => {
    expect(resolveAuthenticationPolicy({ serviceCredentials: { credentialDays: 30, tokenMinutes: 5 } }).serviceCredentials)
      .toEqual({ credentialDays: 30, tokenMinutes: 5, riskTreatment: null })
    expect(resolveAuthenticationPolicy({ serviceCredentials: { credentialDays: 365, tokenMinutes: 60, riskTreatment: 'RT-9' } }).serviceCredentials)
      .toEqual({ credentialDays: 365, tokenMinutes: 60, riskTreatment: 'RT-9' })
    for (const bounds of Object.values(AUTHENTICATION_SERVICE_CREDENTIAL_BOUNDS)) {
      expect(bounds.min).toBeLessThanOrEqual(bounds.default)
      expect(bounds.default).toBeLessThanOrEqual(bounds.max)
    }
  })

  it('rejects unknown policy keys rather than ignoring them', () => {
    expect(() => resolveAuthenticationPolicy({ password: { minLenght: 20 } } as never)).toThrow()
  })
})
