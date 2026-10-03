import { describe, expect, it } from 'vitest'
import { DEFAULT_AUTHENTICATION_POLICY, resolveAuthenticationPolicy } from '../contracts'

describe('Authentication policy', () => {
  it('defaults to secure values', () => {
    const policy = resolveAuthenticationPolicy()
    expect(policy).toEqual(DEFAULT_AUTHENTICATION_POLICY)
    expect(policy.password.minLength).toBe(15)
    expect(policy.password.maxLength).toBeGreaterThanOrEqual(64)
    expect(policy.password.compromisedCheck).toBe('hibp-range')
    expect(policy.mfa).toBe('required')
    expect(policy.emailVerification).toBe('required')
    expect(policy.session).toEqual({ idleTimeoutSeconds: 3_600, absoluteLifetimeSeconds: 86_400 })
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
    ['re-authentication window over an hour', { reauthentication: { maxAgeSeconds: 7_200 } }],
    ['idle timeout longer than absolute lifetime', { session: { idleTimeoutSeconds: 90_000 } }],
  ])('rejects %s', (_label, input) => {
    expect(() => resolveAuthenticationPolicy(input as never)).toThrow()
  })

  it('rejects unknown policy keys rather than ignoring them', () => {
    expect(() => resolveAuthenticationPolicy({ password: { minLenght: 20 } } as never)).toThrow()
  })
})
