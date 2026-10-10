import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AuthenticationEvent } from '../contracts'
import { AuthenticationCompositionError, DEFAULT_AUTHENTICATION_POLICY } from '../contracts'
import { currentTime } from '../server/internal/clock'
import {
  clearAuthenticationComposition,
  emitAuthenticationEvent,
  provideAuthenticationClock,
  provideAuthenticationDatabase,
  provideAuthenticationEventSink,
  provideAuthenticationLegalHolds,
  provideAuthenticationMailer,
  provideAuthenticationPolicy,
  useAuthenticationClock,
  useAuthenticationDatabase,
  useAuthenticationLegalHolds,
  useAuthenticationMailer,
  useAuthenticationPolicy,
} from '../server/utils/authentication-composition'

const pool = { query: vi.fn(), connect: vi.fn(), end: vi.fn() }

const event: AuthenticationEvent = {
  type: 'authentication.signed-in',
  occurredAt: '2026-10-03T12:00:00.000Z',
  principalId: 'principal-1',
  sessionId: 'session-1',
  method: 'password',
  reason: null,
  client: null,
}

afterEach(() => {
  clearAuthenticationComposition()
  vi.restoreAllMocks()
})

describe('Authentication composition ports', () => {
  it('fails closed when the database port is absent', () => {
    expect(() => useAuthenticationDatabase()).toThrow(AuthenticationCompositionError)
    expect(() => useAuthenticationDatabase()).toThrow(/AuthenticationDatabase/)
  })

  it('fails closed when the mailer port is absent', () => {
    expect(() => useAuthenticationMailer()).toThrow(AuthenticationCompositionError)
  })

  it('supplies the database with the default capability-owned schema', () => {
    provideAuthenticationDatabase({ dialect: 'postgres', pool })
    expect(useAuthenticationDatabase()).toEqual({ dialect: 'postgres', pool, schema: 'authentication' })
  })

  it.each([
    ['a non-postgres dialect', { dialect: 'mysql', pool }],
    ['a pool without query()', { dialect: 'postgres', pool: {} }],
    ['an unsafe schema name', { dialect: 'postgres', pool, schema: 'auth; drop schema public' }],
    ['an upper-case schema name', { dialect: 'postgres', pool, schema: 'Authentication' }],
  ])('rejects %s', (_label, input) => {
    expect(() => provideAuthenticationDatabase(input as never)).toThrow(TypeError)
    expect(() => useAuthenticationDatabase()).toThrow(AuthenticationCompositionError)
  })

  it('rejects a mailer or event sink without the required function', () => {
    expect(() => provideAuthenticationMailer({} as never)).toThrow(TypeError)
    expect(() => provideAuthenticationEventSink({} as never)).toThrow(TypeError)
  })

  it('uses the secure default policy when the host supplies none', () => {
    expect(useAuthenticationPolicy()).toEqual(DEFAULT_AUTHENTICATION_POLICY)
  })

  it('validates host policy when it is supplied, not when it is first used', () => {
    expect(() => provideAuthenticationPolicy({ password: { minLength: 4 } })).toThrow()
    provideAuthenticationPolicy({ password: { minLength: 20 } })
    expect(useAuthenticationPolicy().password.minLength).toBe(20)
  })

  it('treats a missing event sink as a no-op', async () => {
    await expect(emitAuthenticationEvent(event)).resolves.toBeUndefined()
  })

  it('delivers events to the supplied sink', async () => {
    const emit = vi.fn()
    provideAuthenticationEventSink({ emit })
    await emitAuthenticationEvent(event)
    expect(emit).toHaveBeenCalledWith(event)
  })

  it('never lets a failing event sink change the operation outcome', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    provideAuthenticationEventSink({ emit: () => Promise.reject(new Error('sink down')) })
    await expect(emitAuthenticationEvent(event)).resolves.toBeUndefined()
    expect(error).toHaveBeenCalledOnce()
    expect(String(error.mock.calls[0])).toContain('authentication.signed-in')
  })

  it('has no legal-hold port unless the host supplies one, and rejects one without covers()', () => {
    expect(useAuthenticationLegalHolds()).toBeNull()
    expect(() => provideAuthenticationLegalHolds({} as never)).toThrow(TypeError)
    const holds = { covers: async () => false }
    provideAuthenticationLegalHolds(holds)
    expect(useAuthenticationLegalHolds()).toBe(holds)
  })

  it('uses the system clock when the host supplies none', () => {
    const before = Date.now()
    const now = currentTime().getTime()
    expect(now).toBeGreaterThanOrEqual(before)
    expect(now).toBeLessThanOrEqual(Date.now())
    expect(useAuthenticationClock().now()).toBeInstanceOf(Date)
  })

  it('takes every time from a supplied clock', () => {
    provideAuthenticationClock({ now: () => new Date('2031-01-02T03:04:05.000Z') })
    expect(currentTime().toISOString()).toBe('2031-01-02T03:04:05.000Z')
  })

  it('rejects a clock without now()', () => {
    expect(() => provideAuthenticationClock({} as never)).toThrow(TypeError)
    expect(() => provideAuthenticationClock(null as never)).toThrow(TypeError)
  })

  it.each([
    ['throws', () => { throw new Error('clock service down') }],
    ['answers an invalid date', () => new Date('not a date')],
    ['answers a timestamp instead of a Date', () => Date.now()],
    ['answers a string', () => '2031-01-02T03:04:05.000Z'],
    ['answers nothing', () => undefined],
  ])('fails closed as unavailable when the clock %s, never falling back', (_label, now) => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    provideAuthenticationClock({ now: now as never })
    let failure: unknown
    try {
      currentTime()
    }
    catch (error) {
      failure = error
    }
    expect(failure).toMatchObject({ statusCode: 503, data: { code: 'unavailable' } })
  })

  it('hands out a copy, so nothing can move the host\'s clock', () => {
    const fixed = new Date('2031-01-02T03:04:05.000Z')
    provideAuthenticationClock({ now: () => fixed })
    currentTime().setFullYear(1999)
    expect(fixed.toISOString()).toBe('2031-01-02T03:04:05.000Z')
  })
})
