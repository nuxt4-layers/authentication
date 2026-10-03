import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AuthenticationEvent } from '../contracts'
import { AuthenticationCompositionError, DEFAULT_AUTHENTICATION_POLICY } from '../contracts'
import {
  clearAuthenticationComposition,
  emitAuthenticationEvent,
  provideAuthenticationDatabase,
  provideAuthenticationEventSink,
  provideAuthenticationMailer,
  provideAuthenticationPolicy,
  useAuthenticationDatabase,
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
})
