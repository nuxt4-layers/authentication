import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import * as contracts from '../contracts'
import * as presentation from '../presentation'

const root = resolve(import.meta.dirname, '..')

function sourceFiles(dir: string): string[] {
  return readdirSync(resolve(root, dir), { recursive: true, encoding: 'utf8' })
    .filter(file => file.endsWith('.ts'))
    .map(file => resolve(root, dir, file))
}

describe('Authentication public contract', () => {
  it('exports the documented runtime values', () => {
    expect(Object.keys(contracts).sort()).toEqual([
      'AUTHENTICATION_ERROR_CODES',
      'AUTHENTICATION_ERROR_STATUS',
      'AUTHENTICATION_EVENT_TYPES',
      'AUTHENTICATION_MESSAGE_KINDS',
      'AUTHENTICATION_RECOVERY_METHODS',
      'AUTHENTICATION_STANDINGS',
      'AuthenticationCompositionError',
      'DEFAULT_AUTHENTICATION_POLICY',
      'isAuthenticationErrorCode',
      'publicAuthenticationPolicy',
      'resolveAuthenticationPolicy',
      'safeRedirectPath',
    ])
  })

  it('keeps presentation out of the contract', () => {
    expect(Object.keys(presentation).sort()).toEqual([
      'AUTHENTICATION_MESSAGES_EN_GB',
      'DELIBERATE_PAIRINGS',
      'authenticationClasses',
      'formatMessage',
      'resolveMessage',
    ])
    for (const name of Object.keys(presentation)) expect(contracts, name).not.toHaveProperty(name)
  })

  it('imports nothing but zod and its own shared modules', () => {
    for (const file of [...sourceFiles('contracts'), ...sourceFiles('shared')]) {
      const specifiers = [...readFileSync(file, 'utf8').matchAll(/from '([^']+)'/g)].map(m => m[1])
      for (const specifier of specifiers) {
        expect(specifier, `${file} imports ${specifier}`).toMatch(/^(zod|\.\.?\/.*)$/)
      }
    }
  })

  it('does not leak engine, driver or vendor SDK names into the contract', () => {
    const forbidden = /better-auth|better_auth|kysely|drizzle|supabase|from 'pg'/i
    for (const file of [...sourceFiles('contracts'), ...sourceFiles('shared')]) {
      expect(readFileSync(file, 'utf8'), file).not.toMatch(forbidden)
    }
  })

  it('maps every error code to an HTTP status', () => {
    for (const code of contracts.AUTHENTICATION_ERROR_CODES) {
      expect(contracts.AUTHENTICATION_ERROR_STATUS[code]).toBeGreaterThanOrEqual(400)
    }
    expect(Object.keys(contracts.AUTHENTICATION_ERROR_STATUS).sort())
      .toEqual([...contracts.AUTHENTICATION_ERROR_CODES].sort())
  })

  it('recognises only documented error codes', () => {
    expect(contracts.isAuthenticationErrorCode('invalid-credentials')).toBe(true)
    expect(contracts.isAuthenticationErrorCode('user-not-found')).toBe(false)
    expect(contracts.isAuthenticationErrorCode(401)).toBe(false)
  })

  it('has no error code that would reveal whether an account exists', () => {
    for (const code of contracts.AUTHENTICATION_ERROR_CODES) {
      expect(code).not.toMatch(/not-found|unknown|exists|disabled|suspended/)
    }
  })

  it('namespaces every event type', () => {
    for (const type of contracts.AUTHENTICATION_EVENT_TYPES) {
      expect(type).toMatch(/^authentication\.[a-z-]+$/)
    }
  })
})

describe('Authentication message catalogue', () => {
  it('has an en-GB message for every error code', () => {
    for (const code of contracts.AUTHENTICATION_ERROR_CODES) {
      expect(presentation.AUTHENTICATION_MESSAGES_EN_GB, code).toHaveProperty(`authentication.error.${code}`)
    }
  })

  it('has a message for every federation outcome', () => {
    for (const outcome of ['cancelled', 'link-required', 'link-failed', 'failed']) {
      expect(presentation.AUTHENTICATION_MESSAGES_EN_GB).toHaveProperty(`authentication.federation.${outcome}`)
    }
  })

  it('prefers host overrides for the active locale, then en-GB, then the key', () => {
    const overrides = { 'cy-GB': { 'authentication.signIn.title': 'Mewngofnodi' } }
    expect(presentation.resolveMessage('authentication.signIn.title', 'cy-GB', overrides)).toBe('Mewngofnodi')
    expect(presentation.resolveMessage('authentication.signUp.title', 'cy-GB', overrides)).toBe('Create an account')
    expect(presentation.resolveMessage('authentication.unknown.key', 'en-GB', undefined)).toBe('authentication.unknown.key')
  })

  it('fills placeholders and leaves unknown ones visible', () => {
    expect(presentation.formatMessage('At least {min} characters', { min: 15 })).toBe('At least 15 characters')
    expect(presentation.formatMessage('Hello {name}')).toBe('Hello {name}')
  })

  it('uses only placeholders that the components supply', () => {
    const allowed = new Set(['min', 'email', 'provider', 'count', 'name', 'time', 'device'])
    for (const [key, template] of Object.entries(presentation.AUTHENTICATION_MESSAGES_EN_GB)) {
      for (const [, name] of template.matchAll(/\{(\w+)\}/g)) expect(allowed, `${key} uses {${name}}`).toContain(name)
    }
  })
})
