import { fileURLToPath } from 'node:url'
import pg from 'pg'
import { setup, url } from '@nuxt/test-utils/e2e'
import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import type { AuthenticatedPrincipal, AuthenticationEvent, AuthenticationMessage } from '../../contracts'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from '../support/database'

/**
 * Black-box tests of the composed layer: the playground is built and started as
 * a real Nitro server over a disposable PostgreSQL database, and exercised only
 * through HTTP, exactly as a host application's browser would.
 */

requireDatabaseInCi()

const PORT = 3417
const ORIGIN = `http://127.0.0.1:${PORT}`
const PASSWORD = 'correct horse battery staple'
const database = hasDatabase ? await createTestDatabase() : null

/** A minimal browser: one cookie jar, same-origin requests. */
class Browser {
  cookies = new Map<string, string>()

  async request(path: string, init: { method?: string, body?: unknown, origin?: string | null } = {}) {
    const headers: Record<string, string> = { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0' }
    if (init.body !== undefined) headers['content-type'] = 'application/json'
    if (init.origin !== null) headers.origin = init.origin ?? ORIGIN
    if (this.cookies.size) headers.cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ')
    const response = await fetch(url(path), {
      method: init.method ?? 'GET',
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      redirect: 'manual',
    })
    const setCookies = response.headers.getSetCookie()
    for (const cookie of setCookies) {
      const [pair] = cookie.split(';')
      const [name, ...rest] = pair!.split('=')
      const value = rest.join('=')
      if (value === '' || /max-age=0/i.test(cookie)) this.cookies.delete(name!)
      else this.cookies.set(name!, value)
    }
    const text = await response.text()
    const json = response.headers.get('content-type')?.includes('application/json')
    const data = json && text ? JSON.parse(text) : null
    return { status: response.status, data, setCookies, location: response.headers.get('location') }
  }

  post(path: string, body?: unknown, origin?: string | null) {
    return this.request(path, { method: 'POST', body: body ?? {}, origin })
  }

  async principal(): Promise<AuthenticatedPrincipal | null> {
    return (await this.request('/api/authentication/session')).data.principal
  }
}

async function recorder(): Promise<{ messages: AuthenticationMessage[], events: AuthenticationEvent[] }> {
  return (await new Browser().request('/api/__playground/recorder')).data
}

async function lastMessage(to: string, kind: AuthenticationMessage['kind']): Promise<AuthenticationMessage> {
  const { messages } = await recorder()
  const message = messages.filter(m => m.to === to && m.kind === kind).at(-1)
  expect(message, `${kind} message to ${to}`).toBeDefined()
  return message!
}

async function messageCount(to: string, kind: AuthenticationMessage['kind']): Promise<number> {
  return (await recorder()).messages.filter(m => m.to === to && m.kind === kind).length
}

let sequence = 0
const freshEmail = () => `user${++sequence}.${Date.now()}@example.com`

/** Registers, verifies and signs in a new account. */
async function verifiedAccount(browser = new Browser()) {
  const email = freshEmail()
  await browser.post('/api/authentication/sign-up', { email, password: PASSWORD })
  const verification = await lastMessage(email, 'email-verification')
  await browser.request(new URL(verification.actionUrl!).pathname + new URL(verification.actionUrl!).search)
  const signIn = await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
  expect(signIn.status).toBe(200)
  return { email, browser }
}

describe.skipIf(!hasDatabase)('authentication HTTP API (composed playground)', async () => {
  await setup({
    rootDir: fileURLToPath(new URL('../../playground', import.meta.url)),
    server: true,
    build: true,
    port: PORT,
    env: {
      AUTHENTICATION_DATABASE_URL: database?.url,
      AUTHENTICATION_PLAYGROUND_TEST: '1',
      NUXT_AUTHENTICATION_SECRET: 'integration-test-secret-that-is-long-enough-0123456789',
      NUXT_AUTHENTICATION_BASE_URL: ORIGIN,
    },
  })

  afterAll(async () => {
    await database?.drop()
  })

  describe('registration and verification', () => {
    it('accepts a sign-up and sends a verification link', async () => {
      const email = freshEmail()
      const response = await new Browser().post('/api/authentication/sign-up', { email, password: PASSWORD })
      expect(response.status).toBe(202)
      expect(response.data).toEqual({ status: 'accepted' })
      const message = await lastMessage(email, 'email-verification')
      expect(message.actionUrl).toMatch(new RegExp(`^${ORIGIN}/api/authentication/verify-email\\?token=`))
      expect(message.locale).toBe('en-GB')
    })

    it('answers a duplicate sign-up identically (no enumeration)', async () => {
      const email = freshEmail()
      const first = await new Browser().post('/api/authentication/sign-up', { email, password: PASSWORD })
      const second = await new Browser().post('/api/authentication/sign-up', { email, password: 'a different long password' })
      expect(second.status).toBe(first.status)
      expect(second.data).toEqual(first.data)
    })

    it('rejects a password below the policy minimum', async () => {
      const response = await new Browser().post('/api/authentication/sign-up', { email: freshEmail(), password: 'short-pass' })
      expect(response.status).toBe(400)
      expect(response.data.data).toEqual({ code: 'password-rejected', messageKey: 'authentication.error.password-rejected' })
    })

    it('rejects malformed input', async () => {
      const response = await new Browser().post('/api/authentication/sign-up', { email: 'not-an-email', password: PASSWORD, admin: true })
      expect(response.status).toBe(400)
      expect(response.data.data.code).toBe('validation-failed')
    })

    it('refuses sign-in until the email is verified, then accepts it', async () => {
      const email = freshEmail()
      const browser = new Browser()
      await browser.post('/api/authentication/sign-up', { email, password: PASSWORD })

      const before = await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect(before.status).toBe(403)
      expect(before.data.data.code).toBe('email-not-verified')
      expect(await messageCount(email, 'email-verification')).toBe(2)

      const link = new URL((await lastMessage(email, 'email-verification')).actionUrl!)
      const verified = await browser.request(link.pathname + link.search)
      expect(verified.status).toBe(303)
      expect(verified.location).toBe('/sign-in?verification=success')

      const after = await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect(after.status).toBe(200)
    })

    it('redirects with a failure for an invalid verification token', async () => {
      const response = await new Browser().request('/api/authentication/verify-email?token=forged')
      expect(response.status).toBe(303)
      expect(response.location).toBe('/sign-in?verification=failed')
    })
  })

  describe('sign-in', () => {
    it('issues a hardened session cookie and a password-only aal1 principal', async () => {
      const { browser } = await verifiedAccount()
      const principal = await browser.principal()
      expect(principal).toMatchObject({ assurance: { level: 'aal1', methods: ['password'], phishingResistant: false } })
      expect(principal!.principalId).toEqual(expect.any(String))
      const remaining = new Date(principal!.expiresAt).getTime() - Date.now()
      expect(remaining).toBeGreaterThan(0)
      expect(remaining).toBeLessThanOrEqual(3_600_000)
    })

    it('sets the session cookie HttpOnly and SameSite=Lax', async () => {
      const email = freshEmail()
      const browser = new Browser()
      await browser.post('/api/authentication/sign-up', { email, password: PASSWORD })
      const link = new URL((await lastMessage(email, 'email-verification')).actionUrl!)
      await browser.request(link.pathname + link.search)
      const response = await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
      const sessionCookie = response.setCookies.find(cookie => cookie.includes('session_token='))
      expect(sessionCookie).toMatch(/HttpOnly/i)
      expect(sessionCookie).toMatch(/SameSite=Lax/i)
      expect(sessionCookie).toMatch(/Path=\//i)
    })

    it('answers unknown accounts and wrong passwords identically', async () => {
      const { email } = await verifiedAccount()
      const wrong = await new Browser().post('/api/authentication/sign-in', { email, password: 'not the right password' })
      const unknown = await new Browser().post('/api/authentication/sign-in', { email: freshEmail(), password: PASSWORD })
      expect(wrong.status).toBe(401)
      expect(unknown.status).toBe(401)
      expect(unknown.data.data).toEqual(wrong.data.data)
      expect(wrong.data.data).toEqual({ code: 'invalid-credentials', messageKey: 'authentication.error.invalid-credentials' })
    })

    it('locks an account after repeated failures, even for the right password', async () => {
      const { email } = await verifiedAccount()
      const attacker = new Browser()
      for (let i = 0; i < 3; i++) await attacker.post('/api/authentication/sign-in', { email, password: `guess number ${i} guess` })

      const owner = await new Browser().post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect(owner.status).toBe(401)
      expect(owner.data.data.code).toBe('invalid-credentials')

      expect((await lastMessage(email, 'security-notification')).eventType).toBe('authentication.account-locked')
      const { events } = await recorder()
      expect(events.some(e => e.type === 'authentication.account-locked' && e.principalId)).toBe(true)
    })

    it('replaces any previous session on sign-in (session fixation)', async () => {
      const { email, browser } = await verifiedAccount()
      const first = await browser.principal()
      await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
      const second = await browser.principal()
      expect(second!.sessionId).not.toBe(first!.sessionId)
      const sessions = await browser.request('/api/authentication/sessions')
      expect(sessions.data.sessions.map((s: { sessionId: string }) => s.sessionId)).not.toContain(first!.sessionId)
    })
  })

  describe('CSRF and origin checks', () => {
    it('rejects state-changing requests from another origin', async () => {
      const response = await new Browser().post('/api/authentication/sign-in', { email: freshEmail(), password: PASSWORD }, 'https://evil.example')
      expect(response.status).toBe(403)
      expect(response.data.data.code).toBe('origin-rejected')
    })

    it('rejects state-changing requests with no origin', async () => {
      const response = await new Browser().post('/api/authentication/sign-out', {}, null)
      expect(response.status).toBe(403)
    })
  })

  describe('sessions', () => {
    it('requires authentication', async () => {
      const response = await new Browser().request('/api/authentication/sessions')
      expect(response.status).toBe(401)
      expect(response.data.data.code).toBe('unauthenticated')
    })

    it('lists sessions with coarse client descriptions only', async () => {
      const { email, browser } = await verifiedAccount()
      const other = new Browser()
      await other.post('/api/authentication/sign-in', { email, password: PASSWORD })
      const { data } = await browser.request('/api/authentication/sessions')
      expect(data.sessions).toHaveLength(2)
      expect(data.sessions.filter((s: { current: boolean }) => s.current)).toHaveLength(1)
      expect(data.sessions[0].clientDescription).toBe('Firefox on Linux')
      expect(JSON.stringify(data)).not.toMatch(/token|ipAddress|userAgent|Mozilla/)
    })

    it('revokes other sessions server-side', async () => {
      const { email, browser } = await verifiedAccount()
      const other = new Browser()
      await other.post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect(await other.principal()).not.toBeNull()
      expect((await browser.post('/api/authentication/sessions/revoke-others')).status).toBe(200)
      expect(await other.principal()).toBeNull()
      expect(await browser.principal()).not.toBeNull()
    })

    it('revokes a single session and cannot touch another principal\'s', async () => {
      const { email, browser } = await verifiedAccount()
      const other = new Browser()
      await other.post('/api/authentication/sign-in', { email, password: PASSWORD })
      const otherSession = (await other.principal())!.sessionId

      const stranger = (await verifiedAccount()).browser
      const forbidden = await stranger.request(`/api/authentication/sessions/${otherSession}`, { method: 'DELETE' })
      expect(forbidden.status).toBe(400)
      expect(await other.principal()).not.toBeNull()

      const revoked = await browser.request(`/api/authentication/sessions/${otherSession}`, { method: 'DELETE' })
      expect(revoked.status).toBe(204)
      expect(await other.principal()).toBeNull()
    })

    it('signs out server-side, so a copied cookie stops working', async () => {
      const { browser } = await verifiedAccount()
      const copy = new Browser()
      copy.cookies = new Map(browser.cookies)
      expect((await browser.post('/api/authentication/sign-out')).status).toBe(200)
      expect(await browser.principal()).toBeNull()
      expect(await copy.principal()).toBeNull()
    })

    it('ends sessions older than the absolute lifetime', async () => {
      const { browser } = await verifiedAccount()
      const sessionId = (await browser.principal())!.sessionId
      const pool = new pg.Pool({ connectionString: database!.url })
      await pool.query(`update "authentication"."session" set "createdAt" = now() - interval '25 hours' where "id" = $1`, [sessionId])
      expect(await browser.principal()).toBeNull()
      const { rows } = await pool.query(`select 1 from "authentication"."session" where "id" = $1`, [sessionId])
      expect(rows).toHaveLength(0)
      await pool.end()
    })
  })

  describe('password management', () => {
    beforeEach(() => {
      sequence += 100
    })

    it('resets a password with a single-use token and revokes every session', async () => {
      const { email, browser } = await verifiedAccount()
      const anonymous = new Browser()
      const request = await anonymous.post('/api/authentication/password/forgot', { email })
      expect(request.status).toBe(202)

      const message = await lastMessage(email, 'password-reset')
      const token = new URL(message.actionUrl!).searchParams.get('token')!
      expect(new URL(message.actionUrl!).pathname).toBe('/reset-password')

      const newPassword = 'an entirely new long passphrase'
      const reset = await anonymous.post('/api/authentication/password/reset', { token, password: newPassword })
      expect(reset.status).toBe(200)
      expect(await browser.principal()).toBeNull()

      const reuse = await anonymous.post('/api/authentication/password/reset', { token, password: 'yet another long passphrase' })
      expect(reuse.status).toBe(400)
      expect(reuse.data.data.code).toBe('invalid-or-expired-token')

      expect((await anonymous.post('/api/authentication/sign-in', { email, password: PASSWORD })).status).toBe(401)
      expect((await anonymous.post('/api/authentication/sign-in', { email, password: newPassword })).status).toBe(200)
      expect((await lastMessage(email, 'security-notification')).eventType).toBe('authentication.password-reset-completed')
    })

    it('answers reset requests for unknown addresses identically and sends nothing', async () => {
      const email = freshEmail()
      const response = await new Browser().post('/api/authentication/password/forgot', { email })
      expect(response.status).toBe(202)
      expect(response.data).toEqual({ status: 'accepted' })
      expect(await messageCount(email, 'password-reset')).toBe(0)
    })

    it('caps reset emails per address', async () => {
      const { email } = await verifiedAccount()
      for (let i = 0; i < 5; i++) {
        expect((await new Browser().post('/api/authentication/password/forgot', { email })).status).toBe(202)
      }
      expect(await messageCount(email, 'password-reset')).toBe(3)
    })

    it('changes a password only with the current one, revoking other sessions', async () => {
      const { email, browser } = await verifiedAccount()
      const other = new Browser()
      await other.post('/api/authentication/sign-in', { email, password: PASSWORD })

      const wrong = await browser.post('/api/authentication/password/change', { currentPassword: 'wrong wrong wrong wrong', newPassword: 'a brand new long passphrase' })
      expect(wrong.status).toBe(401)
      expect(wrong.data.data.code).toBe('invalid-credentials')

      const changed = await browser.post('/api/authentication/password/change', { currentPassword: PASSWORD, newPassword: 'a brand new long passphrase' })
      expect(changed.status).toBe(200)
      expect(await browser.principal()).not.toBeNull()
      expect(await other.principal()).toBeNull()
      expect((await lastMessage(email, 'security-notification')).eventType).toBe('authentication.password-changed')
    })
  })

  describe('client composable and route middleware (server-rendered)', () => {
    it('redirects anonymous visitors from a protected page to sign-in with a return path', async () => {
      const response = await new Browser().request('/protected')
      expect(response.status).toBe(302)
      expect(response.location).toBe('/sign-in?redirect=/protected')
    })

    it('renders a protected page for a signed-in principal', async () => {
      const { browser } = await verifiedAccount()
      const response = await browser.request('/protected')
      expect(response.status).toBe(200)
      const principalId = (await browser.principal())!.principalId
      const page = await fetch(url('/protected'), { headers: { cookie: [...browser.cookies].map(([n, v]) => `${n}=${v}`).join('; ') } })
      expect(await page.text()).toContain(principalId)
    })

    it('sends a signed-in visitor away from the guest-only page to a safe redirect', async () => {
      const { browser } = await verifiedAccount()
      expect((await browser.request('/sign-in?redirect=/protected')).location).toBe('/protected')
      expect((await browser.request('/sign-in?redirect=//evil.example')).location).toBe('/')
    })
  })

  describe('events', () => {
    it('emits the expected facts and never includes email addresses or secrets', async () => {
      const { events } = await recorder()
      const types = new Set(events.map(event => event.type))
      for (const type of [
        'authentication.account-registered',
        'authentication.email-verified',
        'authentication.signed-in',
        'authentication.sign-in-failed',
        'authentication.signed-out',
        'authentication.account-locked',
        'authentication.password-changed',
        'authentication.password-reset-requested',
        'authentication.password-reset-completed',
        'authentication.session-revoked',
      ] as const) {
        expect(types, type).toContain(type)
      }
      const serialized = JSON.stringify(events)
      expect(serialized).not.toMatch(/@example\.com/)
      expect(serialized).not.toContain(PASSWORD)
      expect(serialized).not.toMatch(/token/i)
    })
  })
})
