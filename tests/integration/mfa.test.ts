import { fileURLToPath } from 'node:url'
import pg from 'pg'
import { setup } from '@nuxt/test-utils/e2e'
import { afterAll, describe, expect, it } from 'vitest'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from '../support/database'
import { createHarness, PASSWORD, type HarnessBrowser } from '../support/harness'
import { msLeftInStep, totpCode } from '../support/totp'
import { VirtualAuthenticator } from '../support/webauthn'

/**
 * Black-box multi-factor tests with the secure default policy (`mfa: 'required'`).
 * TOTP codes come from an independent RFC 6238 oracle and passkeys from a
 * software authenticator, so neither shares code with the server.
 */

requireDatabaseInCi()

const PORT = 3418
const ORIGIN = `http://127.0.0.1:${PORT}`
const database = hasDatabase ? await createTestDatabase() : null
const { Browser, recorder, lastMessage, verifiedAccount } = createHarness(ORIGIN)

/** Avoids generating a code in the last seconds of a 30-second step. */
async function safeStep(): Promise<void> {
  if (msLeftInStep() < 3_000) await new Promise(resolve => setTimeout(resolve, msLeftInStep() + 200))
}

async function query(text: string, values: unknown[] = []) {
  const pool = new pg.Pool({ connectionString: database!.url })
  try {
    return await pool.query(text, values)
  }
  finally {
    await pool.end()
  }
}

/** An account with TOTP enrolled; the browser holds an aal2 session. */
async function totpAccount() {
  const { email, browser } = await verifiedAccount()
  const enrolment = await browser.post('/api/authentication/mfa/totp/enrol', { password: PASSWORD })
  expect(enrolment.status).toBe(200)
  await safeStep()
  const confirm = await browser.post('/api/authentication/mfa/totp/confirm', { code: totpCode(enrolment.data.totpUri) })
  expect(confirm.status).toBe(200)
  return { email, browser, totpUri: enrolment.data.totpUri as string, backupCodes: enrolment.data.backupCodes as string[] }
}

async function registerPasskey(browser: HarnessBrowser, authenticator: VirtualAuthenticator, userVerified = true) {
  const options = await browser.post('/api/authentication/passkeys/registration-options')
  expect(options.status).toBe(200)
  return browser.post('/api/authentication/passkeys/registration', { response: authenticator.register(options.data, { userVerified }), name: 'Test key' })
}

async function passkeySignIn(browser: HarnessBrowser, authenticator: VirtualAuthenticator, options: { userVerified?: boolean, forge?: boolean } = {}) {
  const challenge = await browser.post('/api/authentication/passkeys/authentication-options')
  expect(challenge.status).toBe(200)
  return browser.post('/api/authentication/passkeys/authentication', { response: authenticator.authenticate(challenge.data, options) })
}

describe.skipIf(!hasDatabase)('multi-factor authentication (mfa required)', async () => {
  await setup({
    rootDir: fileURLToPath(new URL('../../playground', import.meta.url)),
    server: true,
    build: true,
    port: PORT,
    env: {
      AUTHENTICATION_DATABASE_URL: database?.url,
      AUTHENTICATION_PLAYGROUND_TEST: '1',
      AUTHENTICATION_PLAYGROUND_MFA: 'required',
      NUXT_AUTHENTICATION_SECRET: 'integration-test-secret-that-is-long-enough-0123456789',
      NUXT_AUTHENTICATION_BASE_URL: ORIGIN,
    },
  })

  afterAll(async () => {
    await database?.drop()
  })

  describe('enrol-only sessions', () => {
    it('signs in a password-only account at aal1 and reports aal2 as required', async () => {
      const { browser } = await verifiedAccount()
      const session = await browser.request('/api/authentication/session')
      expect(session.data.principal.assurance).toEqual({ level: 'aal1', methods: ['password'], phishingResistant: false })
      expect(session.data.requiredLevel).toBe('aal2')
    })

    it('refuses everything but enrolment until a second factor is added', async () => {
      const { browser } = await verifiedAccount()
      const sessions = await browser.request('/api/authentication/sessions')
      expect(sessions.status).toBe(403)
      expect(sessions.data.data.code).toBe('insufficient-assurance')
      const change = await browser.post('/api/authentication/password/change', { currentPassword: PASSWORD, newPassword: 'a brand new long passphrase' })
      expect(change.data.data.code).toBe('insufficient-assurance')
      expect((await browser.request('/api/authentication/mfa')).status).toBe(200)
    })

    it('sends enrol-only sessions from protected pages to the MFA route', async () => {
      const { browser } = await verifiedAccount()
      const page = await browser.request('/protected')
      expect(page.status).toBe(302)
      expect(page.location).toBe('/mfa?redirect=/protected')
      expect((await browser.request('/mfa')).status).toBe(200)
    })
  })

  describe('TOTP', () => {
    it('enrols with the password, then a first code raises the session to aal2', async () => {
      const { email, browser } = await verifiedAccount()
      expect((await browser.post('/api/authentication/mfa/totp/enrol', { password: 'not my password at all' })).data.data.code).toBe('invalid-credentials')

      const enrolment = await browser.post('/api/authentication/mfa/totp/enrol', { password: PASSWORD })
      expect(enrolment.data.totpUri).toMatch(/^otpauth:\/\/totp\//)
      expect(enrolment.data.backupCodes).toHaveLength(10)
      for (const code of enrolment.data.backupCodes) expect(code).toMatch(/^[A-Za-z0-9]{5}-[A-Za-z0-9]{11}$/)

      expect((await browser.post('/api/authentication/mfa/totp/confirm', { code: '000000' })).data.data.code).toBe('invalid-mfa-code')
      await safeStep()
      expect((await browser.post('/api/authentication/mfa/totp/confirm', { code: totpCode(enrolment.data.totpUri) })).status).toBe(200)

      expect((await browser.principal())!.assurance).toEqual({ level: 'aal2', methods: ['password', 'totp'], phishingResistant: false })
      expect((await browser.request('/api/authentication/sessions')).status).toBe(200)
      expect((await lastMessage(email, 'security-notification')).eventType).toBe('authentication.mfa-enrolled')
    })

    it('stores the TOTP secret encrypted and backup codes only as keyed digests', async () => {
      const { browser, totpUri, backupCodes } = await totpAccount()
      const principalId = (await browser.principal())!.principalId
      const { rows } = await query(`select "secret", "backupCodes" from "authentication"."twoFactor" where "userId" = $1`, [principalId])
      const secret = new URL(totpUri).searchParams.get('secret')!
      expect(rows[0].secret).not.toContain(secret)
      const stored = JSON.parse(rows[0].backupCodes) as string[]
      expect(stored).toHaveLength(10)
      for (const digest of stored) expect(digest).toMatch(/^[0-9a-f]{64}$/)
      for (const code of backupCodes) expect(rows[0].backupCodes).not.toContain(code)
    })

    it('issues no session after the password alone, then signs in with a code', async () => {
      const { email, totpUri } = await totpAccount()
      const browser = new Browser()
      const first = await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect(first.data).toEqual({ status: 'second-factor-required', methods: ['totp', 'backup-code'] })
      expect(await browser.principal()).toBeNull()

      await safeStep()
      const second = await browser.post('/api/authentication/mfa/verify', { method: 'totp', code: totpCode(totpUri, 1) })
      expect(second.status).toBe(200)
      expect((await browser.principal())!.assurance).toEqual({ level: 'aal2', methods: ['password', 'totp'], phishingResistant: false })
    })

    it('rejects a replayed TOTP code', async () => {
      const { email, totpUri } = await totpAccount()
      await safeStep()
      const code = totpCode(totpUri, 1)

      const first = new Browser()
      await first.post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect((await first.post('/api/authentication/mfa/verify', { method: 'totp', code })).status).toBe(200)

      const replay = new Browser()
      await replay.post('/api/authentication/sign-in', { email, password: PASSWORD })
      const result = await replay.post('/api/authentication/mfa/verify', { method: 'totp', code })
      expect(result.status).toBe(401)
      expect(result.data.data.code).toBe('invalid-mfa-code')
      expect(await replay.principal()).toBeNull()
    })

    it('rejects a second factor with no pending password sign-in', async () => {
      const result = await new Browser().post('/api/authentication/mfa/verify', { method: 'totp', code: '123456' })
      expect(result.status).toBe(401)
      expect(result.data.data.code).toBe('unauthenticated')
    })

    it('locks the second factor after repeated wrong codes', async () => {
      const { email, totpUri } = await totpAccount()
      const browser = new Browser()
      await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
      for (let i = 0; i < 3; i++) await browser.post('/api/authentication/mfa/verify', { method: 'totp', code: '000000' })
      await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
      await safeStep()
      const locked = await browser.post('/api/authentication/mfa/verify', { method: 'totp', code: totpCode(totpUri, 1) })
      expect(locked.status).toBe(429)
      expect(locked.data.data.code).toBe('rate-limited')
    })

    it('never sets a remembered-device cookie while the policy disables it', async () => {
      const { email, totpUri } = await totpAccount()
      const browser = new Browser()
      await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
      await safeStep()
      const result = await browser.post('/api/authentication/mfa/verify', { method: 'totp', code: totpCode(totpUri, 1), rememberDevice: true })
      expect(result.status).toBe(200)
      expect(result.setCookies.some(cookie => /trust_device=[^;]/.test(cookie))).toBe(false)
    })

    it('disables TOTP only with a recent authentication and the password', async () => {
      const { email, browser } = await totpAccount()
      const sessionId = (await browser.principal())!.sessionId
      await query(`update "authentication"."session" set "authenticatedAt" = now() - interval '20 minutes' where "id" = $1`, [sessionId])
      expect((await browser.post('/api/authentication/mfa/totp/disable', { password: PASSWORD })).data.data.code).toBe('reauthentication-required')

      expect((await browser.post('/api/authentication/reauthenticate', { method: 'password', password: PASSWORD })).status).toBe(200)
      expect((await browser.post('/api/authentication/mfa/totp/disable', { password: PASSWORD })).status).toBe(200)
      expect((await lastMessage(email, 'security-notification')).eventType).toBe('authentication.mfa-removed')

      const again = await new Browser().post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect(again.data).toEqual({ status: 'signed-in' })
    })
  })

  describe('backup codes', () => {
    it('signs in once per code and reports the remaining count', async () => {
      const { email, backupCodes } = await totpAccount()
      const browser = new Browser()
      await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect((await browser.post('/api/authentication/mfa/verify', { method: 'backup-code', code: backupCodes[0] })).status).toBe(200)
      expect((await browser.principal())!.assurance.methods).toEqual(['password', 'backup-code'])
      expect((await browser.request('/api/authentication/mfa')).data.backupCodes.remaining).toBe(9)
      expect((await lastMessage(email, 'security-notification')).eventType).toBe('authentication.backup-code-used')

      const reuse = new Browser()
      await reuse.post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect((await reuse.post('/api/authentication/mfa/verify', { method: 'backup-code', code: backupCodes[0] })).data.data.code).toBe('invalid-mfa-code')
    })

    it('regenerates codes, invalidating the old ones', async () => {
      const { email, browser, backupCodes } = await totpAccount()
      const regenerated = await browser.post('/api/authentication/mfa/backup-codes', { password: PASSWORD })
      expect(regenerated.data.backupCodes).toHaveLength(10)
      const old = new Browser()
      await old.post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect((await old.post('/api/authentication/mfa/verify', { method: 'backup-code', code: backupCodes[1] })).data.data.code).toBe('invalid-mfa-code')
      const fresh = new Browser()
      await fresh.post('/api/authentication/sign-in', { email, password: PASSWORD })
      expect((await fresh.post('/api/authentication/mfa/verify', { method: 'backup-code', code: regenerated.data.backupCodes[0] })).status).toBe(200)
    })
  })

  describe('step-up re-authentication', () => {
    it('raises an enrol-only password session to aal2 with a TOTP code', async () => {
      const { email, totpUri } = await totpAccount()
      // Simulate a password-only session for an enrolled user (e.g. created before enrolment).
      const browser = new Browser()
      await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
      await safeStep()
      await browser.post('/api/authentication/mfa/verify', { method: 'totp', code: totpCode(totpUri, 1) })
      const sessionId = (await browser.principal())!.sessionId
      await query(`update "authentication"."session" set "authenticationMethods" = 'password' where "id" = $1`, [sessionId])
      expect((await browser.principal())!.assurance.level).toBe('aal1')

      expect((await browser.post('/api/authentication/reauthenticate', { method: 'totp', code: '000000' })).data.data.code).toBe('invalid-mfa-code')
      await new Promise(resolve => setTimeout(resolve, msLeftInStep() + 200))
      expect((await browser.post('/api/authentication/reauthenticate', { method: 'totp', code: totpCode(totpUri, 1) })).status).toBe(200)
      expect((await browser.principal())!.assurance).toEqual({ level: 'aal2', methods: ['password', 'totp'], phishingResistant: false })
    }, 60_000)
  })

  describe('passkeys', () => {
    it('registers a user-verifying passkey and signs in with it alone at aal2', async () => {
      const { email, browser } = await totpAccount()
      const authenticator = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
      expect((await registerPasskey(browser, authenticator)).status).toBe(200)
      expect((await lastMessage(email, 'security-notification')).eventType).toBe('authentication.mfa-enrolled')
      expect((await browser.request('/api/authentication/mfa')).data.passkeys).toEqual([
        expect.objectContaining({ name: 'Test key', createdAt: expect.any(String) }),
      ])

      const elsewhere = new Browser()
      expect((await passkeySignIn(elsewhere, authenticator)).status).toBe(200)
      expect((await elsewhere.principal())!.assurance).toEqual({ level: 'aal2', methods: ['passkey'], phishingResistant: true })
    })

    it('refuses authenticators that do not verify the user', async () => {
      const { browser } = await totpAccount()
      const authenticator = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
      const registration = await registerPasskey(browser, authenticator, false)
      expect(registration.status).toBe(403)
      expect(registration.data.data.code).toBe('insufficient-assurance')

      expect((await registerPasskey(browser, authenticator)).status).toBe(200)
      const presenceOnly = await passkeySignIn(new Browser(), authenticator, { userVerified: false })
      expect(presenceOnly.status).toBe(403)
      expect(presenceOnly.data.data.code).toBe('insufficient-assurance')
    })

    it('rejects an assertion signed by the wrong key', async () => {
      const { browser } = await totpAccount()
      const authenticator = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
      await registerPasskey(browser, authenticator)
      const forged = new Browser()
      const result = await passkeySignIn(forged, authenticator, { forge: true })
      expect(result.status).toBe(401)
      expect(await forged.principal()).toBeNull()
    })

    it('lets an enrol-only session add a passkey and step up with it', async () => {
      const { browser } = await verifiedAccount()
      const authenticator = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
      expect((await registerPasskey(browser, authenticator)).status).toBe(200)
      const before = (await browser.principal())!
      expect(before.assurance.level).toBe('aal1')
      expect((await passkeySignIn(browser, authenticator)).status).toBe(200)
      const after = (await browser.principal())!
      expect(after.assurance).toEqual({ level: 'aal2', methods: ['passkey'], phishingResistant: true })
      expect(after.sessionId).not.toBe(before.sessionId)
      expect((await browser.request('/api/authentication/sessions')).status).toBe(200)
    })

    it('removes a passkey only with a recent authentication', async () => {
      const { browser } = await totpAccount()
      const authenticator = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
      await registerPasskey(browser, authenticator)
      const [passkey] = (await browser.request('/api/authentication/mfa')).data.passkeys
      const sessionId = (await browser.principal())!.sessionId
      await query(`update "authentication"."session" set "authenticatedAt" = now() - interval '20 minutes' where "id" = $1`, [sessionId])
      expect((await browser.request(`/api/authentication/passkeys/${passkey.id}`, { method: 'DELETE' })).data.data.code).toBe('reauthentication-required')

      expect((await browser.post('/api/authentication/reauthenticate', { method: 'password', password: PASSWORD })).status).toBe(200)
      expect((await browser.request(`/api/authentication/passkeys/${passkey.id}`, { method: 'DELETE' })).status).toBe(204)
      expect((await passkeySignIn(new Browser(), authenticator)).status).toBe(401)
    })

    it('cannot remove another principal\'s passkey', async () => {
      const owner = await totpAccount()
      const authenticator = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
      await registerPasskey(owner.browser, authenticator)
      const [passkey] = (await owner.browser.request('/api/authentication/mfa')).data.passkeys
      const stranger = await totpAccount()
      const result = await stranger.browser.request(`/api/authentication/passkeys/${passkey.id}`, { method: 'DELETE' })
      expect(result.status).toBeGreaterThanOrEqual(400)
      expect((await passkeySignIn(new Browser(), authenticator)).status).toBe(200)
    })
  })

  describe('events', () => {
    it('records multi-factor facts without secrets or personal data', async () => {
      const { events } = await recorder()
      const types = new Set(events.map(event => event.type))
      for (const type of [
        'authentication.mfa-enrolled',
        'authentication.mfa-removed',
        'authentication.backup-code-used',
        'authentication.backup-codes-regenerated',
        'authentication.reauthenticated',
        'authentication.signed-in',
      ] as const) {
        expect(types, type).toContain(type)
      }
      expect(events.some(event => event.reason === 'totp-replayed')).toBe(true)
      expect(events.some(event => event.reason === 'user-not-verified')).toBe(true)
      const serialized = JSON.stringify(events)
      expect(serialized).not.toMatch(/@example\.com|otpauth|secret/i)
    })
  })
})
