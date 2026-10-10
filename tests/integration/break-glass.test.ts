import { randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import pg from 'pg'
import { setup } from '@nuxt/test-utils/e2e'
import { afterAll, describe, expect, it } from 'vitest'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from '../support/database'
import { createHarness, PASSWORD, type HarnessBrowser } from '../support/harness'
import { VirtualAuthenticator } from '../support/webauthn'

/**
 * Break-glass accounts (ADR-0007), black-box, with the secure default policy
 * and **no identity port**: the layer itself keeps a break-glass account
 * passkey-only. Provisioning and rotation are server-only; the playground
 * exposes them to tests through a test-only endpoint.
 */

requireDatabaseInCi()

const PORT = 3424
const ORIGIN = `http://127.0.0.1:${PORT}`
const database = hasDatabase ? await createTestDatabase() : null
const { Browser, recorder, messageCount, lastMessage, freshEmail, verifiedAccount } = createHarness(ORIGIN)

async function query(text: string, values: unknown[] = []) {
  const pool = new pg.Pool({ connectionString: database!.url })
  try {
    return await pool.query(text, values)
  }
  finally {
    await pool.end()
  }
}

const operator = (body: object) => new Browser().post('/api/__playground/break-glass', body)
const moveClock = (advanceSeconds: number) => new Browser().post('/api/__playground/clock', { advanceSeconds })

async function provision() {
  const identityId = randomUUID()
  const address = freshEmail()
  const result = await operator({ action: 'provision', identityId, address })
  expect(result.status).toBe(200)
  return { identityId, address, token: result.data.enrolmentToken as string, expiresAt: result.data.expiresAt as string }
}

async function enrol(token: string, authenticator: VirtualAuthenticator, { userVerified = true } = {}) {
  const browser = new Browser()
  const options = await browser.post('/api/authentication/break-glass/enrolment-options', { token })
  if (options.status !== 200) return options
  return browser.post('/api/authentication/break-glass/enrolment', { token, response: authenticator.register(options.data, { userVerified }), name: 'Offline key' })
}

async function passkeySignIn(browser: HarnessBrowser, authenticator: VirtualAuthenticator) {
  const challenge = await browser.post('/api/authentication/passkeys/authentication-options')
  expect(challenge.status).toBe(200)
  return browser.post('/api/authentication/passkeys/authentication', { response: authenticator.authenticate(challenge.data) })
}

/** A provisioned break-glass account with an enrolled passkey, signed in with it. */
async function signedInBreakGlass() {
  const account = await provision()
  const authenticator = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
  expect((await enrol(account.token, authenticator)).status).toBe(200)
  const browser = new Browser()
  expect((await passkeySignIn(browser, authenticator)).status).toBe(200)
  return { ...account, authenticator, browser }
}

describe.skipIf(!hasDatabase)('break-glass accounts (composed playground, no identity port)', async () => {
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

  describe('provisioning', () => {
    it('creates a passkey-only account under Identity\'s identifier, with no credential, and a one-time token', async () => {
      const before = Date.now()
      const { identityId, address, token, expiresAt } = await provision()
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/)
      // The default policy: 60 minutes, by the layer's clock.
      expect(Date.parse(expiresAt) - before).toBeGreaterThan(59 * 60_000)
      expect(Date.parse(expiresAt) - Date.now()).toBeLessThanOrEqual(60 * 60_000)

      const { rows: users } = await query(`select "id", "email", "emailVerified", "name", "image" from "authentication"."user" where "id" = $1`, [identityId])
      expect(users).toEqual([{ id: identityId, email: address, emailVerified: true, name: '', image: null }])
      expect((await query(`select 1 from "authentication"."account" where "userId" = $1`, [identityId])).rows).toHaveLength(0)
      expect((await query(`select 1 from "authentication"."passkey" where "userId" = $1`, [identityId])).rows).toHaveLength(0)
      expect((await query(`select 1 from "authentication"."break_glass_account" where "user_id" = $1`, [identityId])).rows).toHaveLength(1)
    })

    it('stores the token only as a keyed digest, and never puts it or the address in an event or message', async () => {
      const { identityId, address, token } = await provision()
      const { rows } = await query(`select * from "authentication"."break_glass_enrolment" where "user_id" = $1`, [identityId])
      expect(rows).toHaveLength(1)
      expect(rows[0].token_digest).toMatch(/^[0-9a-f]{64}$/)
      expect(JSON.stringify(rows)).not.toContain(token)
      const { events, messages } = await recorder()
      const provisioned = events.filter(e => e.type === 'authentication.break-glass-provisioned' && e.principalId === identityId)
      expect(provisioned).toHaveLength(1)
      expect(events.some(e => e.type === 'authentication.account-registered' && e.principalId === identityId)).toBe(false)
      expect(JSON.stringify(events)).not.toContain(token)
      expect(JSON.stringify(events)).not.toContain(address)
      expect(JSON.stringify(messages)).not.toContain(token)
    })

    it('refuses a second account for the same identity or the same address', async () => {
      const { identityId, address } = await provision()
      const sameIdentity = await operator({ action: 'provision', identityId, address: freshEmail() })
      const sameAddress = await operator({ action: 'provision', identityId: randomUUID(), address })
      for (const refused of [sameIdentity, sameAddress]) {
        expect(refused.status).toBe(400)
        expect(refused.data.data.code).toBe('validation-failed')
      }
      const { email } = await verifiedAccount()
      expect((await operator({ action: 'provision', identityId: randomUUID(), address: email })).status).toBe(400)
      expect((await operator({ action: 'provision', identityId: 'not-a-uuid', address: freshEmail() })).status).toBe(400)
    })
  })

  describe('enrolment', () => {
    it('offers creation options for a discoverable, user-verifying passkey with the engine\'s relying party', async () => {
      const { token, address } = await provision()
      const options = await new Browser().post('/api/authentication/break-glass/enrolment-options', { token })
      expect(options.status).toBe(200)
      expect(options.data.rp).toEqual({ id: '127.0.0.1', name: '127.0.0.1' })
      expect(options.data.user.name).toBe(address)
      expect(options.data.attestation).toBe('none')
      expect(options.data.authenticatorSelection).toMatchObject({ residentKey: 'required', requireResidentKey: true, userVerification: 'required' })
      expect(options.data.challenge).toMatch(/^[A-Za-z0-9_-]+$/)
    })

    it('registers the passkey, consumes the token and signs nobody in', async () => {
      const { identityId, address, token } = await provision()
      const browser = new Browser()
      const options = await browser.post('/api/authentication/break-glass/enrolment-options', { token })
      const authenticator = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
      const enrolled = await browser.post('/api/authentication/break-glass/enrolment', { token, response: authenticator.register(options.data), name: 'Offline key' })
      expect(enrolled.status).toBe(200)
      expect(enrolled.data).toEqual({ status: 'passkey-registered' })
      expect(enrolled.setCookies.some(cookie => cookie.includes('session_token'))).toBe(false)
      expect(await browser.principal()).toBeNull()

      const { rows } = await query(`select "name", "credentialID" from "authentication"."passkey" where "userId" = $1`, [identityId])
      expect(rows).toEqual([{ name: 'Offline key', credentialID: authenticator.credentials[0]!.id.toString('base64url') }])
      expect((await query(`select 1 from "authentication"."break_glass_enrolment" where "user_id" = $1`, [identityId])).rows).toHaveLength(0)
      const enrolledEvent = (await recorder()).events.find(e => e.type === 'authentication.break-glass-enrolled' && e.principalId === identityId)
      expect(enrolledEvent?.method).toBe('passkey')
      expect((await lastMessage(address, 'security-notification')).eventType).toBe('authentication.break-glass-enrolled')
    })

    it('answers a used token exactly like an unknown one', async () => {
      const { token } = await provision()
      expect((await enrol(token, new VirtualAuthenticator(ORIGIN, '127.0.0.1'))).status).toBe(200)
      const used = await new Browser().post('/api/authentication/break-glass/enrolment-options', { token })
      const unknown = await new Browser().post('/api/authentication/break-glass/enrolment-options', { token: 'A'.repeat(43) })
      const malformed = await new Browser().post('/api/authentication/break-glass/enrolment-options', { token: 'short', extra: true })
      const usedEnrolment = await new Browser().post('/api/authentication/break-glass/enrolment', { token, response: {} })
      const answer = ({ url: _url, ...rest }: Record<string, unknown>) => rest
      for (const refused of [used, unknown, malformed, usedEnrolment]) {
        expect(refused.status).toBe(400)
        expect(answer(refused.data)).toEqual(answer(unknown.data))
      }
      expect(unknown.data.data.code).toBe('invalid-or-expired-token')
    })

    it('uses each challenge once, and refuses an authenticator that did not verify the user', async () => {
      const { identityId, token } = await provision()
      const browser = new Browser()
      const authenticator = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
      const options = await browser.post('/api/authentication/break-glass/enrolment-options', { token })
      const unverified = await browser.post('/api/authentication/break-glass/enrolment', { token, response: authenticator.register(options.data, { userVerified: false }) })
      expect(unverified.status).toBe(400)
      expect(unverified.data.data.code).toBe('invalid-or-expired-token')
      // The challenge is spent; the token is not.
      const replay = await browser.post('/api/authentication/break-glass/enrolment', { token, response: authenticator.register(options.data) })
      expect(replay.status).toBe(400)
      expect((await query(`select 1 from "authentication"."passkey" where "userId" = $1`, [identityId])).rows).toHaveLength(0)
      expect((await enrol(token, authenticator)).status).toBe(200)
    })

    it('needs no session and is refused from another origin', async () => {
      const { token } = await provision()
      const foreign = await new Browser().post('/api/authentication/break-glass/enrolment-options', { token }, 'https://evil.example')
      expect(foreign.status).toBe(403)
      expect(foreign.data.data.code).toBe('origin-rejected')
    })
  })

  describe('signing in', () => {
    it('signs in with the enrolled passkey through the ordinary passkey endpoints, at aal2 and phishing resistant', async () => {
      const { identityId, browser } = await signedInBreakGlass()
      const principal = (await browser.principal())!
      expect(principal.principalId).toBe(identityId)
      expect(principal.assurance).toEqual({ level: 'aal2', methods: ['passkey'], phishingResistant: true })
      expect(principal.standing).toBe('allowed')
    })

    it('refuses a password sign-in and sends no password-reset link, with no identity port', async () => {
      const { identityId, address } = await signedInBreakGlass()
      const signIn = await new Browser().post('/api/authentication/sign-in', { email: address, password: PASSWORD })
      expect(signIn.status).toBe(401)
      expect(signIn.data.data.code).toBe('invalid-credentials')
      const forgot = await new Browser().post('/api/authentication/password/forgot', { email: address })
      expect(forgot.status).toBe(202)
      expect(await messageCount(address, 'password-reset')).toBe(0)
      expect((await query(`select 1 from "authentication"."account" where "userId" = $1`, [identityId])).rows).toHaveLength(0)
    })

    it('refuses an authenticator app, backup codes, a password, provider links and further passkeys', async () => {
      const { browser } = await signedInBreakGlass()
      const attempts = [
        await browser.post('/api/authentication/mfa/totp/enrol', {}),
        await browser.post('/api/authentication/mfa/totp/confirm', { code: '123456' }),
        await browser.post('/api/authentication/mfa/backup-codes', {}),
        await browser.post('/api/authentication/password/change', { currentPassword: PASSWORD, newPassword: 'a brand new long passphrase' }),
        await browser.post('/api/authentication/passkeys/registration-options'),
      ]
      for (const attempt of attempts) {
        expect(attempt.status).toBe(403)
        expect(attempt.data.data.code).toBe('account-restricted')
      }
      expect((await browser.request('/api/authentication/mfa')).data.totp).toEqual({ enabled: false })
    })
  })

  describe('rotation', () => {
    it('deletes every passkey, ends every session and kills the old token, then enrols afresh with the new one', async () => {
      const { identityId, authenticator, browser } = await signedInBreakGlass()
      const outstanding = await operator({ action: 'rotate', identityId })
      expect(outstanding.status).toBe(200)
      const rotated = await operator({ action: 'rotate', identityId })
      expect(rotated.status).toBe(200)
      expect(rotated.data.enrolmentToken).not.toBe(outstanding.data.enrolmentToken)

      expect(await browser.principal()).toBeNull()
      expect((await query(`select 1 from "authentication"."passkey" where "userId" = $1`, [identityId])).rows).toHaveLength(0)
      expect((await query(`select 1 from "authentication"."session" where "userId" = $1`, [identityId])).rows).toHaveLength(0)
      expect((await passkeySignIn(new Browser(), authenticator)).status).toBe(401)
      // At most one outstanding token: the first rotation's is dead.
      expect((await enrol(outstanding.data.enrolmentToken, authenticator)).status).toBe(400)
      expect((await query(`select 1 from "authentication"."break_glass_enrolment" where "user_id" = $1`, [identityId])).rows).toHaveLength(1)

      const fresh = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
      expect((await enrol(rotated.data.enrolmentToken, fresh)).status).toBe(200)
      expect((await passkeySignIn(new Browser(), fresh)).status).toBe(200)
      const events = (await recorder()).events.filter(e => e.type === 'authentication.break-glass-rotated' && e.principalId === identityId)
      expect(events).toHaveLength(2)
      expect(JSON.stringify(events)).not.toContain(rotated.data.enrolmentToken)
    })

    it('refuses to rotate an account that is not break-glass', async () => {
      const { browser } = await verifiedAccount()
      const { principalId } = (await browser.principal())!
      const refused = await operator({ action: 'rotate', identityId: principalId })
      expect(refused.status).toBe(400)
      expect(refused.data.data.code).toBe('validation-failed')
      expect((await operator({ action: 'rotate', identityId: randomUUID() })).status).toBe(400)
    })
  })

  // Last: the clock only moves forward.
  describe('expiry', () => {
    it('refuses a token once the layer\'s clock passes its expiry, like an unknown one', async () => {
      const { token } = await provision()
      await moveClock(61 * 60)
      const expired = await new Browser().post('/api/authentication/break-glass/enrolment-options', { token })
      const unknown = await new Browser().post('/api/authentication/break-glass/enrolment-options', { token: 'B'.repeat(43) })
      expect(expired.status).toBe(400)
      expect(expired.data).toEqual(unknown.data)
    })

    it('deletes an expired token once its retention period has passed, announcing counts only', async () => {
      const { identityId } = await provision()
      const maintain = () => new Browser().post('/api/__playground/maintenance')
      await moveClock(61 * 60 + 29 * 86_400)
      await maintain()
      expect((await query(`select 1 from "authentication"."break_glass_enrolment" where "user_id" = $1`, [identityId])).rows).toHaveLength(1)
      await moveClock(2 * 86_400)
      const run = await maintain()
      expect(run.status).toBe(200)
      expect(run.data.retention.enrolmentTokens).toBeGreaterThanOrEqual(1)
      expect((await query(`select 1 from "authentication"."break_glass_enrolment" where "user_id" = $1`, [identityId])).rows).toHaveLength(0)
      const applied = (await recorder()).events.filter(e => e.type === 'authentication.retention-applied').at(-1)!
      expect(applied).toMatchObject({ principalId: null, counts: run.data.retention })
      expect(JSON.stringify(applied)).not.toContain(identityId)
    })
  })
})
