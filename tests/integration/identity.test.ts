import { fileURLToPath } from 'node:url'
import { setup } from '@nuxt/test-utils/e2e'
import { afterAll, describe, expect, it } from 'vitest'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from '../support/database'
import { createHarness, PASSWORD } from '../support/harness'

/**
 * The identity port, black-box: the playground runs with a stand-in identity
 * port (as iam-integration's adapter over Identity would be), which these
 * tests steer through test-only endpoints.
 */

requireDatabaseInCi()

const PORT = 3423
const ORIGIN = `http://127.0.0.1:${PORT}`
const database = hasDatabase ? await createTestDatabase() : null

const { Browser, recorder, lastMessage, freshEmail, verifiedAccount } = createHarness(ORIGIN)

interface IdentityState {
  reserved: { principalId: string, invitationToken: string | null }[]
  confirmed: string[]
  standings: Record<string, { standing: string, passkeyOnly: boolean }>
}

const state = async (): Promise<IdentityState> => (await new Browser().request('/api/__playground/identity')).data
const steer = (body: object) => new Browser().post('/api/__playground/identity', body)

describe.skipIf(!hasDatabase)('identity port (composed playground)', async () => {
  await setup({
    rootDir: fileURLToPath(new URL('../../playground', import.meta.url)),
    server: true,
    build: true,
    port: PORT,
    env: {
      AUTHENTICATION_DATABASE_URL: database?.url,
      AUTHENTICATION_PLAYGROUND_TEST: '1',
      AUTHENTICATION_PLAYGROUND_IDENTITY: '1',
      NUXT_AUTHENTICATION_SECRET: 'integration-test-secret-that-is-long-enough-0123456789',
      NUXT_AUTHENTICATION_BASE_URL: ORIGIN,
      AUTHENTICATION_PLAYGROUND_MFA: 'optional',
    },
  })

  afterAll(async () => {
    await database?.drop()
  })

  it('takes the account identifier from the identity port, and confirms it once the address is verified', async () => {
    const { browser } = await verifiedAccount()
    const principal = (await browser.principal())!
    const { reserved, confirmed } = await state()
    expect(reserved.at(-1)).toEqual({ principalId: principal.principalId, invitationToken: null })
    expect(confirmed).toContain(principal.principalId)
    expect(principal.standing).toBe('allowed')
  })

  it('passes an invitation token to the identity port only', async () => {
    const email = freshEmail()
    const token = 'invitation-token-0123456789abcdefghijklmnop'
    expect((await new Browser().post('/api/authentication/sign-up', { email, password: PASSWORD, invitationToken: token })).status).toBe(202)
    expect((await state()).reserved.at(-1)!.invitationToken).toBe(token)
    const { events, messages } = await recorder()
    expect(JSON.stringify(events)).not.toContain(token)
    expect(JSON.stringify(messages)).not.toContain(token)
  })

  it('ends the session of an account that becomes refused, on its very next request', async () => {
    const { email, browser } = await verifiedAccount()
    const { principalId } = (await browser.principal())!
    await steer({ principalId, standing: 'refused' })
    expect(await browser.principal()).toBeNull()
    const again = await new Browser().post('/api/authentication/sign-in', { email, password: PASSWORD })
    expect(again.status).toBe(401)
    expect(again.data.data.code).toBe('invalid-credentials')
    await steer({ principalId, standing: 'allowed' })
    expect(await browser.principal()).toBeNull()
  })

  it('lets a paused account sign in, restricted to what accepts its standing', async () => {
    const { email, browser } = await verifiedAccount()
    const { principalId } = (await browser.principal())!
    await steer({ principalId, standing: 'resume-only' })
    expect((await browser.principal())!.standing).toBe('resume-only')
    const fresh = new Browser()
    expect((await fresh.post('/api/authentication/sign-in', { email, password: PASSWORD })).status).toBe(200)
    expect((await fresh.principal())!.standing).toBe('resume-only')
  })

  it('refuses a break-glass account any way in but a passkey', async () => {
    const { email, browser } = await verifiedAccount()
    const { principalId } = (await browser.principal())!
    await steer({ principalId, standing: 'allowed', passkeyOnly: true })
    const attempt = await new Browser().post('/api/authentication/sign-in', { email, password: PASSWORD })
    expect(attempt.status).toBe(401)
    expect(attempt.data.data.code).toBe('invalid-credentials')
    const refused = (await recorder()).events.filter(e => e.type === 'authentication.sign-in-failed' && e.principalId === principalId).at(-1)
    expect(refused?.reason).toBe('passkey-only')
  })

  it('fails closed when the identity port is unreachable', async () => {
    const { email, browser } = await verifiedAccount()
    await steer({ failing: true })
    try {
      expect((await browser.request('/api/authentication/session')).status).toBe(503)
      expect((await new Browser().post('/api/authentication/sign-in', { email, password: PASSWORD })).status).toBe(503)
      const signUp = await new Browser().post('/api/authentication/sign-up', { email: freshEmail(), password: PASSWORD })
      expect(signUp.status).toBe(503)
    }
    finally {
      await steer({ failing: false })
    }
    expect(await browser.principal()).not.toBeNull()
  })

  it('confirms again an account whose confirmation was lost', async () => {
    const email = freshEmail()
    const browser = new Browser()
    await browser.post('/api/authentication/sign-up', { email, password: PASSWORD })
    const { principalId } = (await state()).reserved.at(-1)!
    await steer({ failing: true })
    const link = new URL((await lastMessage(email, 'email-verification')).actionUrl!)
    await browser.request(link.pathname + link.search)
    await steer({ failing: false })
    expect((await state()).confirmed).not.toContain(principalId)
    expect((await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })).status).toBe(200)
    expect((await state()).confirmed).toContain(principalId)
  })
})
