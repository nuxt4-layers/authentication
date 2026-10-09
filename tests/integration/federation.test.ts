import { fileURLToPath } from 'node:url'
import pg from 'pg'
import { setup } from '@nuxt/test-utils/e2e'
import { OAuth2Server } from 'oauth2-mock-server'
import { afterAll, describe, expect, it } from 'vitest'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from '../support/database'
import { createHarness, PASSWORD, type HarnessBrowser } from '../support/harness'
import { msLeftInStep, totpCode } from '../support/totp'

/**
 * Black-box federation tests against a local mock OpenID Connect provider
 * (RS256-signed ID tokens, PKCE, nonce). No real provider is contacted.
 */

requireDatabaseInCi()

const PORT = 3419
const IDP_PORT = 3420
const ORIGIN = `http://127.0.0.1:${PORT}`
const database = hasDatabase ? await createTestDatabase() : null
const { Browser, recorder, lastMessage, freshEmail, verifiedAccount } = createHarness(ORIGIN)

interface Identity { sub: string, email: string, email_verified: boolean, name?: string, picture?: string }
let identity: Identity = { sub: 'nobody', email: 'nobody@example.com', email_verified: true }

const idp = new OAuth2Server()
if (hasDatabase) {
  await idp.issuer.keys.generate('RS256')
  await idp.start(IDP_PORT, '127.0.0.1')
  idp.service.on('beforeTokenSigning', (token) => {
    Object.assign(token.payload, identity)
  })
  idp.service.on('beforeUserinfo', (userInfoResponse) => {
    userInfoResponse.body = { ...identity }
  })
}

let subjects = 0
const newIdentity = (overrides: Partial<Identity> = {}): Identity =>
  ({ sub: `subject-${++subjects}-${Date.now()}`, email: freshEmail(), email_verified: true, name: 'Alice Example', picture: 'https://idp.example.test/alice.png', ...overrides })

/** Follows a provider round trip: our start/link URL → mock IdP → our callback → final redirect. */
async function roundTrip(browser: HarnessBrowser, providerUrl: string) {
  const authorize = await fetch(providerUrl, { redirect: 'manual' })
  expect(authorize.status).toBe(302)
  const callback = new URL(authorize.headers.get('location')!)
  expect(callback.origin).toBe(ORIGIN)
  const result = await browser.request(callback.pathname + callback.search)
  expect(result.status).toBe(302)
  return result.location!
}

async function federatedSignIn(browser: HarnessBrowser, as: Identity, redirect = '/protected') {
  identity = as
  const start = await browser.request(`/api/authentication/federation/oidc/start?redirect=${encodeURIComponent(redirect)}`)
  expect(start.status).toBe(302)
  return roundTrip(browser, start.location!)
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

/** A password account with TOTP (aal2 session), able to perform sensitive operations. */
async function strongAccount() {
  const { email, browser } = await verifiedAccount()
  const enrolment = await browser.post('/api/authentication/mfa/totp/enrol', { password: PASSWORD })
  if (msLeftInStep() < 3_000) await new Promise(resolve => setTimeout(resolve, msLeftInStep() + 200))
  expect((await browser.post('/api/authentication/mfa/totp/confirm', { code: totpCode(enrolment.data.totpUri) })).status).toBe(200)
  return { email, browser }
}

describe.skipIf(!hasDatabase)('federated sign-in (mock OIDC provider)', async () => {
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
      NUXT_AUTHENTICATION_PROVIDERS_OIDC_NAME: 'Test IdP',
      NUXT_AUTHENTICATION_PROVIDERS_OIDC_DISCOVERY_URL: `http://127.0.0.1:${IDP_PORT}/.well-known/openid-configuration`,
      NUXT_AUTHENTICATION_PROVIDERS_OIDC_CLIENT_ID: 'test-client',
      NUXT_AUTHENTICATION_PROVIDERS_OIDC_CLIENT_SECRET: 'test-client-secret',
    },
  })

  afterAll(async () => {
    await idp.stop()
    await database?.drop()
  })

  it('lists only the enabled providers', async () => {
    const { data } = await new Browser().request('/api/authentication/federation/providers')
    expect(data).toEqual({ providers: [{ id: 'oidc', name: 'Test IdP' }] })
    expect((await new Browser().request('/api/authentication/federation/google/start')).status).toBe(400)
  })

  it('creates an account for a new verified identity and signs in at aal1', async () => {
    const browser = new Browser()
    const as = newIdentity()
    expect(await federatedSignIn(browser, as)).toBe('/protected')
    const principal = (await browser.principal())!
    expect(principal.assurance).toEqual({ level: 'aal1', methods: ['federated'], phishingResistant: false })
    const { rows } = await query(`select u."emailVerified", a."providerId", a."accountId" from "authentication"."user" u join "authentication"."account" a on a."userId" = u."id" where u."id" = $1`, [principal.principalId])
    expect(rows).toEqual([{ emailVerified: true, providerId: 'oidc', accountId: as.sub }])
  })

  it('stores no name or picture from the provider: they are Profile\'s', async () => {
    const browser = new Browser()
    await federatedSignIn(browser, newIdentity())
    const principal = (await browser.principal())!
    const { rows } = await query(`select "name", "image" from "authentication"."user" where "id" = $1`, [principal.principalId])
    expect(rows).toEqual([{ name: '', image: null }])
  })

  it('keeps no provider tokens at all (identity only)', async () => {
    const browser = new Browser()
    await federatedSignIn(browser, newIdentity())
    const principal = (await browser.principal())!
    const { rows } = await query(`select "accessToken", "refreshToken", "idToken" from "authentication"."account" where "userId" = $1 and "providerId" = 'oidc'`, [principal.principalId])
    expect(rows).toEqual([{ accessToken: null, refreshToken: null, idToken: null }])
  })

  it('lets a provider-only account enrol TOTP without a password and step up to aal2', async () => {
    const browser = new Browser()
    await federatedSignIn(browser, newIdentity())
    const enrolment = await browser.post('/api/authentication/mfa/totp/enrol', {})
    expect(enrolment.status).toBe(200)
    if (msLeftInStep() < 3_000) await new Promise(resolve => setTimeout(resolve, msLeftInStep() + 200))
    expect((await browser.post('/api/authentication/mfa/totp/confirm', { code: totpCode(enrolment.data.totpUri) })).status).toBe(200)
    expect((await browser.principal())!.assurance).toEqual({ level: 'aal2', methods: ['federated', 'totp'], phishingResistant: false })
  })

  it('refuses to create an account for an unverified email, revealing nothing', async () => {
    const browser = new Browser()
    const as = newIdentity({ email_verified: false })
    expect(await federatedSignIn(browser, as)).toBe('/sign-in?federation=link-required')
    expect(await browser.principal()).toBeNull()
    expect((await query(`select 1 from "authentication"."user" where "email" = $1`, [as.email])).rows).toHaveLength(0)
  })

  it('never links to an existing account by email (no takeover), and answers the same way', async () => {
    const { email } = await verifiedAccount()
    const browser = new Browser()
    expect(await federatedSignIn(browser, newIdentity({ email }))).toBe('/sign-in?federation=link-required')
    expect(await browser.principal()).toBeNull()
    const { rows } = await query(`select a."providerId" from "authentication"."account" a join "authentication"."user" u on u."id" = a."userId" where u."email" = $1`, [email])
    expect(rows.map(row => row.providerId)).toEqual(['credential'])
  })

  it('links a provider explicitly while signed in, after which it signs in to that account', async () => {
    const { email, browser } = await strongAccount()
    const principalId = (await browser.principal())!.principalId
    identity = newIdentity({ email: `different.${Date.now()}@example.com` })
    const linked = identity
    const link = await browser.post('/api/authentication/federation/oidc/link', { redirect: '/account' })
    expect(link.status).toBe(200)
    expect(await roundTrip(browser, link.data.url)).toBe('/account')
    expect((await lastMessage(email, 'security-notification')).eventType).toBe('authentication.federated-identity-linked')

    const accounts = await browser.request('/api/authentication/federation/accounts')
    expect(accounts.data).toEqual({ password: true, providers: [{ provider: 'oidc', linkedAt: expect.any(String) }] })

    const elsewhere = new Browser()
    expect(await federatedSignIn(elsewhere, linked)).toBe('/protected')
    expect((await elsewhere.principal())!.principalId).toBe(principalId)
  })

  it('requires a recent, strong session to link', async () => {
    const { browser } = await verifiedAccount()
    const weak = await browser.post('/api/authentication/federation/oidc/link', {})
    expect(weak.status).toBe(403)
    expect(weak.data.data.code).toBe('insufficient-assurance')
  })

  it('refuses to link an identity that already belongs to another account', async () => {
    const owner = new Browser()
    const taken = newIdentity()
    await federatedSignIn(owner, taken)
    const { browser } = await strongAccount()
    identity = taken
    const link = await browser.post('/api/authentication/federation/oidc/link', { redirect: '/account' })
    expect(await roundTrip(browser, link.data.url)).toBe('/account?federation=link-failed')
  })

  it('unlinks a provider, but never the last way to sign in', async () => {
    const providerOnly = new Browser()
    await federatedSignIn(providerOnly, newIdentity())
    const enrolment = await providerOnly.post('/api/authentication/mfa/totp/enrol', {})
    if (msLeftInStep() < 3_000) await new Promise(resolve => setTimeout(resolve, msLeftInStep() + 200))
    await providerOnly.post('/api/authentication/mfa/totp/confirm', { code: totpCode(enrolment.data.totpUri) })
    const last = await providerOnly.request('/api/authentication/federation/oidc', { method: 'DELETE' })
    expect(last.status).toBe(400)

    const { email, browser } = await strongAccount()
    identity = newIdentity()
    const linked = identity
    const link = await browser.post('/api/authentication/federation/oidc/link', { redirect: '/account' })
    await roundTrip(browser, link.data.url)
    expect((await browser.request('/api/authentication/federation/oidc', { method: 'DELETE' })).status).toBe(204)
    expect((await lastMessage(email, 'security-notification')).eventType).toBe('authentication.federated-identity-unlinked')
    // The identity no longer reaches that account.
    expect(await federatedSignIn(new Browser(), { ...linked, email })).toBe('/sign-in?federation=link-required')
  })

  it('rejects a callback with forged or missing state', async () => {
    const browser = new Browser()
    identity = newIdentity()
    const start = await browser.request('/api/authentication/federation/oidc/start')
    const authorize = await fetch(start.location!, { redirect: 'manual' })
    const callback = new URL(authorize.headers.get('location')!)
    callback.searchParams.set('state', 'forged-state')
    const forged = await browser.request(callback.pathname + callback.search)
    expect(forged.location).toBe('/sign-in?federation=failed')
    expect(await browser.principal()).toBeNull()

    const stranger = new Browser()
    const replay = await stranger.request(new URL(authorize.headers.get('location')!).pathname + new URL(authorize.headers.get('location')!).search)
    expect(replay.location).toMatch(/^\/sign-in\?federation=/)
    expect(await stranger.principal()).toBeNull()
  })

  it('replaces any previous session on federated sign-in (session fixation)', async () => {
    const browser = new Browser()
    await federatedSignIn(browser, newIdentity())
    const first = (await browser.principal())!
    await federatedSignIn(browser, newIdentity())
    const second = (await browser.principal())!
    expect(second.sessionId).not.toBe(first.sessionId)
    expect((await query(`select 1 from "authentication"."session" where "id" = $1`, [first.sessionId])).rows).toHaveLength(0)
  })

  it('records federation facts without personal data', async () => {
    const { events } = await recorder()
    expect(events.some(event => event.type === 'authentication.federated-identity-linked')).toBe(true)
    expect(events.some(event => event.type === 'authentication.federated-identity-unlinked')).toBe(true)
    expect(events.some(event => event.type === 'authentication.signed-in' && event.method === 'federated')).toBe(true)
    expect(events.some(event => event.reason === 'oidc:link-required')).toBe(true)
    expect(JSON.stringify(events)).not.toMatch(/@example\.com|subject-/)
  })
})
