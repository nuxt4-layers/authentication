import { generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import pg from 'pg'
import { setup, url } from '@nuxt/test-utils/e2e'
import { afterAll, describe, expect, it } from 'vitest'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from '../support/database'
import { createHarness, type HarnessBrowser } from '../support/harness'
import { VirtualAuthenticator } from '../support/webauthn'

/**
 * Service identities (iam-integration's service identities process),
 * black-box: credentials issued by a person the stand-in service-governance
 * port allows, after a passkey sign-in; the client-credentials grant with a
 * secret or a signed assertion; bearer tokens on a host route; and what
 * suspension, closure and maintenance do to them.
 */

requireDatabaseInCi()

const PORT = 3425
const ORIGIN = `http://127.0.0.1:${PORT}`
const TOKEN_ENDPOINT = `${ORIGIN}/api/authentication/service-token`
const database = hasDatabase ? await createTestDatabase() : null
const { Browser, recorder, verifiedAccount } = createHarness(ORIGIN)

async function query(text: string, values: unknown[] = []) {
  const pool = new pg.Pool({ connectionString: database!.url })
  try {
    return await pool.query(text, values)
  }
  finally {
    await pool.end()
  }
}

const steer = (body: object) => new Browser().post('/api/__playground/identity', body)

/** A service identity, active in Identity, managed by `managers`. */
async function serviceIdentity(managers: string[]) {
  const identityId = randomUUID()
  await steer({ principalId: identityId, standing: 'allowed' })
  await steer({ serviceIdentityId: identityId, managers })
  return identityId
}

/** A person signed in with a passkey: phishing resistant. */
async function administrator() {
  const { browser } = await verifiedAccount()
  const authenticator = new VirtualAuthenticator(ORIGIN, '127.0.0.1')
  const options = await browser.post('/api/authentication/passkeys/registration-options')
  expect((await browser.post('/api/authentication/passkeys/registration', { response: authenticator.register(options.data), name: 'Key' })).status).toBe(200)
  const challenge = await browser.post('/api/authentication/passkeys/authentication-options')
  expect((await browser.post('/api/authentication/passkeys/authentication', { response: authenticator.authenticate(challenge.data) })).status).toBe(200)
  const principal = (await browser.principal())!
  expect(principal.assurance.phishingResistant).toBe(true)
  return { browser, principalId: principal.principalId }
}

const credentialsPath = (identityId: string) => `/api/authentication/service-identities/${identityId}/credentials`
const issueSecret = (browser: HarnessBrowser, identityId: string) => browser.post(credentialsPath(identityId), { kind: 'secret' })

/** Calls the token endpoint as a service would: no browser, no cookie, no Origin. */
async function token(form: Record<string, string>, headers: Record<string, string> = {}) {
  const response = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(form).toString(),
  })
  return { status: response.status, headers: response.headers, data: await response.json() as Record<string, unknown> }
}

const basic = (identityId: string, secret: string) => ({ authorization: `Basic ${Buffer.from(`${identityId}:${secret}`).toString('base64')}` })
const withSecret = (identityId: string, secret: string) => token({ grant_type: 'client_credentials' }, basic(identityId, secret))

/** The principal a host route sees for a bearer token. */
async function bearer(accessToken: string, path = '/api/__playground/principal') {
  const response = await fetch(url(path), { headers: { authorization: `Bearer ${accessToken}` } })
  return { status: response.status, data: await response.json().catch(() => null) }
}

function assertion(privateKey: KeyObject, identityId: string, claims: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000)
  const part = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const signed = `${part({ alg: 'EdDSA', typ: 'JWT' })}.${part({ iss: identityId, sub: identityId, aud: TOKEN_ENDPOINT, exp: now + 60, iat: now, jti: randomUUID(), ...claims })}`
  return `${signed}.${sign(null, Buffer.from(signed), privateKey).toString('base64url')}`
}

const assertionGrant = (value: string) => token({
  grant_type: 'client_credentials',
  client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
  client_assertion: value,
})

describe.skipIf(!hasDatabase)('service identities (composed playground)', async () => {
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

  describe('issuing credentials', () => {
    it('lets an administrator, after a passkey sign-in, issue a secret shown once, and announces it', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      const issued = await issueSecret(admin.browser, identityId)
      expect(issued.status).toBe(201)
      expect(issued.data.clientSecret).toMatch(/^[A-Za-z0-9_-]{43}$/)
      expect(issued.data.credential).toMatchObject({ identityId, kind: 'secret', keyThumbprint: null })
      const listed = await admin.browser.request(credentialsPath(identityId))
      expect(listed.data.credentials).toEqual([issued.data.credential])
      expect(JSON.stringify(listed.data)).not.toContain(issued.data.clientSecret)

      const event = (await recorder()).events.find(e => e.type === 'authentication.service-credential-issued' && e.principalId === identityId)
      expect(event).toMatchObject({ actorId: admin.principalId, credential: { credentialId: issued.data.credential.credentialId, kind: 'secret', expiresAt: issued.data.credential.expiresAt } })
      expect(new Date(issued.data.credential.expiresAt).getTime() - new Date(issued.data.credential.createdAt).getTime()).toBe(90 * 86_400_000)
      expect(JSON.stringify((await recorder()).events)).not.toContain(issued.data.clientSecret)
    })

    it('refuses anyone the governance port does not allow, whether or not the identity exists', async () => {
      const admin = await administrator()
      const other = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      for (const path of [credentialsPath(identityId), credentialsPath(randomUUID()), credentialsPath('not-an-identifier')]) {
        const attempt = await other.browser.post(path, { kind: 'secret' })
        expect(attempt.status).toBe(403)
        expect(attempt.data.data.code).toBe('forbidden')
        expect((await other.browser.request(path)).status).toBe(403)
      }
      // A suspended service identity's credentials are managed by nobody.
      await steer({ principalId: identityId, standing: 'refused' })
      expect((await issueSecret(admin.browser, identityId)).status).toBe(403)
    })

    it('needs a phishing-resistant authentication within fifteen minutes to issue or revoke', async () => {
      const { browser } = await verifiedAccount()
      const person = (await browser.principal())!
      const identityId = await serviceIdentity([person.principalId])
      expect((await browser.request(credentialsPath(identityId))).status).toBe(200)
      const refused = await issueSecret(browser, identityId)
      expect(refused.status).toBe(403)
      expect(refused.data.data.code).toBe('insufficient-assurance')

      const admin = await administrator()
      await steer({ serviceIdentityId: identityId, managers: [admin.principalId] })
      await query(`update "authentication"."session" set "authenticatedAt" = now() - interval '16 minutes' where "userId" = $1`, [admin.principalId])
      const stale = await issueSecret(admin.browser, identityId)
      expect(stale.status).toBe(401)
      expect(stale.data.data.code).toBe('reauthentication-required')
    })

    it('refuses an unsupported or private key', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' })
      for (const publicKey of [ec.privateKey.export({ format: 'jwk' }), generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' })]) {
        const attempt = await admin.browser.post(credentialsPath(identityId), { kind: 'public-key', publicKey })
        expect(attempt.status).toBe(400)
      }
      expect((await admin.browser.post(credentialsPath(identityId), { kind: 'public-key', publicKey: ec.publicKey.export({ format: 'jwk' }) })).status).toBe(201)
    })
  })

  describe('authenticating', () => {
    it('exchanges a secret, in Basic or the body, for a short-lived token a host route sees as a service', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      const { clientSecret, credential } = (await issueSecret(admin.browser, identityId)).data

      const answer = await withSecret(identityId, clientSecret)
      expect(answer.status).toBe(200)
      expect(answer.headers.get('cache-control')).toBe('no-store')
      expect(answer.headers.get('set-cookie')).toBeNull()
      expect(answer.data).toEqual({ access_token: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), token_type: 'Bearer', expires_in: 900 })
      const viaBody = await token({ grant_type: 'client_credentials', client_id: identityId, client_secret: clientSecret })
      expect(viaBody.status).toBe(200)

      const seen = await bearer(answer.data.access_token as string)
      expect(seen.data.principal).toMatchObject({
        principalId: identityId,
        kind: 'service',
        assurance: { level: 'aal2', methods: ['client-secret'], phishingResistant: false },
        standing: 'allowed',
      })
      // A token is never a session: the layer's own endpoints do not read it.
      expect((await bearer(answer.data.access_token as string, '/api/authentication/session')).data.principal).toBeNull()

      const events = (await recorder()).events.filter(e => e.type === 'authentication.service-token-issued' && e.principalId === identityId)
      expect(events).toHaveLength(2)
      expect(events[0]).toMatchObject({ method: 'client-secret', credential: { credentialId: credential.credentialId } })
      expect(JSON.stringify((await recorder()).events)).not.toContain(answer.data.access_token)
      expect((await admin.browser.request(credentialsPath(identityId))).data.credentials[0].lastUsedAt).not.toBeNull()
    })

    it('answers invalid_client to a wrong secret, an unknown identity or a bad token, alike', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      await issueSecret(admin.browser, identityId)
      for (const attempt of [
        await withSecret(identityId, 'A'.repeat(43)),
        await withSecret(randomUUID(), 'A'.repeat(43)),
        await withSecret('not-an-identifier', 'A'.repeat(43)),
      ]) {
        expect(attempt.status).toBe(401)
        expect(attempt.data).toEqual({ error: 'invalid_client' })
        expect(attempt.headers.get('www-authenticate')).toMatch(/^Basic/)
      }
      expect((await bearer('A'.repeat(43))).data.principal).toBeNull()
      expect((await bearer('malformed token')).data.principal).toBeNull()
    })

    it('refuses other grants, duplicated parameters and two ways of authenticating', async () => {
      const identityId = randomUUID()
      expect((await token({ grant_type: 'password', client_id: identityId, client_secret: 'A'.repeat(43) })).data).toEqual({ error: 'unsupported_grant_type' })
      expect((await token({ client_id: identityId, client_secret: 'A'.repeat(43) })).data).toEqual({ error: 'invalid_request' })
      const duplicated = await fetch(TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: `grant_type=client_credentials&client_id=${identityId}&client_secret=a&client_secret=b`,
      })
      expect(duplicated.status).toBe(400)
      const both = await token({ grant_type: 'client_credentials', client_secret: 'A'.repeat(43) }, basic(identityId, 'A'.repeat(43)))
      expect(both.data).toEqual({ error: 'invalid_request' })
    })

    it('locks a service identity out after repeated failures, and counts them as for an account', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      const { clientSecret } = (await issueSecret(admin.browser, identityId)).data
      for (let attempt = 0; attempt < 3; attempt++) await withSecret(identityId, 'A'.repeat(43))
      expect((await withSecret(identityId, clientSecret)).data).toEqual({ error: 'invalid_client' })
    })

    it('exchanges a signed assertion for a registered key, once', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      const keys = generateKeyPairSync('ed25519')
      const registered = await admin.browser.post(credentialsPath(identityId), { kind: 'public-key', publicKey: keys.publicKey.export({ format: 'jwk' }) })
      expect(registered.status).toBe(201)
      expect(registered.data.clientSecret).toBeNull()

      const signed = assertion(keys.privateKey, identityId)
      const answer = await assertionGrant(signed)
      expect(answer.status).toBe(200)
      expect((await bearer(answer.data.access_token as string)).data.principal.assurance.methods).toEqual(['client-assertion'])
      expect((await assertionGrant(signed)).data).toEqual({ error: 'invalid_client' })
      expect((await assertionGrant(assertion(keys.privateKey, identityId, { aud: `${ORIGIN}/elsewhere` }))).data).toEqual({ error: 'invalid_client' })
      expect((await assertionGrant(assertion(generateKeyPairSync('ed25519').privateKey, identityId))).data).toEqual({ error: 'invalid_client' })
    })
  })

  describe('rotating and revoking', () => {
    it('keeps two credentials at most, so the old one can be revoked without losing access; revoking ends its tokens at once', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      const old = (await issueSecret(admin.browser, identityId)).data
      const fresh = (await issueSecret(admin.browser, identityId)).data
      const third = await issueSecret(admin.browser, identityId)
      expect(third.status).toBe(409)
      expect(third.data.data.code).toBe('credential-limit-reached')

      const oldToken = (await withSecret(identityId, old.clientSecret)).data.access_token as string
      const freshToken = (await withSecret(identityId, fresh.clientSecret)).data.access_token as string
      const revoked = await admin.browser.request(`${credentialsPath(identityId)}/${old.credential.credentialId}`, { method: 'DELETE' })
      expect(revoked.status).toBe(204)
      expect((await bearer(oldToken)).data.principal).toBeNull()
      expect((await bearer(freshToken)).data.principal.principalId).toBe(identityId)
      expect((await withSecret(identityId, old.clientSecret)).status).toBe(401)
      expect((await recorder()).events.find(e => e.type === 'authentication.service-credential-revoked' && e.credential?.credentialId === old.credential.credentialId))
        .toMatchObject({ actorId: admin.principalId, credential: { endedHow: 'revoked' } })
      expect((await issueSecret(admin.browser, identityId)).status).toBe(201)
    })
  })

  describe('standing', () => {
    it('refuses a suspended identity\'s very next request and new tokens; reinstated, it asks again', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      const { clientSecret } = (await issueSecret(admin.browser, identityId)).data
      const live = (await withSecret(identityId, clientSecret)).data.access_token as string

      await steer({ principalId: identityId, standing: 'refused' })
      expect((await bearer(live)).data.principal).toBeNull()
      expect((await withSecret(identityId, clientSecret)).data).toEqual({ error: 'invalid_client' })
      expect((await new Browser().post('/api/__playground/accounts', { action: 'revoke-sessions', principalId: identityId })).status).toBe(200)

      await steer({ principalId: identityId, standing: 'allowed' })
      expect((await bearer(live)).data.principal).toBeNull()
      const again = (await withSecret(identityId, clientSecret)).data.access_token as string
      expect((await bearer(again)).data.principal.principalId).toBe(identityId)
    })

    it('fails closed when the identity port is unreachable', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      const { clientSecret } = (await issueSecret(admin.browser, identityId)).data
      const live = (await withSecret(identityId, clientSecret)).data.access_token as string
      await steer({ failing: true })
      try {
        expect((await withSecret(identityId, clientSecret)).data).toEqual({ error: 'temporarily_unavailable' })
        expect((await bearer(live)).status).toBe(503)
        expect((await admin.browser.request(credentialsPath(identityId))).status).toBe(503)
      }
      finally {
        await steer({ failing: false })
      }
      expect((await bearer(live)).data.principal.principalId).toBe(identityId)
    })

    it('deletes a closed identity\'s credentials and tokens, announcing each credential', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      const { clientSecret, credential } = (await issueSecret(admin.browser, identityId)).data
      const live = (await withSecret(identityId, clientSecret)).data.access_token as string
      const closed = await new Browser().post('/api/__playground/accounts', { action: 'delete', principalId: identityId })
      expect(closed.data).toEqual({ deleted: true })
      expect((await bearer(live)).data.principal).toBeNull()
      expect((await withSecret(identityId, clientSecret)).status).toBe(401)
      expect((await query(`select 1 from "authentication"."service_credential" where "identity_id" = $1`, [identityId])).rows).toHaveLength(0)
      expect((await recorder()).events.find(e => e.type === 'authentication.service-credential-revoked' && e.credential?.credentialId === credential.credentialId))
        .toMatchObject({ principalId: identityId, credential: { endedHow: 'identity-closed' } })
    })
  })

  describe('maintenance', () => {
    it('warns once fourteen days before a credential expires, then ends it with its tokens', async () => {
      const admin = await administrator()
      const identityId = await serviceIdentity([admin.principalId])
      const { clientSecret, credential } = (await issueSecret(admin.browser, identityId)).data
      const maintain = async () => (await new Browser().post('/api/__playground/maintenance')).data
      const advance = (days: number) => new Browser().post('/api/__playground/clock', { advanceSeconds: days * 86_400 })

      await advance(77)
      expect((await maintain()).serviceCredentials.expiring).toBeGreaterThanOrEqual(1)
      await maintain()
      const warnings = (await recorder()).events.filter(e => e.type === 'authentication.service-credential-expiring' && e.credential?.credentialId === credential.credentialId)
      expect(warnings).toHaveLength(1)
      const live = (await withSecret(identityId, clientSecret)).data.access_token as string

      await advance(14)
      expect((await maintain()).serviceCredentials.expired).toBeGreaterThanOrEqual(1)
      expect((await bearer(live)).data.principal).toBeNull()
      expect((await withSecret(identityId, clientSecret)).status).toBe(401)
      expect((await recorder()).events.find(e => e.type === 'authentication.service-credential-revoked' && e.credential?.credentialId === credential.credentialId))
        .toMatchObject({ credential: { endedHow: 'expired' } })
    })
  })
})
