import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { clientSecretDigest, serviceTokenDigest, SERVICE_SECRET_PATTERN } from '../server/internal/service-credentials'
import { keyThumbprint, parsePublicKey, verifyClientAssertion, type ServicePublicKey } from '../server/internal/client-assertion'

/** Signed client assertions (`private_key_jwt`) and the keyed digests of service secrets and tokens. */

const CLIENT = '01929f6e-7c1a-7d3e-9a4b-0123456789ab'
const AUDIENCE = 'https://example.com/api/authentication/service-token'
const NOW = new Date('2026-10-11T12:00:00Z')
const now = Math.floor(NOW.getTime() / 1000)

function pair(kind: 'ec' | 'ed25519'): { privateKey: KeyObject, publicKey: ServicePublicKey } {
  const keys = kind === 'ec' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : generateKeyPairSync('ed25519')
  const jwk = keys.publicKey.export({ format: 'jwk' })
  return { privateKey: keys.privateKey, publicKey: parsePublicKey(jwk)! }
}

const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')

function assertion(privateKey: KeyObject, claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
  const alg = privateKey.asymmetricKeyType === 'ec' ? 'ES256' : 'EdDSA'
  const signed = `${b64({ alg, typ: 'JWT', ...header })}.${b64({ iss: CLIENT, sub: CLIENT, aud: AUDIENCE, exp: now + 120, iat: now, jti: 'assertion-identifier-0001', ...claims })}`
  const signature = alg === 'ES256'
    ? sign('sha256', Buffer.from(signed), { key: privateKey, dsaEncoding: 'ieee-p1363' })
    : sign(null, Buffer.from(signed), privateKey)
  return `${signed}.${signature.toString('base64url')}`
}

const keyOf = (credentialId: string, publicKey: ServicePublicKey) => ({ credentialId, publicKey, keyThumbprint: keyThumbprint(publicKey) })
const verify = (value: string, keys: ReturnType<typeof keyOf>[]) => verifyClientAssertion({ assertion: value, clientId: CLIENT, audience: AUDIENCE, keys, now: NOW })

describe('public keys for service identities', () => {
  it('accepts P-256 and Ed25519 public keys, keeping only their public members', () => {
    const { publicKey } = pair('ec')
    expect(Object.keys(publicKey).sort()).toEqual(['crv', 'kty', 'x', 'y'])
    expect(Object.keys(pair('ed25519').publicKey).sort()).toEqual(['crv', 'kty', 'x'])
    expect(parsePublicKey({ ...publicKey, use: 'sig', kid: 'mine' })).toEqual(publicKey)
  })

  it('refuses private keys, other types and curves, and points off the curve', () => {
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    expect(parsePublicKey(ec.privateKey.export({ format: 'jwk' }))).toBeNull()
    expect(parsePublicKey(generateKeyPairSync('ec', { namedCurve: 'P-384' }).publicKey.export({ format: 'jwk' }))).toBeNull()
    expect(parsePublicKey(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' }))).toBeNull()
    expect(parsePublicKey({ kty: 'oct', k: 'c2VjcmV0' })).toBeNull()
    const jwk = ec.publicKey.export({ format: 'jwk' })
    expect(parsePublicKey({ ...jwk, y: jwk.x })).toBeNull()
    expect(parsePublicKey('not a key')).toBeNull()
    expect(parsePublicKey(null)).toBeNull()
  })

  it('computes the RFC 7638 thumbprint', () => {
    // RFC 8037 appendix A.3: the Ed25519 example key's thumbprint.
    expect(keyThumbprint({ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }))
      .toBe('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k')
    const { publicKey } = pair('ec')
    const expected = createHash('sha256').update(JSON.stringify({ crv: 'P-256', kty: 'EC', x: (publicKey as { x: string }).x, y: (publicKey as { y: string }).y })).digest('base64url')
    expect(keyThumbprint(publicKey)).toBe(expected)
  })
})

describe('client assertions', () => {
  const ec = pair('ec')
  const ed = pair('ed25519')
  const keys = [keyOf('credential-ec', ec.publicKey), keyOf('credential-ed', ed.publicKey)]

  it('verifies an ES256 or EdDSA assertion against the key that signed it', () => {
    expect(verify(assertion(ec.privateKey), keys)).toEqual({ credentialId: 'credential-ec', jti: 'assertion-identifier-0001', expiresAt: new Date((now + 120) * 1000) })
    expect(verify(assertion(ed.privateKey), keys)?.credentialId).toBe('credential-ed')
    expect(verify(assertion(ec.privateKey, { aud: ['https://other.example', AUDIENCE] }), keys)?.credentialId).toBe('credential-ec')
    expect(verify(assertion(ec.privateKey, {}, { kid: keys[0]!.keyThumbprint }), keys)?.credentialId).toBe('credential-ec')
  })

  it('refuses a signature by another key, or a key it does not name', () => {
    expect(verify(assertion(pair('ec').privateKey), keys)).toBeNull()
    expect(verify(assertion(ec.privateKey), [keys[1]!])).toBeNull()
    expect(verify(assertion(ec.privateKey, {}, { kid: 'credential-ed' }), keys)).toBeNull()
  })

  it.each([
    ['another issuer', { iss: 'someone-else' }],
    ['another subject', { sub: 'someone-else' }],
    ['another audience', { aud: 'https://example.com/elsewhere' }],
    ['an expired assertion', { exp: now - 1 }],
    ['an assertion valid too long', { exp: now + 301 }],
    ['an assertion issued in the future', { iat: now + 120, exp: now + 200 }],
    ['an assertion not yet valid', { nbf: now + 120 }],
    ['no identifier', { jti: undefined }],
    ['a short identifier', { jti: 'short' }],
    ['a non-numeric expiry', { exp: String(now + 60) }],
  ])('refuses %s', (_label, claims) => {
    expect(verify(assertion(ec.privateKey, claims), keys)).toBeNull()
  })

  it('refuses an unsigned or mislabelled assertion, a critical header, and anything malformed', () => {
    const good = assertion(ec.privateKey)
    const [, payload] = good.split('.')
    expect(verify(`${b64({ alg: 'none' })}.${payload}.`, keys)).toBeNull()
    expect(verify(`${b64({ alg: 'HS256' })}.${payload}.${good.split('.')[2]}`, keys)).toBeNull()
    expect(verify(`${b64({ alg: 'EdDSA' })}.${payload}.${good.split('.')[2]}`, keys)).toBeNull()
    expect(verify(assertion(ec.privateKey, {}, { crit: ['exp'] }), keys)).toBeNull()
    expect(verify('not.a.jwt', keys)).toBeNull()
    expect(verify(good.slice(0, -2), keys)).toBeNull()
    expect(verify(`${good}x`.repeat(20), keys)).toBeNull()
  })
})

describe('service secrets and tokens', () => {
  it('keeps keyed digests that differ by purpose and key', () => {
    const value = 'A'.repeat(43)
    expect(SERVICE_SECRET_PATTERN.test(value)).toBe(true)
    expect(clientSecretDigest('k'.repeat(32), value)).toMatch(/^[0-9a-f]{64}$/)
    expect(clientSecretDigest('k'.repeat(32), value)).not.toBe(serviceTokenDigest('k'.repeat(32), value))
    expect(clientSecretDigest('k'.repeat(32), value)).not.toBe(clientSecretDigest('j'.repeat(32), value))
  })
})
