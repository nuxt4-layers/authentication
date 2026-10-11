import { createHash, createPublicKey, verify } from 'node:crypto'
import type { JsonWebKeyInput } from 'node:crypto'

/**
 * PRIVATE. Signed client assertions (`private_key_jwt`, RFC 7523 §3; OpenID
 * Connect Core §9) for service identities, verified with Node's own crypto.
 *
 * Only two algorithms, each bound to its key type, so an assertion cannot
 * choose a weaker one: `ES256` with a P-256 key and `EdDSA` with an Ed25519
 * key. A registered key is public only: any private member refuses it.
 */

export type ServiceKeyAlgorithm = 'ES256' | 'EdDSA'

/** A public key as stored: only the members its type needs. */
export type ServicePublicKey =
  | { kty: 'EC', crv: 'P-256', x: string, y: string }
  | { kty: 'OKP', crv: 'Ed25519', x: string }

const B64URL = /^[A-Za-z0-9_-]+$/

/** Node's JWK type, named the way every supported `@types/node` exports it. */
type JsonWebKey = JsonWebKeyInput['key']

/** Every member a JWK may carry that would make it a private key. */
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']

/** The public key in `input`, or null for anything else (a private key, another curve or type, malformed members). */
export function parsePublicKey(input: unknown): ServicePublicKey | null {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) return null
  const jwk = input as Record<string, unknown>
  if (PRIVATE_MEMBERS.some(member => member in jwk)) return null
  const coordinate = (value: unknown, bytes: number) =>
    typeof value === 'string' && B64URL.test(value) && Buffer.from(value, 'base64url').length === bytes
  let key: ServicePublicKey
  if (jwk.kty === 'EC' && jwk.crv === 'P-256' && coordinate(jwk.x, 32) && coordinate(jwk.y, 32)) {
    key = { kty: 'EC', crv: 'P-256', x: jwk.x as string, y: jwk.y as string }
  }
  else if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && coordinate(jwk.x, 32)) {
    key = { kty: 'OKP', crv: 'Ed25519', x: jwk.x as string }
  }
  else {
    return null
  }
  try {
    // Refuses a point that is not on the curve.
    createPublicKey({ key: key as JsonWebKey, format: 'jwk' })
  }
  catch {
    return null
  }
  return key
}

export function algorithmOf(key: ServicePublicKey): ServiceKeyAlgorithm {
  return key.kty === 'EC' ? 'ES256' : 'EdDSA'
}

/** The RFC 7638 SHA-256 thumbprint of a public key: its required members, in lexicographic order. */
export function keyThumbprint(key: ServicePublicKey): string {
  const canonical = key.kty === 'EC'
    ? JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y })
    : JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x })
  return createHash('sha256').update(canonical).digest('base64url')
}

/** The longest an assertion may be valid, from now: a captured one is useless soon after. */
export const ASSERTION_MAX_LIFETIME_SECONDS = 300
/** Allowance for clocks that differ, on `iat` and `nbf` only. */
const SKEW_SECONDS = 60

export interface VerifiedAssertion {
  credentialId: string
  jti: string
  expiresAt: Date
}

function decodeJson(part: string): Record<string, unknown> | null {
  if (!B64URL.test(part)) return null
  try {
    const value = JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as unknown
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null
  }
  catch {
    return null
  }
}

/**
 * Verifies a client assertion for `clientId` against the service identity's
 * active keys. Null for anything that does not verify: a bad signature, the
 * wrong issuer, subject or audience, an expired, future-dated or too
 * long-lived assertion, or no `jti`. Replay is the caller's to refuse, by
 * remembering the `jti` until `expiresAt`.
 */
export function verifyClientAssertion(input: {
  assertion: string
  clientId: string
  /** The token endpoint's absolute URL, the audience an assertion must name. */
  audience: string
  keys: readonly { credentialId: string, publicKey: ServicePublicKey, keyThumbprint: string }[]
  now: Date
}): VerifiedAssertion | null {
  if (input.assertion.length > 4096) return null
  const parts = input.assertion.split('.')
  if (parts.length !== 3) return null
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string]
  const header = decodeJson(encodedHeader)
  const payload = decodeJson(encodedPayload)
  if (!header || !payload || !B64URL.test(encodedSignature)) return null
  if (header.alg !== 'ES256' && header.alg !== 'EdDSA') return null
  if ('crit' in header) return null

  const now = Math.floor(input.now.getTime() / 1000)
  if (payload.iss !== input.clientId || payload.sub !== input.clientId) return null
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
  if (!audiences.includes(input.audience)) return null
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) || payload.exp <= now || payload.exp > now + ASSERTION_MAX_LIFETIME_SECONDS) return null
  if (payload.iat !== undefined && (typeof payload.iat !== 'number' || payload.iat > now + SKEW_SECONDS || payload.exp - payload.iat > ASSERTION_MAX_LIFETIME_SECONDS)) return null
  if (payload.nbf !== undefined && (typeof payload.nbf !== 'number' || payload.nbf > now + SKEW_SECONDS)) return null
  if (typeof payload.jti !== 'string' || payload.jti.length < 16 || payload.jti.length > 200) return null

  const signed = Buffer.from(`${encodedHeader}.${encodedPayload}`)
  const signature = Buffer.from(encodedSignature, 'base64url')
  const kid = typeof header.kid === 'string' ? header.kid : null
  for (const key of input.keys) {
    if (algorithmOf(key.publicKey) !== header.alg) continue
    if (kid !== null && kid !== key.keyThumbprint && kid !== key.credentialId) continue
    let valid = false
    try {
      const publicKey = createPublicKey({ key: key.publicKey as JsonWebKey, format: 'jwk' })
      valid = header.alg === 'ES256'
        ? verify('sha256', signed, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)
        : verify(null, signed, publicKey, signature)
    }
    catch {
      valid = false
    }
    if (valid) return { credentialId: key.credentialId, jti: payload.jti, expiresAt: new Date(payload.exp * 1000) }
  }
  return null
}
