import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto'

/**
 * A software WebAuthn authenticator for tests: ES256 credentials, "none"
 * attestation, and switchable user-verification, so the server can be tested
 * against compliant and non-compliant authenticators without a browser.
 */

// --- Minimal CBOR encoder (integers, byte/text strings, arrays, maps) ---------
function head(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length])
  if (length < 256) return Buffer.from([(major << 5) | 24, length])
  if (length < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(length, 1); return b }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(length, 1); return b
}
type Cbor = number | string | Buffer | Cbor[] | Map<Cbor, Cbor>
function cbor(value: Cbor): Buffer {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value)
  if (typeof value === 'string') { const bytes = Buffer.from(value, 'utf8'); return Buffer.concat([head(3, bytes.length), bytes]) }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value])
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)])
  return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])])
}

const b64url = (bytes: Buffer) => bytes.toString('base64url')
const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest()

const UP = 0x01
const UV = 0x04
const AT = 0x40

export interface VirtualCredential {
  id: Buffer
  privateKey: KeyObject
  counter: number
}

export class VirtualAuthenticator {
  credentials: VirtualCredential[] = []

  constructor(private readonly origin: string, private readonly rpId: string) {}

  private clientData(type: 'webauthn.create' | 'webauthn.get', challenge: string): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }))
  }

  /** Builds a registration response for server-issued creation options. */
  register(options: { challenge: string }, { userVerified = true } = {}) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string, y: string }
    const id = randomBytes(32)
    this.credentials.push({ id, privateKey, counter: 0 })
    const cose = cbor(new Map<Cbor, Cbor>([
      [1, 2], [3, -7], [-1, 1],
      [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')],
    ]))
    const idLength = Buffer.alloc(2)
    idLength.writeUInt16BE(id.length)
    const authData = Buffer.concat([
      sha256(this.rpId), Buffer.from([UP | AT | (userVerified ? UV : 0)]), Buffer.alloc(4),
      Buffer.alloc(16), idLength, id, cose,
    ])
    const attestationObject = cbor(new Map<Cbor, Cbor>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))
    return {
      id: b64url(id),
      rawId: b64url(id),
      type: 'public-key' as const,
      response: {
        clientDataJSON: b64url(this.clientData('webauthn.create', options.challenge)),
        attestationObject: b64url(attestationObject),
        transports: ['internal'],
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    }
  }

  /** Builds an assertion with a stored credential (or a forged key when `forge` is set). */
  authenticate(options: { challenge: string }, { userVerified = true, credential = this.credentials[0]!, forge = false } = {}) {
    credential.counter += 1
    const counter = Buffer.alloc(4)
    counter.writeUInt32BE(credential.counter)
    const authData = Buffer.concat([sha256(this.rpId), Buffer.from([UP | (userVerified ? UV : 0)]), counter])
    const clientDataJSON = this.clientData('webauthn.get', options.challenge)
    const key = forge ? generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey : credential.privateKey
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), key)
    return {
      id: b64url(credential.id),
      rawId: b64url(credential.id),
      type: 'public-key' as const,
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    }
  }
}
