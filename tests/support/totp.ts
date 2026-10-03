import { createHmac } from 'node:crypto'

/**
 * Independent RFC 6238 oracle for tests: derives codes from the provisioning
 * URI alone, sharing no code with the server implementation.
 */
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32Decode(input: string): Buffer {
  const clean = input.replace(/=+$/, '').toUpperCase()
  let bits = 0
  let value = 0
  const bytes: number[] = []
  for (const char of clean) {
    value = (value << 5) | BASE32.indexOf(char)
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xFF)
      bits -= 8
    }
  }
  return Buffer.from(bytes)
}

export function secretFromUri(uri: string): Buffer {
  return base32Decode(new URL(uri).searchParams.get('secret')!)
}

/** The code for the current 30-second step plus `offset` steps. */
export function totpCode(uri: string, offset = 0, now = Date.now()): string {
  const counter = Math.floor(now / 30_000) + offset
  const message = Buffer.alloc(8)
  message.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac('sha1', secretFromUri(uri)).update(message).digest()
  const start = digest[digest.length - 1]! & 0x0F
  return ((digest.readUInt32BE(start) & 0x7FFFFFFF) % 1_000_000).toString().padStart(6, '0')
}

/** Milliseconds until the current step ends; tests wait when too close to a boundary. */
export function msLeftInStep(now = Date.now()): number {
  return 30_000 - (now % 30_000)
}
