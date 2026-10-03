import { createHmac } from 'node:crypto'
import { decodeAttestationObject, isoBase64URL, parseAuthenticatorData } from '@simplewebauthn/server/helpers'
import { symmetricDecrypt } from 'better-auth/crypto'
import type { AuthenticationMethod, PostgresPoolLike } from '../../contracts'
import { quoteSchema } from '../database/migrations'
import type { AuthenticationRuntime } from './runtime'

/** PRIVATE. Multi-factor helpers the engine does not provide. */

// ---------------------------------------------------------------------------
// Session authentication record
// ---------------------------------------------------------------------------

export function mergeMethods(existing: readonly AuthenticationMethod[], added: readonly AuthenticationMethod[]): AuthenticationMethod[] {
  return [...new Set([...existing, ...added])]
}

/** Records how and when a session was (re-)authenticated; drives the principal's assurance. */
export async function recordSessionAuthentication(
  runtime: AuthenticationRuntime,
  sessionToken: string,
  methods: readonly AuthenticationMethod[],
): Promise<void> {
  const context = await runtime.engine.$context
  await context.internalAdapter.updateSession(sessionToken, {
    authenticatedAt: new Date(),
    authenticationMethods: methods.join(','),
  })
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238: SHA-1, 6 digits, 30-second steps, as configured in the engine)
// ---------------------------------------------------------------------------

const PERIOD_SECONDS = 30
const DIGITS = 6

function hotp(key: Buffer, counter: number): string {
  const message = Buffer.alloc(8)
  message.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac('sha1', key).update(message).digest()
  const offset = digest[digest.length - 1]! & 0x0F
  const binary = (digest.readUInt32BE(offset) & 0x7FFFFFFF) % 10 ** DIGITS
  return binary.toString().padStart(DIGITS, '0')
}

/** The time step a valid code belongs to (window ±1 step), or null when it matches none. */
export function matchTotpStep(secret: string, code: string, now: number = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null
  const key = Buffer.from(secret, 'utf8')
  const current = Math.floor(now / 1000 / PERIOD_SECONDS)
  for (const step of [current, current - 1, current + 1]) {
    if (hotp(key, step) === code) return step
  }
  return null
}

/** Decrypts the engine-stored TOTP secret for a user, or null when TOTP is not set up. */
export async function loadTotpSecret(runtime: AuthenticationRuntime, userId: string): Promise<{ secret: string, verified: boolean } | null> {
  const context = await runtime.engine.$context
  const record = await context.adapter.findOne<{ secret: string, verified: boolean | null }>({
    model: 'twoFactor',
    where: [{ field: 'userId', value: userId }],
  })
  if (!record) return null
  const secret = await symmetricDecrypt({ key: context.secretConfig, data: record.secret })
  return { secret, verified: record.verified !== false }
}

/**
 * Consumes a TOTP time step for a user. Returns false when the step (or a later
 * one) was already used: a replayed code. Atomic across concurrent requests.
 */
export async function consumeTotpStep(pool: PostgresPoolLike, schema: string, userId: string, step: number): Promise<boolean> {
  const table = `${quoteSchema(schema)}."totp_last_step"`
  const result = await pool.query(
    `insert into ${table} as t ("user_id", "step") values ($1, $2)
     on conflict ("user_id") do update set "step" = excluded."step" where t."step" < excluded."step"
     returning "step"`,
    [userId, step],
  ) as { rows: unknown[] }
  return result.rows.length === 1
}

/**
 * Checks a code the engine has already accepted (or that the layer verifies
 * itself) against replay. Returns false for a replay or a non-matching code.
 */
export async function acceptTotpOnce(runtime: AuthenticationRuntime, userId: string, code: string): Promise<boolean> {
  const totp = await loadTotpSecret(runtime, userId)
  if (!totp) return false
  const step = matchTotpStep(totp.secret, code)
  if (step === null) return false
  const { database } = runtime
  return consumeTotpStep(database.pool, database.schema, userId, step)
}

// ---------------------------------------------------------------------------
// WebAuthn user verification
// ---------------------------------------------------------------------------

const FLAG_USER_PRESENT = 0x01
const FLAG_USER_VERIFIED = 0x04

function flagsVerified(authenticatorData: Uint8Array<ArrayBuffer>): boolean {
  const { flags } = parseAuthenticatorData(authenticatorData)
  return flags.up && flags.uv && (authenticatorData[32]! & (FLAG_USER_PRESENT | FLAG_USER_VERIFIED)) === (FLAG_USER_PRESENT | FLAG_USER_VERIFIED)
}

/**
 * True when an assertion carries the UP and UV flags. The engine verifies the
 * signature over this authenticator data, so the flags cannot be forged; it
 * does not, however, require UV itself.
 */
export function assertionUserVerified(response: unknown): boolean {
  try {
    const data = (response as { response?: { authenticatorData?: unknown } })?.response?.authenticatorData
    if (typeof data !== 'string') return false
    return flagsVerified(isoBase64URL.toBuffer(data))
  }
  catch {
    return false
  }
}

/** True when a registration's attested authenticator data carries the UP and UV flags. */
export function registrationUserVerified(response: unknown): boolean {
  try {
    const attestation = (response as { response?: { attestationObject?: unknown } })?.response?.attestationObject
    if (typeof attestation !== 'string') return false
    const decoded = decodeAttestationObject(isoBase64URL.toBuffer(attestation))
    return flagsVerified(new Uint8Array(decoded.get('authData')))
  }
  catch {
    return false
  }
}
