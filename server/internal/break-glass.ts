import { AsyncLocalStorage } from 'node:async_hooks'
import { createHmac, randomBytes } from 'node:crypto'
import type { PostgresPoolLike } from '../../contracts'
import { quoteSchema } from '../database/migrations'

/**
 * PRIVATE. Break-glass accounts (ADR-0007) and their one-time passkey
 * enrolment tokens.
 *
 * A token is 32 random bytes (base64url), returned once and stored only as an
 * HMAC-SHA-256 digest keyed from the layer's secret, the mechanism backup codes
 * use. Each account has at most one outstanding token; it is single use and
 * expires by the layer's clock. The WebAuthn challenge of the ceremony in
 * progress is held here, bound to the token's digest, and is single use too.
 */

/** The shape of every enrolment token: 32 bytes, base64url without padding. */
export const ENROLMENT_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/

/** Identity's identifiers are UUIDs. */
export const IDENTITY_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export function newEnrolmentToken(): string {
  return randomBytes(32).toString('base64url')
}

/** The keyed digest of an enrolment token; the key is derived from the layer's secret for this purpose only. */
export function enrolmentTokenDigest(secret: string, token: string): string {
  const key = createHmac('sha256', secret).update('authentication.break-glass-enrolment-token').digest()
  return createHmac('sha256', key).update(token).digest('hex')
}

/** Set while the layer creates a break-glass account, so the engine's hooks neither reserve nor confirm an identity. */
export const breakGlassProvisioning = new AsyncLocalStorage<{ identityId: string }>()

interface QueryResult<T> { rows: T[], rowCount?: number | null }

export function createBreakGlassAccounts(pool: PostgresPoolLike, schema: string, secret: string) {
  const accounts = `${quoteSchema(schema)}."break_glass_account"`
  const enrolments = `${quoteSchema(schema)}."break_glass_enrolment"`
  const query = <T>(text: string, values: unknown[]) => pool.query(text, values) as Promise<QueryResult<T>>
  const digest = (token: string) => enrolmentTokenDigest(secret, token)

  return {
    /** Whether the account is a break-glass account: passkey-only, whatever the identity port says. */
    async is(principalId: string): Promise<boolean> {
      const { rows } = await query(`select 1 from ${accounts} where "user_id" = $1`, [principalId])
      return rows.length === 1
    },

    async register(principalId: string, at: Date): Promise<void> {
      await query(`insert into ${accounts} ("user_id", "provisioned_at") values ($1, $2)`, [principalId, at])
    },

    /** Issues a new token, replacing any outstanding one (and its challenge). Returns the token, once. */
    async issue(principalId: string, expiresAt: Date): Promise<string> {
      const token = newEnrolmentToken()
      await query(
        `insert into ${enrolments} ("user_id", "token_digest", "expires_at", "challenge") values ($1, $2, $3, null)
         on conflict ("user_id") do update set "token_digest" = excluded."token_digest", "expires_at" = excluded."expires_at", "challenge" = null`,
        [principalId, digest(token), expiresAt],
      )
      return token
    },

    /** The account of a live token, or null for an unknown, used or expired one. */
    async live(token: string, now: Date): Promise<string | null> {
      const { rows } = await query<{ user_id: string }>(
        `select "user_id" from ${enrolments} where "token_digest" = $1 and "expires_at" > $2`,
        [digest(token), now],
      )
      return rows[0]?.user_id ?? null
    },

    /** Binds a new challenge to a live token, replacing any earlier one; returns its account, or null. */
    async challenge(token: string, challenge: string, now: Date): Promise<string | null> {
      const { rows } = await query<{ user_id: string }>(
        `update ${enrolments} set "challenge" = $3 where "token_digest" = $1 and "expires_at" > $2 returning "user_id"`,
        [digest(token), now, challenge],
      )
      return rows[0]?.user_id ?? null
    },

    /** Takes the challenge bound to a live token, once: a second attempt finds none. */
    async takeChallenge(token: string, now: Date): Promise<{ principalId: string, challenge: string } | null> {
      const { rows } = await query<{ user_id: string, challenge: string }>(
        `update ${enrolments} as e set "challenge" = null
           from (select "user_id", "challenge" from ${enrolments}
                  where "token_digest" = $1 and "expires_at" > $2 and "challenge" is not null for update) as old
          where e."user_id" = old."user_id"
          returning old."user_id", old."challenge"`,
        [digest(token), now],
      )
      return rows[0] ? { principalId: rows[0].user_id, challenge: rows[0].challenge } : null
    },

    /** Consumes a live token of the account. False when it was replaced, used or expired meanwhile. */
    async consume(token: string, principalId: string, now: Date): Promise<boolean> {
      const { rows } = await query(
        `delete from ${enrolments} where "token_digest" = $1 and "user_id" = $2 and "expires_at" > $3 returning 1`,
        [digest(token), principalId, now],
      )
      return rows.length === 1
    },
  }
}

export type BreakGlassAccounts = ReturnType<typeof createBreakGlassAccounts>
