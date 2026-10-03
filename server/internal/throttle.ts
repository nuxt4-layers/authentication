import { createHash } from 'node:crypto'
import type { AuthenticationPolicy, PostgresPoolLike } from '../../contracts'
import { quoteSchema } from '../database/migrations'

/**
 * PRIVATE. Fixed-window sign-in throttling backed by the capability schema.
 *
 * Accounts are keyed by a hash of the normalised email, so unknown and known
 * accounts are throttled identically and no address is stored in plain text.
 */

export type ThrottleKey = `account:${string}` | `client:${string}` | `reset:${string}`

export function accountKey(email: string): ThrottleKey {
  return `account:${createHash('sha256').update(email.trim().toLowerCase()).digest('hex')}`
}

/** Limits password-reset emails per address, preventing mail flooding. */
export function resetKey(email: string): ThrottleKey {
  return `reset:${createHash('sha256').update(email.trim().toLowerCase()).digest('hex')}`
}

export function clientKey(ip: string): ThrottleKey {
  return `client:${ip}`
}

interface QueryResult { rows: Record<string, unknown>[] }

export interface SignInThrottle {
  /** True when the key is currently locked out or over its window limit. */
  isBlocked(key: ThrottleKey, limit: number): Promise<boolean>
  /** Records a failure. Returns true when this failure triggered a new lockout. */
  recordFailure(key: ThrottleKey, limit: number): Promise<boolean>
  clear(key: ThrottleKey): Promise<void>
}

export function createSignInThrottle(pool: PostgresPoolLike, schema: string, policy: AuthenticationPolicy['signInThrottle']): SignInThrottle {
  const table = `${quoteSchema(schema)}."sign_in_throttle"`
  const query = (text: string, values: unknown[]) => pool.query(text, values) as Promise<QueryResult>

  return {
    async isBlocked(key, limit) {
      const { rows } = await query(
        `select "failures", "window_started_at" > now() - make_interval(secs => $2) as "in_window",
                coalesce("locked_until" > now(), false) as "locked"
           from ${table} where "key" = $1`,
        [key, policy.windowSeconds],
      )
      const row = rows[0]
      if (!row) return false
      return row.locked === true || (row.in_window === true && Number(row.failures) >= limit)
    },

    async recordFailure(key, limit) {
      const { rows } = await query(
        `insert into ${table} as t ("key", "failures", "window_started_at") values ($1, 1, now())
         on conflict ("key") do update set
           "failures" = case when t."window_started_at" <= now() - make_interval(secs => $2) then 1 else t."failures" + 1 end,
           "window_started_at" = case when t."window_started_at" <= now() - make_interval(secs => $2) then now() else t."window_started_at" end
         returning "failures", coalesce("locked_until" > now(), false) as "locked"`,
        [key, policy.windowSeconds],
      )
      const row = rows[0]!
      if (Number(row.failures) >= limit && row.locked !== true && key.startsWith('account:')) {
        await query(`update ${table} set "locked_until" = now() + make_interval(secs => $2) where "key" = $1`, [key, policy.lockoutSeconds])
        return true
      }
      return false
    },

    async clear(key) {
      await query(`delete from ${table} where "key" = $1`, [key])
    },
  }
}
