import type { AuthenticationLegalHolds, AuthenticationPolicy, AuthenticationRetentionCounts, PostgresPoolLike } from '../../contracts'
import { quoteSchema } from '../database/migrations'

/**
 * PRIVATE. Retention schedules (iam-integration's retention process): deletes
 * records whose purpose is over, past the policy's periods.
 *
 * - Sessions, from their expiry. A signed-out or revoked session is already
 *   gone; an expired one is kept for `sessionDays`. Session and verification
 *   expiries are the engine's own times, on the system clock, so they are
 *   judged by `engineAt`: a host clock ahead of the system clock must never
 *   delete a session the engine still honours.
 * - Credential-recovery records, from the recovery, unless a legal hold
 *   covers the person. Without the hold port, or when it fails, every record
 *   is kept for the next run.
 * - Break-glass enrolment tokens and engine verification values, from their
 *   expiry. A used token is already gone.
 */

const DAY = 86_400_000

type Retention = AuthenticationPolicy['retention']

export function createRetention(pool: PostgresPoolLike, schema: string) {
  const s = quoteSchema(schema)
  const count = async (text: string, values: unknown[]) =>
    ((await pool.query(text, values)) as { rows: { n: number }[] }).rows[0]?.n ?? 0

  return {
    /**
     * `at` is the layer's clock (break-glass tokens, recoveries); `engineAt`
     * the system clock the engine keeps sessions and verification values by.
     */
    async apply(input: { at: Date, engineAt: Date, retention: Retention, holds: AuthenticationLegalHolds | null, limit?: number }): Promise<AuthenticationRetentionCounts> {
      const { at, engineAt, retention, holds } = input
      const limit = Math.min(Math.max(Math.trunc(input.limit ?? 1000), 1), 10_000)
      const before = (days: number, from = at) => new Date(from.getTime() - days * DAY)

      const sessions = await count(
        `with gone as (delete from ${s}."session" where "expiresAt" < $1 returning 1) select count(*)::int as n from gone`,
        [before(retention.sessionDays, engineAt)],
      )
      const enrolmentTokens = await count(
        `with gone as (delete from ${s}."break_glass_enrolment" where "expires_at" < $1 returning 1) select count(*)::int as n from gone`,
        [before(retention.tokenDays)],
      )
      const verifications = await count(
        `with gone as (delete from ${s}."verification" where "expiresAt" < $1 returning 1) select count(*)::int as n from gone`,
        [before(retention.tokenDays, engineAt)],
      )

      let credentialRecoveries = 0
      if (holds) {
        const cutoff = before(retention.recoveryDays)
        const { rows } = await pool.query(
          `select "user_id" from ${s}."credential_recovery" where "recovered_at" < $1 order by "recovered_at", "user_id" limit $2`,
          [cutoff, limit],
        ) as { rows: { user_id: string }[] }
        const free: string[] = []
        for (const { user_id: id } of rows) {
          try {
            if (await holds.covers({ kind: 'person', id }) === false) free.push(id)
          }
          catch {
            // Unknown: keep it for the next run.
          }
        }
        if (free.length) {
          // A recovery recorded since the candidates were read is newer than the cutoff, and stays.
          credentialRecoveries = await count(
            `with gone as (delete from ${s}."credential_recovery" where "user_id" = any($1::text[]) and "recovered_at" < $2 returning 1) select count(*)::int as n from gone`,
            [free, cutoff],
          )
        }
      }

      return { sessions, credentialRecoveries, enrolmentTokens, verifications }
    },
  }
}
