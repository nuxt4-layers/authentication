import type { AuthenticationCredentialRecovery, AuthenticationCredentialRecoveryPage, AuthenticationRecoveryMethod, PostgresPoolLike } from '../../contracts'
import { quoteSchema } from '../database/migrations'

/**
 * PRIVATE. Durable credential recovery records (one row per principal, the
 * latest recovery). Recording is part of the recovery itself: if it fails,
 * the recovery fails, so Identity's hold can always be reconciled from here.
 */

interface Row {
  principal_id: string
  recovered_at: Date
  method: AuthenticationRecoveryMethod
}

const toRecovery = (row: Row): AuthenticationCredentialRecovery => ({
  principalId: row.principal_id,
  recoveredAt: new Date(row.recovered_at).toISOString(),
  method: row.method,
})

/** A cursor over (recovered_at, principal) that names nobody. */
function encodeCursor(recovery: AuthenticationCredentialRecovery): string {
  return Buffer.from(JSON.stringify([recovery.recoveredAt, recovery.principalId])).toString('base64url')
}

function decodeCursor(cursor: string): [string, string] {
  try {
    const value = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as unknown
    if (Array.isArray(value) && value.length === 2 && typeof value[0] === 'string' && typeof value[1] === 'string' && !Number.isNaN(Date.parse(value[0]))) {
      return [value[0], value[1]]
    }
  }
  catch {
    // Falls through to the error below.
  }
  throw new TypeError('Invalid credential recovery cursor.')
}

export function createCredentialRecoveries(pool: PostgresPoolLike, schema: string) {
  const table = `${quoteSchema(schema)}."credential_recovery"`
  const query = (text: string, values: unknown[]) => pool.query(text, values) as Promise<{ rows: Row[] }>

  return {
    /** Records a recovery; an earlier time never replaces a later one. */
    async record(principalId: string, method: AuthenticationRecoveryMethod, at: Date = new Date()): Promise<void> {
      await query(
        `insert into ${table} ("user_id", "recovered_at", "method") values ($1, $2, $3)
         on conflict ("user_id") do update set "recovered_at" = excluded."recovered_at", "method" = excluded."method"
         where ${table}."recovered_at" <= excluded."recovered_at"`,
        [principalId, at, method],
      )
    },

    async get(principalId: string): Promise<AuthenticationCredentialRecovery | null> {
      const { rows } = await query(`select "user_id" as principal_id, "recovered_at", "method" from ${table} where "user_id" = $1`, [principalId])
      return rows[0] ? toRecovery(rows[0]) : null
    },

    /** Recoveries in the order they happened, after `after` (a cursor from a previous page). */
    async list(input: { after?: string | null, limit?: number } = {}): Promise<AuthenticationCredentialRecoveryPage> {
      const limit = Math.min(Math.max(Math.trunc(input.limit ?? 100), 1), 1000)
      const [at, id] = input.after ? decodeCursor(input.after) : ['-infinity', '']
      const { rows } = await query(
        `select "user_id" as principal_id, "recovered_at", "method" from ${table}
         where ("recovered_at", "user_id") > ($1::timestamptz, $2) order by "recovered_at", "user_id" limit $3`,
        [at, id, limit + 1],
      )
      const recoveries = rows.slice(0, limit).map(toRecovery)
      return { recoveries, next: rows.length > limit ? encodeCursor(recoveries.at(-1)!) : null }
    },
  }
}

export type CredentialRecoveries = ReturnType<typeof createCredentialRecoveries>
