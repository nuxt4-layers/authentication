import pg from 'pg'
import { getMigrations } from 'better-auth/db/migration'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { resolveAuthenticationPolicy } from '../contracts'
import { AUTHENTICATION_MIGRATIONS, quoteSchema, runAuthenticationMigrations } from '../server/database/migrations'
import { createBreakGlassAccounts, enrolmentTokenDigest } from '../server/internal/break-glass'
import { buildEngineOptions } from '../server/internal/engine-options'
import { createCredentialRecoveries } from '../server/internal/recovery'
import { createRetention } from '../server/internal/retention'
import { accountKey, clientKey, createSignInThrottle } from '../server/internal/throttle'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from './support/database'

requireDatabaseInCi()

describe.skipIf(!hasDatabase)('authentication database', () => {
  let pool: pg.Pool
  let drop: () => Promise<void>

  beforeAll(async () => {
    const database = await createTestDatabase()
    drop = database.drop
    pool = new pg.Pool({ connectionString: database.url })
  })

  afterAll(async () => {
    await pool?.end()
    await drop?.()
  })

  it('applies every migration once, even when instances race', async () => {
    const results = await Promise.all([
      runAuthenticationMigrations(pool, 'authentication'),
      runAuthenticationMigrations(pool, 'authentication'),
    ])
    expect(results.flat()).toEqual(AUTHENTICATION_MIGRATIONS.map(m => m.id))
    expect(await runAuthenticationMigrations(pool, 'authentication')).toEqual([])
  })

  it('creates every table inside the capability-owned schema only', async () => {
    const { rows } = await pool.query(
      `select table_schema, table_name from information_schema.tables where table_schema not in ('pg_catalog', 'information_schema') order by table_name`,
    )
    expect(rows.every(row => row.table_schema === 'authentication')).toBe(true)
    expect(rows.map(row => row.table_name)).toEqual(['account', 'break_glass_account', 'break_glass_enrolment', 'credential_recovery', 'passkey', 'schema_migration', 'session', 'sign_in_throttle', 'totp_last_step', 'twoFactor', 'user', 'verification'])
  })

  it('blanks names and pictures stored by earlier releases (0003)', async () => {
    await pool.query(`insert into "authentication"."user" ("id", "name", "email", "emailVerified", "image") values ('legacy-federated', 'Alice Example', 'legacy@example.test', true, 'https://idp.example.test/alice.png'), ('legacy-email', '', 'plain@example.test', true, null)`)
    const migration = AUTHENTICATION_MIGRATIONS.find(m => m.id === '0003_no_names_or_images')!
    await pool.query(migration.sql.replaceAll('{{schema}}', quoteSchema('authentication')))
    const { rows } = await pool.query(`select "id", "name", "image" from "authentication"."user" where "id" like 'legacy-%' order by "id"`)
    expect(rows).toEqual([
      { id: 'legacy-email', name: '', image: null },
      { id: 'legacy-federated', name: '', image: null },
    ])
    await pool.query(`delete from "authentication"."user" where "id" like 'legacy-%'`)
  })

  it('matches the engine schema exactly (drift check on engine upgrades)', async () => {
    const options = buildEngineOptions({
      pool,
      schema: 'authentication',
      secret: 'x'.repeat(40),
      baseUrl: 'http://localhost:3000',
      appName: 'Test',
      policy: resolveAuthenticationPolicy(),
    })
    const pending = await getMigrations(options)
    expect(pending.toBeCreated).toEqual([])
    expect(pending.toBeAdded).toEqual([])
    expect(pending.toBeAddedIndexes).toEqual([])
    expect(pending.unsafeChanges).toEqual([])
    expect(pending.schemaProblems).toEqual([])
  })

  it('migrates as a least-privilege role that owns only its schema', async () => {
    const role = `authentication_app_${Date.now()}`
    await pool.query(`create role "${role}" login password 'test'`)
    await pool.query(`create schema "auth_owned" authorization "${role}"`)
    await pool.query(`revoke all on schema public from "${role}"`)
    const url = new URL(pool.options.connectionString!)
    url.username = role
    url.password = 'test'
    const restricted = new pg.Pool({ connectionString: url.toString() })
    try {
      expect(await runAuthenticationMigrations(restricted, 'auth_owned')).toEqual(AUTHENTICATION_MIGRATIONS.map(m => m.id))
      await expect(restricted.query('create table public.intruder (id int)')).rejects.toThrow(/permission denied/)
      await expect(restricted.query('create schema elsewhere')).rejects.toThrow(/permission denied/)
    }
    finally {
      await restricted.end()
      await pool.query(`drop schema "auth_owned" cascade`)
      await pool.query(`drop role "${role}"`)
    }
  })

  it('supports a host-chosen schema name and rejects unsafe ones', async () => {
    expect(await runAuthenticationMigrations(pool, 'auth_alt')).toEqual(AUTHENTICATION_MIGRATIONS.map(m => m.id))
    expect(() => quoteSchema('auth"; drop schema public; --')).toThrow(TypeError)
  })

  describe('credential recovery records', () => {
    it('keeps each principal\'s latest recovery, never moving it back', async () => {
      await pool.query(`insert into "authentication"."user" ("id", "name", "email", "emailVerified") values ('recovered-a', '', 'a@recovery.test', true), ('recovered-b', '', 'b@recovery.test', true)`)
      const recoveries = createCredentialRecoveries(pool, 'authentication')
      await recoveries.record('recovered-a', 'password-reset', new Date('2026-10-01T10:00:00Z'))
      await recoveries.record('recovered-a', 'backup-code', new Date('2026-10-01T09:00:00Z'))
      expect(await recoveries.get('recovered-a')).toEqual({ principalId: 'recovered-a', recoveredAt: '2026-10-01T10:00:00.000Z', method: 'password-reset' })
      await recoveries.record('recovered-a', 'backup-code', new Date('2026-10-02T10:00:00Z'))
      expect(await recoveries.get('recovered-a')).toMatchObject({ recoveredAt: '2026-10-02T10:00:00.000Z', method: 'backup-code' })
      expect(await recoveries.get('recovered-b')).toBeNull()
    })

    it('pages through recoveries in order, with a cursor that names nobody', async () => {
      const recoveries = createCredentialRecoveries(pool, 'authentication')
      await recoveries.record('recovered-b', 'password-reset', new Date('2026-10-03T10:00:00Z'))
      const first = await recoveries.list({ limit: 1 })
      expect(first.recoveries.map(r => r.principalId)).toEqual(['recovered-a'])
      expect(Buffer.from(first.next!, 'base64url').toString()).not.toMatch(/@/)
      const second = await recoveries.list({ after: first.next, limit: 1 })
      expect(second.recoveries.map(r => r.principalId)).toEqual(['recovered-b'])
      expect(second.next).toBeNull()
      expect((await recoveries.list({ after: second.next ?? undefined })).recoveries).toHaveLength(2)
      await expect(recoveries.list({ after: 'not-a-cursor' })).rejects.toThrow(TypeError)
    })

    it('forgets a principal\'s recoveries with the account', async () => {
      await pool.query(`delete from "authentication"."user" where "id" like 'recovered-%'`)
      expect((await createCredentialRecoveries(pool, 'authentication').list()).recoveries).toEqual([])
    })
  })

  describe('break-glass enrolment tokens', () => {
    const secret = 'database-test-secret-that-is-long-enough-0123'
    const at = (iso: string) => new Date(iso)

    it('keeps at most one outstanding token per account, stored only as a keyed digest', async () => {
      await pool.query(`insert into "authentication"."user" ("id", "name", "email", "emailVerified") values ('glass-a', '', 'a@glass.test', true), ('glass-b', '', 'b@glass.test', true)`)
      const accounts = createBreakGlassAccounts(pool, 'authentication', secret)
      await accounts.register('glass-a', at('2026-10-01T10:00:00Z'))
      expect(await accounts.is('glass-a')).toBe(true)
      expect(await accounts.is('glass-b')).toBe(false)
      const first = await accounts.issue('glass-a', at('2026-10-01T11:00:00Z'))
      const second = await accounts.issue('glass-a', at('2026-10-01T11:00:00Z'))
      const { rows } = await pool.query(`select "token_digest" from "authentication"."break_glass_enrolment" where "user_id" = 'glass-a'`)
      expect(rows).toEqual([{ token_digest: enrolmentTokenDigest(secret, second) }])
      expect(rows[0].token_digest).not.toContain(second)
      const now = at('2026-10-01T10:30:00Z')
      expect(await accounts.live(first, now)).toBeNull()
      expect(await accounts.live(second, now)).toBe('glass-a')
      // Another secret derives another digest: the token is useless without the layer's secret.
      expect(await createBreakGlassAccounts(pool, 'authentication', `${secret}-other`).live(second, now)).toBeNull()
    })

    it('expires a token by the time it is given', async () => {
      const accounts = createBreakGlassAccounts(pool, 'authentication', secret)
      const token = await accounts.issue('glass-a', at('2026-10-01T11:00:00Z'))
      expect(await accounts.live(token, at('2026-10-01T10:59:59Z'))).toBe('glass-a')
      expect(await accounts.live(token, at('2026-10-01T11:00:00Z'))).toBeNull()
      expect(await accounts.challenge(token, 'challenge', at('2026-10-01T11:00:01Z'))).toBeNull()
      expect(await accounts.consume(token, 'glass-a', at('2026-10-01T11:00:01Z'))).toBe(false)
    })

    it('hands out each challenge once, and consumes a token once', async () => {
      const accounts = createBreakGlassAccounts(pool, 'authentication', secret)
      const now = at('2026-10-01T10:30:00Z')
      const token = await accounts.issue('glass-a', at('2026-10-01T11:00:00Z'))
      expect(await accounts.takeChallenge(token, now)).toBeNull()
      expect(await accounts.challenge(token, 'first', now)).toBe('glass-a')
      expect(await accounts.challenge(token, 'second', now)).toBe('glass-a')
      expect(await accounts.takeChallenge(token, now)).toEqual({ principalId: 'glass-a', challenge: 'second' })
      expect(await accounts.takeChallenge(token, now)).toBeNull()
      expect(await accounts.consume(token, 'glass-b', now)).toBe(false)
      expect(await accounts.consume(token, 'glass-a', now)).toBe(true)
      expect(await accounts.consume(token, 'glass-a', now)).toBe(false)
      expect(await accounts.live(token, now)).toBeNull()
    })

    it('rejects anything but a digest, and forgets the account with its user', async () => {
      await expect(pool.query(`insert into "authentication"."break_glass_enrolment" ("user_id", "token_digest", "expires_at") values ('glass-a', 'plain-token', now())`)).rejects.toThrow(/check constraint/)
      await pool.query(`delete from "authentication"."user" where "id" like 'glass-%'`)
      expect((await pool.query(`select 1 from "authentication"."break_glass_account"`)).rows).toHaveLength(0)
    })
  })

  describe('retention schedules', () => {
    const at = new Date('2027-06-01T00:00:00Z')
    const daysBefore = (days: number) => new Date(at.getTime() - days * 86_400_000)
    const retention = resolveAuthenticationPolicy().retention
    const ids = async (table: string, column: string) =>
      (await pool.query(`select ${column} as id from "authentication".${table} order by 1`)).rows.map(row => row.id)

    beforeAll(async () => {
      await pool.query(`insert into "authentication"."user" ("id", "name", "email", "emailVerified") values ('kept-a', '', 'a@kept.test', true), ('kept-b', '', 'b@kept.test', true), ('kept-c', '', 'c@kept.test', true)`)
      await pool.query(`insert into "authentication"."break_glass_account" ("user_id", "provisioned_at") values ('kept-a', $1), ('kept-b', $1)`, [daysBefore(400)])
      const sessions: [string, Date][] = [['old', daysBefore(91)], ['recent', daysBefore(89)], ['live', new Date(at.getTime() + 3_600_000)]]
      for (const [id, expiresAt] of sessions) {
        await pool.query(`insert into "authentication"."session" ("id", "expiresAt", "token", "updatedAt", "userId") values ($1, $2, $1, $2, 'kept-a')`, [`session-${id}`, expiresAt])
        await pool.query(`insert into "authentication"."verification" ("id", "identifier", "value", "expiresAt") values ($1, 'challenge', 'value', $2)`, [`verification-${id}`, new Date(expiresAt.getTime() + 60 * 86_400_000)])
      }
      await pool.query(`insert into "authentication"."break_glass_enrolment" ("user_id", "token_digest", "expires_at") values ('kept-a', $1, $2), ('kept-b', $3, $4)`, ['a'.repeat(64), daysBefore(31), 'b'.repeat(64), daysBefore(29)])
      const recoveries = createCredentialRecoveries(pool, 'authentication')
      await recoveries.record('kept-a', 'password-reset', daysBefore(366))
      await recoveries.record('kept-b', 'backup-code', daysBefore(366))
      await recoveries.record('kept-c', 'password-reset', daysBefore(364))
    })

    afterAll(async () => {
      await pool.query(`delete from "authentication"."user" where "id" like 'kept-%'`)
      await pool.query(`delete from "authentication"."verification" where "id" like 'verification-%'`)
    })

    it('deletes expired sessions and tokens past their periods, and keeps every recovery record without the hold port', async () => {
      const counts = await createRetention(pool, 'authentication').apply({ at, retention, holds: null })
      expect(counts).toEqual({ sessions: 1, credentialRecoveries: 0, enrolmentTokens: 1, verifications: 1 })
      expect(await ids('"session"', '"id"')).toEqual(['session-live', 'session-recent'])
      expect(await ids('"verification"', '"id"')).toEqual(['verification-live', 'verification-recent'])
      expect(await ids('"break_glass_enrolment"', '"user_id"')).toEqual(['kept-b'])
      expect(await ids('"credential_recovery"', '"user_id"')).toEqual(['kept-a', 'kept-b', 'kept-c'])
    })

    it('keeps a held person\'s recovery record, and one the port cannot answer for, until the next run', async () => {
      const asked: unknown[] = []
      const holds = {
        async covers(subject: { kind: 'person', id: string }) {
          asked.push(subject)
          if (subject.id === 'kept-b') throw new Error('Profile unavailable')
          return subject.id === 'kept-a'
        },
      }
      const retentionRun = createRetention(pool, 'authentication')
      expect(await retentionRun.apply({ at, retention, holds })).toEqual({ sessions: 0, credentialRecoveries: 0, enrolmentTokens: 0, verifications: 0 })
      expect(asked).toEqual([{ kind: 'person', id: 'kept-a' }, { kind: 'person', id: 'kept-b' }])
      expect(await ids('"credential_recovery"', '"user_id"')).toEqual(['kept-a', 'kept-b', 'kept-c'])

      // The hold on kept-a ends and the port answers again: both go; kept-c is still within its period.
      expect(await retentionRun.apply({ at, retention, holds: { covers: async () => false } }))
        .toEqual({ sessions: 0, credentialRecoveries: 2, enrolmentTokens: 0, verifications: 0 })
      expect(await ids('"credential_recovery"', '"user_id"')).toEqual(['kept-c'])
    })

    it('keeps a record recovered again since the run read it', async () => {
      const recoveries = createCredentialRecoveries(pool, 'authentication')
      await recoveries.record('kept-a', 'backup-code', daysBefore(400))
      const holds = {
        async covers() {
          await recoveries.record('kept-a', 'password-reset', at)
          return false
        },
      }
      expect((await createRetention(pool, 'authentication').apply({ at, retention, holds })).credentialRecoveries).toBe(0)
      expect(await recoveries.get('kept-a')).toMatchObject({ recoveredAt: at.toISOString() })
    })
  })

  describe('sign-in throttle', () => {
    const policy = { maxFailedAttempts: 3, maxFailedAttemptsPerClient: 10, windowSeconds: 900, lockoutSeconds: 900 }

    it('locks an account after the configured failures and reports the lock once', async () => {
      const throttle = createSignInThrottle(pool, 'authentication', policy)
      const key = accountKey('Locked@Example.com ')
      expect(await throttle.recordFailure(key, 3)).toBe(false)
      expect(await throttle.recordFailure(key, 3)).toBe(false)
      expect(await throttle.isBlocked(key, 3)).toBe(false)
      expect(await throttle.recordFailure(key, 3)).toBe(true)
      expect(await throttle.isBlocked(key, 3)).toBe(true)
      expect(await throttle.recordFailure(key, 3)).toBe(false)
      expect(await throttle.isBlocked(accountKey('locked@example.com'), 3)).toBe(true)
    })

    it('stores only hashed account keys', async () => {
      const { rows } = await pool.query(`select "key" from "authentication"."sign_in_throttle"`)
      expect(rows.some(row => String(row.key).includes('@'))).toBe(false)
    })

    it('rate-limits clients without locking them out permanently', async () => {
      const throttle = createSignInThrottle(pool, 'authentication', policy)
      const key = clientKey('203.0.113.7')
      for (let i = 0; i < 10; i++) expect(await throttle.recordFailure(key, 10)).toBe(false)
      expect(await throttle.isBlocked(key, 10)).toBe(true)
      const { rows } = await pool.query(`select "locked_until" from "authentication"."sign_in_throttle" where "key" = $1`, [key])
      expect(rows[0].locked_until).toBeNull()
    })

    it('starts a new window once the old one has passed', async () => {
      const throttle = createSignInThrottle(pool, 'authentication', policy)
      const key = clientKey('203.0.113.8')
      for (let i = 0; i < 10; i++) await throttle.recordFailure(key, 10)
      await pool.query(`update "authentication"."sign_in_throttle" set "window_started_at" = now() - interval '1 hour' where "key" = $1`, [key])
      expect(await throttle.isBlocked(key, 10)).toBe(false)
      await throttle.recordFailure(key, 10)
      const { rows } = await pool.query(`select "failures" from "authentication"."sign_in_throttle" where "key" = $1`, [key])
      expect(rows[0].failures).toBe(1)
    })

    it('clears a key', async () => {
      const throttle = createSignInThrottle(pool, 'authentication', policy)
      const key = accountKey('locked@example.com')
      await throttle.clear(key)
      expect(await throttle.isBlocked(key, 3)).toBe(false)
    })
  })
})
