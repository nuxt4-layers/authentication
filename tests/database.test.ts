import pg from 'pg'
import { getMigrations } from 'better-auth/db/migration'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { resolveAuthenticationPolicy } from '../contracts'
import { AUTHENTICATION_MIGRATIONS, quoteSchema, runAuthenticationMigrations } from '../server/database/migrations'
import { buildEngineOptions } from '../server/internal/engine-options'
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
    expect(rows.map(row => row.table_name)).toEqual(['account', 'passkey', 'schema_migration', 'session', 'sign_in_throttle', 'totp_last_step', 'twoFactor', 'user', 'verification'])
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
