import type { PostgresPoolLike } from '../../contracts'

/**
 * Versioned, append-only migrations for the capability-owned schema (ADR-0002).
 *
 * `{{schema}}` is replaced with the validated, quoted schema identifier.
 * Never edit a released migration; add a new one.
 *
 * 0001 reproduces the engine's expected tables exactly. `tests/database.test.ts`
 * asserts the engine reports no pending changes after these migrations, which
 * catches drift whenever the engine is upgraded.
 */
export const AUTHENTICATION_MIGRATIONS: readonly { id: string, sql: string }[] = [
  {
    id: '0001_initial',
    sql: `
create table {{schema}}."user" ("id" text not null primary key, "name" text not null, "email" text not null unique, "emailVerified" boolean not null, "image" text, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz default CURRENT_TIMESTAMP not null);
create table {{schema}}."session" ("id" text not null primary key, "expiresAt" timestamptz not null, "token" text not null unique, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz not null, "ipAddress" text, "userAgent" text, "userId" text not null references {{schema}}."user" ("id") on delete cascade, "authenticatedAt" timestamptz, "authenticationMethods" text);
create table {{schema}}."account" ("id" text not null primary key, "accountId" text not null, "providerId" text not null, "userId" text not null references {{schema}}."user" ("id") on delete cascade, "accessToken" text, "refreshToken" text, "idToken" text, "accessTokenExpiresAt" timestamptz, "refreshTokenExpiresAt" timestamptz, "scope" text, "password" text, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz not null);
create table {{schema}}."verification" ("id" text not null primary key, "identifier" text not null, "value" text not null, "expiresAt" timestamptz not null, "createdAt" timestamptz default CURRENT_TIMESTAMP not null, "updatedAt" timestamptz default CURRENT_TIMESTAMP not null);
create index "session_userId_idx" on {{schema}}."session" ("userId");
create index "account_userId_idx" on {{schema}}."account" ("userId");
create index "verification_identifier_idx" on {{schema}}."verification" ("identifier");
create table {{schema}}."sign_in_throttle" ("key" text not null primary key, "failures" integer not null, "window_started_at" timestamptz not null, "locked_until" timestamptz);
`,
  },
]

const SCHEMA_PATTERN = /^[a-z_][a-z0-9_]{0,62}$/

export function quoteSchema(schema: string): string {
  if (!SCHEMA_PATTERN.test(schema)) throw new TypeError(`Invalid authentication schema name '${schema}'.`)
  return `"${schema}"`
}

interface PoolClientLike {
  query(text: string, values?: readonly unknown[]): Promise<{ rows: Record<string, unknown>[] }>
  release(): void
}

/**
 * Applies pending migrations inside one transaction, serialised across
 * instances with a transaction-scoped advisory lock. Returns the ids applied.
 */
export async function runAuthenticationMigrations(pool: PostgresPoolLike, schema: string): Promise<string[]> {
  const quoted = quoteSchema(schema)
  const client = await pool.connect() as PoolClientLike
  const applied: string[] = []
  try {
    await client.query('begin')
    await client.query('select pg_advisory_xact_lock(hashtext($1))', [`authentication-migrations:${schema}`])
    // Create the schema only when missing: a least-privilege role that owns a
    // pre-created schema has no CREATE privilege on the database itself.
    const existing = await client.query('select 1 from pg_namespace where nspname = $1', [schema])
    if (existing.rows.length === 0) await client.query(`create schema ${quoted}`)
    await client.query(`create table if not exists ${quoted}."schema_migration" ("id" text primary key, "applied_at" timestamptz not null default now())`)
    const { rows } = await client.query(`select "id" from ${quoted}."schema_migration"`)
    const done = new Set(rows.map(row => row.id))
    for (const migration of AUTHENTICATION_MIGRATIONS) {
      if (done.has(migration.id)) continue
      await client.query(migration.sql.replaceAll('{{schema}}', quoted))
      await client.query(`insert into ${quoted}."schema_migration" ("id") values ($1)`, [migration.id])
      applied.push(migration.id)
    }
    await client.query('commit')
    return applied
  }
  catch (error) {
    await client.query('rollback').catch(() => {})
    throw error
  }
  finally {
    client.release()
  }
}
