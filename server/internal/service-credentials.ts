import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import type {
  AuthenticationIssuedServiceCredential,
  AuthenticationServiceCredential,
  AuthenticationServiceCredentialEnding,
  AuthenticationServiceCredentialKind,
  PostgresPoolLike,
} from '../../contracts'
import { AUTHENTICATION_SERVICE_CREDENTIALS_ACTIVE_MAX } from '../../contracts'
import { quoteSchema } from '../database/migrations'
import type { ServicePublicKey } from './client-assertion'
import { keyThumbprint } from './client-assertion'

/**
 * PRIVATE. Service identities' machine credentials and tokens
 * (iam-integration's service identities process).
 *
 * - A client secret is 32 random bytes (base64url), returned once and stored
 *   only as an HMAC-SHA-256 digest keyed from the layer's secret for this
 *   purpose; a public key is stored as its public JWK and thumbprint.
 * - At most `AUTHENTICATION_SERVICE_CREDENTIALS_ACTIVE_MAX` credentials are
 *   active per identity, counted under a per-identity lock.
 * - A token is 32 random bytes, stored only as a keyed digest, bound to the
 *   credential that obtained it: revoking or expiring the credential ends
 *   its tokens.
 * - Every time is the layer's clock, passed in by the caller.
 */

/** The shape of every client secret and token: 32 bytes, base64url without padding. */
export const SERVICE_SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/

function digest(secret: string, purpose: string, value: string): string {
  const key = createHmac('sha256', secret).update(purpose).digest()
  return createHmac('sha256', key).update(value).digest('hex')
}

export const clientSecretDigest = (secret: string, clientSecret: string) => digest(secret, 'authentication.service-client-secret', clientSecret)
export const serviceTokenDigest = (secret: string, token: string) => digest(secret, 'authentication.service-token', token)

interface CredentialRow {
  credential_id: string
  identity_id: string
  kind: AuthenticationServiceCredentialKind
  public_key: ServicePublicKey | null
  key_thumbprint: string | null
  created_at: Date
  expires_at: Date
  last_used_at: Date | null
}

const toCredential = (row: CredentialRow): AuthenticationServiceCredential => ({
  credentialId: row.credential_id,
  identityId: row.identity_id,
  kind: row.kind,
  keyThumbprint: row.key_thumbprint,
  createdAt: new Date(row.created_at).toISOString(),
  expiresAt: new Date(row.expires_at).toISOString(),
  lastUsedAt: row.last_used_at ? new Date(row.last_used_at).toISOString() : null,
})

const CREDENTIAL_COLUMNS = `"credential_id", "identity_id", "kind", "public_key", "key_thumbprint", "created_at", "expires_at", "last_used_at"`

export class ServiceCredentialLimit extends Error {
  constructor() {
    super('too many active service credentials')
  }
}

interface ClientLike {
  query(text: string, values?: readonly unknown[]): Promise<{ rows: Record<string, unknown>[] }>
  release(): void
}

export interface ResolvedServiceToken {
  tokenId: string
  identityId: string
  credentialId: string
  method: 'client-secret' | 'client-assertion'
  issuedAt: Date
  expiresAt: Date
}

export function createServiceCredentials(pool: PostgresPoolLike, schema: string, secret: string) {
  const s = quoteSchema(schema)
  const query = <T>(text: string, values: readonly unknown[]) => pool.query(text, values) as Promise<{ rows: T[] }>

  /** Runs `work` in a transaction holding the identity's credential lock. */
  async function locked<T>(identityId: string, work: (client: ClientLike) => Promise<T>): Promise<T> {
    const client = await pool.connect() as ClientLike
    try {
      await client.query('begin')
      await client.query('select pg_advisory_xact_lock(hashtext($1))', [`authentication-service-credentials:${identityId}`])
      const result = await work(client)
      await client.query('commit')
      return result
    }
    catch (error) {
      await client.query('rollback').catch(() => {})
      throw error
    }
    finally {
      client.release()
    }
  }

  async function insert(identityId: string, columns: { kind: AuthenticationServiceCredentialKind, secretDigest: string | null, publicKey: ServicePublicKey | null }, at: Date, expiresAt: Date): Promise<AuthenticationServiceCredential> {
    return locked(identityId, async (client) => {
      const { rows } = await client.query(
        `select count(*)::int as n from ${s}."service_credential" where "identity_id" = $1 and "ended_at" is null and "expires_at" > $2`,
        [identityId, at],
      )
      if (Number(rows[0]?.n ?? 0) >= AUTHENTICATION_SERVICE_CREDENTIALS_ACTIVE_MAX) throw new ServiceCredentialLimit()
      const inserted = await client.query(
        `insert into ${s}."service_credential" ("credential_id", "identity_id", "kind", "secret_digest", "public_key", "key_thumbprint", "created_at", "expires_at")
         values ($1, $2, $3, $4, $5::jsonb, $6, $7, $8) returning ${CREDENTIAL_COLUMNS}`,
        [randomUUID(), identityId, columns.kind, columns.secretDigest, columns.publicKey ? JSON.stringify(columns.publicKey) : null,
          columns.publicKey ? keyThumbprint(columns.publicKey) : null, at, expiresAt],
      )
      return toCredential(inserted.rows[0] as unknown as CredentialRow)
    })
  }

  /** Ends every active credential matching `where`, deleting their tokens; returns those it ended. */
  async function end(where: string, values: unknown[], how: AuthenticationServiceCredentialEnding, at: Date): Promise<AuthenticationServiceCredential[]> {
    const { rows } = await query<CredentialRow>(
      `update ${s}."service_credential" set "ended_at" = $${values.length + 1}, "ended_how" = $${values.length + 2}
       where "ended_at" is null and ${where} returning ${CREDENTIAL_COLUMNS}`,
      [...values, at, how],
    )
    if (rows.length > 0) {
      await query(`delete from ${s}."service_token" where "credential_id" = any($1::uuid[])`, [rows.map(row => row.credential_id)])
    }
    return rows.map(toCredential)
  }

  return {
    /** Issues a client secret, returned this once. Refuses a third active credential (`ServiceCredentialLimit`). */
    async issueSecret(identityId: string, at: Date, expiresAt: Date): Promise<AuthenticationIssuedServiceCredential> {
      const clientSecret = randomBytes(32).toString('base64url')
      const credential = await insert(identityId, { kind: 'secret', secretDigest: clientSecretDigest(secret, clientSecret), publicKey: null }, at, expiresAt)
      return { credential, clientSecret }
    },

    /** Registers a public key for signed assertions. Refuses a third active credential, or a key already active for the identity. */
    async registerKey(identityId: string, publicKey: ServicePublicKey, at: Date, expiresAt: Date): Promise<AuthenticationIssuedServiceCredential> {
      const thumbprint = keyThumbprint(publicKey)
      const { rows } = await query(
        `select 1 from ${s}."service_credential" where "identity_id" = $1 and "key_thumbprint" = $2 and "ended_at" is null and "expires_at" > $3`,
        [identityId, thumbprint, at],
      )
      if (rows.length > 0) throw new ServiceCredentialLimit()
      return { credential: await insert(identityId, { kind: 'public-key', secretDigest: null, publicKey }, at, expiresAt), clientSecret: null }
    },

    /** The identity's active credentials, oldest first. */
    async list(identityId: string, at: Date): Promise<AuthenticationServiceCredential[]> {
      const { rows } = await query<CredentialRow>(
        `select ${CREDENTIAL_COLUMNS} from ${s}."service_credential"
         where "identity_id" = $1 and "ended_at" is null and "expires_at" > $2 order by "created_at", "credential_id"`,
        [identityId, at],
      )
      return rows.map(toCredential)
    },

    /** Revokes one of the identity's active credentials, ending its tokens at once; null when it has no such credential. */
    async revoke(identityId: string, credentialId: string, at: Date): Promise<AuthenticationServiceCredential | null> {
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(credentialId)) return null
      const [ended] = await end(`"identity_id" = $1 and "credential_id" = $2`, [identityId, credentialId], 'revoked', at)
      return ended ?? null
    },

    /** Ends the tokens of an identity (suspended or paused): its credentials stay. Returns how many. */
    async endTokens(identityId: string): Promise<number> {
      const { rows } = await query(`with gone as (delete from ${s}."service_token" where "identity_id" = $1 returning 1) select count(*)::int as n from gone`, [identityId])
      return Number((rows[0] as { n?: number } | undefined)?.n ?? 0)
    },

    /** Deletes every credential, token and remembered assertion of a closed identity; returns the credentials that were active. */
    async forget(identityId: string, at: Date): Promise<AuthenticationServiceCredential[]> {
      const ended = await end(`"identity_id" = $1 and "expires_at" > $2`, [identityId, at], 'identity-closed', at)
      await query(`delete from ${s}."service_credential" where "identity_id" = $1`, [identityId])
      await query(`delete from ${s}."service_assertion" where "identity_id" = $1`, [identityId])
      return ended
    },

    /** The active credential a client secret belongs to, for that identity only; null otherwise. */
    async authenticateSecret(identityId: string, clientSecret: string, at: Date): Promise<AuthenticationServiceCredential | null> {
      if (!SERVICE_SECRET_PATTERN.test(clientSecret)) return null
      const presented = clientSecretDigest(secret, clientSecret)
      const { rows } = await query<CredentialRow & { secret_digest: string }>(
        `select ${CREDENTIAL_COLUMNS}, "secret_digest" from ${s}."service_credential"
         where "identity_id" = $1 and "kind" = 'secret' and "ended_at" is null and "expires_at" > $2`,
        [identityId, at],
      )
      const match = rows.find(row => timingSafeEqual(Buffer.from(row.secret_digest, 'hex'), Buffer.from(presented, 'hex')))
      return match ? toCredential(match) : null
    },

    /** The identity's active public keys, for verifying an assertion. */
    async keys(identityId: string, at: Date): Promise<{ credentialId: string, publicKey: ServicePublicKey, keyThumbprint: string }[]> {
      const { rows } = await query<CredentialRow>(
        `select ${CREDENTIAL_COLUMNS} from ${s}."service_credential"
         where "identity_id" = $1 and "kind" = 'public-key' and "ended_at" is null and "expires_at" > $2`,
        [identityId, at],
      )
      return rows.map(row => ({ credentialId: row.credential_id, publicKey: row.public_key!, keyThumbprint: row.key_thumbprint! }))
    },

    /** Remembers an assertion's identifier until it expires; false when it was already used. */
    async rememberAssertion(identityId: string, jti: string, expiresAt: Date, at: Date): Promise<boolean> {
      await query(`delete from ${s}."service_assertion" where "expires_at" <= $1`, [at])
      const { rows } = await query(
        `insert into ${s}."service_assertion" ("identity_id", "jti", "expires_at") values ($1, $2, $3) on conflict do nothing returning 1`,
        [identityId, jti, expiresAt],
      )
      return rows.length === 1
    },

    /** Issues a token for a credential, returned this once. */
    async issueToken(credential: AuthenticationServiceCredential, method: ResolvedServiceToken['method'], at: Date, expiresAt: Date): Promise<{ token: string, tokenId: string }> {
      const token = randomBytes(32).toString('base64url')
      const tokenId = randomUUID()
      await query(
        `insert into ${s}."service_token" ("token_digest", "token_id", "identity_id", "credential_id", "method", "issued_at", "expires_at")
         values ($1, $2, $3, $4, $5, $6, $7)`,
        [serviceTokenDigest(secret, token), tokenId, credential.identityId, credential.credentialId, method, at, expiresAt],
      )
      await query(`update ${s}."service_credential" set "last_used_at" = $2 where "credential_id" = $1`, [credential.credentialId, at])
      return { token, tokenId }
    },

    /** The live token presented, while its credential is active; null otherwise. */
    async resolveToken(token: string, at: Date): Promise<ResolvedServiceToken | null> {
      if (!SERVICE_SECRET_PATTERN.test(token)) return null
      const { rows } = await query<{ token_id: string, identity_id: string, credential_id: string, method: ResolvedServiceToken['method'], issued_at: Date, expires_at: Date }>(
        `select t."token_id", t."identity_id", t."credential_id", t."method", t."issued_at", t."expires_at"
         from ${s}."service_token" t join ${s}."service_credential" c on c."credential_id" = t."credential_id"
         where t."token_digest" = $1 and t."expires_at" > $2 and c."ended_at" is null and c."expires_at" > $2`,
        [serviceTokenDigest(secret, token), at],
      )
      const row = rows[0]
      return row
        ? { tokenId: row.token_id, identityId: row.identity_id, credentialId: row.credential_id, method: row.method, issuedAt: new Date(row.issued_at), expiresAt: new Date(row.expires_at) }
        : null
    },

    /** Marks credentials expiring within `warningDays` as warned and returns them, each once. */
    async warnExpiring(at: Date, warningDays: number): Promise<AuthenticationServiceCredential[]> {
      const { rows } = await query<CredentialRow>(
        `update ${s}."service_credential" set "warned_at" = $1
         where "ended_at" is null and "warned_at" is null and "expires_at" > $1 and "expires_at" <= $1 + make_interval(days => $2)
         returning ${CREDENTIAL_COLUMNS}`,
        [at, warningDays],
      )
      return rows.map(toCredential)
    },

    /** Ends credentials past their expiry, with their tokens, and returns them, each once. */
    expireDue(at: Date): Promise<AuthenticationServiceCredential[]> {
      return end(`"expires_at" <= $1`, [at], 'expired', at)
    },
  }
}

export type ServiceCredentials = ReturnType<typeof createServiceCredentials>
