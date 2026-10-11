import type { H3Event } from 'h3'
import { getRequestHeader, getRequestURL } from 'h3'
import { useRuntimeConfig } from '#imports'
import type { AuthenticatedPrincipal, AuthenticationDatabase } from '../../contracts'
import { runAuthenticationMigrations } from '../database/migrations'
import {
  emitAuthenticationEvent,
  useAuthenticationDatabase,
  useAuthenticationIdentity,
  useAuthenticationMailer,
  useAuthenticationPolicy,
} from '../utils/authentication-composition'
import { currentTime } from './clock'
import { authenticationError, forwardCookies, requestHeaders } from './http'
import { absoluteExpiry, toPrincipal, type EngineSessionRecord } from './principal'
import { enabledProviders } from './federation-config'
import { createAuthenticationRuntime, type AuthenticationRuntime } from './runtime'
import { IdentityPortFailure } from './standing'

/** PRIVATE. Binds the pure runtime to Nitro: runtime config, ports and per-request caching. */

let cached: { database: AuthenticationDatabase, runtime: AuthenticationRuntime } | null = null
let migration: Promise<string[]> | null = null

export function startMigrations(): Promise<string[]> {
  const database = useAuthenticationDatabase()
  migration = runAuthenticationMigrations(database.pool, database.schema)
  // Handled here so a host that does not await cannot crash the process with an
  // unhandled rejection. Requests still fail closed: they await the rejection.
  migration.catch((error) => {
    console.error('[authentication] database migrations failed:', error instanceof Error ? error.message : error)
  })
  return migration
}

export async function useAuthenticationRuntime(): Promise<AuthenticationRuntime> {
  if (migration) await migration.catch(() => { throw authenticationError('unavailable') })
  const database = useAuthenticationDatabase()
  if (cached?.database === database) return cached.runtime

  const config = useRuntimeConfig()
  const runtime = createAuthenticationRuntime({
    database,
    mailer: useAuthenticationMailer(),
    emit: emitAuthenticationEvent,
    identity: useAuthenticationIdentity,
    policy: useAuthenticationPolicy(),
    secret: config.authentication.secret,
    baseUrl: config.authentication.baseUrl,
    locale: config.public.authentication.locale,
    appName: config.public.authentication.appName,
    providers: enabledProviders(config.authentication.providers),
    routes: config.public.authentication.routes,
    production: !import.meta.dev,
  })
  cached = { database, runtime }
  return runtime
}

export function trustProxy(): boolean {
  return useRuntimeConfig().authentication.trustProxy === true
}

const CONTEXT_KEY = 'authenticationPrincipal'
const TOKEN_KEY = 'authenticationSessionToken'

/**
 * Outside the layer's own endpoints (a person's session, credentials and
 * pages, which never accept a service token): the bearer token presented, an
 * empty string for a malformed one, or null when there is none.
 */
function bearerToken(event: H3Event): string | null {
  if (getRequestURL(event).pathname.startsWith('/api/authentication/')) return null
  const header = getRequestHeader(event, 'authorization')
  if (!header || !/^Bearer\s/i.test(header)) return null
  return /^Bearer ([A-Za-z0-9_-]{1,200})$/.exec(header)?.[1] ?? ''
}

/**
 * The service principal a bearer token stands for, read with the identity's
 * standing on every request: a suspended or closed service identity is
 * refused at once, and its tokens ended. Null for anything else.
 */
async function servicePrincipal(runtime: AuthenticationRuntime, token: string): Promise<AuthenticatedPrincipal | null> {
  const resolved = await runtime.serviceCredentials.resolveToken(token, currentTime())
  if (!resolved) return null
  // Without an identity port nothing stands behind a service identity.
  if (!runtime.standing.enabled) return null
  let standing
  try {
    standing = await runtime.standing.of(resolved.identityId)
  }
  catch (error) {
    if (error instanceof IdentityPortFailure) throw authenticationError('unavailable')
    throw error
  }
  if (standing.standing !== 'allowed') {
    await runtime.serviceCredentials.endTokens(resolved.identityId)
    return null
  }
  return {
    principalId: resolved.identityId,
    kind: 'service',
    sessionId: resolved.tokenId,
    authenticatedAt: resolved.issuedAt.toISOString(),
    expiresAt: resolved.expiresAt.toISOString(),
    // A service token is a second factor's equal, never phishing-resistant: never enough for `critical`.
    assurance: { level: 'aal2', methods: [resolved.method], phishingResistant: false },
    standing: 'allowed',
  }
}

/**
 * Resolves the current principal once per request: a service identity's
 * bearer token when one is presented (never falling back to a cookie), or
 * else the session. Enforces the absolute session lifetime by signing out
 * sessions past it.
 */
export async function resolvePrincipal(event: H3Event): Promise<AuthenticatedPrincipal | null> {
  if (CONTEXT_KEY in event.context) return event.context[CONTEXT_KEY] as AuthenticatedPrincipal | null

  const runtime = await useAuthenticationRuntime()
  // A bearer token is a service's: it never falls back to a session cookie.
  const bearer = bearerToken(event)
  if (bearer !== null) {
    const principal = bearer === '' ? null : await servicePrincipal(runtime, bearer)
    event.context[CONTEXT_KEY] = principal
    return principal
  }
  const headers = requestHeaders(event)
  const result = await runtime.engine.api.getSession({ headers, returnHeaders: true })
  forwardCookies(event, result.headers)

  let principal: AuthenticatedPrincipal | null = null
  const session = result.response?.session as EngineSessionRecord | undefined
  if (session) {
    const lifetime = runtime.policy.session.absoluteLifetimeSeconds
    if (absoluteExpiry(session, lifetime) <= new Date()) {
      const signOut = await runtime.engine.api.signOut({ headers, returnHeaders: true })
      forwardCookies(event, signOut.headers)
    }
    else {
      // Standing is read on every request: a suspended or closed account loses its session at once.
      let standing
      try {
        standing = await runtime.standing.of(session.userId)
      }
      catch (error) {
        if (error instanceof IdentityPortFailure) throw authenticationError('unavailable')
        throw error
      }
      if (standing.standing === 'refused') {
        const context = await runtime.engine.$context
        await context.internalAdapter.deleteUserSessions(session.userId)
      }
      else {
        principal = toPrincipal(session, lifetime, standing.standing)
        event.context[TOKEN_KEY] = session.token
      }
    }
  }
  event.context[CONTEXT_KEY] = principal
  return principal
}

/** The current session's token, available after a principal has been resolved. Never sent to clients. */
export function currentSessionToken(event: H3Event): string | null {
  return (event.context[TOKEN_KEY] as string | undefined) ?? null
}

/** Clears the per-request cache after the session changes within the same request. */
export function forgetPrincipal(event: H3Event): void {
  delete event.context[CONTEXT_KEY]
  delete event.context[TOKEN_KEY]
}
