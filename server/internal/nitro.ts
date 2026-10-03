import type { H3Event } from 'h3'
import { useRuntimeConfig } from '#imports'
import type { AuthenticatedPrincipal, AuthenticationDatabase } from '../../contracts'
import { runAuthenticationMigrations } from '../database/migrations'
import {
  emitAuthenticationEvent,
  useAuthenticationDatabase,
  useAuthenticationMailer,
  useAuthenticationPolicy,
} from '../utils/authentication-composition'
import { authenticationError, forwardCookies, requestHeaders } from './http'
import { absoluteExpiry, toPrincipal, type EngineSessionRecord } from './principal'
import { enabledProviders } from './federation-config'
import { createAuthenticationRuntime, type AuthenticationRuntime } from './runtime'

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
 * Resolves the current principal once per request. Enforces the absolute
 * session lifetime by signing out sessions past it.
 */
export async function resolvePrincipal(event: H3Event): Promise<AuthenticatedPrincipal | null> {
  if (CONTEXT_KEY in event.context) return event.context[CONTEXT_KEY] as AuthenticatedPrincipal | null

  const runtime = await useAuthenticationRuntime()
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
      principal = toPrincipal(session, lifetime)
      event.context[TOKEN_KEY] = session.token
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
