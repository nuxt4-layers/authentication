import { betterAuth } from 'better-auth'
import type {
  AuthenticationDatabase,
  AuthenticationEvent,
  AuthenticationMailer,
  AuthenticationMessage,
  AuthenticationPolicy,
} from '../../contracts'
import { createHibpCheck, noCompromisedPasswordCheck, type CompromisedPasswordCheck } from './compromised-password'
import { buildEngineOptions } from './engine-options'
import type { EnabledProvider } from './federation-config'
import { createCredentialRecoveries, type CredentialRecoveries } from './recovery'
import { accountKey, createSignInThrottle, type SignInThrottle } from './throttle'

/**
 * PRIVATE. Assembles the authentication runtime from host-supplied ports and
 * validated configuration. Pure: no Nitro globals, so it is unit-testable.
 */

export interface AuthenticationRoutes {
  signIn: string
  afterSignIn: string
  afterSignOut: string
  resetPassword: string
}

export interface AuthenticationRuntimeInput {
  database: AuthenticationDatabase & { schema: string }
  mailer: AuthenticationMailer
  emit: (event: AuthenticationEvent) => Promise<void>
  policy: AuthenticationPolicy
  secret: string
  baseUrl: string
  locale: string
  /** Shown in authenticator apps and passkey prompts. Defaults to the base URL's host. */
  appName?: string
  /** Enabled identity providers (see federation-config). */
  providers?: readonly EnabledProvider[]
  routes: AuthenticationRoutes
  production: boolean
  fetch?: typeof fetch
}

export interface AuthenticationRuntime {
  engine: ReturnType<typeof createEngine>
  database: AuthenticationDatabase & { schema: string }
  /** The engine secret, also used as the key for backup-code digests. */
  secret: string
  throttle: SignInThrottle
  /** Durable credential recovery records (for Identity's recovery hold). */
  recoveries: CredentialRecoveries
  policy: AuthenticationPolicy
  isCompromisedPassword: CompromisedPasswordCheck
  baseUrl: string
  routes: AuthenticationRoutes
  providers: readonly EnabledProvider[]
  /** Sends a security notification; failures are logged, never thrown. */
  notify(to: string, eventType: AuthenticationEvent['type']): Promise<void>
  emit: (event: AuthenticationEvent) => Promise<void>
}

function createEngine(options: ReturnType<typeof buildEngineOptions>) {
  return betterAuth(options)
}

/** Validates server-only configuration. Throws at startup rather than running insecurely. */
export function validateRuntimeConfig(input: Pick<AuthenticationRuntimeInput, 'secret' | 'baseUrl' | 'production'>): URL {
  if (typeof input.secret !== 'string' || input.secret.length < 32) {
    throw new Error('NUXT_AUTHENTICATION_SECRET must be set to at least 32 characters of random data.')
  }
  let url: URL
  try {
    url = new URL(input.baseUrl)
  }
  catch {
    throw new Error('NUXT_AUTHENTICATION_BASE_URL must be an absolute URL, e.g. https://example.com.')
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  if (input.production && url.protocol !== 'https:' && !loopback) {
    throw new Error('NUXT_AUTHENTICATION_BASE_URL must use https in production (loopback hosts excepted).')
  }
  return url
}

export function systemEvent(type: AuthenticationEvent['type'], principalId: string | null, extra: Partial<AuthenticationEvent> = {}): AuthenticationEvent {
  return {
    type,
    occurredAt: new Date().toISOString(),
    principalId,
    sessionId: null,
    method: null,
    reason: null,
    client: null,
    ...extra,
  }
}

export function createAuthenticationRuntime(input: AuthenticationRuntimeInput): AuthenticationRuntime {
  const url = validateRuntimeConfig(input)
  const origin = url.origin
  const { database, mailer, emit, policy, locale, routes } = input

  const send = async (message: Omit<AuthenticationMessage, 'locale'>) => {
    try {
      await mailer.send({ ...message, locale })
    }
    catch (error) {
      // Mail failures must not reveal account existence through error responses.
      console.error(`[authentication] mailer failed for '${message.kind}':`, error instanceof Error ? error.message : error)
    }
  }

  const notify = (to: string, eventType: AuthenticationEvent['type']) =>
    send({ kind: 'security-notification', to, actionUrl: null, expiresAt: null, eventType })

  const throttle = createSignInThrottle(database.pool, database.schema, policy.signInThrottle)
  const recoveries = createCredentialRecoveries(database.pool, database.schema)

  const engine = createEngine(buildEngineOptions({
    pool: database.pool,
    schema: database.schema,
    secret: input.secret,
    baseUrl: origin,
    appName: input.appName || url.hostname,
    providers: input.providers ?? [],
    policy,
    hooks: {
      async sendVerificationEmail({ email, token }) {
        await send({
          kind: 'email-verification',
          to: email,
          actionUrl: `${origin}/api/authentication/verify-email?token=${encodeURIComponent(token)}`,
          expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
          eventType: null,
        })
      },
      async sendPasswordReset({ userId, email, token }) {
        await send({
          kind: 'password-reset',
          to: email,
          actionUrl: `${origin}${routes.resetPassword}?token=${encodeURIComponent(token)}`,
          expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
          eventType: null,
        })
        await emit(systemEvent('authentication.password-reset-requested', userId))
      },
      async onPasswordReset({ userId, email }) {
        await throttle.clear(accountKey(email))
        // Recorded before anything is announced; a failure fails the reset, so no recovery goes unrecorded.
        await recoveries.record(userId, 'password-reset')
        await emit(systemEvent('authentication.password-reset-completed', userId))
        await emit(systemEvent('authentication.credentials-recovered', userId, { method: 'password', reason: 'password-reset' }))
        await notify(email, 'authentication.password-reset-completed')
      },
      async onAccountRegistered({ userId }) {
        await emit(systemEvent('authentication.account-registered', userId))
      },
      async onEmailVerified({ userId }) {
        await emit(systemEvent('authentication.email-verified', userId))
      },
      async onIdentityLinked({ userId, providerId }) {
        await emit(systemEvent('authentication.federated-identity-linked', userId, { method: 'federated', reason: providerId }))
        const context = await engine.$context
        const user = await context.internalAdapter.findUserById(userId)
        const accounts = await context.internalAdapter.findAccounts(userId)
        // A new sign-in method on an existing account is security relevant; an
        // account created by this very sign-in (its only method) needs no notice.
        if (user && accounts.length > 1) {
          await notify(user.email, 'authentication.federated-identity-linked')
        }
      },
    },
  }))

  return {
    engine,
    database,
    secret: input.secret,
    throttle,
    recoveries,
    policy,
    isCompromisedPassword: policy.password.compromisedCheck === 'hibp-range'
      ? createHibpCheck(input.fetch)
      : noCompromisedPasswordCheck,
    baseUrl: origin,
    routes,
    providers: input.providers ?? [],
    notify,
    emit,
  }
}
