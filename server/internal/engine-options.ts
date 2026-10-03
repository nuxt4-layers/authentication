import type { BetterAuthOptions } from 'better-auth'
import { PostgresDialect } from 'kysely'
import type { AuthenticationPolicy, PostgresPoolLike } from '../../contracts'

/**
 * PRIVATE. Builds the authentication engine's options from validated layer
 * configuration. Nothing in this module is part of the public contract.
 */

export interface EngineHooks {
  sendVerificationEmail(input: { email: string, token: string }): Promise<void>
  sendPasswordReset(input: { userId: string, email: string, token: string }): Promise<void>
  onPasswordReset(input: { userId: string, email: string }): Promise<void>
  onAccountRegistered(input: { userId: string }): Promise<void>
  onEmailVerified(input: { userId: string }): Promise<void>
}

export interface EngineConfig {
  pool: PostgresPoolLike
  schema: string
  secret: string
  baseUrl: string
  policy: AuthenticationPolicy
  hooks?: EngineHooks
}

/** Engine routes are never mounted; the layer calls the engine server-side only. */
export const ENGINE_BASE_PATH = '/api/authentication/__engine'

export function buildEngineOptions(config: EngineConfig): BetterAuthOptions {
  const { policy } = config
  return {
    appName: 'authentication',
    secret: config.secret,
    baseURL: config.baseUrl,
    basePath: ENGINE_BASE_PATH,
    telemetry: { enabled: false },
    database: {
      dialect: new PostgresDialect({ pool: config.pool as never }),
      type: 'postgres',
      schemaName: config.schema,
      transaction: true,
    },
    emailAndPassword: {
      enabled: true,
      minPasswordLength: policy.password.minLength,
      maxPasswordLength: policy.password.maxLength,
      requireEmailVerification: policy.emailVerification === 'required',
      autoSignIn: false,
      revokeSessionsOnPasswordReset: true,
      resetPasswordTokenExpiresIn: 30 * 60,
      sendResetPassword: async ({ user, token }) => {
        await config.hooks?.sendPasswordReset({ userId: user.id, email: user.email, token })
      },
      onPasswordReset: async ({ user }) => {
        await config.hooks?.onPasswordReset({ userId: user.id, email: user.email })
      },
    },
    emailVerification: {
      sendOnSignUp: true,
      sendOnSignIn: true,
      autoSignInAfterVerification: false,
      expiresIn: 60 * 60,
      sendVerificationEmail: async ({ user, token }) => {
        await config.hooks?.sendVerificationEmail({ email: user.email, token })
      },
      afterEmailVerification: async (user) => {
        await config.hooks?.onEmailVerified({ userId: user.id })
      },
    },
    verification: {
      // Single-use tokens are stored as hashes, never in plain text.
      storeIdentifier: 'hashed',
    },
    session: {
      // Sliding expiry implements the idle timeout; the absolute lifetime is
      // enforced by the principal resolver from `createdAt`.
      expiresIn: policy.session.idleTimeoutSeconds,
      updateAge: Math.max(60, Math.floor(policy.session.idleTimeoutSeconds / 4)),
      freshAge: policy.reauthentication.maxAgeSeconds,
      cookieCache: { enabled: false },
      additionalFields: {
        authenticatedAt: { type: 'date', required: false, input: false },
        authenticationMethods: { type: 'string', required: false, input: false },
      },
    },
    rateLimit: { enabled: false },
    advanced: {
      useSecureCookies: config.baseUrl.startsWith('https://'),
      cookiePrefix: 'authentication',
      // Data minimisation: session records do not store client IP addresses.
      ipAddress: { disableIpTracking: true },
      defaultCookieAttributes: { httpOnly: true, sameSite: 'lax', path: '/' },
    },
    databaseHooks: {
      user: {
        create: {
          after: async (user) => {
            await config.hooks?.onAccountRegistered({ userId: user.id })
          },
        },
      },
      session: {
        create: {
          before: async session => ({
            data: {
              ...session,
              authenticatedAt: new Date(),
              authenticationMethods: 'password',
            },
          }),
        },
      },
    },
  }
}
