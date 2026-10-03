import { createHmac } from 'node:crypto'
import { passkey } from '@better-auth/passkey'
import type { BetterAuthOptions } from 'better-auth'
import { twoFactor } from 'better-auth/plugins'
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
  /** Name shown in authenticator apps and passkey prompts. */
  appName: string
  hooks?: EngineHooks
}

const HASHED = /^[0-9a-f]{64}$/

/**
 * Backup codes are stored as HMAC-SHA-256 digests keyed with the server secret,
 * never in recoverable form. The layer passes the digest of the submitted code
 * to the engine, whose comparison is then digest against digest.
 */
export function hashBackupCode(secret: string, code: string): string {
  return createHmac('sha256', secret).update(code.trim()).digest('hex')
}

function backupCodeStorage(secret: string) {
  return {
    encrypt: async (json: string) => {
      const codes = JSON.parse(json) as string[]
      return JSON.stringify(codes.map(code => (HASHED.test(code) ? code : hashBackupCode(secret, code))))
    },
    decrypt: async (stored: string) => stored,
  }
}

/** Engine routes are never mounted; the layer calls the engine server-side only. */
export const ENGINE_BASE_PATH = '/api/authentication/__engine'

export function buildEngineOptions(config: EngineConfig) {
  const { policy } = config
  return {
    appName: config.appName,
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
      // Freshness is enforced by the layer from `authenticatedAt`, which step-up
      // re-authentication refreshes; the engine would use `createdAt` instead.
      freshAge: 0,
      cookieCache: { enabled: false },
      additionalFields: {
        authenticatedAt: { type: 'date', required: false, input: false },
        authenticationMethods: { type: 'string', required: false, input: false },
      },
    },
    rateLimit: { enabled: false },
    plugins: [
      twoFactor({
        issuer: config.appName,
        skipVerificationOnEnable: false,
        // Short-lived interim state between the password and the second factor.
        twoFactorCookieMaxAge: 5 * 60,
        // Remembered devices are off unless the policy enables them (days > 0).
        trustDeviceMaxAge: Math.max(1, policy.rememberedDevice.days * 86_400),
        accountLockout: {
          enabled: true,
          maxFailedAttempts: policy.signInThrottle.maxFailedAttempts,
          durationSeconds: policy.signInThrottle.lockoutSeconds,
        },
        backupCodeOptions: {
          amount: 10,
          // 16 characters from a 62-symbol alphabet: about 95 bits of entropy.
          length: 16,
          storeBackupCodes: backupCodeStorage(config.secret),
        },
      }),
      passkey({
        rpID: new URL(config.baseUrl).hostname,
        rpName: config.appName,
        origin: new URL(config.baseUrl).origin,
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: 'required',
        },
      }),
    ],
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
          // Endpoints record the real methods after creation. Rotated sessions
          // carry the previous values; new sessions start with none (aal1).
          before: async (session) => {
            const record = session as typeof session & { authenticatedAt?: Date | null, authenticationMethods?: string | null }
            return {
              data: {
                ...session,
                authenticatedAt: record.authenticatedAt ?? new Date(),
                authenticationMethods: record.authenticationMethods ?? '',
              },
            }
          },
        },
      },
    },
  } satisfies BetterAuthOptions
}
