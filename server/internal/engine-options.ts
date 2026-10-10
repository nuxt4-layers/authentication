import { createHmac } from 'node:crypto'
import { passkey } from '@better-auth/passkey'
import type { BetterAuthOptions } from 'better-auth'
import { genericOAuth, twoFactor } from 'better-auth/plugins'
import { PostgresDialect } from 'kysely'
import type { AuthenticationPolicy, PostgresPoolLike } from '../../contracts'
import { currentTime } from './clock'
import { federationCallbackUrl, type EnabledProvider } from './federation-config'

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
  onIdentityLinked(input: { userId: string, providerId: string }): Promise<void>
  /** The identifier for a new account from the identity port, or null for the engine's own. Throws to refuse. */
  reserveIdentity(): Promise<string | null>
  /** The account's sign-in identifier is verified. */
  confirmIdentity(input: { userId: string }): Promise<void>
  /** Whether the account is a break-glass account, which holds nothing but passkeys. */
  isBreakGlass(userId: string): Promise<boolean>
}

export interface EngineConfig {
  pool: PostgresPoolLike
  schema: string
  secret: string
  baseUrl: string
  policy: AuthenticationPolicy
  /** Name shown in authenticator apps and passkey prompts. */
  appName: string
  /** Enabled identity providers; empty disables federation. */
  providers?: readonly EnabledProvider[]
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

/** Removes provider-issued tokens from an account record; credential accounts are untouched. */
export function withoutProviderTokens<T extends { providerId?: string }>(account: T): T {
  if (account.providerId === 'credential') return account
  const stripped: Record<string, unknown> = { ...account }
  for (const field of ['accessToken', 'refreshToken', 'idToken', 'accessTokenExpiresAt', 'refreshTokenExpiresAt']) {
    if (field in stripped) stripped[field] = null
  }
  return stripped as T
}

/** Built-in social providers, keyed as the engine expects. */
function socialProviders(origin: string, providers: readonly EnabledProvider[]) {
  const result: Record<string, Record<string, unknown>> = {}
  for (const provider of providers) {
    const common = { clientId: provider.clientId, clientSecret: provider.clientSecret, redirectURI: federationCallbackUrl(origin, provider.id) }
    if (provider.id === 'google') result.google = { ...common, prompt: 'select_account' }
    if (provider.id === 'github') result.github = common
    if (provider.id === 'facebook') result.facebook = common
    if (provider.id === 'microsoft') result.microsoft = { ...common, tenantId: provider.tenantId ?? 'common' }
  }
  return result
}

export function buildEngineOptions(config: EngineConfig) {
  const { policy } = config
  const origin = new URL(config.baseUrl).origin
  const providers = config.providers ?? []
  const oidc = providers.find(provider => provider.id === 'oidc')
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
        await config.hooks?.confirmIdentity({ userId: user.id })
        await config.hooks?.onEmailVerified({ userId: user.id })
      },
    },
    verification: {
      // Single-use tokens are stored as hashes, never in plain text.
      storeIdentifier: 'hashed',
    },
    session: {
      // Sliding expiry implements the idle timeout; the absolute lifetime is
      // enforced by the principal resolver from `createdAt`. Both are the
      // engine's own times, on the system clock.
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
    socialProviders: socialProviders(origin, providers),
    account: {
      // Provider tokens are discarded (see databaseHooks.account); encryption is a second line of defence.
      encryptOAuthTokens: true,
      updateAccountOnSignIn: false,
      accountLinking: {
        // Explicit linking while signed in only: never link by matching email.
        enabled: true,
        disableImplicitLinking: true,
        allowDifferentEmails: true,
        updateUserInfoOnLink: false,
        allowUnlinkingAll: false,
      },
    },
    plugins: [
      twoFactor({
        issuer: config.appName,
        // Accounts created through a provider have no password to confirm with.
        allowPasswordless: true,
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
      ...(oidc
        ? [genericOAuth({
            config: [{
              providerId: 'oidc',
              discoveryUrl: oidc.discoveryUrl!,
              clientId: oidc.clientId,
              clientSecret: oidc.clientSecret,
              scopes: ['openid', 'email', 'profile'],
              pkce: true,
              requireIdTokenVerification: true,
              redirectURI: federationCallbackUrl(origin, 'oidc'),
            }],
          })]
        : []),
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
          // Provider sign-up only with an email the provider has verified.
          // Names and pictures are personal data owned by Profile (ADR-0005):
          // the engine copies them from the provider's profile, so they are
          // blanked here and never stored.
          // With an identity port, the account's identifier is Identity's,
          // reserved before the account exists; a failure refuses the sign-up.
          before: async (user, context) => {
            if (context?.path?.startsWith('/callback/') && !user.emailVerified) return false
            const id = await config.hooks?.reserveIdentity() ?? null
            return { data: { ...user, ...(id ? { id } : {}), name: '', image: null } }
          },
          after: async (user) => {
            // A provider-verified account needs no further verification.
            if (user.emailVerified) await config.hooks?.confirmIdentity({ userId: user.id })
            await config.hooks?.onAccountRegistered({ userId: user.id })
          },
        },
      },
      account: {
        // Data minimisation: the layer needs only the provider's identity, never
        // its tokens. The engine would otherwise keep ID tokens in plain text.
        create: {
          // A break-glass account holds passkeys only: never a password (a reset
          // would otherwise create one) or a provider link.
          before: async (account) => {
            if (account.userId && await config.hooks?.isBreakGlass(account.userId)) return false
            return { data: withoutProviderTokens(account) }
          },
          after: async (account) => {
            if (account.providerId !== 'credential') {
              await config.hooks?.onIdentityLinked({ userId: account.userId, providerId: account.providerId })
            }
          },
        },
        update: {
          before: async account => ({ data: withoutProviderTokens(account) }),
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
                authenticatedAt: record.authenticatedAt ?? currentTime(),
                authenticationMethods: record.authenticationMethods ?? '',
              },
            }
          },
        },
      },
    },
  } satisfies BetterAuthOptions
}
