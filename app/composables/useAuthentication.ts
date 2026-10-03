import { computed, readonly } from 'vue'
import { useRequestFetch, useState } from '#imports'
import type {
  AuthenticatedPrincipal,
  AuthenticationAssuranceLevel,
  AuthenticationResult,
  AuthenticationSessionSummary,
} from '../../contracts'
import { isAuthenticationErrorCode } from '../../contracts'

/**
 * PUBLIC client composable. Client-side state is for user experience only;
 * every protected operation is enforced on the server.
 */

const BASE = '/api/authentication'

export interface MfaStatus {
  requiredLevel: AuthenticationAssuranceLevel
  totp: { enabled: boolean }
  backupCodes: { remaining: number }
  passkeys: { id: string, name: string | null, createdAt: string | null }[]
}

export type SignInOutcome =
  | { status: 'signed-in' }
  | { status: 'second-factor-required', methods: readonly ('totp' | 'backup-code')[] }

function failure(error: unknown): AuthenticationResult<never> {
  const code = (error as { data?: { data?: { code?: unknown } } } | null)?.data?.data?.code
  return { ok: false, code: isAuthenticationErrorCode(code) ? code : 'unavailable' }
}

export function useAuthentication() {
  const principal = useState<AuthenticatedPrincipal | null>('authentication:principal', () => null)
  const requiredLevel = useState<AuthenticationAssuranceLevel>('authentication:required-level', () => 'aal1')
  const ready = useState<boolean>('authentication:ready', () => false)
  const requestFetch = useRequestFetch()

  async function refresh(): Promise<AuthenticatedPrincipal | null> {
    try {
      const response = await requestFetch<{ principal: AuthenticatedPrincipal | null, requiredLevel: AuthenticationAssuranceLevel }>(`${BASE}/session`)
      principal.value = response.principal
      requiredLevel.value = response.requiredLevel
    }
    catch {
      principal.value = null
    }
    ready.value = true
    return principal.value
  }

  async function call<T>(path: string, body?: Record<string, unknown>, method: 'POST' | 'GET' | 'DELETE' = 'POST'): Promise<AuthenticationResult<T>> {
    try {
      const data = await $fetch(`${BASE}${path}`, { method, body }) as T
      return { ok: true, data }
    }
    catch (error) {
      return failure(error)
    }
  }

  /** Runs a WebAuthn ceremony in the browser; a cancelled or failed ceremony maps to `validation-failed`. */
  async function ceremony<T>(run: () => Promise<T>): Promise<AuthenticationResult<T>> {
    try {
      return { ok: true, data: await run() }
    }
    catch {
      return { ok: false, code: 'validation-failed' }
    }
  }

  return {
    /** The signed-in principal, or null. Read-only; changed through the actions below. */
    principal: readonly(principal),
    isAuthenticated: computed(() => principal.value !== null),
    /** The assurance level the policy requires (`aal2` while MFA is required). */
    requiredLevel: readonly(requiredLevel),
    /** True when signed in below the required level: enrol a factor or step up. */
    needsSecondFactor: computed(() => principal.value !== null && requiredLevel.value === 'aal2' && principal.value.assurance.level !== 'aal2'),
    /** True once the session has been loaded at least once. */
    ready: readonly(ready),
    refresh,

    signUp: (email: string, password: string) =>
      call<{ status: 'accepted' }>('/sign-up', { email, password }),

    /** Password sign-in. May answer `second-factor-required`; then call `verifySecondFactor`. */
    async signIn(email: string, password: string) {
      const result = await call<SignInOutcome>('/sign-in', { email, password })
      if (result.ok && result.data.status === 'signed-in') await refresh()
      return result
    },

    /** Completes a sign-in with a TOTP or backup code. */
    async verifySecondFactor(method: 'totp' | 'backup-code', code: string, rememberDevice = false) {
      const result = await call<{ status: 'signed-in' }>('/mfa/verify', { method, code, rememberDevice })
      if (result.ok) await refresh()
      return result
    },

    /** Signs in, or steps up, with a passkey (phishing resistant, aal2). */
    async signInWithPasskey() {
      const options = await call<Record<string, unknown>>('/passkeys/authentication-options')
      if (!options.ok) return options
      const assertion = await ceremony(async () => {
        const { startAuthentication } = await import('@simplewebauthn/browser')
        return startAuthentication({ optionsJSON: options.data as never })
      })
      if (!assertion.ok) return assertion
      const result = await call<{ status: 'signed-in' }>('/passkeys/authentication', { response: assertion.data as never })
      if (result.ok) await refresh()
      return result
    },

    /** Step-up re-authentication with the password or a TOTP code. */
    async reauthenticate(proof: { method: 'password', password: string } | { method: 'totp', code: string }) {
      const result = await call<{ status: 'reauthenticated' }>('/reauthenticate', proof)
      if (result.ok) await refresh()
      return result
    },

    mfaStatus: () => call<MfaStatus>('/mfa', undefined, 'GET'),

    /** Starts TOTP enrolment: returns the provisioning URI and one-time-visible backup codes. */
    enrolTotp: (password: string) =>
      call<{ totpUri: string, backupCodes: string[] }>('/mfa/totp/enrol', { password }),

    async confirmTotp(code: string) {
      const result = await call<{ status: 'totp-enabled' }>('/mfa/totp/confirm', { code })
      if (result.ok) await refresh()
      return result
    },

    async disableTotp(password: string) {
      const result = await call<{ status: 'totp-disabled' }>('/mfa/totp/disable', { password })
      if (result.ok) await refresh()
      return result
    },

    regenerateBackupCodes: (password: string) =>
      call<{ backupCodes: string[] }>('/mfa/backup-codes', { password }),

    /** Registers a passkey on this device for the signed-in account. */
    async registerPasskey(name?: string) {
      const options = await call<Record<string, unknown>>('/passkeys/registration-options')
      if (!options.ok) return options
      const attestation = await ceremony(async () => {
        const { startRegistration } = await import('@simplewebauthn/browser')
        return startRegistration({ optionsJSON: options.data as never })
      })
      if (!attestation.ok) return attestation
      return call<{ status: 'passkey-registered' }>('/passkeys/registration', { response: attestation.data as never, ...(name ? { name } : {}) })
    },

    removePasskey: (id: string) =>
      call<null>(`/passkeys/${encodeURIComponent(id)}`, undefined, 'DELETE'),

    async signOut() {
      const result = await call<{ status: 'signed-out' }>('/sign-out')
      await refresh()
      return result
    },

    requestPasswordReset: (email: string) =>
      call<{ status: 'accepted' }>('/password/forgot', { email }),

    resetPassword: (token: string, password: string) =>
      call<{ status: 'password-reset' }>('/password/reset', { token, password }),

    async changePassword(currentPassword: string, newPassword: string) {
      const result = await call<{ status: 'password-changed' }>('/password/change', { currentPassword, newPassword })
      if (result.ok) await refresh()
      return result
    },

    async listSessions(): Promise<AuthenticationResult<AuthenticationSessionSummary[]>> {
      const result = await call<{ sessions: AuthenticationSessionSummary[] }>('/sessions', undefined, 'GET')
      return result.ok ? { ok: true, data: result.data.sessions } : result
    },

    async revokeSession(sessionId: string) {
      const result = await call<null>(`/sessions/${encodeURIComponent(sessionId)}`, undefined, 'DELETE')
      if (result.ok && sessionId === principal.value?.sessionId) await refresh()
      return result
    },

    revokeOtherSessions: () =>
      call<{ status: 'revoked' }>('/sessions/revoke-others'),
  }
}
