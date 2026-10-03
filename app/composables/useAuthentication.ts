import { computed, readonly } from 'vue'
import { useRequestFetch, useState } from '#imports'
import type {
  AuthenticatedPrincipal,
  AuthenticationResult,
  AuthenticationSessionSummary,
} from '../../contracts'
import { isAuthenticationErrorCode } from '../../contracts'

/**
 * PUBLIC client composable. Client-side state is for user experience only;
 * every protected operation is enforced on the server.
 */

const BASE = '/api/authentication'

function failure(error: unknown): AuthenticationResult<never> {
  const code = (error as { data?: { data?: { code?: unknown } } } | null)?.data?.data?.code
  return { ok: false, code: isAuthenticationErrorCode(code) ? code : 'unavailable' }
}

export function useAuthentication() {
  const principal = useState<AuthenticatedPrincipal | null>('authentication:principal', () => null)
  const ready = useState<boolean>('authentication:ready', () => false)
  const requestFetch = useRequestFetch()

  async function refresh(): Promise<AuthenticatedPrincipal | null> {
    try {
      const response = await requestFetch<{ principal: AuthenticatedPrincipal | null }>(`${BASE}/session`)
      principal.value = response.principal
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

  return {
    /** The signed-in principal, or null. Read-only; changed through the actions below. */
    principal: readonly(principal),
    isAuthenticated: computed(() => principal.value !== null),
    /** True once the session has been loaded at least once. */
    ready: readonly(ready),
    refresh,

    signUp: (email: string, password: string) =>
      call<{ status: 'accepted' }>('/sign-up', { email, password }),

    async signIn(email: string, password: string) {
      const result = await call<{ status: 'signed-in' }>('/sign-in', { email, password })
      if (result.ok) await refresh()
      return result
    },

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
