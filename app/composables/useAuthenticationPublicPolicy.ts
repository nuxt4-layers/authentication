import { useFetch } from '#imports'
import type { AuthenticationPublicPolicy } from '../../contracts'

/**
 * PUBLIC. The non-secret policy an interface needs to guide users (password
 * length, whether MFA is required), loaded once per request and shared.
 * Interfaces read it here rather than calling the HTTP API themselves.
 */
export function useAuthenticationPublicPolicy() {
  const { data } = useFetch<AuthenticationPublicPolicy>('/api/authentication/policy', {
    key: 'authentication:policy',
    server: true,
    lazy: false,
  })
  return data
}
