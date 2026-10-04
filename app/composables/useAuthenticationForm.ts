import type { AuthenticationErrorCode, AuthenticationResult } from '../../contracts'
import { useAuthenticationText } from './useAuthenticationText'

interface PublicPolicy {
  password: { minLength: number, maxLength: number }
  mfa: 'required' | 'optional'
  rememberedDevice: { days: number }
}

/**
 * PUBLIC. Shared state for the layer's forms: a pending flag, the current
 * error message, and the public policy for password guidance.
 */
export function useAuthenticationForm() {
  const { t } = useAuthenticationText()
  const pending = ref(false)
  const error = ref<string | null>(null)
  const { data: policy } = useFetch<PublicPolicy>('/api/authentication/policy', { key: 'authentication:policy', server: true, lazy: false })
  const minLength = computed(() => policy.value?.password.minLength ?? 15)

  function messageFor(code: AuthenticationErrorCode): string {
    return t(`authentication.error.${code}`, { min: minLength.value })
  }

  /** Runs an action, tracking pending state and translating a failure into `error`. */
  async function submit<T>(action: () => Promise<AuthenticationResult<T>>): Promise<AuthenticationResult<T>> {
    pending.value = true
    error.value = null
    try {
      const result = await action()
      if (!result.ok) error.value = messageFor(result.code)
      return result
    }
    finally {
      pending.value = false
    }
  }

  return { pending, error, policy, minLength, messageFor, submit, t }
}
