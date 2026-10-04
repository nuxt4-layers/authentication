import type { AuthenticationErrorCode, AuthenticationResult } from '../../contracts'
import { useAuthenticationPublicPolicy } from '../../app/composables/useAuthenticationPublicPolicy'
import { useAuthenticationText } from './useAuthenticationText'

/**
 * PUBLIC. Shared state for the layer's forms: a pending flag, the current
 * error message, and the public policy for password guidance. `disabled` is
 * also true until the component has hydrated, so a form can never be
 * submitted natively (which would send its fields without the layer's checks).
 */
export function useAuthenticationForm() {
  const { t } = useAuthenticationText()
  const pending = ref(false)
  const hydrated = ref(false)
  onMounted(() => { hydrated.value = true })
  const disabled = computed(() => pending.value || !hydrated.value)
  const error = ref<string | null>(null)
  const policy = useAuthenticationPublicPolicy()
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

  return { pending, disabled, error, policy, minLength, messageFor, submit, t }
}
