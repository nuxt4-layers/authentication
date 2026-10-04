import { useAppConfig, useRuntimeConfig } from '#imports'
import type { AuthenticationMessages } from '../../shared/messages'
import { resolveMessage } from '../../shared/messages'

/**
 * PUBLIC. Localised text for the layer's pages and forms.
 * Hosts override wording or add locales in app.config.ts under `authentication.messages`.
 */
export function useAuthenticationText() {
  const locale = useRuntimeConfig().public.authentication.locale
  const overrides = (useAppConfig() as { authentication?: { messages?: Record<string, AuthenticationMessages> } }).authentication?.messages
  return {
    locale,
    t: (key: string, params?: Record<string, string | number>) => resolveMessage(key, locale, overrides, params),
  }
}
