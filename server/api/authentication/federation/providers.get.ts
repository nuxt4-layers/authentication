import { defineEventHandler } from 'h3'
import { useAuthenticationRuntime } from '../../../internal/nitro'

/** The identity providers this deployment has enabled, for rendering sign-in buttons. */
export default defineEventHandler(async () => {
  const runtime = await useAuthenticationRuntime()
  return { providers: runtime.providers.map(({ id, name }) => ({ id, name })) }
})
