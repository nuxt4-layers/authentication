import { defineNuxtPlugin } from '#imports'
import { useAuthentication } from '../composables/useAuthentication'

/** Loads the session before the first navigation, so route middleware never races it. */
export default defineNuxtPlugin({
  name: 'authentication',
  async setup() {
    const { ready, refresh } = useAuthentication()
    if (!ready.value) await refresh()
  },
})
