<script setup lang="ts">
/**
 * PUBLIC. Registers a break-glass account's passkey on this device (ADR-0007).
 * The one-time token travels in the link's fragment (`#token`), which browsers
 * never send to a server or in a Referer, and is read here in the browser
 * only. It offers one action and links nowhere: the account has nothing else
 * to do here.
 */
const auth = useAuthentication()
const { disabled, error, submit, t } = useAuthenticationForm()
const token = ref<string | null>(null)
const done = ref(false)

// Read again when only the fragment changes, as when a second link is opened in the same tab.
function readToken() {
  const value = window.location.hash.slice(1)
  token.value = /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null
  if (token.value) {
    done.value = false
    error.value = null
  }
}
onMounted(() => {
  readToken()
  window.addEventListener('hashchange', readToken)
})
onBeforeUnmount(() => window.removeEventListener('hashchange', readToken))

async function register() {
  const result = await submit(() => auth.enrolBreakGlassPasskey(token.value!))
  if (result.ok) {
    done.value = true
    // The token is spent; keep it out of the address bar and history.
    history.replaceState(null, '', window.location.pathname)
  }
}
</script>

<template>
  <div :class="authenticationClasses.stack">
    <AuthenticationAlert v-if="done" tone="success" :focus-on-mount="false">
      <div :class="authenticationClasses.stack">
        <p>{{ t('authentication.breakGlass.done') }}</p>
        <p>{{ t('authentication.breakGlass.storeOffline') }}</p>
      </div>
    </AuthenticationAlert>
    <template v-else-if="token">
      <AuthenticationAlert v-if="error" tone="error" :title="t('authentication.common.errorSummary')">
        <p>{{ error }}</p>
      </AuthenticationAlert>
      <p :class="authenticationClasses.text">{{ t('authentication.breakGlass.intro') }}</p>
      <button type="button" :class="authenticationClasses.primaryButton" :disabled="disabled" @click="register">
        {{ t('authentication.breakGlass.register') }}
      </button>
    </template>
    <AuthenticationAlert v-else tone="info" :focus-on-mount="false">
      <p>{{ t('authentication.breakGlass.missingToken') }}</p>
    </AuthenticationAlert>
  </div>
</template>
