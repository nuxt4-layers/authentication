<script setup lang="ts">
/** PUBLIC. "Continue with …" buttons for every enabled identity provider. */
const props = defineProps<{ redirect?: string }>()
const { federationProviders, signInWithProvider } = useAuthentication()
const { t } = useAuthenticationText()
const { data: providers } = await useAsyncData('authentication:providers', async () => {
  const result = await federationProviders()
  return result.ok ? result.data : []
})
</script>

<template>
  <ul v-if="providers?.length" :class="authenticationClasses.stack" role="list">
    <li v-for="provider in providers" :key="provider.id">
      <button
        type="button"
        :class="[authenticationClasses.secondaryButton, 'w-full']"
        @click="signInWithProvider(provider.id, props.redirect)"
      >
        {{ t('authentication.common.continueWithProvider', { provider: provider.name }) }}
      </button>
    </li>
  </ul>
</template>
