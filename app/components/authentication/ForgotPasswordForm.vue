<script setup lang="ts">
/** PUBLIC. Requests a password-reset email; the reply never reveals whether the account exists. */
const routes = useRuntimeConfig().public.authentication.routes
const auth = useAuthentication()
const { pending, disabled, error, submit, t } = useAuthenticationForm()
const email = ref('')
const sentTo = ref<string | null>(null)

async function send() {
  const result = await submit(() => auth.requestPasswordReset(email.value.trim()))
  if (result.ok) sentTo.value = email.value.trim()
}
</script>

<template>
  <div :class="authenticationClasses.stack">
    <AuthenticationAlert v-if="sentTo" tone="success">
      <p>{{ t('authentication.forgotPassword.sent', { email: sentTo }) }}</p>
    </AuthenticationAlert>
    <template v-else>
      <p :class="authenticationClasses.text">{{ t('authentication.forgotPassword.intro') }}</p>
      <AuthenticationAlert v-if="error" tone="error" :title="t('authentication.common.errorSummary')">
        <p>{{ error }}</p>
      </AuthenticationAlert>
      <form :class="authenticationClasses.stack" method="post" novalidate @submit.prevent="send">
        <AuthenticationField id="authentication-email" v-model="email" type="email" inputmode="email" autocomplete="email" :label="t('authentication.common.email')" />
        <button type="submit" :class="authenticationClasses.primaryButton" :disabled="disabled">
          {{ pending ? t('authentication.common.working') : t('authentication.forgotPassword.submit') }}
        </button>
      </form>
    </template>
    <p><NuxtLink :to="routes.signIn" :class="authenticationClasses.actionLink">{{ t('authentication.forgotPassword.backToSignIn') }}</NuxtLink></p>
  </div>
</template>
