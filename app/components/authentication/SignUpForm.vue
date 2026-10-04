<script setup lang="ts">
/**
 * PUBLIC. Email and password sign-up. The confirmation message is the same
 * whether or not the address already has an account.
 */
const props = withDefaults(defineProps<{ showProviders?: boolean }>(), { showProviders: true })
const routes = useRuntimeConfig().public.authentication.routes
const auth = useAuthentication()
const { pending, disabled, error, submit, minLength, t } = useAuthenticationForm()

const email = ref('')
const password = ref('')
const confirm = ref('')
const mismatch = ref<string | null>(null)
const sentTo = ref<string | null>(null)

async function signUp() {
  mismatch.value = password.value === confirm.value ? null : t('authentication.common.passwordsDoNotMatch')
  if (mismatch.value) return
  const result = await submit(() => auth.signUp(email.value.trim(), password.value))
  if (result.ok) {
    sentTo.value = email.value.trim()
    password.value = ''
    confirm.value = ''
  }
}
</script>

<template>
  <div :class="authenticationClasses.stack">
    <AuthenticationAlert v-if="sentTo" tone="success">
      <p>{{ t('authentication.signUp.checkEmail', { email: sentTo }) }}</p>
    </AuthenticationAlert>
    <template v-else>
      <AuthenticationAlert v-if="error" tone="error" :title="t('authentication.common.errorSummary')">
        <p>{{ error }}</p>
      </AuthenticationAlert>
      <form :class="authenticationClasses.stack" method="post" novalidate @submit.prevent="signUp">
        <AuthenticationField id="authentication-email" v-model="email" type="email" inputmode="email" autocomplete="email" :label="t('authentication.common.email')" />
        <AuthenticationField
          id="authentication-new-password" v-model="password" type="password" autocomplete="new-password"
          :minlength="minLength" :label="t('authentication.common.password')" :hint="t('authentication.common.passwordHint', { min: minLength })"
        />
        <AuthenticationField
          id="authentication-confirm-password" v-model="confirm" type="password" autocomplete="new-password"
          :label="t('authentication.common.confirmPassword')" :error="mismatch"
        />
        <button type="submit" :class="authenticationClasses.primaryButton" :disabled="disabled">
          {{ pending ? t('authentication.common.working') : t('authentication.signUp.submit') }}
        </button>
      </form>
      <AuthenticationProviderButtons v-if="props.showProviders" />
    </template>
    <p :class="authenticationClasses.muted">
      {{ t('authentication.signUp.haveAccount') }}
      <NuxtLink :to="routes.signIn" :class="authenticationClasses.link">{{ t('authentication.signIn.title') }}</NuxtLink>
    </p>
  </div>
</template>
