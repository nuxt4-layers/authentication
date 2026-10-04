<script setup lang="ts">
/** PUBLIC. Sets a new password from the emailed single-use token (`?token=`). */
const route = useRoute()
const routes = useRuntimeConfig().public.authentication.routes
const auth = useAuthentication()
const { pending, disabled, error, submit, minLength, t } = useAuthenticationForm()
const token = computed(() => (typeof route.query.token === 'string' ? route.query.token : ''))
const password = ref('')
const confirm = ref('')
const mismatch = ref<string | null>(null)

async function reset() {
  mismatch.value = password.value === confirm.value ? null : t('authentication.common.passwordsDoNotMatch')
  if (mismatch.value) return
  const result = await submit(() => auth.resetPassword(token.value, password.value))
  if (result.ok) await navigateTo({ path: routes.signIn, query: { reset: 'success' } })
}
</script>

<template>
  <div :class="authenticationClasses.stack">
    <AuthenticationAlert v-if="!token" tone="error">
      <p>{{ t('authentication.resetPassword.missingToken') }}</p>
    </AuthenticationAlert>
    <template v-else>
      <AuthenticationAlert v-if="error" tone="error" :title="t('authentication.common.errorSummary')">
        <p>{{ error }}</p>
      </AuthenticationAlert>
      <form :class="authenticationClasses.stack" method="post" novalidate @submit.prevent="reset">
        <AuthenticationField
          id="authentication-new-password" v-model="password" type="password" autocomplete="new-password"
          :minlength="minLength" :label="t('authentication.common.newPassword')" :hint="t('authentication.common.passwordHint', { min: minLength })"
        />
        <AuthenticationField
          id="authentication-confirm-password" v-model="confirm" type="password" autocomplete="new-password"
          :label="t('authentication.common.confirmPassword')" :error="mismatch"
        />
        <button type="submit" :class="authenticationClasses.primaryButton" :disabled="disabled">
          {{ pending ? t('authentication.common.working') : t('authentication.resetPassword.submit') }}
        </button>
      </form>
    </template>
    <p><NuxtLink :to="routes.forgotPassword" :class="authenticationClasses.actionLink">{{ t('authentication.forgotPassword.title') }}</NuxtLink></p>
  </div>
</template>
