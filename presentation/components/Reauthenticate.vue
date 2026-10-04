<script setup lang="ts">
/**
 * PUBLIC. Step-up re-authentication with whatever the account has: password,
 * authenticator code or passkey. Emits `done` once the session is fresh.
 */
const props = defineProps<{ password: boolean, totp: boolean, passkey: boolean, intro?: string }>()
const emit = defineEmits<{ done: [] }>()
const auth = useAuthentication()
const { disabled, error, submit, t } = useAuthenticationForm()
const secret = ref('')
const code = ref('')
const heading = ref<HTMLElement | null>(null)
onMounted(() => heading.value?.focus())

async function withPassword() {
  const result = await submit(() => auth.reauthenticate({ method: 'password', password: secret.value }))
  secret.value = ''
  if (result.ok) emit('done')
}
async function withCode() {
  const result = await submit(() => auth.reauthenticate({ method: 'totp', code: code.value.trim() }))
  code.value = ''
  if (result.ok) emit('done')
}
async function withPasskey() {
  const result = await submit(() => auth.signInWithPasskey())
  if (result.ok) emit('done')
}
</script>

<template>
  <section :class="authenticationClasses.stack" aria-labelledby="authentication-reauth-title">
    <h2 id="authentication-reauth-title" ref="heading" tabindex="-1" :class="authenticationClasses.sectionTitle">{{ t('authentication.security.reauthTitle') }}</h2>
    <p :class="authenticationClasses.text">{{ props.intro ?? t('authentication.security.reauthIntro') }}</p>
    <AuthenticationAlert v-if="error" tone="error" :title="t('authentication.common.errorSummary')">
      <p>{{ error }}</p>
    </AuthenticationAlert>
    <form v-if="props.totp" :class="authenticationClasses.stack" method="post" novalidate @submit.prevent="withCode">
      <AuthenticationField id="authentication-reauth-code" v-model="code" inputmode="numeric" autocomplete="one-time-code" :maxlength="6" :label="t('authentication.signIn.code')" />
      <button type="submit" :class="authenticationClasses.primaryButton" :disabled="disabled">{{ t('authentication.security.reauthCode') }}</button>
    </form>
    <form v-if="props.password" :class="authenticationClasses.stack" method="post" novalidate @submit.prevent="withPassword">
      <AuthenticationField id="authentication-reauth-password" v-model="secret" type="password" autocomplete="current-password" :label="t('authentication.common.password')" />
      <button type="submit" :class="props.totp ? authenticationClasses.secondaryButton : authenticationClasses.primaryButton" :disabled="disabled">{{ t('authentication.security.reauthPassword') }}</button>
    </form>
    <button v-if="props.passkey" type="button" :class="authenticationClasses.secondaryButton" :disabled="disabled" @click="withPasskey">
      {{ t('authentication.security.reauthPasskey') }}
    </button>
  </section>
</template>
