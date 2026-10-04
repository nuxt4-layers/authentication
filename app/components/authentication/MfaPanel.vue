<script setup lang="ts">
import { safeRedirectPath } from '../../../shared/redirect'

/**
 * PUBLIC. Brings a session up to the required assurance: steps up with an
 * enrolled factor, or enrols a first one (authenticator app or passkey).
 */
const route = useRoute()
const routes = useRuntimeConfig().public.authentication.routes
const auth = useAuthentication()
const { disabled, error, submit, t } = useAuthenticationForm()
const redirect = computed(() => safeRedirectPath(route.query.redirect, routes.afterSignIn))

const { data: state, refresh: reload } = await useAsyncData('authentication:mfa-state', async () => {
  const [mfa, accounts] = await Promise.all([auth.mfaStatus(), auth.linkedAccounts()])
  return {
    totp: mfa.ok && mfa.data.totp.enabled,
    passkeys: mfa.ok ? mfa.data.passkeys.length : 0,
    password: accounts.ok ? accounts.data.password : true,
  }
})
const enrolled = computed(() => Boolean(state.value && (state.value.totp || state.value.passkeys > 0)))
const choice = ref<'totp' | 'passkey' | null>(null)
const passkeyName = ref('')
const passkeyCreated = ref(false)

async function done() {
  await auth.refresh()
  await navigateTo(redirect.value)
}

async function createPasskey() {
  const result = await submit(() => auth.registerPasskey(passkeyName.value.trim() || undefined))
  if (result.ok) {
    passkeyCreated.value = true
    await reload()
  }
}

async function usePasskey() {
  const result = await submit(() => auth.signInWithPasskey())
  if (result.ok) await done()
}
</script>

<template>
  <div :class="authenticationClasses.stack">
    <AuthenticationAlert v-if="error" tone="error" :title="t('authentication.common.errorSummary')">
      <p>{{ error }}</p>
    </AuthenticationAlert>

    <template v-if="enrolled && !passkeyCreated && state">
      <AuthenticationReauthenticate
        :password="false" :totp="state.totp" :passkey="state.passkeys > 0"
        :intro="t('authentication.mfa.stepUpIntro')" @done="done"
      />
    </template>

    <template v-else-if="passkeyCreated">
      <AuthenticationAlert tone="success"><p>{{ t('authentication.mfa.passkeyCreated') }}</p></AuthenticationAlert>
      <button type="button" :class="authenticationClasses.primaryButton" :disabled="disabled" @click="usePasskey">{{ t('authentication.mfa.passkeyUse') }}</button>
    </template>

    <template v-else-if="state">
      <p :class="authenticationClasses.text">{{ t('authentication.mfa.enrolIntro') }}</p>
      <div v-if="!choice" :class="authenticationClasses.stack">
        <button type="button" :class="authenticationClasses.primaryButton" @click="choice = 'totp'">{{ t('authentication.mfa.chooseTotp') }}</button>
        <button type="button" :class="authenticationClasses.secondaryButton" @click="choice = 'passkey'">{{ t('authentication.mfa.choosePasskey') }}</button>
      </div>
      <AuthenticationTotpEnrolment v-else-if="choice === 'totp'" :requires-password="state.password" @enrolled="done" />
      <form v-else :class="authenticationClasses.stack" method="post" novalidate @submit.prevent="createPasskey">
        <AuthenticationField id="authentication-passkey-name" v-model="passkeyName" :required="false" :maxlength="64" :label="t('authentication.mfa.passkeyName')" />
        <button type="submit" :class="authenticationClasses.primaryButton" :disabled="disabled">{{ t('authentication.mfa.passkeyCreate') }}</button>
      </form>
    </template>
  </div>
</template>
