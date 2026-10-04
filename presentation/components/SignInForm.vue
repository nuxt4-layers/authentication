<script setup lang="ts">
import { safeRedirectPath } from '../../contracts'

/**
 * PUBLIC. Complete sign-in: password, second factor, passkey and identity
 * providers. Emits `signed-in` before navigating to the safe redirect target.
 */
const props = withDefaults(defineProps<{ showProviders?: boolean, showPasskey?: boolean }>(), { showProviders: true, showPasskey: true })
const emit = defineEmits<{ 'signed-in': [] }>()

const route = useRoute()
const routes = useRuntimeConfig().public.authentication.routes
const auth = useAuthentication()
const { pending, disabled, error, submit, t } = useAuthenticationForm()

const step = ref<'credentials' | 'second-factor'>('credentials')
const method = ref<'totp' | 'backup-code'>('totp')
const email = ref('')
const password = ref('')
const code = ref('')
const codeField = ref<{ focus: () => void } | null>(null)

const redirect = computed(() => safeRedirectPath(route.query.redirect, routes.afterSignIn))
const notice = computed(() => {
  if (route.query.verification === 'success') return { tone: 'success' as const, text: t('authentication.signIn.verified') }
  if (route.query.verification === 'failed') return { tone: 'error' as const, text: t('authentication.signIn.verificationFailed') }
  if (route.query.reset === 'success') return { tone: 'success' as const, text: t('authentication.signIn.passwordReset') }
  const federation = route.query.federation
  if (typeof federation === 'string' && ['cancelled', 'link-required', 'link-failed', 'failed'].includes(federation)) {
    return { tone: 'error' as const, text: t(`authentication.federation.${federation}`) }
  }
  return null
})

async function finish() {
  emit('signed-in')
  await navigateTo(auth.needsSecondFactor.value ? { path: routes.mfa, query: { redirect: redirect.value } } : redirect.value)
}

async function signIn() {
  const result = await submit(() => auth.signIn(email.value, password.value))
  if (!result.ok) return
  if (result.data.status === 'second-factor-required') {
    password.value = ''
    step.value = 'second-factor'
    await nextTick()
    codeField.value?.focus()
    return
  }
  await finish()
}

async function verify() {
  const result = await submit(() => auth.verifySecondFactor(method.value, code.value.trim()))
  if (result.ok) await finish()
}

async function passkey() {
  const result = await submit(() => auth.signInWithPasskey())
  if (result.ok) await finish()
}

async function switchMethod() {
  method.value = method.value === 'totp' ? 'backup-code' : 'totp'
  code.value = ''
  error.value = null
  await nextTick()
  codeField.value?.focus()
}
</script>

<template>
  <div :class="authenticationClasses.stack">
    <AuthenticationAlert v-if="notice" :tone="notice.tone" :focus-on-mount="false">
      <p>{{ notice.text }}</p>
    </AuthenticationAlert>
    <AuthenticationAlert v-if="error" tone="error" :title="t('authentication.common.errorSummary')">
      <p>{{ error }}</p>
    </AuthenticationAlert>

    <form v-if="step === 'credentials'" :class="authenticationClasses.stack" method="post" novalidate @submit.prevent="signIn">
      <AuthenticationField id="authentication-email" v-model="email" type="email" inputmode="email" autocomplete="username" :label="t('authentication.common.email')" />
      <AuthenticationField id="authentication-password" v-model="password" type="password" autocomplete="current-password" :label="t('authentication.common.password')" />
      <button type="submit" :class="authenticationClasses.primaryButton" :disabled="disabled">
        {{ pending ? t('authentication.common.working') : t('authentication.signIn.submit') }}
      </button>
      <p :class="authenticationClasses.muted">
        <NuxtLink :to="routes.forgotPassword" :class="authenticationClasses.actionLink">{{ t('authentication.signIn.forgotPassword') }}</NuxtLink>
      </p>
    </form>

    <form v-else :class="authenticationClasses.stack" method="post" novalidate aria-labelledby="authentication-second-factor-title" @submit.prevent="verify">
      <h2 id="authentication-second-factor-title" :class="authenticationClasses.sectionTitle">{{ t('authentication.signIn.secondFactorTitle') }}</h2>
      <p :class="authenticationClasses.text">
        {{ method === 'totp' ? t('authentication.signIn.secondFactorIntro') : t('authentication.signIn.backupCodeIntro') }}
      </p>
      <AuthenticationField
        id="authentication-code"
        ref="codeField"
        v-model="code"
        :inputmode="method === 'totp' ? 'numeric' : 'text'"
        autocomplete="one-time-code"
        :maxlength="method === 'totp' ? 6 : 32"
        :label="method === 'totp' ? t('authentication.signIn.code') : t('authentication.signIn.backupCode')"
      />
      <button type="submit" :class="authenticationClasses.primaryButton" :disabled="disabled">
        {{ pending ? t('authentication.common.working') : t('authentication.signIn.verify') }}
      </button>
      <button type="button" :class="authenticationClasses.secondaryButton" @click="switchMethod">
        {{ method === 'totp' ? t('authentication.signIn.useBackupCode') : t('authentication.signIn.useAuthenticator') }}
      </button>
    </form>

    <template v-if="step === 'credentials' && (props.showPasskey || props.showProviders)">
      <p :class="authenticationClasses.divider" aria-hidden="true">
        <span class="h-px flex-1 bg-fill-muted-default" />{{ t('authentication.common.or') }}<span class="h-px flex-1 bg-fill-muted-default" />
      </p>
      <button v-if="props.showPasskey" type="button" :class="[authenticationClasses.secondaryButton, 'w-full']" :disabled="disabled" @click="passkey">
        {{ t('authentication.signIn.passkey') }}
      </button>
      <AuthenticationProviderButtons v-if="props.showProviders" :redirect="redirect" />
    </template>
  </div>
</template>
