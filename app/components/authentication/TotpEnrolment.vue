<script setup lang="ts">
import { renderSVG } from 'uqr'

/**
 * PUBLIC. Authenticator-app enrolment: password (when the account has one),
 * QR code and setup key, a first code to confirm, then the backup codes.
 */
const props = defineProps<{ requiresPassword: boolean }>()
const emit = defineEmits<{ enrolled: [] }>()
const auth = useAuthentication()
const { disabled, error, submit, t } = useAuthenticationForm()

const stage = ref<'password' | 'scan' | 'codes'>('password')
const password = ref('')
const code = ref('')
const uri = ref('')
const backupCodes = ref<string[]>([])
const qr = computed(() => (uri.value ? renderSVG(uri.value) : ''))
const setupKey = computed(() => (uri.value ? (new URL(uri.value).searchParams.get('secret') ?? '').replace(/(.{4})/g, '$1 ').trim() : ''))

async function start() {
  const result = await submit(() => auth.enrolTotp(props.requiresPassword ? password.value : undefined))
  if (!result.ok) return
  uri.value = result.data.totpUri
  backupCodes.value = result.data.backupCodes
  password.value = ''
  stage.value = 'scan'
}

async function confirm() {
  const result = await submit(() => auth.confirmTotp(code.value.trim()))
  if (result.ok) stage.value = 'codes'
}

onMounted(() => {
  if (!props.requiresPassword) start()
})
</script>

<template>
  <div :class="authenticationClasses.stack">
    <AuthenticationAlert v-if="error" tone="error" :title="t('authentication.common.errorSummary')">
      <p>{{ error }}</p>
    </AuthenticationAlert>

    <form v-if="stage === 'password' && requiresPassword" :class="authenticationClasses.stack" method="post" novalidate @submit.prevent="start">
      <AuthenticationField id="authentication-totp-password" v-model="password" type="password" autocomplete="current-password" :label="t('authentication.common.password')" />
      <button type="submit" :class="authenticationClasses.primaryButton" :disabled="disabled">{{ t('authentication.common.continue') }}</button>
    </form>

    <form v-else-if="stage === 'scan'" :class="authenticationClasses.stack" method="post" novalidate @submit.prevent="confirm">
      <p :class="authenticationClasses.text">{{ t('authentication.mfa.totpScan') }}</p>
      <!-- eslint-disable-next-line vue/no-v-html -- SVG generated locally from the server-issued provisioning URI -->
      <div class="mx-auto w-48 rounded-md bg-fill-base-default p-2" role="img" :aria-label="t('authentication.mfa.totpQrLabel')" v-html="qr" />
      <p :class="authenticationClasses.text">
        {{ t('authentication.mfa.totpKey') }}:
        <code :class="authenticationClasses.code" data-testid="totp-key" :data-uri="uri">{{ setupKey }}</code>
      </p>
      <p :class="authenticationClasses.text">{{ t('authentication.mfa.totpConfirm') }}</p>
      <AuthenticationField id="authentication-totp-code" v-model="code" inputmode="numeric" autocomplete="one-time-code" :maxlength="6" :label="t('authentication.signIn.code')" />
      <button type="submit" :class="authenticationClasses.primaryButton" :disabled="disabled">{{ t('authentication.signIn.verify') }}</button>
    </form>

    <AuthenticationBackupCodes v-else-if="stage === 'codes'" :codes="backupCodes" @saved="emit('enrolled')" />
  </div>
</template>
