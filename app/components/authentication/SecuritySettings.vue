<script setup lang="ts">
import type { AuthenticationResult, AuthenticationSessionSummary } from '../../../contracts'

/**
 * PUBLIC. Account security: password, authenticator app and backup codes,
 * passkeys, linked providers and sessions. Sensitive actions that need a
 * recent sign-in prompt for re-authentication and then retry.
 */
const routes = useRuntimeConfig().public.authentication.routes
const auth = useAuthentication()
const { disabled, error, submit, messageFor, minLength, t } = useAuthenticationForm()
const status = ref<string | null>(null)

const { data, refresh } = await useAsyncData('authentication:security', async () => {
  const [mfa, accounts, sessions, providers] = await Promise.all([
    auth.mfaStatus(), auth.linkedAccounts(), auth.listSessions(), auth.federationProviders(),
  ])
  return {
    mfa: mfa.ok ? mfa.data : null,
    accounts: accounts.ok ? accounts.data : { password: false, providers: [] },
    sessions: sessions.ok ? sessions.data : [] as AuthenticationSessionSummary[],
    providers: providers.ok ? providers.data : [],
  }
})

// --- Re-authentication around sensitive actions ------------------------------
const reauthNeeded = ref(false)
let retry: (() => Promise<void>) | null = null

async function sensitive<T>(action: () => Promise<AuthenticationResult<T>>, onSuccess: (data: T) => void | Promise<void>) {
  status.value = null
  const result = await submit(action)
  if (!result.ok && result.code === 'reauthentication-required') {
    error.value = null
    retry = () => sensitive(action, onSuccess)
    reauthNeeded.value = true
    return
  }
  if (result.ok) await onSuccess(result.data)
}

async function reauthenticated() {
  reauthNeeded.value = false
  await auth.refresh()
  const next = retry
  retry = null
  await next?.()
}

// --- Password -----------------------------------------------------------------
const current = ref('')
const next = ref('')
const confirm = ref('')
const mismatch = ref<string | null>(null)
async function changePassword() {
  mismatch.value = next.value === confirm.value ? null : t('authentication.common.passwordsDoNotMatch')
  if (mismatch.value) return
  await sensitive(() => auth.changePassword(current.value, next.value), async () => {
    current.value = next.value = confirm.value = ''
    status.value = t('authentication.security.passwordChanged')
    await refresh()
  })
}

// --- Authenticator app and backup codes -----------------------------------------
const enrolling = ref(false)
const factorPassword = ref('')
const freshCodes = ref<string[] | null>(null)
async function disableTotp() {
  await sensitive(() => auth.disableTotp(data.value?.accounts.password ? factorPassword.value : undefined), async () => {
    factorPassword.value = ''
    status.value = t('authentication.security.saved')
    await refresh()
  })
}
async function regenerateCodes() {
  await sensitive(() => auth.regenerateBackupCodes(data.value?.accounts.password ? factorPassword.value : undefined), async (result) => {
    factorPassword.value = ''
    freshCodes.value = result.backupCodes
  })
}
async function enrolled() {
  enrolling.value = false
  status.value = t('authentication.mfa.done')
  await refresh()
}

// --- Passkeys ---------------------------------------------------------------------
const passkeyName = ref('')
async function addPasskey() {
  status.value = null
  const result = await submit(() => auth.registerPasskey(passkeyName.value.trim() || undefined))
  if (result.ok) {
    passkeyName.value = ''
    status.value = t('authentication.security.saved')
    await refresh()
  }
}
async function removePasskey(id: string) {
  await sensitive(() => auth.removePasskey(id), async () => {
    status.value = t('authentication.security.saved')
    await refresh()
  })
}

// --- Providers ------------------------------------------------------------------
const linked = (id: string) => data.value?.accounts.providers.some(account => account.provider === id) ?? false
async function link(id: string) {
  await sensitive(() => auth.linkProvider(id, routes.security), () => {})
}
async function unlink(id: string) {
  await sensitive(() => auth.unlinkProvider(id), async () => {
    status.value = t('authentication.security.saved')
    await refresh()
  })
}

// --- Sessions -------------------------------------------------------------------
const formatter = new Intl.DateTimeFormat(useAuthenticationText().locale, { dateStyle: 'medium', timeStyle: 'short' })
async function revoke(id: string) {
  const result = await submit(() => auth.revokeSession(id))
  if (result.ok) await refresh()
}
async function revokeOthers() {
  const result = await submit(() => auth.revokeOtherSessions())
  if (result.ok) await refresh()
}
async function signOut() {
  await auth.signOut()
  await navigateTo(routes.afterSignOut)
}

const route = useRoute()
const federationNotice = computed(() => {
  const outcome = route.query.federation
  return typeof outcome === 'string' && ['cancelled', 'link-required', 'link-failed', 'failed'].includes(outcome)
    ? t(`authentication.federation.${outcome}`)
    : null
})
</script>

<template>
  <div v-if="data" :class="authenticationClasses.stack">
    <AuthenticationAlert v-if="status" tone="success"><p>{{ status }}</p></AuthenticationAlert>
    <AuthenticationAlert v-if="federationNotice" tone="error" :focus-on-mount="false"><p>{{ federationNotice }}</p></AuthenticationAlert>
    <AuthenticationAlert v-if="error" tone="error" :title="t('authentication.common.errorSummary')"><p>{{ error }}</p></AuthenticationAlert>

    <AuthenticationReauthenticate
      v-if="reauthNeeded"
      :password="data.accounts.password" :totp="Boolean(data.mfa?.totp.enabled)" :passkey="(data.mfa?.passkeys.length ?? 0) > 0"
      @done="reauthenticated"
    />

    <section v-if="data.accounts.password" aria-labelledby="authentication-password-title" :class="authenticationClasses.section">
      <h2 id="authentication-password-title" :class="authenticationClasses.sectionTitle">{{ t('authentication.security.password') }}</h2>
      <form :class="authenticationClasses.stack" method="post" novalidate @submit.prevent="changePassword">
        <AuthenticationField id="authentication-current-password" v-model="current" type="password" autocomplete="current-password" :label="t('authentication.common.currentPassword')" />
        <AuthenticationField
          id="authentication-next-password" v-model="next" type="password" autocomplete="new-password"
          :minlength="minLength" :label="t('authentication.common.newPassword')" :hint="t('authentication.common.passwordHint', { min: minLength })"
        />
        <AuthenticationField id="authentication-confirm-next-password" v-model="confirm" type="password" autocomplete="new-password" :label="t('authentication.common.confirmPassword')" :error="mismatch" />
        <button type="submit" :class="authenticationClasses.primaryButton" :disabled="disabled">{{ t('authentication.security.changePassword') }}</button>
      </form>
    </section>

    <section aria-labelledby="authentication-two-step-title" :class="authenticationClasses.section">
      <h2 id="authentication-two-step-title" :class="authenticationClasses.sectionTitle">{{ t('authentication.security.twoStep') }}</h2>
      <AuthenticationBackupCodes v-if="freshCodes" :codes="freshCodes" @saved="freshCodes = null" />
      <template v-else-if="data.mfa?.totp.enabled">
        <p :class="authenticationClasses.text">{{ t('authentication.security.totpOn') }}</p>
        <p :class="authenticationClasses.muted">{{ t('authentication.security.backupRemaining', { count: data.mfa.backupCodes.remaining }) }}</p>
        <AuthenticationField v-if="data.accounts.password" id="authentication-factor-password" v-model="factorPassword" type="password" autocomplete="current-password" :label="t('authentication.common.password')" />
        <div :class="authenticationClasses.row">
          <button type="button" :class="authenticationClasses.secondaryButton" :disabled="disabled" @click="regenerateCodes">{{ t('authentication.security.backupRegenerate') }}</button>
          <button type="button" :class="authenticationClasses.dangerButton" :disabled="disabled" @click="disableTotp">{{ t('authentication.security.totpDisable') }}</button>
        </div>
      </template>
      <template v-else>
        <p :class="authenticationClasses.text">{{ t('authentication.security.totpOff') }}</p>
        <AuthenticationTotpEnrolment v-if="enrolling" :requires-password="data.accounts.password" @enrolled="enrolled" />
        <button v-else type="button" :class="authenticationClasses.secondaryButton" @click="enrolling = true">{{ t('authentication.security.totpSetUp') }}</button>
      </template>
    </section>

    <section aria-labelledby="authentication-passkeys-title" :class="authenticationClasses.section">
      <h2 id="authentication-passkeys-title" :class="authenticationClasses.sectionTitle">{{ t('authentication.security.passkeys') }}</h2>
      <ul v-if="data.mfa?.passkeys.length" :class="authenticationClasses.list">
        <li v-for="passkey in data.mfa.passkeys" :key="passkey.id" :class="authenticationClasses.listItem">
          <span :class="authenticationClasses.text">{{ passkey.name || t('authentication.security.passkeyUnnamed') }}</span>
          <button type="button" :class="authenticationClasses.dangerButton" :disabled="disabled" @click="removePasskey(passkey.id)">
            {{ t('authentication.security.passkeyRemove', { name: passkey.name || t('authentication.security.passkeyUnnamed') }) }}
          </button>
        </li>
      </ul>
      <p v-else :class="authenticationClasses.muted">{{ t('authentication.security.noPasskeys') }}</p>
      <form :class="[authenticationClasses.stack, 'mt-4']" method="post" novalidate @submit.prevent="addPasskey">
        <AuthenticationField id="authentication-new-passkey-name" v-model="passkeyName" :required="false" :maxlength="64" :label="t('authentication.mfa.passkeyName')" />
        <button type="submit" :class="authenticationClasses.secondaryButton" :disabled="disabled">{{ t('authentication.security.passkeyAdd') }}</button>
      </form>
    </section>

    <section v-if="data.providers.length" aria-labelledby="authentication-providers-title" :class="authenticationClasses.section">
      <h2 id="authentication-providers-title" :class="authenticationClasses.sectionTitle">{{ t('authentication.security.providers') }}</h2>
      <ul :class="authenticationClasses.list">
        <li v-for="provider in data.providers" :key="provider.id" :class="authenticationClasses.listItem">
          <span :class="authenticationClasses.text">{{ linked(provider.id) ? t('authentication.security.providerLinked', { provider: provider.name }) : provider.name }}</span>
          <button v-if="linked(provider.id)" type="button" :class="authenticationClasses.dangerButton" :disabled="disabled" @click="unlink(provider.id)">
            {{ t('authentication.security.providerUnlink', { provider: provider.name }) }}
          </button>
          <button v-else type="button" :class="authenticationClasses.secondaryButton" :disabled="disabled" @click="link(provider.id)">
            {{ t('authentication.security.providerLink', { provider: provider.name }) }}
          </button>
        </li>
      </ul>
    </section>

    <section aria-labelledby="authentication-sessions-title" :class="authenticationClasses.section">
      <h2 id="authentication-sessions-title" :class="authenticationClasses.sectionTitle">{{ t('authentication.security.sessions') }}</h2>
      <ul :class="authenticationClasses.list">
        <li v-for="session in data.sessions" :key="session.sessionId" :class="authenticationClasses.listItem">
          <span :class="authenticationClasses.text">
            {{ session.clientDescription ?? t('authentication.security.unknownDevice') }}
            <strong v-if="session.current"> ({{ t('authentication.security.thisDevice') }})</strong>
            <span :class="['block', authenticationClasses.muted]">{{ t('authentication.security.lastActive', { time: formatter.format(new Date(session.lastActiveAt)) }) }}</span>
          </span>
          <button v-if="!session.current" type="button" :class="authenticationClasses.secondaryButton" :disabled="disabled" @click="revoke(session.sessionId)">
            {{ t('authentication.security.sessionRevoke', { device: session.clientDescription ?? t('authentication.security.unknownDevice') }) }}
          </button>
        </li>
      </ul>
      <div :class="[authenticationClasses.row, 'mt-4']">
        <button v-if="data.sessions.length > 1" type="button" :class="authenticationClasses.secondaryButton" :disabled="disabled" @click="revokeOthers">{{ t('authentication.security.sessionRevokeOthers') }}</button>
        <button type="button" :class="authenticationClasses.dangerButton" @click="signOut">{{ t('authentication.security.signOut') }}</button>
      </div>
    </section>
  </div>
  <AuthenticationAlert v-else tone="error"><p>{{ messageFor('unavailable') }}</p></AuthenticationAlert>
</template>
