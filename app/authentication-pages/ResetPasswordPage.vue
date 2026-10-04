<script setup lang="ts">
/** Default page provided by @nuxt4-layers/authentication. Disable with authentication.pages.enabled = false. */

const { t, locale } = useAuthenticationText()
useHead({ title: t('authentication.resetPassword.title'), htmlAttrs: { lang: locale } })
</script>

<template>
  <div :class="authenticationClasses.page">
    <main :class="authenticationClasses.card" aria-labelledby="authentication-page-title">
      <h1 id="authentication-page-title" :class="authenticationClasses.title">{{ t('authentication.resetPassword.title') }}</h1>
      <AuthenticationResetPasswordForm />
    </main>
  </div>
</template>
