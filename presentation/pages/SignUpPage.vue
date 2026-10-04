<script setup lang="ts">
/** Default page provided by @nuxt4-layers/authentication. Disable with authentication.pages.enabled = false. */
definePageMeta({ middleware: 'guest' })
const { t, locale } = useAuthenticationText()
useHead({ title: t('authentication.signUp.title'), htmlAttrs: { lang: locale } })
</script>

<template>
  <div :class="authenticationClasses.page">
    <main :class="authenticationClasses.card" aria-labelledby="authentication-page-title">
      <h1 id="authentication-page-title" :class="authenticationClasses.title">{{ t('authentication.signUp.title') }}</h1>
      <AuthenticationSignUpForm />
    </main>
  </div>
</template>
