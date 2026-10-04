<script setup lang="ts">
/** Default page provided by @nuxt4-layers/authentication. Disable with authentication.pages.enabled = false. */
definePageMeta({ middleware: 'authenticated' })
const { t, locale } = useAuthenticationText()
useHead({ title: t('authentication.security.title'), htmlAttrs: { lang: locale } })
</script>

<template>
  <div :class="authenticationClasses.page">
    <main :class="authenticationClasses.wideCard" aria-labelledby="authentication-page-title">
      <h1 id="authentication-page-title" :class="authenticationClasses.title">{{ t('authentication.security.title') }}</h1>
      <AuthenticationSecuritySettings />
    </main>
  </div>
</template>
