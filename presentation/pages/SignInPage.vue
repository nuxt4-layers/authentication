<script setup lang="ts">
/** Default page provided by @nuxt4-layers/authentication. Disable with authentication.pages.enabled = false. */
definePageMeta({ middleware: 'guest' })
const { t, locale } = useAuthenticationText()
useHead({ title: t('authentication.signIn.title'), htmlAttrs: { lang: locale } })
</script>

<template>
  <div :class="authenticationClasses.page">
    <main :class="authenticationClasses.card" aria-labelledby="authentication-page-title">
      <h1 id="authentication-page-title" :class="authenticationClasses.title">{{ t('authentication.signIn.title') }}</h1>
      <AuthenticationSignInForm />
      <p :class="[authenticationClasses.muted, 'mt-6']">
        {{ t('authentication.signIn.noAccount') }}
        <NuxtLink :to="useRuntimeConfig().public.authentication.routes.signUp" :class="authenticationClasses.link">{{ t('authentication.signIn.createAccount') }}</NuxtLink>
      </p>
    </main>
  </div>
</template>
