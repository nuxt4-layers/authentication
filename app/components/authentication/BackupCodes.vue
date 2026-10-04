<script setup lang="ts">
/** PUBLIC. Shows freshly issued backup codes once, until the user confirms they are saved. */
defineProps<{ codes: readonly string[] }>()
const emit = defineEmits<{ saved: [] }>()
const { t } = useAuthenticationText()
const heading = ref<HTMLElement | null>(null)
onMounted(() => heading.value?.focus())
</script>

<template>
  <section :class="authenticationClasses.stack" aria-labelledby="authentication-backup-codes-title">
    <h2 id="authentication-backup-codes-title" ref="heading" tabindex="-1" :class="authenticationClasses.sectionTitle">{{ t('authentication.mfa.backupCodesTitle') }}</h2>
    <p :class="authenticationClasses.text">{{ t('authentication.mfa.backupCodesIntro') }}</p>
    <ol class="grid grid-cols-2 gap-2" data-testid="backup-codes">
      <li v-for="code in codes" :key="code" :class="authenticationClasses.code">{{ code }}</li>
    </ol>
    <button type="button" :class="authenticationClasses.primaryButton" @click="emit('saved')">{{ t('authentication.mfa.backupCodesSaved') }}</button>
  </section>
</template>
