<script setup lang="ts">
definePageMeta({ middleware: 'authenticated' })
const { principal } = useAuthentication()
</script>

<template>
  <main>
    <h1>Protected</h1>
    <p data-testid="principal">{{ principal?.principalId }}</p>
  </main>
</template>
