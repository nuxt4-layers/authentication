<script setup lang="ts">
const { principal, requiredLevel } = useAuthentication()
</script>

<template>
  <main>
    <h1>Second factor</h1>
    <p data-testid="level">{{ principal?.assurance.level }} of {{ requiredLevel }}</p>
  </main>
</template>
