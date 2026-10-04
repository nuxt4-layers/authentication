<script setup lang="ts">
/**
 * PUBLIC. A labelled form field with hint, error and (for passwords) a
 * show/hide control. Errors are linked with aria-describedby and aria-invalid.
 */
const props = withDefaults(defineProps<{
  id: string
  label: string
  type?: 'email' | 'password' | 'text'
  autocomplete?: string
  inputmode?: 'numeric' | 'text' | 'email'
  hint?: string
  error?: string | null
  required?: boolean
  minlength?: number
  maxlength?: number
  spellcheck?: boolean
}>(), { type: 'text', required: true, spellcheck: false })

const model = defineModel<string>({ required: true })
const { t } = useAuthenticationText()
const revealed = ref(false)
const input = ref<HTMLInputElement | null>(null)
const effectiveType = computed(() => (props.type === 'password' && revealed.value ? 'text' : props.type))
const describedBy = computed(() => [props.hint && `${props.id}-hint`, props.error && `${props.id}-error`].filter(Boolean).join(' ') || undefined)

defineExpose({ focus: () => input.value?.focus() })
</script>

<template>
  <div>
    <label :for="id" :class="authenticationClasses.label">{{ label }}</label>
    <p v-if="hint" :id="`${id}-hint`" :class="authenticationClasses.hint">{{ hint }}</p>
    <p v-if="error" :id="`${id}-error`" :class="authenticationClasses.fieldError">{{ error }}</p>
    <div class="flex items-center">
      <input
        :id="id"
        ref="input"
        v-model="model"
        :name="id"
        :type="effectiveType"
        :autocomplete="autocomplete"
        :inputmode="inputmode"
        :required="required"
        :minlength="minlength"
        :maxlength="maxlength"
        :spellcheck="spellcheck"
        :aria-invalid="error ? 'true' : undefined"
        :aria-describedby="describedBy"
        autocapitalize="off"
        :class="authenticationClasses.input"
      >
      <button
        v-if="type === 'password'"
        type="button"
        :class="authenticationClasses.toggleButton"
        :aria-controls="id"
        :aria-pressed="revealed ? 'true' : 'false'"
        @click="revealed = !revealed"
      >
        {{ revealed ? t('authentication.common.hidePassword') : t('authentication.common.showPassword') }}
      </button>
    </div>
  </div>
</template>
