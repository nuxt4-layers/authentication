import type { PlaygroundRecorder } from '../../plugins/composition'

/** Test-only: exposes captured mail and events. Absent (404) outside test mode. */
export default defineEventHandler(() => {
  const recorder = (globalThis as { __authenticationPlayground?: PlaygroundRecorder }).__authenticationPlayground
  if (!recorder) throw createError({ statusCode: 404 })
  return recorder
})
