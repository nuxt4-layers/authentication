import type { PlaygroundIdentity } from '../../plugins/composition'

/** Test-only: the stand-in identity port's state. Absent (404) unless the identity stand-in is on. */
export default defineEventHandler(() => {
  const identity = (globalThis as { __authenticationPlaygroundIdentity?: PlaygroundIdentity }).__authenticationPlaygroundIdentity
  if (!identity) throw createError({ statusCode: 404 })
  return identity
})
