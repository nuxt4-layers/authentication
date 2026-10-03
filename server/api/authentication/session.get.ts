import { defineEventHandler, setResponseHeader } from 'h3'
import { resolvePrincipal } from '../../internal/nitro'

/** The current principal, or null. Never cached. */
export default defineEventHandler(async (event) => {
  setResponseHeader(event, 'cache-control', 'no-store')
  return { principal: await resolvePrincipal(event) }
})
