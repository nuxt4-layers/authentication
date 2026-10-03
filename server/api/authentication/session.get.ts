import { defineEventHandler, setResponseHeader } from 'h3'
import { resolvePrincipal } from '../../internal/nitro'
import { requiredAssuranceLevel } from '../../utils/authentication-principal'

/**
 * The current principal (or null) and the assurance level the policy requires.
 * A principal below `requiredLevel` must enrol or step up a second factor.
 * Never cached.
 */
export default defineEventHandler(async (event) => {
  setResponseHeader(event, 'cache-control', 'no-store')
  return { principal: await resolvePrincipal(event), requiredLevel: requiredAssuranceLevel() }
})
