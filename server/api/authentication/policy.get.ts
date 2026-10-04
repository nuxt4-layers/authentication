import { defineEventHandler, setResponseHeader } from 'h3'
import { publicAuthenticationPolicy } from '../../../shared/policy'
import { useAuthenticationPolicy } from '../../utils/authentication-composition'

/** The non-secret parts of the policy that forms need to guide users. */
export default defineEventHandler((event) => {
  setResponseHeader(event, 'cache-control', 'public, max-age=300')
  return publicAuthenticationPolicy(useAuthenticationPolicy())
})
