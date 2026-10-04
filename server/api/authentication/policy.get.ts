import { defineEventHandler, setResponseHeader } from 'h3'
import { useAuthenticationPolicy } from '../../utils/authentication-composition'

/** The non-secret parts of the policy that forms need to guide users. */
export default defineEventHandler((event) => {
  const policy = useAuthenticationPolicy()
  setResponseHeader(event, 'cache-control', 'public, max-age=300')
  return {
    password: { minLength: policy.password.minLength, maxLength: policy.password.maxLength },
    mfa: policy.mfa,
    rememberedDevice: { days: policy.rememberedDevice.days },
  }
})
