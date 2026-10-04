/**
 * Public presentation surface of `@nuxt4-layers/authentication`
 * (`@nuxt4-layers/authentication/presentation`).
 *
 * The default pages and form components depend on the contract and the
 * client API (`useAuthentication()`, `useAuthenticationPublicPolicy()`) only.
 * Nothing here is needed to verify who is signed in; that is `./contracts`.
 */

export type { AuthenticationMessageKey, AuthenticationMessages } from './messages'
export { AUTHENTICATION_MESSAGES_EN_GB, formatMessage, resolveMessage } from './messages'
export { authenticationClasses, DELIBERATE_PAIRINGS } from './utils/authentication-classes'
