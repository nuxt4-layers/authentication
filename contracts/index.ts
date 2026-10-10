/**
 * Public contract for the `@nuxt4-layers/authentication` capability.
 *
 * This module is the only supported cross-layer import path for the layer's
 * types and pure helpers. Everything else in the repository is private.
 *
 * The contract uses the language of authentication. It deliberately exposes no
 * type from the private authentication engine, database driver or ORM, and
 * nothing from the presentation (page text lives in `./presentation`). It is
 * plain TypeScript: it imports nothing from Nuxt, Vue, h3 or the server.
 */

// ---------------------------------------------------------------------------
// Authenticated principal
// ---------------------------------------------------------------------------

export type {
  AuthenticatedPrincipal,
  AuthenticationAssurance,
  AuthenticationAssuranceLevel,
  AuthenticationMethod,
  AuthenticationRequirement,
  AuthenticationSessionSummary,
} from '../shared/principal'
export type { AuthenticationResult } from '../shared/client'

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type { AuthenticationErrorCode, AuthenticationErrorBody } from '../shared/errors'
export {
  AUTHENTICATION_ERROR_CODES,
  AUTHENTICATION_ERROR_STATUS,
  AuthenticationCompositionError,
  isAuthenticationErrorCode,
} from '../shared/errors'

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

export type {
  AuthenticationEvent,
  AuthenticationEventClient,
  AuthenticationEventType,
} from '../shared/events'
export { AUTHENTICATION_EVENT_TYPES } from '../shared/events'

// ---------------------------------------------------------------------------
// Credential recovery
// ---------------------------------------------------------------------------

export type {
  AuthenticationCredentialRecovery,
  AuthenticationCredentialRecoveryPage,
  AuthenticationRecoveryMethod,
} from '../shared/recovery'
export { AUTHENTICATION_RECOVERY_METHODS } from '../shared/recovery'

// ---------------------------------------------------------------------------
// Data-subject export
// ---------------------------------------------------------------------------

export type { AuthenticationDataExport } from '../shared/export'

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export type {
  AuthenticationPolicy,
  AuthenticationPolicyInput,
  AuthenticationPublicPolicy,
} from '../shared/policy'
export {
  DEFAULT_AUTHENTICATION_POLICY,
  publicAuthenticationPolicy,
  resolveAuthenticationPolicy,
} from '../shared/policy'

// ---------------------------------------------------------------------------
// Return paths
// ---------------------------------------------------------------------------

export { safeRedirectPath } from '../shared/redirect'

// ---------------------------------------------------------------------------
// Composition ports (supplied by the host application)
// ---------------------------------------------------------------------------

export type {
  AuthenticationClock,
  AuthenticationDatabase,
  AuthenticationEventSink,
  AuthenticationMailer,
  AuthenticationMessage,
  AuthenticationMessageKind,
  PostgresPoolLike,
} from '../shared/ports'
export { AUTHENTICATION_MESSAGE_KINDS } from '../shared/ports'

// ---------------------------------------------------------------------------
// Identity port (optional)
// ---------------------------------------------------------------------------

export type { AuthenticationAccountStanding, AuthenticationIdentity, AuthenticationStanding } from '../shared/identity'
export { AUTHENTICATION_STANDINGS } from '../shared/identity'
