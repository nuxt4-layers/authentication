/**
 * Public contract for the `@nuxt4-layers/authentication` capability.
 *
 * This module is the only supported cross-layer import path for the layer's
 * types and pure helpers. Everything else in the repository is private.
 *
 * The contract uses the language of authentication. It deliberately exposes no
 * type from the private authentication engine, database driver or ORM.
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
// Policy
// ---------------------------------------------------------------------------

export type {
  AuthenticationPolicy,
  AuthenticationPolicyInput,
} from '../shared/policy'
export {
  DEFAULT_AUTHENTICATION_POLICY,
  resolveAuthenticationPolicy,
} from '../shared/policy'

// ---------------------------------------------------------------------------
// Composition ports (supplied by the host application)
// ---------------------------------------------------------------------------

export type {
  AuthenticationDatabase,
  AuthenticationEventSink,
  AuthenticationMailer,
  AuthenticationMessage,
  AuthenticationMessageKind,
  PostgresPoolLike,
} from '../shared/ports'
export { AUTHENTICATION_MESSAGE_KINDS } from '../shared/ports'
