import type { AuthenticationStanding } from './identity'

/**
 * Authenticated principal and session types. Re-exported from the public contract.
 */

/**
 * A way the principal proved who they are during the current session.
 *
 * - `password` — memorised secret.
 * - `totp` — time-based one-time code from an authenticator app.
 * - `backup-code` — single-use recovery code.
 * - `passkey` — WebAuthn/FIDO2 credential (phishing resistant).
 * - `federated` — external identity provider sign-in.
 * - `remembered-device` — the second factor was skipped on a device the user
 *   chose to remember (only when the host enables `rememberedDevice.days`).
 */
export type AuthenticationMethod =
  | 'password'
  | 'totp'
  | 'backup-code'
  | 'passkey'
  | 'federated'
  | 'remembered-device'

/**
 * Authentication assurance level, aligned with NIST SP 800-63-4 terminology.
 *
 * The layer reports the level the session actually achieved. Reporting `aal2`
 * is not by itself a claim that an application conforms to AAL2.
 */
export type AuthenticationAssuranceLevel = 'aal1' | 'aal2'

export interface AuthenticationAssurance {
  level: AuthenticationAssuranceLevel
  /** Methods used to establish the session, in the order they were completed. */
  methods: readonly AuthenticationMethod[]
  /** True when at least one method is phishing resistant (currently `passkey`). */
  phishingResistant: boolean
}

/**
 * The single fact authentication publishes to the rest of the platform:
 * who is signed in, through which session, and how strongly.
 *
 * Authentication is tenant-agnostic. Group, organisation and tenant context
 * belong to Identity and are evaluated by Authorization.
 */
export interface AuthenticatedPrincipal {
  /** Stable, opaque principal identifier. Other capabilities store this value. */
  principalId: string
  /** Opaque identifier of the current session. */
  sessionId: string
  /** ISO 8601 timestamp of the most recent primary or step-up authentication. */
  authenticatedAt: string
  /** ISO 8601 timestamp after which the session is no longer valid. */
  expiresAt: string
  assurance: AuthenticationAssurance
  /**
   * What the account may do, from the identity port: `allowed` unless the
   * host supplies one. A `refused` account never has a principal.
   */
  standing: Exclude<AuthenticationStanding, 'refused'>
}

/** Requirements a protected server operation can place on the current session. */
export interface AuthenticationRequirement {
  /** Minimum assurance level. Defaults to `aal1`. */
  minimumLevel?: AuthenticationAssuranceLevel
  /** Require a phishing-resistant method, for privileged operations. */
  phishingResistant?: boolean
  /** Maximum seconds since `authenticatedAt`; older sessions must re-authenticate. */
  maxAuthenticationAgeSeconds?: number
  /**
   * Standings besides `allowed` that the operation accepts, e.g. `resume-only`
   * for resuming a paused account. Defaults to `allowed` only.
   */
  allowStandings?: readonly Exclude<AuthenticationStanding, 'refused' | 'allowed'>[]
}

/** A session as shown to its owner in an "active sessions" list. */
export interface AuthenticationSessionSummary {
  sessionId: string
  current: boolean
  createdAt: string
  lastActiveAt: string
  expiresAt: string
  /** Coarse, user-presentable client description, e.g. "Firefox on Linux". */
  clientDescription: string | null
}
