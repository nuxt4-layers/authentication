/**
 * Service credentials (iam-integration's service identities process).
 * Re-exported from the public contract.
 *
 * A service identity is software acting on a group's behalf. Identity holds
 * it; Authentication holds its machine credentials and authenticates it with
 * the OAuth 2.0 client-credentials grant (RFC 6749 §4.4): a client secret,
 * or a signed assertion (`private_key_jwt`, RFC 7523) for a registered
 * public key. The token endpoint answers a short-lived opaque bearer token,
 * looked up, with the identity's standing, on every request.
 */

/**
 * - `secret` — 32 random bytes, returned once, stored only as a keyed digest.
 * - `public-key` — a public JWK (`ES256` on P-256, or `EdDSA` on Ed25519);
 *   only the public key is stored.
 */
export const AUTHENTICATION_SERVICE_CREDENTIAL_KINDS = ['secret', 'public-key'] as const

export type AuthenticationServiceCredentialKind = typeof AUTHENTICATION_SERVICE_CREDENTIAL_KINDS[number]

/** Why a credential stopped working. */
export const AUTHENTICATION_SERVICE_CREDENTIAL_ENDINGS = ['revoked', 'expired', 'identity-closed'] as const

export type AuthenticationServiceCredentialEnding = typeof AUTHENTICATION_SERVICE_CREDENTIAL_ENDINGS[number]

/** At most this many credentials are active for one service identity, so one can be rolled out before the other is revoked. */
export const AUTHENTICATION_SERVICE_CREDENTIALS_ACTIVE_MAX = 2

/** Days before a credential expires that its owners are warned, once. */
export const AUTHENTICATION_SERVICE_CREDENTIAL_WARNING_DAYS = 14

/** A credential as its owners see it: never the secret, and only the key's thumbprint. */
export interface AuthenticationServiceCredential {
  credentialId: string
  /** The service identity it authenticates (Identity's identifier, the OAuth client identifier). */
  identityId: string
  kind: AuthenticationServiceCredentialKind
  /** RFC 7638 SHA-256 thumbprint of a public key; null for a secret. */
  keyThumbprint: string | null
  createdAt: string
  expiresAt: string
  /** When a token was last issued with it, or null. */
  lastUsedAt: string | null
}

/** A newly issued credential: the secret is returned this once, and never again. */
export interface AuthenticationIssuedServiceCredential {
  credential: AuthenticationServiceCredential
  /** For a `secret`: the client secret. Null for a `public-key`. */
  clientSecret: string | null
}

/**
 * The token endpoint's successful answer (RFC 6749 §5.1). The token is
 * opaque; it is never a session and sets no cookie.
 */
export interface AuthenticationServiceTokenResponse {
  access_token: string
  token_type: 'Bearer'
  /** Seconds until the token expires. */
  expires_in: number
}

/** The token endpoint's refusals (RFC 6749 §5.2). Every failed client authentication is `invalid_client`, whatever the reason. */
export const AUTHENTICATION_SERVICE_TOKEN_ERRORS = ['invalid_request', 'invalid_client', 'unsupported_grant_type', 'temporarily_unavailable'] as const

export type AuthenticationServiceTokenError = typeof AUTHENTICATION_SERVICE_TOKEN_ERRORS[number]
