/**
 * A break-glass account's one-time passkey enrolment (ADR-0007), as returned
 * to the operator by the server-only provisioning and rotation functions.
 */
export interface AuthenticationBreakGlassEnrolment {
  /**
   * 32 random bytes, base64url. Single use; returned once and never stored,
   * logged or put in an event. The operator opens it on the offline device as
   * the enrolment page's fragment: `<enrolment page>#<token>`.
   */
  enrolmentToken: string
  /** ISO 8601 expiry, by the layer's clock. */
  expiresAt: string
}
