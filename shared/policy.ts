import { z } from 'zod'

/**
 * Authentication policy.
 *
 * Defaults are secure by default and oriented toward OWASP ASVS 5.0 Level 2 and
 * NIST SP 800-63-4 AAL2. A host may tighten any value. Loosening a value below
 * the default is permitted only within the floors enforced here, and the
 * host's security documentation MUST record the gap and its risk treatment.
 */
const policySchema = z.object({
  password: z.object({
    /** NIST SP 800-63-4: at least 15 when the password is the only factor; never fewer than 8. */
    minLength: z.int().min(8).max(64),
    /** Must allow at least 64 characters; capped to bound hashing cost. */
    maxLength: z.int().min(64).max(256),
    /**
     * Reject passwords found in breach corpora. `hibp-range` uses the Have I Been
     * Pwned k-anonymity range API, which receives only a 5-character SHA-1 prefix.
     * This is a third-party integration and is documented as such.
     */
    compromisedCheck: z.enum(['hibp-range', 'disabled']),
  }).strict(),

  signInThrottle: z.object({
    /** Failed attempts per account within the window before a temporary lockout. */
    maxFailedAttempts: z.int().min(3).max(100),
    /** Failed attempts per client IP within the window before it is rate limited. Sized for shared NAT addresses. */
    maxFailedAttemptsPerClient: z.int().min(10).max(10_000),
    windowSeconds: z.int().min(60).max(86_400),
    lockoutSeconds: z.int().min(60).max(86_400),
  }).strict(),

  session: z.object({
    /** Inactivity after which the session ends. NIST AAL2 guidance: 1 hour. */
    idleTimeoutSeconds: z.int().min(300).max(2_592_000),
    /** Hard limit regardless of activity. NIST AAL2 guidance: 24 hours. */
    absoluteLifetimeSeconds: z.int().min(900).max(2_592_000),
  }).strict(),

  reauthentication: z.object({
    /** Maximum age of the last authentication for sensitive operations. */
    maxAgeSeconds: z.int().min(60).max(3_600),
  }).strict(),

  /** Whether accounts must enrol a second factor. */
  mfa: z.enum(['required', 'optional']),

  rememberedDevice: z.object({
    /**
     * Days a device may skip the second factor after the user opts in. 0 (the
     * default) disables remembered devices. Enabling it is a documented risk.
     */
    days: z.int().min(0).max(30),
  }).strict(),

  /** Whether an email address must be verified before the first sign-in. */
  emailVerification: z.enum(['required', 'optional']),
}).strict().refine(
  policy => policy.session.idleTimeoutSeconds <= policy.session.absoluteLifetimeSeconds,
  { message: 'session.idleTimeoutSeconds must not exceed session.absoluteLifetimeSeconds', path: ['session'] },
)

export type AuthenticationPolicy = z.infer<typeof policySchema>

/** Partial policy accepted from the host; omitted values take the defaults. */
export type AuthenticationPolicyInput = {
  [K in keyof AuthenticationPolicy]?: AuthenticationPolicy[K] extends string
    ? AuthenticationPolicy[K]
    : Partial<AuthenticationPolicy[K]>
}

export const DEFAULT_AUTHENTICATION_POLICY: Readonly<AuthenticationPolicy> = Object.freeze({
  password: Object.freeze({ minLength: 15, maxLength: 128, compromisedCheck: 'hibp-range' as const }),
  signInThrottle: Object.freeze({ maxFailedAttempts: 5, maxFailedAttemptsPerClient: 50, windowSeconds: 900, lockoutSeconds: 900 }),
  session: Object.freeze({ idleTimeoutSeconds: 3_600, absoluteLifetimeSeconds: 86_400 }),
  reauthentication: Object.freeze({ maxAgeSeconds: 900 }),
  mfa: 'required' as const,
  rememberedDevice: Object.freeze({ days: 0 }),
  emailVerification: 'required' as const,
})

/**
 * Merges host overrides onto the defaults and validates the result.
 * Throws a `ZodError` describing every violation when the policy is invalid.
 */
export function resolveAuthenticationPolicy(input: AuthenticationPolicyInput = {}): AuthenticationPolicy {
  const defaults = DEFAULT_AUTHENTICATION_POLICY
  return policySchema.parse({
    password: { ...defaults.password, ...input.password },
    signInThrottle: { ...defaults.signInThrottle, ...input.signInThrottle },
    session: { ...defaults.session, ...input.session },
    reauthentication: { ...defaults.reauthentication, ...input.reauthentication },
    mfa: input.mfa ?? defaults.mfa,
    rememberedDevice: { ...defaults.rememberedDevice, ...input.rememberedDevice },
    emailVerification: input.emailVerification ?? defaults.emailVerification,
  })
}
