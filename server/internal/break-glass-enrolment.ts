import type { H3Event } from 'h3'
import { readBody, setResponseHeader } from 'h3'
import { z } from 'zod'
import { ENROLMENT_TOKEN_PATTERN } from './break-glass'
import { authenticationError, clientInfo } from './http'
import { trustProxy } from './nitro'
import type { AuthenticationRuntime } from './runtime'
import { clientKey } from './throttle'

/**
 * PRIVATE. Shared steps of the two token-gated break-glass enrolment endpoints.
 *
 * The engine's passkey registration needs a session (its endpoints use
 * `freshSessionMiddleware`; dropping that is a global switch that would also
 * loosen the session-bound registration, and would bind the user to whatever
 * session cookie the request carries). So these endpoints run the WebAuthn
 * ceremony with `@simplewebauthn/server`, the engine's own WebAuthn library,
 * using exactly the relying party the engine is configured with, and store
 * the credential through the engine's adapter in its passkey table, where its
 * passkey sign-in finds it.
 */

const token = z.string().regex(ENROLMENT_TOKEN_PATTERN)
const webAuthnResponse = z.object({
  id: z.string().min(1).max(1024),
  rawId: z.string().min(1).max(1024),
  type: z.literal('public-key'),
  response: z.record(z.string(), z.unknown()),
}).passthrough()

export const enrolmentOptionsBody = z.object({ token }).strict()
export const enrolmentBody = z.object({ token, response: webAuthnResponse, name: z.string().trim().min(1).max(64).optional() }).strict()

/** The engine's relying party: the passkey plugin's own configuration. */
export function engineRelyingParty(runtime: AuthenticationRuntime): { rpID: string, rpName: string, origin: string } {
  const plugins = (runtime.engine.options as { plugins?: { id: string, options?: Record<string, unknown> }[] }).plugins ?? []
  const options = plugins.find(plugin => plugin.id === 'passkey')?.options
  const { rpID, rpName, origin } = (options ?? {}) as { rpID?: unknown, rpName?: unknown, origin?: unknown }
  if (typeof rpID !== 'string' || typeof rpName !== 'string' || typeof origin !== 'string') throw authenticationError('unavailable')
  return { rpID, rpName, origin }
}

/**
 * The client's throttle, and a refusal that reads the same whatever went
 * wrong (unknown, used or expired token, or a malformed body). Each refusal
 * counts against the client.
 */
export async function enrolmentGuard(event: H3Event, runtime: AuthenticationRuntime) {
  setResponseHeader(event, 'cache-control', 'no-store')
  const client = clientInfo(event, trustProxy())
  const key = client.ipAddress ? clientKey(client.ipAddress) : null
  const limit = runtime.policy.signInThrottle.maxFailedAttemptsPerClient
  if (key && await runtime.throttle.isBlocked(key, limit)) throw authenticationError('rate-limited')

  return {
    client,
    async refuse(): Promise<never> {
      if (key) await runtime.throttle.recordFailure(key, limit)
      throw authenticationError('invalid-or-expired-token')
    },
  }
}

/** The body parsed by `schema`, or null for anything else (never a distinguishable error). */
export async function readEnrolmentBody<T>(event: H3Event, schema: z.ZodType<T>): Promise<T | null> {
  try {
    const result = schema.safeParse(await readBody(event))
    return result.success ? result.data : null
  }
  catch {
    return null
  }
}
