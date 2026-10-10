import { z } from 'zod'
import type { AuthenticationBreakGlassEnrolment } from '../../contracts'
import { breakGlassProvisioning, IDENTITY_ID_PATTERN } from '../internal/break-glass'
import { currentTime } from '../internal/clock'
import { authenticationError } from '../internal/http'
import { emailSchema } from '../internal/input'
import { useAuthenticationRuntime } from '../internal/nitro'
import { systemEvent, type AuthenticationRuntime } from '../internal/runtime'

/**
 * PUBLIC server helpers for break-glass accounts (ADR-0007), auto-imported for
 * the host's server code. Operator functions: server-only, never an endpoint.
 *
 * A break-glass account belongs to a `break-glass` identity Identity
 * provisioned, under the identifier Identity issued. It signs in with a
 * passkey only. Its passkey is enrolled through a one-time token the operator
 * opens on an offline device, and is replaced after each use.
 */

const correlationSchema = z.string().min(1).max(128)

const provisionInput = z.object({
  identityId: z.string().regex(IDENTITY_ID_PATTERN),
  address: emailSchema,
  correlationId: correlationSchema,
}).strict()

const rotateInput = z.object({
  identityId: z.string().regex(IDENTITY_ID_PATTERN),
  correlationId: correlationSchema,
}).strict()

function parse<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input)
  if (!result.success) throw authenticationError('validation-failed')
  return result.data
}

async function issueEnrolment(runtime: AuthenticationRuntime, principalId: string): Promise<AuthenticationBreakGlassEnrolment> {
  const expiresAt = new Date(currentTime().getTime() + runtime.policy.breakGlass.enrolmentTokenMinutes * 60_000)
  const enrolmentToken = await runtime.breakGlass.issue(principalId, expiresAt)
  return { enrolmentToken, expiresAt: expiresAt.toISOString() }
}

/**
 * Creates the passkey-only account of a break-glass identity and returns its
 * first enrolment token. The account's identifier is `identityId` (Identity's,
 * not reserved through the identity port); its sign-in identifier is
 * `address`, which the operator chooses and attests, used only for security
 * notices. It has no password and no other credential. Refuses
 * (`validation-failed`) when an account already exists for the identity or
 * the address. Emits `authentication.break-glass-provisioned`.
 */
export async function provisionAuthenticationBreakGlass(input: { identityId: string, address: string, correlationId: string }): Promise<AuthenticationBreakGlassEnrolment> {
  const { identityId, address } = parse(provisionInput, input)
  const email = address.toLowerCase()
  const runtime = await useAuthenticationRuntime()
  const context = await runtime.engine.$context
  if (await context.internalAdapter.findUserById(identityId) || await context.internalAdapter.findUserByEmail(email)) {
    throw authenticationError('validation-failed')
  }
  const now = currentTime()
  try {
    await breakGlassProvisioning.run({ identityId }, () =>
      context.internalAdapter.createUser({ id: identityId, email, emailVerified: true, name: '', image: null }, { method: 'break-glass' }))
  }
  catch {
    // A concurrent provisioning of the same identity or address.
    throw authenticationError('validation-failed')
  }
  let enrolment: AuthenticationBreakGlassEnrolment
  try {
    await runtime.breakGlass.register(identityId, now)
    enrolment = await issueEnrolment(runtime, identityId)
  }
  catch (error) {
    // Never leave an account that is not known to be passkey-only.
    await context.internalAdapter.deleteUser(identityId).catch(() => {})
    throw error
  }
  await runtime.emit(systemEvent('authentication.break-glass-provisioned', identityId))
  return enrolment
}

/**
 * Rotates a break-glass account's passkey, as after each use (on Identity's
 * `break-glass.used`): replaces any outstanding enrolment token, then deletes
 * every passkey and ends every session, and returns a new token. Refuses
 * (`validation-failed`) for any other account. Emits
 * `authentication.break-glass-rotated`.
 */
export async function rotateAuthenticationBreakGlass(input: { identityId: string, correlationId: string }): Promise<AuthenticationBreakGlassEnrolment> {
  const { identityId } = parse(rotateInput, input)
  const runtime = await useAuthenticationRuntime()
  if (!await runtime.breakGlass.is(identityId)) throw authenticationError('validation-failed')
  const context = await runtime.engine.$context
  // The token first: an enrolment racing this rotation either completed before
  // it (its passkey is deleted below) or finds its token gone and withdraws
  // its passkey itself.
  const enrolment = await issueEnrolment(runtime, identityId)
  await context.adapter.deleteMany({ model: 'passkey', where: [{ field: 'userId', value: identityId }] })
  await context.internalAdapter.deleteUserSessions(identityId)
  await runtime.emit(systemEvent('authentication.break-glass-rotated', identityId))
  return enrolment
}
