import type { H3Event } from 'h3'
import { readValidatedBody } from 'h3'
import { z } from 'zod'
import { authenticationError } from './http'

/** PRIVATE. Request body schemas and validation for the layer's endpoints. */

export const emailSchema = z.email().max(254)
/** Upper bound protects hashing cost; the policy's own maximum is enforced by the engine. */
export const passwordSchema = z.string().min(1).max(1024)

export const credentialsBody = z.object({ email: emailSchema, password: passwordSchema }).strict()
export const emailBody = z.object({ email: emailSchema }).strict()
export const resetBody = z.object({ token: z.string().min(1).max(512), password: passwordSchema }).strict()
export const changePasswordBody = z.object({ currentPassword: passwordSchema, newPassword: passwordSchema }).strict()

export async function readBodyAs<T>(event: H3Event, schema: z.ZodType<T>): Promise<T> {
  try {
    return await readValidatedBody(event, body => schema.parse(body))
  }
  catch {
    throw authenticationError('validation-failed')
  }
}

export const passwordOnlyBody = z.object({ password: passwordSchema }).strict()
export const totpCodeBody = z.object({ code: z.string().regex(/^\d{6}$/) }).strict()
export const secondFactorBody = z.object({
  method: z.enum(['totp', 'backup-code']),
  code: z.string().min(6).max(64),
  rememberDevice: z.boolean().optional(),
}).strict()
export const reauthenticateBody = z.discriminatedUnion('method', [
  z.object({ method: z.literal('password'), password: passwordSchema }).strict(),
  z.object({ method: z.literal('totp'), code: z.string().regex(/^\d{6}$/) }).strict(),
])
/** A WebAuthn credential JSON from the browser; validated in depth by the engine. */
const webAuthnResponse = z.object({
  id: z.string().min(1).max(1024),
  rawId: z.string().min(1).max(1024),
  type: z.literal('public-key'),
  response: z.record(z.string(), z.unknown()),
}).passthrough()
export const passkeyRegistrationBody = z.object({ response: webAuthnResponse, name: z.string().trim().min(1).max(64).optional() }).strict()
export const passkeyAuthenticationBody = z.object({ response: webAuthnResponse }).strict()
