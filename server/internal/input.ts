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
