import type { AuthenticationRuntime } from './runtime'
import { authenticationError } from './http'

/** PRIVATE. Applies the password policy before a new password reaches the engine. */
export async function assertAcceptablePassword(runtime: AuthenticationRuntime, password: string): Promise<void> {
  const { minLength, maxLength } = runtime.policy.password
  // Length is measured in Unicode code points, as NIST SP 800-63B requires.
  const length = [...password].length
  if (length < minLength || length > maxLength) throw authenticationError('password-rejected')
  if (await runtime.isCompromisedPassword(password)) throw authenticationError('password-rejected')
}
