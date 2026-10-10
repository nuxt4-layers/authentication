import type { H3Event } from 'h3'
import type { AuthenticationEventClient, AuthenticationMethod } from '../../contracts'
import { authenticationError, forwardCookies } from './http'
import { recordSessionAuthentication } from './mfa'
import { forgetPrincipal } from './nitro'
import { systemEvent, type AuthenticationRuntime } from './runtime'
import { IdentityPortFailure, signInRefusal } from './standing'
import type { ThrottleKey } from './throttle'

/** PRIVATE. Steps shared by every way of completing a sign-in. */

/** The token of the session the request arrived with, if any (for fixation protection). */
export async function previousSessionToken(runtime: AuthenticationRuntime, headers: Headers): Promise<string | null> {
  const previous = await runtime.engine.api.getSession({ headers }).catch(() => null)
  return previous?.session.token ?? null
}

export async function completeSignIn(event: H3Event, runtime: AuthenticationRuntime, input: {
  engineHeaders: Headers | null | undefined
  sessionToken: string
  userId: string
  methods: readonly AuthenticationMethod[]
  previousToken: string | null
  account: ThrottleKey | null
  client: AuthenticationEventClient
}): Promise<void> {
  // The account's standing decides whether the new session may exist at all;
  // a refusal reads like a wrong password, so it reveals nothing. A
  // break-glass account is passkey-only by the layer's own record, whether or
  // not an identity port is supplied.
  let refusal: string | null
  try {
    const standing = await runtime.standing.of(input.userId)
    const breakGlass = await runtime.breakGlass.is(input.userId)
    refusal = signInRefusal(breakGlass ? { ...standing, passkeyOnly: true } : standing, input.methods)
  }
  catch (error) {
    if (!(error instanceof IdentityPortFailure)) throw error
    refusal = 'identity-unavailable'
  }
  if (refusal) {
    const context = await runtime.engine.$context
    await context.internalAdapter.deleteSession(input.sessionToken)
    await runtime.emit(systemEvent('authentication.sign-in-failed', input.userId, { method: input.methods.at(-1) ?? null, reason: refusal, client: input.client }))
    throw authenticationError(refusal === 'identity-unavailable' ? 'unavailable' : 'invalid-credentials')
  }
  await recordSessionAuthentication(runtime, input.sessionToken, input.methods)
  forwardCookies(event, input.engineHeaders)
  // Session fixation: the request's previous session does not survive a new sign-in.
  if (input.previousToken && input.previousToken !== input.sessionToken) {
    const context = await runtime.engine.$context
    await context.internalAdapter.deleteSession(input.previousToken)
  }
  if (input.account) await runtime.throttle.clear(input.account)
  forgetPrincipal(event)
  await runtime.emit(systemEvent('authentication.signed-in', input.userId, {
    method: input.methods.at(-1) ?? null,
    client: input.client,
  }))
}
