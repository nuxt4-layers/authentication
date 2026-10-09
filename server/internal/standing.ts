import { AsyncLocalStorage } from 'node:async_hooks'
import type { AuthenticationAccountStanding, AuthenticationIdentity, AuthenticationMethod } from '../../contracts'
import { AUTHENTICATION_STANDINGS } from '../../contracts'

/**
 * PRIVATE. Account standing from the host's identity port. Every failure of
 * the port fails closed: sign-in and requests are `unavailable`, never let
 * through.
 */

export class IdentityPortFailure extends Error {
  constructor(what: string) {
    super(`identity port ${what} failed`)
  }
}

const ALLOWED: AuthenticationAccountStanding = Object.freeze({ standing: 'allowed', passkeyOnly: false })
const REFUSED: AuthenticationAccountStanding = Object.freeze({ standing: 'refused', passkeyOnly: false })

/** Parses whatever the port answered; anything malformed is `refused`. */
function parseStanding(value: unknown): AuthenticationAccountStanding {
  if (value === null || value === undefined) return REFUSED
  const answer = value as Partial<AuthenticationAccountStanding>
  if (!(AUTHENTICATION_STANDINGS as readonly unknown[]).includes(answer.standing) || typeof answer.passkeyOnly !== 'boolean') return REFUSED
  return { standing: answer.standing!, passkeyOnly: answer.passkeyOnly }
}

export interface StandingSource {
  /** The port, read when needed: the host may supply it after the runtime is built. */
  identity: () => AuthenticationIdentity | null
  /** Whether the account's sign-in identifier is verified, for re-confirming a stuck account. */
  isVerified: (principalId: string) => Promise<boolean>
}

export function createStanding(source: StandingSource) {
  async function call<T>(what: string, run: (identity: AuthenticationIdentity) => Promise<T>): Promise<T | null> {
    const identity = source.identity()
    if (!identity) return null
    try {
      return await run(identity)
    }
    catch {
      throw new IdentityPortFailure(what)
    }
  }

  return {
    /** Whether an identity port is supplied. */
    get enabled(): boolean {
      return source.identity() !== null
    },

    /**
     * The account's standing. An account whose identifier is verified but
     * whose confirmation was lost is confirmed again first (idempotent).
     */
    async of(principalId: string): Promise<AuthenticationAccountStanding> {
      if (!source.identity()) return ALLOWED
      let standing = parseStanding(await call('standing', identity => identity.standing(principalId)))
      if (standing.standing === 'verification-only' && await source.isVerified(principalId)) {
        await call('confirm', identity => identity.confirm(principalId))
        standing = parseStanding(await call('standing', identity => identity.standing(principalId)))
      }
      return standing
    },

    /** The principal identifier for a new account, or null to let the engine issue one. */
    async reserve(invitationToken: string | null): Promise<string | null> {
      const reserved = await call('reserve', identity => identity.reserve({ invitationToken }))
      if (reserved === null) return null
      if (typeof reserved?.principalId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(reserved.principalId)) {
        throw new IdentityPortFailure('reserve')
      }
      return reserved.principalId
    },

    async confirm(principalId: string): Promise<void> {
      await call('confirm', identity => identity.confirm(principalId))
    },
  }
}

export type Standing = ReturnType<typeof createStanding>

/**
 * Why a sign-in with `methods` must not complete for an account in `standing`,
 * or null. A break-glass account signs in with a passkey only.
 */
export function signInRefusal(standing: AuthenticationAccountStanding, methods: readonly AuthenticationMethod[]): 'standing-refused' | 'passkey-only' | null {
  if (standing.standing === 'refused') return 'standing-refused'
  if (standing.passkeyOnly && (methods.length !== 1 || methods[0] !== 'passkey')) return 'passkey-only'
  return null
}

/** The invitation token of the sign-up in progress, for the identity port's `reserve`. Never stored or logged. */
export const signUpInvitation = new AsyncLocalStorage<{ invitationToken: string | null }>()
