import { randomUUID } from 'node:crypto'
import pg from 'pg'
import type { AuthenticationAccountStanding, AuthenticationEvent, AuthenticationMessage } from '../../../contracts'

/**
 * Playground composition root: supplies the authentication ports the way a
 * host application would.
 *
 * Environment:
 * - AUTHENTICATION_DATABASE_URL       PostgreSQL connection string (required to sign in)
 * - AUTHENTICATION_PLAYGROUND_TEST=1  in-memory mailbox/event log for tests; no HIBP calls
 * - AUTHENTICATION_PLAYGROUND_MFA     'required' (default) or 'optional', in test mode
 * - AUTHENTICATION_PLAYGROUND_IDENTITY=1  in test mode, a stand-in identity port
 *   that tests steer through /api/__playground/identity
 *
 * In test mode only, the clock can be moved forward (or made to fail) through
 * /api/__playground/clock. A host never composes a movable clock outside tests.
 */

/** The stand-in identity port's state, for tests. */
export interface PlaygroundIdentity {
  /** Identifiers issued, with the invitation token each reservation carried. */
  reserved: { principalId: string, invitationToken: string | null }[]
  confirmed: string[]
  standings: Record<string, AuthenticationAccountStanding>
  /** When true, every call rejects, as an unreachable port would. */
  failing: boolean
}
/** The test clock: real time plus an offset that only moves forward. */
export interface PlaygroundClock {
  offsetMs: number
  /** When true, `now()` throws, as a failed clock service would. */
  failing: boolean
}
export interface PlaygroundRecorder {
  messages: AuthenticationMessage[]
  events: AuthenticationEvent[]
}

const recorder: PlaygroundRecorder = { messages: [], events: [] }
const testMode = process.env.AUTHENTICATION_PLAYGROUND_TEST === '1'
;(globalThis as { __authenticationPlayground?: PlaygroundRecorder }).__authenticationPlayground = testMode ? recorder : undefined
const identityMode = testMode && process.env.AUTHENTICATION_PLAYGROUND_IDENTITY === '1'
const identity: PlaygroundIdentity = { reserved: [], confirmed: [], standings: {}, failing: false }
;(globalThis as { __authenticationPlaygroundIdentity?: PlaygroundIdentity }).__authenticationPlaygroundIdentity = identityMode ? identity : undefined

const clock: PlaygroundClock = { offsetMs: 0, failing: false }
;(globalThis as { __authenticationPlaygroundClock?: PlaygroundClock }).__authenticationPlaygroundClock = testMode ? clock : undefined

export default defineNitroPlugin(() => {
  const connectionString = process.env.AUTHENTICATION_DATABASE_URL
  if (connectionString) {
    provideAuthenticationDatabase({ dialect: 'postgres', pool: new pg.Pool({ connectionString }) })
    migrateAuthenticationDatabase()
  }

  provideAuthenticationMailer({
    async send(message) {
      if (testMode) recorder.messages.push(message)
      // Never log actionUrl: it carries a single-use secret.
      console.info(`[playground mailer] ${message.kind} to ${message.to} (${message.locale})`)
    },
  })

  provideAuthenticationEventSink({
    emit(event) {
      if (testMode) recorder.events.push(event)
    },
  })

  if (identityMode) {
    const available = () => {
      if (identity.failing) throw new Error('identity port unavailable')
    }
    provideAuthenticationIdentity({
      async reserve({ invitationToken }) {
        available()
        const principalId = randomUUID()
        identity.reserved.push({ principalId, invitationToken })
        identity.standings[principalId] = { standing: 'verification-only', passkeyOnly: false }
        return { principalId }
      },
      async confirm(principalId) {
        available()
        if (!identity.confirmed.includes(principalId)) identity.confirmed.push(principalId)
        if (identity.standings[principalId]?.standing === 'verification-only') identity.standings[principalId] = { standing: 'allowed', passkeyOnly: false }
      },
      async standing(principalId) {
        available()
        return identity.standings[principalId] ?? null
      },
    })
  }

  if (testMode) {
    provideAuthenticationClock({
      now() {
        if (clock.failing) throw new Error('clock unavailable')
        return new Date(Date.now() + clock.offsetMs)
      },
    })
    provideAuthenticationPolicy({
      mfa: process.env.AUTHENTICATION_PLAYGROUND_MFA === 'optional' ? 'optional' : 'required',
      password: { compromisedCheck: 'disabled' },
      signInThrottle: { maxFailedAttempts: 3, maxFailedAttemptsPerClient: 10_000 },
    })
  }
})
