import pg from 'pg'
import type { AuthenticationEvent, AuthenticationMessage } from '../../../contracts'

/**
 * Playground composition root: supplies the authentication ports the way a
 * host application would.
 *
 * Environment:
 * - AUTHENTICATION_DATABASE_URL       PostgreSQL connection string (required to sign in)
 * - AUTHENTICATION_PLAYGROUND_TEST=1  in-memory mailbox/event log for tests; no HIBP calls
 * - AUTHENTICATION_PLAYGROUND_MFA     'required' (default) or 'optional', in test mode
 */
export interface PlaygroundRecorder {
  messages: AuthenticationMessage[]
  events: AuthenticationEvent[]
}

const recorder: PlaygroundRecorder = { messages: [], events: [] }
const testMode = process.env.AUTHENTICATION_PLAYGROUND_TEST === '1'
;(globalThis as { __authenticationPlayground?: PlaygroundRecorder }).__authenticationPlayground = testMode ? recorder : undefined

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

  if (testMode) {
    provideAuthenticationPolicy({
      mfa: process.env.AUTHENTICATION_PLAYGROUND_MFA === 'optional' ? 'optional' : 'required',
      password: { compromisedCheck: 'disabled' },
      signInThrottle: { maxFailedAttempts: 3, maxFailedAttemptsPerClient: 10_000 },
    })
  }
})
