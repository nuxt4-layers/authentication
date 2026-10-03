/**
 * Playground composition root: supplies the authentication ports the way a
 * host application would. The database port is added once the engine lands.
 */
export default defineNitroPlugin(() => {
  provideAuthenticationMailer({
    async send(message) {
      // Development mailer: never log actionUrl, which carries a single-use secret.
      console.info(`[playground mailer] ${message.kind} to ${message.to} (${message.locale})`)
    },
  })

  provideAuthenticationEventSink({
    emit(event) {
      console.info(`[playground events] ${event.type}`, { principalId: event.principalId, reason: event.reason })
    },
  })
})
