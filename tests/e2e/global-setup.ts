import { OAuth2Server } from 'oauth2-mock-server'
import { IDP_CONTROL_PORT, IDP_PORT } from './constants'

/** Starts the mock OIDC provider for the whole run; identity claims come from the test via /__identity. */
export default async function globalSetup() {
  if (!process.env.AUTHENTICATION_TEST_DATABASE_URL) throw new Error('AUTHENTICATION_TEST_DATABASE_URL must be set for browser tests.')
  const idp = new OAuth2Server()
  await idp.issuer.keys.generate('RS256')
  let identity: Record<string, unknown> = {}
  idp.service.on('beforeTokenSigning', (token) => { Object.assign(token.payload, identity) })
  idp.service.on('beforeUserinfo', (response) => { response.body = { ...identity } })
  // Test-only control endpoint to set the identity the next sign-in returns.
  const server = await import('node:http').then(({ createServer }) => createServer((request, response) => {
    let body = ''
    request.on('data', (chunk) => { body += chunk })
    request.on('end', () => {
      identity = JSON.parse(body || '{}')
      response.end('ok')
    })
  }))
  await new Promise<void>(resolve => server.listen(IDP_CONTROL_PORT, 'localhost', resolve))
  await idp.start(IDP_PORT, 'localhost')
  return async () => {
    await idp.stop()
    server.close()
  }
}
