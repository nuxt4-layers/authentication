import type { H3Event } from 'h3'
import { defineEventHandler, getRequestHeader, readRawBody, setResponseHeader, setResponseHeaders, setResponseStatus } from 'h3'
import type { AuthenticationServiceCredential, AuthenticationServiceTokenError, AuthenticationServiceTokenResponse } from '../../../contracts'
import { verifyClientAssertion } from '../../internal/client-assertion'
import { currentTime } from '../../internal/clock'
import { clientInfo } from '../../internal/http'
import { trustProxy, useAuthenticationRuntime } from '../../internal/nitro'
import { systemEvent } from '../../internal/runtime'
import { credentialEvent } from '../../internal/service-endpoints'
import { IdentityPortFailure } from '../../internal/standing'
import { clientKey, serviceKey } from '../../internal/throttle'

/**
 * The service token endpoint (iam-integration's service identities process,
 * "Authenticating"): the OAuth 2.0 client-credentials grant (RFC 6749 §4.4).
 * The client identifier is the service identity's; it authenticates with its
 * secret (HTTP Basic or the body) or a signed assertion (`private_key_jwt`,
 * RFC 7523) for a registered key, whose `jti` is used once. Only an identity
 * whose standing the identity port answers `allowed` receives a token.
 *
 * Every failed client authentication answers `invalid_client`, whatever the
 * reason (an unknown identity, a wrong or expired credential, a replayed
 * assertion, a refused standing, a throttle), and counts against the
 * identity's and the caller's throttles. A service calls it from no browser
 * and it reads no cookie, so it is exempt from the origin check.
 */

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
const CLIENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const MAX_BODY = 8192

const STATUS: Record<AuthenticationServiceTokenError, number> = {
  invalid_request: 400,
  invalid_client: 401,
  unsupported_grant_type: 400,
  temporarily_unavailable: 503,
}

class Refusal extends Error {
  constructor(readonly error: AuthenticationServiceTokenError) {
    super(error)
  }
}

/** The request's parameters, each at most once (RFC 6749 §3.2), from a form or JSON body. */
async function readParameters(event: H3Event): Promise<Map<string, string>> {
  const raw = await readRawBody(event, 'utf8').catch(() => undefined) ?? ''
  if (raw.length > MAX_BODY) throw new Refusal('invalid_request')
  const type = (getRequestHeader(event, 'content-type') ?? '').split(';')[0]!.trim().toLowerCase()
  const parameters = new Map<string, string>()
  if (type === 'application/x-www-form-urlencoded') {
    for (const [name, value] of new URLSearchParams(raw)) {
      if (parameters.has(name)) throw new Refusal('invalid_request')
      parameters.set(name, value)
    }
  }
  else if (type === 'application/json') {
    let body: unknown
    try {
      body = JSON.parse(raw)
    }
    catch {
      throw new Refusal('invalid_request')
    }
    if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new Refusal('invalid_request')
    for (const [name, value] of Object.entries(body)) {
      if (typeof value !== 'string') throw new Refusal('invalid_request')
      parameters.set(name, value)
    }
  }
  else {
    throw new Refusal('invalid_request')
  }
  return parameters
}

type Presented =
  | { method: 'client-secret', clientId: string, secret: string, basic: boolean }
  | { method: 'client-assertion', clientId: string, assertion: string }

/** How the client authenticates: exactly one way (RFC 6749 §2.3). */
function presented(event: H3Event, parameters: Map<string, string>): Presented {
  const header = getRequestHeader(event, 'authorization')
  const bodySecret = parameters.get('client_secret')
  const assertion = parameters.get('client_assertion')
  const assertionType = parameters.get('client_assertion_type')
  const ways = [header !== undefined, bodySecret !== undefined, assertion !== undefined || assertionType !== undefined].filter(Boolean).length
  if (ways !== 1) throw new Refusal(ways === 0 ? 'invalid_client' : 'invalid_request')

  if (header !== undefined) {
    const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(header)
    if (!match) throw new Refusal('invalid_client')
    const decoded = Buffer.from(match[1]!, 'base64').toString('utf8')
    const colon = decoded.indexOf(':')
    if (colon < 0) throw new Refusal('invalid_client')
    let clientId: string, secret: string
    try {
      clientId = decodeURIComponent(decoded.slice(0, colon).replace(/\+/g, ' '))
      secret = decodeURIComponent(decoded.slice(colon + 1).replace(/\+/g, ' '))
    }
    catch {
      throw new Refusal('invalid_client')
    }
    const bodyClient = parameters.get('client_id')
    if (bodyClient !== undefined && bodyClient !== clientId) throw new Refusal('invalid_request')
    return { method: 'client-secret', clientId, secret, basic: true }
  }
  const clientId = parameters.get('client_id')
  if (bodySecret !== undefined) {
    if (clientId === undefined) throw new Refusal('invalid_client')
    return { method: 'client-secret', clientId, secret: bodySecret, basic: false }
  }
  if (assertionType !== ASSERTION_TYPE || !assertion) throw new Refusal('invalid_request')
  // The client identifier is the assertion's issuer; a `client_id` given as well must name it (checked by verification).
  let issuer: unknown
  try {
    issuer = JSON.parse(Buffer.from(assertion.split('.')[1] ?? '', 'base64url').toString('utf8')).iss
  }
  catch {
    throw new Refusal('invalid_client')
  }
  if (typeof issuer !== 'string' || (clientId !== undefined && clientId !== issuer)) throw new Refusal('invalid_client')
  return { method: 'client-assertion', clientId: issuer, assertion }
}

export default defineEventHandler(async (event) => {
  // RFC 6749 §5.1: nothing the endpoint answers is cached.
  setResponseHeaders(event, { 'cache-control': 'no-store', 'pragma': 'no-cache' })
  const refuse = (error: AuthenticationServiceTokenError, basic = false) => {
    setResponseStatus(event, STATUS[error])
    if (error === 'invalid_client' && basic) setResponseHeader(event, 'www-authenticate', 'Basic realm="service-token"')
    return { error }
  }

  const runtime = await useAuthenticationRuntime()
  const { throttle, policy } = runtime
  const client = clientInfo(event, trustProxy())
  const callerKey = client.ipAddress ? clientKey(client.ipAddress) : null

  let parameters: Map<string, string>
  let credentials: Presented
  try {
    parameters = await readParameters(event)
    if (!parameters.has('grant_type')) throw new Refusal('invalid_request')
    if (parameters.get('grant_type') !== 'client_credentials') throw new Refusal('unsupported_grant_type')
    credentials = presented(event, parameters)
  }
  catch (error) {
    if (error instanceof Refusal) return refuse(error.error, getRequestHeader(event, 'authorization') !== undefined)
    throw error
  }
  const basic = credentials.method === 'client-secret' && credentials.basic
  const failed = async (reason: string) => {
    await runtime.emit(systemEvent('authentication.sign-in-failed', null, { method: credentials.method, reason, client }))
    return refuse('invalid_client', basic)
  }

  if (callerKey && await throttle.isBlocked(callerKey, policy.signInThrottle.maxFailedAttemptsPerClient)) return failed('rate-limited')
  const clientId = credentials.clientId
  if (!CLIENT_ID.test(clientId)) {
    if (callerKey) await throttle.recordFailure(callerKey, policy.signInThrottle.maxFailedAttemptsPerClient)
    return failed('invalid-client')
  }
  const identityKey = serviceKey(clientId)
  if (await throttle.isBlocked(identityKey, policy.signInThrottle.maxFailedAttempts)) return failed('account-locked')

  const at = currentTime()
  let credential: AuthenticationServiceCredential | null = null
  if (credentials.method === 'client-secret') {
    credential = await runtime.serviceCredentials.authenticateSecret(clientId, credentials.secret, at)
  }
  else {
    const keys = await runtime.serviceCredentials.keys(clientId, at)
    const verified = keys.length === 0
      ? null
      : verifyClientAssertion({
          assertion: credentials.assertion,
          clientId,
          audience: new URL('/api/authentication/service-token', runtime.baseUrl).href,
          keys,
          now: at,
        })
    // An assertion is used once: a replayed one is refused like a wrong one.
    if (verified && await runtime.serviceCredentials.rememberAssertion(clientId, verified.jti, verified.expiresAt, at)) {
      credential = (await runtime.serviceCredentials.list(clientId, at)).find(found => found.credentialId === verified.credentialId) ?? null
    }
  }
  // Without an identity port nothing stands behind a service identity: no token.
  if (!credential || !runtime.standing.enabled) {
    await throttle.recordFailure(identityKey, policy.signInThrottle.maxFailedAttempts)
    if (callerKey) await throttle.recordFailure(callerKey, policy.signInThrottle.maxFailedAttemptsPerClient)
    return failed('invalid-client')
  }

  let standing
  try {
    standing = await runtime.standing.of(clientId)
  }
  catch (error) {
    if (error instanceof IdentityPortFailure) return refuse('temporarily_unavailable')
    throw error
  }
  if (standing.standing !== 'allowed') {
    await runtime.serviceCredentials.endTokens(clientId)
    return failed('account-refused')
  }

  await throttle.clear(identityKey)
  const lifetime = policy.serviceCredentials.tokenMinutes * 60
  const issued = await runtime.serviceCredentials.issueToken(credential, credentials.method, at, new Date(at.getTime() + lifetime * 1000))
  await runtime.emit(credentialEvent('authentication.service-token-issued', credential, {
    sessionId: issued.tokenId,
    method: credentials.method,
    client,
  }))
  const answer: AuthenticationServiceTokenResponse = { access_token: issued.token, token_type: 'Bearer', expires_in: lifetime }
  return answer
})
