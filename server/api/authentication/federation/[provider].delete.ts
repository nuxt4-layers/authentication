import { defineEventHandler, setResponseStatus } from 'h3'
import { requireAccess } from '../../../internal/guards'
import { authenticationError, clientInfo, requestHeaders, translateEngineError } from '../../../internal/http'
import { routeProvider } from '../../../internal/federation'
import { trustProxy, useAuthenticationRuntime } from '../../../internal/nitro'
import { systemEvent } from '../../../internal/runtime'

/** Unlinks an identity provider. The last way of signing in cannot be removed. */
export default defineEventHandler(async (event) => {
  const principal = await requireAccess(event, 'sensitive')
  const runtime = await useAuthenticationRuntime()
  const provider = routeProvider(event, runtime)
  const headers = requestHeaders(event)
  const accounts = await runtime.engine.api.listUserAccounts({ headers }) as { id: string, providerId: string }[]
  const account = accounts.find(candidate => candidate.providerId === provider.id)
  if (!account) throw authenticationError('validation-failed')
  try {
    await runtime.engine.api.unlinkAccount({ body: { accountId: account.id }, headers })
  }
  catch (error) {
    throw translateEngineError(error)
  }
  const context = await runtime.engine.$context
  const owner = await context.internalAdapter.findUserById(principal.principalId)
  await runtime.emit(systemEvent('authentication.federated-identity-unlinked', principal.principalId, {
    method: 'federated',
    reason: provider.id,
    client: clientInfo(event, trustProxy()),
  }))
  if (owner) await runtime.notify(owner.email, 'authentication.federated-identity-unlinked')
  setResponseStatus(event, 204)
  return null
})
