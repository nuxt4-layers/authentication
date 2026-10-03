import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { requireAccess } from '../../../internal/guards'
import { clientInfo, requestHeaders, translateEngineError } from '../../../internal/http'
import { trustProxy, useAuthenticationRuntime } from '../../../internal/nitro'
import { systemEvent } from '../../../internal/runtime'

/** Removes one of the principal's own passkeys. Requires a recent authentication. */
export default defineEventHandler(async (event) => {
  const principal = await requireAccess(event, 'sensitive')
  const id = getRouterParam(event, 'id') ?? ''
  const runtime = await useAuthenticationRuntime()
  try {
    await runtime.engine.api.deletePasskey({ body: { id }, headers: requestHeaders(event) })
  }
  catch (error) {
    throw translateEngineError(error)
  }
  const context = await runtime.engine.$context
  const owner = await context.internalAdapter.findUserById(principal.principalId)
  await runtime.emit(systemEvent('authentication.mfa-removed', principal.principalId, { method: 'passkey', client: clientInfo(event, trustProxy()) }))
  if (owner) await runtime.notify(owner.email, 'authentication.mfa-removed')
  setResponseStatus(event, 204)
  return null
})
