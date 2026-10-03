import { defineEventHandler } from 'h3'
import { requireAccess } from '../../../internal/guards'
import { clientInfo, requestHeaders, translateEngineError } from '../../../internal/http'
import { passwordOnlyBody, readBodyAs } from '../../../internal/input'
import { trustProxy, useAuthenticationRuntime } from '../../../internal/nitro'
import { systemEvent } from '../../../internal/runtime'

/** Replaces every backup code. The new codes are shown once; the old ones stop working. */
export default defineEventHandler(async (event) => {
  const principal = await requireAccess(event, 'sensitive')
  const { password } = await readBodyAs(event, passwordOnlyBody)
  const runtime = await useAuthenticationRuntime()
  let backupCodes: string[]
  try {
    const result = await runtime.engine.api.generateBackupCodes({ body: { password }, headers: requestHeaders(event) }) as { backupCodes: string[] }
    backupCodes = result.backupCodes
  }
  catch (error) {
    throw translateEngineError(error)
  }
  const context = await runtime.engine.$context
  const owner = await context.internalAdapter.findUserById(principal.principalId)
  await runtime.emit(systemEvent('authentication.backup-codes-regenerated', principal.principalId, { client: clientInfo(event, trustProxy()) }))
  if (owner) await runtime.notify(owner.email, 'authentication.backup-codes-regenerated')
  return { backupCodes }
})
