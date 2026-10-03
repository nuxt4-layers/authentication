import { defineEventHandler, setResponseHeader } from 'h3'
import { requireAccess } from '../../../internal/guards'
import { requestHeaders } from '../../../internal/http'
import { useAuthenticationRuntime } from '../../../internal/nitro'

/** The principal's linked identity providers, and whether a password is set. */
export default defineEventHandler(async (event) => {
  await requireAccess(event, 'step-up')
  const runtime = await useAuthenticationRuntime()
  const accounts = await runtime.engine.api.listUserAccounts({ headers: requestHeaders(event) }) as { providerId: string, createdAt: Date | string }[]
  setResponseHeader(event, 'cache-control', 'no-store')
  return {
    password: accounts.some(account => account.providerId === 'credential'),
    providers: accounts
      .filter(account => account.providerId !== 'credential')
      .map(account => ({ provider: account.providerId, linkedAt: new Date(account.createdAt).toISOString() })),
  }
})
