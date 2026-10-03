import { defineEventHandler, setResponseHeader } from 'h3'
import { requireAccess } from '../../../internal/guards'
import { useAuthenticationRuntime } from '../../../internal/nitro'
import { requiredAssuranceLevel } from '../../../utils/authentication-principal'

/** The principal's second factors. Available to enrol-only sessions. */
export default defineEventHandler(async (event) => {
  const principal = await requireAccess(event, 'step-up')
  const runtime = await useAuthenticationRuntime()
  const context = await runtime.engine.$context
  const totp = await context.adapter.findOne<{ verified: boolean | null, backupCodes: string }>({
    model: 'twoFactor',
    where: [{ field: 'userId', value: principal.principalId }],
  })
  const passkeys = await context.adapter.findMany<{ id: string, name: string | null, createdAt: Date | null }>({
    model: 'passkey',
    where: [{ field: 'userId', value: principal.principalId }],
  })
  const totpEnabled = Boolean(totp && totp.verified !== false)
  setResponseHeader(event, 'cache-control', 'no-store')
  return {
    requiredLevel: requiredAssuranceLevel(),
    totp: { enabled: totpEnabled },
    backupCodes: { remaining: totpEnabled ? (JSON.parse(totp!.backupCodes) as unknown[]).length : 0 },
    passkeys: passkeys.map(passkey => ({
      id: passkey.id,
      name: passkey.name,
      createdAt: passkey.createdAt ? new Date(passkey.createdAt).toISOString() : null,
    })),
  }
})
