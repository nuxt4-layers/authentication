import { defineEventHandler } from 'h3'
import { refuseBreakGlass, requireAccess } from '../../../../internal/guards'
import { requestHeaders, translateEngineError } from '../../../../internal/http'
import { passwordOnlyBody, readBodyAs } from '../../../../internal/input'
import { useAuthenticationRuntime } from '../../../../internal/nitro'

/**
 * Starts TOTP enrolment. Returns the provisioning URI (for a QR code) and the
 * backup codes, which are shown once and stored only as keyed digests. TOTP is
 * not active until `POST /mfa/totp/confirm` proves the authenticator works.
 */
export default defineEventHandler(async (event) => {
  await refuseBreakGlass(await requireAccess(event, 'enrolment'))
  const { password } = await readBodyAs(event, passwordOnlyBody)
  const runtime = await useAuthenticationRuntime()
  try {
    const result = await runtime.engine.api.enableTwoFactor({ body: { password }, headers: requestHeaders(event) }) as { totpURI: string, backupCodes: string[] }
    return { totpUri: result.totpURI, backupCodes: result.backupCodes }
  }
  catch (error) {
    throw translateEngineError(error)
  }
})
