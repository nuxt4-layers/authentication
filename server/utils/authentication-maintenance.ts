import type { AuthenticationRetentionCounts } from '../../contracts'
import { AUTHENTICATION_SERVICE_CREDENTIAL_WARNING_DAYS } from '../../contracts'
import { currentTime } from '../internal/clock'
import { useAuthenticationRuntime } from '../internal/nitro'
import { createRetention } from '../internal/retention'
import { systemEvent } from '../internal/runtime'
import { credentialEvent } from '../internal/service-endpoints'
import { useAuthenticationLegalHolds } from './authentication-composition'

/**
 * PUBLIC server helper (auto-imported for the host's server code), server-only:
 * never an endpoint. The host schedules it, as it does every member's
 * maintenance.
 *
 * Applies the policy's retention schedules (iam-integration's retention
 * process): deletes sessions expired more than `retention.sessionDays` ago
 * (by the system clock, the engine's own),
 * break-glass enrolment tokens and verification values expired more than
 * `retention.tokenDays` ago, and credential-recovery records older than
 * `retention.recoveryDays` that no legal hold covers. Emits
 * `authentication.retention-applied` with counts when anything was deleted.
 *
 * Service credentials (iam-integration's service identities): ends those
 * past their expiry, with their tokens
 * (`authentication.service-credential-revoked`, `expired`), and warns once of
 * those expiring within fourteen days
 * (`authentication.service-credential-expiring`), for the host to tell the
 * owning group's owners.
 *
 * A failed run leaves the rest for the next one.
 */
export async function runAuthenticationMaintenance(input: { limit?: number } = {}): Promise<{
  retention: AuthenticationRetentionCounts
  serviceCredentials: { expired: number, expiring: number }
}> {
  const runtime = await useAuthenticationRuntime()
  const at = currentTime()
  const expired = await runtime.serviceCredentials.expireDue(at)
  for (const credential of expired) {
    await runtime.emit(credentialEvent('authentication.service-credential-revoked', credential, { endedHow: 'expired' }))
  }
  const expiring = await runtime.serviceCredentials.warnExpiring(at, AUTHENTICATION_SERVICE_CREDENTIAL_WARNING_DAYS)
  for (const credential of expiring) {
    await runtime.emit(credentialEvent('authentication.service-credential-expiring', credential))
  }
  const retention = await createRetention(runtime.database.pool, runtime.database.schema).apply({
    at,
    // The engine keeps session and verification expiries on the system clock.
    engineAt: new Date(),
    retention: runtime.policy.retention,
    holds: useAuthenticationLegalHolds(),
    limit: input.limit,
  })
  if (Object.values(retention).some(count => count > 0)) {
    await runtime.emit(systemEvent('authentication.retention-applied', null, { counts: retention }))
  }
  return { retention, serviceCredentials: { expired: expired.length, expiring: expiring.length } }
}
