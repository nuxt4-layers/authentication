import type { AuthenticationRetentionCounts } from '../../contracts'
import { currentTime } from '../internal/clock'
import { useAuthenticationRuntime } from '../internal/nitro'
import { createRetention } from '../internal/retention'
import { systemEvent } from '../internal/runtime'
import { useAuthenticationLegalHolds } from './authentication-composition'

/**
 * PUBLIC server helper (auto-imported for the host's server code), server-only:
 * never an endpoint. The host schedules it, as it does every member's
 * maintenance.
 *
 * Applies the policy's retention schedules (iam-integration's retention
 * process): deletes sessions expired more than `retention.sessionDays` ago,
 * break-glass enrolment tokens and verification values expired more than
 * `retention.tokenDays` ago, and credential-recovery records older than
 * `retention.recoveryDays` that no legal hold covers. Emits
 * `authentication.retention-applied` with counts when anything was deleted.
 * A failed run leaves the rest for the next one.
 */
export async function runAuthenticationMaintenance(input: { limit?: number } = {}): Promise<{ retention: AuthenticationRetentionCounts }> {
  const runtime = await useAuthenticationRuntime()
  const retention = await createRetention(runtime.database.pool, runtime.database.schema).apply({
    at: currentTime(),
    retention: runtime.policy.retention,
    holds: useAuthenticationLegalHolds(),
    limit: input.limit,
  })
  if (Object.values(retention).some(count => count > 0)) {
    await runtime.emit(systemEvent('authentication.retention-applied', null, { counts: retention }))
  }
  return { retention }
}
