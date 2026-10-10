import type { AuthenticationDataExport } from '../../shared/export'
import { useAuthenticationRuntime } from '../internal/nitro'
import { absoluteExpiry } from '../internal/principal'
import { toSessionSummary } from '../internal/sessions'

/**
 * PUBLIC server helper (auto-imported): Authentication's part of a
 * data-subject access request, or null when there is no account. Server-only:
 * the host calls it through iam-integration's coordination adapter, for
 * Profile, which assembles the person's archive. Never exposed over HTTP.
 *
 * It exports what Authentication holds about the account and nothing that
 * would let anyone sign in as the person: no password hash, TOTP secret,
 * backup code, passkey key, provider token, session token or IP address.
 */
export async function exportAuthenticationData(input: { principalId: string, correlationId: string }): Promise<AuthenticationDataExport | null> {
  const runtime = await useAuthenticationRuntime()
  const context = await runtime.engine.$context
  const { principalId, correlationId } = input
  const user = await context.internalAdapter.findUserById(principalId)
  if (!user) return null
  const iso = (value: Date | string) => new Date(value).toISOString()
  const lifetime = runtime.policy.session.absoluteLifetimeSeconds
  const [accounts, passkeys, totp, sessions, recovery] = await Promise.all([
    context.adapter.findMany<{ providerId: string, createdAt: Date | string }>({ model: 'account', where: [{ field: 'userId', value: principalId }] }),
    context.adapter.findMany<{ name: string | null, createdAt: Date | null, backedUp: boolean }>({ model: 'passkey', where: [{ field: 'userId', value: principalId }] }),
    context.adapter.findOne<{ verified: boolean | null, backupCodes: string }>({ model: 'twoFactor', where: [{ field: 'userId', value: principalId }] }),
    context.internalAdapter.listSessions(principalId),
    runtime.recoveries.get(principalId),
  ])
  const totpEnabled = Boolean(totp && totp.verified !== false)
  return {
    principalId,
    exportedAt: new Date().toISOString(),
    correlationId,
    signInIdentifiers: [{ kind: 'email', value: user.email, verified: user.emailVerified, createdAt: iso(user.createdAt) }],
    password: { set: accounts.some(account => account.providerId === 'credential') },
    providers: accounts
      .filter(account => account.providerId !== 'credential')
      .map(account => ({ provider: account.providerId, linkedAt: iso(account.createdAt) })),
    passkeys: passkeys.map(passkey => ({ name: passkey.name, createdAt: passkey.createdAt ? iso(passkey.createdAt) : null, backedUp: Boolean(passkey.backedUp) })),
    totp: { enabled: totpEnabled, backupCodesRemaining: totpEnabled ? (JSON.parse(totp!.backupCodes) as unknown[]).length : 0 },
    sessions: sessions
      .filter(session => absoluteExpiry(session, lifetime) > new Date())
      .map(session => toSessionSummary(session, '', lifetime))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(({ createdAt, lastActiveAt, expiresAt, clientDescription }) => ({ createdAt, lastActiveAt, expiresAt, clientDescription })),
    credentialRecovery: recovery ? { recoveredAt: recovery.recoveredAt, method: recovery.method } : null,
  }
}
