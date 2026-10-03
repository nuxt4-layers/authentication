import type { AuthenticationSessionSummary } from '../../contracts'
import { describeClient } from './http'
import { absoluteExpiry, type EngineSessionRecord } from './principal'

/** PRIVATE. Maps engine sessions to owner-facing summaries; no IP or raw user agent leaves the server. */
export function toSessionSummary(
  session: EngineSessionRecord & { updatedAt: Date | string, userAgent?: string | null },
  currentSessionId: string,
  absoluteLifetimeSeconds: number,
): AuthenticationSessionSummary {
  const iso = (value: Date | string) => new Date(value).toISOString()
  return {
    sessionId: session.id,
    current: session.id === currentSessionId,
    createdAt: iso(session.createdAt),
    lastActiveAt: iso(session.updatedAt),
    expiresAt: absoluteExpiry(session, absoluteLifetimeSeconds).toISOString(),
    clientDescription: describeClient(session.userAgent),
  }
}
