import { createHash } from 'node:crypto'

/**
 * PRIVATE. Have I Been Pwned k-anonymity range check.
 *
 * Only the first five hex characters of the password's SHA-1 leave the server.
 * Padding is requested so response size does not reveal the prefix bucket.
 *
 * Fails open: if the service is unreachable the password is accepted and a
 * warning is logged, so a third-party outage cannot block sign-up or reset.
 * This trade-off is recorded in docs/threat-model.md.
 */
export type CompromisedPasswordCheck = (password: string) => Promise<boolean>

export function createHibpCheck(fetchImpl: typeof fetch = fetch, timeoutMs = 3_000): CompromisedPasswordCheck {
  return async (password) => {
    const digest = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase()
    const prefix = digest.slice(0, 5)
    const suffix = digest.slice(5)
    try {
      const response = await fetchImpl(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true', 'User-Agent': 'nuxt4-layers-authentication' },
        signal: AbortSignal.timeout(timeoutMs),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const body = await response.text()
      return body.split('\n').some((line) => {
        const [candidate, count] = line.trim().split(':')
        return candidate === suffix && Number(count) > 0
      })
    }
    catch (error) {
      console.warn('[authentication] compromised-password check unavailable; accepting password:', error instanceof Error ? error.message : error)
      return false
    }
  }
}

export const noCompromisedPasswordCheck: CompromisedPasswordCheck = async () => false
