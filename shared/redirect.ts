/** Accepts only same-origin absolute paths, preventing open redirects. */
export function safeRedirectPath(candidate: unknown, fallback: string): string {
  if (typeof candidate !== 'string') return fallback
  if (!candidate.startsWith('/') || candidate.startsWith('//') || candidate.includes('\\')) return fallback
  try {
    const url = new URL(candidate, 'http://localhost')
    return url.host === 'localhost' ? `${url.pathname}${url.search}${url.hash}` : fallback
  }
  catch {
    return fallback
  }
}
