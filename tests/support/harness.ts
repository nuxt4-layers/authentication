import { url } from '@nuxt/test-utils/e2e'
import { expect } from 'vitest'
import type { AuthenticatedPrincipal, AuthenticationEvent, AuthenticationMessage } from '../../contracts'

/** Shared black-box harness: a minimal browser and access to the playground's test recorder. */

export const PASSWORD = 'correct horse battery staple'

export function createHarness(origin: string) {
  class Browser {
    cookies = new Map<string, string>()

    async request(path: string, init: { method?: string, body?: unknown, origin?: string | null } = {}) {
      const headers: Record<string, string> = { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0' }
      if (init.body !== undefined) headers['content-type'] = 'application/json'
      if (init.origin !== null) headers.origin = init.origin ?? origin
      if (this.cookies.size) headers.cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ')
      const response = await fetch(url(path), {
        method: init.method ?? 'GET',
        headers,
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
        redirect: 'manual',
      })
      const setCookies = response.headers.getSetCookie()
      for (const cookie of setCookies) {
        const [pair] = cookie.split(';')
        const [name, ...rest] = pair!.split('=')
        const value = rest.join('=')
        if (value === '' || /max-age=0/i.test(cookie)) this.cookies.delete(name!)
        else this.cookies.set(name!, value)
      }
      const text = await response.text()
      const json = response.headers.get('content-type')?.includes('application/json')
      const data = json && text ? JSON.parse(text) : null
      return { status: response.status, data, setCookies, location: response.headers.get('location') }
    }

    post(path: string, body?: unknown, requestOrigin?: string | null) {
      return this.request(path, { method: 'POST', body: body ?? {}, origin: requestOrigin })
    }

    async principal(): Promise<AuthenticatedPrincipal | null> {
      return (await this.request('/api/authentication/session')).data.principal
    }
  }

  async function recorder(): Promise<{ messages: AuthenticationMessage[], events: AuthenticationEvent[] }> {
    return (await new Browser().request('/api/__playground/recorder')).data
  }

  async function lastMessage(to: string, kind: AuthenticationMessage['kind']): Promise<AuthenticationMessage> {
    const { messages } = await recorder()
    const message = messages.filter(m => m.to === to && m.kind === kind).at(-1)
    expect(message, `${kind} message to ${to}`).toBeDefined()
    return message!
  }

  async function messageCount(to: string, kind: AuthenticationMessage['kind']): Promise<number> {
    return (await recorder()).messages.filter(m => m.to === to && m.kind === kind).length
  }

  let sequence = 0
  const freshEmail = () => `user${++sequence}.${Date.now()}@example.com`

  /** Registers and verifies a new account, then signs in with the password. */
  async function verifiedAccount(browser = new Browser()) {
    const email = freshEmail()
    await browser.post('/api/authentication/sign-up', { email, password: PASSWORD })
    const link = new URL((await lastMessage(email, 'email-verification')).actionUrl!)
    await browser.request(link.pathname + link.search)
    const signIn = await browser.post('/api/authentication/sign-in', { email, password: PASSWORD })
    expect(signIn.status).toBe(200)
    return { email, browser }
  }

  return { Browser, recorder, lastMessage, messageCount, freshEmail, verifiedAccount }
}

export type HarnessBrowser = InstanceType<ReturnType<typeof createHarness>['Browser']>
