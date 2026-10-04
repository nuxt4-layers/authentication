import AxeBuilder from '@axe-core/playwright'
import { expect, test, type APIRequestContext, type Page } from '@playwright/test'
import pg from 'pg'
import { totpCode, msLeftInStep } from '../support/totp'
import { IDP_CONTROL_PORT, ORIGIN, PASSWORD } from './constants'

/**
 * Default pages in a real browser: full journeys, keyboard-only use, reflow,
 * passkeys through Chromium's virtual authenticator, and axe checks against
 * WCAG 2.2 AA rules with Theme Manager's real styles.
 */

const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']
let sequence = 0
const freshEmail = () => `e2e${++sequence}.${Date.now()}@example.com`

async function expectAccessible(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze()
  expect(results.violations.map(v => `${v.id}: ${v.nodes.map(n => n.target.join(' ')).join(', ')}`)).toEqual([])
}

/**
 * WCAG 1.4.11 (non-text contrast), which axe does not check: the input border
 * and the keyboard focus indicator need 3:1 against the surface they sit on.
 */
async function expectNonTextContrast(page: Page) {
  const ratios = await page.evaluate(() => {
    const parse = (value: string) => (value.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number)
    const luminance = (value: string) => {
      const [r, g, b] = parse(value).map((c) => {
        const v = c / 255
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
      })
      return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!
    }
    const ratio = (a: string, b: string) => {
      const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p)
      return (x! + 0.05) / (y! + 0.05)
    }
    const surface = (element: Element) => {
      for (let node = element.parentElement; node; node = node.parentElement) {
        const colour = getComputedStyle(node).backgroundColor
        if (colour !== 'rgba(0, 0, 0, 0)') return colour
      }
      return 'rgb(255, 255, 255)'
    }
    const input = document.querySelector('input[type="email"]') as HTMLInputElement
    input.focus()
    const style = getComputedStyle(input)
    return {
      inputBorder: ratio(style.borderTopColor, surface(input)),
      focusIndicator: ratio(style.outlineColor, surface(input)),
      focusVisible: style.outlineStyle !== 'none' && Number.parseFloat(style.outlineWidth) >= 2,
    }
  })
  expect(ratios.focusVisible).toBe(true)
  expect(ratios.inputBorder).toBeGreaterThanOrEqual(3)
  expect(ratios.focusIndicator).toBeGreaterThanOrEqual(3)
}

async function recorder(request: APIRequestContext) {
  return (await request.get('/api/__playground/recorder')).json() as Promise<{ messages: { to: string, kind: string, actionUrl: string | null }[] }>
}

async function lastLink(request: APIRequestContext, to: string, kind: string): Promise<string> {
  const { messages } = await recorder(request)
  const message = messages.filter(m => m.to === to && m.kind === kind).at(-1)
  expect(message, `${kind} to ${to}`).toBeTruthy()
  const url = new URL(message!.actionUrl!)
  return url.pathname + url.search
}

async function query(text: string, values: unknown[] = []) {
  const url = new URL(process.env.AUTHENTICATION_TEST_DATABASE_URL!)
  url.pathname = '/authentication_e2e'
  const client = new pg.Client({ connectionString: url.toString() })
  await client.connect()
  try {
    return await client.query(text, values)
  }
  finally {
    await client.end()
  }
}

async function safeStep() {
  if (msLeftInStep() < 4_000) await new Promise(resolve => setTimeout(resolve, msLeftInStep() + 200))
}

/** Signs up and confirms an email through the UI's API surface, returning the address. */
async function verifiedEmail(page: Page): Promise<string> {
  const email = freshEmail()
  await page.request.post('/api/authentication/sign-up', { data: { email, password: PASSWORD }, headers: { origin: ORIGIN } })
  await page.goto(await lastLink(page.request, email, 'email-verification'))
  return email
}

async function signInThroughForm(page: Page, email: string, password = PASSWORD) {
  await page.goto('/sign-in?redirect=/protected')
  await page.getByLabel('Email address').fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
}

/** Enrols TOTP through the MFA page, returning the provisioning URI. */
async function enrolTotpThroughPage(page: Page): Promise<string> {
  await expect(page).toHaveURL(/\/mfa\?redirect=/)
  await page.getByRole('button', { name: 'Use an authenticator app' }).click()
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
  await page.getByRole('button', { name: 'Continue' }).click()
  const uri = await page.getByTestId('totp-key').getAttribute('data-uri')
  await safeStep()
  await page.getByLabel('Verification code').fill(totpCode(uri!))
  await page.getByRole('button', { name: 'Verify' }).click()
  await expect(page.getByRole('heading', { name: 'Save your backup codes' })).toBeFocused()
  return uri!
}

test.describe('default pages', () => {
  test('every public page meets the automated WCAG 2.2 AA rules', async ({ page }) => {
    for (const path of ['/sign-in', '/sign-up', '/forgot-password', '/reset-password?token=example']) {
      await page.goto(path)
      await expect(page.locator('h1')).toBeVisible()
      await expectAccessible(page)
    }
  })

  test('text and non-text contrast hold in light and dark mode', async ({ page }) => {
    for (const mode of ['light', 'dark'] as const) {
      for (const path of ['/sign-in', '/sign-up', '/forgot-password']) {
        await page.goto(path)
        await page.evaluate(dark => document.documentElement.classList.toggle('dark', dark), mode === 'dark')
        await expectAccessible(page)
        await expectNonTextContrast(page)
      }
      // Hover changes fill and pen together, so contrast holds under the pointer.
      await page.goto('/sign-in')
      await page.evaluate(dark => document.documentElement.classList.toggle('dark', dark), mode === 'dark')
      await page.getByRole('button', { name: 'Sign in', exact: true }).hover()
      await expectAccessible(page)
    }
  })

  test('pages refuse framing, caching and referrer leakage', async ({ request }) => {
    for (const path of ['/sign-in', '/sign-up', '/forgot-password', '/reset-password?token=example', '/mfa', '/account/security']) {
      const response = await request.get(path, { maxRedirects: 0 })
      const headers = response.headers()
      expect(headers['content-security-policy'], path).toContain("frame-ancestors 'none'")
      expect(headers['x-frame-options'], path).toBe('DENY')
      expect(headers['referrer-policy'], path).toBe('no-referrer')
      expect(headers['cache-control'], path).toBe('no-store')
    }
  })

  test('pages reflow at 320 CSS pixels without horizontal scrolling', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 640 })
    for (const path of ['/sign-in', '/sign-up', '/forgot-password']) {
      await page.goto(path)
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
      expect(overflow, path).toBeLessThanOrEqual(0)
    }
  })

  test('applies Theme Manager styling through the semantic vocabulary', async ({ page }) => {
    await page.goto('/sign-in')
    const button = page.getByRole('button', { name: 'Sign in', exact: true })
    const background = await button.evaluate(element => getComputedStyle(element).backgroundColor)
    expect(background).not.toBe('rgba(0, 0, 0, 0)')
  })

  test('sign-up, confirmation, sign-in and authenticator enrolment by keyboard alone', async ({ page }) => {
    const email = freshEmail()
    await page.goto('/sign-up')
    await page.keyboard.press('Tab')
    await expect(page.getByLabel('Email address')).toBeFocused()
    await page.keyboard.type(email)
    await page.keyboard.press('Tab')
    await page.keyboard.type(PASSWORD)
    await page.keyboard.press('Tab') // show/hide control
    await page.keyboard.press('Tab')
    await page.keyboard.type(PASSWORD)
    await page.keyboard.press('Enter')
    await expect(page.getByRole('status')).toContainText(email)

    await page.goto(await lastLink(page.request, email, 'email-verification'))
    await expect(page).toHaveURL(/\/sign-in\?verification=success/)
    await expect(page.getByRole('status')).toContainText('Your email address is confirmed')

    await signInThroughForm(page, email)
    await enrolTotpThroughPage(page)
    await expectAccessible(page)
    await page.getByRole('button', { name: 'I have saved my backup codes' }).click()
    await expect(page).toHaveURL(/\/protected$/)
  })

  test('wrong credentials raise an announced, focused error and keep the form usable', async ({ page }) => {
    const email = await verifiedEmail(page)
    await signInThroughForm(page, email, 'not the right password at all')
    const alert = page.getByRole('alert')
    await expect(alert).toContainText('The email address or password is not right.')
    await expect(alert).toBeFocused()
    await expectAccessible(page)
  })

  test('fields name their purpose for password managers and autofill', async ({ page }) => {
    await page.goto('/sign-in')
    await expect(page.getByLabel('Email address')).toHaveAttribute('autocomplete', 'username')
    await expect(page.getByLabel('Password', { exact: true })).toHaveAttribute('autocomplete', 'current-password')
    await page.goto('/sign-up')
    await expect(page.getByLabel('Email address')).toHaveAttribute('autocomplete', 'email')
    await expect(page.getByLabel('Password', { exact: true })).toHaveAttribute('autocomplete', 'new-password')
    await expect(page.getByLabel('Confirm new password')).toHaveAttribute('autocomplete', 'new-password')
  })

  test('sign-in never leaves the site through the redirect parameter', async ({ page }) => {
    const email = await verifiedEmail(page)
    await page.goto('/sign-in?redirect=https://evil.example/collect')
    await page.getByLabel('Email address').fill(email)
    await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
    await enrolTotpThroughPage(page)
    await page.getByRole('button', { name: 'I have saved my backup codes' }).click()
    await expect(page).toHaveURL(`${ORIGIN}/`)
  })

  test('credentials never reach the URL, even before the page is interactive', async ({ browser }) => {
    // Without JavaScript the page is as it is before hydration.
    const context = await browser.newContext({ javaScriptEnabled: false })
    const page = await context.newPage()
    for (const path of ['/sign-in', '/sign-up', '/forgot-password', '/reset-password?token=example']) {
      await page.goto(path)
      for (const form of await page.locator('form').all()) {
        await expect(form, path).toHaveAttribute('method', 'post')
      }
      await expect(page.locator('button[type="submit"]').first(), path).toBeDisabled()
    }
    await page.goto('/sign-in')
    await page.getByLabel('Email address').fill('someone@example.com')
    await page.getByLabel('Password', { exact: true }).fill(PASSWORD)
    await page.getByLabel('Password', { exact: true }).press('Enter')
    await page.waitForTimeout(500)
    expect(page.url()).toBe(`${ORIGIN}/sign-in`)
    await context.close()
  })

  test('the password field reveals and hides its value with a pressed state', async ({ page }) => {
    await page.goto('/sign-in')
    const toggle = page.getByRole('button', { name: 'Show password' })
    await expect(toggle).toHaveAttribute('aria-pressed', 'false')
    await toggle.click()
    await expect(page.getByRole('button', { name: 'Hide password' })).toHaveAttribute('aria-pressed', 'true')
    await expect(page.locator('#authentication-password')).toHaveAttribute('type', 'text')
  })

  test('second-factor sign-in with a backup code', async ({ page, browser }) => {
    const email = await verifiedEmail(page)
    await signInThroughForm(page, email)
    await enrolTotpThroughPage(page)
    const code = (await page.getByTestId('backup-codes').locator('li').first().textContent())!.trim()
    await page.getByRole('button', { name: 'I have saved my backup codes' }).click()

    const otherContext = await browser.newContext()
    const other = await otherContext.newPage()
    await signInThroughForm(other, email)
    await expect(other.getByRole('heading', { name: 'Two-step verification' })).toBeVisible()
    await expect(other.getByLabel('Verification code')).toBeFocused()
    await expectAccessible(other)
    await other.getByRole('button', { name: 'Use a backup code instead' }).click()
    await other.getByLabel('Backup code').fill(code)
    await other.getByRole('button', { name: 'Verify' }).click()
    await expect(other).toHaveURL(/\/protected$/)
    await otherContext.close()
  })

  test('passkeys: add one in security settings, then sign in with it alone', async ({ page, context, browser }) => {
    const client = await context.newCDPSession(page)
    await client.send('WebAuthn.enable')
    const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
    })

    const email = await verifiedEmail(page)
    await signInThroughForm(page, email)
    await enrolTotpThroughPage(page)
    await page.getByRole('button', { name: 'I have saved my backup codes' }).click()

    await page.goto('/account/security')
    await expect(page.getByRole('heading', { level: 1, name: 'Security' })).toBeVisible()
    await expectAccessible(page)
    await page.getByLabel('Passkey name (optional)').fill('Laptop')
    await page.getByRole('button', { name: 'Add a passkey' }).click()
    await expect(page.getByRole('button', { name: 'Remove Laptop' })).toBeVisible()

    const { credentials } = await client.send('WebAuthn.getCredentials', { authenticatorId })
    const fresh = await browser.newContext()
    const second = await fresh.newPage()
    const secondClient = await fresh.newCDPSession(second)
    await secondClient.send('WebAuthn.enable')
    const { authenticatorId: secondId } = await secondClient.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
    })
    await secondClient.send('WebAuthn.addCredential', { authenticatorId: secondId, credential: credentials[0]! })
    await second.goto('/sign-in?redirect=/protected')
    await second.getByRole('button', { name: 'Sign in with a passkey' }).click()
    await expect(second).toHaveURL(/\/protected$/)
    await fresh.close()
  })

  test('a sensitive change asks to confirm it is you, then completes', async ({ page }) => {
    const email = await verifiedEmail(page)
    await signInThroughForm(page, email)
    const uri = await enrolTotpThroughPage(page)
    await page.getByRole('button', { name: 'I have saved my backup codes' }).click()
    await query(`update "authentication"."session" set "authenticatedAt" = now() - interval '20 minutes'`)

    await page.goto('/account/security')
    await page.getByLabel('Current password').fill(PASSWORD)
    await page.getByLabel('New password', { exact: true }).fill('an entirely new long passphrase')
    await page.getByLabel('Confirm new password').fill('an entirely new long passphrase')
    await page.getByRole('button', { name: 'Change password' }).click()

    await expect(page.getByRole('heading', { name: 'Confirm it is you' })).toBeFocused()
    await new Promise(resolve => setTimeout(resolve, msLeftInStep() + 200))
    await page.getByLabel('Verification code').fill(totpCode(uri, 1))
    await page.getByRole('button', { name: 'Confirm with code' }).click()
    await expect(page.getByRole('status')).toContainText('Your password has been changed')
  })

  test('sign-in with an identity provider, then step up to reach protected pages', async ({ page }) => {
    await fetch(`http://localhost:${IDP_CONTROL_PORT}`, {
      method: 'POST',
      body: JSON.stringify({ sub: `e2e-subject-${Date.now()}`, email: freshEmail(), email_verified: true }),
    })
    await page.goto('/sign-in?redirect=/protected')
    await page.getByRole('button', { name: 'Continue with Test IdP' }).click()
    await expect(page).toHaveURL(/\/mfa\?redirect=\/protected/)
    await expect(page.getByRole('button', { name: 'Use an authenticator app' })).toBeVisible()
    await expectAccessible(page)
  })

  test('provider failures return to sign-in with a clear message', async ({ page }) => {
    const email = await verifiedEmail(page)
    await fetch(`http://localhost:${IDP_CONTROL_PORT}`, {
      method: 'POST',
      body: JSON.stringify({ sub: `e2e-subject-${Date.now()}`, email, email_verified: true }),
    })
    await page.goto('/sign-in')
    await page.getByRole('button', { name: 'Continue with Test IdP' }).click()
    await expect(page).toHaveURL(/\/sign-in\?federation=link-required/)
    await expect(page.getByRole('alert')).toContainText('sign in another way and link the provider')
  })

  test('forgotten password journey ends signed out with a success notice', async ({ page }) => {
    const email = await verifiedEmail(page)
    await page.goto('/forgot-password')
    await page.getByLabel('Email address').fill(email)
    await page.getByRole('button', { name: 'Send reset link' }).click()
    await expect(page.getByRole('status')).toContainText(email)

    await page.goto(await lastLink(page.request, email, 'password-reset'))
    await page.getByLabel('New password', { exact: true }).fill('a completely different passphrase')
    await page.getByLabel('Confirm new password').fill('a different confirmation entirely')
    await page.getByRole('button', { name: 'Save new password' }).click()
    await expect(page.getByText('The passwords do not match.')).toBeVisible()
    await expect(page.getByLabel('Confirm new password')).toHaveAttribute('aria-invalid', 'true')

    await page.getByLabel('Confirm new password').fill('a completely different passphrase')
    await page.getByRole('button', { name: 'Save new password' }).click()
    await expect(page).toHaveURL(/\/sign-in\?reset=success/)
    await expect(page.getByRole('status')).toContainText('Your password has been changed')
  })
})
