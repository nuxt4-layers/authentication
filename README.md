# @nuxt4-layers/authentication

Nuxt 4 **foundation** capability that establishes **who has signed in** and manages the secure lifecycle of the authenticated session.

It is designed to be composed into a host application as a black box: the host supplies infrastructure through documented ports, and everything else stays private to the layer.

> **Status: 0.6.0, phase 6 (host integration) in progress.** Email and password, verification, reset, sessions, lockout and throttling; TOTP with backup codes, passkeys (including passwordless sign-in) and step-up re-authentication; sign-in with Google, Microsoft, GitHub, Facebook or any OIDC provider (linked only explicitly, by provider subject); and accessible, localisable default pages styled through Theme Manager's semantic vocabulary all work end to end on PostgreSQL. **MFA is required by default.** See [docs/roadmap.md](docs/roadmap.md).

## Bounded responsibility

| Owns | Does not own |
|---|---|
| Credentials (passwords, passkeys, TOTP, backup codes) | Profiles, display names, avatars (Identity) |
| Sign-in, sign-up, sign-out, email verification, password reset | Groups, organisations, tenancy (Identity) |
| Sessions: creation, rotation, expiry, revocation, active-session list | Permissions, roles, policy decisions (Authorization) |
| Multi-factor enrolment, step-up and re-authentication | Compliance records, KYC, consent (Privacy) |
| Federated sign-in and safe account linking | Navigation, theming, application layouts |
| Abuse controls: throttling, lockout, enumeration resistance | Audit storage and reporting (Audit) |

Authentication is **tenant-agnostic**. It publishes one fact, the `AuthenticatedPrincipal` (principal, session and assurance). Identity maps it to an actor context with groups and organisations, and Authorization decides what that actor may do.

## Public surface

```text
@nuxt4-layers/authentication              Nuxt layer (compose with extends)
@nuxt4-layers/authentication/contracts    Types, error codes, events, policy, port interfaces
@nuxt4-layers/authentication/capability   Capability manifest
@nuxt4-layers/authentication/presentation  Page text catalogue and styling classes
@nuxt4-layers/authentication/tailwind.css  Tailwind sources for the default pages
```

The layer has three parts with one-way dependencies: the **contract** (plain TypeScript), the **core** (server, endpoints, client API, middleware) and an optional **presentation** (pages, components, text, styling) that uses only the contract and the client API. See [docs/architecture.md](docs/architecture.md).

The layer also provides these, auto-imported for the host:

- **Composition, server side:** `provideAuthenticationDatabase`, `provideAuthenticationMailer`, `provideAuthenticationEventSink`, `provideAuthenticationPolicy`, `migrateAuthenticationDatabase`.
- **Protecting server routes:** `getAuthenticatedPrincipal(event)`, `requireAuthenticatedPrincipal(event, requirement?)`. The latter requires aal2 by default while MFA is required.
- **Client:** the `useAuthentication()` and `useAuthenticationPublicPolicy()` composables, and the `authenticated`, `guest` and `authentication-signed-in` route middleware.
- **Presentation (optional):** default sign-in, sign-up, password recovery, MFA and security pages at configurable paths, the `Authentication*` form components they are built from, `useAuthenticationText()` and the en-GB message catalogue. `authentication: { presentation: false }` registers none of it.
- **HTTP:** endpoints under `/api/authentication/*`.

Every other path is private. See [docs/contracts.md](docs/contracts.md).

## Installation

Install as a Git-backed package dependency **pinned to a tag or commit**, then extend it by package name:

```jsonc
// package.json
"dependencies": {
  "@nuxt4-layers/authentication": "github:nuxt4-layers/authentication#<tag-or-commit-sha>"
}
```

```ts
// nuxt.config.ts
export default defineNuxtConfig({
  extends: ['@nuxt4-layers/authentication'],
})
```

Commit the lockfile, and install with `pnpm install --frozen-lockfile` in CI.

## Composition

The host supplies ports from a Nitro plugin. Required ports fail closed when absent.

```ts
// server/plugins/authentication.ts
import pg from 'pg'

export default defineNitroPlugin(() => {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })

  provideAuthenticationDatabase({ dialect: 'postgres', pool })            // required
  migrateAuthenticationDatabase()                                          // applies pending migrations
  provideAuthenticationMailer({ send: message => mailer.send(message) })  // required
  provideAuthenticationEventSink({ emit: event => audit.record(event) })  // optional
  provideAuthenticationPolicy({ password: { minLength: 16 } })            // optional
})
```

Protect server routes on the server; route middleware is only a user-experience guard:

```ts
// server/api/account/profile.get.ts
export default defineEventHandler(async (event) => {
  const principal = await requireAuthenticatedPrincipal(event)          // 401 signed out, 403 below aal2
  return loadProfile(principal.principalId)
})
```

```vue
<script setup lang="ts">
definePageMeta({ middleware: 'authenticated' })
const { principal, signOut } = useAuthentication()
</script>
```

### Default pages

Pages are registered at `/sign-in`, `/sign-up`, `/forgot-password`, `/reset-password`, `/mfa` and `/account/security`. Move or disable them in `nuxt.config.ts`:

```ts
export default defineNuxtConfig({
  extends: ['@nuxt4-layers/authentication', '@nuxt4-layers/theme-manager'],
  authentication: { pages: { paths: { signIn: '/login' } } },   // or { enabled: false }
})
```

A host with its own design sets `authentication: { presentation: false }`: no pages, components or presentation auto-imports are registered, and the core works unchanged.

They are styled only through the `SemanticPresentationTheme` vocabulary (Theme Manager), an optional capability. Add the layer's sources to your Tailwind entry so the utilities are generated:

```css
@import "@nuxt4-layers/theme-manager/presentation.css";
@import "@nuxt4-layers/authentication/tailwind.css";
```

Your theme must meet the contrast pairings in [docs/contracts.md](docs/contracts.md) §11. Override text or add locales in `app.config.ts` under `authentication.messages`.

See [docs/composition-contract.md](docs/composition-contract.md) for the full contract, including persistence ([ADR-0002](https://github.com/nuxt4-layers/platform-architecture/blob/main/docs/decisions/ADR-0002-composition-supplied-persistence-and-capability-owned-schemas.md)) and configuration.

## Configuration

| Runtime config | Environment variable | Purpose |
|---|---|---|
| `authentication.secret` | `NUXT_AUTHENTICATION_SECRET` | Signing/encryption secret, at least 32 random bytes. Server-only. |
| `authentication.baseUrl` | `NUXT_AUTHENTICATION_BASE_URL` | Canonical external origin used in links and origin checks. Must be https in production. |
| `authentication.trustProxy` | `NUXT_AUTHENTICATION_TRUST_PROXY` | Read client IPs from `X-Forwarded-For`. Enable only behind a proxy that overwrites it. |
| `public.authentication.routes` | `NUXT_PUBLIC_AUTHENTICATION_ROUTES_*` | Sign-in, sign-up, forgot-password, reset-password, MFA (enrol / step-up), security, after-sign-in and after-sign-out paths. When the default pages are on, `authentication.pages.paths` sets them at build time. |
| `public.authentication.locale` | `NUXT_PUBLIC_AUTHENTICATION_LOCALE` | Locale passed to the mailer (default `en-GB`). |
| `authentication.providers.<id>.clientId` / `clientSecret` | `NUXT_AUTHENTICATION_PROVIDERS_<ID>_CLIENT_ID` / `_CLIENT_SECRET` | Enables `google`, `microsoft` (`_TENANT_ID`), `github`, `facebook`, or `oidc` (`_DISCOVERY_URL`, `_NAME`). Register `<base URL>/api/authentication/federation/callback/<id>` with the provider. |
| `public.authentication.appName` | `NUXT_PUBLIC_AUTHENTICATION_APP_NAME` | Name in authenticator apps and passkey prompts (default: base URL host). |

Secrets come from deployment secret management and are never committed.

## Security and privacy

The layer targets **OWASP ASVS 5.0 Level 2**, applying relevant Level 3 requirements for authentication and session management, and uses **NIST SP 800-63-4** for assurance terminology. It does not claim certification or formal conformance. See [docs/threat-model.md](docs/threat-model.md).

## Development

```bash
pnpm install
pnpm dev:prepare      # generate Nuxt types (not run on install, so hosts installing from Git get runtime dependencies only)
pnpm test             # Vitest (database suites need AUTHENTICATION_TEST_DATABASE_URL)
pnpm typecheck        # nuxt typecheck (layer, shared, contracts, tests, playground)
pnpm check            # typecheck + test
pnpm dev              # run the playground (set AUTHENTICATION_DATABASE_URL)
pnpm build:playground # production build of the playground
pnpm test:e2e         # Playwright + axe against the built playground (needs AUTHENTICATION_TEST_DATABASE_URL)
```

The playground composes [Theme Manager](https://github.com/nuxt4-layers/theme-manager) v0.1.0, pinned by its release commit as a devDependency. Hosts installing the layer from Git do not get it: the package has no install-time scripts, so only its runtime dependencies are installed.

Database and end-to-end suites run against a **disposable local PostgreSQL**, never a hosted one. Point `AUTHENTICATION_TEST_DATABASE_URL` at an admin connection (for example `postgres://postgres@localhost:5432/postgres`); each suite creates and drops its own database. Without it those suites are skipped locally and **fail in CI**.

## Documentation

- [Architecture](docs/architecture.md)
- [Public contract](docs/contracts.md)
- [Composition contract](docs/composition-contract.md)
- [Threat model](docs/threat-model.md)
- [Roadmap](docs/roadmap.md)
- [Legacy layer review](docs/legacy-review.md)
- [Repository security configuration](docs/repository-security.md)
- [Contributing](CONTRIBUTING.md) and [security policy](SECURITY.md)

## License

MIT
