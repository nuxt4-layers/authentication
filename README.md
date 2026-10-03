# @nuxt4-layers/authentication

Nuxt 4 **foundation** capability that establishes **who has signed in** and manages the secure lifecycle of the authenticated session.

It is designed to be composed into a host application as a black box: the host supplies infrastructure through documented ports, and everything else stays private to the layer.

> **Status: 0.3.0, phase 3 (multi-factor).** Email and password, verification, reset, sessions, lockout and throttling, plus TOTP with backup codes, passkeys (including passwordless sign-in) and step-up re-authentication all work end to end on PostgreSQL. **MFA is required by default.** Federation and default pages follow; see [docs/roadmap.md](docs/roadmap.md).

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
```

The layer also provides these, auto-imported for the host:

- **Composition, server side:** `provideAuthenticationDatabase`, `provideAuthenticationMailer`, `provideAuthenticationEventSink`, `provideAuthenticationPolicy`, `migrateAuthenticationDatabase`.
- **Protecting server routes:** `getAuthenticatedPrincipal(event)`, `requireAuthenticatedPrincipal(event, requirement?)`. The latter requires aal2 by default while MFA is required.
- **Client:** the `useAuthentication()` composable, and the `authenticated` and `guest` route middleware.
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

See [docs/composition-contract.md](docs/composition-contract.md) for the full contract, including persistence ([ADR-0002](https://github.com/nuxt4-layers/platform-architecture/blob/main/docs/decisions/ADR-0002-composition-supplied-persistence-and-capability-owned-schemas.md)) and configuration.

## Configuration

| Runtime config | Environment variable | Purpose |
|---|---|---|
| `authentication.secret` | `NUXT_AUTHENTICATION_SECRET` | Signing/encryption secret, at least 32 random bytes. Server-only. |
| `authentication.baseUrl` | `NUXT_AUTHENTICATION_BASE_URL` | Canonical external origin used in links and origin checks. Must be https in production. |
| `authentication.trustProxy` | `NUXT_AUTHENTICATION_TRUST_PROXY` | Read client IPs from `X-Forwarded-For`. Enable only behind a proxy that overwrites it. |
| `public.authentication.routes` | `NUXT_PUBLIC_AUTHENTICATION_ROUTES_*` | Sign-in, after-sign-in, after-sign-out, reset-password and MFA (enrol / step-up) paths. |
| `public.authentication.locale` | `NUXT_PUBLIC_AUTHENTICATION_LOCALE` | Locale passed to the mailer (default `en-GB`). |
| `public.authentication.appName` | `NUXT_PUBLIC_AUTHENTICATION_APP_NAME` | Name in authenticator apps and passkey prompts (default: base URL host). |

Secrets come from deployment secret management and are never committed.

## Security and privacy

The layer targets **OWASP ASVS 5.0 Level 2**, applying relevant Level 3 requirements for authentication and session management, and uses **NIST SP 800-63-4** for assurance terminology. It does not claim certification or formal conformance. See [docs/threat-model.md](docs/threat-model.md).

## Development

```bash
pnpm install          # also runs nuxt prepare
pnpm test             # Vitest (database suites need AUTHENTICATION_TEST_DATABASE_URL)
pnpm typecheck        # nuxt typecheck (layer, shared, contracts, tests, playground)
pnpm check            # typecheck + test
pnpm dev              # run the playground (set AUTHENTICATION_DATABASE_URL)
pnpm build:playground # production build of the playground
```

Database and end-to-end suites run against a **disposable local PostgreSQL**, never a hosted one. Point `AUTHENTICATION_TEST_DATABASE_URL` at an admin connection (for example `postgres://postgres@localhost:5432/postgres`); each suite creates and drops its own database. Without it those suites are skipped locally and **fail in CI**.

## Documentation

- [Public contract](docs/contracts.md)
- [Composition contract](docs/composition-contract.md)
- [Threat model](docs/threat-model.md)
- [Roadmap](docs/roadmap.md)
- [Legacy layer review](docs/legacy-review.md)

## License

MIT
