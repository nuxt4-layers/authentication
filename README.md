# @nuxt4-layers/authentication

Nuxt 4 **foundation** capability that establishes **who has signed in** and manages the secure lifecycle of the authenticated session.

It is designed to be composed into a host application as a black box: the host supplies infrastructure through documented ports, and everything else stays private to the layer.

> **Status: 0.1.0, phase 1 (foundation).** The public contract, composition ports, policy and test harness are in place. The authentication engine, endpoints and UI arrive in later phases; see [docs/roadmap.md](docs/roadmap.md).

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

Server-side, the layer auto-imports these composition functions for the host:

- `provideAuthenticationDatabase`
- `provideAuthenticationMailer`
- `provideAuthenticationEventSink`
- `provideAuthenticationPolicy`

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
  provideAuthenticationMailer({ send: message => mailer.send(message) })  // required
  provideAuthenticationEventSink({ emit: event => audit.record(event) })  // optional
  provideAuthenticationPolicy({ password: { minLength: 16 } })            // optional
})
```

See [docs/composition-contract.md](docs/composition-contract.md) for the full contract, including persistence ([ADR-0002](https://github.com/nuxt4-layers/platform-architecture/blob/main/docs/decisions/ADR-0002-composition-supplied-persistence-and-capability-owned-schemas.md)) and configuration.

## Configuration

| Runtime config | Environment variable | Purpose |
|---|---|---|
| `authentication.secret` | `NUXT_AUTHENTICATION_SECRET` | Signing/encryption secret, at least 32 random bytes. Server-only. |
| `authentication.baseUrl` | `NUXT_AUTHENTICATION_BASE_URL` | Canonical external origin used in links and origin checks. |

Secrets come from deployment secret management and are never committed.

## Security and privacy

The layer targets **OWASP ASVS 5.0 Level 2**, applying relevant Level 3 requirements for authentication and session management, and uses **NIST SP 800-63-4** for assurance terminology. It does not claim certification or formal conformance. See [docs/threat-model.md](docs/threat-model.md).

## Development

```bash
pnpm install          # also runs nuxt prepare
pnpm test             # Vitest
pnpm typecheck        # nuxt typecheck (layer, shared, contracts, tests, playground)
pnpm check            # typecheck + test
pnpm dev              # run the playground composition harness
pnpm build:playground # production build of the playground
```

## Documentation

- [Public contract](docs/contracts.md)
- [Composition contract](docs/composition-contract.md)
- [Threat model](docs/threat-model.md)
- [Roadmap](docs/roadmap.md)
- [Legacy layer review](docs/legacy-review.md)

## License

MIT
