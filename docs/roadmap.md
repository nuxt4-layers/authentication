# Roadmap

Each phase is delivered as its own pull request with tests, and keeps `pnpm check` green.

| Phase | Scope | Status |
|---|---|---|
| 1. Foundation | Package, manifest, public contract, composition ports (fail closed), policy, docs, threat model, CI, playground | Complete |
| 2. Core | Better Auth engine (private), PostgreSQL schema and migrations, email and password, email verification, password reset, sessions (rotation, idle/absolute expiry, revocation, active-session list), throttling and lockout, compromised-password check, `getAuthenticatedPrincipal` / `requireAuthenticatedPrincipal`, `useAuthentication()`, route middleware | Complete |
| 3. Multi-factor | TOTP with backup codes, passkeys, step-up and re-authentication, MFA-required enrolment flow | In review |
| 4. Federation | External identity providers with safe linking by provider subject | Planned |
| 5. Default pages | Accessible (WCAG 2.2 AA), localisable pages styled only through semantic design tokens with fallbacks; host can disable; Playwright end-to-end tests | Planned |
| 6. Host integration | Composition into a host application with its own adapters and negative tests | Planned |

## Testing infrastructure by phase

- **Phase 1:** Vitest unit and contract tests, `nuxt typecheck`, playground build.
- **Phase 2:** integration tests against a disposable PostgreSQL. CI uses a service container; Supabase is never used in CI.
- **Phase 5:** Playwright end-to-end tests against the playground, with automated accessibility checks.

## Deliberate exclusions

These came from the legacy layer and are intentionally **not** part of this capability:

- profile data, which goes to Identity;
- permissions and roles, which go to Authorization;
- compliance, KYC and consent records, which go to Privacy;
- tenancy, which goes to Identity and Authorization;
- navigation and theme pages, which go to host applications and Theme Manager;
- SMS, push, voice-call and biometric factors. These are modelled in the legacy layer but not planned here. Platform passkeys cover biometrics.
