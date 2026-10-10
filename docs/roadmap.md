# Roadmap

Each phase is delivered as its own pull request with tests, and keeps `pnpm check` green.

| Phase | Scope | Status |
|---|---|---|
| 1. Foundation | Package, manifest, public contract, composition ports (fail closed), policy, docs, threat model, CI, playground | Complete |
| 2. Core | Better Auth engine (private), PostgreSQL schema and migrations, email and password, email verification, password reset, sessions (rotation, idle/absolute expiry, revocation, active-session list), throttling and lockout, compromised-password check, `getAuthenticatedPrincipal` / `requireAuthenticatedPrincipal`, `useAuthentication()`, route middleware | Complete |
| 3. Multi-factor | TOTP with backup codes, passkeys, step-up and re-authentication, MFA-required enrolment flow | Complete |
| 4. Federation | Google, Microsoft, GitHub, Facebook and generic OIDC; explicit linking by provider subject only; verified-email account creation; provider tokens discarded | Complete |
| 5. Default pages | Accessible (WCAG 2.2 AA), localisable pages and reusable form components styled only through the `SemanticPresentationTheme` vocabulary; host-configurable paths, can be disabled; Playwright and axe end-to-end tests | Complete |
| 6. Host integration | Composition into `platform-test-harness` beside Theme Manager and Nuxt UI, with host adapters, principal-to-actor mapping and negative tests; Git installs carry runtime dependencies only; durable credential recovery records and `authentication.credentials-recovered` for Identity's recovery hold; the optional identity port (Identity issues account identifiers, standing gates sign-in and every request, passkey-only break-glass) and helpers for Identity's events; `exportAuthenticationData` for Profile's data-subject requests; `DELIBERATE_PAIRINGS` no longer auto-imported (it collided with Identity's and Profile's in a host) | In progress |

## Testing infrastructure by phase

- **Phase 1:** Vitest unit and contract tests, `nuxt typecheck`, playground build.
- **Phase 2:** integration tests against a disposable PostgreSQL. CI uses a service container; Supabase is never used in CI.
- **Phase 5:** Playwright end-to-end tests against the built playground composed with Theme Manager: axe (WCAG 2.2 AA rules) in light and dark mode, non-text contrast, reflow, keyboard-only journeys, passkeys through Chromium's virtual authenticator, and a mock OIDC provider. A manual screen-reader audit remains open before 1.0.

## Deliberate exclusions

These came from the legacy layer and are intentionally **not** part of this capability:

- profile data, which goes to Profile (ADR-0005). Authentication is never its canonical source: it stores no name or picture, even when a provider supplies one, and never serves or seeds profile attributes. Importing a provider's claims into a profile, if ever wanted, is a Profile workflow specified in Profile's contract;
- permissions and roles, which go to Authorization;
- compliance, KYC and consent records, which go to Privacy;
- tenancy, which goes to Identity and Authorization;
- navigation and theme pages, which go to host applications and Theme Manager;
- SMS, push, voice-call and biometric factors. These are modelled in the legacy layer but not planned here. Platform passkeys cover biometrics.
