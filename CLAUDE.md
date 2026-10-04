# @nuxt4-layers/authentication — notes for Claude

## What this is
Nuxt 4 foundation layer for authentication (who is signed in, session lifecycle).
Governed by `nuxt4-layers/platform-architecture`; persistence follows ADR-0002.
Better Auth is the private engine (from phase 2) and must never appear in `contracts/` or `shared/`.

## Commands
- `pnpm install`, then `pnpm dev:prepare` for Nuxt types. Never add a `prepare`/`postinstall` script: Git installs would then pull devDependencies (private Theme Manager) into hosts
- `pnpm check` = `nuxt typecheck` + `vitest run`; run it after every code change
- `pnpm build:playground` proves the layer composes in a host
- Single test file: `pnpm vitest run tests/<name>.test.ts`
- Database and end-to-end suites need `AUTHENTICATION_TEST_DATABASE_URL` (admin URL of a local, disposable PostgreSQL). They skip locally without it and fail in CI.
- End-to-end: `pnpm test:e2e` (builds the playground, then Playwright). Locally, set `PLAYWRIGHT_CHROMIUM_EXECUTABLE` if Playwright's own browser is not installed.
- After changing engine options or upgrading the engine, run `tests/database.test.ts`: the drift test demands a new migration if the engine's schema changed. Never edit a released migration.

## Rules
- Public surface: package root, `./contracts`, `./capability`, the `provide*`/`migrateAuthenticationDatabase`/`get|requireAuthenticatedPrincipal` server functions, `useAuthentication()`, the `authenticated`/`guest`/`authentication-signed-in` middleware, the default pages and `Authentication*` components, `useAuthenticationText()` and `/api/authentication/*`. Everything else (`server/internal`, `server/database`) is private.
- Engine (Better Auth) routes are never mounted; endpoints call `engine.api.*` server-side and translate errors to contract codes.
- Engine gaps the layer closes itself (keep their tests): TOTP replay (`totp_last_step`), passkey user verification (engine passes `requireUserVerification: false`), backup codes stored as keyed digests, session freshness from `authenticatedAt` (engine `freshAge` is 0 because it measures `createdAt`).
- When the engine rotates a session it may return the OLD token; read the new one from Set-Cookie (`sessionTokenFromCookies`) and record its methods with `recordSessionAuthentication`.
- `requireAuthenticatedPrincipal` defaults to the policy's required level (aal2 when MFA is required). Layer endpoints choose an access level via `requireAccess` (enrolment / step-up / standard / sensitive).
- Federation: never enable implicit linking; account creation only for provider-verified emails (user.create.before hook); provider tokens stripped in account hooks; callback outcomes must stay coarse (no account enumeration). Tests use `oauth2-mock-server`.
- TOTP tests: each user can use at most the current and next time step without waiting; use `safeStep()` and fresh accounts.
- Required ports fail closed. No implicit in-memory or file fallback stores.
- Authentication is tenant-agnostic. No roles, groups, tenants or profile data here.
- No secrets, codes, tokens or email addresses in events or logs.
- Defaults are secure; loosening policy requires a documented risk treatment.
- Keep `docs/contracts.md`, `docs/threat-model.md` (control register) and `docs/roadmap.md` in step with code.
- Default pages and components style only through Theme Manager's SemanticPresentationTheme grammar (`authenticationClasses`): colour roles/states and its text, weight, radius and spacing scales. Never Tailwind defaults (e.g. `min-h-11`, `w-48`, `tracking-*`), raw colours or arbitrary values; `tests/presentation-grammar.test.ts` enforces it. Text comes from `shared/messages.ts` via `useAuthenticationText()`.
- No workarounds for presentation: the layer ships no CSS and the playground/hosts write none (no `@source` recompiles, no `--ui-*` overrides). Never weaken an axe or contrast assertion to get green; if Theme Manager is at fault, report it and leave the test failing.
- Client calls that may run during SSR must use `useRequestFetch()` so the session cookie is forwarded.
- Package manager: pnpm. Commit `pnpm-lock.yaml`.
