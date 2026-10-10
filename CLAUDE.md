# @nuxt4-layers/authentication — notes for Claude

## What this is
Nuxt 4 foundation layer for authentication (who is signed in, session lifecycle).
Governed by `nuxt4-layers/platform-architecture`; persistence follows ADR-0002.
Better Auth is the private engine (from phase 2) and must never appear in `contracts/` or `shared/`.

## Commands
- `pnpm install`, then `pnpm dev:prepare` for Nuxt types. Never add a `prepare`/`postinstall` script: Git installs would then pull devDependencies (Theme Manager, Playwright) into hosts
- `pnpm check` = `nuxt typecheck` + `vitest run`; run it after every code change
- `pnpm build:playground` proves the layer composes in a host
- Theme Manager is pinned as `git+https://github.com/...#<sha>`; the lockfile must not record `git@github.com` (CI has no SSH key). Cloud sessions inject SSH-to-HTTPS rewrites that make pnpm pick SSH: re-resolve with `GIT_CONFIG_COUNT=1 pnpm install`
- Single test file: `pnpm vitest run tests/<name>.test.ts`
- Database and end-to-end suites need `AUTHENTICATION_TEST_DATABASE_URL` (admin URL of a local, disposable PostgreSQL). They skip locally without it and fail in CI.
- End-to-end: `pnpm test:e2e` (builds the playground, then Playwright). Locally, set `PLAYWRIGHT_CHROMIUM_EXECUTABLE` if Playwright's own browser is not installed.
- After changing engine options or upgrading the engine, run `tests/database.test.ts`: the drift test demands a new migration if the engine's schema changed. Never edit a released migration.

## Rules
- Three parts, one-way dependencies (docs/architecture.md, enforced by `tests/architecture.test.ts`): contract (`contracts/`, `shared/`: imports only zod), core (`server/`, `app/`: never imports or uses presentation), presentation (`presentation/`, `modules/presentation.ts`: only the contract and the client API `useAuthentication()`/`useAuthenticationPublicPolicy()`, never `$fetch` or `/api/`). Page text and classes belong in `./presentation`, never `./contracts`.
- Public surface: package root, `./contracts`, `./capability`, `./presentation`, the `provide*` (including `provideAuthenticationClock`)/`useAuthenticationClock`/`migrateAuthenticationDatabase`/`get|requireAuthenticatedPrincipal`/`getAuthenticationCredentialRecovery`/`listAuthenticationCredentialRecoveries`/`revokeAuthenticationSessions`/`discardAuthenticationAccount`/`deleteAuthenticationAccount`/`exportAuthenticationData` server functions, `useAuthentication()`, `useAuthenticationPublicPolicy()`, the `authenticated`/`guest`/`authentication-signed-in` middleware, the default pages and `Authentication*` components, `useAuthenticationText()`, `./tailwind.css` and `/api/authentication/*`. Everything else (`server/internal`, `server/database`) is private.
- Engine (Better Auth) routes are never mounted; endpoints call `engine.api.*` server-side and translate errors to contract codes.
- Engine gaps the layer closes itself (keep their tests): TOTP replay (`totp_last_step`), passkey user verification (engine passes `requireUserVerification: false`), backup codes stored as keyed digests, session freshness from `authenticatedAt` (engine `freshAge` is 0 because it measures `createdAt`).
- When the engine rotates a session it may return the OLD token; read the new one from Set-Cookie (`sessionTokenFromCookies`) and record its methods with `recordSessionAuthentication`.
- `requireAuthenticatedPrincipal` defaults to the policy's required level (aal2 when MFA is required). Layer endpoints choose an access level via `requireAccess` (enrolment / step-up / standard / sensitive).
- Federation: never enable implicit linking; account creation only for provider-verified emails (user.create.before hook); provider tokens stripped in account hooks; callback outcomes must stay coarse (no account enumeration). Tests use `oauth2-mock-server`.
- TOTP tests: each user can use at most the current and next time step without waiting; use `safeStep()` and fresh accounts.
- Required ports fail closed. No implicit in-memory or file fallback stores.
- Identity port (optional): when supplied, every account identifier comes from `reserve`, the standing is read at every sign-in and on every request (never cached), `refused` ends sessions, `passkeyOnly` admits only passkeys, refusals read as `invalid-credentials`, and any port failure fails closed. Keep `tests/integration/identity.test.ts` proving it.
- Authentication is tenant-agnostic. No roles, groups, tenants or profile data here.
- Never a source of profile data. Sign-in identifiers are Authentication's (ADR-0006 §6) and are used only for signing in, recovery and security notices. Names, pictures and anything else that describes a person are Profile's, as are the workflows over them: the engine's `name` stays `''` and `image` `null` (user.create.before hook), and nothing here stores, serves or seeds profile attributes.
- No secrets, codes, tokens or email addresses in events or logs.
- Credential recoveries (password reset, backup-code sign-in) are recorded in `credential_recovery` before they complete, failing closed, then announced as `authentication.credentials-recovered`. Keep the tests proving it.
- Defaults are secure; loosening policy requires a documented risk treatment.
- Keep `docs/contracts.md`, `docs/threat-model.md` (control register) and `docs/roadmap.md` in step with code.
- Default pages and components style only through the SemanticPresentationTheme vocabulary (`authenticationClasses`), never raw colours or Tailwind default sizes (e.g. `min-h-11`, `w-48`, `tracking-*`: use Theme Manager's scales), following Theme Manager's Semantic Presentation Guide: Fill/Pen/Edge of one surface share role and state; any other pairing goes in `DELIBERATE_PAIRINGS` (`presentation/pairings.ts`, never auto-imported) and `docs/contracts.md`. Text comes from `presentation/messages.ts` via `useAuthenticationText()`. Keep every component in `tailwind.css` source paths.
- Never weaken an axe or contrast assertion to get green. Fix the component's semantic composition first; a genuine palette defect is fixed in Theme Manager, never by setting its private `--ui-*` variables here or in the playground.
- Client calls that may run during SSR must use `useRequestFetch()` so the session cookie is forwarded.
- Package manager: pnpm. Commit `pnpm-lock.yaml`.
