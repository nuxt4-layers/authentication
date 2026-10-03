# @nuxt4-layers/authentication — notes for Claude

## What this is
Nuxt 4 foundation layer for authentication (who is signed in, session lifecycle).
Governed by `nuxt4-layers/platform-architecture`; persistence follows ADR-0002.
Better Auth is the private engine (from phase 2) and must never appear in `contracts/` or `shared/`.

## Commands
- `pnpm install` (runs `nuxt prepare`)
- `pnpm check` = `nuxt typecheck` + `vitest run`; run it after every code change
- `pnpm build:playground` proves the layer composes in a host
- Single test file: `pnpm vitest run tests/<name>.test.ts`
- Database and end-to-end suites need `AUTHENTICATION_TEST_DATABASE_URL` (admin URL of a local, disposable PostgreSQL). They skip locally without it and fail in CI.
- After changing engine options or upgrading the engine, run `tests/database.test.ts`: the drift test demands a new migration if the engine's schema changed. Never edit a released migration.

## Rules
- Public surface: package root, `./contracts`, `./capability`, the `provide*`/`migrateAuthenticationDatabase`/`get|requireAuthenticatedPrincipal` server functions, `useAuthentication()`, the `authenticated`/`guest` middleware and `/api/authentication/*`. Everything else (`server/internal`, `server/database`) is private.
- Engine (Better Auth) routes are never mounted; endpoints call `engine.api.*` server-side and translate errors to contract codes.
- Required ports fail closed. No implicit in-memory or file fallback stores.
- Authentication is tenant-agnostic. No roles, groups, tenants or profile data here.
- No secrets, codes, tokens or email addresses in events or logs.
- Defaults are secure; loosening policy requires a documented risk treatment.
- Keep `docs/contracts.md`, `docs/threat-model.md` (control register) and `docs/roadmap.md` in step with code.
- Package manager: pnpm. Commit `pnpm-lock.yaml`.
