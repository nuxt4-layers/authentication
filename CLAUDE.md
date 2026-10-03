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

## Rules
- Public surface: package root, `./contracts`, `./capability`, and the `provide*` server functions. Everything else is private.
- Required ports fail closed. No implicit in-memory or file fallback stores.
- Authentication is tenant-agnostic. No roles, groups, tenants or profile data here.
- No secrets, codes, tokens or email addresses in events or logs.
- Defaults are secure; loosening policy requires a documented risk treatment.
- Keep `docs/contracts.md`, `docs/threat-model.md` (control register) and `docs/roadmap.md` in step with code.
- Package manager: pnpm. Commit `pnpm-lock.yaml`.
