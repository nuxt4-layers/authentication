# Authentication Composition Contract

## 1. Purpose

This document defines how a host Nuxt application composes the authentication capability. The host is the composition root (Composition and Dependency Model §1). Authentication stays a bounded foundation capability and never becomes an application shell.

## 2. Package composition

Install through the package manager and compose the package root with Nuxt `extends`, following the Layer Consumption Workflow:

- during early development, use a Git-backed dependency **pinned to a tag or commit SHA** in `package.json`. The package runs no install-time scripts, so only its runtime dependencies are installed;
- commit the lockfile and install with `--frozen-lockfile` in CI;
- never follow a mutable default branch in production.

Compose authentication as a **peer** of other capabilities. It does not extend, and is not extended by, Identity, Authorization, UI or Theme Manager.

## 3. Dependency graph

```text
            AuthenticatedPrincipal
Authentication ───────────────────────► Identity ──► actor context ──► Authorization
      │                                                                      ▲
      │ events (optional sink)                                               │
      ▼                                                                      │
    Audit / Logging                       domain capabilities ── requests ───┘

Composition root supplies: database pool, mailer, event sink, policy, clock.
```

Authentication has **no package dependency** on UI, Theme Manager, Identity, Authorization, Audit, any database vendor SDK, or any mail provider.

The default pages declare an **optional** required capability, `SemanticPresentationTheme` contract version 1, in `capability.json`. It is a vocabulary contract, not a package dependency: the components use Theme Manager's semantic utility classes, and the host composes Theme Manager (or another provider of the same vocabulary) beside authentication. Without it, the server, composables and middleware work unchanged, and the pages render unstyled but usable. Theme Manager appears in this repository only as a pinned devDependency for the playground and the end-to-end suite.

## 4. Host responsibilities

The host application:

- selects a compatible version and pins it;
- supplies a PostgreSQL pool through `provideAuthenticationDatabase` (required);
- supplies a mailer through `provideAuthenticationMailer` (required);
- optionally supplies an event sink, policy overrides and the suite's clock (`provideAuthenticationClock`, the same clock it gives every IAM member, or none); a clock that can be moved is composed only in a test mode, never in production;
- supplies `NUXT_AUTHENTICATION_SECRET` and `NUXT_AUTHENTICATION_BASE_URL` through secret management;
- applies the layer's database migrations by calling `migrateAuthenticationDatabase()` once after supplying the database (authentication requests wait for it);
- serves the application from a registrable domain (not an IP address) so passkeys work; the passkey relying-party ID is the base URL's host;
- for each identity provider it enables, registers `<base URL>/api/authentication/federation/callback/<id>` as the redirect URI and supplies the client ID and secret through secret management (`NUXT_AUTHENTICATION_PROVIDERS_<ID>_CLIENT_ID` / `_CLIENT_SECRET`; Microsoft also takes `_TENANT_ID`; the generic OIDC provider takes `_DISCOVERY_URL` and an optional `_NAME`);
- keeps the default pages (configured under `authentication.pages` in `nuxt.config.ts`), or disables them (`pages.enabled: false`) or the whole presentation (`presentation: false`) and provides its own pages at the configured routes, including `routes.mfa`, where sessions below the required level enrol a second factor or step up;
- when using the default pages with Theme Manager, adds `@import "@nuxt4-layers/authentication/tailwind.css";` after Theme Manager's `presentation.css` in its Tailwind entry, and composes a theme whose pairings meet the contrast requirements in `docs/contracts.md` (Styling), customising it through Theme Manager rather than by overriding its private `--ui-*` variables;
- overrides or translates page text through `app.config.ts` (`authentication.messages`);
- sets `NUXT_AUTHENTICATION_TRUST_PROXY=true` only when a reverse proxy overwrites `X-Forwarded-For`, so per-client throttling sees real client addresses;
- for break-glass accounts (ADR-0007), runs `provisionAuthenticationBreakGlass` from its operator procedure after Identity's `provisionIdentityBreakGlass`, and `rotateAuthenticationBreakGlass` on Identity's `break-glass.used`; hands each returned enrolment token to the operator as `<base URL><routes.breakGlassEnrol>#<token>` over a channel it trusts, never logging it; and never exposes either function over HTTP;
- integration-tests the composed system, including negative tests.

## 5. Layer responsibilities

The authentication layer:

- owns credentials, sessions, MFA factors and federated links;
- owns the `authentication` database schema and its migrations;
- owns abuse controls (throttling, lockout, enumeration resistance);
- publishes `AuthenticatedPrincipal` and `AuthenticationEvent`;
- fails closed when a required port is absent.

## 6. Persistence (ADR-0002)

- The host creates and owns the pool: credentials, TLS, pooling mode and lifecycle.
- The layer reads and writes only its own schema, `authentication` by default. Hosts may override the schema name. It must be a lower-case PostgreSQL identifier.
- The host SHOULD connect with a database role limited to that schema.
- No other capability reads the `authentication` schema. They use the public contract.
- Hosted PostgreSQL (for example Supabase) is used as a plain PostgreSQL endpoint. A hosted provider's own authentication service MUST NOT run alongside this layer.

### 6.1 Migrations

Migrations are versioned, append-only SQL shipped with the layer (`server/database/migrations.ts`) and recorded in `<schema>.schema_migration`. `migrateAuthenticationDatabase()` applies the pending ones in a single transaction under an advisory lock, so several instances may start at once.

A drift test (`tests/database.test.ts`) asserts that, after the migrations, the engine reports no missing tables, columns or indexes. An engine upgrade that changes its schema therefore fails CI until a new migration is added.

### 6.2 Least-privilege database role (recommended)

Run this as the database owner once, then give the host a connection string for `authentication_app`. On Supabase, use the SQL editor and connect through the session pooler as `authentication_app`.

```sql
create role authentication_app login password '<generated secret>';
create schema if not exists authentication authorization authentication_app;
-- authentication_app owns only its own schema; it receives no rights on public or other capabilities' schemas.
revoke all on schema public from authentication_app;
```

Because the role owns the `authentication` schema, `migrateAuthenticationDatabase()` can create and alter its tables, and nothing else.

On Supabase, also make sure `authentication` is not listed under **Project Settings → Data API → Exposed schemas**.

## 7. Failure boundaries

| Condition | Behaviour |
|---|---|
| Required port missing | `AuthenticationCompositionError` is thrown at first use. The operation is refused. There is no fallback store. |
| Invalid port shape or schema name | `TypeError` from the `provide*` call at startup |
| Invalid policy | Validation error from `provideAuthenticationPolicy` at startup |
| Event sink failure | Reported via `console.error`. The operation outcome is unchanged. |
| Clock throws or answers anything but a valid `Date` | `unavailable` (503) for the operation that needed the time. The layer never falls back to the system clock. |
| Engine or database failure | `unavailable` (503). Internal details are not disclosed. |
| Missing or short `NUXT_AUTHENTICATION_SECRET`, missing base URL, or non-https base URL in production (loopback excepted) | Error at the first authentication request; nothing is served insecurely |
| Mailer failure | Logged. The HTTP response is unchanged, so it cannot reveal whether an account exists. |

Driver and engine exceptions are translated at the boundary. They never become undocumented cross-layer contracts.

## 8. Composed-system verification

A consuming application must test its own combination of:

- the pinned authentication version;
- its database, mailer and event-sink adapters;
- its route exposure, and middleware placement for protected pages;
- its Identity and Authorization adapters that consume `AuthenticatedPrincipal`.

The layer's own tests establish its contract. They cannot establish the correctness of a host's adapters.
