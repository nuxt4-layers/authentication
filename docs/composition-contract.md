# Authentication Composition Contract

## 1. Purpose

This document defines how a host Nuxt application composes the authentication capability. The host is the composition root (Composition and Dependency Model §1). Authentication stays a bounded foundation capability and never becomes an application shell.

## 2. Package composition

Install through the package manager and compose the package root with Nuxt `extends`, following the Layer Consumption Workflow:

- during early development, use a Git-backed dependency **pinned to a tag or commit SHA** in `package.json`;
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

Composition root supplies: database pool, mailer, event sink, policy.
```

Authentication has **no package dependency** on UI, Theme Manager, Identity, Authorization, Audit, any database vendor SDK, or any mail provider.

## 4. Host responsibilities

The host application:

- selects a compatible version and pins it;
- supplies a PostgreSQL pool through `provideAuthenticationDatabase` (required);
- supplies a mailer through `provideAuthenticationMailer` (required);
- optionally supplies an event sink and policy overrides;
- supplies `NUXT_AUTHENTICATION_SECRET` and `NUXT_AUTHENTICATION_BASE_URL` through secret management;
- applies the layer's database migrations before serving traffic;
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

## 7. Failure boundaries

| Condition | Behaviour |
|---|---|
| Required port missing | `AuthenticationCompositionError` is thrown at first use. The operation is refused. There is no fallback store. |
| Invalid port shape or schema name | `TypeError` from the `provide*` call at startup |
| Invalid policy | Validation error from `provideAuthenticationPolicy` at startup |
| Event sink failure | Reported via `console.error`. The operation outcome is unchanged. |
| Engine or database failure | `unavailable` (503). Internal details are not disclosed. |

Driver and engine exceptions are translated at the boundary. They never become undocumented cross-layer contracts.

## 8. Composed-system verification

A consuming application must test its own combination of:

- the pinned authentication version;
- its database, mailer and event-sink adapters;
- its route exposure, and middleware placement for protected pages;
- its Identity and Authorization adapters that consume `AuthenticatedPrincipal`.

The layer's own tests establish its contract. They cannot establish the correctness of a host's adapters.
