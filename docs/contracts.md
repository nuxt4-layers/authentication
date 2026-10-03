# Authentication Public Contract

**Contract:** `Authentication`, version `1`
**Status:** Provisional (pre-1.0). Breaking changes are documented explicitly.

## 1. Purpose

The authentication capability's supported cross-layer surface is the package root (the Nuxt layer), `@nuxt4-layers/authentication/contracts`, `@nuxt4-layers/authentication/capability`, and the server composition functions listed in §6.

Consumers MUST NOT import any other path. The authentication engine, database schema, server utilities and HTTP handler internals are private and may change without a major release.

No type from the private authentication engine, database driver, ORM or hosted-database SDK is part of this contract. `tests/contracts.test.ts` enforces this.

## 2. Data contracts

### `AuthenticatedPrincipal`

The single fact authentication publishes:

| Field | Meaning |
|---|---|
| `principalId` | Stable, opaque identifier. Other capabilities store this value and never a credential or email address. |
| `sessionId` | Opaque identifier of the current session. |
| `authenticatedAt` | Time of the most recent primary or step-up authentication. |
| `expiresAt` | Time after which the session is no longer valid. |
| `assurance` | `{ level: 'aal1' \| 'aal2', methods, phishingResistant }` |

The principal carries **no tenant, group or role**. Those belong to Identity and Authorization (Platform Architecture §6).

### `AuthenticationRequirement`

What a protected operation may require of the current session:

- `minimumLevel`;
- `phishingResistant`;
- `maxAuthenticationAgeSeconds`, which forces re-authentication for sensitive operations.

### `AuthenticationSessionSummary`

One entry in the owner's "active sessions" list. It holds a coarse client description and no raw IP address or full user agent.

## 3. Error contract

Failures from the layer's HTTP endpoints and from `requireAuthenticatedPrincipal` are standard h3/Nuxt errors whose `data` field is an `AuthenticationErrorBody`:

```json
{
  "statusCode": 401,
  "statusMessage": "invalid-credentials",
  "data": { "code": "invalid-credentials", "messageKey": "authentication.error.invalid-credentials" }
}
```

The codes are in `AUTHENTICATION_ERROR_CODES`, and their HTTP statuses are in `AUTHENTICATION_ERROR_STATUS`.

Enumeration resistance is part of the contract. `invalid-credentials` covers unknown accounts, wrong passwords and disabled or locked accounts alike. No code reveals whether an account exists.

`AuthenticationCompositionError` is a deployment fault raised when a required port is missing. It is never a user-facing response.

## 4. Event contract

`AuthenticationEvent` values are emitted after security-relevant facts (`AUTHENTICATION_EVENT_TYPES`, all namespaced `authentication.*`).

Events MUST NOT contain credentials, one-time codes, tokens, session secrets or email addresses. `client.ipAddress` and `client.userAgent` are personal data. The sink owner is responsible for their retention.

Delivery is best effort. A failing sink is reported, but it never changes the outcome of the operation.

## 5. Configuration contract: `AuthenticationPolicy`

`resolveAuthenticationPolicy(input)` merges host overrides onto `DEFAULT_AUTHENTICATION_POLICY` and validates the result. Unknown keys and values below the enforced floors are rejected.

| Setting | Default | Floor / ceiling |
|---|---|---|
| `password.minLength` | 15 | ≥ 8 |
| `password.maxLength` | 128 | ≥ 64 |
| `password.compromisedCheck` | `hibp-range` | `hibp-range` or `disabled` |
| `signInThrottle.maxFailedAttempts` | 5 | 3–100 |
| `signInThrottle.maxFailedAttemptsPerClient` | 50 | 10–10 000 |
| `signInThrottle.windowSeconds` / `lockoutSeconds` | 900 / 900 | 60–86 400 |
| `session.idleTimeoutSeconds` | 3 600 | ≥ 300, and not more than the absolute lifetime |
| `session.absoluteLifetimeSeconds` | 86 400 | 900–2 592 000 |
| `reauthentication.maxAgeSeconds` | 900 | 60–3 600 |
| `mfa` | `required` | `required` or `optional` |
| `emailVerification` | `required` | `required` or `optional` |

The defaults follow ASVS 5.0 Level 2 and NIST SP 800-63-4 AAL2 guidance. A host that loosens a default MUST record the gap and its risk treatment (Security Architecture §12).

`hibp-range` sends only a 5-character SHA-1 prefix to the Have I Been Pwned range API. It is a classified third-party integration (Privacy Architecture §4).

## 6. Composition ports

The host supplies these from a Nitro plugin. See [composition-contract.md](composition-contract.md).

| Function | Port | Required |
|---|---|---|
| `provideAuthenticationDatabase` | `AuthenticationDatabase` (`{ dialect: 'postgres', pool, schema? }`) | Yes |
| `provideAuthenticationMailer` | `AuthenticationMailer` (`send(message)`) | Yes |
| `provideAuthenticationEventSink` | `AuthenticationEventSink` (`emit(event)`) | No |
| `provideAuthenticationPolicy` | `AuthenticationPolicyInput` | No, the secure defaults apply |

`PostgresPoolLike` is a structural interface satisfied by a `pg` `Pool`. The contract does not depend on the driver package.

## 7. Server helpers

These are auto-imported into the host's server code:

| Function | Behaviour |
|---|---|
| `getAuthenticatedPrincipal(event)` | The current `AuthenticatedPrincipal`, or `null`. Resolved once per request. |
| `requireAuthenticatedPrincipal(event, requirement?)` | The principal, or throws `unauthenticated` (401), `insufficient-assurance` (403) or `reauthentication-required` (401). |
| `migrateAuthenticationDatabase()` | Applies pending migrations to the capability schema. Requests wait for it to finish. |

Every protected host operation MUST call `requireAuthenticatedPrincipal` (or pass the principal to Authorization). Route middleware is not a security boundary.

## 8. HTTP endpoints

All endpoints live under `/api/authentication`. Every state-changing request must carry an `Origin` (or `Referer`) header matching `NUXT_AUTHENTICATION_BASE_URL`, otherwise it fails with `origin-rejected` (403). Bodies are JSON and strictly validated, so unknown fields are rejected.

| Method and path | Body | Success | Notes |
|---|---|---|---|
| `POST /sign-up` | `{ email, password }` | 202 `{ status: 'accepted' }` | Identical for new and existing addresses. A verification email is sent to new addresses. |
| `POST /sign-in` | `{ email, password }` | 200 `{ status: 'signed-in' }` | Sets the session cookie and replaces any previous session. |
| `POST /sign-out` | none | 200 `{ status: 'signed-out' }` | Revokes the session server-side. Always succeeds. |
| `GET /session` | | 200 `{ principal }` | `principal` is `null` when signed out. `Cache-Control: no-store`. |
| `GET /verify-email?token=` | | 303 redirect | To `routes.signIn` with `?verification=success` or `?verification=failed`. |
| `POST /password/forgot` | `{ email }` | 202 `{ status: 'accepted' }` | Identical for unknown addresses. At most 3 emails per address per throttle window. |
| `POST /password/reset` | `{ token, password }` | 200 `{ status: 'password-reset' }` | Single-use token, valid for 30 minutes. Revokes every session. |
| `POST /password/change` | `{ currentPassword, newPassword }` | 200 `{ status: 'password-changed' }` | Requires a session. Revokes other sessions and rotates the current one. |
| `GET /sessions` | | 200 `{ sessions }` | The principal's own `AuthenticationSessionSummary[]`, newest first. |
| `DELETE /sessions/:id` | | 204 | Revokes one of the principal's own sessions. Another principal's id answers `validation-failed`. |
| `POST /sessions/revoke-others` | none | 200 `{ status: 'revoked' }` | Revokes every session except the current one. |

## 9. Client surface

`useAuthentication()` is auto-imported in the host's app. It returns:

| Member | Meaning |
|---|---|
| `principal` | Read-only `AuthenticatedPrincipal \| null`. |
| `isAuthenticated` | Computed boolean. |
| `ready` | True once the session has loaded. A layer plugin loads it before the first navigation. |
| `refresh()` | Reloads the session from the server. |
| `signUp`, `signIn`, `signOut`, `requestPasswordReset`, `resetPassword`, `changePassword`, `listSessions`, `revokeSession`, `revokeOtherSessions` | Each resolves to `AuthenticationResult<T>`: `{ ok: true, data }` or `{ ok: false, code }`. |

Named route middleware:

- `authenticated` sends anonymous visitors to `routes.signIn?redirect=<path>`.
- `guest` sends signed-in visitors to the `redirect` query, but only same-origin paths are accepted. Otherwise they go to `routes.afterSignIn`.

Client state and middleware improve the user experience. They are not security enforcement.

## 10. Route configuration

These are public runtime config values under `authentication.routes`, and hosts may override them:

| Key | Default | Used for |
|---|---|---|
| `signIn` | `/sign-in` | `authenticated` middleware target and verification-link redirect |
| `afterSignIn` | `/` | `guest` middleware fallback |
| `afterSignOut` | `/` | Reserved for the default pages (phase 5) |
| `resetPassword` | `/reset-password` | Path in password-reset emails (`?token=`) |

`authentication.locale` (default `en-GB`) is passed to the mailer with every message.
