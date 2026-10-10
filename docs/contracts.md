# Authentication Public Contract

**Contract:** `Authentication`, version `1`
**Status:** Provisional (pre-1.0). Breaking changes are documented explicitly.

## 1. Purpose

The authentication capability's supported cross-layer surface is the package root (the Nuxt layer), `@nuxt4-layers/authentication/contracts`, `@nuxt4-layers/authentication/capability`, `@nuxt4-layers/authentication/presentation` (page text and styling, §11), `@nuxt4-layers/authentication/tailwind.css` (a Tailwind source declaration, §11), the server composition functions listed in §6, the client surface in §9, and the default pages and components in §11, and the break-glass functions and endpoints in §12.

The surface has three parts with one-way dependencies, described in [architecture.md](architecture.md): the **contract** (`./contracts`, plain TypeScript), the **core** (server, endpoints, client API and route middleware) and the **presentation** (pages, components, text and styling). Code that only needs to know who is signed in uses the contract and the core, and can turn the presentation off.

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
| `standing` | What the account may do, from the identity port (§6.1): `allowed`, `resume-only`, `cancel-closure-only` or `verification-only`. Always `allowed` without one. A `refused` account has no principal. |

The principal carries **no tenant, group or role**. Those belong to Identity and Authorization (Platform Architecture §6).

How `assurance` is derived:

| Methods | Level | Phishing resistant |
|---|---|---|
| `password` | `aal1` | no |
| `password` + `totp`, or `password` + `backup-code` | `aal2` | no |
| `passkey` (user verification is always required) | `aal2` | yes |
| `password` + `remembered-device` (only if the host enables `rememberedDevice.days`) | `aal2` | no |
| `federated` (identity provider) | `aal1` | no |
| `federated` + `totp`, `backup-code` or `passkey` | `aal2` | no, or yes with a passkey |

A provider's own MFA is not trusted. Provider sign-ins step up with a local factor.

Reporting a level describes the session. It is not a claim that the application conforms to NIST SP 800-63-4.

### `AuthenticationRequirement`

What a protected operation may require of the current session:

- `minimumLevel`;
- `phishingResistant`;
- `maxAuthenticationAgeSeconds`, which forces re-authentication for sensitive operations;
- `allowStandings`, the standings besides `allowed` the operation accepts (for example `resume-only` to resume a paused account). Any other standing is `account-restricted` (403).

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

Enumeration resistance is part of the contract. `invalid-credentials` covers unknown accounts, wrong passwords and disabled or locked accounts alike, including an account the identity port refuses or a break-glass account signing in without a passkey. No code reveals whether an account exists.

`AuthenticationCompositionError` is a deployment fault raised when a required port is missing. It is never a user-facing response.

## 4. Event contract

`AuthenticationEvent` values are emitted after security-relevant facts (`AUTHENTICATION_EVENT_TYPES`, all namespaced `authentication.*`).

Phase 3 adds `authentication.backup-code-used`. Phase 6 adds `authentication.break-glass-provisioned`, `authentication.break-glass-enrolled` (with `method: 'passkey'`) and `authentication.break-glass-rotated` (§12); they carry the principal, never the enrolment token or the address. Sign-in failures carry a machine-readable `reason`, such as `invalid-credentials`, `account-locked`, `rate-limited`, `totp-replayed` or `user-not-verified`.

Events MUST NOT contain credentials, one-time codes, tokens, session secrets or email addresses. `client.ipAddress` and `client.userAgent` are personal data. The sink owner is responsible for their retention.

Delivery is best effort. A failing sink is reported, but it never changes the outcome of the operation.

### 4.1 Credential recovery

A **password reset** and a **sign-in with a backup code** are credential recoveries. Each records, in the layer's own `credential_recovery` table, when the principal's credentials were last recovered and how (`AUTHENTICATION_RECOVERY_METHODS`: `password-reset`, `backup-code`), and then emits `authentication.credentials-recovered` (with `method` `password` or `backup-code` and the recovery method as `reason`).

The record is part of the recovery: if it cannot be written, the reset fails, and a backup-code sign-in is refused (`unavailable`) and its new session removed. The host relays the event to Identity's `recordIdentityCredentialRecovery`, which holds `critical` governance changes the person requests soon afterwards (iam-integration's [recovery process](https://github.com/nuxt4-layers/iam-integration/blob/38e06eb38c10d7415b93d5ab754a5a4a5b4cc910/docs/processes/recovery.md)). Because event delivery is best effort, the host also reconciles from the records with `listAuthenticationCredentialRecoveries` (§7), so a lost event never skips the hold. Records hold only the principal, a time and a method code, and are deleted with the account.

## 5. Configuration contract: `AuthenticationPolicy`

`resolveAuthenticationPolicy(input)` merges host overrides onto `DEFAULT_AUTHENTICATION_POLICY` and validates the result. Unknown keys and values below the enforced floors are rejected.

`AuthenticationPublicPolicy` is the non-secret part an interface needs to guide users (`password.minLength`/`maxLength`, `mfa`, `rememberedDevice.days`); `publicAuthenticationPolicy(policy)` derives it, and `GET /api/authentication/policy` returns it.

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
| `rememberedDevice.days` | 0 (off) | 0–30. Days a device may skip the second factor after the user opts in. |
| `breakGlass.enrolmentTokenMinutes` | 60 | 5–1 440. How long a break-glass enrolment token stays valid (§12). A longer period gives a leaked token longer to be used. |

The defaults follow ASVS 5.0 Level 2 and NIST SP 800-63-4 AAL2 guidance. A host that loosens a default MUST record the gap and its risk treatment (Security Architecture §12).

`hibp-range` sends only a 5-character SHA-1 prefix to the Have I Been Pwned range API. It is a classified third-party integration (Privacy Architecture §4).

## 6. Composition ports

The host supplies these from a Nitro plugin. See [composition-contract.md](composition-contract.md).

| Function | Port | Required |
|---|---|---|
| `provideAuthenticationDatabase` | `AuthenticationDatabase` (`{ dialect: 'postgres', pool, schema? }`) | Yes |
| `provideAuthenticationIdentity` | `AuthenticationIdentity` (`reserve`, `confirm`, `standing`; §6.1) | No |
| `provideAuthenticationMailer` | `AuthenticationMailer` (`send(message)`) | Yes |
| `provideAuthenticationEventSink` | `AuthenticationEventSink` (`emit(event)`) | No |
| `provideAuthenticationPolicy` | `AuthenticationPolicyInput` | No, the secure defaults apply |
| `provideAuthenticationClock` | `AuthenticationClock` (`now(): Date`; §6.2) | No, the system clock applies |

`PostgresPoolLike` is a structural interface satisfied by a `pg` `Pool`. The contract does not depend on the driver package.

### 6.1 Identity port

The identity port tells Authentication whose an account is and whether it may hold a session. The host supplies it, normally through iam-integration's reference adapter over Identity's provisioning port ([provisioning process](https://github.com/nuxt4-layers/iam-integration/blob/38e06eb38c10d7415b93d5ab754a5a4a5b4cc910/docs/processes/provisioning.md)). Without it, the engine issues account identifiers and every account is `allowed`, as before.

| Method | Called | Effect |
|---|---|---|
| `reserve({ invitationToken })` | When an account is about to be created (sign-up or a provider's first sign-in) | Its `principalId` becomes the account's identifier. It receives no personal data; `invitationToken` is the sign-up body's, passed through and never stored or logged. A failure refuses the sign-up (`unavailable`) |
| `confirm(principalId)` | Once the sign-in identifier is verified (the verification link, or a provider-verified address) | Makes the identity usable. Idempotent; a lost confirmation is retried when the account next signs in |
| `standing(principalId)` | At every sign-in, and on every request with a session | `refused` (or unknown) ends every session and refuses sign-in as `invalid-credentials`; any other standing is carried on the principal; `passkeyOnly` refuses every sign-in but a passkey |

Every call failure fails closed: sign-in, sign-up and requests with a session answer `unavailable` until the port answers again.

The host also acts on Identity's events with these server helpers (§7), although access never depends on them, since every request reads the standing:

| Identity event | Helper |
|---|---|
| `identity.paused`, `identity.suspended`, `identity.closure-requested` | `revokeAuthenticationSessions(principalId)` |
| `identity.provisioning-expired` | `discardAuthenticationAccount(principalId)` (only an unverified account) |
| `identity.closed` | `deleteAuthenticationAccount(principalId)` (credentials, sessions and the sign-in identifier) |

### 6.2 Clock

Each member of the IAM suite reads the current time from a clock port the host may supply ([iam-integration's architecture §7](https://github.com/nuxt4-layers/iam-integration/blob/e986245d746507bf7093ca203e346ab1b571e3a8/docs/architecture.md#7-time)). Here it is `provideAuthenticationClock({ now(): Date })`; `useAuthenticationClock()` returns it, or the system clock when the host supplies none. The host supplies the same clock to every member, or none, because times cross members: the authentication time Authentication records is judged against Identity's safety periods.

| Time | Clock |
|---|---|
| When something happened: every event's `occurredAt`, a credential recovery's `recoveredAt`, `authenticatedAt` recorded for a session's authentication (sign-in, second factor, step-up, re-authentication, new and rotated sessions), a data-subject export's `exportedAt`, and a break-glass enrolment token's `expiresAt` (§12) | The layer's clock |
| Whether an authentication is recent: `maxAuthenticationAgeSeconds` in `requireAuthenticatedPrincipal`, and so the `enrolment` and `sensitive` access levels (§8); whether a break-glass enrolment token has expired | The layer's clock |
| The engine's own times: a session's idle and absolute lifetime (`expiresAt`), sign-in throttling and lockout windows, TOTP time steps (an authenticator app computes them from real time), and the expiry of email links the engine issues (verification, password reset) | The system clock, always |

A clock that throws, or answers anything but a valid `Date`, fails the operation as `unavailable` (503); the layer never falls back to the system clock. A clock is trusted like a key: whoever supplies it decides whether an authentication is recent. Only the host composes it, from server code; no request can set or move it, and a clock that can be moved is for tests only (the threat model's control register).

## 7. Server helpers

These are auto-imported into the host's server code:

| Function | Behaviour |
|---|---|
| `getAuthenticatedPrincipal(event)` | The current `AuthenticatedPrincipal`, or `null`. Resolved once per request. |
| `requireAuthenticatedPrincipal(event, requirement?)` | The principal, or throws `unauthenticated` (401), `insufficient-assurance` (403) or `reauthentication-required` (401); the age of the authentication is judged by the layer's clock (§6.2). `minimumLevel` **defaults to the policy's required level**: `aal2` while `mfa: 'required'` (the default). Pass `{ minimumLevel: 'aal1' }` to accept sessions that have not completed a second factor. |
| `requiredAssuranceLevel()` | `'aal2'` when the policy requires MFA, otherwise `'aal1'`. |
| `migrateAuthenticationDatabase()` | Applies pending migrations to the capability schema. Requests wait for it to finish. |
| `getAuthenticationCredentialRecovery(principalId)` | The principal's latest credential recovery (`AuthenticationCredentialRecovery`: `principalId`, `recoveredAt`, `method`), or `null` (§4.1). |
| `revokeAuthenticationSessions(principalId)` | Ends every session of the principal; returns how many (§6.1). |
| `discardAuthenticationAccount(principalId)` | Removes an account whose sign-in identifier was never verified; `authentication.account-deleted` (§6.1). |
| `deleteAuthenticationAccount(principalId)` | Deletes an account with its credentials, sessions and sign-in identifier; `authentication.account-deleted` (§6.1). |
| `listAuthenticationCredentialRecoveries({ after?, limit? })` | Recoveries in the order they happened, up to `limit` (default 100, at most 1000), with `next` to pass as `after`; a principal recovered again moves to a later page. For the host's reconciliation with Identity (§4.1). |
| `provisionAuthenticationBreakGlass({ identityId, address, correlationId })` | Creates a break-glass identity's passkey-only account and returns `{ enrolmentToken, expiresAt }` (§12). Operator function: server-only, never an endpoint. |
| `rotateAuthenticationBreakGlass({ identityId, correlationId })` | Deletes the break-glass account's passkeys, ends its sessions, replaces any outstanding token and returns a new `{ enrolmentToken, expiresAt }` (§12). Server-only. |
| `exportAuthenticationData({ principalId, correlationId })` | Authentication's part of a data-subject access request (`AuthenticationDataExport`), or `null` without an account: the sign-in identifier and whether it was verified, whether a password is set, linked providers, passkeys (name, when added, whether backed up), whether TOTP is enrolled and how many backup codes remain, the sessions in force (times and a coarse client description) and the latest credential recovery. Never a password hash, secret, code, key, token or IP address, and no profile data, which is Profile's. Server-only: the host calls it through iam-integration's coordination adapter, for Profile, which assembles the archive ([data-subject requests](https://github.com/nuxt4-layers/iam-integration/blob/3fb6866e0b6b7abbdf599ea06df9d4b8508482f5/docs/processes/data-subject-requests.md)). |

Every protected host operation MUST call `requireAuthenticatedPrincipal` (or pass the principal to Authorization). Route middleware is not a security boundary.

## 8. HTTP endpoints

All endpoints live under `/api/authentication`. Every state-changing request must carry an `Origin` (or `Referer`) header matching `NUXT_AUTHENTICATION_BASE_URL`, otherwise it fails with `origin-rejected` (403). Bodies are JSON and strictly validated, so unknown fields are rejected.

| Method and path | Body | Success | Notes |
|---|---|---|---|
| `POST /sign-up` | `{ email, password, invitationToken? }` | 202 `{ status: 'accepted' }` | Identical for new and existing addresses. A verification email is sent to new addresses. |
| `POST /sign-in` | `{ email, password }` | 200 `{ status: 'signed-in' }` or `{ status: 'second-factor-required', methods: ['totp', 'backup-code'] }` | Signed in: sets the session cookie and replaces any previous session. Second factor required: no session yet, only a 5-minute interim cookie. |
| `POST /sign-out` | none | 200 `{ status: 'signed-out' }` | Revokes the session server-side. Always succeeds. |
| `GET /session` | | 200 `{ principal, requiredLevel }` | `principal` is `null` when signed out. A principal below `requiredLevel` must enrol or step up. `Cache-Control: no-store`. |
| `GET /verify-email?token=` | | 303 redirect | To `routes.signIn` with `?verification=success` or `?verification=failed`. |
| `POST /password/forgot` | `{ email }` | 202 `{ status: 'accepted' }` | Identical for unknown addresses. At most 3 emails per address per throttle window. |
| `POST /password/reset` | `{ token, password }` | 200 `{ status: 'password-reset' }` | Single-use token, valid for 30 minutes. Revokes every session. |
| `POST /password/change` | `{ currentPassword, newPassword }` | 200 `{ status: 'password-changed' }` | Requires a session. Revokes other sessions and rotates the current one. |
| `GET /sessions` | | 200 `{ sessions }` | The principal's own `AuthenticationSessionSummary[]`, newest first. |
| `DELETE /sessions/:id` | | 204 | Revokes one of the principal's own sessions. Another principal's id answers `validation-failed`. |
| `POST /sessions/revoke-others` | none | 200 `{ status: 'revoked' }` | Revokes every session except the current one. |
| `GET /policy` | | 200 `{ password: { minLength, maxLength }, mfa, rememberedDevice: { days } }` | The non-secret policy values that forms use to guide people. `Cache-Control: public, max-age=300`. |

### Multi-factor and step-up endpoints

Access levels:
- **Enrolment**: any session, `aal1` included, authenticated within `reauthentication.maxAgeSeconds`.
- **Step-up**: any session.
- **Standard**: the policy's required level.
- **Sensitive**: the required level, plus authentication within `reauthentication.maxAgeSeconds`.

| Method and path | Access | Body | Success | Notes |
|---|---|---|---|---|
| `POST /mfa/verify` | interim cookie | `{ method: 'totp' \| 'backup-code', code, rememberDevice? }` | 200 `{ status: 'signed-in' }` | Completes a `second-factor-required` sign-in (aal2). TOTP codes are single-use per time step. Repeated failures lock the second factor (`rate-limited`). |
| `GET /mfa` | step-up | | 200 `{ requiredLevel, totp: { enabled }, backupCodes: { remaining }, passkeys: [{ id, name, createdAt }] }` | |
| `POST /mfa/totp/enrol` | enrolment | `{ password }` | 200 `{ totpUri, backupCodes }` | Backup codes are shown once. TOTP is inactive until confirmed. |
| `POST /mfa/totp/confirm` | enrolment | `{ code }` | 200 `{ status: 'totp-enabled' }` | Rotates the session, which then counts `totp` (aal2 with a password). |
| `POST /mfa/totp/disable` | sensitive | `{ password }` | 200 `{ status: 'totp-disabled' }` | Removes TOTP and the backup codes. |
| `POST /mfa/backup-codes` | sensitive | `{ password }` | 200 `{ backupCodes }` | Replaces every code. |
| `POST /passkeys/registration-options` | enrolment | none | 200 WebAuthn creation options | |
| `POST /passkeys/registration` | enrolment | `{ response, name? }` | 200 `{ status: 'passkey-registered' }` | Authenticators that do not verify the user answer `insufficient-assurance`. |
| `POST /passkeys/authentication-options` | none | none | 200 WebAuthn request options | |
| `POST /passkeys/authentication` | none | `{ response }` | 200 `{ status: 'signed-in' }` | Passwordless sign-in or step-up. Creates a new aal2, phishing-resistant session and replaces the current one. |
| `DELETE /passkeys/:id` | sensitive | | 204 | Only the principal's own passkeys. |
| `POST /reauthenticate` | step-up | `{ method: 'password', password }` or `{ method: 'totp', code }` | 200 `{ status: 'reauthenticated' }` | Refreshes `authenticatedAt`. A TOTP code also adds the factor (aal1 to aal2). |

`POST /password/change` is now **sensitive**: it requires the required level and a recent authentication.

### Break-glass enrolment endpoints

Gated by a one-time enrolment token, not a session (§12). Every refusal (an unknown, used or expired token, a spent challenge, a failed or unverified registration, or a malformed body) answers the same `invalid-or-expired-token` (400) and counts against the client's sign-in throttle (`rate-limited` once over it). The origin check applies as everywhere. `Cache-Control: no-store`.

| Method and path | Access | Body | Success | Notes |
|---|---|---|---|---|
| `POST /break-glass/enrolment-options` | token | `{ token }` | 200 WebAuthn creation options | `residentKey: 'required'`, `userVerification: 'required'`, `attestation: 'none'`, the engine's relying party. Binds a fresh challenge to the token, replacing any earlier one. |
| `POST /break-glass/enrolment` | token | `{ token, response, name? }` | 200 `{ status: 'passkey-registered' }` | Uses the challenge once, refuses an authenticator that did not verify the user, stores the passkey and consumes the token. Sets no session cookie and ends nothing else. `authentication.break-glass-enrolled`, and a security notice to the account's address. |

### Federation endpoints

Providers: `google`, `microsoft`, `github`, `facebook` and one generic `oidc` provider. Each is enabled only when configured.

A provider's profile claims (name, picture, locale and so on) are discarded: Authentication keeps only the provider subject and the verified email it signs in with. Personal data that describes a person is Profile's, and Profile is its only canonical source; Authentication never stores, serves or seeds it.

| Method and path | Access | Body | Success | Notes |
|---|---|---|---|---|
| `GET /federation/providers` | none | | 200 `{ providers: [{ id, name }] }` | |
| `GET /federation/:provider/start?redirect=` | none | | 302 to the provider | State, PKCE and nonce are bound to the browser by a short-lived cookie. |
| `GET /federation/callback/:provider` | none | | 302 | Registered with the provider as its redirect URI. On success, goes to `redirect`. On failure, goes back to where the flow began with `?federation=<outcome>`. |
| `POST /federation/:provider/link` | sensitive | `{ redirect? }` | 200 `{ url }` | The browser visits `url`. The provider is linked to the signed-in account. |
| `GET /federation/accounts` | step-up | | 200 `{ password, providers: [{ provider, linkedAt }] }` | |
| `DELETE /federation/:provider` | sensitive | | 204 | The last way of signing in cannot be removed (`validation-failed`). |

Federation rules:
- **Never linked by email.** A provider identity whose email matches an existing account is refused. The user signs in and links it explicitly.
- **New accounts** are created only when the provider reports the email as verified, and are then marked verified. Facebook never reports verification, so Facebook identities can only be linked.
- **Outcomes** are deliberately coarse: `cancelled`, `link-required` (any reason the identity cannot sign in on its own, whether or not an account exists), `link-failed` (the identity belongs to another account) and `failed`.
- **Provider tokens are discarded.** The layer keeps only the provider's subject identifier.

## 9. Client surface

`useAuthentication()` is auto-imported in the host's app. It returns:

| Member | Meaning |
|---|---|
| `principal` | Read-only `AuthenticatedPrincipal \| null`. |
| `isAuthenticated` | Computed boolean. |
| `ready` | True once the session has loaded. A layer plugin loads it before the first navigation. |
| `refresh()` | Reloads the session from the server. |
| `requiredLevel` | The policy's required assurance level. |
| `needsSecondFactor` | True when signed in below `requiredLevel`. |
| `federationProviders`, `linkedAccounts`, `linkProvider`, `unlinkProvider` | Federation, as `AuthenticationResult<T>`. `signInWithProvider(provider, redirect?)` navigates to the provider. `linkProvider` navigates on success. |
| `breakGlassEnrolmentOptions(token)`, `enrolBreakGlass(token, response, name?)`, `enrolBreakGlassPasskey(token, name?)` | Break-glass enrolment (§12), as `AuthenticationResult<T>`: the creation options, the enrolment itself, or both around the browser's passkey creation. They need no session and sign nobody in. |
| `signUp`, `signIn`, `verifySecondFactor`, `signInWithPasskey`, `reauthenticate`, `signOut`, `requestPasswordReset`, `resetPassword`, `changePassword`, `mfaStatus`, `enrolTotp`, `confirmTotp`, `disableTotp`, `regenerateBackupCodes`, `registerPasskey`, `removePasskey`, `listSessions`, `revokeSession`, `revokeOtherSessions` | Each resolves to `AuthenticationResult<T>`: `{ ok: true, data }` or `{ ok: false, code }`. `signIn` may return `{ status: 'second-factor-required' }`. Passkey ceremonies use `@simplewebauthn/browser`, and a cancelled ceremony answers `validation-failed`. |

`useAuthenticationPublicPolicy()` is also auto-imported. It returns a ref to the `AuthenticationPublicPolicy`, loaded once per request and shared. Interfaces, including the default pages, read the policy through it rather than calling the endpoint.

`safeRedirectPath(candidate, fallback)` (from `./contracts`) accepts only same-origin absolute paths. Use it for any `redirect` query a custom page honours.

Named route middleware:

- `authenticated` sends anonymous visitors to `routes.signIn?redirect=<path>`, and sessions below the required level to `routes.mfa?redirect=<path>`.
- `guest` sends signed-in visitors to the `redirect` query, but only same-origin paths are accepted. Otherwise they go to `routes.afterSignIn`.
- `authentication-signed-in` admits any signed-in session, including one below the required level. The MFA page uses it so a person can enrol or step up.

Client state and middleware improve the user experience. They are not security enforcement.

## 10. Route configuration

These are public runtime config values under `authentication.routes`. They belong to the core, which uses them for redirects and email links, and hosts may override them:

| Key | Default | Used for |
|---|---|---|
| `signIn` | `/sign-in` | `authenticated` middleware target and verification-link redirect |
| `signUp` | `/sign-up` | Link from the sign-in page |
| `forgotPassword` | `/forgot-password` | Link from the sign-in and reset pages |
| `afterSignIn` | `/` | `guest` middleware fallback and default destination after sign-in |
| `afterSignOut` | `/` | Destination after signing out from the security page |
| `resetPassword` | `/reset-password` | Path in password-reset emails (`?token=`) |
| `mfa` | `/mfa` | `authenticated` middleware target for enrolment or step-up |
| `security` | `/account/security` | Security settings page |
| `breakGlassEnrol` | `/break-glass/enrol` | Where an operator opens a break-glass enrolment link, `<base URL><path>#<token>` (§12) |

When the default pages are enabled, the paths chosen in `authentication.pages.paths` (§11) are written into these route values at build time, so links, redirects and emails always point at pages that exist.

`authentication.locale` (default `en-GB`) is passed to the mailer with every message. `authentication.appName` (default: the base URL's host) is shown in authenticator apps and passkey prompts.

## 11. Presentation: default pages, components and messages

The presentation is optional. It depends only on the contract and the client surface (§9), never on the server, and the core never depends on it. Hosts configure it in `nuxt.config.ts`:

```ts
export default defineNuxtConfig({
  extends: ['@nuxt4-layers/authentication'],
  authentication: {
    presentation: true,                    // false: core only; no pages, components or presentation auto-imports
    pages: {
      enabled: true,                       // false: no pages, but keep the components to build your own
      paths: { signIn: '/login' },         // absolute paths; unspecified keys keep their defaults
    },
  },
})
```

With `presentation: false` the server, endpoints, `useAuthentication()`, `useAuthenticationPublicPolicy()` and the route middleware work unchanged; the host supplies its own pages at the configured `routes` (§10).

### Pages

When enabled, the layer registers seven pages:

| Key | Default path | Page | Middleware |
|---|---|---|---|
| `signIn` | `/sign-in` | Password, second factor, passkey and provider sign-in; verification, reset and federation notices | `guest` |
| `signUp` | `/sign-up` | Create an account | `guest` |
| `forgotPassword` | `/forgot-password` | Request a reset link | none |
| `resetPassword` | `/reset-password` | Choose a new password from the emailed link | none |
| `mfa` | `/mfa` | Enrol a second factor (authenticator app or passkey) or step up | `authentication-signed-in` |
| `security` | `/account/security` | Password, authenticator app and backup codes, passkeys, linked providers, sessions | `authenticated` |
| `breakGlassEnrol` | `/break-glass/enrol` | Registers a break-glass account's passkey from the token in the URL fragment (§12): one action, then a reminder to store the device offline; no links to any other page | none |

Each page has one `<main>` landmark, one `h1`, a document title and the `lang` of `authentication.locale`.

### Components

Registered with the `Authentication` prefix (when `presentation` is on), for hosts that build their own pages: `AuthenticationSignInForm`, `AuthenticationSignUpForm`, `AuthenticationForgotPasswordForm`, `AuthenticationResetPasswordForm`, `AuthenticationMfaPanel`, `AuthenticationTotpEnrolment`, `AuthenticationBackupCodes`, `AuthenticationReauthenticate`, `AuthenticationSecuritySettings`, `AuthenticationBreakGlassEnrolment`, `AuthenticationProviderButtons`, `AuthenticationField` and `AuthenticationAlert`. Their props and events are documented in each component's header. They render no page chrome, so a host may place them in its own layout.

`authenticationClasses` (auto-imported, and exported from `./presentation`) holds the utility classes the components use, all taken from the `SemanticPresentationTheme` vocabulary. `DELIBERATE_PAIRINGS` is exported from `./presentation` only, not auto-imported, so it never collides with the lists of the same name from Identity and Profile in a host.

### Styling

The components use only `SemanticPresentationTheme` utilities: the `bg-fill-*`, `text-pen-*`, `border-edge-*`, `divide-edge-*` and `outline-edge-*` colour roles and states, and Theme Manager's text, weight, radius and spacing scales. No utility falls back to Tailwind's own defaults. A host composing Theme Manager adds the layer's sources to its own Tailwind entry so the utilities are generated:

```css
@import "@nuxt4-layers/theme-manager/presentation.css";
@import "@nuxt4-layers/authentication/tailwind.css";
```

The components follow Theme Manager's [Semantic Presentation Guide](https://github.com/nuxt4-layers/theme-manager/blob/master/docs/semantic-presentation-guide.md): tokens are chosen by meaning, and the Fill, Pen and Edge of one surface or control share a role and a state and change state together (hover, active and disabled). Text without a fill of its own sits on the card, `fill-base-default`. Links are link-role surfaces (`pen-link` on `fill-link`, underlined), and the keyboard focus indicator is the card's own edge in its active state. Components never set Theme Manager's private `--ui-*` or `--api-*` variables, and neither should a host: a theme that falls short is corrected in its Theme Definition.

Beyond Theme Manager's same-role guarantees, the components use these deliberate pairings, which a host's theme must keep at WCAG 2.2 AA in light and dark mode:

| Pairing | Purpose | Minimum |
|---|---|---|
| `pen-muted-default` on `fill-base-default` | Hints, notes and the "or" divider | 4.5:1 |
| `pen-error-default` on `fill-base-default` | A field's error message | 4.5:1 |
| `edge-error-default` on `fill-input-default` | An invalid field's border | 3:1 |
| `edge-base-active` on `fill-base-default` | Keyboard focus indicator | 3:1 |

`tests/presentation.test.ts` enforces the pairing rules and compiles every class against Theme Manager's public `presentation.css` to catch Tailwind defaults, and the end-to-end suite checks rendered contrast with Theme Manager's default theme, unmodified.

### Messages

All text comes from the layer's en-GB catalogue, `AUTHENTICATION_MESSAGES_EN_GB` (exported from `./presentation`). Hosts override wording or add locales in `app.config.ts`:

```ts
export default defineAppConfig({
  authentication: {
    messages: {
      'en-GB': { 'authentication.signIn.title': 'Log in' },
      'cy-GB': { 'authentication.signIn.title': 'Mewngofnodi' },
    },
  },
})
```

The locale is `authentication.locale`. A key resolves to the host override for that locale, then the en-GB default, then the key itself. `{name}` placeholders are filled from parameters, and unknown placeholders stay visible so gaps are noticed. `useAuthenticationText()` returns `{ locale, t }`, and `resolveMessage` and `formatMessage` are exported for server or test use. Each error code `<code>` has the message `authentication.error.<code>`.

## 12. Break-glass accounts (ADR-0007)

A break-glass account is the Authentication side of an Identity `break-glass` identity, which Identity provisions with its migration role (`provisionIdentityBreakGlass`). The identity has no personal group, memberships or roles; each break-glass action in Identity needs a phishing-resistant aal2 authentication within 15 minutes, and every use alerts every operator and opens a mandatory review (iam-integration's approvals process). Authentication's part is the account and its passkey.

### Provisioning and rotation

Both are operator functions (§7): server-only, never an HTTP endpoint.

- `provisionAuthenticationBreakGlass({ identityId, address, correlationId })` creates the account under `identityId`, the identifier Identity issued (the identity port's `reserve` is not called, and neither is `confirm`: Identity creates break-glass identities active). Its sign-in identifier is `address`, an address the operator chooses and attests, marked verified and used only for security notices. The engine's `name` stays `''` and `image` `null`. It has no password and no other credential. The layer records the account as break-glass in its own `break_glass_account` table, so it stays passkey-only with or without an identity port. It refuses (`validation-failed`) an identity or an address that already has an account, or malformed input. It emits `authentication.break-glass-provisioned` (not `account-registered`) and returns `{ enrolmentToken, expiresAt }`.
- `rotateAuthenticationBreakGlass({ identityId, correlationId })` replaces any outstanding enrolment token, then deletes every passkey of the account and ends every session, emits `authentication.break-glass-rotated` and returns a new `{ enrolmentToken, expiresAt }`. The host calls it on Identity's `break-glass.used`, so the passkey is replaced after each use. It refuses (`validation-failed`) any account that is not break-glass.

`AuthenticationBreakGlassEnrolment` (`./contracts`) is `{ enrolmentToken, expiresAt }`. The `correlationId` ties the call to the host's operator procedure; the layer's events have no field for it, so it is not stored.

### Enrolment tokens

- 32 random bytes, base64url; returned once by the function and never stored, logged or put in an event.
- Stored only as an HMAC-SHA-256 digest keyed with a key derived from `NUXT_AUTHENTICATION_SECRET` for this purpose (the mechanism backup codes use).
- At most one outstanding per account: issuing a new one replaces the old.
- Single use: the enrolment consumes it. It expires after `breakGlass.enrolmentTokenMinutes` (default 60, 5–1 440), by the layer's clock (§6.2).
- The operator opens `<base URL><routes.breakGlassEnrol>#<token>` on the offline device. The token is in the fragment, which the browser never sends to a server or in a Referer; the page reads it in the browser and posts it in a request body.

### The WebAuthn ceremony

The engine's passkey registration needs a signed-in session (its registration endpoints use a fresh-session middleware, and the challenge is bound to a signed cookie). Turning that off is a global engine switch (`registration.requireSession: false`) that would loosen the session-bound registration too, and the engine would then register the passkey for whatever session the request happened to carry. So the enrolment endpoints run the ceremony with `@simplewebauthn/server`, the library the engine itself uses (a direct dependency at the engine's version), with exactly the relying party the engine is configured with (its passkey plugin's `rpID`, `rpName` and `origin`):

- the challenge is held server-side, bound to the token's digest, replaced by each request for options and used once, whatever the outcome, and it expires with the token;
- user verification is required, both in the verification and by the layer's own check of the UV flag (`registrationUserVerified`), as for every passkey;
- the credential is stored through the engine's adapter in the engine's `passkey` table, in the engine's own encoding, so the engine's normal passkey sign-in (`POST /passkeys/authentication`) finds it;
- the token is consumed after the passkey is stored; if a rotation replaced it meanwhile, the passkey is withdrawn and the enrolment refused, so a rotation always ends with no passkey from an older token.

### Passkey-only, enforced by the layer

With or without an identity port, a break-glass account:

- signs in by passkey alone: any other sign-in is refused as `invalid-credentials`, like the identity port's `passkeyOnly`;
- never gets a password: no reset link is sent (the response is the same as for any address), and the engine's account hook refuses to create a password or provider account for it, so a reset fails rather than setting one;
- cannot enrol an authenticator app or backup codes, change a password, link a provider or register a further passkey through the session endpoints: these answer `account-restricted` (403). Its passkeys come only from enrolment tokens.

A passkey sign-in gives an aal2, phishing-resistant session, which Identity's break-glass actions require.

