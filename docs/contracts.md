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

Failures crossing the HTTP boundary return `AuthenticationErrorBody`:

```json
{ "code": "invalid-credentials", "messageKey": "authentication.error.invalid-credentials" }
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

## 7. Planned additions (not yet in contract version 1)

These are added as each phase lands, and recorded here when they do:

- server helpers `getAuthenticatedPrincipal(event)` and `requireAuthenticatedPrincipal(event, requirement?)`;
- the client composable `useAuthentication()`;
- the route middleware `authenticated` and `guest`;
- the HTTP endpoint map.
