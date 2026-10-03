# Legacy Layer Review: `nuxt4-layers/legacy-authentication`

**Reviewed:** 2026-10-03, commit `25d6050` on `master` (35 files, about 5 000 lines).
**Purpose:** Record what to keep and what to leave behind when building this layer. No legacy source is copied into this repository.

## 1. Summary

The legacy layer had a strong design in its comments and interfaces, but almost none of it worked from start to finish. Client and server were written against different APIs, the security code was placeholders, and the layer could only build inside its original monorepo. It is treated as a source of ideas, not code.

## 2. What it contained

| Area | Contents |
|---|---|
| Server | 7 API routes (`login`, `register`, `logout`, `session`, `account`, `changePassword`, `toggleMfa`), an `AuthenticationService`, a repository port with a JSON-file adapter |
| Client | A 1 280-line Pinia store, `useAuthentication` and `useAccountSettings` composables, `init-auth` (global), `authentication` and `guest` middleware |
| UI | Login/register, reset-password and verify-2FA pages, account pages, an `account` layout, nav and settings components |
| Data model | A rich `UserAccount`: change history, federated identities, eight MFA channels, security counters, compliance records |

## 3. Critical defects

### Security

- `verifyPassword` accepted the literal `password` for every hash containing `hash_placeholder`, and every generated hash contained it.
- Session tokens were unsigned base64 JSON (`mock.<payload>.signature`), so anyone could forge a user ID.
- `loginFederated` auto-linked a provider to any existing account with a matching email, without checking the provider had verified it.
- The MFA step returned the raw `userId` to the browser, and no endpoint existed to verify the second factor.
- `Account is ${status}` errors revealed account existence and state.
- The lockout was checked, but failed attempts were never counted.
- Password reset was a stub returning `'mock-token'`.

### Client and server mismatch

- The server set cookie `auth_token`; the store read `auth-token` and stored the email in it.
- Logged-in endpoints read only an `Authorization: Bearer` header while login set a cookie, so they always returned 401.
- The store called about 15 endpoints that did not exist (`/me`, `/security/change-password`, `/profile`, `/mfa/*`, `/recovery/*`, `/federation/*`).
- The store expected `{ success, account }`; the server returned `{ status, user }`, so login never succeeded.
- The store set `'MFA_REQUIRED'`; the page checked `'2FA_REQUIRED'`.
- `useAuthentication()` exposed `user`, `pending2faUserEmail`, `verify2FA` and `toggle2FA`, none of which existed on the store.
- The global middleware started `initialize()` without awaiting it, so route guards ran before the session was known.

### Build

- Duplicate `updateAccount` method; a call to the non-existent `verifyPasswordMock`; an import from the non-existent `../types/IUserRepository`.
- Relative imports reaching outside the repository (`../../../../../server/...`, `../../types/navigation`, `../../.nuxt/tsconfig.json`), plus `extends: ['@monorepo/theme-manager']`.
- No tests.

### Scope

- `permissions.ts` (RBAC) belongs to Authorization.
- Profile bio and avatar belong to Identity.
- `/api/navigation` and theme pages do not belong in authentication.

## 4. Ideas carried forward

1. **Repository port with swappable adapters.** Now the composition-supplied persistence port (ADR-0002).
2. **Never return secrets.** Now an explicit public principal type; engine records never cross the boundary.
3. **Two-step MFA challenge** with a short-lived token scoped to second-factor verification.
4. **Federated linking by provider subject, never by email.** The legacy comments stated this correctly.
5. **Credential change history and lockout/ageing fields.** These inform the phase 2 schema and the policy contract.
6. **Enumeration resistance**, including on password reset. Now part of the error contract.
7. **Session cookie posture** (HttpOnly, SameSite=Lax, Secure in production), strengthened with `__Host-` prefix, rotation and server-side revocation.
8. **Separate `guest` and authenticated route guards.**
9. **Accessible forms**: correct `autocomplete` attributes, per-field show/hide, `role="status"` messages.
10. **Clear boundaries**: authentication is *who*, authorisation is *what*.
