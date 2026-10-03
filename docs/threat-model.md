# Authentication Threat Model

**Status:** Living document. Revised in every phase that changes the attack surface.
**Baseline:** OWASP ASVS 5.0 Level 2, with relevant Level 3 requirements for authentication and session management (Security Architecture §1). NIST SP 800-63-4 for assurance terminology.

This document records design intent and planned controls. It is not a claim of conformance or certification. Verified controls, with evidence, are tracked in the control register in §6 as each phase lands.

## 1. Assets

| Asset | Why it matters |
|---|---|
| Password hashes | Offline cracking leads to account takeover across reused passwords |
| Session tokens | Bearer access to the account |
| TOTP secrets, backup codes, passkey public keys | Second-factor integrity |
| Verification, reset and email-change tokens | Account recovery and takeover path |
| Federated identity links | Sign-in by an external provider |
| `NUXT_AUTHENTICATION_SECRET` | Forges or decrypts signed values |
| Account existence | Enumeration enables targeted attacks and is a privacy disclosure |

## 2. Trust boundaries

1. **Browser → Nitro server.** All input is untrusted. Client-side guards are UX only.
2. **Nitro server → PostgreSQL** (host-supplied pool). The layer trusts only its own schema.
3. **Server → mail provider** (host-supplied mailer). Messages carry single-use secrets in URLs.
4. **Server → external identity providers** (OAuth/OIDC).
5. **Server → Have I Been Pwned range API.** Only a 5-character hash prefix leaves the server.
6. **Server → event sink** (host-supplied). It receives no secrets.
7. **Supply chain**: npm dependencies, GitHub Actions, the Git-backed package consumed by hosts.

## 3. Threats and planned controls

| # | Threat | Planned controls | Phase |
|---|---|---|---|
| T1 | Credential stuffing and password spraying | Per-account and per-IP throttling, temporary lockout, MFA required by default, compromised-password check | 2, 3 |
| T2 | Account enumeration | Uniform `invalid-credentials` errors, identical responses for reset and registration of existing emails, timing equalisation | 2 |
| T3 | Offline cracking after database theft | Memory-hard password hashing using the engine's reviewed implementation, no custom cryptography, minimum length 15 | 2 |
| T4 | Session hijacking | `__Secure-` prefixed (over https), `HttpOnly`, `Secure`, `SameSite=Lax`, host-only cookies; opaque tokens stored server-side with no cookie cache; idle (sliding) and absolute timeouts; revocation | 2 |
| T5 | Session fixation | Session rotated on sign-in, privilege change and step-up | 2 |
| T6 | CSRF on state-changing endpoints | SameSite cookies plus origin checks against `baseUrl`; no state change on GET | 2 |
| T7 | Reset/verification token abuse | Reset tokens: single-use, 30 minutes, hashed at rest, never logged. Email-verification links: signed, expire after 1 hour; reuse only re-confirms the same address | 2 |
| T8 | MFA bypass | No session issued before the second factor; the interim challenge is bound to the first-factor attempt; TOTP replay prevention; backup codes hashed and single-use | 3 |
| T9 | Phishing | Passkeys (WebAuthn, user verification required) available to all. Hosts require them for privileged administration with `requireAuthenticatedPrincipal(event, { phishingResistant: true })` | 3 |
| T10 | Federated account takeover | Link by provider subject only; never auto-link to an unverified email; explicit linking while signed in | 4 |
| T11 | Sensitive change without the owner present | Re-authentication within `maxAgeSeconds` for password, email, MFA and session changes; security notification emails | 2, 3 |
| T12 | Secret leakage via logs or events | Events carry no secrets or email addresses; mailers must not log action URLs; structured redaction | 1 (contract), 2 |
| T13 | Misconfiguration in a host | Ports fail closed, policy floors validated at startup, secret-strength check at startup | 1, 2 |
| T14 | Supply-chain compromise | Pinned lockfile, minimal dependencies, Renovate/Dependabot, secret scanning, pinned Action versions | 1, ongoing |
| T15 | Cross-capability data access | Capability-owned schema (ADR-0002), no cross-schema foreign keys, least-privilege database role | 2 |

## 4. Legacy defects this design closes

The [legacy review](legacy-review.md) found these in `legacy-authentication`, and they must not recur:

- password verification that accepted a fixed password for every account;
- unsigned, client-editable session tokens;
- auto-linking federated sign-ins by email without verification;
- an MFA step that returned the raw user ID to the browser;
- status-revealing login errors;
- a lockout check with no failure counting.

Phase 2 and 3 tests include explicit negative cases for each.

## 5. Out of scope for this capability

- tenant isolation, which belongs to Identity and Authorization;
- authorisation decisions;
- audit storage, which belongs to the event sink owner;
- transport security and security headers for the whole application, which the host configures (the layer documents its requirements).

## 6. Control register

| Control | Status | Evidence |
|---|---|---|
| Required ports fail closed | Implemented (phase 1) | `tests/composition.test.ts` |
| Policy floors validated; unknown keys rejected | Implemented (phase 1) | `tests/policy.test.ts` |
| Error codes cannot reveal account existence | Implemented (contract, phase 1) | `tests/contracts.test.ts` |
| Event sink failure cannot alter outcomes | Implemented (phase 1) | `tests/composition.test.ts` |
| Contract free of engine/vendor types | Implemented (phase 1) | `tests/contracts.test.ts` |
| Database migrations idempotent and race-safe; tables confined to the capability schema | Implemented (phase 2) | `tests/database.test.ts` |
| Engine schema drift detected | Implemented (phase 2) | `tests/database.test.ts` |
| T1 Per-account lockout and per-client throttling; lock notification | Implemented (phase 2) | `tests/database.test.ts`, `tests/integration/api.test.ts` |
| T1 Compromised-password check (k-anonymity, padded, fails open) | Implemented (phase 2) | `tests/internals.test.ts` |
| T2 Uniform responses for sign-in, sign-up and reset | Implemented (phase 2) | `tests/integration/api.test.ts` |
| T3 scrypt password hashing (engine), minimum length 15 | Implemented (phase 2) | `tests/internals.test.ts` (policy) |
| T4 HttpOnly, SameSite=Lax cookies; server-side revocation; idle and absolute timeouts | Implemented (phase 2) | `tests/integration/api.test.ts` |
| T5 Previous session revoked on sign-in | Implemented (phase 2) | `tests/integration/api.test.ts` |
| T6 Origin check on state-changing requests | Implemented (phase 2) | `tests/integration/api.test.ts` |
| T7 Single-use, hashed reset tokens | Implemented (phase 2) | `tests/integration/api.test.ts`, `tests/internals.test.ts` |
| T11 Current password required to change password; notifications for change, reset and lockout | Implemented (phase 2) | `tests/integration/api.test.ts` |
| T12 Events contain no email addresses, passwords or tokens | Implemented (phase 2) | `tests/integration/api.test.ts` |
| T13 Secret length and https base URL enforced | Implemented (phase 2) | `tests/internals.test.ts` |
| Telemetry and client-IP tracking disabled in the engine | Implemented (phase 2) | `tests/internals.test.ts` |
| Open-redirect protection for return paths | Implemented (phase 2) | `tests/internals.test.ts`, `tests/integration/api.test.ts` |
| MFA required by default; sessions without a second factor limited to enrolment (`requireAuthenticatedPrincipal` defaults to aal2) | Implemented (phase 3) | `tests/integration/mfa.test.ts` |
| T8 No session before the second factor; 5-minute interim cookie | Implemented (phase 3) | `tests/integration/mfa.test.ts` |
| T8 TOTP replay rejected (last-used time step per user, atomic) | Implemented (phase 3) | `tests/integration/mfa.test.ts`, `tests/internals.test.ts` |
| T8 TOTP activated only after a first valid code; secret encrypted at rest | Implemented (phase 3) | `tests/integration/mfa.test.ts` |
| T8 Backup codes: about 95 bits, single-use, stored as HMAC-SHA-256 digests keyed with the server secret | Implemented (phase 3) | `tests/integration/mfa.test.ts` |
| T8 Second-factor lockout after repeated failures | Implemented (phase 3) | `tests/integration/mfa.test.ts` |
| T9 Passkeys with user verification enforced by the layer (the engine does not require it) | Implemented (phase 3) | `tests/integration/mfa.test.ts` |
| T9 Forged assertions rejected; another principal's passkey cannot be removed | Implemented (phase 3) | `tests/integration/mfa.test.ts` |
| T11 Step-up: sensitive operations need authentication within 15 minutes; re-authenticate by password, TOTP or passkey | Implemented (phase 3) | `tests/integration/api.test.ts`, `tests/integration/mfa.test.ts` |
| Remembered devices off by default (policy `rememberedDevice.days: 0`) | Implemented (phase 3) | `tests/integration/mfa.test.ts`, `tests/policy.test.ts` |
| Notifications for MFA enrolment and removal, backup-code use and regeneration | Implemented (phase 3) | `tests/integration/mfa.test.ts` |
| T10 Federated account linking | Planned | Phase 4 |

### ASVS 5.0 mapping (by section)

This maps controls to OWASP ASVS 5.0 chapters and sections. Requirement-level identifiers must be checked against the official 5.0.0 text before they are cited as evidence. That check is an open action and is listed below.

| ASVS 5.0 area | Controls |
|---|---|
| V6 Authentication: password security | Minimum 15 / maximum 128 characters, breached-password check, no composition rules, scrypt hashing |
| V6 Authentication: general security | Uniform errors, per-account lockout, per-client throttling, security notifications |
| V6 Authentication: factor lifecycle and recovery | Single-use reset tokens hashed at rest, reset revokes sessions, factor changes require recent authentication and notify |
| V6 Authentication: multi-factor | MFA required by default, TOTP replay protection, backup codes hashed and single-use, second-factor lockout |
| V6 Authentication: cryptographic authenticators | Passkeys with user verification, signature counters checked by the engine |
| V7 Session management | Opaque server-side tokens, HttpOnly/SameSite cookies, rotation on sign-in and privilege change, idle and absolute timeouts, revocation, active-session list, re-authentication for sensitive operations |
| V3 Web frontend security (CSRF) | Origin check on state-changing requests, SameSite=Lax |

### Known gaps and risk treatment

| Gap | Risk | Treatment |
|---|---|---|
| Compromised-password check fails open when HIBP is unreachable | A breached password may be accepted during an outage | Logged warning. Length minimum of 15 still applies. Revisit if outages are frequent. |
| Email-verification links are stateless signed tokens, so they can be reused until expiry | Reuse only re-verifies the same address | Accepted. 1-hour expiry. |
| Per-client throttling relies on correct `trustProxy` configuration | Behind a proxy without `trustProxy`, all clients share one address and hit the limit together; with `trustProxy` but no overwriting proxy, attackers can spoof addresses | Documented in the composition contract. The per-account lockout is unaffected. |
| ASVS mapping is by section, not yet by requirement identifier | Evidence is not yet traceable to individual requirements | Open action: verify identifiers against the official ASVS 5.0.0 text and add them to the register. |
| Remembered devices, when a host enables them, let a stolen device cookie skip the second factor | Second-factor bypass on that device for up to `days` | Off by default. A host that enables it must record the risk. |
| Passkeys need a registrable domain as the relying-party ID | IP-address origins cannot use passkeys in browsers | Production base URLs use a domain. Tests use a software authenticator. |
