# Changelog

All notable changes to `@nuxt4-layers/authentication`. The package follows [semantic versioning](https://semver.org/), and contract version 1 is frozen for 1.x.

## Unreleased

- The layer's own tests pass on Windows as well as on Linux and macOS: the paths they compare with import specifiers and routes are written with `/` on every platform (`tests/support/paths.ts`). On Windows the contract, architecture and endpoint tests used to fail, or check nothing.

## 1.0.0 (2026-10-11)

The first stable release: everything in contract version 1 ([docs/contracts.md](docs/contracts.md)).

- Email and password with breach checks, verification, reset, lockout and throttling; TOTP with replay protection and backup codes; passkeys and passwordless sign-in; step-up; federation with any OIDC provider, linked only explicitly. MFA is required by default.
- Sessions read with Identity's standing on every request; credential recoveries recorded before they complete.
- Break-glass accounts, service identities' client credentials and short-lived opaque tokens, and retention with legal holds.
- The accessible, localisable default pages.
