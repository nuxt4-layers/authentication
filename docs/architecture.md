# Architecture

`@nuxt4-layers/authentication` is one package with three parts. Each part has one job, and dependencies run one way only:

```text
            ┌──────────────────────────┐
            │ Presentation (optional)  │  pages, components, text, styling
            └────────────┬─────────────┘
                         │ client API only
            ┌────────────▼─────────────┐
            │ Core                     │  server, endpoints, client API, route middleware
            └────────────┬─────────────┘
                         │
            ┌────────────▼─────────────┐
            │ Contract                 │  types, error codes, events, policy, ports
            └──────────────────────────┘
```

Presentation also uses the contract directly (types and pure helpers). Nothing points upwards.

## The three parts

| Part | Directories | Public surface | May depend on |
|---|---|---|---|
| **Contract** | `contracts/`, `shared/` | `@nuxt4-layers/authentication/contracts` | `zod` only. No Nuxt, Vue, h3, server or engine code |
| **Core** | `server/`, `app/`, `nuxt.config.ts` | `/api/authentication/*`, `get/requireAuthenticatedPrincipal` and the `provide*` server functions, `useAuthentication()`, `useAuthenticationPublicPolicy()`, the `authenticated`, `guest` and `authentication-signed-in` middleware, `authentication.routes` | The contract, and its private engine (Better Auth), database and HTTP libraries |
| **Presentation** | `presentation/`, `modules/presentation.ts`, `tailwind.css` | The default pages, the `Authentication*` components, `useAuthenticationText()`, `useAuthenticationForm()`, `authenticationClasses`, `@nuxt4-layers/authentication/presentation` (text catalogue and classes) | The contract, the core's client API (`useAuthentication()`, `useAuthenticationPublicPolicy()`), Vue and UI libraries (`uqr`) |

What each part means for the code that uses it:

- **Another capability that needs to know who is signed in** uses the contract and the core: `requireAuthenticatedPrincipal(event)` on the server, `useAuthentication()` in the app, and the `AuthenticatedPrincipal` type. It never sees page text, components or styling.
- **A host with its own design** sets `authentication.presentation: false`. The core works unchanged, and the host's pages live at the paths in `authentication.routes`. Or it keeps `presentation` on with `pages.enabled: false`, and builds pages from the `Authentication*` components.
- **A host using the default pages** changes nothing: presentation is on by default.

## Rules and how they are enforced

| Rule | Enforced by |
|---|---|
| The contract imports nothing but `zod` and its own modules | `tests/architecture.test.ts`, `tests/contracts.test.ts` |
| The contract exports no presentation (no page text or classes) | `tests/contracts.test.ts` |
| The core never imports presentation, uses its auto-imports or renders its components | `tests/architecture.test.ts` |
| Presentation imports only the contract, the client API, its own modules and UI libraries | `tests/architecture.test.ts` |
| Presentation reaches the server only through the client API (no `$fetch`, `useFetch` or `/api/` paths) | `tests/architecture.test.ts` |
| `presentation: false` registers no pages, components, auto-imports or route rules | `tests/architecture.test.ts` |
| Presentation uses only Theme Manager's semantic vocabulary and scales | `tests/presentation.test.ts`, and the end-to-end suite |
| No engine or vendor types in the contract | `tests/contracts.test.ts` |

## Configuration that crosses the boundary

`authentication.routes` is core configuration: the core's middleware redirects to `routes.signIn` and `routes.mfa`, and emails link to `routes.resetPassword`. When the default pages are enabled, the presentation module writes their paths into it at build time. That is presentation depending on core configuration, which is the permitted direction. With presentation off, the host sets the routes to its own pages.

## Operation and performance

- One package, one version and one pin, as before.
- Nuxt bundles only what is used. With `presentation: false`, none of the presentation code is registered, so none of it can be bundled, and the host's auto-import namespace holds only core names.
- Presentation is type-checked with the host's app code. The module adds `presentation/` to the generated TypeScript configuration only when it is enabled.

## Migrating from 0.5

| 0.5 | 0.6 |
|---|---|
| `AUTHENTICATION_MESSAGES_EN_GB`, `resolveMessage`, `formatMessage`, `AuthenticationMessages`, `AuthenticationMessageKey` from `./contracts` | Import them from `./presentation` |
| — | `safeRedirectPath`, `AuthenticationPublicPolicy` and `publicAuthenticationPolicy` are new in `./contracts`; `useAuthenticationPublicPolicy()` is a new client composable |
| Custom pages fetching `/api/authentication/policy` | Use `useAuthenticationPublicPolicy()` |
| No way to drop the presentation | `authentication: { presentation: false }` |

The default pages, component names, auto-import names, endpoints and middleware are unchanged.
