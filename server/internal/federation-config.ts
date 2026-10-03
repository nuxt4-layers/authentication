/**
 * PRIVATE. Identity-provider configuration from server-only runtime config.
 * A provider is enabled only when both its client ID and secret are set.
 */

export const FEDERATION_PROVIDER_IDS = ['google', 'microsoft', 'github', 'facebook', 'oidc'] as const
export type FederationProviderId = typeof FEDERATION_PROVIDER_IDS[number]

export interface FederationProvidersConfig {
  google?: { clientId?: string, clientSecret?: string }
  microsoft?: { clientId?: string, clientSecret?: string, tenantId?: string }
  github?: { clientId?: string, clientSecret?: string }
  facebook?: { clientId?: string, clientSecret?: string }
  /** One standards-based OpenID Connect provider (Okta, Keycloak, Auth0, Entra ID via OIDC, ...). */
  oidc?: { name?: string, discoveryUrl?: string, clientId?: string, clientSecret?: string }
}

export interface EnabledProvider {
  id: FederationProviderId
  name: string
  clientId: string
  clientSecret: string
  tenantId?: string
  discoveryUrl?: string
}

const DISPLAY_NAMES: Record<FederationProviderId, string> = {
  google: 'Google',
  microsoft: 'Microsoft',
  github: 'GitHub',
  facebook: 'Facebook',
  oidc: 'Single sign-on',
}

export function enabledProviders(config: FederationProvidersConfig | undefined): EnabledProvider[] {
  const enabled: EnabledProvider[] = []
  for (const id of FEDERATION_PROVIDER_IDS) {
    const entry = config?.[id] as (Record<string, string | undefined> | undefined)
    if (!entry?.clientId || !entry.clientSecret) continue
    if (id === 'oidc' && !entry.discoveryUrl) {
      throw new Error('The OIDC provider needs NUXT_AUTHENTICATION_PROVIDERS_OIDC_DISCOVERY_URL as well as a client ID and secret.')
    }
    enabled.push({
      id,
      name: (id === 'oidc' && entry.name) || DISPLAY_NAMES[id],
      clientId: entry.clientId,
      clientSecret: entry.clientSecret,
      tenantId: entry.tenantId || undefined,
      discoveryUrl: entry.discoveryUrl || undefined,
    })
  }
  return enabled
}

/** Callback URL registered with each provider. */
export function federationCallbackUrl(origin: string, id: FederationProviderId): string {
  return `${origin}/api/authentication/federation/callback/${id}`
}
