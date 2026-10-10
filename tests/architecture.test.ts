import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, normalize, relative } from 'node:path'
import { beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * The layer is three parts with one-way dependencies (docs/architecture.md):
 *
 *   contract      contracts/, shared/   imports nothing but zod
 *   core          server/, app/         imports the contract, never presentation
 *   presentation  presentation/         imports the contract and the client API only
 */

const root = normalize(join(import.meta.dirname, '..'))

function files(dir: string): string[] {
  return readdirSync(join(root, dir), { recursive: true, encoding: 'utf8' })
    .filter(file => /\.(ts|vue)$/.test(file))
    .map(file => join(dir, file))
}

/** Import specifiers, with relative ones resolved to repository paths. */
function imports(file: string): string[] {
  const source = readFileSync(join(root, file), 'utf8')
  return [...source.matchAll(/(?:from|import)\s*\(?\s*'([^']+)'/g)].map(([, specifier]) =>
    specifier!.startsWith('.') ? relative(root, join(root, dirname(file), specifier!)) : specifier!)
}

const inLayer = (path: string, ...dirs: string[]) => dirs.some(dir => path === dir || path.startsWith(`${dir}/`))

/** Auto-imports the presentation registers, and its components as used in templates. */
const PRESENTATION_IMPORTS = /\b(useAuthenticationText|useAuthenticationForm|authenticationClasses|DELIBERATE_PAIRINGS)\b/
const PRESENTATION_COMPONENTS = /<(Lazy)?Authentication[A-Z]\w*[\s/>]/

/** The client API presentation may call: the core's public composables. */
const CLIENT_API = ['app/composables/useAuthentication', 'app/composables/useAuthenticationPublicPolicy']

describe('architecture: contract', () => {
  it('imports nothing but zod and its own modules', () => {
    for (const file of [...files('contracts'), ...files('shared')]) {
      for (const target of imports(file)) {
        expect(target === 'zod' || inLayer(target, 'contracts', 'shared'), `${file} imports ${target}`).toBe(true)
      }
    }
  })
})

describe('architecture: core', () => {
  const core = [...files('server'), ...files('app')]

  it('never imports presentation', () => {
    for (const file of core) {
      for (const target of imports(file)) {
        expect(inLayer(target, 'presentation') || target === 'uqr', `${file} imports ${target}`).toBe(false)
      }
    }
  })

  it('never uses a presentation auto-import or component', () => {
    for (const file of core) {
      const source = readFileSync(join(root, file), 'utf8')
      expect(source, file).not.toMatch(PRESENTATION_IMPORTS)
      if (file.endsWith('.vue')) expect(source, file).not.toMatch(PRESENTATION_COMPONENTS)
    }
  })
})

describe('architecture: presentation', () => {
  const presentation = files('presentation')

  it('imports only the contract, the client API, its own modules and UI libraries', () => {
    for (const file of presentation) {
      for (const target of imports(file)) {
        const allowed = ['vue', '#imports', 'uqr'].includes(target)
          || inLayer(target, 'presentation', 'contracts')
          || CLIENT_API.includes(target.replace(/\.ts$/, ''))
        expect(allowed, `${file} imports ${target}`).toBe(true)
      }
    }
  })

  it('reaches the server only through the client API', () => {
    for (const file of presentation) {
      expect(readFileSync(join(root, file), 'utf8'), file).not.toMatch(/\$fetch|useFetch|useRequestFetch|\/api\//)
    }
  })
})

// ---------------------------------------------------------------------------
// The presentation module registers nothing when presentation is off.
// ---------------------------------------------------------------------------

const kit = vi.hoisted(() => ({
  addComponentsDir: vi.fn(),
  addImportsDir: vi.fn(),
  extendPages: vi.fn(),
}))

vi.mock('@nuxt/kit', () => ({
  ...kit,
  createResolver: () => ({ resolve: (...parts: string[]) => parts.join('/') }),
  defineNuxtModule: (definition: unknown) => definition,
}))

type Options = { presentation: boolean, pages: { enabled: boolean, paths: Record<string, string> } }
interface ModuleDefinition {
  defaults: Options
  setup: (options: Options, nuxt: unknown) => void
}

async function runModule(overrides: { presentation?: boolean, pages?: { enabled?: boolean } } = {}) {
  const definition = (await import('../modules/presentation')).default as unknown as ModuleDefinition
  const defaults = structuredClone(definition.defaults)
  const options = { ...defaults, ...overrides, pages: { ...defaults.pages, ...overrides.pages } }
  const routes = { signIn: '/sign-in' }
  const nuxt = {
    options: { runtimeConfig: { public: { authentication: { routes } } }, routeRules: {} as Record<string, unknown> },
    hook: vi.fn(),
  }
  definition.setup(options, nuxt)
  const pages: { path: string }[] = []
  for (const [extend] of kit.extendPages.mock.calls) extend(pages)
  return { nuxt, routes, pages }
}

describe('architecture: presentation can be switched off', () => {
  beforeEach(() => vi.clearAllMocks())

  it('registers pages, components and auto-imports by default', async () => {
    const { nuxt, pages } = await runModule()
    expect(kit.addComponentsDir).toHaveBeenCalledOnce()
    expect(kit.addImportsDir).toHaveBeenCalledOnce()
    expect(pages).toHaveLength(7)
    expect(Object.keys(nuxt.options.routeRules)).toHaveLength(7)
  })

  it('keeps components and auto-imports but no pages when the pages are disabled', async () => {
    const { nuxt, routes, pages } = await runModule({ pages: { enabled: false } })
    expect(kit.addComponentsDir).toHaveBeenCalledOnce()
    expect(pages).toHaveLength(0)
    expect(nuxt.options.routeRules).toEqual({})
    expect(routes).toEqual({ signIn: '/sign-in' })
  })

  it('registers nothing at all with presentation: false', async () => {
    const { nuxt, routes, pages } = await runModule({ presentation: false })
    expect(kit.addComponentsDir).not.toHaveBeenCalled()
    expect(kit.addImportsDir).not.toHaveBeenCalled()
    expect(kit.extendPages).not.toHaveBeenCalled()
    expect(nuxt.hook).not.toHaveBeenCalled()
    expect(pages).toHaveLength(0)
    expect(nuxt.options.routeRules).toEqual({})
    expect(routes).toEqual({ signIn: '/sign-in' })
  })
})
