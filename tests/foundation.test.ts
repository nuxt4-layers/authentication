import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = resolve(import.meta.dirname, '..')
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'))
const manifest = JSON.parse(readFileSync(resolve(root, 'capability.json'), 'utf8'))

describe('Authentication repository foundation', () => {
  it('keeps package and capability manifest identity/version aligned', () => {
    expect(manifest.name).toBe(pkg.name)
    expect(manifest.version).toBe(pkg.version)
    expect(manifest.classification).toBe('foundation')
  })

  it('publishes deliberate root, contracts and capability entry points', () => {
    expect(pkg.exports).toEqual({
      '.': './nuxt.config.ts',
      './contracts': './contracts/index.ts',
      './capability': './capability.json',
      './tailwind.css': './tailwind.css',
    })
    expect(manifest.publicExports).toEqual(Object.keys(pkg.exports))
  })

  it('provides the Authentication contract and requires only an optional presentation theme', () => {
    expect(manifest.provides).toEqual([{ capability: 'Authentication', contractVersion: '1' }])
    expect(manifest.requires).toEqual([expect.objectContaining({ capability: 'SemanticPresentationTheme', contractVersion: '1', optional: true })])
  })

  it('keeps Theme Manager a development dependency only (no runtime package dependency)', () => {
    expect(pkg.dependencies).not.toHaveProperty('@nuxt4-layers/theme-manager')
    expect(pkg.devDependencies['@nuxt4-layers/theme-manager']).toMatch(/#[0-9a-f]{40}$/)
  })

  it('declares database and mailer as required ports and the rest as optional', () => {
    const required = manifest.ports.filter((p: { optional: boolean }) => !p.optional).map((p: { port: string }) => p.port)
    expect(required).toEqual(['AuthenticationDatabase', 'AuthenticationMailer'])
  })

  it('declares every runtime import as a dependency rather than relying on the host', () => {
    expect(pkg.dependencies).toHaveProperty('zod')
    expect(pkg.peerDependencies).toHaveProperty('nuxt')
  })
})
