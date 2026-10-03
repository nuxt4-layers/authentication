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
    })
    expect(manifest.publicExports).toEqual(Object.keys(pkg.exports))
  })

  it('provides the Authentication contract and requires no other capability', () => {
    expect(manifest.provides).toEqual([{ capability: 'Authentication', contractVersion: '1' }])
    expect(manifest.requires).toEqual([])
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
