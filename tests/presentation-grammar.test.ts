import { globSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { authenticationClasses } from '../app/utils/authentication-classes'

/**
 * The default pages and components style only through Theme Manager's
 * SemanticPresentationTheme grammar. Every class the layer uses is compiled
 * against Theme Manager's public presentation.css; a utility that falls back
 * to Tailwind's own defaults (base spacing multiples, default palette, fonts,
 * tracking, leading) or uses an arbitrary value is outside the grammar.
 */
const root = resolve(import.meta.dirname, '..')
const sources = globSync('app/**/*.{vue,ts}', { cwd: root }).map(file => readFileSync(resolve(root, file), 'utf8'))

function candidates(): string[] {
  const found = new Set<string>()
  for (const source of sources) {
    for (const literal of source.match(/(["'`])(?:(?!\1)[^\\\n]|\\.)*\1/g) ?? []) {
      for (const token of literal.slice(1, -1).split(/\s+/)) {
        if (/^[a-z-]+(?::[a-z-[\]=]+)*:?[a-z0-9-./[\]]+$/.test(token)) found.add(token)
      }
    }
  }
  return [...found]
}

async function compileWithThemeManager(classes: string[]): Promise<string> {
  const require = createRequire(import.meta.url)
  const { compile } = await import(require.resolve('@tailwindcss/node', { paths: [dirname(require.resolve('tailwindcss/package.json'))] }))
  // Theme Manager's public stylesheet export only, never its private file paths.
  const presentation = require.resolve('@nuxt4-layers/theme-manager/presentation.css')
  const compiler = await compile(`@import ${JSON.stringify(presentation)};`, { base: dirname(presentation), onDependency: () => {} })
  return compiler.build(classes)
}

describe('presentation grammar', () => {
  it('uses only Theme Manager tokens, never Tailwind defaults', async () => {
    const classes = candidates()
    const css = await compileWithThemeManager(classes)
    const offGrammar = classes.filter((name) => {
      const escaped = name.replace(/[:./[\]=]/g, m => `\\${m}`)
      const rule = css.match(new RegExp(`\\.${escaped}(?::[a-z-]+)*\\s*\\{([^}]*)\\}`))?.[1]
      if (!rule) return false // not a utility (plain text in a string literal)
      return /calc\(var\(--spacing\)|--color-(?!fill-|pen-|edge-)[a-z]+-\d|--tracking-|--leading-|--default-font|\[/.test(rule)
    })
    expect(offGrammar).toEqual([])
  })

  it('every colour utility names a semantic role (fill, pen or edge)', () => {
    const colour = /^(?:[a-z-]+:)*(?:bg|text|border|outline|divide|ring|fill|stroke|decoration|placeholder)-(?!fill-|pen-|edge-)(?:red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|slate|gray|zinc|neutral|stone|black|white)\b/
    expect(candidates().filter(name => colour.test(name))).toEqual([])
  })

  it('controls compose edge, fill and pen of one role, advancing together through each state', () => {
    const controls = ['primaryButton', 'secondaryButton', 'dangerButton', 'alertError', 'alertSuccess', 'alertInfo', 'card', 'input'] as const
    const problems: string[] = []
    for (const name of controls) {
      const byVariant = new Map<string, Map<string, string>>()
      for (const token of authenticationClasses[name].split(/\s+/)) {
        const match = token.match(/^((?:[a-z-]+(?:\[[^\]]+\])?:)*)(?:bg|text|border)-(fill|pen|edge)-([a-z]+)-([a-z]+)$/)
        if (!match) continue
        const [, variant, family, role, state] = match
        if (variant!.startsWith('focus-visible') || variant!.startsWith('aria-')) continue // deliberate cross-role indicators
        const families = byVariant.get(variant!) ?? new Map<string, string>()
        families.set(family!, `${role}-${state}`)
        byVariant.set(variant!, families)
      }
      for (const [variant, families] of byVariant) {
        if (families.size !== 3) problems.push(`${name} ${variant || 'default'}: ${[...families.keys()].join('+')} (needs edge, fill and pen)`)
        if (new Set(families.values()).size !== 1) problems.push(`${name} ${variant || 'default'}: mixed ${[...families.values()].join(', ')}`)
        const state = variant ? variant.replace(/:$/, '') : 'default'
        for (const value of families.values()) if (!value.endsWith(`-${state}`)) problems.push(`${name} ${variant}: state ${value} does not match`)
      }
      if (name.endsWith('Button')) {
        for (const variant of ['', 'hover:', 'active:', 'disabled:']) if (!byVariant.has(variant)) problems.push(`${name}: no ${variant || 'default'} state`)
      }
    }
    expect(problems).toEqual([])
  })
})
