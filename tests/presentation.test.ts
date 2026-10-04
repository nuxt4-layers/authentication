import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { authenticationClasses, DELIBERATE_PAIRINGS } from '../app/utils/authentication-classes'

/**
 * Theme Manager's Semantic Presentation Guide: Fill, Pen and Edge of one
 * surface share a role and state, and cross-role pairings are deliberate.
 */

const CARD = 'fill-base-default'
const deliberate = new Set(DELIBERATE_PAIRINGS.map(({ token, on }) => `${token} on ${on}`))

type Token = { variant: string, utility: string, family: 'fill' | 'pen' | 'edge', name: string }

function tokens(classes: string): Token[] {
  return classes.split(/\s+/).flatMap((cls) => {
    const match = cls.match(/^((?:[\w-]+|aria-\[[^\]]+\]):)?(bg|text|border(?:-[trblxy])?|divide|outline)-(fill|pen|edge)-([a-z]+-[a-z]+)$/)
    if (!match) return []
    return [{ variant: match[1] ?? '', utility: match[2]!, family: match[3] as Token['family'], name: `${match[3]}-${match[4]}` }]
  })
}

/** The fill each pen or edge is drawn on, by the guide's reading of one class string. */
function pairings(classes: string): string[] {
  const all = tokens(classes)
  const fill = (variant: string) =>
    all.find(t => t.family === 'fill' && t.variant === variant)?.name ?? all.find(t => t.family === 'fill' && t.variant === '')?.name ?? CARD
  return all
    .filter(t => t.family !== 'fill')
    .map(t => `${t.name} on ${t.utility === 'outline' ? CARD : fill(t.variant)}`)
}

const sameRoleAndState = (pairing: string) => {
  const [token, , surface] = pairing.split(' ')
  return token!.replace(/^(pen|edge)-/, '') === surface!.replace(/^fill-/, '')
}

describe('semantic presentation', () => {
  it('pairs pen and edge with a fill of the same role and state, or a listed deliberate pairing', () => {
    const offending = Object.entries(authenticationClasses).flatMap(([name, classes]) =>
      pairings(classes).filter(p => !sameRoleAndState(p) && !deliberate.has(p)).map(p => `${name}: ${p}`))
    expect(offending).toEqual([])
  })

  it('advances fill, pen and edge together through hover and disabled states', () => {
    const offending = Object.entries(authenticationClasses).flatMap(([name, classes]) => {
      const all = tokens(classes)
      const roles = (variant: string) => new Set(all.filter(t => t.variant === variant).map(t => `${t.family}-${t.name.split('-')[1]}`))
      const base = roles('')
      return ['hover:', 'disabled:'].flatMap((variant) => {
        const changed = roles(variant)
        if (changed.size === 0) return []
        return [...base].filter(r => !r.startsWith('edge-base') && !changed.has(r)).map(r => `${name}: ${r} has no ${variant} state`)
      })
    })
    expect(offending).toEqual([])
  })

  it('uses every deliberate pairing and documents it for hosts', () => {
    const used = new Set(Object.values(authenticationClasses).flatMap(pairings))
    const contracts = readFileSync('docs/contracts.md', 'utf8')
    for (const { token, on } of DELIBERATE_PAIRINGS) {
      expect(used.has(`${token} on ${on}`), `${token} on ${on} unused`).toBe(true)
      expect(contracts, `${token} on ${on} undocumented`).toContain(`\`${token}\` on \`${on}\``)
    }
  })

  it('never reaches into Theme Manager private variables', () => {
    const files = [
      'tailwind.css',
      'playground/app/assets/css/main.css',
      ...readdirSync('app', { recursive: true, encoding: 'utf8' }).filter(f => /\.(vue|ts|css)$/.test(f)).map(f => join('app', f)),
    ]
    const offending = files.filter(f => /--(ui|api|tm)-[a-z]/.test(readFileSync(f, 'utf8')))
    expect(offending).toEqual([])
  })
})
