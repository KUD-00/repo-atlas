import fs from 'node:fs'
import path from 'node:path'
import { atlasDir } from './scan.js'
import type { GlossaryEntry } from './types.js'

export function loadGlossaryRaw(root: string): string {
  try {
    return fs.readFileSync(path.join(atlasDir(root), 'glossary.md'), 'utf8')
  } catch {
    return ''
  }
}

export function parseGlossary(raw: string): GlossaryEntry[] {
  if (!raw.trim()) return []
  const terms: GlossaryEntry[] = []
  const sections = raw.split(/^##\s+/mu).slice(1)
  for (const section of sections) {
    const nl = section.indexOf('\n')
    const term = (nl === -1 ? section : section.slice(0, nl)).trim()
    if (!term) continue
    let body = nl === -1 ? '' : section.slice(nl + 1).trim()
    let aliases: string[] = []
    const aliasMatch = body.match(/^(?:别名|aliases)[:：]\s*(.+)$/mu)
    if (aliasMatch) {
      aliases = aliasMatch[1].split(/[,、]/u).map((s) => s.trim()).filter(Boolean)
      body = body.replace(aliasMatch[0], '').trim()
    }
    terms.push({ term, aliases, def: body })
  }
  return terms
}