import fs from 'node:fs'
import path from 'node:path'
import { atlasDir } from './scan.js'

/**
 * Glossary: .atlas/glossary.md in the target repo — the single source for
 * project jargon, so notes don't drift. Format, one term per section:
 *
 *   ## L0（内核原语）
 *   别名：L0 原语, L0 kernel
 *   零内部依赖的基础件……（正文到下一个 ## 为止）
 *
 * The alias line is optional ("别名：" or "aliases:", comma/、-separated).
 * The viewer highlights every term/alias occurrence in note prose and shows
 * the definition in a hover popover.
 */
export function loadGlossaryRaw(root) {
  try {
    return fs.readFileSync(path.join(atlasDir(root), 'glossary.md'), 'utf8')
  } catch {
    return ''
  }
}

export function parseGlossary(raw) {
  if (!raw.trim()) return []
  const terms = []
  const sections = raw.split(/^##\s+/mu).slice(1)
  for (const section of sections) {
    const nl = section.indexOf('\n')
    const term = (nl === -1 ? section : section.slice(0, nl)).trim()
    if (!term) continue
    let body = nl === -1 ? '' : section.slice(nl + 1).trim()
    let aliases = []
    const aliasMatch = body.match(/^(?:别名|aliases)[:：]\s*(.+)$/mu)
    if (aliasMatch) {
      aliases = aliasMatch[1].split(/[,、]/u).map((s) => s.trim()).filter(Boolean)
      body = body.replace(aliasMatch[0], '').trim()
    }
    terms.push({ term, aliases, def: body })
  }
  return terms
}
