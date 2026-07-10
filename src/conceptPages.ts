import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { atlasDir, hashFor } from './scan.js'
import type { ConceptPage, ConceptStatusEntry, ScanResult } from './types.js'

/**
 * Concept pages — the third page kind, next to file and dir notes.
 *
 * A concept page explains one important mechanism end-to-end (often for a
 * non-developer audience), so it can't anchor to a single path: it declares
 * the SET of repo paths it was written against (`sources`), and goes stale
 * when any of them changes. Storage: `.atlas/concepts/<slug>.md` with
 * frontmatter `title / audience / sources / sources_hash / anchor / stamped`.
 * There is no 'missing' state — pages exist only once someone writes them.
 */

export function conceptsRoot(root: string): string {
  return path.join(atlasDir(root), 'concepts')
}

export function conceptFileFor(root: string, slug: string): string {
  return path.join(conceptsRoot(root), slug + '.md')
}

function parseConceptPage(slug: string, file: string, raw: string): ConceptPage {
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/)
  const meta: Record<string, string> = {}
  let body = raw
  if (m) {
    body = raw.slice(m[0].length)
    for (const line of m[1].split(/\r?\n/)) {
      const kv = line.match(/^(\w+):\s*(.*)$/)
      if (kv) meta[kv[1]] = kv[2].trim()
    }
  }
  let sources: string[] = []
  if (meta.sources) {
    try {
      const parsed: unknown = JSON.parse(meta.sources)
      if (Array.isArray(parsed)) sources = parsed.filter((x): x is string => typeof x === 'string')
    } catch {
      /* malformed sources — treat as absent rather than failing the whole page */
    }
  }
  return {
    slug,
    file,
    title: meta.title || slug,
    audience: meta.audience === 'general' ? 'general' : 'dev',
    sources,
    sourcesHash: meta.sources_hash || null,
    anchor: meta.anchor || null,
    stamped: meta.stamped || null,
    body,
  }
}

export function loadConceptPages(root: string): ConceptPage[] {
  const base = conceptsRoot(root)
  if (!fs.existsSync(base)) return []
  const pages: ConceptPage[] = []
  for (const entry of fs.readdirSync(base, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.md')) continue
    const file = path.join(base, entry.name)
    pages.push(parseConceptPage(entry.name.slice(0, -'.md'.length), file, fs.readFileSync(file, 'utf8')))
  }
  return pages.sort((a, b) => (a.slug < b.slug ? -1 : 1))
}

/**
 * Current combined hash of a page's sources: each source's scan hash (blob
 * hash for files, dir hash for dirs) concatenated in `sources` order, sha1'd.
 * A source that doesn't resolve in the scan is reported broken and the hash
 * is withheld — freshness is meaningless while a source is gone.
 */
export function sourcesHashFor(
  scanResult: ScanResult,
  sources: string[],
): { hash: string | null; broken: string[] } {
  const parts: string[] = []
  const broken: string[] = []
  for (const s of sources) {
    const found = hashFor(scanResult, s)
    if (found) parts.push(found.hash)
    else broken.push(s)
  }
  if (broken.length) return { hash: null, broken }
  return { hash: createHash('sha1').update(parts.join('')).digest('hex'), broken }
}

export function conceptStatusEntries(root: string, scanResult: ScanResult): ConceptStatusEntry[] {
  return loadConceptPages(root).map((p) => {
    const { hash, broken } = sourcesHashFor(scanResult, p.sources)
    return {
      slug: p.slug,
      title: p.title,
      audience: p.audience,
      status: broken.length
        ? ('broken-source' as const)
        : p.sourcesHash !== null && p.sourcesHash === hash
          ? ('fresh' as const)
          : ('outdated' as const),
      sources: p.sources,
      brokenSources: broken,
      stamped: p.stamped,
      anchor: p.anchor,
      file: p.file,
      body: p.body,
    }
  })
}

/** Rewrite the page with a fresh sources_hash / anchor / stamped; the
 * authored fields (title, audience, sources) and body pass through. */
export function stampConceptPage(page: ConceptPage, hash: string, anchor: string | null): void {
  const lines = [
    `title: ${page.title}`,
    `audience: ${page.audience}`,
    `sources: ${JSON.stringify(page.sources)}`,
    `sources_hash: ${hash}`,
  ]
  if (anchor) lines.push(`anchor: ${anchor}`)
  lines.push(`stamped: ${new Date().toISOString()}`)
  fs.writeFileSync(page.file, `---\n${lines.join('\n')}\n---\n${page.body}`)
}
