import fs from 'node:fs'
import path from 'node:path'
import { atlasDir } from './scan.js'

/**
 * Page artifacts — files an optional pipeline produced FOR a page (e.g. a
 * video storyboard distilled from a concept page). They hang off the page,
 * they are not part of it: the viewer shows them in a side-panel tab, print
 * scopes skip them, and status/stamp ignore them entirely — freshness is the
 * producing pipeline's business, the engine keeps no hashes.
 *
 * Storage convention: `.atlas/artifacts/<page key>/<name>.md|.json`, where the
 * page key is the repo path verbatim for path notes (dirs of the key mirror
 * the path) and `concepts/<slug>` for concept pages.
 */

export interface RawArtifact {
  /** Page the artifact belongs to: a repo path, or `concepts/<slug>`. */
  pageKey: string
  /** File name without the extension. */
  name: string
  kind: 'md' | 'json'
  body: string
}

export function artifactsRoot(root: string): string {
  return path.join(atlasDir(root), 'artifacts')
}

/** All artifacts under .atlas/artifacts/, sorted by page key then name.
 * Anything that isn't `.md`/`.json` (or sits directly under artifacts/,
 * i.e. belongs to no page) is skipped. */
export function loadArtifacts(root: string): RawArtifact[] {
  const base = artifactsRoot(root)
  if (!fs.existsSync(base)) return []
  const out: RawArtifact[] = []
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(full)
        continue
      }
      if (!entry.isFile()) continue
      const ext = entry.name.endsWith('.md') ? 'md' : entry.name.endsWith('.json') ? 'json' : null
      if (!ext) continue
      const pageKey = path.relative(base, dir).split(path.sep).join('/')
      if (!pageKey || pageKey.startsWith('..')) continue
      out.push({
        pageKey,
        name: entry.name.slice(0, -(ext.length + 1)),
        kind: ext,
        body: fs.readFileSync(full, 'utf8'),
      })
    }
  }
  walk(base)
  return out.sort((a, b) =>
    a.pageKey !== b.pageKey ? (a.pageKey < b.pageKey ? -1 : 1) : a.name < b.name ? -1 : 1,
  )
}
