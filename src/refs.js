import fs from 'node:fs'
import path from 'node:path'

/**
 * Reference integrity: note bodies point at other paths as inline code
 * (`packages/kernel/core`, `src/queue.ts`) — the viewer links whatever
 * resolves. Hash staleness can't see these going stale: when the TARGET
 * moves, the referencing note's own subject is untouched. This pass runs
 * the same resolution the viewer uses and reports the spans that look like
 * paths but no longer resolve, with a suggestion when the move map or a
 * unique basename identifies the new home.
 *
 * Deliberately conservative — a token is only "path-like" when it contains
 * a '/' , or is a bare *.ts/*.tsx filename whose basename exists nowhere in
 * the scan (bare .js/.json/.md names are usually products, not paths:
 * postgres.js, package.json, README.md).
 */

const INLINE_CODE = /`([^`\n]{1,120})`/g
const FENCE = /^```[\s\S]*?^```[^\S\n]*$/gm
const BARE_FILE_EXT = /\.[cm]?tsx?$/

function pathlike(t) {
  if (/[\s"'$(){}<>\\]/.test(t)) return false
  // URL routes (/api/x), home paths (~/.x), relative-dot and hidden paths,
  // package names (@scope/x), flags, headings — none are repo-path refs
  if (/^[@\-#/~.]/.test(t)) return false
  if (t.includes('@') || t.includes('://') || t.startsWith('node:')) return false
  if (!/^[\w./-]+$/.test(t)) return false // |-alternation, globs, ellipses, MIME params
  if (!t.includes('/')) return BARE_FILE_EXT.test(t)
  const segments = t.split('/')
  // a dot before the final segment means method chaining, not a directory
  // (`artifacts.submit/get/evidence`, `ctx.services.runtime.listRoles/…`)
  if (segments.slice(0, -1).some((s) => s.includes('.'))) return false
  // every segment a bare lowercase word: alternation/route shorthand
  // (`cli/init`, `tools/list`, `vite/client`) — real repo paths in prose
  // virtually always carry a dash, dot, or underscore somewhere
  if (segments.every((s) => /^[a-z]+$/.test(s))) return false
  return true
}

/** Same tail-stripping the viewer applies before resolving (`drivers/`, `ctx-*`). */
function normalize(t) {
  const stripped = t.replace(/\/$/, '').replace(/\/?\*$/, '').replace(/-\*$/, '')
  return stripped.includes('*') ? null : stripped
}

/**
 * Bases a ref may be relative to: the note's dir, every ancestor, and each
 * one's src/ (dir notes conventionally describe `flow/graph.ts` meaning
 * `src/flow/graph.ts`).
 */
function searchBases(base) {
  const out = []
  let p = base
  while (p) {
    out.push(p, p + '/src')
    p = p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : ''
  }
  out.push('', 'src')
  return out
}

export function checkRefs(root, scanResult, notes, moved = []) {
  // scan membership first; fs as fallback so refs into EXCLUDED-but-real
  // paths (docs/**, generated dirs) don't false-positive. Probe the same
  // variants deps.js resolves: ESM `./x.js` meaning x.ts, and bare `x`
  // meaning x.ts / x/index.ts.
  const present = (p) => scanResult.files.has(p) || scanResult.dirs.has(p) ||
    fs.existsSync(path.join(root, p))
  const exists = (p) => {
    if (present(p)) return true
    if (/\.[cm]?js$/.test(p)) return present(p.replace(/\.([cm]?)js$/, '.$1ts')) || present(p.replace(/\.js$/, '.tsx'))
    if (!/\.\w+$/.test(p)) {
      return ['.ts', '.tsx', '.js', '/index.ts'].some((ext) => present(p + ext))
    }
    return false
  }
  const movedTo = new Map(moved.map((m) => [m.from, m.to]))

  const basenames = new Map() // basename -> paths (files only), for bare names + suggestions
  for (const p of scanResult.files.keys()) {
    const b = path.posix.basename(p)
    if (!basenames.has(b)) basenames.set(b, [])
    basenames.get(b).push(p)
  }

  const broken = []
  for (const [notePath, note] of notes) {
    const base = note.type === 'dir' ? notePath : notePath.includes('/') ? notePath.slice(0, notePath.lastIndexOf('/')) : ''
    const prose = note.body.replace(FENCE, '')
    const seen = new Set()
    INLINE_CODE.lastIndex = 0
    let m
    while ((m = INLINE_CODE.exec(prose)) !== null) {
      const raw = m[1].trim()
      if (seen.has(raw) || !pathlike(raw)) continue
      seen.add(raw)
      const t = normalize(raw)
      // tail-stripping can demote a token below the path bar (`relayos/*` ->
      // `relayos`); a trailing slash stays deliberate dir-intent though
      if (!t || (!pathlike(t) && !raw.endsWith('/'))) continue
      if (searchBases(base).some((a) => exists(a ? a + '/' + t : t))) continue
      if (!t.includes('/')) {
        // bare *.ts filename: only stale if that basename vanished repo-wide
        if (basenames.has(t)) continue
        const hint = [...movedTo.entries()].find(([from]) => path.posix.basename(from) === t)
        broken.push({ note: notePath, noteFile: note.file, ref: raw, suggestion: hint?.[1] ?? null })
        continue
      }
      // resolve the same candidate set to a FORMER path, then follow the move map
      const formerly = searchBases(base).map((a) => (a ? a + '/' + t : t)).find((c) => movedTo.has(c))
      const unique = basenames.get(path.posix.basename(t))
      broken.push({
        note: notePath,
        noteFile: note.file,
        ref: raw,
        suggestion: formerly ? movedTo.get(formerly) : unique?.length === 1 ? unique[0] : null,
      })
    }
  }
  return broken
}
