import fs from 'node:fs'
import path from 'node:path'

/**
 * Import graph over the scanned files: who imports whom, resolved to scanned
 * repo paths. Two specifier families are resolved; everything else (npm deps,
 * node builtins) is ignored:
 *
 *   - relative:  './x', '../y/z.js'  → sibling file (extension/index probing;
 *     ESM-style './x.js' also tries x.ts/x.tsx — the TS convention)
 *   - workspace: a package name declared by any scanned package.json
 *     → that package's directory path
 *
 * Per-file extraction is memoized by the file's scan blob hash, so `serve`'s
 * rebuild-per-request stays cheap after the first build.
 */

const IMPORT_SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["']([^"']+)["']/gu
const CODE_EXT = /\.[cm]?[jt]sx?$/u

// blobHash -> string[] of raw specifiers
const specifierCache = new Map()

function extractSpecifiers(absFile, hash) {
  const hit = specifierCache.get(hash)
  if (hit) return hit
  let body
  try {
    body = fs.readFileSync(absFile, 'utf8')
  } catch {
    return []
  }
  const out = []
  IMPORT_SPECIFIER.lastIndex = 0
  let m
  while ((m = IMPORT_SPECIFIER.exec(body)) !== null) out.push(m[1])
  specifierCache.set(hash, out)
  return out
}

/** package name -> package dir path, from every package.json in the scan */
function workspacePackages(root, files) {
  const byName = new Map()
  for (const p of files.keys()) {
    if (p !== 'package.json' && !p.endsWith('/package.json')) continue
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'))
      if (pkg.name) byName.set(pkg.name, p === 'package.json' ? '' : p.slice(0, -'/package.json'.length))
    } catch {
      /* unparsable manifest — skip */
    }
  }
  return byName
}

function resolveRelative(fromFile, spec, files) {
  const dir = fromFile.includes('/') ? fromFile.slice(0, fromFile.lastIndexOf('/')) : ''
  const joined = path.posix.normalize(path.posix.join(dir, spec))
  if (joined.startsWith('..')) return null
  const candidates = [joined]
  if (/\.[cm]?js$/u.test(joined)) {
    // ESM TS convention: './x.js' on disk is x.ts/x.tsx
    candidates.push(joined.replace(/\.([cm]?)js$/u, '.$1ts'), joined.replace(/\.js$/u, '.tsx'))
  } else if (!/\.\w+$/u.test(joined)) {
    for (const ext of ['.ts', '.tsx', '.js', '.mjs', '.cjs', '.jsx']) candidates.push(joined + ext)
    for (const ext of ['.ts', '.tsx', '.js']) candidates.push(joined + '/index' + ext)
  }
  return candidates.find((c) => files.has(c)) ?? null
}

/**
 * Build the graph. Returns { paths: string[], edges: [srcIdx, dstIdx][] } —
 * endpoints are indexes into `paths`; a dst may be a package DIR (workspace
 * import) or a file (relative import). Also returns packageRoots (dir paths
 * of every scanned package.json) for viewer-side grouping.
 */
export function buildImportGraph(root, scanResult) {
  const files = scanResult.files
  const byName = workspacePackages(root, files)
  const pathIndex = new Map()
  const paths = []
  const idx = (p) => {
    let i = pathIndex.get(p)
    if (i === undefined) {
      i = paths.length
      paths.push(p)
      pathIndex.set(p, i)
    }
    return i
  }
  const edges = []
  const seen = new Set()
  for (const [file, hash] of files) {
    if (!CODE_EXT.test(file)) continue
    for (const spec of extractSpecifiers(path.join(root, file), hash)) {
      let target = null
      if (spec.startsWith('.')) {
        target = resolveRelative(file, spec, files)
      } else {
        // exact package name, or a subpath export "name/sub"
        const name = spec.startsWith('@')
          ? spec.split('/').slice(0, 2).join('/')
          : spec.split('/')[0]
        target = byName.get(name) ?? null
      }
      if (target === null || target === file) continue
      const key = file + '\0' + target
      if (seen.has(key)) continue
      seen.add(key)
      edges.push([idx(file), idx(target)])
    }
  }
  return { paths, edges, packageRoots: [...byName.values()].filter((p) => p !== '').sort() }
}
