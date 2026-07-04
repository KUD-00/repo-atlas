import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import picomatch from 'picomatch'

const MAX_BUFFER = 1024 * 1024 * 512

export function git(root, args, input) {
  return execFileSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    input,
    maxBuffer: MAX_BUFFER,
  })
}

export function repoRoot(cwd = process.cwd()) {
  try {
    return git(cwd, ['rev-parse', '--show-toplevel']).trim()
  } catch {
    throw new Error(`not inside a git repository: ${cwd}`)
  }
}

export function headCommit(root) {
  try {
    return git(root, ['rev-parse', '--short', 'HEAD']).trim()
  } catch {
    return null
  }
}

/** Full HEAD sha — the stamp anchor. Null in a repo with no commits yet. */
export function headCommitFull(root) {
  try {
    return git(root, ['rev-parse', 'HEAD']).trim()
  } catch {
    return null
  }
}

/**
 * Repo paths with uncommitted changes (staged or not, incl. untracked).
 * Used to mark stamps taken against worktree state that HEAD doesn't contain.
 */
export function dirtyPaths(root) {
  const out = new Set()
  let raw
  try {
    raw = git(root, ['status', '--porcelain', '-z'])
  } catch {
    return out
  }
  const fields = raw.split('\0')
  for (let i = 0; i < fields.length; i++) {
    const f = fields[i]
    if (!f || f.length < 4) continue
    out.add(f.slice(3))
    // renames carry the origin path as the NEXT NUL field
    if (f[0] === 'R' || f[0] === 'C') out.add(fields[++i])
  }
  return out
}

export function atlasDir(root) {
  return path.join(root, '.atlas')
}

/**
 * Version of the on-disk .atlas data format (config.json + notes layout +
 * frontmatter fields). The tool migrates OLDER data forward transparently
 * (absent formatVersion = 1) and refuses NEWER data with a clear "update the
 * tool" error — so the CLI can live outside the repo without version pinning.
 */
export const DATA_FORMAT = 1

export function loadConfig(root) {
  const file = path.join(atlasDir(root), 'config.json')
  if (!fs.existsSync(file)) return null
  const config = JSON.parse(fs.readFileSync(file, 'utf8'))
  const version = config.formatVersion ?? 1
  if (version > DATA_FORMAT) {
    throw new Error(
      `.atlas data is format v${version}, but this repo-atlas only knows v${DATA_FORMAT} — ` +
      `update the tool (git pull in the repo-atlas checkout).`,
    )
  }
  // version < DATA_FORMAT: apply forward migrations here as the format evolves.
  return config
}

export const DEFAULT_EXCLUDE = [
  '**/*.lock',
  '**/pnpm-lock.yaml',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/*.{png,jpg,jpeg,gif,ico,webp,avif,woff,woff2,ttf,eot,otf,mp3,mp4,webm,pdf,zip,gz,tar,wasm,bin}',
  '**/*.min.{js,css}',
  '**/__snapshots__/**',
]

/**
 * Scan the repository working tree.
 *
 * Returns { files: Map<relPath, blobHash>, dirs: Map<relPath, dirHash> }.
 * The root directory is keyed as '' in dirs.
 *
 * - Files come from `git ls-files` (tracked) + `--others --exclude-standard`
 *   (untracked but not gitignored), so .gitignore is respected for free.
 * - config.exclude patterns (picomatch) filter on top; `.atlas/**` is always excluded.
 * - A file's hash is its git blob hash of the current working-tree content.
 * - A directory's hash covers its IMMEDIATE children only: child file blobs and
 *   child directory names. So editing a file marks the file and its direct
 *   parent outdated; adding/removing/renaming entries marks the directory.
 *   Deep edits do not cascade to every ancestor.
 */
export function scan(root, config) {
  const patterns = ['.atlas/**', ...(config?.exclude ?? [])]
  const isExcluded = picomatch(patterns, { dot: true })

  const tracked = git(root, ['ls-files', '-z']).split('\0')
  const untracked = git(root, ['ls-files', '-z', '--others', '--exclude-standard']).split('\0')
  const candidates = [...new Set([...tracked, ...untracked])]
    .filter((p) => p && !isExcluded(p))
    .filter((p) => {
      try {
        return fs.lstatSync(path.join(root, p)).isFile()
      } catch {
        return false
      }
    })
    .sort()

  const files = new Map()
  if (candidates.length > 0) {
    const out = git(root, ['hash-object', '--stdin-paths'], candidates.join('\n') + '\n')
    const hashes = out.trim().split('\n')
    if (hashes.length !== candidates.length) {
      throw new Error(`git hash-object returned ${hashes.length} hashes for ${candidates.length} paths`)
    }
    candidates.forEach((p, i) => files.set(p, hashes[i]))
  }

  // children: dirPath -> Map<childName, {type, hash?}>
  const children = new Map()
  children.set('', new Map())
  const ensureDir = (dir) => {
    if (children.has(dir)) return
    children.set(dir, new Map())
    const parent = dir.includes('/') ? dir.slice(0, dir.lastIndexOf('/')) : ''
    ensureDir(parent)
    children.get(parent).set(dir.slice(dir.lastIndexOf('/') + 1), { type: 'dir' })
  }
  for (const [file, hash] of files) {
    const parent = file.includes('/') ? file.slice(0, file.lastIndexOf('/')) : ''
    ensureDir(parent)
    children.get(parent).set(file.slice(file.lastIndexOf('/') + 1), { type: 'file', hash })
  }

  const dirs = new Map()
  for (const [dir, entries] of children) {
    const lines = [...entries.entries()]
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([name, e]) => (e.type === 'file' ? `F ${name} ${e.hash}` : `D ${name}`))
    dirs.set(dir, createHash('sha1').update(lines.join('\n')).digest('hex'))
  }

  return { files, dirs }
}

/** Current hash for a single scanned path, or null if it doesn't exist in the scan. */
export function hashFor(scanResult, relPath) {
  if (scanResult.files.has(relPath)) return { type: 'file', hash: scanResult.files.get(relPath) }
  if (scanResult.dirs.has(relPath)) return { type: 'dir', hash: scanResult.dirs.get(relPath) }
  return null
}
