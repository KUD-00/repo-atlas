import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import picomatch from 'picomatch'
import type { AtlasConfig, PathType, ScanResult } from './types.js'

const MAX_BUFFER = 1024 * 1024 * 512

export function git(root: string, args: string[], input?: string): string {
  return execFileSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    input,
    maxBuffer: MAX_BUFFER,
  })
}

export function repoRoot(cwd = process.cwd()): string {
  try {
    return git(cwd, ['rev-parse', '--show-toplevel']).trim()
  } catch {
    throw new Error(`not inside a git repository: ${cwd}`)
  }
}

export function headCommit(root: string): string | null {
  try {
    return git(root, ['rev-parse', '--short', 'HEAD']).trim()
  } catch {
    return null
  }
}

/** Full HEAD sha — the stamp anchor. Null in a repo with no commits yet. */
export function headCommitFull(root: string): string | null {
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
export function dirtyPaths(root: string): Set<string> {
  const out = new Set<string>()
  let raw: string
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
    if (f[0] === 'R' || f[0] === 'C') out.add(fields[++i])
  }
  return out
}

export function atlasDir(root: string): string {
  return path.join(root, '.atlas')
}

export const DATA_FORMAT = 1

export function loadConfig(root: string): AtlasConfig | null {
  const file = path.join(atlasDir(root), 'config.json')
  if (!fs.existsSync(file)) return null
  const config = JSON.parse(fs.readFileSync(file, 'utf8')) as AtlasConfig
  const version = config.formatVersion ?? 1
  if (version > DATA_FORMAT) {
    throw new Error(
      `.atlas data is format v${version}, but this repo-atlas only knows v${DATA_FORMAT} — ` +
      `update the tool (git pull in the repo-atlas checkout).`,
    )
  }
  return config
}

export function buildExcludeMatcher(patterns: string[] | undefined): (p: string) => boolean {
  const rules = (patterns ?? []).map((raw) => {
    const neg = raw.startsWith('!')
    return { neg, match: picomatch(neg ? raw.slice(1) : raw, { dot: true }) }
  })
  return (p) => {
    let excluded = false
    for (const r of rules) if (r.match(p)) excluded = !r.neg
    return excluded
  }
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

export function scan(root: string, config: AtlasConfig): ScanResult {
  const isAtlas = picomatch('.atlas/**', { dot: true })
  const isExcluded = buildExcludeMatcher(config?.exclude)

  const tracked = git(root, ['ls-files', '-z']).split('\0')
  const untracked = git(root, ['ls-files', '-z', '--others', '--exclude-standard']).split('\0')
  const ignored = new Set<string>()
  const candidates = [...new Set([...tracked, ...untracked])]
    .filter((p) => p && !isAtlas(p))
    .filter((p) => {
      try {
        return fs.lstatSync(path.join(root, p)).isFile()
      } catch {
        return false
      }
    })
    .filter((p) => {
      if (!isExcluded(p)) return true
      ignored.add(p)
      return false
    })
    .sort()

  const files = new Map<string, string>()
  if (candidates.length > 0) {
    const out = git(root, ['hash-object', '--stdin-paths'], candidates.join('\n') + '\n')
    const hashes = out.trim().split('\n')
    if (hashes.length !== candidates.length) {
      throw new Error(`git hash-object returned ${hashes.length} hashes for ${candidates.length} paths`)
    }
    candidates.forEach((p, i) => files.set(p, hashes[i]))
  }

  const children = new Map<string, Map<string, { type: 'file'; hash: string } | { type: 'dir' }>>()
  children.set('', new Map())
  const ensureDir = (dir: string) => {
    if (children.has(dir)) return
    children.set(dir, new Map())
    const parent = dir.includes('/') ? dir.slice(0, dir.lastIndexOf('/')) : ''
    ensureDir(parent)
    children.get(parent)!.set(dir.slice(dir.lastIndexOf('/') + 1), { type: 'dir' })
  }
  for (const [file, hash] of files) {
    const parent = file.includes('/') ? file.slice(0, file.lastIndexOf('/')) : ''
    ensureDir(parent)
    children.get(parent)!.set(file.slice(file.lastIndexOf('/') + 1), { type: 'file', hash })
  }

  const dirs = new Map<string, string>()
  for (const [dir, entries] of children) {
    const lines = [...entries.entries()]
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([name, e]) => (e.type === 'file' ? `F ${name} ${e.hash}` : `D ${name}`))
    dirs.set(dir, createHash('sha1').update(lines.join('\n')).digest('hex'))
  }

  return { files, dirs, ignored }
}

export function hashFor(
  scanResult: ScanResult,
  relPath: string,
): { type: PathType; hash: string } | null {
  if (scanResult.files.has(relPath)) return { type: 'file', hash: scanResult.files.get(relPath)! }
  if (scanResult.dirs.has(relPath)) return { type: 'dir', hash: scanResult.dirs.get(relPath)! }
  return null
}