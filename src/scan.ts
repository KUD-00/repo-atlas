import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import fs from 'node:fs'
import path from 'node:path'
import type { AtlasConfig, PathType, ScanResult } from './types.js'

type Picomatch = (glob: string, options?: { dot?: boolean }) => (candidate: string) => boolean
const picomatch = createRequire(import.meta.url)('picomatch') as Picomatch

const MAX_BUFFER = 1024 * 1024 * 512

class UnsafeRepoFileError extends Error {}

interface OpenRepoFile {
  fd: number
  stat: fs.Stats
}

export interface RepoFileRead {
  buffer: Buffer
  size: number
  truncated: boolean
}

function createRepoFileReader(root: string) {
  const rootPath = path.resolve(root)
  const rootReal = fs.realpathSync(rootPath)
  const inside = (candidate: string, parent: string) => candidate !== parent && candidate.startsWith(parent + path.sep)

  const open = (relPath: string): OpenRepoFile => {
    const absolute = path.resolve(rootPath, relPath)
    if (!relPath || path.isAbsolute(relPath) || !inside(absolute, rootPath)) throw new UnsafeRepoFileError(`unsafe repository path: ${relPath}`)
    let fd: number | null = null
    try {
      fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0))
      const opened = fs.fstatSync(fd)
      const real = fs.realpathSync(absolute)
      const resolved = fs.statSync(real)
      const expected = path.resolve(rootReal, relPath)
      if (!opened.isFile() || real !== expected || !inside(real, rootReal) ||
          opened.dev !== resolved.dev || opened.ino !== resolved.ino) {
        throw new UnsafeRepoFileError(`repository path is symlinked, outside the repository, or not a regular file: ${relPath}`)
      }
      return { fd, stat: opened }
    } catch (error) {
      if (fd !== null) fs.closeSync(fd)
      if (error instanceof UnsafeRepoFileError) throw error
      const code = (error as NodeJS.ErrnoException).code
      if (code === 'ENOENT' || code === 'ENOTDIR' || code === 'ELOOP') throw new UnsafeRepoFileError(`unsafe or missing repository path: ${relPath}`)
      throw error
    }
  }

  const hash = (relPath: string): string => {
    const { fd, stat } = open(relPath)
    try {
      const digest = createHash('sha1').update(`blob ${stat.size}\0`)
      const chunk = Buffer.allocUnsafe(64 * 1024)
      let total = 0
      while (total < stat.size) {
        const read = fs.readSync(fd, chunk, 0, Math.min(chunk.length, stat.size - total), null)
        if (!read) throw new Error(`repository file changed while hashing: ${relPath}`)
        digest.update(chunk.subarray(0, read))
        total += read
      }
      const extra = fs.readSync(fd, chunk, 0, 1, null)
      const after = fs.fstatSync(fd)
      if (extra || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs) {
        throw new Error(`repository file changed while hashing: ${relPath}`)
      }
      return digest.digest('hex')
    } finally {
      fs.closeSync(fd)
    }
  }

  const read = (relPath: string, maxBytes = Number.POSITIVE_INFINITY): RepoFileRead => {
    const { fd, stat } = open(relPath)
    try {
      const bounded = Number.isFinite(maxBytes)
      const capacity = bounded ? Math.min(stat.size, Math.max(0, Math.floor(maxBytes))) : stat.size
      const buffer = Buffer.allocUnsafe(capacity)
      let total = 0
      while (total < capacity) {
        const count = fs.readSync(fd, buffer, total, capacity - total, null)
        if (!count) break
        total += count
      }
      const extra = Buffer.allocUnsafe(1)
      const hasExtra = fs.readSync(fd, extra, 0, 1, null) > 0
      return { buffer: buffer.subarray(0, total), size: stat.size, truncated: hasExtra || total < stat.size }
    } finally {
      fs.closeSync(fd)
    }
  }

  const validate = (relPath: string): void => {
    const { fd } = open(relPath)
    fs.closeSync(fd)
  }

  return { hash, read, validate }
}

export function readRepoFile(root: string, relPath: string, maxBytes = Number.POSITIVE_INFINITY): RepoFileRead | null {
  try {
    return createRepoFileReader(root).read(relPath, maxBytes)
  } catch {
    return null
  }
}

export function isSafeRepoFile(root: string, relPath: string): boolean {
  try {
    createRepoFileReader(root).validate(relPath)
    return true
  } catch {
    return false
  }
}

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
    .sort()

  const files = new Map<string, string>()
  const reader = createRepoFileReader(root)
  for (const repoPath of candidates) {
    try {
      if (isExcluded(repoPath)) {
        reader.validate(repoPath)
        ignored.add(repoPath)
      } else {
        files.set(repoPath, reader.hash(repoPath))
      }
    } catch {
      // A missing, unreadable, symlinked, or concurrently changing path does
      // not enter the trusted scan. Callers may retry on the next scan.
    }
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

export interface FileHashSnapshot {
  hashes: Map<string, string>
  /** Absent, outside-root, symlinked, or non-regular paths. */
  missing: string[]
  /** Regular contained files that could not be hashed. */
  failed: string[]
}

/** Hash an explicit file scope independently of atlas presentation excludes.
 * Scan hashes are reused when available; excluded paths fall back to bounded
 * `git hash-object` batches. Symlinks and realpath escapes are never followed. */
export function hashFilePaths(root: string, relPaths: string[], scanResult?: ScanResult): FileHashSnapshot {
  const hashes = new Map<string, string>()
  const missing: string[] = []
  const failed: string[] = []
  let reader: ReturnType<typeof createRepoFileReader>
  try {
    reader = createRepoFileReader(root)
  } catch {
    return { hashes, missing: [...relPaths], failed }
  }
  for (const relPath of relPaths) {
    try {
      const found = scanResult ? hashFor(scanResult, relPath) : null
      if (found?.type === 'file') {
        // Revalidate containment at consumption time; the hash itself belongs
        // to the caller's trusted scan snapshot, keeping status internally
        // consistent without rereading every included file.
        reader.validate(relPath)
        hashes.set(relPath, found.hash)
      } else {
        hashes.set(relPath, reader.hash(relPath))
      }
    } catch (error) {
      if (error instanceof UnsafeRepoFileError) missing.push(relPath)
      else failed.push(relPath)
    }
  }
  return { hashes, missing, failed }
}
