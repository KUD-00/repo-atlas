import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { TextDecoder } from 'node:util'

export const AUDIT_LIMITS = {
  jsonBytes: 32 * 1024 * 1024,
  collectionItems: 1_000_000,
  textCodeUnits: 256 * 1024,
} as const

const AUDIT_MAX_DEPTH = 256
const AUDIT_LOCK_BYTES = 16 * 1024
const UTF8 = new TextDecoder('utf-8', { fatal: true })
const PROCESS_STARTED_AT = new Date(Date.now() - process.uptime() * 1_000).toISOString()
const PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype'])
const AUDIT_ID_PREFIXES = new Set(['aobs', 'atf', 'atocc', 'adev', 'amig'])

export type AuditIdPrefix = 'aobs' | 'atf' | 'atocc' | 'adev' | 'amig'

interface SafeRoot {
  absolute: string
  real: string
}

interface LockHandle {
  fd: number
  file: string
  device: number
  inode: number
}

function errnoCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error
    ? String((error as NodeJS.ErrnoException).code)
    : undefined
}

function isInside(candidate: string, parent: string): boolean {
  return candidate !== parent && candidate.startsWith(parent + path.sep)
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index)
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!Number.isFinite(next) || next < 0xdc00 || next > 0xdfff) return true
      index += 1
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true
    }
  }
  return false
}

function safeRoot(root: string): SafeRoot {
  if (typeof root !== 'string' || root.length === 0) {
    throw new Error('audit repository root must be a nonempty path')
  }
  const absolute = path.resolve(root)
  let stat: fs.Stats
  try {
    stat = fs.lstatSync(absolute)
  } catch {
    throw new Error('audit repository root must be an existing safe directory')
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('audit repository root must be an existing safe directory, not a symlink')
  }
  const real = fs.realpathSync(absolute)
  if (real !== absolute) {
    throw new Error('audit repository root contains a symlink and is not safe')
  }
  return { absolute, real }
}

export function normalizeAuditRepoPath(value: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.includes('\0') ||
    value.includes('\\') ||
    path.posix.isAbsolute(value) ||
    /^[A-Za-z]:($|\/)/.test(value)
  ) {
    throw new Error('audit path must be a normalized repository-relative POSIX path')
  }

  const segments = value.split('/')
  if (
    segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..') ||
    path.posix.normalize(value) !== value
  ) {
    throw new Error('audit path must be a normalized repository-relative POSIX path')
  }
  return value
}

export function resolveSafeAuditFile(
  root: string,
  repoPath: string,
  options: { mustExist?: boolean; regularFile?: boolean } = {},
): string {
  const normalized = normalizeAuditRepoPath(repoPath)
  const repository = safeRoot(root)
  const target = path.join(repository.real, ...normalized.split('/'))
  if (!isInside(target, repository.real)) {
    throw new Error(`audit path is outside the safe repository: ${normalized}`)
  }

  const segments = normalized.split('/')
  let current = repository.real
  for (let index = 0; index < segments.length; index += 1) {
    current = path.join(current, segments[index])
    const stat = fs.lstatSync(current, { throwIfNoEntry: false })
    if (!stat) {
      if (options.mustExist) {
        throw new Error(`audit path is missing or not a safe regular file: ${normalized}`)
      }
      return target
    }
    if (stat.isSymbolicLink()) {
      throw new Error(`audit path contains a symlink and is not safe: ${normalized}`)
    }
    if (index < segments.length - 1 && !stat.isDirectory()) {
      throw new Error(`audit path parent is not a safe directory: ${normalized}`)
    }
    if (index === segments.length - 1 && options.regularFile && !stat.isFile()) {
      throw new Error(`audit path is not a safe regular file: ${normalized}`)
    }

    const real = fs.realpathSync(current)
    if (real !== current || !isInside(real, repository.real)) {
      throw new Error(`audit path resolves outside the safe repository: ${normalized}`)
    }
  }
  return target
}

function validateJsonValue(value: unknown): void {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }]
  let collectionItems = 0

  while (pending.length > 0) {
    const current = pending.pop()!
    if (current.depth > AUDIT_MAX_DEPTH) {
      throw new Error(`audit JSON exceeds the nesting depth limit of ${AUDIT_MAX_DEPTH}`)
    }
    if (typeof current.value === 'string') {
      if (current.value.length > AUDIT_LIMITS.textCodeUnits) {
        throw new Error(`audit JSON string exceeds the ${AUDIT_LIMITS.textCodeUnits} code-unit limit`)
      }
      continue
    }
    if (
      current.value === null ||
      typeof current.value === 'boolean' ||
      (typeof current.value === 'number' && Number.isFinite(current.value))
    ) {
      continue
    }
    if (!current.value || typeof current.value !== 'object') {
      throw new Error('audit JSON contains an unsupported value')
    }

    const entries = Array.isArray(current.value)
      ? current.value.map((item, index) => [String(index), item] as const)
      : Object.entries(current.value)
    collectionItems += entries.length
    if (collectionItems > AUDIT_LIMITS.collectionItems) {
      throw new Error(`audit JSON exceeds the ${AUDIT_LIMITS.collectionItems} collection-item limit`)
    }
    for (const [key, item] of entries) {
      if (key.length > AUDIT_LIMITS.textCodeUnits) {
        throw new Error(`audit JSON key exceeds the ${AUDIT_LIMITS.textCodeUnits} code-unit limit`)
      }
      if (PROTOTYPE_KEYS.has(key)) {
        throw new Error(`audit JSON contains prohibited prototype key: ${key}`)
      }
      pending.push({ value: item, depth: current.depth + 1 })
    }
  }
}

function readExactFile(fd: number, stat: fs.Stats, repoPath: string): Buffer {
  const buffer = Buffer.allocUnsafe(stat.size)
  let offset = 0
  while (offset < buffer.length) {
    const count = fs.readSync(fd, buffer, offset, buffer.length - offset, null)
    if (count === 0) {
      throw new Error(`audit JSON changed while being read: ${repoPath}`)
    }
    offset += count
  }

  const extra = Buffer.allocUnsafe(1)
  const hasExtra = fs.readSync(fd, extra, 0, 1, null) !== 0
  const after = fs.fstatSync(fd)
  if (
    hasExtra ||
    after.dev !== stat.dev ||
    after.ino !== stat.ino ||
    after.size !== stat.size ||
    after.mtimeMs !== stat.mtimeMs ||
    after.ctimeMs !== stat.ctimeMs
  ) {
    throw new Error(`audit JSON changed while being read: ${repoPath}`)
  }
  return buffer
}

export function readBoundedAuditJson(
  root: string,
  repoPath: string,
  maxBytes = AUDIT_LIMITS.jsonBytes,
): unknown {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new Error('audit JSON byte limit must be a nonnegative safe integer')
  }
  const normalized = normalizeAuditRepoPath(repoPath)
  const file = resolveSafeAuditFile(root, normalized, { mustExist: true, regularFile: true })
  const byteLimit = Math.min(maxBytes, AUDIT_LIMITS.jsonBytes)
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  let fd: number | null = null
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow)
    const opened = fs.fstatSync(fd)
    if (!opened.isFile()) {
      throw new Error(`audit JSON is not a safe regular file: ${normalized}`)
    }
    if (opened.size > byteLimit) {
      throw new Error(`audit JSON exceeds the ${byteLimit}-byte limit: ${normalized}`)
    }

    const repository = safeRoot(root)
    const real = fs.realpathSync(file)
    const resolved = fs.statSync(real)
    if (
      real !== file ||
      !isInside(real, repository.real) ||
      resolved.dev !== opened.dev ||
      resolved.ino !== opened.ino
    ) {
      throw new Error(`audit JSON is symlinked or outside the safe repository: ${normalized}`)
    }

    const bytes = readExactFile(fd, opened, normalized)
    let text: string
    try {
      text = UTF8.decode(bytes)
    } catch {
      throw new Error(`audit JSON is not strict UTF-8: ${normalized}`)
    }

    let value: unknown
    try {
      value = JSON.parse(text) as unknown
    } catch {
      throw new Error(`audit document is not valid JSON: ${normalized}`)
    }
    validateJsonValue(value)
    return value
  } catch (error) {
    const code = errnoCode(error)
    if (code === 'ENOENT' || code === 'ENOTDIR' || code === 'ELOOP') {
      throw new Error(`audit JSON is missing or not a safe regular file: ${normalized}`)
    }
    throw error
  } finally {
    if (fd !== null) fs.closeSync(fd)
  }
}

type CanonicalValue =
  | null
  | boolean
  | number
  | string
  | CanonicalValue[]
  | { [key: string]: CanonicalValue }

function canonicalize(value: unknown): CanonicalValue {
  const ancestors = new Set<object>()
  let collectionItems = 0

  const visit = (current: unknown, depth: number): CanonicalValue => {
    if (depth > AUDIT_MAX_DEPTH) {
      throw new Error(`canonical JSON exceeds the nesting depth limit of ${AUDIT_MAX_DEPTH}`)
    }
    if (current === null || typeof current === 'boolean') return current
    if (typeof current === 'string') {
      if (current.length > AUDIT_LIMITS.textCodeUnits) {
        throw new Error(`canonical JSON string exceeds the ${AUDIT_LIMITS.textCodeUnits} code-unit limit`)
      }
      if (hasLoneSurrogate(current)) {
        throw new Error('canonical JSON strings may not contain lone surrogates')
      }
      return current
    }
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) throw new Error('canonical JSON numbers must be finite')
      return current
    }
    if (!current || typeof current !== 'object') {
      throw new Error('canonical JSON contains an unsupported value')
    }
    if (ancestors.has(current)) throw new Error('canonical JSON contains a cyclic value')

    ancestors.add(current)
    try {
      if (Array.isArray(current)) {
        if (Object.getPrototypeOf(current) !== Array.prototype) {
          throw new Error('canonical JSON contains an unsupported array value')
        }
        const ownKeys = Reflect.ownKeys(current)
        if (
          ownKeys.some((key) =>
            typeof key !== 'string' ||
            (key !== 'length' && !/^(0|[1-9][0-9]*)$/.test(key))
          )
        ) {
          throw new Error('canonical JSON arrays may not have extra properties')
        }
        collectionItems += current.length
        if (collectionItems > AUDIT_LIMITS.collectionItems) {
          throw new Error(`canonical JSON exceeds the ${AUDIT_LIMITS.collectionItems} collection-item limit`)
        }
        const result: CanonicalValue[] = []
        for (let index = 0; index < current.length; index += 1) {
          if (!Object.hasOwn(current, index)) {
            throw new Error('canonical JSON arrays may not be sparse')
          }
          result.push(visit(current[index], depth + 1))
        }
        return result
      }

      const prototype = Object.getPrototypeOf(current)
      if (prototype !== Object.prototype && prototype !== null) {
        throw new Error('canonical JSON contains an unsupported object value')
      }
      const ownKeys = Reflect.ownKeys(current)
      if (ownKeys.some((key) => typeof key !== 'string')) {
        throw new Error('canonical JSON objects may not have symbol keys')
      }
      const keys = (ownKeys as string[]).sort()
      collectionItems += keys.length
      if (collectionItems > AUDIT_LIMITS.collectionItems) {
        throw new Error(`canonical JSON exceeds the ${AUDIT_LIMITS.collectionItems} collection-item limit`)
      }

      const result: Record<string, CanonicalValue> = Object.create(null) as Record<string, CanonicalValue>
      for (const key of keys) {
        if (key.length > AUDIT_LIMITS.textCodeUnits) {
          throw new Error(`canonical JSON key exceeds the ${AUDIT_LIMITS.textCodeUnits} code-unit limit`)
        }
        if (hasLoneSurrogate(key)) {
          throw new Error('canonical JSON keys may not contain lone surrogates')
        }
        if (PROTOTYPE_KEYS.has(key)) {
          throw new Error(`canonical JSON contains prohibited prototype key: ${key}`)
        }
        const descriptor = Object.getOwnPropertyDescriptor(current, key)
        if (!descriptor?.enumerable || !('value' in descriptor)) {
          throw new Error('canonical JSON objects may contain only enumerable data properties')
        }
        result[key] = visit(descriptor.value, depth + 1)
      }
      return result
    } finally {
      ancestors.delete(current)
    }
  }

  return visit(value, 0)
}

function serializeCanonical(value: CanonicalValue): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => serializeCanonical(item)).join(',')}]`
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${serializeCanonical(value[key])}`)
    .join(',')}}`
}

export function canonicalJson(value: unknown): string {
  return serializeCanonical(canonicalize(value))
}

export function stableAuditId(
  prefix: AuditIdPrefix,
  domainTag: string,
  parts: readonly string[],
): string {
  if (typeof prefix !== 'string' || !AUDIT_ID_PREFIXES.has(prefix)) {
    throw new Error(`unsupported stable audit ID prefix: ${String(prefix)}`)
  }
  if (
    typeof domainTag !== 'string' ||
    domainTag.length === 0 ||
    domainTag.length > AUDIT_LIMITS.textCodeUnits ||
    domainTag.includes('\0') ||
    hasLoneSurrogate(domainTag)
  ) {
    throw new Error('stable audit ID domain tag must be nonempty text without NUL or lone surrogates')
  }
  if (!Array.isArray(parts) || !parts.every((part) => typeof part === 'string')) {
    throw new Error('stable audit ID parts must be an array of strings')
  }
  if (parts.some((part) =>
    part.length > AUDIT_LIMITS.textCodeUnits ||
    part.includes('\0') ||
    hasLoneSurrogate(part)
  )) {
    throw new Error('stable audit ID parts must not contain NUL, lone surrogates, or over-limit text')
  }
  const digest = createHash('sha256')
    .update(`${domainTag}\0${parts.join('\0')}`, 'utf8')
    .digest('hex')
  return `${prefix}_${digest.slice(0, 24)}`
}

function ensureSafeAuditParent(root: string, repoPath: string): string {
  const repository = safeRoot(root)
  const segments = normalizeAuditRepoPath(repoPath).split('/').slice(0, -1)
  let current = repository.real

  for (const segment of segments) {
    current = path.join(current, segment)
    let stat = fs.lstatSync(current, { throwIfNoEntry: false })
    if (!stat) {
      try {
        fs.mkdirSync(current, { recursive: false, mode: 0o700 })
      } catch (error) {
        if (errnoCode(error) !== 'EEXIST') throw error
      }
      stat = fs.lstatSync(current, { throwIfNoEntry: false })
    }
    if (!stat || stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error(`audit output parent is not a safe directory: ${repoPath}`)
    }
    const real = fs.realpathSync(current)
    if (real !== current || !isInside(real, repository.real)) {
      throw new Error(`audit output parent is symlinked or outside the safe repository: ${repoPath}`)
    }
  }
  return current
}

function fsyncDirectory(directory: string): void {
  let fd: number | null = null
  try {
    fd = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0))
    fs.fsyncSync(fd)
  } catch {
    // Directory fsync is not supported on every platform/filesystem.
  } finally {
    if (fd !== null) fs.closeSync(fd)
  }
}

function removeOwnedFile(file: string, device: number | null, inode: number | null): void {
  if (device === null || inode === null) return
  try {
    const current = fs.lstatSync(file)
    if (
      !current.isSymbolicLink() &&
      current.isFile() &&
      current.dev === device &&
      current.ino === inode
    ) {
      fs.unlinkSync(file)
    }
  } catch {
    // The file was already renamed/removed or its parent is no longer reachable.
  }
}

export function atomicWriteAuditFile(root: string, repoPath: string, contents: string): void {
  if (typeof contents !== 'string') throw new Error('audit file contents must be a string')
  const normalized = normalizeAuditRepoPath(repoPath)
  const parent = ensureSafeAuditParent(root, normalized)
  const target = resolveSafeAuditFile(root, normalized, { regularFile: true })
  const temporaryName = `.${path.basename(target)}.${process.pid}.${randomUUID()}.tmp`
  const temporary = path.join(parent, temporaryName)
  const temporaryRepoPath = [...normalized.split('/').slice(0, -1), temporaryName].join('/')
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  let fd: number | null = null
  let device: number | null = null
  let inode: number | null = null

  try {
    fd = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow,
      0o600,
    )
    const opened = fs.fstatSync(fd)
    device = opened.dev
    inode = opened.ino
    fs.writeFileSync(fd, contents, 'utf8')
    fs.fsyncSync(fd)
    fs.closeSync(fd)
    fd = null

    resolveSafeAuditFile(root, normalized, { regularFile: true })
    resolveSafeAuditFile(root, temporaryRepoPath, { mustExist: true, regularFile: true })
    fs.renameSync(temporary, target)
    fsyncDirectory(parent)
  } finally {
    if (fd !== null) fs.closeSync(fd)
    removeOwnedFile(temporary, device, inode)
  }
}

function gitAdminDirectory(root: string): string {
  const repository = safeRoot(root)
  let output: string
  try {
    output = execFileSync(
      'git',
      ['-C', repository.real, 'rev-parse', '--path-format=absolute', '--absolute-git-dir'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    )
  } catch {
    throw new Error('audit locking requires an initialized Git worktree')
  }
  const gitDirectory = output.replace(/\r?\n$/, '')
  if (!path.isAbsolute(gitDirectory) || gitDirectory.includes('\0') || /[\r\n]/.test(gitDirectory)) {
    throw new Error('Git returned an unsafe audit administration path')
  }
  const real = fs.realpathSync(gitDirectory)
  const stat = fs.lstatSync(real)
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error('Git audit administration path is not a safe directory')
  }
  return real
}

function auditLockPath(root: string): string {
  const gitDirectory = gitAdminDirectory(root)
  const directory = path.join(gitDirectory, 'repo-atlas')
  let stat = fs.lstatSync(directory, { throwIfNoEntry: false })
  if (!stat) {
    try {
      fs.mkdirSync(directory, { recursive: false, mode: 0o700 })
    } catch (error) {
      if (errnoCode(error) !== 'EEXIST') throw error
    }
    stat = fs.lstatSync(directory, { throwIfNoEntry: false })
  }
  if (!stat || stat.isSymbolicLink() || !stat.isDirectory() || fs.realpathSync(directory) !== directory) {
    throw new Error('audit lock parent is not a safe regular directory')
  }
  return path.join(directory, 'audit-state.lock')
}

function sourceSnapshot(root: string): string {
  try {
    return execFileSync('git', ['-C', root, 'rev-parse', '--verify', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
  } catch {
    return 'unborn'
  }
}

function existingLockDescription(file: string): string {
  try {
    const stat = fs.lstatSync(file)
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > AUDIT_LOCK_BYTES) {
      return 'an unsafe or malformed existing lock'
    }
    const noFollow = fs.constants.O_NOFOLLOW ?? 0
    const fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow)
    try {
      const opened = fs.fstatSync(fd)
      if (!opened.isFile() || opened.size > AUDIT_LOCK_BYTES) return 'a malformed existing lock'
      const value = JSON.parse(fs.readFileSync(fd, 'utf8')) as unknown
      if (
        value &&
        typeof value === 'object' &&
        'pid' in value &&
        Number.isSafeInteger((value as { pid?: unknown }).pid)
      ) {
        const operation = 'operation' in value && typeof (value as { operation?: unknown }).operation === 'string'
          ? ` (${(value as { operation: string }).operation.slice(0, 128)})`
          : ''
        return `pid ${(value as { pid: number }).pid}${operation}`
      }
      return 'a malformed existing lock'
    } finally {
      fs.closeSync(fd)
    }
  } catch {
    return 'an existing lock'
  }
}

function acquireAuditLock(root: string, operation: () => unknown): LockHandle {
  const file = auditLockPath(root)
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  let fd: number | null = null
  let device: number | null = null
  let inode: number | null = null
  try {
    fd = fs.openSync(
      file,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow,
      0o600,
    )
    const opened = fs.fstatSync(fd)
    device = opened.dev
    inode = opened.ino
    const operationName = operation.name || 'anonymous'
    const receipt = canonicalJson({
      command: operationName,
      hostname: os.hostname(),
      operation: operationName,
      pid: process.pid,
      processStartedAt: PROCESS_STARTED_AT,
      sourceSnapshot: sourceSnapshot(root),
      startedAt: new Date().toISOString(),
      token: randomUUID(),
    })
    if (Buffer.byteLength(receipt, 'utf8') > AUDIT_LOCK_BYTES) {
      throw new Error('audit lock receipt exceeds its byte limit')
    }
    fs.writeFileSync(fd, receipt, 'utf8')
    fs.fsyncSync(fd)
    return { fd, file, device, inode }
  } catch (error) {
    if (fd !== null) fs.closeSync(fd)
    removeOwnedFile(file, device, inode)
    if (errnoCode(error) === 'EEXIST') {
      throw new Error(`audit state lock is already held by ${existingLockDescription(file)}`)
    }
    throw error
  }
}

function releaseAuditLock(lock: LockHandle): void {
  fs.closeSync(lock.fd)
  removeOwnedFile(lock.file, lock.device, lock.inode)
}

export function withAuditLock<T>(root: string, operation: () => T): T {
  if (typeof operation !== 'function') throw new Error('audit lock operation must be a function')
  const lock = acquireAuditLock(root, operation)
  try {
    return operation()
  } finally {
    releaseAuditLock(lock)
  }
}
