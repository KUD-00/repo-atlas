import { execFileSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { AsyncLocalStorage } from 'node:async_hooks'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { TextDecoder, types as utilTypes } from 'node:util'

export const AUDIT_LIMITS = {
  jsonBytes: 32 * 1024 * 1024,
  collectionItems: 1_000_000,
  textCodeUnits: 256 * 1024,
  textTotalCodeUnits: 8 * 1024 * 1024,
} as const

const AUDIT_MAX_DEPTH = 256
const AUDIT_LOCK_BYTES = 16 * 1024
const AUDIT_ID_MAX_PARTS = 64
const AUDIT_ID_MAX_BYTES = 256 * 1024
const UTF8 = new TextDecoder('utf-8', { fatal: true })
const PROCESS_STARTED_AT = new Date(Date.now() - process.uptime() * 1_000).toISOString()
const PROTOTYPE_KEYS = new Set(['__proto__', 'constructor', 'prototype'])
const AUDIT_ID_PREFIXES = new Set(['aobs', 'atocc', 'adev', 'amig', 'acmp'])

export type AuditIdPrefix = 'aobs' | 'atocc' | 'adev' | 'amig' | 'acmp'

interface SafeRoot {
  absolute: string
  real: string
  device: number
  inode: number
}

interface LockHandle {
  fd: number
  gitAdmin: AnchoredGitAdmin
  parent: AnchoredLockParent
  root: AnchoredDirectory
  device: number
  inode: number
}

interface AuditSupportParentSeal {
  relativePath: string
  device: bigint
  inode: bigint
  mode: bigint
  ctimeNs: bigint
  mtimeNs: bigint
}

interface AuditSupportFileSeal {
  repoPath: string
  blobSha256: string
  size: bigint
  device: bigint
  inode: bigint
  mode: bigint
  ctimeNs: bigint
  mtimeNs: bigint
  parent: AuditSupportParentSeal
}

interface AuditSupportDirectorySeal {
  repoPath: string
  entriesDigest: string
  device: bigint
  inode: bigint
  mode: bigint
  ctimeNs: bigint
  mtimeNs: bigint
}

interface AuditSupportGitQuerySeal {
  arguments: readonly string[]
  maxBytes: number
  byteLength: number
  sha256: string
}

interface AuditSupportAbsenceSeal {
  repoPath: string
  maxBytes: number
  parent: AuditSupportParentSeal
}

interface AnchoredRootIdentityContext {
  root: AnchoredDirectory
  auditDirectory?: AnchoredDirectory
  auditSupportFiles?: Map<string, AuditSupportFileSeal>
  auditSupportDirectories?: Map<string, AuditSupportDirectorySeal>
  auditSupportGitQueries?: Map<string, AuditSupportGitQuerySeal>
  auditSupportAbsences?: Map<string, AuditSupportAbsenceSeal>
  verifyingAuditSupport?: boolean
  gitAdmin?: AnchoredGitAdmin
  lockParent?: AnchoredLockParent
}

const anchoredRootIdentity =
  new AsyncLocalStorage<AnchoredRootIdentityContext | undefined>()

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
  const retained = anchoredRootIdentity.getStore()
  if (retained !== undefined) {
    const retainedReal = retainedSafeRoot(retained.root)
    if (
      absolute !== retained.root.repository.absolute &&
      absolute !== retained.root.procPath &&
      absolute !== retainedReal.real
    ) {
      throw new Error(
        'audit repository root differs from the retained operation root identity',
      )
    }
    return retainedReal
  }
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
  const confirmed = fs.lstatSync(absolute)
  if (
    confirmed.isSymbolicLink() ||
    !confirmed.isDirectory() ||
    confirmed.dev !== stat.dev ||
    confirmed.ino !== stat.ino
  ) {
    throw new Error('audit repository root changed identity during validation')
  }
  return {
    absolute,
    real,
    device: confirmed.dev,
    inode: confirmed.ino,
  }
}

function retainedSafeRoot(root: AnchoredDirectory): SafeRoot {
  const opened = fs.fstatSync(root.fd)
  let real: string
  let visible: fs.Stats
  try {
    real = fs.realpathSync(root.procPath)
    visible = fs.lstatSync(real)
  } catch {
    throw new Error('retained audit repository root is no longer a safe directory')
  }
  if (
    !opened.isDirectory() ||
    opened.dev !== root.device ||
    opened.ino !== root.inode ||
    visible.isSymbolicLink() ||
    !visible.isDirectory() ||
    visible.dev !== root.device ||
    visible.ino !== root.inode ||
    fs.realpathSync(real) !== real
  ) {
    throw new Error('retained audit repository root changed identity')
  }
  return {
    absolute: real,
    real,
    device: root.device,
    inode: root.inode,
  }
}

export function anchoredAuditRootPath(root: string): string {
  const retained = anchoredRootIdentity.getStore()
  if (retained === undefined) return root
  const absolute = path.resolve(root)
  const retainedReal = retainedSafeRoot(retained.root)
  if (
    absolute !== retained.root.repository.absolute &&
    absolute !== retained.root.procPath &&
    absolute !== retainedReal.real
  ) {
    throw new Error(
      'audit repository root differs from the retained operation root identity',
    )
  }
  return retained.root.procPath
}

function verifySafeRootIdentity(repository: SafeRoot): void {
  let current: fs.Stats
  let real: string
  try {
    current = fs.lstatSync(repository.absolute)
    real = fs.realpathSync(repository.absolute)
  } catch {
    throw new Error('audit repository root changed or is no longer safe')
  }
  if (
    current.isSymbolicLink() ||
    !current.isDirectory() ||
    current.dev !== repository.device ||
    current.ino !== repository.inode ||
    real !== repository.real
  ) {
    throw new Error('audit repository root changed identity')
  }
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

class BoundedJsonParser {
  private index = 0
  private collectionItems = 0
  private textCodeUnits = 0

  constructor(
    private readonly source: string,
    private readonly repoPath: string,
  ) {}

  parse(): unknown {
    this.skipWhitespace()
    const value = this.parseValue(0)
    this.skipWhitespace()
    if (this.index !== this.source.length) this.invalid('unexpected trailing input')
    return value
  }

  private invalid(reason: string): never {
    throw new Error(`audit document is not valid JSON (${reason}): ${this.repoPath}`)
  }

  private skipWhitespace(): void {
    while (this.index < this.source.length) {
      const codeUnit = this.source.charCodeAt(this.index)
      if (codeUnit !== 0x20 && codeUnit !== 0x09 && codeUnit !== 0x0a && codeUnit !== 0x0d) {
        return
      }
      this.index += 1
    }
  }

  private parseValue(depth: number): unknown {
    if (depth > AUDIT_MAX_DEPTH) {
      throw new Error(`audit JSON exceeds the nesting depth limit of ${AUDIT_MAX_DEPTH}`)
    }
    const current = this.source[this.index]
    if (current === '"') return this.parseString('string')
    if (current === '{') return this.parseObject(depth)
    if (current === '[') return this.parseArray(depth)
    if (current === 't') return this.parseLiteral('true', true)
    if (current === 'f') return this.parseLiteral('false', false)
    if (current === 'n') return this.parseLiteral('null', null)
    if (current === '-' || (current >= '0' && current <= '9')) return this.parseNumber()
    this.invalid('expected a value')
  }

  private parseLiteral<T>(token: string, value: T): T {
    if (!this.source.startsWith(token, this.index)) this.invalid(`expected ${token}`)
    this.index += token.length
    return value
  }

  private parseNumber(): number {
    const numberPattern = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y
    numberPattern.lastIndex = this.index
    const match = numberPattern.exec(this.source)
    if (!match) this.invalid('invalid number')
    this.index = numberPattern.lastIndex
    const value = Number(match[0])
    if (!Number.isFinite(value)) this.invalid('number must be finite')
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      this.invalid('integer exceeds safe integer precision')
    }
    return value
  }

  private addCollectionItem(): void {
    this.collectionItems += 1
    if (this.collectionItems > AUDIT_LIMITS.collectionItems) {
      throw new Error(`audit JSON exceeds the ${AUDIT_LIMITS.collectionItems} collection-item limit`)
    }
  }

  private addTextCodeUnits(count: number, kind: 'key' | 'string'): void {
    if (count > AUDIT_LIMITS.textCodeUnits) {
      throw new Error(`audit JSON ${kind} exceeds the ${AUDIT_LIMITS.textCodeUnits} code-unit limit`)
    }
    this.textCodeUnits += count
    if (this.textCodeUnits > AUDIT_LIMITS.textTotalCodeUnits) {
      throw new Error(
        `audit JSON exceeds the aggregate string limit of ${AUDIT_LIMITS.textTotalCodeUnits} code units`,
      )
    }
  }

  private parseString(kind: 'key' | 'string'): string {
    this.index += 1
    const chunks: string[] = []
    let chunkStart = this.index
    let length = 0

    while (this.index < this.source.length) {
      const codeUnit = this.source.charCodeAt(this.index)
      if (codeUnit === 0x22) {
        const spanLength = this.index - chunkStart
        length += spanLength
        if (length > AUDIT_LIMITS.textCodeUnits) {
          throw new Error(`audit JSON ${kind} exceeds the ${AUDIT_LIMITS.textCodeUnits} code-unit limit`)
        }
        if (spanLength > 0) chunks.push(this.source.slice(chunkStart, this.index))
        this.index += 1
        this.addTextCodeUnits(length, kind)
        return chunks.join('')
      }
      if (codeUnit < 0x20) this.invalid('unescaped control character in string')

      if (codeUnit !== 0x5c) {
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
          const low = this.source.charCodeAt(this.index + 1)
          if (low < 0xdc00 || low > 0xdfff) {
            throw new Error('audit JSON string contains a lone surrogate')
          }
          this.index += 2
        } else {
          if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            throw new Error('audit JSON string contains a lone surrogate')
          }
          this.index += 1
        }
        if (length + this.index - chunkStart > AUDIT_LIMITS.textCodeUnits) {
          throw new Error(`audit JSON ${kind} exceeds the ${AUDIT_LIMITS.textCodeUnits} code-unit limit`)
        }
        continue
      }

      const spanLength = this.index - chunkStart
      length += spanLength
      if (spanLength > 0) chunks.push(this.source.slice(chunkStart, this.index))
      this.index += 1
      const escape = this.source[this.index]
      const simpleEscapes: Record<string, string> = {
        '"': '"',
        '\\': '\\',
        '/': '/',
        b: '\b',
        f: '\f',
        n: '\n',
        r: '\r',
        t: '\t',
      }
      if (escape in simpleEscapes) {
        chunks.push(simpleEscapes[escape])
        length += 1
        this.index += 1
      } else if (escape === 'u') {
        const high = this.parseUnicodeEscape()
        if (high >= 0xd800 && high <= 0xdbff) {
          if (this.source[this.index] !== '\\' || this.source[this.index + 1] !== 'u') {
            throw new Error('audit JSON string contains a lone surrogate')
          }
          this.index += 2
          const low = this.parseUnicodeEscapeDigits()
          if (low < 0xdc00 || low > 0xdfff) {
            throw new Error('audit JSON string contains a lone surrogate')
          }
          chunks.push(String.fromCharCode(high, low))
          length += 2
        } else {
          if (high >= 0xdc00 && high <= 0xdfff) {
            throw new Error('audit JSON string contains a lone surrogate')
          }
          chunks.push(String.fromCharCode(high))
          length += 1
        }
      } else {
        this.invalid('invalid string escape')
      }
      if (length > AUDIT_LIMITS.textCodeUnits) {
        throw new Error(`audit JSON ${kind} exceeds the ${AUDIT_LIMITS.textCodeUnits} code-unit limit`)
      }
      chunkStart = this.index
    }
    this.invalid('unterminated string')
  }

  private parseUnicodeEscape(): number {
    this.index += 1
    return this.parseUnicodeEscapeDigits()
  }

  private parseUnicodeEscapeDigits(): number {
    const digits = this.source.slice(this.index, this.index + 4)
    if (!/^[0-9a-fA-F]{4}$/.test(digits)) this.invalid('invalid Unicode escape')
    this.index += 4
    return Number.parseInt(digits, 16)
  }

  private parseArray(depth: number): unknown[] {
    this.index += 1
    this.skipWhitespace()
    const result: unknown[] = []
    if (this.source[this.index] === ']') {
      this.index += 1
      return result
    }

    while (true) {
      this.addCollectionItem()
      result.push(this.parseValue(depth + 1))
      this.skipWhitespace()
      const delimiter = this.source[this.index]
      this.index += 1
      if (delimiter === ']') return result
      if (delimiter !== ',') this.invalid('expected a comma or closing bracket')
      this.skipWhitespace()
    }
  }

  private parseObject(depth: number): Record<string, unknown> {
    this.index += 1
    this.skipWhitespace()
    const result: Record<string, unknown> = {}
    const keys = new Set<string>()
    if (this.source[this.index] === '}') {
      this.index += 1
      return result
    }

    while (true) {
      if (this.source[this.index] !== '"') this.invalid('expected an object key')
      const key = this.parseString('key')
      if (keys.has(key)) throw new Error(`audit JSON contains duplicate key: ${key}`)
      if (PROTOTYPE_KEYS.has(key)) {
        throw new Error(`audit JSON contains prohibited prototype key: ${key}`)
      }
      keys.add(key)
      this.addCollectionItem()
      this.skipWhitespace()
      if (this.source[this.index] !== ':') this.invalid('expected a colon after object key')
      this.index += 1
      this.skipWhitespace()
      result[key] = this.parseValue(depth + 1)
      this.skipWhitespace()
      const delimiter = this.source[this.index]
      this.index += 1
      if (delimiter === '}') return result
      if (delimiter !== ',') this.invalid('expected a comma or closing brace')
      this.skipWhitespace()
    }
  }
}

function auditSupportParentSeal(
  parent: AnchoredDirectory,
  repoPath: string,
): AuditSupportParentSeal | null {
  const stat = fs.fstatSync(parent.fd, { bigint: true })
  if (!stat.isDirectory()) {
    throw new Error('retained audit support parent is no longer a directory')
  }
  const parentPath = path.posix.dirname(repoPath)
  return {
    relativePath: parentPath === '.' ? '' : parentPath,
    device: stat.dev,
    inode: stat.ino,
    mode: stat.mode,
    ctimeNs: stat.ctimeNs,
    mtimeNs: stat.mtimeNs,
  }
}

function sameAuditSupportParent(
  left: AuditSupportParentSeal,
  right: AuditSupportParentSeal,
): boolean {
  return left.relativePath === right.relativePath &&
    left.device === right.device &&
    left.inode === right.inode &&
    left.mode === right.mode &&
    left.ctimeNs === right.ctimeNs &&
    left.mtimeNs === right.mtimeNs
}

function registerAuditSupportFileSeal(
  repoPath: string,
  parent: AnchoredDirectory,
  fd: number,
  blobSha256: string,
): void {
  const context = anchoredRootIdentity.getStore()
  const seals = context?.auditSupportFiles
  if (seals === undefined) return
  if (context?.auditSupportAbsences?.has(repoPath)) {
    throw new Error(
      `audit support path appeared during the retained transaction: ${repoPath}`,
    )
  }
  const parentSeal = auditSupportParentSeal(parent, repoPath)
  if (parentSeal === null) return
  const stat = fs.fstatSync(fd, { bigint: true })
  if (!stat.isFile()) {
    throw new Error(`retained audit support file is no longer regular: ${repoPath}`)
  }
  const candidate: AuditSupportFileSeal = {
    repoPath,
    blobSha256,
    size: stat.size,
    device: stat.dev,
    inode: stat.ino,
    mode: stat.mode,
    ctimeNs: stat.ctimeNs,
    mtimeNs: stat.mtimeNs,
    parent: parentSeal,
  }
  const existing = seals.get(repoPath)
  if (existing === undefined) {
    if (context?.verifyingAuditSupport) {
      throw new Error(
        `audit support verification encountered an unsealed file: ${repoPath}`,
      )
    }
    if (seals.size >= AUDIT_LIMITS.collectionItems) {
      throw new Error(
        `audit support file seals exceed the ${AUDIT_LIMITS.collectionItems}-file limit`,
      )
    }
    seals.set(repoPath, candidate)
    return
  }
  if (
    existing.blobSha256 !== candidate.blobSha256 ||
    existing.size !== candidate.size ||
    existing.device !== candidate.device ||
    existing.inode !== candidate.inode ||
    existing.mode !== candidate.mode ||
    existing.ctimeNs !== candidate.ctimeNs ||
    existing.mtimeNs !== candidate.mtimeNs ||
    !sameAuditSupportParent(existing.parent, candidate.parent)
  ) {
    throw new Error(
      `audit support file changed during the retained transaction: ${repoPath}`,
    )
  }
}

function registerAuditSupportAbsenceSeal(
  repoPath: string,
  parent: AnchoredDirectory,
  parentRelativePath: string,
  maxBytes: number,
): void {
  const context = anchoredRootIdentity.getStore()
  const seals = context?.auditSupportAbsences
  if (seals === undefined) return
  if (context?.auditSupportFiles?.has(repoPath)) {
    throw new Error(
      `audit support path disappeared during the retained transaction: ${repoPath}`,
    )
  }
  const stat = fs.fstatSync(parent.fd, { bigint: true })
  if (!stat.isDirectory()) {
    throw new Error(
      `retained audit support absence parent is no longer a directory: ${repoPath}`,
    )
  }
  const candidate: AuditSupportAbsenceSeal = {
    repoPath,
    maxBytes,
    parent: {
      relativePath: parentRelativePath,
      device: stat.dev,
      inode: stat.ino,
      mode: stat.mode,
      ctimeNs: stat.ctimeNs,
      mtimeNs: stat.mtimeNs,
    },
  }
  const existing = seals.get(repoPath)
  if (existing === undefined) {
    if (context?.verifyingAuditSupport) {
      throw new Error(
        `audit support verification encountered an unsealed absence: ${repoPath}`,
      )
    }
    if (seals.size >= AUDIT_LIMITS.collectionItems) {
      throw new Error(
        `audit support absence seals exceed the ${AUDIT_LIMITS.collectionItems}-path limit`,
      )
    }
    seals.set(repoPath, candidate)
    return
  }
  if (
    existing.maxBytes !== candidate.maxBytes ||
    !sameAuditSupportParent(existing.parent, candidate.parent)
  ) {
    throw new Error(
      `audit support absence changed during the retained transaction: ${repoPath}`,
    )
  }
}

function auditDirectoryEntriesDigest(entries: readonly string[]): string {
  const digest = createHash('sha256')
    .update('repo-atlas/audit-support-directory/v1\0', 'utf8')
  for (const entry of entries) {
    const bytes = Buffer.from(entry, 'utf8')
    digest
      .update(String(bytes.byteLength), 'ascii')
      .update(':', 'ascii')
      .update(bytes)
  }
  return digest.digest('hex')
}

function registerAuditSupportDirectorySeal(
  repoPath: string,
  directory: AnchoredDirectory,
  entries: readonly string[],
): void {
  const context = anchoredRootIdentity.getStore()
  const seals = context?.auditSupportDirectories
  if (
    seals === undefined ||
    repoPath.length === 0
  ) {
    return
  }
  const stat = fs.fstatSync(directory.fd, { bigint: true })
  if (!stat.isDirectory()) {
    throw new Error(`retained audit support directory is no longer safe: ${repoPath}`)
  }
  const candidate: AuditSupportDirectorySeal = {
    repoPath,
    entriesDigest: auditDirectoryEntriesDigest(entries),
    device: stat.dev,
    inode: stat.ino,
    mode: stat.mode,
    ctimeNs: stat.ctimeNs,
    mtimeNs: stat.mtimeNs,
  }
  const existing = seals.get(repoPath)
  if (existing === undefined) {
    if (context?.verifyingAuditSupport) {
      throw new Error(
        `audit support verification encountered an unsealed directory: ${repoPath}`,
      )
    }
    if (seals.size >= AUDIT_LIMITS.collectionItems) {
      throw new Error(
        `audit support directory seals exceed the ${AUDIT_LIMITS.collectionItems}-directory limit`,
      )
    }
    seals.set(repoPath, candidate)
    return
  }
  if (
    existing.entriesDigest !== candidate.entriesDigest ||
    existing.device !== candidate.device ||
    existing.inode !== candidate.inode ||
    existing.mode !== candidate.mode ||
    existing.ctimeNs !== candidate.ctimeNs ||
    existing.mtimeNs !== candidate.mtimeNs
  ) {
    throw new Error(
      `audit support directory changed during the retained transaction: ${repoPath}`,
    )
  }
}

function auditSupportGitQueryKey(
  arguments_: readonly string[],
  maxBytes: number,
): string {
  const digest = createHash('sha256')
    .update('repo-atlas/audit-support-git-query/v1\0', 'utf8')
    .update(String(maxBytes), 'ascii')
    .update('\0', 'ascii')
  for (const argument of arguments_) {
    const bytes = Buffer.from(argument, 'utf8')
    digest
      .update(String(bytes.byteLength), 'ascii')
      .update(':', 'ascii')
      .update(bytes)
  }
  return digest.digest('hex')
}

function registerAuditSupportGitQuerySeal(
  arguments_: readonly string[],
  maxBytes: number,
  output: Uint8Array,
): void {
  const context = anchoredRootIdentity.getStore()
  const seals = context?.auditSupportGitQueries
  if (seals === undefined) return
  if (
    arguments_.length > AUDIT_LIMITS.collectionItems ||
    arguments_.some((argument) =>
      argument.length > AUDIT_LIMITS.textCodeUnits ||
      argument.includes('\0') ||
      hasLoneSurrogate(argument))
  ) {
    throw new Error('audit support Git query arguments exceed their safe bounds')
  }
  const key = auditSupportGitQueryKey(arguments_, maxBytes)
  const candidate: AuditSupportGitQuerySeal = {
    arguments: [...arguments_],
    maxBytes,
    byteLength: output.byteLength,
    sha256: createHash('sha256').update(output).digest('hex'),
  }
  const existing = seals.get(key)
  if (existing === undefined) {
    if (context?.verifyingAuditSupport) {
      throw new Error(
        'audit support verification encountered an unsealed Git query',
      )
    }
    if (seals.size >= AUDIT_LIMITS.collectionItems) {
      throw new Error(
        `audit support Git query seals exceed the ${AUDIT_LIMITS.collectionItems}-query limit`,
      )
    }
    seals.set(key, candidate)
    return
  }
  if (
    existing.maxBytes !== candidate.maxBytes ||
    existing.byteLength !== candidate.byteLength ||
    existing.sha256 !== candidate.sha256 ||
    existing.arguments.length !== candidate.arguments.length ||
    existing.arguments.some(
      (argument, index) => argument !== candidate.arguments[index],
    )
  ) {
    throw new Error(
      `audit support Git query changed during the retained transaction: ${
        arguments_.join(' ')
      }`,
    )
  }
}

function verifyVisibleAuditSupportFileSeal(
  rootPath: string,
  seal: AuditSupportFileSeal,
): void {
  const anchored = openAnchoredAuditParent(rootPath, seal.repoPath, false)
  const cleanupFailures: unknown[] = []
  let primaryFailed = false
  let primaryFailure: unknown
  try {
    verifyAnchoredAuditParent(anchored, seal.repoPath)
    const parent = auditSupportParentSeal(
      anchored.parent,
      seal.repoPath,
    )
    const visible = fs.lstatSync(
      anchoredChildPath(
        anchored.parent,
        path.posix.basename(seal.repoPath),
      ),
      { bigint: true, throwIfNoEntry: false },
    )
    if (
      parent === null ||
      !sameAuditSupportParent(parent, seal.parent) ||
      visible === undefined ||
      !visible.isFile() ||
      visible.isSymbolicLink() ||
      visible.dev !== seal.device ||
      visible.ino !== seal.inode ||
      visible.mode !== seal.mode ||
      visible.size !== seal.size ||
      visible.ctimeNs !== seal.ctimeNs ||
      visible.mtimeNs !== seal.mtimeNs
    ) {
      throw new Error(
        `audit support file changed after final hashing: ${seal.repoPath}`,
      )
    }
    verifyAnchoredAuditParent(anchored, seal.repoPath)
  } catch (error) {
    primaryFailed = true
    primaryFailure = error
  }
  closeAnchoredAuditParent(anchored, cleanupFailures)
  throwCombinedFailures(
    primaryFailed,
    primaryFailure,
    cleanupFailures,
    'audit support final visibility verification failed and cleanup also failed',
  )
}

function verifyVisibleAuditSupportDirectorySeal(
  rootPath: string,
  seal: AuditSupportDirectorySeal,
): void {
  const anchored = openAnchoredAuditParent(rootPath, seal.repoPath, false)
  const cleanupFailures: unknown[] = []
  let primaryFailed = false
  let primaryFailure: unknown
  try {
    verifyAnchoredAuditParent(anchored, seal.repoPath)
    const visible = fs.lstatSync(
      anchoredChildPath(
        anchored.parent,
        path.posix.basename(seal.repoPath),
      ),
      { bigint: true, throwIfNoEntry: false },
    )
    if (
      visible === undefined ||
      !visible.isDirectory() ||
      visible.isSymbolicLink() ||
      visible.dev !== seal.device ||
      visible.ino !== seal.inode ||
      visible.mode !== seal.mode ||
      visible.ctimeNs !== seal.ctimeNs ||
      visible.mtimeNs !== seal.mtimeNs
    ) {
      throw new Error(
        `audit support directory changed after final listing: ${seal.repoPath}`,
      )
    }
    verifyAnchoredAuditParent(anchored, seal.repoPath)
  } catch (error) {
    primaryFailed = true
    primaryFailure = error
  }
  closeAnchoredAuditParent(anchored, cleanupFailures)
  throwCombinedFailures(
    primaryFailed,
    primaryFailure,
    cleanupFailures,
    'audit support directory final visibility verification failed and cleanup also failed',
  )
}

function verifyVisibleAuditSupportAbsenceSeal(
  rootPath: string,
  seal: AuditSupportAbsenceSeal,
): void {
  const parentProbePath = seal.parent.relativePath.length === 0
    ? '.audit-absence-probe'
    : `${seal.parent.relativePath}/.audit-absence-probe`
  const anchored = openAnchoredAuditParent(
    rootPath,
    parentProbePath,
    false,
  )
  const cleanupFailures: unknown[] = []
  let primaryFailed = false
  let primaryFailure: unknown
  try {
    verifyAnchoredAuditParent(anchored, seal.repoPath)
    const parent = auditSupportParentSeal(
      anchored.parent,
      parentProbePath,
    )
    const pathSegments = seal.repoPath.split('/')
    const parentSegmentCount = seal.parent.relativePath.length === 0
      ? 0
      : seal.parent.relativePath.split('/').length
    const firstMissingSegment = pathSegments[parentSegmentCount]
    const visible = firstMissingSegment === undefined
      ? undefined
      : fs.lstatSync(
          path.join(anchored.parent.procPath, firstMissingSegment),
          { throwIfNoEntry: false },
        )
    const parentAfterVisibilityProbe = auditSupportParentSeal(
      anchored.parent,
      parentProbePath,
    )
    if (
      parent === null ||
      !sameAuditSupportParent(parent, seal.parent) ||
      firstMissingSegment === undefined ||
      visible !== undefined ||
      parentAfterVisibilityProbe === null ||
      !sameAuditSupportParent(parentAfterVisibilityProbe, seal.parent)
    ) {
      throw new Error(
        `audit support path appeared after final absence hashing: ${seal.repoPath}`,
      )
    }
    verifyAnchoredAuditParent(anchored, seal.repoPath)
  } catch (error) {
    primaryFailed = true
    primaryFailure = error
  }
  closeAnchoredAuditParent(anchored, cleanupFailures)
  throwCombinedFailures(
    primaryFailed,
    primaryFailure,
    cleanupFailures,
    'audit support absence final visibility verification failed and cleanup also failed',
  )
}

function verifyAuditSupportSnapshot(
  context: AnchoredRootIdentityContext,
): void {
  const fileSeals = context.auditSupportFiles
  const directorySeals = context.auditSupportDirectories
  const gitQuerySeals = context.auditSupportGitQueries
  const absenceSeals = context.auditSupportAbsences
  if (
    (fileSeals === undefined || fileSeals.size === 0) &&
    (directorySeals === undefined || directorySeals.size === 0) &&
    (gitQuerySeals === undefined || gitQuerySeals.size === 0) &&
    (absenceSeals === undefined || absenceSeals.size === 0)
  ) {
    return
  }
  const verificationContext: AnchoredRootIdentityContext = {
    ...context,
    verifyingAuditSupport: true,
  }
  anchoredRootIdentity.run(verificationContext, () => {
    for (const repoPath of [...(directorySeals?.keys() ?? [])].sort()) {
      listBoundedAuditDirectory(
        context.root.procPath,
        repoPath,
        AUDIT_LIMITS.collectionItems,
      )
    }
    if (
      (fileSeals !== undefined && fileSeals.size > 0) ||
      (gitQuerySeals !== undefined && gitQuerySeals.size > 0) ||
      (absenceSeals !== undefined && absenceSeals.size > 0)
    ) {
      withAnchoredAuditGitCapability(context.root.procPath, (capability) => {
        for (const repoPath of [...(absenceSeals?.keys() ?? [])].sort()) {
          const seal = absenceSeals!.get(repoPath)!
          if (
            capability.hashWorktreeFile(
              repoPath,
              'sha256',
              seal.maxBytes,
            ) !== null
          ) {
            throw new Error(
              `audit support path appeared during the retained transaction: ${repoPath}`,
            )
          }
        }
        for (const repoPath of [...(fileSeals?.keys() ?? [])].sort()) {
          const seal = fileSeals!.get(repoPath)!
          const maxBytes = Number(seal.size)
          if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
            throw new Error(
              `audit support file size is outside the safe integer range: ${repoPath}`,
            )
          }
          if (
            capability.hashWorktreeFile(
              repoPath,
              'sha256',
              maxBytes,
            ) === null
          ) {
            throw new Error(
              `audit support file disappeared during the retained transaction: ${repoPath}`,
            )
          }
        }
        for (const key of [...(gitQuerySeals?.keys() ?? [])].sort()) {
          const seal = gitQuerySeals!.get(key)!
          capability.gitBytes(seal.arguments, seal.maxBytes)
        }
      })
    }
    for (const repoPath of [...(fileSeals?.keys() ?? [])].sort()) {
      verifyVisibleAuditSupportFileSeal(
        context.root.procPath,
        fileSeals!.get(repoPath)!,
      )
    }
    for (const repoPath of [...(directorySeals?.keys() ?? [])].sort()) {
      verifyVisibleAuditSupportDirectorySeal(
        context.root.procPath,
        directorySeals!.get(repoPath)!,
      )
    }
    for (const repoPath of [...(absenceSeals?.keys() ?? [])].sort()) {
      verifyVisibleAuditSupportAbsenceSeal(
        context.root.procPath,
        absenceSeals!.get(repoPath)!,
      )
    }
  })
}

/**
 * Records every bounded repository input read by one operation and revalidates
 * the complete support set before allowing the operation result to escape.
 * When an anchored root already exists (for example under withAuditLock), the
 * retained root identity is reused instead of reopening the repository name.
 */
export function withAnchoredAuditSupportSnapshot<T>(
  rootPath: string,
  operation: () => T,
): T {
  if (typeof operation !== 'function') {
    throw new Error('anchored audit support operation must be a function')
  }
  const inheritedContext = anchoredRootIdentity.getStore()
  if (inheritedContext === undefined) {
    return withAnchoredAuditRootIdentity(
      rootPath,
      (anchoredRootPath) =>
        withAnchoredAuditSupportSnapshot(anchoredRootPath, operation),
    )
  }
  safeRoot(rootPath)
  const operationContext: AnchoredRootIdentityContext = {
    ...inheritedContext,
    auditSupportFiles:
      inheritedContext.auditSupportFiles ??
      new Map<string, AuditSupportFileSeal>(),
    auditSupportDirectories:
      inheritedContext.auditSupportDirectories ??
      new Map<string, AuditSupportDirectorySeal>(),
    auditSupportGitQueries:
      inheritedContext.auditSupportGitQueries ??
      new Map<string, AuditSupportGitQuerySeal>(),
    auditSupportAbsences:
      inheritedContext.auditSupportAbsences ??
      new Map<string, AuditSupportAbsenceSeal>(),
  }
  const finish = (
    primaryFailed: boolean,
    primaryFailure: unknown,
    value?: unknown,
  ): unknown => {
    const verificationFailures: unknown[] = []
    try {
      verifyAuditSupportSnapshot(operationContext)
    } catch (error) {
      verificationFailures.push(error)
    }
    throwCombinedFailures(
      primaryFailed,
      primaryFailure,
      verificationFailures,
      'anchored audit support operation failed and snapshot verification also failed',
    )
    return value
  }

  return anchoredRootIdentity.run(operationContext, () => {
    let result: T
    try {
      result = operation()
    } catch (error) {
      return finish(true, error) as T
    }
    if (
      result !== null &&
      (typeof result === 'object' || typeof result === 'function')
    ) {
      let then: unknown
      try {
        then = (result as { then?: unknown }).then
      } catch (error) {
        return finish(true, error) as T
      }
      if (typeof then === 'function') {
        const pending = new Promise<unknown>((resolve, reject) => {
          queueMicrotask(() => {
            try {
              Reflect.apply(then, result, [resolve, reject])
            } catch (error) {
              reject(error)
            }
          })
        })
        return pending.then(
          (value) => finish(false, undefined, value),
          (error) => finish(true, error),
        ) as T
      }
    }
    return finish(false, undefined, result) as T
  })
}

function readExactFile(
  fd: number,
  stat: fs.Stats,
  repoPath: string,
  subject: string,
): Buffer {
  const buffer = Buffer.allocUnsafe(stat.size)
  let offset = 0
  while (offset < buffer.length) {
    const count = fs.readSync(fd, buffer, offset, buffer.length - offset, null)
    if (count === 0) {
      throw new Error(`${subject} changed while being read: ${repoPath}`)
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
    throw new Error(`${subject} changed while being read: ${repoPath}`)
  }
  return buffer
}

function readAnchoredAuditFile<T>(
  root: string,
  repoPath: string,
  maxBytes: number,
  subject: string,
  transform: (bytes: Buffer, normalizedRepoPath: string) => T,
): T {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new Error(`${subject} byte limit must be a nonnegative safe integer`)
  }
  const normalized = normalizeAuditRepoPath(repoPath)
  const byteLimit = Math.min(maxBytes, AUDIT_LIMITS.jsonBytes)
  const anchored = openAnchoredAuditParent(root, normalized, false)
  const parent = anchored.parent
  const fileName = path.posix.basename(normalized)
  const file = anchoredChildPath(parent, fileName)
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  const nonBlocking = fs.constants.O_NONBLOCK ?? 0
  let fd: number | null = null
  let result!: T
  let primaryFailed = false
  let primaryFailure: unknown
  const cleanupFailures: unknown[] = []
  try {
    verifyAnchoredAuditParent(anchored, normalized)
    fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow | nonBlocking)
    const opened = fs.fstatSync(fd)
    if (!opened.isFile()) {
      throw new Error(`${subject} is not a safe regular file: ${normalized}`)
    }
    verifyAnchoredAuditParent(anchored, normalized)
    verifyAnchoredRegularFile(parent, fileName, opened, normalized)
    if (opened.size > byteLimit) {
      throw new Error(`${subject} exceeds the ${byteLimit}-byte limit: ${normalized}`)
    }

    const openedPath = procFdPath(fd)
    const real = fs.realpathSync(openedPath)
    const resolved = fs.statSync(openedPath)
    const expected = path.join(parent.namedPath, fileName)
    if (
      real !== expected ||
      !isInside(real, parent.repository.real) ||
      resolved.dev !== opened.dev ||
      resolved.ino !== opened.ino
    ) {
      throw new Error(`${subject} is symlinked or outside the safe repository: ${normalized}`)
    }

    const bytes = readExactFile(fd, opened, normalized, subject)
    verifyAnchoredAuditParent(anchored, normalized)
    verifyAnchoredRegularFile(parent, fileName, opened, normalized)
    registerAuditSupportFileSeal(
      normalized,
      parent,
      fd,
      createHash('sha256')
        .update(`blob ${bytes.byteLength}\0`, 'utf8')
        .update(bytes)
        .digest('hex'),
    )
    result = transform(bytes, normalized)
    verifyAnchoredAuditParent(anchored, normalized)
    verifyAnchoredRegularFile(parent, fileName, opened, normalized)
  } catch (error) {
    const code = errnoCode(error)
    if (code === 'ENOENT' || code === 'ENOTDIR' || code === 'ELOOP') {
      primaryFailure = new Error(`${subject} is missing or not a safe regular file: ${normalized}`)
    } else {
      primaryFailure = error
    }
    primaryFailed = true
  }

  if (fd !== null) {
    try {
      closeDescriptorReliably(fd)
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  closeAnchoredAuditParent(anchored, cleanupFailures)
  throwCombinedFailures(
    primaryFailed,
    primaryFailure,
    cleanupFailures,
    `${subject} read failed and descriptor cleanup also failed`,
  )
  return result
}

export function readBoundedAuditBytes(
  root: string,
  repoPath: string,
  maxBytes = AUDIT_LIMITS.jsonBytes,
): Uint8Array {
  return readAnchoredAuditFile(
    root,
    repoPath,
    maxBytes,
    'audit file',
    (bytes) => bytes,
  )
}

export function parseBoundedAuditJsonBytes(
  bytes: Uint8Array,
  maxBytes = AUDIT_LIMITS.jsonBytes,
  source = 'audit JSON',
): unknown {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('audit JSON bytes must be a Uint8Array')
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new Error('audit JSON byte limit must be a nonnegative safe integer')
  }
  const byteLimit = Math.min(maxBytes, AUDIT_LIMITS.jsonBytes)
  if (bytes.byteLength > byteLimit) {
    throw new Error(
      `audit JSON exceeds the ${byteLimit}-byte limit: ${source}`,
    )
  }
  let text: string
  try {
    text = UTF8.decode(bytes)
  } catch {
    throw new Error(`audit JSON is not strict UTF-8: ${source}`)
  }
  return new BoundedJsonParser(text, source).parse()
}

export function readBoundedAuditJsonDocument(
  root: string,
  repoPath: string,
  maxBytes = AUDIT_LIMITS.jsonBytes,
): { bytes: Uint8Array; value: unknown } {
  return readAnchoredAuditFile(
    root,
    repoPath,
    maxBytes,
    'audit JSON',
    (bytes, normalized) => ({
      bytes,
      value: parseBoundedAuditJsonBytes(
        bytes,
        Math.min(maxBytes, AUDIT_LIMITS.jsonBytes),
        normalized,
      ),
    }),
  )
}

export function readBoundedAuditJson(
  root: string,
  repoPath: string,
  maxBytes = AUDIT_LIMITS.jsonBytes,
): unknown {
  return readBoundedAuditJsonDocument(root, repoPath, maxBytes).value
}

export function listBoundedAuditDirectory(
  root: string,
  repoDirectory: string,
  maxEntries = 100_000,
): string[] {
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 0) {
    throw new Error('audit directory entry limit must be a nonnegative safe integer')
  }
  const normalized = normalizeAuditRepoPath(repoDirectory)
  const repository = safeRoot(root)
  const owned: AnchoredDirectory[] = []
  let listing: fs.Dir | null = null
  let result: string[] = []
  let primaryFailed = false
  let primaryFailure: unknown
  const cleanupFailures: unknown[] = []
  try {
    const rootDirectory = openVerifiedRepositoryRoot(
      repository,
      `audit directory listing ${normalized}`,
    )
    owned.push(rootDirectory)
    let current = rootDirectory
    let namedPath = repository.real
    let missing: { parent: AnchoredDirectory; segment: string } | null = null
    for (const [segmentIndex, segment] of normalized
      .split('/')
      .entries()) {
      if (segmentIndex === 0 && segment === '.atlas') {
        const retainedAuditDirectory = openRetainedAuditDirectory(
          repository,
          normalized,
        )
        if (retainedAuditDirectory !== null) {
          owned.push(retainedAuditDirectory)
          current = retainedAuditDirectory
          namedPath = retainedAuditDirectory.namedPath
          continue
        }
      }
      const childPath = path.join(current.procPath, segment)
      const child = fs.lstatSync(childPath, { throwIfNoEntry: false })
      if (!child) {
        missing = { parent: current, segment }
        break
      }
      if (child.isSymbolicLink() || !child.isDirectory()) {
        throw new Error(`audit directory is symlinked or not safe: ${normalized}`)
      }
      const childFd = fs.openSync(childPath, directoryOpenFlags())
      let adopted = false
      try {
        const opened = fs.fstatSync(childFd)
        namedPath = path.join(namedPath, segment)
        const next: AnchoredDirectory = {
          fd: childFd,
          namedPath,
          procPath: procFdPath(childFd),
          repository,
          device: opened.dev,
          inode: opened.ino,
          ...(current.auditRelativePath === undefined
            ? {}
            : {
                auditRelativePath: current.auditRelativePath.length === 0
                  ? segment
                  : `${current.auditRelativePath}/${segment}`,
              }),
        }
        owned.push(next)
        adopted = true
        if (
          !opened.isDirectory() ||
          child.dev !== opened.dev ||
          child.ino !== opened.ino
        ) {
          throw new Error(`audit directory changed while opening: ${normalized}`)
        }
        verifyAnchoredDirectory(next, normalized)
        current = next
      } catch (error) {
        if (!adopted) {
          try {
            closeDescriptorReliably(childFd)
          } catch (cleanupError) {
            throw new AggregateError(
              [error, cleanupError],
              'audit directory open failed and descriptor cleanup also failed',
            )
          }
        }
        throw error
      }
    }
    if (missing === null) {
      for (const directory of owned) {
        verifyAnchoredDirectory(directory, normalized)
      }
      listing = fs.opendirSync(
        owned.at(-1)!.procPath,
        {
          encoding: 'buffer' as BufferEncoding,
          bufferSize: 1,
        },
      )
      const entryLimit = Math.min(maxEntries, AUDIT_LIMITS.collectionItems)
      const entries: string[] = []
      let nameBytes = 0
      let nameCodeUnits = 0
      while (true) {
        const directoryEntry = listing.readSync()
        if (directoryEntry === null) break
        if (entries.length >= entryLimit) {
          throw new Error(
            `audit directory exceeds the ${entryLimit}-entry limit: ${normalized}`,
          )
        }
        const rawEntry: unknown = directoryEntry.name
        if (!Buffer.isBuffer(rawEntry)) {
          throw new Error(`audit directory did not return raw entry-name bytes: ${normalized}`)
        }
        nameBytes += rawEntry.byteLength
        if (nameBytes > AUDIT_LIMITS.jsonBytes) {
          throw new Error(
            `audit directory exceeds the aggregate entry-name byte limit of ${AUDIT_LIMITS.jsonBytes}: ${normalized}`,
          )
        }
        let entry: string
        try {
          entry = UTF8.decode(rawEntry)
        } catch {
          throw new Error(`audit directory contains a non-UTF-8 entry name: ${normalized}`)
        }
        if (
          entry.length === 0 ||
          entry.length > AUDIT_LIMITS.textCodeUnits ||
          entry.includes('\0') ||
          entry.includes('/') ||
          entry.includes('\\') ||
          hasLoneSurrogate(entry)
        ) {
          throw new Error(`audit directory contains an unsafe entry name: ${normalized}`)
        }
        nameCodeUnits += entry.length
        if (nameCodeUnits > AUDIT_LIMITS.textTotalCodeUnits) {
          throw new Error(
            `audit directory exceeds the aggregate entry-name text limit of ${AUDIT_LIMITS.textTotalCodeUnits}: ${normalized}`,
          )
        }
        entries.push(entry)
      }
      for (const directory of owned) {
        verifyAnchoredDirectory(directory, normalized)
      }
      result = entries.sort((left, right) =>
        left < right ? -1 : left > right ? 1 : 0
      )
      registerAuditSupportDirectorySeal(normalized, current, result)
    } else {
      for (const directory of owned) {
        verifyAnchoredDirectory(directory, normalized)
      }
      const appeared = fs.lstatSync(
        path.join(missing.parent.procPath, missing.segment),
        { throwIfNoEntry: false },
      )
      for (const directory of owned) {
        verifyAnchoredDirectory(directory, normalized)
      }
      if (appeared) {
        throw new Error(`audit directory appeared while being listed: ${normalized}`)
      }
      result = []
    }
  } catch (error) {
    primaryFailed = true
    primaryFailure = error
  }
  if (listing !== null) {
    try {
      listing.closeSync()
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  for (const directory of owned.reverse()) {
    try {
      closeDescriptorReliably(directory.fd)
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  throwCombinedFailures(
    primaryFailed,
    primaryFailure,
    cleanupFailures,
    'audit directory listing failed and descriptor cleanup also failed',
  )
  return result
}

function retainedAuditFileDigest(
  fd: number,
  expected: fs.Stats,
  repoPath: string,
): string {
  if (
    !Number.isSafeInteger(expected.size) ||
    expected.size < 0 ||
    expected.size > AUDIT_LIMITS.jsonBytes
  ) {
    throw new Error(
      `retained audit file exceeds its byte bound: ${repoPath}`,
    )
  }
  const hash = createHash('sha256')
  const buffer = Buffer.allocUnsafe(
    Math.max(1, Math.min(64 * 1024, expected.size)),
  )
  let position = 0
  while (position < expected.size) {
    const count = fs.readSync(
      fd,
      buffer,
      0,
      Math.min(buffer.length, expected.size - position),
      position,
    )
    if (count <= 0) {
      throw new Error(
        `retained audit file changed while being sealed: ${repoPath}`,
      )
    }
    hash.update(buffer.subarray(0, count))
    position += count
  }
  if (fs.readSync(fd, buffer, 0, 1, position) !== 0) {
    throw new Error(
      `retained audit file grew while being sealed: ${repoPath}`,
    )
  }
  const after = fs.fstatSync(fd)
  if (
    !after.isFile() ||
    after.dev !== expected.dev ||
    after.ino !== expected.ino ||
    after.size !== expected.size ||
    after.mode !== expected.mode ||
    after.mtimeMs !== expected.mtimeMs ||
    after.ctimeMs !== expected.ctimeMs
  ) {
    throw new Error(
      `retained audit file changed while being sealed: ${repoPath}`,
    )
  }
  return hash.digest('hex')
}

/**
 * Retains one safe audit file and its parent directories for an entire
 * transaction. The callback may perform additional repository reads; before
 * any result is returned, the original file must still be the visible named
 * file beneath the same retained parent identity.
 */
export function withAnchoredAuditFileIdentity<T>(
  rootPath: string,
  repoPath: string,
  operation: () => T,
): T {
  if (typeof operation !== 'function') {
    throw new Error('anchored audit file operation must be a function')
  }
  const normalized = normalizeAuditRepoPath(repoPath)
  const inheritedContext = anchoredRootIdentity.getStore()
  const name = path.posix.basename(normalized)
  const anchored = openAnchoredAuditParent(rootPath, normalized, false)
  const target = anchoredChildPath(anchored.parent, name)
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  const nonBlocking = fs.constants.O_NONBLOCK ?? 0
  let fd: number | null = null
  let opened: fs.Stats | null = null
  let initialDigest: string | null = null
  let parentChangeTimeNs: bigint | null = null
  let parentModifyTimeNs: bigint | null = null
  const normalizedSegments = normalized.split('/')
  const directAtlasFile =
    normalizedSegments.length === 2 &&
    normalizedSegments[0] === '.atlas'
  const ownsAuditSupportSnapshot =
    directAtlasFile &&
    inheritedContext?.auditSupportFiles === undefined &&
    inheritedContext?.auditSupportDirectories === undefined &&
    inheritedContext?.auditSupportGitQueries === undefined &&
    inheritedContext?.auditSupportAbsences === undefined
  const auditSupportFiles = inheritedContext?.auditSupportFiles ??
    (directAtlasFile ? new Map<string, AuditSupportFileSeal>() : undefined)
  const auditSupportDirectories =
    inheritedContext?.auditSupportDirectories ??
    (directAtlasFile
      ? new Map<string, AuditSupportDirectorySeal>()
      : undefined)
  const auditSupportGitQueries =
    inheritedContext?.auditSupportGitQueries ??
    (directAtlasFile
      ? new Map<string, AuditSupportGitQuerySeal>()
      : undefined)
  const auditSupportAbsences =
    inheritedContext?.auditSupportAbsences ??
    (directAtlasFile
      ? new Map<string, AuditSupportAbsenceSeal>()
      : undefined)

  try {
    verifyAnchoredAuditParent(anchored, normalized)
    const parentTimes = fs.fstatSync(
      anchored.parent.fd,
      { bigint: true },
    )
    parentChangeTimeNs = parentTimes.ctimeNs
    parentModifyTimeNs = parentTimes.mtimeNs
    fd = fs.openSync(
      target,
      fs.constants.O_RDONLY | noFollow | nonBlocking,
    )
    opened = fs.fstatSync(fd)
    if (!opened.isFile()) {
      throw new Error(
        `anchored audit file is not a safe regular file: ${normalized}`,
      )
    }
    verifyAnchoredRegularFile(
      anchored.parent,
      name,
      opened,
      normalized,
    )
    initialDigest = retainedAuditFileDigest(
      fd,
      opened,
      normalized,
    )
    verifyAnchoredAuditParent(anchored, normalized)
  } catch (error) {
    const cleanupFailures: unknown[] = []
    if (fd !== null) {
      try {
        closeDescriptorReliably(fd)
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError)
      }
    }
    closeAnchoredAuditParent(anchored, cleanupFailures)
    throwCombinedFailures(
      true,
      error,
      cleanupFailures,
      'anchored audit file open failed and descriptor cleanup also failed',
    )
    throw new Error('unreachable anchored audit file open')
  }

  const operationContext: AnchoredRootIdentityContext = {
    ...(inheritedContext ?? { root: anchored.root }),
    ...(directAtlasFile
      ? {
          auditDirectory: anchored.parent,
          auditSupportFiles,
          auditSupportDirectories,
          auditSupportGitQueries,
          auditSupportAbsences,
        }
      : {}),
  }
  const finalVerificationContext = inheritedContext === undefined
    ? undefined
    : {
        ...inheritedContext,
        auditDirectory: undefined,
      }
  const verifyParentTimes = (): void => {
    const parentTimes = fs.fstatSync(
      anchored.parent.fd,
      { bigint: true },
    )
    if (
      parentTimes.ctimeNs !== parentChangeTimeNs ||
      parentTimes.mtimeNs !== parentModifyTimeNs
    ) {
      throw new Error(
        `retained audit parent changed during the transaction: ${normalized}`,
      )
    }
  }

  const finish = (
    primaryFailed: boolean,
    primaryFailure: unknown,
    value?: unknown,
  ): unknown => {
    const cleanupFailures: unknown[] = []
    if (ownsAuditSupportSnapshot) {
      try {
        verifyAuditSupportSnapshot(operationContext)
      } catch (error) {
        cleanupFailures.push(error)
      }
    }
    try {
      verifyParentTimes()
      const retained = fs.fstatSync(fd!)
      if (
        !retained.isFile() ||
        retained.dev !== opened!.dev ||
        retained.ino !== opened!.ino ||
        retainedAuditFileDigest(
          fd!,
          opened!,
          normalized,
        ) !== initialDigest
      ) {
        throw new Error(
          `retained audit file changed identity: ${normalized}`,
        )
      }
      anchoredRootIdentity.run(finalVerificationContext, () => {
        verifyAnchoredAuditParent(anchored, normalized)
        verifyAnchoredRegularFile(
          anchored.parent,
          name,
          opened!,
          normalized,
        )
      })
    } catch (error) {
      cleanupFailures.push(error)
    }
    try {
      closeDescriptorReliably(fd!)
    } catch (error) {
      cleanupFailures.push(error)
    }
    try {
      anchoredRootIdentity.run(finalVerificationContext, () => {
        verifyParentTimes()
        verifyAnchoredAuditParent(anchored, normalized)
        verifyAnchoredRegularFile(
          anchored.parent,
          name,
          opened!,
          normalized,
        )
      })
    } catch (error) {
      cleanupFailures.push(error)
    }
    closeAnchoredAuditParent(anchored, cleanupFailures)
    throwCombinedFailures(
      primaryFailed,
      primaryFailure,
      cleanupFailures,
      'anchored audit file operation failed and descriptor cleanup also failed',
    )
    return value
  }

  return anchoredRootIdentity.run(operationContext, () => {
    let result: T
    try {
      result = operation()
    } catch (error) {
      return finish(true, error) as T
    }

    if (
      result !== null &&
      (typeof result === 'object' || typeof result === 'function')
    ) {
      let then: unknown
      try {
        then = (result as { then?: unknown }).then
      } catch (error) {
        return finish(true, error) as T
      }
      if (typeof then === 'function') {
        const pending = new Promise<unknown>((resolve, reject) => {
          queueMicrotask(() => {
            try {
              Reflect.apply(then, result, [resolve, reject])
            } catch (error) {
              reject(error)
            }
          })
        })
        return pending.then(
          (value) => finish(false, undefined, value),
          (error) => finish(true, error),
        ) as T
      }
    }

    return finish(false, undefined, result) as T
  })
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
  let textCodeUnits = 0

  const addText = (text: string, kind: 'key' | 'string'): void => {
    if (text.length > AUDIT_LIMITS.textCodeUnits) {
      throw new Error(
        `canonical JSON ${kind} exceeds the ${AUDIT_LIMITS.textCodeUnits} code-unit limit`,
      )
    }
    if (hasLoneSurrogate(text)) {
      throw new Error(`canonical JSON ${kind}s may not contain lone surrogates`)
    }
    textCodeUnits += text.length
    if (textCodeUnits > AUDIT_LIMITS.textTotalCodeUnits) {
      throw new Error(
        `canonical JSON exceeds the aggregate string limit of ${AUDIT_LIMITS.textTotalCodeUnits} code units`,
      )
    }
  }

  const visit = (current: unknown, depth: number): CanonicalValue => {
    if (depth > AUDIT_MAX_DEPTH) {
      throw new Error(`canonical JSON exceeds the nesting depth limit of ${AUDIT_MAX_DEPTH}`)
    }
    if (current === null || typeof current === 'boolean') return current
    if (typeof current === 'string') {
      addText(current, 'string')
      return current
    }
    if (typeof current === 'number') {
      if (!Number.isFinite(current)) throw new Error('canonical JSON numbers must be finite')
      if (Number.isInteger(current) && !Number.isSafeInteger(current)) {
        throw new Error('canonical JSON integers must use safe integer precision')
      }
      return current
    }
    if (!current || typeof current !== 'object') {
      throw new Error('canonical JSON contains an unsupported value')
    }
    if (utilTypes.isProxy(current)) {
      throw new Error('canonical JSON contains an unsupported Proxy value')
    }
    if (ancestors.has(current)) throw new Error('canonical JSON contains a cyclic value')

    ancestors.add(current)
    try {
      if (Array.isArray(current)) {
        if (Object.getPrototypeOf(current) !== Array.prototype) {
          throw new Error('canonical JSON contains an unsupported array value')
        }
        const lengthDescriptor = Object.getOwnPropertyDescriptor(current, 'length')
        if (
          !lengthDescriptor ||
          !('value' in lengthDescriptor) ||
          typeof lengthDescriptor.value !== 'number' ||
          !Number.isSafeInteger(lengthDescriptor.value) ||
          lengthDescriptor.value < 0
        ) {
          throw new Error('canonical JSON arrays must have a safe data-property length')
        }
        const length = lengthDescriptor.value
        collectionItems += length
        if (collectionItems > AUDIT_LIMITS.collectionItems) {
          throw new Error(`canonical JSON exceeds the ${AUDIT_LIMITS.collectionItems} collection-item limit`)
        }
        const ownKeys = Reflect.ownKeys(current)
        if (
          ownKeys.length !== length + 1 ||
          ownKeys.some((key) => {
            if (key === 'length') return false
            if (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key)) {
              return true
            }
            const index = Number(key)
            return !Number.isSafeInteger(index) || index < 0 || index >= length
          })
        ) {
          throw new Error('canonical JSON arrays may not have extra properties')
        }
        const result: CanonicalValue[] = []
        for (let index = 0; index < length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(current, String(index))
          if (!descriptor) {
            throw new Error('canonical JSON arrays may not be sparse')
          }
          if (!descriptor.enumerable || !('value' in descriptor)) {
            throw new Error(
              'canonical JSON arrays may contain only enumerable data properties',
            )
          }
          result.push(visit(descriptor.value, depth + 1))
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
        addText(key, 'key')
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
  const chunks: string[] = []
  let bytes = 0
  const append = (chunk: string): void => {
    bytes += Buffer.byteLength(chunk, 'utf8')
    if (bytes > AUDIT_LIMITS.jsonBytes) {
      throw new Error(
        `canonical JSON serialized document exceeds the ${AUDIT_LIMITS.jsonBytes}-byte limit`,
      )
    }
    chunks.push(chunk)
  }
  const serialize = (current: CanonicalValue): void => {
    if (current === null || typeof current !== 'object') {
      const encoded = JSON.stringify(current)
      if (typeof encoded !== 'string') {
        throw new Error('canonical JSON contains an unsupported value')
      }
      append(encoded)
      return
    }
    if (Array.isArray(current)) {
      append('[')
      for (let index = 0; index < current.length; index += 1) {
        if (index > 0) append(',')
        serialize(current[index])
      }
      append(']')
      return
    }
    append('{')
    const keys = Object.keys(current).sort()
    for (let index = 0; index < keys.length; index += 1) {
      if (index > 0) append(',')
      append(JSON.stringify(keys[index]))
      append(':')
      serialize(current[keys[index]])
    }
    append('}')
  }

  serialize(value)
  return chunks.join('')
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
  if (!Array.isArray(parts) || Object.getPrototypeOf(parts) !== Array.prototype) {
    throw new Error('stable audit ID parts must be a plain array of strings')
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(parts, 'length')
  if (
    !lengthDescriptor ||
    !('value' in lengthDescriptor) ||
    typeof lengthDescriptor.value !== 'number' ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0
  ) {
    throw new Error('stable audit ID parts must have a safe data-property length')
  }
  const partCount = lengthDescriptor.value
  if (partCount > AUDIT_ID_MAX_PARTS) {
    throw new Error(`stable audit ID has too many parts; maximum part count is ${AUDIT_ID_MAX_PARTS}`)
  }
  const ownKeys = Reflect.ownKeys(parts)
  if (
    ownKeys.length !== partCount + 1 ||
    ownKeys.some((key) => {
      if (key === 'length') return false
      if (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key)) return true
      const index = Number(key)
      return !Number.isSafeInteger(index) || index < 0 || index >= partCount
    })
  ) {
    throw new Error('stable audit ID parts must be a dense array without extra properties')
  }
  const snapshot: string[] = []
  for (let index = 0; index < partCount; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(parts, String(index))
    if (
      !descriptor?.enumerable ||
      !('value' in descriptor) ||
      typeof descriptor.value !== 'string'
    ) {
      throw new Error(
        'stable audit ID parts must contain only enumerable string data properties',
      )
    }
    snapshot.push(descriptor.value)
  }
  if (snapshot.some((part) =>
    part.length > AUDIT_LIMITS.textCodeUnits ||
    part.includes('\0') ||
    hasLoneSurrogate(part)
  )) {
    throw new Error('stable audit ID parts must not contain NUL, lone surrogates, or over-limit text')
  }
  const totalBytes = Buffer.byteLength(domainTag, 'utf8') +
    1 +
    snapshot.reduce((sum, part) => sum + Buffer.byteLength(part, 'utf8'), 0) +
    Math.max(0, snapshot.length - 1)
  if (totalBytes > AUDIT_ID_MAX_BYTES) {
    throw new Error(`stable audit ID input exceeds the ${AUDIT_ID_MAX_BYTES}-byte total limit`)
  }
  const digest = createHash('sha256')
    .update(`${domainTag}\0${snapshot.join('\0')}`, 'utf8')
    .digest('hex')
  return `${prefix}_${digest.slice(0, 24)}`
}

interface AnchoredDirectory {
  fd: number
  namedPath: string
  procPath: string
  repository: SafeRoot
  device: number
  inode: number
  auditRelativePath?: string
}

interface AnchoredAuditParent {
  root: AnchoredDirectory
  parent: AnchoredDirectory
}

const UNSUPPORTED_DIRECTORY_FSYNC_CODES = new Set([
  'EINVAL',
  'ENOSYS',
  'ENOTSUP',
  'EOPNOTSUPP',
])

function procFdPath(fd: number): string {
  if (process.platform !== 'linux') {
    throw new Error('safe audit file operations require Linux /proc file-descriptor anchoring')
  }
  const procPath = `/proc/self/fd/${fd}`
  try {
    fs.lstatSync(procPath)
  } catch {
    throw new Error('safe audit file operations require an available Linux /proc filesystem')
  }
  return procPath
}

function directoryOpenFlags(): number {
  return fs.constants.O_RDONLY |
    (fs.constants.O_DIRECTORY ?? 0) |
    (fs.constants.O_NOFOLLOW ?? 0)
}

function closeDescriptorReliably(fd: number): void {
  try {
    fs.closeSync(fd)
    return
  } catch (firstError) {
    try {
      fs.fstatSync(fd)
    } catch (probeError) {
      if (errnoCode(probeError) === 'EBADF') throw firstError
      throw new AggregateError(
        [firstError, probeError],
        'descriptor close failed and descriptor state could not be verified',
      )
    }
    try {
      fs.closeSync(fd)
    } catch (retryError) {
      throw new AggregateError(
        [firstError, retryError],
        'descriptor close failed twice',
      )
    }
    throw firstError
  }
}

function openVerifiedRepositoryRoot(
  repository: SafeRoot,
  context: string,
): AnchoredDirectory {
  verifySafeRootIdentity(repository)
  const fd = fs.openSync(repository.real, directoryOpenFlags())
  try {
    const opened = fs.fstatSync(fd)
    if (
      !opened.isDirectory() ||
      opened.dev !== repository.device ||
      opened.ino !== repository.inode
    ) {
      throw new Error(`audit repository root changed identity before ${context}`)
    }
    const directory: AnchoredDirectory = {
      fd,
      namedPath: repository.real,
      procPath: procFdPath(fd),
      repository,
      device: opened.dev,
      inode: opened.ino,
    }
    verifyAnchoredDirectory(directory, context)
    return directory
  } catch (error) {
    const cleanupFailures: unknown[] = []
    try {
      closeDescriptorReliably(fd)
    } catch (cleanupError) {
      cleanupFailures.push(cleanupError)
    }
    throwCombinedFailures(
      true,
      error,
      cleanupFailures,
      'audit repository root open failed and descriptor cleanup also failed',
    )
    throw error
  }
}

function fsyncDirectoryFd(fd: number): void {
  try {
    fs.fsyncSync(fd)
  } catch (error) {
    if (UNSUPPORTED_DIRECTORY_FSYNC_CODES.has(errnoCode(error) ?? '')) return
    throw error
  }
}

function verifyRetainedDirectoryDescriptor(
  fd: number,
  procPath: string,
  device: number,
  inode: number,
  message: string,
): void {
  const opened = fs.fstatSync(fd)
  let real: string
  let visible: fs.Stats
  try {
    real = fs.realpathSync(procPath)
    visible = fs.lstatSync(real)
  } catch {
    throw new Error(message)
  }
  if (
    !opened.isDirectory() ||
    opened.dev !== device ||
    opened.ino !== inode ||
    visible.isSymbolicLink() ||
    !visible.isDirectory() ||
    visible.dev !== device ||
    visible.ino !== inode ||
    fs.realpathSync(real) !== real
  ) {
    throw new Error(message)
  }
}

function verifyAnchoredDirectory(directory: AnchoredDirectory, repoPath: string): void {
  const retained = anchoredRootIdentity.getStore()
  if (retained !== undefined && directory.fd === retained.root.fd) {
    verifyRetainedDirectoryDescriptor(
      directory.fd,
      directory.procPath,
      directory.device,
      directory.inode,
      `retained audit repository root changed while operating on: ${repoPath}`,
    )
    return
  }
  if (
    retained?.auditDirectory !== undefined &&
    directory.auditRelativePath !== undefined
  ) {
    verifyRetainedDirectoryDescriptor(
      retained.auditDirectory.fd,
      retained.auditDirectory.procPath,
      retained.auditDirectory.device,
      retained.auditDirectory.inode,
      `retained .atlas directory changed while operating on: ${repoPath}`,
    )
    const expectedPath = directory.auditRelativePath.length === 0
      ? retained.auditDirectory.procPath
      : path.join(
          retained.auditDirectory.procPath,
          ...directory.auditRelativePath.split('/'),
        )
    const opened = fs.fstatSync(directory.fd)
    let expected: fs.Stats
    let expectedReal: string
    let openedReal: string
    try {
      expected = directory.auditRelativePath.length === 0
        ? fs.statSync(expectedPath)
        : fs.lstatSync(expectedPath)
      expectedReal = fs.realpathSync(expectedPath)
      openedReal = fs.realpathSync(directory.procPath)
    } catch {
      throw new Error(
        `retained .atlas subtree changed while operating on: ${repoPath}`,
      )
    }
    if (
      !opened.isDirectory() ||
      opened.dev !== directory.device ||
      opened.ino !== directory.inode ||
      expected.isSymbolicLink() ||
      !expected.isDirectory() ||
      expected.dev !== directory.device ||
      expected.ino !== directory.inode ||
      openedReal !== expectedReal
    ) {
      throw new Error(
        `retained .atlas subtree changed while operating on: ${repoPath}`,
      )
    }
    return
  }
  verifySafeRootIdentity(directory.repository)
  const opened = fs.fstatSync(directory.fd)
  if (
    !opened.isDirectory() ||
    opened.dev !== directory.device ||
    opened.ino !== directory.inode
  ) {
    throw new Error(`audit parent directory changed while operating on: ${repoPath}`)
  }

  let named: fs.Stats
  let namedReal: string
  let openedReal: string
  try {
    named = fs.lstatSync(directory.namedPath)
    namedReal = fs.realpathSync(directory.namedPath)
    openedReal = fs.realpathSync(directory.procPath)
  } catch {
    throw new Error(`audit parent directory changed or is no longer safe: ${repoPath}`)
  }
  if (
    named.isSymbolicLink() ||
    !named.isDirectory() ||
    named.dev !== directory.device ||
    named.ino !== directory.inode ||
    namedReal !== directory.namedPath ||
    openedReal !== directory.namedPath ||
    (
      directory.namedPath !== directory.repository.real &&
      !isInside(directory.namedPath, directory.repository.real)
    )
  ) {
    throw new Error(`audit parent directory changed, is symlinked, or is outside the safe repository: ${repoPath}`)
  }
}

function openRetainedAuditDirectory(
  repository: SafeRoot,
  repoPath: string,
): AnchoredDirectory | null {
  const retained = anchoredRootIdentity.getStore()?.auditDirectory
  if (retained === undefined) return null
  if (
    retained.repository.device !== repository.device ||
    retained.repository.inode !== repository.inode
  ) {
    throw new Error(
      `retained .atlas directory belongs to a different repository: ${repoPath}`,
    )
  }
  verifyRetainedDirectoryDescriptor(
    retained.fd,
    retained.procPath,
    retained.device,
    retained.inode,
    `retained .atlas directory changed while operating on: ${repoPath}`,
  )
  const fd = fs.openSync(
    retained.procPath,
    fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0),
  )
  try {
    const opened = fs.fstatSync(fd)
    const directory: AnchoredDirectory = {
      fd,
      namedPath: retained.namedPath,
      procPath: procFdPath(fd),
      repository,
      device: opened.dev,
      inode: opened.ino,
      auditRelativePath: '',
    }
    if (
      !opened.isDirectory() ||
      opened.dev !== retained.device ||
      opened.ino !== retained.inode
    ) {
      throw new Error(
        `retained .atlas directory changed while opening: ${repoPath}`,
      )
    }
    verifyAnchoredDirectory(directory, repoPath)
    return directory
  } catch (error) {
    const cleanupFailures: unknown[] = []
    try {
      closeDescriptorReliably(fd)
    } catch (cleanupError) {
      cleanupFailures.push(cleanupError)
    }
    throwCombinedFailures(
      true,
      error,
      cleanupFailures,
      'retained .atlas directory open failed and cleanup also failed',
    )
    throw new Error('unreachable retained .atlas directory open')
  }
}

function openAnchoredAuditParent(
  root: string,
  repoPath: string,
  create: boolean,
): AnchoredAuditParent {
  const normalized = normalizeAuditRepoPath(repoPath)
  const repository = safeRoot(root)
  const parentSegments = normalized.split('/').slice(0, -1)
  const owned: AnchoredDirectory[] = []

  try {
    const rootDirectory = openVerifiedRepositoryRoot(repository, normalized)
    owned.push(rootDirectory)
    let current = rootDirectory
    let namedPath = repository.real

    for (const [segmentIndex, segment] of parentSegments.entries()) {
      if (segmentIndex === 0 && segment === '.atlas') {
        const retainedAuditDirectory = openRetainedAuditDirectory(
          repository,
          normalized,
        )
        if (retainedAuditDirectory !== null) {
          owned.push(retainedAuditDirectory)
          current = retainedAuditDirectory
          namedPath = retainedAuditDirectory.namedPath
          continue
        }
      }
      const childPath = path.join(current.procPath, segment)
      let child = fs.lstatSync(childPath, { throwIfNoEntry: false })
      if (!child && create) {
        try {
          fs.mkdirSync(childPath, { recursive: false, mode: 0o700 })
          fsyncDirectoryFd(current.fd)
        } catch (error) {
          if (errnoCode(error) !== 'EEXIST') throw error
        }
        child = fs.lstatSync(childPath, { throwIfNoEntry: false })
      }
      if (!child) {
        const missing: NodeJS.ErrnoException = new Error(
          `audit parent is missing: ${normalized}`,
        )
        missing.code = 'ENOENT'
        throw missing
      }
      if (child.isSymbolicLink() || !child.isDirectory()) {
        throw new Error(`audit parent is missing or not a safe directory: ${normalized}`)
      }

      const childFd = fs.openSync(childPath, directoryOpenFlags())
      let next: AnchoredDirectory | null = null
      try {
        const childOpened = fs.fstatSync(childFd)
        namedPath = path.join(namedPath, segment)
        next = {
          fd: childFd,
          namedPath,
          procPath: procFdPath(childFd),
          repository,
          device: childOpened.dev,
          inode: childOpened.ino,
          ...(current.auditRelativePath === undefined
            ? {}
            : {
                auditRelativePath: current.auditRelativePath.length === 0
                  ? segment
                  : `${current.auditRelativePath}/${segment}`,
              }),
        }
        owned.push(next)
        if (
          child.dev !== childOpened.dev ||
          child.ino !== childOpened.ino
        ) {
          throw new Error(`audit parent directory changed while opening: ${normalized}`)
        }
        verifyAnchoredDirectory(next, normalized)
      } catch (error) {
        if (next === null) {
          try {
            closeDescriptorReliably(childFd)
          } catch (cleanupError) {
            throw new AggregateError(
              [error, cleanupError],
              'audit parent open failed and child descriptor cleanup also failed',
            )
          }
        }
        throw error
      }

      if (current !== rootDirectory) {
        const ownedIndex = owned.indexOf(current)
        if (ownedIndex >= 0) owned.splice(ownedIndex, 1)
        closeDescriptorReliably(current.fd)
      }
      current = next
    }

    return {
      root: rootDirectory,
      parent: current,
    }
  } catch (error) {
    const cleanupFailures: unknown[] = []
    for (const directory of owned.reverse()) {
      try {
        closeDescriptorReliably(directory.fd)
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError)
      }
    }
    const code = errnoCode(error)
    if (code === 'ENOENT') {
      const missing: NodeJS.ErrnoException = new Error(
        `audit parent is missing: ${normalized}`,
      )
      missing.code = 'ENOENT'
      throwCombinedFailures(
        true,
        missing,
        cleanupFailures,
        'audit parent validation failed and descriptor cleanup also failed',
      )
    }
    if (code === 'ENOTDIR' || code === 'ELOOP') {
      throwCombinedFailures(
        true,
        new Error(`audit parent is missing or not a safe directory: ${normalized}`),
        cleanupFailures,
        'audit parent validation failed and descriptor cleanup also failed',
      )
    }
    throwCombinedFailures(
      true,
      error,
      cleanupFailures,
      'audit parent open failed and descriptor cleanup also failed',
    )
    throw new Error('unreachable audit parent open')
  }
}

function verifyAnchoredAuditParent(
  anchored: AnchoredAuditParent,
  repoPath: string,
): void {
  verifyAnchoredDirectory(anchored.root, repoPath)
  if (anchored.parent.fd !== anchored.root.fd) {
    verifyAnchoredDirectory(anchored.parent, repoPath)
  }
}

function closeAnchoredAuditParent(
  anchored: AnchoredAuditParent,
  cleanupFailures: unknown[],
): void {
  if (anchored.parent.fd !== anchored.root.fd) {
    try {
      closeDescriptorReliably(anchored.parent.fd)
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  try {
    closeDescriptorReliably(anchored.root.fd)
  } catch (error) {
    cleanupFailures.push(error)
  }
}

function anchoredChildPath(parent: AnchoredDirectory, name: string): string {
  return path.join(parent.procPath, name)
}

function verifyAnchoredRegularFile(
  parent: AnchoredDirectory,
  name: string,
  opened: fs.Stats,
  repoPath: string,
): void {
  let current: fs.Stats
  try {
    current = fs.lstatSync(anchoredChildPath(parent, name))
  } catch {
    throw new Error(`audit file changed or is missing: ${repoPath}`)
  }
  if (
    current.isSymbolicLink() ||
    !current.isFile() ||
    current.dev !== opened.dev ||
    current.ino !== opened.ino
  ) {
    throw new Error(`audit file changed or is not a safe regular file: ${repoPath}`)
  }
}

function verifySafeAnchoredTarget(
  parent: AnchoredDirectory,
  name: string,
  repoPath: string,
): void {
  const target = fs.lstatSync(anchoredChildPath(parent, name), { throwIfNoEntry: false })
  if (target && (target.isSymbolicLink() || !target.isFile())) {
    throw new Error(`audit output is symlinked or is not a safe regular file: ${repoPath}`)
  }
}

function cleanupOwnedTemporary(
  parent: AnchoredDirectory,
  name: string,
  fd: number | null,
  device: number | null,
  inode: number | null,
): void {
  if (fd === null || device === null || inode === null) return
  const opened = fs.fstatSync(fd)
  if (
    !opened.isFile() ||
    opened.dev !== device ||
    opened.ino !== inode
  ) {
    throw new Error('owned audit temporary descriptor changed identity')
  }
  const temporary = anchoredChildPath(parent, name)
  let current: fs.Stats
  try {
    current = fs.lstatSync(temporary)
  } catch (error) {
    if (errnoCode(error) === 'ENOENT') return
    throw error
  }
  if (
    current.isSymbolicLink() ||
    !current.isFile() ||
    current.dev !== device ||
    current.ino !== inode
  ) {
    throw new Error('owned audit temporary changed identity and was not removed')
  }
  fs.unlinkSync(temporary)
  fsyncDirectoryFd(parent.fd)
}

function throwCombinedFailures(
  primaryFailed: boolean,
  primaryFailure: unknown,
  cleanupFailures: unknown[],
  message: string,
): never | void {
  if (primaryFailed && cleanupFailures.length > 0) {
    throw new AggregateError(
      [primaryFailure, ...cleanupFailures],
      message,
    )
  }
  if (primaryFailed) throw primaryFailure
  if (cleanupFailures.length === 1) throw cleanupFailures[0]
  if (cleanupFailures.length > 1) {
    throw new AggregateError(cleanupFailures, message)
  }
}

export function atomicWriteAuditFile(root: string, repoPath: string, contents: string): void {
  if (typeof contents !== 'string') throw new Error('audit file contents must be a string')
  const normalized = normalizeAuditRepoPath(repoPath)
  const targetName = path.posix.basename(normalized)
  const temporaryName = `.${targetName}.${process.pid}.${randomUUID()}.tmp`
  const anchored = openAnchoredAuditParent(root, normalized, true)
  const parent = anchored.parent
  const target = anchoredChildPath(parent, targetName)
  const temporary = anchoredChildPath(parent, temporaryName)
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  let fd: number | null = null
  let device: number | null = null
  let inode: number | null = null
  let primaryFailed = false
  let primaryFailure: unknown
  const cleanupFailures: unknown[] = []

  try {
    verifyAnchoredAuditParent(anchored, normalized)
    verifySafeAnchoredTarget(parent, targetName, normalized)
    fd = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow,
      0o600,
    )
    const opened = fs.fstatSync(fd)
    if (!opened.isFile()) {
      throw new Error(`audit temporary is not a safe regular file: ${normalized}`)
    }
    device = opened.dev
    inode = opened.ino
    verifyAnchoredRegularFile(parent, temporaryName, opened, normalized)
    fs.writeFileSync(fd, contents, 'utf8')
    fs.fsyncSync(fd)
    verifyAnchoredAuditParent(anchored, normalized)
    verifyAnchoredRegularFile(parent, temporaryName, opened, normalized)

    verifySafeAnchoredTarget(parent, targetName, normalized)
    verifyAnchoredAuditParent(anchored, normalized)
    fs.renameSync(temporary, target)
    verifyAnchoredAuditParent(anchored, normalized)
    verifyAnchoredRegularFile(parent, targetName, opened, normalized)
    fsyncDirectoryFd(parent.fd)
  } catch (error) {
    primaryFailed = true
    primaryFailure = error
  }

  try {
    cleanupOwnedTemporary(parent, temporaryName, fd, device, inode)
  } catch (error) {
    cleanupFailures.push(error)
  }
  if (fd !== null) {
    try {
      closeDescriptorReliably(fd)
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  closeAnchoredAuditParent(anchored, cleanupFailures)
  throwCombinedFailures(
    primaryFailed,
    primaryFailure,
    cleanupFailures,
    'atomic audit write failed and temporary cleanup also failed',
  )
}

function sanitizedGitEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {}
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith('GIT_')) environment[key] = value
  }
  return environment
}

function gitOutput(
  root: AnchoredDirectory,
  arguments_: readonly string[],
): { ok: boolean; output: string } {
  verifyAnchoredDirectory(root, 'audit Git subprocess')
  let ok = true
  let output = ''
  try {
    output = execFileSync(
      'git',
      ['-C', `/proc/${process.pid}/fd/${root.fd}`, ...arguments_],
      {
        encoding: 'utf8',
        env: sanitizedGitEnvironment(),
        stdio: ['ignore', 'pipe', 'ignore'],
      },
    )
  } catch {
    ok = false
    output = ''
  }
  verifyAnchoredDirectory(root, 'audit Git subprocess')
  return { ok, output }
}

function checkedGitPath(output: string, description: string): string {
  const value = output.replace(/\r?\n$/, '')
  if (!path.isAbsolute(value) || value.includes('\0') || /[\r\n]/.test(value)) {
    throw new Error(`Git returned an unsafe ${description}`)
  }
  return value
}

interface AnchoredGitAdmin {
  fd: number
  namedPath: string
  procPath: string
  device: number
  inode: number
}

function verifyAnchoredGitAdmin(gitAdmin: AnchoredGitAdmin): void {
  const retained = anchoredRootIdentity.getStore()
  if (
    retained?.gitAdmin !== undefined &&
    gitAdmin.fd === retained.gitAdmin.fd
  ) {
    verifyRetainedDirectoryDescriptor(
      gitAdmin.fd,
      gitAdmin.procPath,
      gitAdmin.device,
      gitAdmin.inode,
      'retained Git audit administration directory changed identity',
    )
    return
  }
  const opened = fs.fstatSync(gitAdmin.fd)
  let named: fs.Stats
  let namedReal: string
  let openedReal: string
  try {
    named = fs.lstatSync(gitAdmin.namedPath)
    namedReal = fs.realpathSync(gitAdmin.namedPath)
    openedReal = fs.realpathSync(gitAdmin.procPath)
  } catch {
    throw new Error('Git audit administration directory changed or is no longer safe')
  }
  if (
    !opened.isDirectory() ||
    opened.dev !== gitAdmin.device ||
    opened.ino !== gitAdmin.inode ||
    named.isSymbolicLink() ||
    !named.isDirectory() ||
    named.dev !== gitAdmin.device ||
    named.ino !== gitAdmin.inode ||
    namedReal !== gitAdmin.namedPath ||
    openedReal !== gitAdmin.namedPath
  ) {
    throw new Error('Git audit administration directory changed identity or is symlinked')
  }
}

function gitAdminOutput(
  root: AnchoredDirectory,
  gitAdmin: AnchoredGitAdmin,
  arguments_: readonly string[],
): { ok: boolean; output: string } {
  verifyAnchoredDirectory(root, 'audit anchored Git subprocess')
  verifyAnchoredGitAdmin(gitAdmin)
  let ok = true
  let output = ''
  try {
    output = execFileSync(
      'git',
      [
        `--git-dir=/proc/${process.pid}/fd/${gitAdmin.fd}`,
        `--work-tree=/proc/${process.pid}/fd/${root.fd}`,
        ...arguments_,
      ],
      {
        encoding: 'utf8',
        env: sanitizedGitEnvironment(),
        stdio: ['ignore', 'pipe', 'ignore'],
      },
    )
  } catch {
    ok = false
    output = ''
  }
  verifyAnchoredDirectory(root, 'audit anchored Git subprocess')
  verifyAnchoredGitAdmin(gitAdmin)
  return { ok, output }
}

function gitAdminDirectory(
  repository: SafeRoot,
  root: AnchoredDirectory,
): AnchoredGitAdmin {
  const topLevelResult = gitOutput(root, ['rev-parse', '--show-toplevel'])
  if (!topLevelResult.ok) {
    throw new Error('audit locking requires an initialized Git worktree')
  }
  const topLevel = checkedGitPath(
    topLevelResult.output,
    'worktree root',
  )
  let realTopLevel: string
  try {
    realTopLevel = fs.realpathSync(topLevel)
  } catch {
    throw new Error('Git returned an unsafe worktree root')
  }
  if (realTopLevel !== repository.real) {
    throw new Error('audit locking requires the exact Git worktree root')
  }
  verifyAnchoredDirectory(root, 'audit Git worktree discovery')

  const gitDirectoryResult = gitOutput(
    root,
    ['rev-parse', '--path-format=absolute', '--absolute-git-dir'],
  )
  if (!gitDirectoryResult.ok) {
    throw new Error('audit locking requires an initialized Git worktree')
  }
  const gitDirectory = checkedGitPath(
    gitDirectoryResult.output,
    'audit administration path',
  )
  const real = fs.realpathSync(gitDirectory)
  const discovered = fs.lstatSync(real)
  if (!discovered.isDirectory() || discovered.isSymbolicLink()) {
    throw new Error('Git audit administration path is not a safe directory')
  }
  const fd = fs.openSync(real, directoryOpenFlags())
  try {
    const opened = fs.fstatSync(fd)
    const gitAdmin: AnchoredGitAdmin = {
      fd,
      namedPath: real,
      procPath: procFdPath(fd),
      device: opened.dev,
      inode: opened.ino,
    }
    if (
      !opened.isDirectory() ||
      opened.dev !== discovered.dev ||
      opened.ino !== discovered.ino
    ) {
      throw new Error('Git audit administration directory changed identity while opening')
    }
    verifyAnchoredGitAdmin(gitAdmin)
    const confirmedTopLevelResult = gitAdminOutput(
      root,
      gitAdmin,
      ['rev-parse', '--show-toplevel'],
    )
    if (!confirmedTopLevelResult.ok) {
      throw new Error('Git audit administration directory is not bound to a worktree')
    }
    const confirmedTopLevel = checkedGitPath(
      confirmedTopLevelResult.output,
      'anchored worktree root',
    )
    let confirmedRealTopLevel: string
    try {
      confirmedRealTopLevel = fs.realpathSync(confirmedTopLevel)
    } catch {
      throw new Error('Git audit administration directory returned an unsafe worktree root')
    }
    if (confirmedRealTopLevel !== repository.real) {
      throw new Error('Git audit administration directory is not bound to the requested worktree')
    }
    verifyAnchoredDirectory(root, 'audit Git administration discovery')
    return gitAdmin
  } catch (error) {
    const cleanupFailures: unknown[] = []
    try {
      closeDescriptorReliably(fd)
    } catch (cleanupError) {
      cleanupFailures.push(cleanupError)
    }
    throwCombinedFailures(
      true,
      error,
      cleanupFailures,
      'Git audit administration discovery failed and descriptor cleanup also failed',
    )
    throw new Error('unreachable Git audit administration discovery')
  }
}

interface AnchoredGitContext {
  root: AnchoredDirectory
  gitAdmin: AnchoredGitAdmin
}

function openAnchoredGitContext(
  rootPath: string,
  context: string,
): AnchoredGitContext {
  const repository = safeRoot(rootPath)
  const root = openVerifiedRepositoryRoot(repository, context)
  let gitAdmin: AnchoredGitAdmin | null = null
  try {
    gitAdmin = gitAdminDirectory(repository, root)
    verifyAnchoredDirectory(root, context)
    verifyAnchoredGitAdmin(gitAdmin)
    return { root, gitAdmin }
  } catch (error) {
    const cleanupFailures: unknown[] = []
    if (gitAdmin !== null) {
      try {
        closeDescriptorReliably(gitAdmin.fd)
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError)
      }
    }
    try {
      closeDescriptorReliably(root.fd)
    } catch (cleanupError) {
      cleanupFailures.push(cleanupError)
    }
    throwCombinedFailures(
      true,
      error,
      cleanupFailures,
      'audit Git capability discovery failed and descriptor cleanup also failed',
    )
    throw new Error('unreachable audit Git capability discovery')
  }
}

function closeAnchoredGitContext(
  context: AnchoredGitContext,
  cleanupFailures: unknown[],
): void {
  try {
    closeDescriptorReliably(context.gitAdmin.fd)
  } catch (error) {
    cleanupFailures.push(error)
  }
  try {
    closeDescriptorReliably(context.root.fd)
  } catch (error) {
    cleanupFailures.push(error)
  }
}

function gitAdminBytes(
  root: AnchoredDirectory,
  gitAdmin: AnchoredGitAdmin,
  arguments_: readonly string[],
  maxBytes: number,
): { ok: boolean; output: Buffer } {
  verifyAnchoredDirectory(root, 'audit anchored Git byte subprocess')
  verifyAnchoredGitAdmin(gitAdmin)
  let ok = true
  let output = Buffer.alloc(0)
  try {
    output = execFileSync(
      'git',
      [
        `--git-dir=/proc/${process.pid}/fd/${gitAdmin.fd}`,
        `--work-tree=/proc/${process.pid}/fd/${root.fd}`,
        ...arguments_,
      ],
      {
        env: sanitizedGitEnvironment(),
        maxBuffer: maxBytes + 1,
        stdio: ['ignore', 'pipe', 'ignore'],
      },
    )
  } catch {
    ok = false
    output = Buffer.alloc(0)
  }
  verifyAnchoredDirectory(root, 'audit anchored Git byte subprocess')
  verifyAnchoredGitAdmin(gitAdmin)
  return { ok, output }
}

export interface AnchoredAuditGitWorktreeFile {
  blob: string
  mode: '100644' | '100755'
}

export interface AnchoredAuditGitWorktreeFileDigests {
  sha1: string
  sha256: string
  mode: '100644' | '100755'
}

export interface AnchoredAuditGitCapability {
  gitBytes(arguments_: readonly string[], maxBytes: number): Uint8Array
  hashWorktreeFile(
    repoPath: string,
    algorithm: 'sha1' | 'sha256',
    maxBytes: number,
  ): AnchoredAuditGitWorktreeFile | null
  hashWorktreeFileDigests(
    repoPath: string,
    maxBytes: number,
  ): AnchoredAuditGitWorktreeFileDigests | null
}

function boundedAnchoredGitBytes(
  context: AnchoredGitContext,
  arguments_: readonly string[],
  maxBytes: number,
): Uint8Array {
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 0 ||
    !Array.isArray(arguments_) ||
    arguments_.some((argument) => typeof argument !== 'string')
  ) {
    throw new Error('anchored Git byte request is invalid')
  }
  const result = gitAdminBytes(
    context.root,
    context.gitAdmin,
    arguments_,
    maxBytes,
  )
  if (!result.ok) {
    throw new Error(
      `anchored Git command failed: ${arguments_.join(' ')}`,
    )
  }
  if (result.output.byteLength > maxBytes) {
    throw new Error(`anchored Git output exceeds the ${maxBytes}-byte limit`)
  }
  const output = new Uint8Array(result.output)
  registerAuditSupportGitQuerySeal(arguments_, maxBytes, output)
  return output
}

function hashAnchoredGitWorktreeFileDigests(
  context: AnchoredGitContext,
  repoPath: string,
  maxBytes: number,
): AnchoredAuditGitWorktreeFileDigests | null {
  const normalized = normalizeAuditRepoPath(repoPath)
  if (
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 0
  ) {
    throw new Error('anchored worktree hash request is invalid')
  }
  const segments = normalized.split('/')
  const leaf = segments.at(-1)!
  let parentSegments = segments.slice(0, -1)
  const ownedDirectories: AnchoredDirectory[] = []
  let current = context.root
  let currentRelativePath = ''
  let fileFd: number | null = null
  let missingParent = false
  let result: AnchoredAuditGitWorktreeFileDigests | null = null
  let primaryFailed = false
  let primaryFailure: unknown
  const cleanupFailures: unknown[] = []

  try {
    verifyAnchoredDirectory(context.root, normalized)
    verifyAnchoredGitAdmin(context.gitAdmin)
    if (segments.length > 1 && segments[0] === '.atlas') {
      const retainedAuditDirectory = openRetainedAuditDirectory(
        context.root.repository,
        normalized,
      )
      if (retainedAuditDirectory !== null) {
        ownedDirectories.push(retainedAuditDirectory)
        current = retainedAuditDirectory
        currentRelativePath = '.atlas'
        parentSegments = segments.slice(1, -1)
      }
    }
    for (const segment of parentSegments) {
      const childPath = path.join(current.procPath, segment)
      const child = fs.lstatSync(childPath, { throwIfNoEntry: false })
      if (!child) {
        registerAuditSupportAbsenceSeal(
          normalized,
          current,
          currentRelativePath,
          maxBytes,
        )
        missingParent = true
        break
      }
      if (child.isSymbolicLink() || !child.isDirectory()) {
        throw new Error(
          `tracked worktree path has an unsafe parent: ${normalized}`,
        )
      }
      const childFd = fs.openSync(childPath, directoryOpenFlags())
      let adopted = false
      try {
        const opened = fs.fstatSync(childFd)
        const next: AnchoredDirectory = {
          fd: childFd,
          namedPath: path.join(current.namedPath, segment),
          procPath: procFdPath(childFd),
          repository: context.root.repository,
          device: opened.dev,
          inode: opened.ino,
          ...(current.auditRelativePath === undefined
            ? {}
            : {
                auditRelativePath: current.auditRelativePath.length === 0
                  ? segment
                  : `${current.auditRelativePath}/${segment}`,
              }),
        }
        ownedDirectories.push(next)
        adopted = true
        if (
          !opened.isDirectory() ||
          opened.dev !== child.dev ||
          opened.ino !== child.ino
        ) {
          throw new Error(
            `tracked worktree parent changed while opening: ${normalized}`,
          )
        }
        verifyAnchoredDirectory(next, normalized)
        current = next
        currentRelativePath = currentRelativePath.length === 0
          ? segment
          : `${currentRelativePath}/${segment}`
      } catch (error) {
        if (!adopted) {
          try {
            closeDescriptorReliably(childFd)
          } catch (cleanupError) {
            throw new AggregateError(
              [error, cleanupError],
              'tracked worktree parent open failed and cleanup also failed',
            )
          }
        }
        throw error
      }
    }

    if (missingParent) {
      // A missing parent already established an ordinary tracked deletion.
    } else {
      const leafPath = path.join(current.procPath, leaf)
      const visible = fs.lstatSync(leafPath, { throwIfNoEntry: false })
      if (!visible) {
        registerAuditSupportAbsenceSeal(
          normalized,
          current,
          currentRelativePath,
          maxBytes,
        )
        result = null
      } else {
        if (visible.isSymbolicLink() || !visible.isFile()) {
          throw new Error(
            `tracked worktree path is not a safe regular file: ${normalized}`,
          )
        }
        fileFd = fs.openSync(
          leafPath,
          fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
        )
        const before = fs.fstatSync(fileFd)
        if (
          !before.isFile() ||
          before.dev !== visible.dev ||
          before.ino !== visible.ino
        ) {
          throw new Error(
            `tracked worktree path changed while opening: ${normalized}`,
          )
        }
        if (before.size > maxBytes) {
          throw new Error(
            `tracked worktree file exceeds the ${maxBytes}-byte limit: ${normalized}`,
          )
        }
        verifyAnchoredRegularFile(current, leaf, before, normalized)
        const blobHeader = `blob ${before.size}\0`
        const sha1 = createHash('sha1').update(blobHeader)
        const sha256 = createHash('sha256').update(blobHeader)
        const buffer = Buffer.allocUnsafe(64 * 1024)
        let total = 0
        while (total < before.size) {
          const count = fs.readSync(
            fileFd,
            buffer,
            0,
            Math.min(buffer.length, before.size - total),
            null,
          )
          if (count === 0) {
            throw new Error(
              `tracked worktree file changed while hashing: ${normalized}`,
            )
          }
          sha1.update(buffer.subarray(0, count))
          sha256.update(buffer.subarray(0, count))
          total += count
        }
        const extra = fs.readSync(fileFd, buffer, 0, 1, null)
        const after = fs.fstatSync(fileFd)
        if (
          extra !== 0 ||
          after.dev !== before.dev ||
          after.ino !== before.ino ||
          after.size !== before.size ||
          after.mtimeMs !== before.mtimeMs ||
          after.ctimeMs !== before.ctimeMs
        ) {
          throw new Error(
            `tracked worktree file changed while hashing: ${normalized}`,
          )
        }
        verifyAnchoredDirectory(context.root, normalized)
        verifyAnchoredGitAdmin(context.gitAdmin)
        for (const directory of ownedDirectories) {
          verifyAnchoredDirectory(directory, normalized)
        }
        verifyAnchoredRegularFile(current, leaf, before, normalized)
        const sha1Digest = sha1.digest('hex')
        const sha256Digest = sha256.digest('hex')
        registerAuditSupportFileSeal(
          normalized,
          current,
          fileFd,
          sha256Digest,
        )
        result = {
          sha1: sha1Digest,
          sha256: sha256Digest,
          mode: (before.mode & 0o111) === 0 ? '100644' : '100755',
        }
      }
    }
    verifyAnchoredDirectory(context.root, normalized)
    verifyAnchoredGitAdmin(context.gitAdmin)
  } catch (error) {
    primaryFailed = true
    primaryFailure = error
  }

  if (fileFd !== null) {
    try {
      closeDescriptorReliably(fileFd)
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  for (const directory of ownedDirectories.reverse()) {
    try {
      closeDescriptorReliably(directory.fd)
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  throwCombinedFailures(
    primaryFailed,
    primaryFailure,
    cleanupFailures,
    'tracked worktree hash failed and descriptor cleanup also failed',
  )
  return result
}

function hashAnchoredGitWorktreeFile(
  context: AnchoredGitContext,
  repoPath: string,
  algorithm: 'sha1' | 'sha256',
  maxBytes: number,
): AnchoredAuditGitWorktreeFile | null {
  if (algorithm !== 'sha1' && algorithm !== 'sha256') {
    throw new Error('anchored worktree hash request is invalid')
  }
  const file = hashAnchoredGitWorktreeFileDigests(
    context,
    repoPath,
    maxBytes,
  )
  return file === null
    ? null
    : {
        blob: file[algorithm],
        mode: file.mode,
      }
}

export function withAnchoredAuditGitCapability<T>(
  rootPath: string,
  operation: (capability: AnchoredAuditGitCapability) => T,
): T {
  if (typeof operation !== 'function') {
    throw new Error('anchored Git operation must be a function')
  }
  const context = openAnchoredGitContext(
    rootPath,
    'anchored audit Git capability',
  )
  const capability: AnchoredAuditGitCapability = {
    gitBytes: (arguments_, maxBytes) =>
      boundedAnchoredGitBytes(context, arguments_, maxBytes),
    hashWorktreeFile: (repoPath, algorithm, maxBytes) =>
      hashAnchoredGitWorktreeFile(
        context,
        repoPath,
        algorithm,
        maxBytes,
      ),
    hashWorktreeFileDigests: (repoPath, maxBytes) =>
      hashAnchoredGitWorktreeFileDigests(
        context,
        repoPath,
        maxBytes,
      ),
  }

  const finish = (
    primaryFailed: boolean,
    primaryFailure: unknown,
    value?: unknown,
  ): unknown => {
    const cleanupFailures: unknown[] = []
    try {
      verifyAnchoredDirectory(
        context.root,
        'anchored audit Git capability completion',
      )
      verifyAnchoredGitAdmin(context.gitAdmin)
    } catch (error) {
      cleanupFailures.push(error)
    }
    closeAnchoredGitContext(context, cleanupFailures)
    throwCombinedFailures(
      primaryFailed,
      primaryFailure,
      cleanupFailures,
      'anchored audit Git operation failed and descriptor cleanup also failed',
    )
    return value
  }

  let result: T
  try {
    result = operation(capability)
  } catch (error) {
    return finish(true, error) as T
  }

  if (
    result !== null &&
    (typeof result === 'object' || typeof result === 'function')
  ) {
    let then: unknown
    try {
      then = (result as { then?: unknown }).then
    } catch (error) {
      return finish(true, error) as T
    }
    if (typeof then === 'function') {
      const pending = new Promise<unknown>((resolve, reject) => {
        queueMicrotask(() => {
          try {
            Reflect.apply(then, result, [resolve, reject])
          } catch (error) {
            reject(error)
          }
        })
      })
      return pending.then(
        (value) => finish(false, undefined, value),
        (error) => finish(true, error),
      ) as T
    }
  }

  return finish(false, undefined, result) as T
}

export function withAnchoredAuditRootIdentity<T>(
  rootPath: string,
  operation: (anchoredRootPath: string) => T,
): T {
  if (typeof operation !== 'function') {
    throw new Error('anchored root operation must be a function')
  }
  const repository = anchoredRootIdentity.run(
    undefined,
    () => safeRoot(rootPath),
  )
  const root = openVerifiedRepositoryRoot(
    repository,
    'anchored audit root identity',
  )
  const context: AnchoredRootIdentityContext = { root }

  const finish = (
    primaryFailed: boolean,
    primaryFailure: unknown,
    value?: unknown,
  ): unknown => {
    const cleanupFailures: unknown[] = []
    try {
      verifySafeRootIdentity(root.repository)
      verifyAnchoredDirectory(
        root,
        'anchored audit root identity completion',
      )
    } catch (error) {
      cleanupFailures.push(error)
    }
    try {
      closeDescriptorReliably(root.fd)
    } catch (error) {
      cleanupFailures.push(error)
    }
    throwCombinedFailures(
      primaryFailed,
      primaryFailure,
      cleanupFailures,
      'anchored audit root operation failed and cleanup also failed',
    )
    return value
  }

  return anchoredRootIdentity.run(context, () => {
    let result: T
    try {
      result = operation(root.procPath)
    } catch (error) {
      return finish(true, error) as T
    }

    if (
      result !== null &&
      (typeof result === 'object' || typeof result === 'function')
    ) {
      let then: unknown
      try {
        then = (result as { then?: unknown }).then
      } catch (error) {
        return finish(true, error) as T
      }
      if (typeof then === 'function') {
        const pending = new Promise<unknown>((resolve, reject) => {
          queueMicrotask(() => {
            try {
              Reflect.apply(then, result, [resolve, reject])
            } catch (error) {
              reject(error)
            }
          })
        })
        return pending.then(
          (value) => finish(false, undefined, value),
          (error) => finish(true, error),
        ) as T
      }
    }

    return finish(false, undefined, result) as T
  })
}

export function readBoundedAuditGitBlob(
  rootPath: string,
  blob: string,
  maxBytes = AUDIT_LIMITS.jsonBytes,
): Uint8Array {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new Error('audit Git blob byte limit must be a nonnegative safe integer')
  }
  const match = /^git-(sha1|sha256):([0-9a-f]+)$/.exec(blob)
  if (
    !match ||
    (match[1] === 'sha1' && match[2].length !== 40) ||
    (match[1] === 'sha256' && match[2].length !== 64)
  ) {
    throw new Error(
      'audit Git blob must be strictly prefixed git-sha1:<40 lowercase hex> or git-sha256:<64 lowercase hex>',
    )
  }
  const algorithm = match[1] as 'sha1' | 'sha256'
  const objectId = match[2]
  const byteLimit = Math.min(maxBytes, AUDIT_LIMITS.jsonBytes)
  const context = openAnchoredGitContext(rootPath, 'audit Git blob read')
  let result!: Uint8Array
  let primaryFailed = false
  let primaryFailure: unknown
  const cleanupFailures: unknown[] = []
  try {
    const objectFormat = gitAdminOutput(
      context.root,
      context.gitAdmin,
      ['rev-parse', '--show-object-format=storage'],
    )
    if (
      !objectFormat.ok ||
      (
        objectFormat.output !== 'sha1\n' &&
        objectFormat.output !== 'sha1\r\n' &&
        objectFormat.output !== 'sha256\n' &&
        objectFormat.output !== 'sha256\r\n'
      )
    ) {
      throw new Error('audit Git repository object format is unavailable or invalid')
    }
    const repositoryAlgorithm = objectFormat.output.replace(/\r?\n$/, '')
    if (repositoryAlgorithm !== algorithm) {
      throw new Error(
        `audit Git blob algorithm ${algorithm} does not match repository object format ${repositoryAlgorithm}`,
      )
    }

    const type = gitAdminOutput(
      context.root,
      context.gitAdmin,
      ['cat-file', '-t', objectId],
    )
    if (!type.ok) {
      throw new Error('audit Git blob object is missing or unavailable')
    }
    if (type.output !== 'blob\n' && type.output !== 'blob\r\n') {
      throw new Error('audit Git object type is not blob')
    }

    const size = gitAdminOutput(
      context.root,
      context.gitAdmin,
      ['cat-file', '-s', objectId],
    )
    if (!size.ok || !/^(0|[1-9][0-9]*)\r?\n$/.test(size.output)) {
      throw new Error('audit Git blob size is unavailable or invalid')
    }
    const expectedSize = Number(size.output.trimEnd())
    if (!Number.isSafeInteger(expectedSize)) {
      throw new Error('audit Git blob size exceeds the safe integer range')
    }
    if (expectedSize > byteLimit) {
      throw new Error(`audit Git blob exceeds the ${byteLimit}-byte limit`)
    }

    const bytes = gitAdminBytes(
      context.root,
      context.gitAdmin,
      ['cat-file', 'blob', objectId],
      byteLimit,
    )
    if (!bytes.ok) {
      throw new Error('audit Git blob bytes are unavailable')
    }
    if (bytes.output.length !== expectedSize) {
      throw new Error('audit Git blob byte length does not match its object size')
    }
    const header = Buffer.from(`blob ${bytes.output.length}\0`, 'utf8')
    const verifiedObjectId = createHash(algorithm)
      .update(header)
      .update(bytes.output)
      .digest('hex')
    if (verifiedObjectId !== objectId) {
      throw new Error('audit Git blob bytes do not match the claimed object identity')
    }
    result = new Uint8Array(bytes.output)
  } catch (error) {
    primaryFailed = true
    primaryFailure = error
  }

  closeAnchoredGitContext(context, cleanupFailures)
  throwCombinedFailures(
    primaryFailed,
    primaryFailure,
    cleanupFailures,
    'audit Git blob read failed and descriptor cleanup also failed',
  )
  return result
}

interface AnchoredLockParent {
  fd: number
  namedPath: string
  procPath: string
  device: number
  inode: number
}

function verifyAnchoredLockParent(parent: AnchoredLockParent): void {
  const retained = anchoredRootIdentity.getStore()
  if (
    retained?.lockParent !== undefined &&
    parent.fd === retained.lockParent.fd
  ) {
    verifyRetainedDirectoryDescriptor(
      parent.fd,
      parent.procPath,
      parent.device,
      parent.inode,
      'retained audit lock parent changed identity',
    )
    return
  }
  const opened = fs.fstatSync(parent.fd)
  let named: fs.Stats
  let namedReal: string
  let openedReal: string
  try {
    named = fs.lstatSync(parent.namedPath)
    namedReal = fs.realpathSync(parent.namedPath)
    openedReal = fs.realpathSync(parent.procPath)
  } catch {
    throw new Error('audit lock parent changed or is no longer safe')
  }
  if (
    !opened.isDirectory() ||
    opened.dev !== parent.device ||
    opened.ino !== parent.inode ||
    named.isSymbolicLink() ||
    !named.isDirectory() ||
    named.dev !== parent.device ||
    named.ino !== parent.inode ||
    namedReal !== parent.namedPath ||
    openedReal !== parent.namedPath
  ) {
    throw new Error('audit lock parent changed identity or is symlinked')
  }
}

function openAuditLockParent(gitAdmin: AnchoredGitAdmin): AnchoredLockParent {
  let childFd: number | null = null
  try {
    verifyAnchoredGitAdmin(gitAdmin)
    const childName = 'repo-atlas'
    const childPath = path.join(gitAdmin.procPath, childName)
    let child = fs.lstatSync(childPath, { throwIfNoEntry: false })
    if (!child) {
      try {
        fs.mkdirSync(childPath, { recursive: false, mode: 0o700 })
        fsyncDirectoryFd(gitAdmin.fd)
      } catch (error) {
        if (errnoCode(error) !== 'EEXIST') throw error
      }
      child = fs.lstatSync(childPath, { throwIfNoEntry: false })
    }
    if (!child || child.isSymbolicLink() || !child.isDirectory()) {
      throw new Error('audit lock parent is not a safe regular directory')
    }

    childFd = fs.openSync(childPath, directoryOpenFlags())
    const openedChild = fs.fstatSync(childFd)
    if (
      !openedChild.isDirectory() ||
      openedChild.dev !== child.dev ||
      openedChild.ino !== child.ino
    ) {
      throw new Error('audit lock parent changed identity while opening')
    }
    const parent: AnchoredLockParent = {
      fd: childFd,
      namedPath: path.join(gitAdmin.namedPath, childName),
      procPath: procFdPath(childFd),
      device: openedChild.dev,
      inode: openedChild.ino,
    }
    verifyAnchoredGitAdmin(gitAdmin)
    verifyAnchoredLockParent(parent)
    return parent
  } catch (error) {
    const cleanupFailures: unknown[] = []
    if (childFd !== null) {
      try {
        closeDescriptorReliably(childFd)
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError)
      }
    }
    throwCombinedFailures(
      true,
      error,
      cleanupFailures,
      'audit lock parent open failed and descriptor cleanup also failed',
    )
    throw new Error('unreachable audit lock parent open')
  }
}

function openAuditLockContext(rootPath: string): {
  root: AnchoredDirectory
  gitAdmin: AnchoredGitAdmin
  parent: AnchoredLockParent
} {
  const context = openAnchoredGitContext(rootPath, 'audit lock capability check')
  let parent: AnchoredLockParent | null = null
  try {
    parent = openAuditLockParent(context.gitAdmin)
    verifyAnchoredDirectory(context.root, 'audit lock context')
    verifyAnchoredGitAdmin(context.gitAdmin)
    verifyAnchoredLockParent(parent)
    return { root: context.root, gitAdmin: context.gitAdmin, parent }
  } catch (error) {
    const cleanupFailures: unknown[] = []
    if (parent !== null) {
      try {
        closeDescriptorReliably(parent.fd)
      } catch (cleanupError) {
        cleanupFailures.push(cleanupError)
      }
    }
    closeAnchoredGitContext(context, cleanupFailures)
    throwCombinedFailures(
      true,
      error,
      cleanupFailures,
      'audit lock discovery failed and descriptor cleanup also failed',
    )
    throw new Error('unreachable audit lock discovery')
  }
}

function verifyAuditLockContext(
  root: AnchoredDirectory,
  gitAdmin: AnchoredGitAdmin,
  parent: AnchoredLockParent,
  context: string,
): void {
  verifyAnchoredDirectory(root, context)
  verifyAnchoredGitAdmin(gitAdmin)
  verifyAnchoredLockParent(parent)
}

function sourceSnapshot(
  root: AnchoredDirectory,
  gitAdmin: AnchoredGitAdmin,
): string {
  const result = gitAdminOutput(
    root,
    gitAdmin,
    ['rev-parse', '--verify', 'HEAD'],
  )
  return result.ok ? result.output.trim() : 'unborn'
}

function readBoundedLockDescriptor(fd: number): Buffer {
  const buffer = Buffer.allocUnsafe(AUDIT_LOCK_BYTES + 1)
  let offset = 0
  while (offset < buffer.length) {
    const count = fs.readSync(fd, buffer, offset, buffer.length - offset, null)
    if (count === 0) break
    offset += count
  }
  return buffer.subarray(0, offset)
}

function existingLockDescription(parent: AnchoredLockParent): string {
  const file = path.join(parent.procPath, 'audit-state.lock')
  let fd: number | null = null
  let description = 'an unsafe or malformed existing lock'
  let primaryFailed = false
  let primaryFailure: unknown
  const cleanupFailures: unknown[] = []

  try {
    verifyAnchoredLockParent(parent)
    const noFollow = fs.constants.O_NOFOLLOW ?? 0
    const nonBlocking = fs.constants.O_NONBLOCK ?? 0
    fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow | nonBlocking)
    verifyAnchoredLockParent(parent)
    const opened = fs.fstatSync(fd)
    if (opened.isFile() && opened.size <= AUDIT_LOCK_BYTES) {
      const bytes = readBoundedLockDescriptor(fd)
      const after = fs.fstatSync(fd)
      verifyAnchoredLockParent(parent)
      if (
        bytes.length <= AUDIT_LOCK_BYTES &&
        after.isFile() &&
        after.dev === opened.dev &&
        after.ino === opened.ino &&
        after.size === opened.size &&
        after.mtimeMs === opened.mtimeMs &&
        after.ctimeMs === opened.ctimeMs
      ) {
        let value: unknown
        try {
          const text = UTF8.decode(bytes)
          value = new BoundedJsonParser(text, 'audit lock receipt').parse()
        } catch {
          value = null
        }
        if (
          value &&
          typeof value === 'object' &&
          'pid' in value &&
          Number.isSafeInteger((value as { pid?: unknown }).pid)
        ) {
          const operation = 'operation' in value && typeof (value as { operation?: unknown }).operation === 'string'
            ? ` (${(value as { operation: string }).operation.slice(0, 128)})`
            : ''
          description = `pid ${(value as { pid: number }).pid}${operation}`
        }
      }
    }
  } catch (error) {
    const code = errnoCode(error)
    if (code !== 'ENOENT' && code !== 'ELOOP' && code !== 'ENXIO') {
      primaryFailed = true
      primaryFailure = error
    }
  }

  if (fd !== null) {
    try {
      closeDescriptorReliably(fd)
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  throwCombinedFailures(
    primaryFailed,
    primaryFailure,
    cleanupFailures,
    'audit lock inspection failed and descriptor cleanup also failed',
  )
  return description
}

function verifyOwnedLockPath(
  parent: AnchoredLockParent,
  device: number,
  inode: number,
): void {
  const file = path.join(parent.procPath, 'audit-state.lock')
  let current: fs.Stats
  try {
    current = fs.lstatSync(file)
  } catch (error) {
    if (errnoCode(error) === 'ENOENT') {
      throw new Error('owned audit lock is missing')
    }
    throw error
  }
  if (
    current.isSymbolicLink() ||
    !current.isFile() ||
    current.dev !== device ||
    current.ino !== inode
  ) {
    throw new Error('owned audit lock changed identity')
  }
}

function cleanupOwnedLock(
  parent: AnchoredLockParent,
  fd: number | null,
  device: number | null,
  inode: number | null,
): void {
  if (fd === null || device === null || inode === null) return
  const opened = fs.fstatSync(fd)
  if (
    !opened.isFile() ||
    opened.dev !== device ||
    opened.ino !== inode
  ) {
    throw new Error('owned audit lock descriptor changed identity')
  }
  const file = path.join(parent.procPath, 'audit-state.lock')
  verifyOwnedLockPath(parent, device, inode)
  fs.unlinkSync(file)
  fsyncDirectoryFd(parent.fd)
}

function closeLockContext(
  root: AnchoredDirectory,
  gitAdmin: AnchoredGitAdmin,
  parent: AnchoredLockParent,
  cleanupFailures: unknown[],
): void {
  try {
    closeDescriptorReliably(parent.fd)
  } catch (error) {
    cleanupFailures.push(error)
  }
  try {
    closeDescriptorReliably(gitAdmin.fd)
  } catch (error) {
    cleanupFailures.push(error)
  }
  try {
    closeDescriptorReliably(root.fd)
  } catch (error) {
    cleanupFailures.push(error)
  }
}

function acquireAuditLock(rootPath: string, operation: () => unknown): LockHandle {
  const context = openAuditLockContext(rootPath)
  const file = path.join(context.parent.procPath, 'audit-state.lock')
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  let fd: number | null = null
  let device: number | null = null
  let inode: number | null = null
  let primaryFailed = false
  let primaryFailure: unknown
  const cleanupFailures: unknown[] = []

  try {
    verifyAuditLockContext(
      context.root,
      context.gitAdmin,
      context.parent,
      'audit lock acquisition',
    )
    try {
      fd = fs.openSync(
        file,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow,
        0o600,
      )
    } catch (error) {
      if (errnoCode(error) === 'EEXIST') {
        const description = existingLockDescription(context.parent)
        throw new Error(`audit state lock is already held by ${description}`)
      }
      throw error
    }

    const opened = fs.fstatSync(fd)
    if (!opened.isFile()) {
      throw new Error('audit state lock is not a safe regular file')
    }
    device = opened.dev
    inode = opened.ino
    verifyOwnedLockPath(context.parent, device, inode)
    verifyAuditLockContext(
      context.root,
      context.gitAdmin,
      context.parent,
      'audit lock acquisition',
    )

    const operationName = operation.name || 'anonymous'
    const receipt = canonicalJson({
      command: operationName,
      hostname: os.hostname(),
      operation: operationName,
      pid: process.pid,
      processStartedAt: PROCESS_STARTED_AT,
      sourceSnapshot: sourceSnapshot(context.root, context.gitAdmin),
      startedAt: new Date().toISOString(),
      token: randomUUID(),
    })
    if (Buffer.byteLength(receipt, 'utf8') > AUDIT_LOCK_BYTES) {
      throw new Error('audit lock receipt exceeds its byte limit')
    }
    fs.writeFileSync(fd, receipt, 'utf8')
    fs.fsyncSync(fd)
    verifyOwnedLockPath(context.parent, device, inode)
    verifyAuditLockContext(
      context.root,
      context.gitAdmin,
      context.parent,
      'audit lock acquisition',
    )
    return {
      fd,
      gitAdmin: context.gitAdmin,
      parent: context.parent,
      root: context.root,
      device,
      inode,
    }
  } catch (error) {
    primaryFailed = true
    primaryFailure = error
  }

  try {
    cleanupOwnedLock(context.parent, fd, device, inode)
  } catch (error) {
    cleanupFailures.push(error)
  }
  if (fd !== null) {
    try {
      closeDescriptorReliably(fd)
    } catch (error) {
      cleanupFailures.push(error)
    }
  }
  closeLockContext(
    context.root,
    context.gitAdmin,
    context.parent,
    cleanupFailures,
  )
  throwCombinedFailures(
    primaryFailed,
    primaryFailure,
    cleanupFailures,
    'audit lock acquisition failed and cleanup also failed',
  )
  throw new Error('unreachable audit lock acquisition')
}

function releaseAuditLock(lock: LockHandle): void {
  const failures: unknown[] = []
  let parentWasValid = true
  try {
    anchoredRootIdentity.run(
      undefined,
      () => verifyAuditLockContext(
        lock.root,
        lock.gitAdmin,
        lock.parent,
        'audit lock release',
      ),
    )
  } catch (error) {
    parentWasValid = false
    failures.push(error)
  }
  try {
    cleanupOwnedLock(lock.parent, lock.fd, lock.device, lock.inode)
  } catch (error) {
    failures.push(error)
  }
  try {
    closeDescriptorReliably(lock.fd)
  } catch (error) {
    failures.push(error)
  }
  if (parentWasValid) {
    try {
      anchoredRootIdentity.run(
        undefined,
        () => verifyAuditLockContext(
          lock.root,
          lock.gitAdmin,
          lock.parent,
          'audit lock release',
        ),
      )
    } catch (error) {
      failures.push(error)
    }
  }
  closeLockContext(lock.root, lock.gitAdmin, lock.parent, failures)
  throwCombinedFailures(
    false,
    undefined,
    failures,
    'audit lock release failed',
  )
}

function throwOperationAndReleaseFailure(
  operationFailure: unknown,
  releaseFailure: unknown,
): never {
  throw new AggregateError(
    [operationFailure, releaseFailure],
    'audit lock operation failed and lock release also failed',
  )
}

function releaseAfterOperationFailure(lock: LockHandle, error: unknown): never {
  try {
    releaseAuditLock(lock)
  } catch (releaseError) {
    throwOperationAndReleaseFailure(error, releaseError)
  }
  throw error
}

export function withAuditLock<T>(root: string, operation: () => T): T {
  if (typeof operation !== 'function') throw new Error('audit lock operation must be a function')
  const lock = anchoredRootIdentity.run(
    undefined,
    () => acquireAuditLock(root, operation),
  )
  const context: AnchoredRootIdentityContext = {
    root: lock.root,
    gitAdmin: lock.gitAdmin,
    lockParent: lock.parent,
  }
  return anchoredRootIdentity.run(context, () => {
    let result: T
    try {
      result = operation()
    } catch (error) {
      return releaseAfterOperationFailure(lock, error)
    }

    if (
      result !== null &&
      (typeof result === 'object' || typeof result === 'function')
    ) {
      let then: unknown
      try {
        then = (result as { then?: unknown }).then
      } catch (error) {
        return releaseAfterOperationFailure(lock, error)
      }
      if (typeof then === 'function') {
        const pending = new Promise<unknown>((resolve, reject) => {
          queueMicrotask(() => {
            try {
              Reflect.apply(then, result, [resolve, reject])
            } catch (error) {
              reject(error)
            }
          })
        })
        return pending.then(
          (value) => {
            releaseAuditLock(lock)
            return value
          },
          (error) => releaseAfterOperationFailure(lock, error),
        ) as T
      }
    }

    releaseAuditLock(lock)
    return result
  })
}
