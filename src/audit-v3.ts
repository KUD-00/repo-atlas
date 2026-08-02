import { createHash } from 'node:crypto'
import path from 'node:path'
import { TextDecoder } from 'node:util'
import {
  canonicalJson,
  atomicWriteAuditFile,
  listBoundedAuditDirectory,
  normalizeAuditRepoPath,
  readBoundedAuditGitBlob,
  readBoundedAuditJson,
  readBoundedAuditJsonDocument,
  stableAuditId,
  withAuditLock,
} from './audit-core.js'
import type {
  AtlasFindingId,
  AtlasFingerprintInput,
  AtlasFingerprintV1,
  AtlasObservationId,
  AtlasObservationIdentityInput,
  AtlasOccurrenceId,
  AtlasSecurityCurrentLedgerV3,
  AtlasSecurityFindingV3,
  AtlasSecurityObservationV3,
  AuditDiagnostic,
  AuditExactScopeIdentityInput,
  AuditFileReceiptV3,
  AuditGitBlob,
  AuditObservationHistoryEntryV3,
  AuditObservationHistoryLoadResult,
  AuditObservationHistoryV3,
  AuditObservationLoadResult,
  AuditObservationPublicationResult,
  AuditParseResult,
  PreparedAuditObservationPublication,
  AuditSemanticScopeIdentityInput,
  AuditSha256,
} from './audit-v3-types.js'

const SHA256_RE = /^sha256:[0-9a-f]{64}$/u
const GIT_BLOB_RE = /^(git-sha1:[0-9a-f]{40}|git-sha256:[0-9a-f]{64})$/u
const OBSERVATION_ID_RE = /^aobs_[0-9a-f]{24}$/u
const FINDING_ID_RE = /^atf_[0-9a-f]{24}$/u
const OCCURRENCE_ID_RE = /^atocc_[0-9a-f]{24}$/u
const FINGERPRINT_RE = /^atlas\/v1:sha256:[0-9a-f]{64}$/u
const CODEX_FINGERPRINT_RE = /^codex-security\/v1:sha256:[0-9a-f]{64}$/u
const SECURITY_SLUG_RE = /^security-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u
const KEBAB_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u
const CODEX_SLUG_RE = /^[a-z0-9][a-z0-9._/-]*$/u
const REPOSITORY_ID_RE = /^repo_[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/u
const FULL_GIT_REVISION_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u
const SOURCE_TIMESTAMP_RE =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))$/u
const RAW_SHA256_RE = /^[0-9a-f]{64}$/u
const JSON_POINTER_RE = /^(?:\/(?:[^~\u0000-\u001f\u007f]|~[01])*)+$/u
const EXTENSION_NAMESPACE_RE = /^[a-z0-9](?:[a-z0-9._/-]*[a-z0-9])?$/u
const PYTHON_WHITESPACE_RE =
  /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/u
const TEXT_LIMIT = 256 * 1024
const LEDGER_BYTE_LIMIT = 1024 * 1024
const EXTENSION_BYTE_LIMIT = 64 * 1024
const EXTENSION_DEPTH_LIMIT = 16
const EXTENSION_MEMBER_LIMIT = 1_000
const UTF8 = new TextDecoder('utf-8', { fatal: true })

export const AUDIT_V3_UNIQUE_BLOB_BYTE_LIMIT = 256 * 1024 * 1024

export function isStrictRfc3339Timestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const match = SOURCE_TIMESTAMP_RE.exec(value)
  if (!match) return false

  const [
    ,
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
    offsetHourText,
    offsetMinuteText,
  ] = match
  const year = Number(yearText)
  const month = Number(monthText)
  const day = Number(dayText)
  const hour = Number(hourText)
  const minute = Number(minuteText)
  const second = Number(secondText)
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return false
  }

  const leapYear =
    year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const daysInMonth = [
    31,
    leapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ][month - 1]
  if (day < 1 || day > daysInMonth) return false

  if (
    offsetHourText !== undefined &&
    (Number(offsetHourText) > 23 || Number(offsetMinuteText) > 59)
  ) {
    return false
  }
  return Number.isFinite(Date.parse(value))
}

interface AuditValidationContext {
  readonly blobBytes: Map<AuditGitBlob, Buffer>
  readonly historyObservationIds: Map<string, string>
  readonly historyOccurrenceIds: Map<string, string>
  uniqueBlobBytes: number
}

function createAuditValidationContext(): AuditValidationContext {
  return {
    blobBytes: new Map(),
    historyObservationIds: new Map(),
    historyOccurrenceIds: new Map(),
    uniqueBlobBytes: 0,
  }
}

export function registerAuditUniqueBlobBytes(
  currentBytes: number,
  additionalBytes: number,
  maxBytes = AUDIT_V3_UNIQUE_BLOB_BYTE_LIMIT,
): number {
  for (const [label, value] of [
    ['current bytes', currentBytes],
    ['additional bytes', additionalBytes],
    ['maximum bytes', maxBytes],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a nonnegative safe integer byte count`)
    }
  }
  if (currentBytes > maxBytes || additionalBytes > maxBytes - currentBytes) {
    throw new Error(
      `unique exact-source blob byte limit of ${maxBytes} bytes exceeded`,
    )
  }
  return currentBytes + additionalBytes
}

function utf16Compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function sha256Text(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function computeCodexFingerprint(
  targetId: string,
  ruleId: string,
  anchor: string,
  instance: string | undefined,
): string {
  return `codex-security/v1:sha256:${sha256Text([
    'codex-security/v1',
    targetId,
    ruleId,
    anchor,
    instance ?? '',
  ].join('\0'))}`
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

export function computeAuditCanonicalDigest(value: unknown): AuditSha256 {
  return `sha256:${sha256Text(canonicalJson(value))}`
}

function assertIdentityText(value: string, label: string): void {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > TEXT_LIMIT ||
    value.includes('\0') ||
    hasLoneSurrogate(value)
  ) {
    throw new Error(
      `${label} must be bounded nonempty identity text without NUL or lone Unicode surrogates`,
    )
  }
}

function assertSha256(value: string, label: string): asserts value is AuditSha256 {
  if (!SHA256_RE.test(value)) throw new Error(`${label} must be a lowercase SHA-256 digest`)
}

function assertGitBlob(value: string, label: string): asserts value is AuditGitBlob {
  if (!GIT_BLOB_RE.test(value)) throw new Error(`${label} must be a canonical Git blob digest`)
}

function assertSecuritySlug(value: string): void {
  if (!SECURITY_SLUG_RE.test(value)) {
    throw new Error('audit slug must begin with security- and use lowercase kebab-case')
  }
}

function assertPattern(value: string, label: string): void {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > TEXT_LIMIT ||
    value.includes('\0') ||
    hasLoneSurrogate(value) ||
    value.includes('\\') ||
    path.posix.isAbsolute(value) ||
    value.split('/').some((segment) => segment.length === 0 || segment === '.' || segment === '..')
  ) {
    throw new Error(`${label} must be a normalized repository-relative path pattern`)
  }
}

function assertSemanticSelector(value: string, label: string): void {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > TEXT_LIMIT ||
    value.includes('\0') ||
    hasLoneSurrogate(value) ||
    value.includes('\\') ||
    path.posix.isAbsolute(value)
  ) {
    throw new Error(`${label} must be a safe repository-relative semantic selector`)
  }
  if (value === '.') return
  const withoutTrailingSlash = value.endsWith('/')
    ? value.slice(0, -1)
    : value
  if (
    withoutTrailingSlash.length === 0 ||
    withoutTrailingSlash.split('/').some((segment) =>
      segment.length === 0 || segment === '.' || segment === '..'
    )
  ) {
    throw new Error(`${label} must be a safe repository-relative semantic selector`)
  }
}

function assertUnique(values: readonly string[], label: string): void {
  if (new Set(values).size !== values.length) throw new Error(`${label} must be unique`)
}

function assertSorted(values: readonly string[], label: string): void {
  for (let index = 1; index < values.length; index += 1) {
    if (utf16Compare(values[index - 1], values[index]) >= 0) {
      throw new Error(`${label} must be unique and sorted by UTF-16 code units`)
    }
  }
}

export function computeAtlasFingerprint(input: AtlasFingerprintInput): AtlasFingerprintV1 {
  if (!REPOSITORY_ID_RE.test(input.repositoryId)) {
    throw new Error('repositoryId must be a stable lowercase repo_ identity')
  }
  if (input.domain !== 'security') throw new Error('Atlas V3 fingerprint domain must be security')
  assertIdentityText(input.ruleId, 'ruleId')
  assertIdentityText(input.anchor, 'anchor')
  if (input.instance !== undefined) assertIdentityText(input.instance, 'instance')
  const digest = sha256Text([
    'atlas/v1',
    input.repositoryId,
    input.domain,
    input.ruleId,
    input.anchor,
    input.instance ?? '',
  ].join('\0'))
  return `atlas/v1:sha256:${digest}`
}

export function computeAtlasFindingId(fingerprint: AtlasFingerprintV1): AtlasFindingId {
  if (!FINGERPRINT_RE.test(fingerprint)) {
    throw new Error('Atlas finding fingerprint must use atlas/v1 SHA-256')
  }
  return `atf_${sha256Text(fingerprint).slice(0, 24)}`
}

export function computeAtlasObservationId(
  input: AtlasObservationIdentityInput,
): AtlasObservationId {
  assertSecuritySlug(input.slug)
  assertIdentityText(input.adapter, 'producer adapter')
  assertIdentityText(input.runId, 'producer runId')
  assertSha256(input.producerIdentityDigest, 'producer identityDigest')
  assertIdentityText(input.targetId, 'targetId')
  assertSha256(input.targetIdentityDigest, 'target identityDigest')
  assertSha256(input.scopeIdentityDigest, 'scope identityDigest')
  return stableAuditId(
    'aobs',
    'atlas-observation/v1',
    [
      input.slug,
      input.adapter,
      input.runId,
      input.producerIdentityDigest,
      input.targetId,
      input.targetIdentityDigest,
      input.scopeIdentityDigest,
    ],
  ) as AtlasObservationId
}

export function computeAtlasOccurrenceId(
  observationId: AtlasObservationId,
  fingerprint: AtlasFingerprintV1,
): AtlasOccurrenceId {
  if (!OBSERVATION_ID_RE.test(observationId)) throw new Error('invalid Atlas observationId')
  if (!FINGERPRINT_RE.test(fingerprint)) throw new Error('invalid Atlas fingerprint')
  return stableAuditId(
    'atocc',
    'atlas-occurrence/v1',
    [observationId, fingerprint],
  ) as AtlasOccurrenceId
}

export function computeExactScopeIdentityDigest(
  input: AuditExactScopeIdentityInput,
): AuditSha256 {
  if (!['repository', 'scoped_path', 'unit', 'diff', 'custom'].includes(input.mode)) {
    throw new Error('invalid exact scope mode')
  }
  for (const pattern of input.includePaths) assertPattern(pattern, 'include path')
  for (const pattern of input.excludePaths) assertPattern(pattern, 'exclude path')
  assertUnique(input.includePaths, 'include paths')
  assertUnique(input.excludePaths, 'exclude paths')
  const files = [...input.files].map((file) => {
    const normalized = normalizeAuditRepoPath(file.path)
    assertGitBlob(file.blob, `blob for ${normalized}`)
    return { path: normalized, blob: file.blob }
  }).sort((left, right) => utf16Compare(left.path, right.path))
  assertUnique(files.map((file) => file.path), 'exact scope file paths')
  const includePaths = [...input.includePaths].sort(utf16Compare)
  const excludePaths = [...input.excludePaths].sort(utf16Compare)
  return computeAuditCanonicalDigest({
    namespace: 'repo-atlas/exact-scope-identity/v1',
    mode: input.mode,
    includePaths,
    excludePaths,
    files,
  })
}

export function computeSemanticScopeIdentityDigest(
  input: AuditSemanticScopeIdentityInput,
): AuditSha256 {
  if (![
    'repository',
    'scoped_path',
    'diff',
    'commit',
    'branch_diff',
    'working_tree',
    'deep_repository',
    'unit',
    'custom',
  ].includes(input.mode)) {
    throw new Error('invalid semantic scope mode')
  }
  if (!['repository', 'scoped_path', 'diff', 'directory', 'custom', 'unit']
    .includes(input.inventoryStrategy)) {
    throw new Error('invalid semantic inventory strategy')
  }
  for (const pattern of input.includePaths) {
    assertSemanticSelector(pattern, 'include path')
  }
  for (const pattern of input.excludePaths) {
    assertSemanticSelector(pattern, 'exclude path')
  }
  assertUnique(input.includePaths, 'include paths')
  assertUnique(input.excludePaths, 'exclude paths')
  const exclusions = [...input.explicitExclusions].map((row) => {
    assertSemanticSelector(row.pattern, 'explicit exclusion pattern')
    assertIdentityText(row.reason, 'explicit exclusion reason')
    return { pattern: row.pattern, reason: row.reason }
  }).sort((left, right) =>
    utf16Compare(left.pattern, right.pattern) || utf16Compare(left.reason, right.reason)
  )
  assertUnique(exclusions.map((row) => `${row.pattern}\0${row.reason}`), 'explicit exclusions')
  const includePaths = [...input.includePaths].sort(utf16Compare)
  const excludePaths = [...input.excludePaths].sort(utf16Compare)
  return computeAuditCanonicalDigest({
    namespace: 'repo-atlas/codex-semantic-scope/v1',
    mode: input.mode,
    inventoryStrategy: input.inventoryStrategy,
    includePaths,
    excludePaths,
    explicitExclusions: exclusions,
  })
}

export function computeAuditInventoryDigest(
  files: readonly AuditFileReceiptV3[],
): AuditSha256 {
  const rows = [...files].map((file) => {
    const normalized = normalizeAuditRepoPath(file.path)
    assertGitBlob(file.blob, `blob for ${normalized}`)
    if (!['reviewed', 'not-reviewed'].includes(file.status)) {
      throw new Error(`invalid review status for ${normalized}`)
    }
    if (!['clean', 'findings', 'unknown'].includes(file.outcome)) {
      throw new Error(`invalid review outcome for ${normalized}`)
    }
    if (!Array.isArray(file.findingOccurrenceIds)) {
      throw new Error(`finding occurrence IDs for ${normalized} must be an array`)
    }
    const findingOccurrenceIds = [...file.findingOccurrenceIds]
    for (const occurrenceId of findingOccurrenceIds) {
      if (typeof occurrenceId !== 'string' || !OCCURRENCE_ID_RE.test(occurrenceId)) {
        throw new Error(`invalid finding occurrence ID for ${normalized}`)
      }
    }
    assertUnique(findingOccurrenceIds, `finding occurrence IDs for ${normalized}`)
    findingOccurrenceIds.sort(utf16Compare)
    if (!Array.isArray(file.receiptRefs)) {
      throw new Error(`receipt refs for ${normalized} must be an array`)
    }
    const receiptRefs = [...file.receiptRefs]
    for (const receiptRef of receiptRefs) {
      assertIdentityText(receiptRef, `receipt ref for ${normalized}`)
    }
    assertUnique(receiptRefs, `receipt refs for ${normalized}`)
    receiptRefs.sort(utf16Compare)
    return {
      path: normalized,
      blob: file.blob,
      status: file.status,
      outcome: file.outcome,
      findingOccurrenceIds,
      receiptRefs,
    }
  }).sort((left, right) => utf16Compare(left.path, right.path))
  assertUnique(rows.map((row) => row.path), 'inventory file paths')
  return computeAuditCanonicalDigest({
    namespace: 'repo-atlas/exact-inventory/v1',
    files: rows,
  })
}

export function computeAuditScopeHash(input: {
  mode: AuditExactScopeIdentityInput['mode']
  includePaths: readonly string[]
  excludePaths: readonly string[]
  inventoryDigest: AuditSha256
}): AuditSha256 {
  assertSha256(input.inventoryDigest, 'inventoryDigest')
  for (const pattern of input.includePaths) assertPattern(pattern, 'include path')
  for (const pattern of input.excludePaths) assertPattern(pattern, 'exclude path')
  assertUnique(input.includePaths, 'include paths')
  assertUnique(input.excludePaths, 'exclude paths')
  return computeAuditCanonicalDigest({
    namespace: 'repo-atlas/exact-scope-result/v1',
    mode: input.mode,
    includePaths: [...input.includePaths].sort(utf16Compare),
    excludePaths: [...input.excludePaths].sort(utf16Compare),
    inventoryDigest: input.inventoryDigest,
  })
}

export function computeAuditHistoryEntryDigest(
  entry: Omit<AuditObservationHistoryEntryV3, 'entryDigest'>,
): AuditSha256 {
  return computeAuditCanonicalDigest(entry)
}

class AuditValidationFailure extends Error {
  constructor(
    readonly code: string,
    readonly pointer: string,
    message: string,
  ) {
    super(message)
  }
}

function invalid(code: string, pointer: string, message: string): never {
  throw new AuditValidationFailure(code, pointer, message)
}

function recordAt(value: unknown, pointer: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    invalid('invalid-type', pointer, 'must be a JSON object')
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    invalid('invalid-object', pointer, 'must be a data-only JSON object')
  }
  return value as Record<string, unknown>
}

function arrayAt(value: unknown, pointer: string): unknown[] {
  if (!Array.isArray(value)) invalid('invalid-type', pointer, 'must be an array')
  return value
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  pointer: string,
): void {
  const allowed = new Set([...required, ...optional])
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) invalid('unknown-member', `${pointer}/${key}`, 'unknown member')
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) invalid('missing-member', `${pointer}/${key}`, 'required member is missing')
  }
}

function stringAt(value: unknown, pointer: string, nonempty = true): string {
  if (
    typeof value !== 'string' ||
    (nonempty && value.trim().length === 0) ||
    value.length > TEXT_LIMIT ||
    value.includes('\0')
  ) {
    invalid('invalid-string', pointer, 'must be bounded text without NUL')
  }
  return value
}

function sourceCoordinateAt(
  value: unknown,
  pointer: string,
  nonempty = false,
): string {
  if (
    typeof value !== 'string' ||
    (nonempty && PYTHON_WHITESPACE_RE.test(value)) ||
    value.length > TEXT_LIMIT
  ) {
    invalid(
      'invalid-source-coordinate',
      pointer,
      'must be a bounded opaque source coordinate',
    )
  }
  return value
}

function enumAt<T extends string>(
  value: unknown,
  allowed: readonly T[],
  pointer: string,
): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    invalid('invalid-enum', pointer, `must be one of ${allowed.join(', ')}`)
  }
  return value as T
}

function safeIntegerAt(value: unknown, pointer: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    invalid('invalid-integer', pointer, `must be a safe integer >= ${minimum}`)
  }
  return value as number
}

function sha256At(value: unknown, pointer: string): AuditSha256 {
  if (typeof value !== 'string' || !SHA256_RE.test(value)) {
    invalid('invalid-digest', pointer, 'must be a lowercase SHA-256 digest')
  }
  return value as AuditSha256
}

function gitBlobAt(value: unknown, pointer: string): AuditGitBlob {
  if (typeof value !== 'string' || !GIT_BLOB_RE.test(value)) {
    invalid('invalid-blob', pointer, 'must be a canonical Git blob digest')
  }
  return value as AuditGitBlob
}

function timestampAt(value: unknown, pointer: string): string {
  const text = stringAt(value, pointer)
  if (!TIMESTAMP_RE.test(text) || new Date(text).toISOString() !== text) {
    invalid('invalid-timestamp', pointer, 'must be a canonical RFC 3339 timestamp')
  }
  return text
}

function repoPathAt(value: unknown, pointer: string): string {
  const text = stringAt(value, pointer)
  try {
    return normalizeAuditRepoPath(text)
  } catch {
    invalid('invalid-path', pointer, 'must be a normalized repository-relative path')
  }
}

function uniqueStringsAt(value: unknown, pointer: string): string[] {
  const rows = arrayAt(value, pointer).map((row, index) =>
    stringAt(row, `${pointer}/${index}`)
  )
  if (new Set(rows).size !== rows.length) invalid('duplicate', pointer, 'must contain unique values')
  const sorted = [...rows].sort(utf16Compare)
  if (rows.some((row, index) => row !== sorted[index])) {
    invalid('invalid-order', pointer, 'must use deterministic UTF-16 lexical order')
  }
  return rows
}

function rawSha256At(value: unknown, pointer: string): string {
  if (typeof value !== 'string' || !RAW_SHA256_RE.test(value)) {
    invalid('invalid-digest', pointer, 'must be 64 lowercase SHA-256 hex characters')
  }
  return value
}

function booleanAt(value: unknown, pointer: string): boolean {
  if (typeof value !== 'boolean') invalid('invalid-type', pointer, 'must be a boolean')
  return value
}

function strictJsonPointerAt(value: unknown, pointer: string): string {
  const text = stringAt(value, pointer)
  if (!JSON_POINTER_RE.test(text)) {
    invalid('invalid-json-pointer', pointer, 'must be a strict non-root JSON Pointer')
  }
  return text
}

function remoteAt(value: unknown, pointer: string): string {
  const text = stringAt(value, pointer)
  if (/[\u0000-\u001f\u007f\\]/u.test(text)) {
    invalid('invalid-remote', pointer, 'remote URL contains control or backslash ambiguity')
  }
  let parsed: URL
  try {
    parsed = new URL(text)
  } catch {
    invalid('invalid-remote', pointer, 'remote must be a canonical absolute URL')
  }
  if (
    !text.includes('://') ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.search !== '' ||
    parsed.hash !== '' ||
    parsed.hostname === '' ||
    parsed.href !== text
  ) {
    invalid(
      'invalid-remote',
      pointer,
      'remote must be a canonical absolute URL without credentials, query, or fragment',
    )
  }
  return text
}

function extensionJsonValueAt(
  value: unknown,
  pointer: string,
): import('./audit-v3-types.js').AuditJsonValue {
  let members = 0
  const seen = new Set<object>()
  const visit = (
    candidate: unknown,
    candidatePointer: string,
    depth: number,
  ): import('./audit-v3-types.js').AuditJsonValue => {
    if (depth > EXTENSION_DEPTH_LIMIT) {
      invalid('extension-depth-limit', candidatePointer, `exceeds depth ${EXTENSION_DEPTH_LIMIT}`)
    }
    if (
      candidate === null ||
      typeof candidate === 'boolean' ||
      typeof candidate === 'string'
    ) {
      if (typeof candidate === 'string' && candidate.length > TEXT_LIMIT) {
        invalid('extension-string-limit', candidatePointer, 'string is too large')
      }
      return candidate
    }
    if (typeof candidate === 'number') {
      if (
        !Number.isFinite(candidate) ||
        (Number.isInteger(candidate) && !Number.isSafeInteger(candidate))
      ) {
        invalid(
          'invalid-extension-value',
          candidatePointer,
          'number must be finite and integer-valued numbers must be safe integers',
        )
      }
      return candidate
    }
    if (!candidate || typeof candidate !== 'object') {
      invalid('invalid-extension-value', candidatePointer, 'must be data-only JSON')
    }
    if (seen.has(candidate)) {
      invalid('invalid-extension-value', candidatePointer, 'must not contain cycles')
    }
    seen.add(candidate)
    try {
      if (Array.isArray(candidate)) {
        const descriptors = Object.getOwnPropertyDescriptors(candidate)
        if (
          Object.keys(descriptors).some((key) => key !== 'length' && !/^(0|[1-9][0-9]*)$/u.test(key)) ||
          Object.keys(candidate).length !== candidate.length
        ) {
          invalid('invalid-extension-value', candidatePointer, 'array must be dense data-only JSON')
        }
        const rows: import('./audit-v3-types.js').AuditJsonValue[] = []
        for (let index = 0; index < candidate.length; index += 1) {
          const descriptor = descriptors[String(index)]
          if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) {
            invalid('invalid-extension-value', `${candidatePointer}/${index}`, 'array accessors are forbidden')
          }
          members += 1
          if (members > EXTENSION_MEMBER_LIMIT) {
            invalid('extension-member-limit', candidatePointer, `exceeds ${EXTENSION_MEMBER_LIMIT} members`)
          }
          rows.push(visit(descriptor.value, `${candidatePointer}/${index}`, depth + 1))
        }
        return rows
      }
      const prototype = Object.getPrototypeOf(candidate)
      if (prototype !== Object.prototype && prototype !== null) {
        invalid('invalid-extension-value', candidatePointer, 'object must be data-only JSON')
      }
      const descriptors = Object.getOwnPropertyDescriptors(candidate)
      const result: Record<string, import('./audit-v3-types.js').AuditJsonValue> = {}
      for (const key of Object.keys(descriptors).sort(utf16Compare)) {
        const descriptor = descriptors[key]
        if (
          !descriptor.enumerable ||
          !('value' in descriptor) ||
          /[\u0000-\u001f\u007f]/u.test(key) ||
          key === '__proto__' ||
          key === 'constructor' ||
          key === 'prototype'
        ) {
          invalid('invalid-extension-value', candidatePointer, 'object keys must be safe enumerable data properties')
        }
        members += 1
        if (members > EXTENSION_MEMBER_LIMIT) {
          invalid('extension-member-limit', candidatePointer, `exceeds ${EXTENSION_MEMBER_LIMIT} members`)
        }
        result[key] = visit(
          descriptor.value,
          `${candidatePointer}/${key.replace(/~/gu, '~0').replace(/\//gu, '~1')}`,
          depth + 1,
        )
      }
      return result
    } finally {
      seen.delete(candidate)
    }
  }
  const parsed = visit(value, pointer, 0)
  if (Buffer.byteLength(canonicalJson(parsed), 'utf8') > EXTENSION_BYTE_LIMIT) {
    invalid('extension-byte-limit', pointer, `exceeds ${EXTENSION_BYTE_LIMIT} canonical bytes`)
  }
  return parsed
}

function configRepositoryId(root: string): string {
  const config = recordAt(readBoundedAuditJson(root, '.atlas/config.json', 1024 * 1024), '/config')
  const repositoryId = stringAt(config.repositoryId, '/config/repositoryId')
  if (!REPOSITORY_ID_RE.test(repositoryId)) {
    invalid('invalid-repository-id', '/config/repositoryId', 'must be a stable lowercase repo_ identity')
  }
  return repositoryId
}

function gitBlobBytes(
  root: string,
  blob: AuditGitBlob,
  pointer: string,
  context: AuditValidationContext,
): Buffer {
  const cached = context.blobBytes.get(blob)
  if (cached !== undefined) return cached
  let loaded: Uint8Array
  try {
    loaded = readBoundedAuditGitBlob(root, blob)
  } catch (error) {
    if (error instanceof AuditValidationFailure) throw error
    invalid(
      'missing-blob',
      pointer,
      error instanceof Error
        ? `claimed Git blob is unavailable: ${error.message}`
        : 'claimed Git blob is unavailable',
    )
  }
  try {
    context.uniqueBlobBytes = registerAuditUniqueBlobBytes(
      context.uniqueBlobBytes,
      loaded.byteLength,
    )
  } catch (error) {
    invalid(
      'unique-blob-byte-limit',
      pointer,
      error instanceof Error
        ? error.message
        : `unique exact-source blob byte limit of ${AUDIT_V3_UNIQUE_BLOB_BYTE_LIMIT} bytes exceeded`,
    )
  }
  const bytes = Buffer.from(loaded)
  context.blobBytes.set(blob, bytes)
  return bytes
}

function lineCount(bytes: Buffer): number {
  if (bytes.length === 0) return 0
  const text = UTF8.decode(bytes)
  const lines = text.split('\n')
  if (lines.at(-1) === '') lines.pop()
  return lines.length
}

function snippetFromBlob(
  bytes: Buffer,
  startLine: number,
  endLine: number,
  pointer: string,
): string {
  let text: string
  try {
    text = UTF8.decode(bytes)
  } catch {
    invalid('invalid-source-utf8', pointer, 'exact code evidence requires UTF-8 source bytes')
  }
  const lines = text.split('\n')
  if (lines.at(-1) === '') lines.pop()
  if (endLine > lines.length) invalid('invalid-line', pointer, 'line range exceeds the source blob')
  return lines.slice(startLine - 1, endLine).join('\n')
}

function parseProducer(value: unknown, pointer: string): {
  kind: 'grok-cli' | 'codex-security' | 'migration' | 'manual'
  adapter: string
  runId: string
  identityDigest: AuditSha256
  completedAt?: string
  rulesetId?: string
  sourceContract?: {
    manifestPath: 'scan-manifest.json'
    coverageRef: 'coverage.json'
    findingsRef: 'findings.json'
  }
} {
  const producer = recordAt(value, pointer)
  const kind = enumAt(
    producer.kind,
    ['grok-cli', 'codex-security', 'migration', 'manual'] as const,
    `${pointer}/kind`,
  )
  const common = [
    'kind',
    'name',
    'version',
    'adapter',
    'adapterVersion',
    'runId',
    'identityDigest',
    'identityBasis',
  ]
  if (kind === 'codex-security') {
    exactKeys(producer, [...common, 'sourceContract'], [], pointer)
  } else {
    exactKeys(
      producer,
      [...common, 'ruleset'],
      ['prompt', 'effectiveConfigDigest', 'environmentPolicyDigest', 'transcriptDigest'],
      pointer,
    )
  }
  const name = stringAt(producer.name, `${pointer}/name`)
  const version = stringAt(producer.version, `${pointer}/version`)
  const adapter = stringAt(producer.adapter, `${pointer}/adapter`)
  const adapterVersion = stringAt(producer.adapterVersion, `${pointer}/adapterVersion`)
  const runId = stringAt(producer.runId, `${pointer}/runId`)
  const identityDigest = sha256At(producer.identityDigest, `${pointer}/identityDigest`)

  if (kind === 'codex-security') {
    enumAt(producer.identityBasis, ['codex-contract'] as const, `${pointer}/identityBasis`)
    const contract = recordAt(producer.sourceContract, `${pointer}/sourceContract`)
    exactKeys(
      contract,
      [
        'namespace',
        'status',
        'startedAt',
        'completedAt',
        'sealedAt',
        'manifestPath',
        'coverageRef',
        'findingsRef',
      ],
      [],
      `${pointer}/sourceContract`,
    )
    enumAt(contract.namespace, ['codex-security/1.0'] as const, `${pointer}/sourceContract/namespace`)
    enumAt(contract.status, ['completed'] as const, `${pointer}/sourceContract/status`)
    const startedAt = stringAt(contract.startedAt, `${pointer}/sourceContract/startedAt`)
    const completedAt = stringAt(contract.completedAt, `${pointer}/sourceContract/completedAt`)
    const sealedAt = stringAt(contract.sealedAt, `${pointer}/sourceContract/sealedAt`)
    for (const [key, timestamp] of [
      ['startedAt', startedAt],
      ['completedAt', completedAt],
      ['sealedAt', sealedAt],
    ] as const) {
      if (!isStrictRfc3339Timestamp(timestamp)) {
        invalid(
          'invalid-timestamp',
          `${pointer}/sourceContract/${key}`,
          'must be a valid RFC 3339 source timestamp',
        )
      }
    }
    if (sealedAt !== completedAt) {
      invalid(
        'timestamp-mismatch',
        `${pointer}/sourceContract/sealedAt`,
        'must be byte-for-byte equal to completedAt',
      )
    }
    if (contract.manifestPath !== 'scan-manifest.json') {
      invalid('invalid-path', `${pointer}/sourceContract/manifestPath`, 'must equal scan-manifest.json')
    }
    if (contract.coverageRef !== 'coverage.json') {
      invalid(
        'invalid-path',
        `${pointer}/sourceContract/coverageRef`,
        'must equal coverage.json for Codex Security 1.0',
      )
    }
    if (contract.findingsRef !== 'findings.json') {
      invalid(
        'invalid-path',
        `${pointer}/sourceContract/findingsRef`,
        'must equal findings.json for Codex Security 1.0',
      )
    }
    const expectedIdentity = computeAuditCanonicalDigest({
      namespace: 'repo-atlas/codex-contract-identity/v1',
      documents: [
        'codex-security.scan-manifest/1.0',
        'codex-security.findings/1.0',
        'codex-security.coverage/1.0',
      ],
      producer: { name, version },
      adapter: { name: adapter, version: adapterVersion },
    })
    if (identityDigest !== expectedIdentity) {
      invalid(
        'identity-mismatch',
        `${pointer}/identityDigest`,
        'does not match the Codex contract identity',
      )
    }
    return {
      kind,
      adapter,
      runId,
      identityDigest,
      completedAt: new Date(completedAt).toISOString(),
      sourceContract: {
        manifestPath: 'scan-manifest.json',
        coverageRef: 'coverage.json',
        findingsRef: 'findings.json',
      },
    }
  }

  enumAt(producer.identityBasis, ['ruleset'] as const, `${pointer}/identityBasis`)
  const ruleset = recordAt(producer.ruleset, `${pointer}/ruleset`)
  exactKeys(ruleset, ['id', 'digest'], [], `${pointer}/ruleset`)
  const rulesetId = stringAt(ruleset.id, `${pointer}/ruleset/id`)
  const rulesetDigest = sha256At(ruleset.digest, `${pointer}/ruleset/digest`)
  if (identityDigest !== rulesetDigest) {
    invalid('identity-mismatch', `${pointer}/identityDigest`, 'must equal ruleset.digest')
  }
  for (const key of ['effectiveConfigDigest', 'environmentPolicyDigest', 'transcriptDigest']) {
    if (producer[key] !== undefined) sha256At(producer[key], `${pointer}/${key}`)
  }
  if (producer.prompt !== undefined) {
    const prompt = recordAt(producer.prompt, `${pointer}/prompt`)
    exactKeys(
      prompt,
      ['builtinVersion', 'digest'],
      ['extraPath', 'extraDigest'],
      `${pointer}/prompt`,
    )
    stringAt(prompt.builtinVersion, `${pointer}/prompt/builtinVersion`)
    sha256At(prompt.digest, `${pointer}/prompt/digest`)
    const hasPath = Object.hasOwn(prompt, 'extraPath')
    const hasDigest = Object.hasOwn(prompt, 'extraDigest')
    if (hasPath !== hasDigest) {
      invalid('variant-mismatch', `${pointer}/prompt`, 'extraPath and extraDigest must appear together')
    }
    if (hasPath) {
      repoPathAt(prompt.extraPath, `${pointer}/prompt/extraPath`)
      sha256At(prompt.extraDigest, `${pointer}/prompt/extraDigest`)
    }
  }
  return { kind, adapter, runId, identityDigest, rulesetId }
}

function parseTarget(
  root: string,
  producerKind: 'grok-cli' | 'codex-security' | 'migration' | 'manual',
  value: unknown,
  pointer: string,
): {
  repositoryId: string
  targetId: string
  identityDigest: AuditSha256
} {
  const target = recordAt(value, pointer)
  const kind = enumAt(
    target.kind,
    ['git-revision', 'git-worktree', 'git-diff', 'directory-snapshot'] as const,
    `${pointer}/kind`,
  )
  const common = [
    'kind',
    'repositoryId',
    'targetId',
    'identityDigest',
    'identityBasis',
  ]
  const metadata = ['displayName', 'remote']
  if (producerKind === 'codex-security') {
    const requiredByKind: Record<typeof kind, string[]> = {
      'git-revision': ['sourceRevision'],
      'git-worktree': [],
      'git-diff': [],
      'directory-snapshot': [],
    }
    const optionalByKind: Record<typeof kind, string[]> = {
      'git-revision': ['sourceBaseRevision', 'sourceHeadRevision'],
      'git-worktree': [
        'sourceRevision',
        'sourceBaseRevision',
        'sourceHeadRevision',
      ],
      'git-diff': [
        'sourceRevision',
        'sourceBaseRevision',
        'sourceHeadRevision',
      ],
      'directory-snapshot': [
        'sourceRevision',
        'sourceBaseRevision',
        'sourceHeadRevision',
      ],
    }
    const basis = enumAt(
      target.identityBasis,
      ['revision-coordinate', 'snapshot'] as const,
      `${pointer}/identityBasis`,
    )
    exactKeys(
      target,
      [...common, 'displayName', 'sourceKind', ...requiredByKind[kind], ...(basis === 'snapshot'
        ? ['snapshotDigest', 'sourceSnapshotDigest']
        : [])],
      ['remote', ...optionalByKind[kind]],
      pointer,
    )
  } else {
    const requiredByKind: Record<typeof kind, string[]> = {
      'git-revision': ['revision', 'dirty'],
      'git-worktree': ['dirty'],
      'git-diff': ['baseRevision', 'headRevision', 'dirty'],
      'directory-snapshot': [],
    }
    exactKeys(
      target,
      [...common, 'snapshotDigest', ...requiredByKind[kind]],
      [...metadata, ...(kind === 'git-worktree' ? ['revision'] : [])],
      pointer,
    )
  }
  const repositoryId = stringAt(target.repositoryId, `${pointer}/repositoryId`)
  if (!REPOSITORY_ID_RE.test(repositoryId) || repositoryId !== configRepositoryId(root)) {
    invalid('repository-identity-mismatch', `${pointer}/repositoryId`, 'does not match committed repository identity')
  }
  const targetId = stringAt(target.targetId, `${pointer}/targetId`)
  const identityDigest = sha256At(target.identityDigest, `${pointer}/identityDigest`)
  if (producerKind === 'codex-security') {
    stringAt(target.displayName, `${pointer}/displayName`)
  } else if (target.displayName !== undefined) {
    stringAt(target.displayName, `${pointer}/displayName`)
  }
  if (target.remote !== undefined) remoteAt(target.remote, `${pointer}/remote`)

  if (producerKind === 'codex-security') {
    const sourceKind = enumAt(
      target.sourceKind,
      ['git_revision', 'git_worktree', 'git_diff', 'directory_snapshot'] as const,
      `${pointer}/sourceKind`,
    )
    const expectedKind = {
      git_revision: 'git-revision',
      git_worktree: 'git-worktree',
      git_diff: 'git-diff',
      directory_snapshot: 'directory-snapshot',
    }[sourceKind]
    if (kind !== expectedKind) {
      invalid('variant-mismatch', `${pointer}/kind`, 'does not match sourceKind')
    }
    for (const key of ['sourceRevision', 'sourceBaseRevision', 'sourceHeadRevision']) {
      if (target[key] !== undefined) {
        sourceCoordinateAt(
          target[key],
          `${pointer}/${key}`,
          key === 'sourceRevision' && kind === 'git-revision',
        )
      }
    }
    const basis = enumAt(
      target.identityBasis,
      ['revision-coordinate', 'snapshot'] as const,
      `${pointer}/identityBasis`,
    )
    if (kind !== 'git-revision' && basis !== 'snapshot') {
      invalid(
        'target-basis-mismatch',
        `${pointer}/identityBasis`,
        'completed Codex worktree, diff, and directory targets require snapshot identity',
      )
    }
    if (basis === 'snapshot') {
      const sourceSnapshot = stringAt(
        target.sourceSnapshotDigest,
        `${pointer}/sourceSnapshotDigest`,
      )
      const sourceMatch =
        /^codex-security-snapshot\/v1:(sha256:[0-9a-f]{64})$/u.exec(sourceSnapshot)
      if (!sourceMatch) {
        invalid(
          'invalid-digest',
          `${pointer}/sourceSnapshotDigest`,
          'must be a Codex Security snapshot digest',
        )
      }
      const snapshotDigest = sha256At(target.snapshotDigest, `${pointer}/snapshotDigest`)
      if (snapshotDigest !== sourceMatch[1] || identityDigest !== snapshotDigest) {
        invalid(
          'identity-mismatch',
          `${pointer}/identityDigest`,
          'snapshot identity must equal the normalized source snapshot digest',
        )
      }
    } else {
      const identityMaterial: Record<string, string> = {
        namespace: 'repo-atlas/revision-coordinate/v1',
        sourceKind,
        targetId,
      }
      for (const key of ['sourceRevision', 'sourceBaseRevision', 'sourceHeadRevision']) {
        if (typeof target[key] === 'string') identityMaterial[key] = target[key]
      }
      const expectedIdentity = computeAuditCanonicalDigest(identityMaterial)
      if (identityDigest !== expectedIdentity) {
        invalid(
          'identity-mismatch',
          `${pointer}/identityDigest`,
          'does not match the source revision-coordinate identity',
        )
      }
    }
    return { repositoryId, targetId, identityDigest }
  }

  enumAt(target.identityBasis, ['snapshot'] as const, `${pointer}/identityBasis`)
  const snapshotDigest = sha256At(target.snapshotDigest, `${pointer}/snapshotDigest`)
  if (identityDigest !== snapshotDigest) {
    invalid('identity-mismatch', `${pointer}/identityDigest`, 'must equal snapshotDigest')
  }
  if (kind === 'directory-snapshot') return { repositoryId, targetId, identityDigest }
  const dirty = booleanAt(target.dirty, `${pointer}/dirty`)
  if (kind === 'git-revision') {
    if (dirty) invalid('invalid-dirty-claim', `${pointer}/dirty`, 'git revision must be clean')
    const revision = stringAt(target.revision, `${pointer}/revision`)
    if (!FULL_GIT_REVISION_RE.test(revision)) {
      invalid('invalid-revision', `${pointer}/revision`, 'must be a full Git object ID')
    }
  } else if (kind === 'git-worktree') {
    if (target.revision === undefined) {
      if (!dirty) {
        invalid('missing-member', `${pointer}/revision`, 'clean worktree revision is required')
      }
    } else {
      const revision = stringAt(target.revision, `${pointer}/revision`)
      if (!FULL_GIT_REVISION_RE.test(revision)) {
        invalid('invalid-revision', `${pointer}/revision`, 'must be a full Git object ID')
      }
    }
  } else {
    if (dirty) invalid('invalid-dirty-claim', `${pointer}/dirty`, 'git diff must be clean')
    for (const key of ['baseRevision', 'headRevision']) {
      const revision = stringAt(target[key], `${pointer}/${key}`)
      if (!FULL_GIT_REVISION_RE.test(revision)) {
        invalid('invalid-revision', `${pointer}/${key}`, 'must be a full Git object ID')
      }
    }
  }
  return { repositoryId, targetId, identityDigest }
}

function parseFileReceipt(
  root: string,
  value: unknown,
  pointer: string,
  context: AuditValidationContext,
): { receipt: AuditFileReceiptV3; bytes: Buffer } {
  const file = recordAt(value, pointer)
  exactKeys(
    file,
    ['path', 'blob', 'lines', 'status', 'outcome', 'findingOccurrenceIds', 'receiptRefs'],
    ['reviewedAt', 'reviewedAtPrecision', 'reviewedBy', 'ruleset'],
    pointer,
  )
  const repoPath = repoPathAt(file.path, `${pointer}/path`)
  const blob = gitBlobAt(file.blob, `${pointer}/blob`)
  const bytes = gitBlobBytes(root, blob, `${pointer}/blob`, context)
  const lines = safeIntegerAt(file.lines, `${pointer}/lines`)
  if (lines !== lineCount(bytes)) {
    invalid('line-count-mismatch', `${pointer}/lines`, 'does not match the exact Git blob')
  }
  const status = enumAt(file.status, ['reviewed', 'not-reviewed'] as const, `${pointer}/status`)
  const outcome = enumAt(file.outcome, ['clean', 'findings', 'unknown'] as const, `${pointer}/outcome`)
  const findingOccurrenceIds = uniqueStringsAt(
    file.findingOccurrenceIds,
    `${pointer}/findingOccurrenceIds`,
  )
  for (const [index, id] of findingOccurrenceIds.entries()) {
    if (!OCCURRENCE_ID_RE.test(id)) {
      invalid('invalid-occurrence-id', `${pointer}/findingOccurrenceIds/${index}`, 'must be an Atlas occurrence ID')
    }
  }
  const receiptRefs = uniqueStringsAt(file.receiptRefs, `${pointer}/receiptRefs`)
  const hasReviewedAt = Object.hasOwn(file, 'reviewedAt')
  const hasPrecision = Object.hasOwn(file, 'reviewedAtPrecision')
  if (hasReviewedAt !== hasPrecision) {
    invalid('precision-mismatch', pointer, 'reviewedAt and reviewedAtPrecision must appear together')
  }
  if (hasReviewedAt) {
    const reviewedAt = timestampAt(file.reviewedAt, `${pointer}/reviewedAt`)
    const precision = enumAt(
      file.reviewedAtPrecision,
      ['timestamp', 'date'] as const,
      `${pointer}/reviewedAtPrecision`,
    )
    if (precision === 'date' && !reviewedAt.endsWith('T00:00:00.000Z')) {
      invalid('precision-mismatch', `${pointer}/reviewedAt`, 'date precision requires midnight UTC')
    }
  }
  if (file.reviewedBy !== undefined) stringAt(file.reviewedBy, `${pointer}/reviewedBy`)
  if (file.ruleset !== undefined) stringAt(file.ruleset, `${pointer}/ruleset`)
  return {
    receipt: file as unknown as AuditFileReceiptV3,
    bytes,
  }
}

function parseExplicitExclusions(
  value: unknown,
  pointer: string,
): Array<{ pattern: string; reason: string }> {
  const rows = arrayAt(value, pointer)
  const parsed = rows.map((row, index) => {
    const itemPointer = `${pointer}/${index}`
    const item = recordAt(row, itemPointer)
    exactKeys(item, ['pattern', 'reason'], [], itemPointer)
    const pattern = stringAt(item.pattern, `${itemPointer}/pattern`)
    try {
      assertSemanticSelector(pattern, 'explicit exclusion')
    } catch (error) {
      invalid(
        'invalid-path',
        `${itemPointer}/pattern`,
        error instanceof Error ? error.message : String(error),
      )
    }
    return {
      pattern,
      reason: stringAt(item.reason, `${itemPointer}/reason`),
    }
  })
  const keys = parsed.map((row) => `${row.pattern}\0${row.reason}`)
  if (new Set(keys).size !== keys.length) {
    invalid('duplicate', pointer, 'must contain unique exclusions')
  }
  const sorted = [...keys].sort(utf16Compare)
  if (keys.some((key, index) => key !== sorted[index])) {
    invalid('invalid-order', pointer, 'must use deterministic UTF-16 lexical order')
  }
  return parsed
}

function parseSemanticCoverage(
  value: unknown,
  pointer: string,
): {
  mode: import('./audit-v3-types.js').AuditSemanticMode
  completeness: 'complete' | 'partial' | 'unknown'
  inventoryStrategy: import('./audit-v3-types.js').AuditInventoryStrategy
  explicitExclusions: Array<{ pattern: string; reason: string }>
  findingRefs: string[]
} {
  const coverage = recordAt(value, pointer)
  exactKeys(
    coverage,
    [
      'mode',
      'completeness',
      'inventoryStrategy',
      'surfaces',
      'explicitExclusions',
      'deferred',
    ],
    ['openQuestions'],
    pointer,
  )
  const mode = enumAt(
    coverage.mode,
    ['repository', 'scoped_path', 'diff', 'commit', 'branch_diff', 'working_tree', 'deep_repository', 'unit', 'custom'] as const,
    `${pointer}/mode`,
  )
  const completeness = enumAt(
    coverage.completeness,
    ['complete', 'partial', 'unknown'] as const,
    `${pointer}/completeness`,
  )
  const inventoryStrategy = enumAt(
    coverage.inventoryStrategy,
    ['repository', 'scoped_path', 'diff', 'directory', 'custom', 'unit'] as const,
    `${pointer}/inventoryStrategy`,
  )
  const explicitExclusions = parseExplicitExclusions(
    coverage.explicitExclusions,
    `${pointer}/explicitExclusions`,
  )
  const surfaces = arrayAt(coverage.surfaces, `${pointer}/surfaces`)
  const surfaceIds = new Set<string>()
  const findingRefs: string[] = []
  let needsFollowUp = false
  for (const [index, row] of surfaces.entries()) {
    const itemPointer = `${pointer}/surfaces/${index}`
    const surface = recordAt(row, itemPointer)
    exactKeys(
      surface,
      ['id', 'label', 'disposition', 'receiptRefs'],
      ['riskArea', 'notes'],
      itemPointer,
    )
    const id = stringAt(surface.id, `${itemPointer}/id`)
    if (surfaceIds.has(id)) invalid('duplicate', `${itemPointer}/id`, 'duplicate semantic surface ID')
    surfaceIds.add(id)
    stringAt(surface.label, `${itemPointer}/label`)
    const disposition = enumAt(
      surface.disposition,
      ['reported', 'no_issue_found', 'rejected', 'not_applicable', 'needs_follow_up'] as const,
      `${itemPointer}/disposition`,
    )
    needsFollowUp ||= disposition === 'needs_follow_up'
    const receiptRefs = uniqueStringsAt(surface.receiptRefs, `${itemPointer}/receiptRefs`)
    findingRefs.push(...receiptRefs.filter((ref) => ref.startsWith('finding:')))
    if (surface.riskArea !== undefined) stringAt(surface.riskArea, `${itemPointer}/riskArea`)
    if (surface.notes !== undefined) stringAt(surface.notes, `${itemPointer}/notes`)
  }
  const deferred = arrayAt(coverage.deferred, `${pointer}/deferred`)
  const deferredIds = new Set<string>()
  for (const [index, row] of deferred.entries()) {
    const itemPointer = `${pointer}/deferred/${index}`
    const item = recordAt(row, itemPointer)
    exactKeys(item, ['id', 'reason'], ['paths', 'surfaceIds'], itemPointer)
    const id = stringAt(item.id, `${itemPointer}/id`)
    if (deferredIds.has(id)) invalid('duplicate', `${itemPointer}/id`, 'duplicate deferred ID')
    deferredIds.add(id)
    stringAt(item.reason, `${itemPointer}/reason`)
    if (item.paths !== undefined) {
      const paths = uniqueStringsAt(item.paths, `${itemPointer}/paths`)
      for (const [pathIndex, candidate] of paths.entries()) {
        repoPathAt(candidate, `${itemPointer}/paths/${pathIndex}`)
      }
    }
    if (item.surfaceIds !== undefined) {
      const ids = uniqueStringsAt(item.surfaceIds, `${itemPointer}/surfaceIds`)
      for (const [surfaceIndex, surfaceId] of ids.entries()) {
        if (!surfaceIds.has(surfaceId)) {
          invalid(
            'unknown-reference',
            `${itemPointer}/surfaceIds/${surfaceIndex}`,
            'must reference a semantic surface',
          )
        }
      }
    }
  }
  const openQuestions = coverage.openQuestions === undefined
    ? []
    : arrayAt(coverage.openQuestions, `${pointer}/openQuestions`)
  for (const [index, row] of openQuestions.entries()) {
    const itemPointer = `${pointer}/openQuestions/${index}`
    const item = recordAt(row, itemPointer)
    exactKeys(item, ['question'], ['followUpPrompt'], itemPointer)
    stringAt(item.question, `${itemPointer}/question`)
    if (item.followUpPrompt !== undefined) {
      stringAt(item.followUpPrompt, `${itemPointer}/followUpPrompt`)
    }
  }
  if (completeness === 'complete' && (deferred.length !== 0 || needsFollowUp)) {
    invalid(
      'semantic-coverage-closure',
      pointer,
      'complete semantic coverage forbids deferred work and needs_follow_up surfaces',
    )
  }
  return { mode, completeness, inventoryStrategy, explicitExclusions, findingRefs }
}

function parseThreatModel(value: unknown, pointer: string): void {
  const model = recordAt(value, pointer)
  exactKeys(
    model,
    ['summary'],
    [
      'assets',
      'trustBoundaries',
      'attackerCapabilities',
      'securityObjectives',
      'assumptions',
    ],
    pointer,
  )
  stringAt(model.summary, `${pointer}/summary`)
  for (const key of [
    'assets',
    'trustBoundaries',
    'attackerCapabilities',
    'securityObjectives',
    'assumptions',
  ]) {
    if (model[key] !== undefined) {
      uniqueStringsAt(model[key], `${pointer}/${key}`)
    }
  }
}

interface ParsedSourceArtifact {
  path: string
  sha256: string
  integrityKind: 'producer-manifest' | 'adapter-bundle'
  integrityIndex?: string
  mediaType: string
  referencedBy: string[]
  retainedInAtlas: boolean
}

function parseSourceArtifacts(
  value: unknown,
  pointer: string,
): Map<string, ParsedSourceArtifact> {
  const rows = arrayAt(value, pointer)
  const artifacts = new Map<string, ParsedSourceArtifact>()
  let previousPath: string | undefined
  for (const [index, row] of rows.entries()) {
    const itemPointer = `${pointer}/${index}`
    const artifact = recordAt(row, itemPointer)
    const integrityKind = enumAt(
      artifact.integrityKind,
      ['producer-manifest', 'adapter-bundle'] as const,
      `${itemPointer}/integrityKind`,
    )
    exactKeys(
      artifact,
      [
        'path',
        'sha256',
        'mediaType',
        'integrityKind',
        'referencedBy',
        'retainedInAtlas',
        ...(integrityKind === 'producer-manifest' ? ['integrityIndex'] : []),
      ],
      [],
      itemPointer,
    )
    const artifactPath = repoPathAt(artifact.path, `${itemPointer}/path`)
    if (previousPath !== undefined && utf16Compare(previousPath, artifactPath) >= 0) {
      invalid('invalid-order', `${itemPointer}/path`, 'source artifacts must be uniquely sorted by path')
    }
    previousPath = artifactPath
    const sha256 = rawSha256At(artifact.sha256, `${itemPointer}/sha256`)
    const mediaType = stringAt(artifact.mediaType, `${itemPointer}/mediaType`)
    const referencedBy = uniqueStringsAt(artifact.referencedBy, `${itemPointer}/referencedBy`)
    for (const [refIndex, ref] of referencedBy.entries()) {
      strictJsonPointerAt(ref, `${itemPointer}/referencedBy/${refIndex}`)
    }
    const retainedInAtlas = booleanAt(
      artifact.retainedInAtlas,
      `${itemPointer}/retainedInAtlas`,
    )
    const integrityIndex = integrityKind === 'producer-manifest'
      ? repoPathAt(artifact.integrityIndex, `${itemPointer}/integrityIndex`)
      : undefined
    artifacts.set(artifactPath, {
      path: artifactPath,
      sha256,
      integrityKind,
      ...(integrityIndex === undefined ? {} : { integrityIndex }),
      mediaType,
      referencedBy,
      retainedInAtlas,
    })
  }
  return artifacts
}

function resolveObservationPointer(
  observation: Record<string, unknown>,
  jsonPointer: string,
): unknown {
  let current: unknown = observation
  for (const encoded of jsonPointer.slice(1).split('/')) {
    const token = encoded.replaceAll('~1', '/').replaceAll('~0', '~')
    if (Array.isArray(current)) {
      if (!/^(?:0|[1-9]\d*)$/u.test(token)) {
        invalid('artifact-backlink-mismatch', jsonPointer, 'does not resolve to an array member')
      }
      const index = Number(token)
      if (!Number.isSafeInteger(index) || index >= current.length) {
        invalid('artifact-backlink-mismatch', jsonPointer, 'does not resolve in the observation')
      }
      current = current[index]
      continue
    }
    if (
      current === null ||
      typeof current !== 'object' ||
      !Object.hasOwn(current, token)
    ) {
      invalid('artifact-backlink-mismatch', jsonPointer, 'does not resolve in the observation')
    }
    current = (current as Record<string, unknown>)[token]
  }
  return current
}

function validateCodexArtifactJoins(
  observation: Record<string, unknown>,
  artifacts: ReadonlyMap<string, ParsedSourceArtifact>,
): void {
  const required: Array<{
    path: string
    pointer: string
    integrityKind?: 'producer-manifest' | 'adapter-bundle'
    mediaType?: string
  }> = [
    {
      path: 'scan-manifest.json',
      pointer: '/producer/sourceContract/manifestPath',
      integrityKind: 'adapter-bundle',
      mediaType: 'application/json',
    },
    {
      path: 'coverage.json',
      pointer: '/producer/sourceContract/coverageRef',
      integrityKind: 'producer-manifest',
      mediaType: 'application/json',
    },
    {
      path: 'findings.json',
      pointer: '/producer/sourceContract/findingsRef',
      integrityKind: 'producer-manifest',
      mediaType: 'application/json',
    },
  ]

  const hardening = observation.hardening as
    | { portfolio: Record<string, unknown> }
    | undefined
  if (hardening !== undefined) {
    required.push({
      path: hardening.portfolio.sourceArtifactPath as string,
      pointer: '/hardening/portfolio/sourceArtifactPath',
      integrityKind: hardening.portfolio.integrityKind as
        | 'producer-manifest'
        | 'adapter-bundle',
      mediaType: hardening.portfolio.mediaType as string,
    })
  }

  const coverage = observation.semanticCoverage as Record<string, unknown>
  for (const [surfaceIndex, candidate] of (
    coverage.surfaces as Array<Record<string, unknown>>
  ).entries()) {
    for (const [refIndex, value] of (candidate.receiptRefs as string[]).entries()) {
      if (!value.startsWith('artifacts/')) {
        invalid(
          'invalid-reference',
          `/semanticCoverage/surfaces/${surfaceIndex}/receiptRefs/${refIndex}`,
          'Codex coverage receipt references must be artifact paths',
        )
      }
      required.push({
        path: value,
        pointer: `/semanticCoverage/surfaces/${surfaceIndex}/receiptRefs/${refIndex}`,
        integrityKind: 'producer-manifest',
      })
    }
  }

  for (const [findingIndex, candidate] of (
    observation.findings as Array<Record<string, unknown>>
  ).entries()) {
    const codeEvidence = candidate.codeEvidence as
      | Array<Record<string, unknown>>
      | undefined
    for (const [evidenceIndex, evidence] of (codeEvidence ?? []).entries()) {
      if (evidence.evidenceBasis !== 'sealed-producer-snippet') continue
      const sourceSeal = evidence.sourceSeal as Record<string, unknown>
      required.push({
        path: sourceSeal.artifactPath as string,
        pointer:
          `/findings/${findingIndex}/codeEvidence/${evidenceIndex}/sourceSeal/artifactPath`,
        integrityKind: 'producer-manifest',
      })
    }
    const artifactRefs = candidate.artifactRefs as
      | Array<Record<string, unknown>>
      | undefined
    for (const [artifactIndex, artifactRef] of (artifactRefs ?? []).entries()) {
      required.push({
        path: artifactRef.sourceArtifactPath as string,
        pointer:
          `/findings/${findingIndex}/artifactRefs/${artifactIndex}/sourceArtifactPath`,
        integrityKind: artifactRef.integrityKind as
          | 'producer-manifest'
          | 'adapter-bundle',
      })
    }
    const validation = candidate.validation as Record<string, unknown> | null | undefined
    if (validation?.artifactRefs !== undefined) {
      for (const [artifactIndex, artifactPath] of (
        validation.artifactRefs as string[]
      ).entries()) {
        required.push({
          path: artifactPath,
          pointer:
            `/findings/${findingIndex}/validation/artifactRefs/${artifactIndex}`,
        })
      }
    }
  }

  const forwardReferences = new Set(
    required.map((reference) => `${reference.path}\0${reference.pointer}`),
  )
  for (const artifact of artifacts.values()) {
    if (
      artifact.integrityKind === 'producer-manifest' &&
      artifact.integrityIndex !== 'scan-manifest.json'
    ) {
      invalid(
        'artifact-integrity-mismatch',
        '/sourceArtifacts',
        `${artifact.path} must be indexed by scan-manifest.json`,
      )
    }
    for (const backlink of artifact.referencedBy) {
      if (!forwardReferences.has(`${artifact.path}\0${backlink}`)) {
        invalid(
          'artifact-backlink-mismatch',
          '/sourceArtifacts',
          `${backlink} is not a recognized forward artifact reference`,
        )
      }
      if (resolveObservationPointer(observation, backlink) !== artifact.path) {
        invalid(
          'artifact-backlink-mismatch',
          '/sourceArtifacts',
          `${backlink} must resolve to the exact artifact path ${artifact.path}`,
        )
      }
    }
  }

  for (const reference of required) {
    const artifact = artifacts.get(reference.path)
    if (
      !artifact ||
      (
        reference.integrityKind !== undefined &&
        artifact.integrityKind !== reference.integrityKind
      ) ||
      (
        reference.mediaType !== undefined &&
        artifact?.mediaType !== reference.mediaType
      )
    ) {
      invalid(
        'artifact-reference-mismatch',
        reference.pointer,
        `must resolve to a ${reference.integrityKind ?? 'source'} artifact`,
      )
    }
    if (!artifact.referencedBy.includes(reference.pointer)) {
      invalid(
        'artifact-backlink-mismatch',
        reference.pointer,
        'source artifact must contain the exact leaf backlink',
      )
    }
  }
}

function parseExtensions(
  value: unknown,
  pointer: string,
  codexSource: boolean,
  keys = new Set<string>(),
): void {
  const rows = arrayAt(value, pointer)
  for (const [index, row] of rows.entries()) {
    const itemPointer = `${pointer}/${index}`
    const extension = recordAt(row, itemPointer)
    exactKeys(extension, ['namespace', 'path', 'value', 'digest'], [], itemPointer)
    const namespace = stringAt(extension.namespace, `${itemPointer}/namespace`)
    if (!EXTENSION_NAMESPACE_RE.test(namespace)) {
      invalid('invalid-extension-namespace', `${itemPointer}/namespace`, 'must be a lowercase contract namespace')
    }
    if (
      codexSource &&
      ![
        'codex-security.scan-manifest/1.0',
        'codex-security.findings/1.0',
        'codex-security.coverage/1.0',
      ].includes(namespace)
    ) {
      invalid(
        'invalid-extension-namespace',
        `${itemPointer}/namespace`,
        'Codex source extensions require a document-specific namespace',
      )
    }
    const jsonPointer = strictJsonPointerAt(extension.path, `${itemPointer}/path`)
    const key = `${namespace}\0${jsonPointer}`
    if (keys.has(key)) invalid('duplicate', itemPointer, 'duplicate extension namespace/path')
    keys.add(key)
    const extensionValue = extensionJsonValueAt(extension.value, `${itemPointer}/value`)
    const digest = sha256At(extension.digest, `${itemPointer}/digest`)
    if (digest !== computeAuditCanonicalDigest(extensionValue)) {
      invalid('extension-digest-mismatch', `${itemPointer}/digest`, 'does not seal extension value')
    }
  }
}

function parseDocumentedJsonArray(value: unknown, pointer: string): void {
  if (!Array.isArray(extensionJsonValueAt(value, pointer))) {
    invalid('invalid-type', pointer, 'must be a data-only JSON array')
  }
}

function parseValidation(
  value: unknown,
  pointer: string,
  evidenceIds: ReadonlySet<string>,
  artifacts: ReadonlyMap<string, ParsedSourceArtifact>,
): void {
  if (value === null) return
  const validation = recordAt(value, pointer)
  exactKeys(
    validation,
    [],
    [
      'method',
      'disposition',
      'summary',
      'confidence',
      'confidenceRationale',
      'evidenceRefs',
      'assertions',
      'evidence',
      'counterevidenceOrProofGap',
      'remainingUncertainty',
      'limitations',
      'artifactRefs',
    ],
    pointer,
  )
  for (const key of ['method', 'summary', 'confidenceRationale']) {
    if (validation[key] !== undefined) stringAt(validation[key], `${pointer}/${key}`)
  }
  if (validation.disposition !== undefined) {
    enumAt(
      validation.disposition,
      ['reportable', 'suppressed', 'not_applicable', 'deferred'] as const,
      `${pointer}/disposition`,
    )
  }
  if (validation.confidence !== undefined) {
    enumAt(validation.confidence, ['high', 'medium', 'low'] as const, `${pointer}/confidence`)
  }
  if (validation.evidenceRefs !== undefined) {
    const refs = uniqueStringsAt(validation.evidenceRefs, `${pointer}/evidenceRefs`)
    for (const [index, ref] of refs.entries()) {
      if (!evidenceIds.has(ref)) {
        invalid('unknown-reference', `${pointer}/evidenceRefs/${index}`, 'must reference code evidence')
      }
    }
  }
  for (const key of [
    'assertions',
    'evidence',
    'counterevidenceOrProofGap',
    'remainingUncertainty',
    'limitations',
  ]) {
    if (validation[key] !== undefined) {
      parseDocumentedJsonArray(validation[key], `${pointer}/${key}`)
    }
  }
  if (validation.artifactRefs !== undefined) {
    const refs = uniqueStringsAt(validation.artifactRefs, `${pointer}/artifactRefs`)
    for (const [index, ref] of refs.entries()) {
      const artifactPath = repoPathAt(ref, `${pointer}/artifactRefs/${index}`)
      if (!artifacts.has(artifactPath)) {
        invalid('unknown-reference', `${pointer}/artifactRefs/${index}`, 'must reference a source artifact')
      }
    }
  }
}

function parseAttackPath(
  value: unknown,
  pointer: string,
  evidenceIds: ReadonlySet<string>,
): void {
  if (value === null) return
  const attack = recordAt(value, pointer)
  exactKeys(
    attack,
    [],
    [
      'summary',
      'dataflow',
      'reachability',
      'impact',
      'likelihood',
      'evidenceRefs',
      'limitations',
    ],
    pointer,
  )
  if (attack.summary !== undefined) stringAt(attack.summary, `${pointer}/summary`)
  if (attack.dataflow !== undefined) {
    const dataflow = recordAt(attack.dataflow, `${pointer}/dataflow`)
    exactKeys(
      dataflow,
      [],
      ['summary', 'source', 'transformations', 'sink', 'outcome', 'evidenceRefs'],
      `${pointer}/dataflow`,
    )
    for (const key of ['summary', 'source', 'sink', 'outcome']) {
      if (dataflow[key] !== undefined) {
        stringAt(dataflow[key], `${pointer}/dataflow/${key}`)
      }
    }
    if (dataflow.transformations !== undefined) {
      parseDocumentedJsonArray(
        dataflow.transformations,
        `${pointer}/dataflow/transformations`,
      )
    }
    if (dataflow.evidenceRefs !== undefined) {
      const refs = uniqueStringsAt(
        dataflow.evidenceRefs,
        `${pointer}/dataflow/evidenceRefs`,
      )
      for (const [index, ref] of refs.entries()) {
        if (!evidenceIds.has(ref)) {
          invalid(
            'unknown-reference',
            `${pointer}/dataflow/evidenceRefs/${index}`,
            'must reference code evidence',
          )
        }
      }
    }
  }
  if (attack.reachability !== undefined) {
    const reachability = recordAt(attack.reachability, `${pointer}/reachability`)
    exactKeys(
      reachability,
      [],
      [
        'summary',
        'attacker',
        'entrypoint',
        'accessRequirements',
        'preconditions',
        'outcome',
      ],
      `${pointer}/reachability`,
    )
    for (const key of ['summary', 'attacker', 'entrypoint', 'outcome']) {
      if (reachability[key] !== undefined) {
        stringAt(reachability[key], `${pointer}/reachability/${key}`)
      }
    }
    for (const key of ['accessRequirements', 'preconditions']) {
      if (reachability[key] !== undefined) {
        parseDocumentedJsonArray(reachability[key], `${pointer}/reachability/${key}`)
      }
    }
  }
  for (const [key, levels] of [
    ['impact', ['critical', 'high', 'medium', 'low', 'informational']],
    ['likelihood', ['high', 'medium', 'low']],
  ] as const) {
    if (attack[key] === undefined) continue
    const rating = recordAt(attack[key], `${pointer}/${key}`)
    exactKeys(rating, ['level'], ['why'], `${pointer}/${key}`)
    enumAt(rating.level, levels, `${pointer}/${key}/level`)
    if (rating.why !== undefined) stringAt(rating.why, `${pointer}/${key}/why`)
  }
  if (attack.evidenceRefs !== undefined) {
    const refs = uniqueStringsAt(attack.evidenceRefs, `${pointer}/evidenceRefs`)
    for (const [index, ref] of refs.entries()) {
      if (!evidenceIds.has(ref)) {
        invalid('unknown-reference', `${pointer}/evidenceRefs/${index}`, 'must reference code evidence')
      }
    }
  }
  if (attack.limitations !== undefined) {
    parseDocumentedJsonArray(attack.limitations, `${pointer}/limitations`)
  }
}

function parseFinding(
  root: string,
  findingIndex: number,
  observationId: AtlasObservationId,
  repositoryId: string,
  targetId: string,
  producerKind: 'grok-cli' | 'codex-security' | 'migration' | 'manual',
  producerRunId: string,
  exactInventory: boolean,
  value: unknown,
  pointer: string,
  fileByPath: Map<string, { receipt: AuditFileReceiptV3; bytes: Buffer }>,
  sourceArtifacts: Map<string, ParsedSourceArtifact>,
  extensionKeys: Set<string>,
): AtlasSecurityFindingV3 {
  const finding = recordAt(value, pointer)
  exactKeys(
    finding,
    [
      'findingId',
      'occurrenceId',
      'decisionLedger',
      'ruleId',
      'identity',
      'fingerprints',
      'title',
      'summary',
      'severity',
      'taxonomy',
      'locations',
      'remediation',
      'provenance',
    ],
    [
      'confidence',
      'codeEvidence',
      'rootCause',
      'validation',
      'attackPath',
      'remediationTests',
      'preventiveControls',
      'artifactRefs',
      'extensions',
    ],
    pointer,
  )
  const findingId = stringAt(finding.findingId, `${pointer}/findingId`)
  if (!FINDING_ID_RE.test(findingId)) invalid('invalid-finding-id', `${pointer}/findingId`, 'must be an Atlas finding ID')
  const occurrenceId = stringAt(finding.occurrenceId, `${pointer}/occurrenceId`)
  if (!OCCURRENCE_ID_RE.test(occurrenceId)) {
    invalid('invalid-occurrence-id', `${pointer}/occurrenceId`, 'must be an Atlas occurrence ID')
  }
  const decisionLedger = stringAt(
    finding.decisionLedger,
    `${pointer}/decisionLedger`,
  )
  if (!SECURITY_SLUG_RE.test(decisionLedger)) {
    invalid(
      'invalid-decision-ledger',
      `${pointer}/decisionLedger`,
      'must be a security- prefixed lowercase kebab-case stable home',
    )
  }
  const ruleId = stringAt(finding.ruleId, `${pointer}/ruleId`)
  const identity = recordAt(finding.identity, `${pointer}/identity`)
  exactKeys(identity, ['anchor'], ['instance'], `${pointer}/identity`)
  const anchor = stringAt(identity.anchor, `${pointer}/identity/anchor`)
  const instance = identity.instance === undefined
    ? undefined
    : stringAt(identity.instance, `${pointer}/identity/instance`)
  if (
    producerKind === 'codex-security' &&
    (
      !CODEX_SLUG_RE.test(ruleId) ||
      !CODEX_SLUG_RE.test(anchor) ||
      (instance !== undefined && !CODEX_SLUG_RE.test(instance))
    )
  ) {
    invalid(
      'invalid-codex-slug',
      `${pointer}/identity`,
      'Codex ruleId, anchor, and optional instance must be lowercase source slugs',
    )
  }
  const expectedFingerprint = computeAtlasFingerprint({
    repositoryId,
    domain: 'security',
    ruleId,
    anchor,
    instance,
  })
  const fingerprints = arrayAt(finding.fingerprints, `${pointer}/fingerprints`)
  if (fingerprints.length === 0) invalid('missing-fingerprint', `${pointer}/fingerprints`, 'must contain the canonical Atlas fingerprint')
  let canonicalFingerprintCount = 0
  let codexFingerprintCount = 0
  const fingerprintKeys = new Set<string>()
  const expectedCodexFingerprint = computeCodexFingerprint(
    targetId,
    ruleId,
    anchor,
    instance,
  )
  for (const [index, candidate] of fingerprints.entries()) {
    const fingerprint = recordAt(candidate, `${pointer}/fingerprints/${index}`)
    exactKeys(fingerprint, ['scheme', 'value', 'role'], [], `${pointer}/fingerprints/${index}`)
    const scheme = stringAt(fingerprint.scheme, `${pointer}/fingerprints/${index}/scheme`)
    const fingerprintValue = stringAt(fingerprint.value, `${pointer}/fingerprints/${index}/value`)
    const role = enumAt(fingerprint.role, ['canonical', 'producer'] as const, `${pointer}/fingerprints/${index}/role`)
    const key = `${scheme}\0${fingerprintValue}`
    if (fingerprintKeys.has(key)) invalid('duplicate', `${pointer}/fingerprints/${index}`, 'duplicate fingerprint')
    fingerprintKeys.add(key)
    if (scheme === 'atlas/v1' && role === 'canonical') {
      canonicalFingerprintCount += 1
      if (fingerprintValue !== expectedFingerprint) {
        invalid('fingerprint-mismatch', `${pointer}/fingerprints/${index}/value`, 'does not match the Atlas fingerprint formula')
      }
    }
    if (scheme === 'codex-security/v1') {
      codexFingerprintCount += 1
      if (
        producerKind !== 'codex-security' ||
        role !== 'producer' ||
        !CODEX_FINGERPRINT_RE.test(fingerprintValue) ||
        fingerprintValue !== expectedCodexFingerprint
      ) {
        invalid(
          'fingerprint-mismatch',
          `${pointer}/fingerprints/${index}`,
          'does not match the Codex Security producer fingerprint formula',
        )
      }
    }
  }
  if (canonicalFingerprintCount !== 1) {
    invalid('canonical-fingerprint-count', `${pointer}/fingerprints`, 'must contain exactly one canonical Atlas fingerprint')
  }
  if (
    (producerKind === 'codex-security' && codexFingerprintCount !== 1) ||
    (producerKind !== 'codex-security' && codexFingerprintCount !== 0)
  ) {
    invalid(
      'producer-fingerprint-count',
      `${pointer}/fingerprints`,
      'Codex observations require exactly one Codex producer fingerprint and other producers forbid it',
    )
  }
  if (findingId !== computeAtlasFindingId(expectedFingerprint)) {
    invalid('finding-identity-mismatch', `${pointer}/findingId`, 'does not match the Atlas finding formula')
  }
  if (occurrenceId !== computeAtlasOccurrenceId(observationId, expectedFingerprint)) {
    invalid('occurrence-identity-mismatch', `${pointer}/occurrenceId`, 'does not match the Atlas occurrence formula')
  }
  stringAt(finding.title, `${pointer}/title`)
  stringAt(finding.summary, `${pointer}/summary`)

  const severity = recordAt(finding.severity, `${pointer}/severity`)
  exactKeys(
    severity,
    ['level'],
    ['score', 'scoringSystem', 'vector', 'rationale', 'changeConditions'],
    `${pointer}/severity`,
  )
  enumAt(
    severity.level,
    ['critical', 'high', 'medium', 'low', 'informational'] as const,
    `${pointer}/severity/level`,
  )
  if (severity.score !== undefined) {
    if (typeof severity.score !== 'number' || !Number.isFinite(severity.score) ||
        severity.score < 0 || severity.score > 10) {
      invalid('invalid-score', `${pointer}/severity/score`, 'must be finite and between 0 and 10')
    }
  }
  for (const key of ['scoringSystem', 'vector', 'rationale', 'changeConditions']) {
    if (severity[key] !== undefined) stringAt(severity[key], `${pointer}/severity/${key}`)
  }

  if (finding.confidence === undefined) {
    if (producerKind === 'grok-cli' || producerKind === 'codex-security') {
      invalid(
        'missing-member',
        `${pointer}/confidence`,
        'first-party Grok and Codex findings require confidence',
      )
    }
  } else {
    const confidence = recordAt(finding.confidence, `${pointer}/confidence`)
    exactKeys(confidence, ['level'], ['rationale'], `${pointer}/confidence`)
    enumAt(
      confidence.level,
      ['low', 'medium', 'high'] as const,
      `${pointer}/confidence/level`,
    )
    if (confidence.rationale !== undefined) {
      stringAt(confidence.rationale, `${pointer}/confidence/rationale`)
    }
  }

  const taxonomy = recordAt(finding.taxonomy, `${pointer}/taxonomy`)
  exactKeys(taxonomy, ['category'], ['cwe'], `${pointer}/taxonomy`)
  stringAt(taxonomy.category, `${pointer}/taxonomy/category`)
  if (taxonomy.cwe !== undefined) uniqueStringsAt(taxonomy.cwe, `${pointer}/taxonomy/cwe`)

  const locations = arrayAt(finding.locations, `${pointer}/locations`)
  if (locations.length === 0) invalid('missing-location', `${pointer}/locations`, 'must contain at least one location')
  for (const [index, candidate] of locations.entries()) {
    const location = recordAt(candidate, `${pointer}/locations/${index}`)
    exactKeys(location, ['path', 'startLine'], ['endLine', 'role'], `${pointer}/locations/${index}`)
    const locationPath = repoPathAt(location.path, `${pointer}/locations/${index}/path`)
    const startLine = safeIntegerAt(location.startLine, `${pointer}/locations/${index}/startLine`, 1)
    const endLine = location.endLine === undefined
      ? startLine
      : safeIntegerAt(location.endLine, `${pointer}/locations/${index}/endLine`, 1)
    if (endLine < startLine) invalid('invalid-line', `${pointer}/locations/${index}`, 'endLine must not precede startLine')
    if (location.role !== undefined) stringAt(location.role, `${pointer}/locations/${index}/role`)
    if (exactInventory) {
      const scoped = fileByPath.get(locationPath)
      if (!scoped) {
        invalid(
          'location-receipt-mismatch',
          `${pointer}/locations/${index}/path`,
          'exact authoritative locations must reference a scoped file receipt',
        )
      }
      if (endLine > scoped.receipt.lines) {
        invalid(
          'invalid-line',
          `${pointer}/locations/${index}`,
          'location range exceeds the exact file receipt line count',
        )
      }
      if (!scoped.receipt.findingOccurrenceIds.includes(occurrenceId)) {
        invalid(
          'location-receipt-mismatch',
          `${pointer}/locations/${index}/path`,
          'exact authoritative location receipt must bind this occurrence',
        )
      }
    }
  }

  const evidenceIds = new Set<string>()
  if (finding.codeEvidence !== undefined) {
    const evidenceRows = arrayAt(finding.codeEvidence, `${pointer}/codeEvidence`)
    if (evidenceRows.length > 32) invalid('snippet-limit', `${pointer}/codeEvidence`, 'exceeds the 32 snippet limit')
    let totalBytes = 0
    for (const [index, candidate] of evidenceRows.entries()) {
      const evidencePointer = `${pointer}/codeEvidence/${index}`
      const evidence = recordAt(candidate, evidencePointer)
      const evidenceBasis = enumAt(
        evidence.evidenceBasis,
        ['exact-blob', 'sealed-producer-snippet'] as const,
        `${evidencePointer}/evidenceBasis`,
      )
      exactKeys(
        evidence,
        [
          'evidenceBasis',
          'id',
          'label',
          'path',
          'startLine',
          'code',
          'explanation',
          evidenceBasis === 'exact-blob' ? 'blob' : 'sourceSeal',
        ],
        ['endLine', 'language', 'role'],
        evidencePointer,
      )
      const id = stringAt(evidence.id, `${evidencePointer}/id`)
      if (evidenceIds.has(id)) invalid('duplicate', `${evidencePointer}/id`, 'duplicate code-evidence ID')
      evidenceIds.add(id)
      stringAt(evidence.label, `${evidencePointer}/label`)
      const evidencePath = repoPathAt(evidence.path, `${evidencePointer}/path`)
      const startLine = safeIntegerAt(evidence.startLine, `${evidencePointer}/startLine`, 1)
      const endLine = evidence.endLine === undefined
        ? startLine
        : safeIntegerAt(evidence.endLine, `${evidencePointer}/endLine`, 1)
      if (endLine < startLine) invalid('invalid-line', evidencePointer, 'endLine must not precede startLine')
      const code = stringAt(
        evidence.code,
        `${evidencePointer}/code`,
        producerKind === 'codex-security',
      )
      const snippetBytes = Buffer.byteLength(code, 'utf8')
      totalBytes += snippetBytes
      if (snippetBytes > 16 * 1024) invalid('snippet-limit', `${evidencePointer}/code`, 'exceeds the 16 KiB snippet limit')
      if (totalBytes > 128 * 1024) invalid('snippet-limit', `${pointer}/codeEvidence`, 'exceeds the 128 KiB aggregate snippet limit')
      stringAt(evidence.explanation, `${evidencePointer}/explanation`)
      if (evidence.language !== undefined) stringAt(evidence.language, `${evidencePointer}/language`)
      if (evidence.role !== undefined) stringAt(evidence.role, `${evidencePointer}/role`)
      if (evidenceBasis === 'exact-blob') {
        const blob = gitBlobAt(evidence.blob, `${evidencePointer}/blob`)
        const scoped = fileByPath.get(evidencePath)
        if (!scoped || scoped.receipt.blob !== blob) {
          invalid('evidence-blob-mismatch', `${evidencePointer}/blob`, 'must match an exact scoped file blob')
        }
        const expectedCode = snippetFromBlob(
          scoped.bytes,
          startLine,
          endLine,
          `${evidencePointer}/code`,
        )
        if (code !== expectedCode) {
          invalid('snippet-mismatch', `${evidencePointer}/code`, 'does not match the claimed exact blob lines')
        }
      } else {
        const sourceSeal = recordAt(evidence.sourceSeal, `${evidencePointer}/sourceSeal`)
        exactKeys(
          sourceSeal,
          ['artifactPath', 'artifactSha256', 'jsonPointer'],
          [],
          `${evidencePointer}/sourceSeal`,
        )
        const artifactPath = repoPathAt(
          sourceSeal.artifactPath,
          `${evidencePointer}/sourceSeal/artifactPath`,
        )
        const artifactSha256 = rawSha256At(
          sourceSeal.artifactSha256,
          `${evidencePointer}/sourceSeal/artifactSha256`,
        )
        const sourceJsonPointer = strictJsonPointerAt(
          sourceSeal.jsonPointer,
          `${evidencePointer}/sourceSeal/jsonPointer`,
        )
        if (
          producerKind === 'codex-security' &&
          artifactPath !== 'findings.json'
        ) {
          invalid(
            'source-seal-artifact-mismatch',
            `${evidencePointer}/sourceSeal/artifactPath`,
            'Codex source seals must resolve through findings.json',
          )
        }
        if (
          producerKind === 'codex-security' &&
          sourceJsonPointer !==
            `/findings/${findingIndex}/codeEvidence/${index}`
        ) {
          invalid(
            'source-seal-pointer-mismatch',
            `${evidencePointer}/sourceSeal/jsonPointer`,
            'Codex source seals must identify the matching findings.json code-evidence slot',
          )
        }
        const artifact = sourceArtifacts.get(artifactPath)
        if (
          !artifact ||
          artifact.integrityKind !== 'producer-manifest' ||
          artifact.sha256 !== artifactSha256
        ) {
          invalid(
            'source-seal-mismatch',
            `${evidencePointer}/sourceSeal`,
            'must resolve to exactly one producer-manifest source artifact',
          )
        }
      }
    }
  }

  if (finding.rootCause !== undefined) {
    if (typeof finding.rootCause === 'string') {
      stringAt(finding.rootCause, `${pointer}/rootCause`)
    } else {
      const rootCause = recordAt(finding.rootCause, `${pointer}/rootCause`)
      exactKeys(rootCause, ['summary'], ['evidenceRefs', 'legacyCode'], `${pointer}/rootCause`)
      stringAt(rootCause.summary, `${pointer}/rootCause/summary`)
      if (rootCause.evidenceRefs !== undefined) {
        const refs = uniqueStringsAt(rootCause.evidenceRefs, `${pointer}/rootCause/evidenceRefs`)
        for (const [index, ref] of refs.entries()) {
          if (!evidenceIds.has(ref)) {
            invalid(
              'unknown-reference',
              `${pointer}/rootCause/evidenceRefs/${index}`,
              'must reference code evidence',
            )
          }
        }
      }
      if (rootCause.legacyCode !== undefined) {
        const legacyCode = recordAt(rootCause.legacyCode, `${pointer}/rootCause/legacyCode`)
        exactKeys(legacyCode, ['code'], ['language'], `${pointer}/rootCause/legacyCode`)
        stringAt(
          legacyCode.code,
          `${pointer}/rootCause/legacyCode/code`,
          producerKind === 'codex-security',
        )
        if (legacyCode.language !== undefined) {
          stringAt(legacyCode.language, `${pointer}/rootCause/legacyCode/language`)
        }
      }
    }
  }
  stringAt(finding.remediation, `${pointer}/remediation`)
  if (finding.validation !== undefined) {
    parseValidation(
      finding.validation,
      `${pointer}/validation`,
      evidenceIds,
      sourceArtifacts,
    )
  }
  if (finding.attackPath !== undefined) {
    parseAttackPath(finding.attackPath, `${pointer}/attackPath`, evidenceIds)
  }
  for (const key of ['remediationTests', 'preventiveControls']) {
    if (finding[key] !== undefined) {
      parseDocumentedJsonArray(finding[key], `${pointer}/${key}`)
    }
  }
  const provenance = recordAt(finding.provenance, `${pointer}/provenance`)
  exactKeys(
    provenance,
    ['source'],
    ['producerSource', 'sourceFindingId', 'sourceOccurrenceId', 'candidateId', 'ledgerRowId', 'reportId'],
    `${pointer}/provenance`,
  )
  for (const [key, candidate] of Object.entries(provenance)) {
    stringAt(candidate, `${pointer}/provenance/${key}`)
  }
  if (producerKind === 'codex-security') {
    if (provenance.source !== 'codex-security') {
      invalid(
        'provenance-source-mismatch',
        `${pointer}/provenance/source`,
        'Codex observations require normalized source codex-security',
      )
    }
    const producerSource = stringAt(
      provenance.producerSource,
      `${pointer}/provenance/producerSource`,
    )
    void producerSource
    const expectedSourceFindingId =
      `csf_${sha256Text(expectedCodexFingerprint).slice(0, 24)}`
    const expectedSourceOccurrenceId =
      `occ_${sha256Text(`${producerRunId}\0${expectedCodexFingerprint}`).slice(0, 24)}`
    if (provenance.sourceFindingId !== expectedSourceFindingId) {
      invalid(
        'source-finding-identity-mismatch',
        `${pointer}/provenance/sourceFindingId`,
        'does not match the Codex finding identity formula',
      )
    }
    if (provenance.sourceOccurrenceId !== expectedSourceOccurrenceId) {
      invalid(
        'source-occurrence-identity-mismatch',
        `${pointer}/provenance/sourceOccurrenceId`,
        'does not match the Codex occurrence identity formula',
      )
    }
  } else if (provenance.source === 'codex-security') {
    invalid(
      'provenance-source-mismatch',
      `${pointer}/provenance/source`,
      'non-Codex producer cannot claim Codex normalized provenance',
    )
  }
  if (finding.artifactRefs !== undefined) {
    const artifactRefs = arrayAt(finding.artifactRefs, `${pointer}/artifactRefs`)
    const keys = new Set<string>()
    for (const [index, row] of artifactRefs.entries()) {
      const itemPointer = `${pointer}/artifactRefs/${index}`
      const artifactRef = recordAt(row, itemPointer)
      exactKeys(
        artifactRef,
        [
          'kind',
          'sourceArtifactPath',
          'integrityKind',
          'sha256',
          'mediaType',
          'retainedInAtlas',
        ],
        [],
        itemPointer,
      )
      enumAt(artifactRef.kind, ['external'] as const, `${itemPointer}/kind`)
      const artifactPath = repoPathAt(
        artifactRef.sourceArtifactPath,
        `${itemPointer}/sourceArtifactPath`,
      )
      const integrityKind = enumAt(
        artifactRef.integrityKind,
        ['producer-manifest', 'adapter-bundle'] as const,
        `${itemPointer}/integrityKind`,
      )
      const sha256 = rawSha256At(artifactRef.sha256, `${itemPointer}/sha256`)
      const mediaType = stringAt(artifactRef.mediaType, `${itemPointer}/mediaType`)
      const retainedInAtlas = booleanAt(
        artifactRef.retainedInAtlas,
        `${itemPointer}/retainedInAtlas`,
      )
      if (keys.has(artifactPath)) {
        invalid('duplicate', `${itemPointer}/sourceArtifactPath`, 'duplicate artifact reference')
      }
      keys.add(artifactPath)
      const artifact = sourceArtifacts.get(artifactPath)
      if (
        !artifact ||
        artifact.integrityKind !== integrityKind ||
        artifact.sha256 !== sha256 ||
        artifact.mediaType !== mediaType ||
        artifact.retainedInAtlas !== retainedInAtlas
      ) {
        invalid('artifact-reference-mismatch', itemPointer, 'does not match sourceArtifacts')
      }
    }
  }
  if (finding.extensions !== undefined) {
    parseExtensions(
      finding.extensions,
      `${pointer}/extensions`,
      producerKind === 'codex-security',
      extensionKeys,
    )
  }
  return finding as unknown as AtlasSecurityFindingV3
}

function parseObservation(
  root: string,
  slug: string,
  value: unknown,
  pointer: string,
  context: AuditValidationContext,
): AtlasSecurityObservationV3 {
  const observation = recordAt(value, pointer)
  exactKeys(
    observation,
    [
      'observationId',
      'observedAt',
      'reviewState',
      'producer',
      'target',
      'scope',
      'exactCoverage',
      'semanticCoverage',
      'findings',
      'evidenceRefs',
      'sourceArtifacts',
      'producerExtensions',
    ],
    ['threatModel', 'hardening'],
    pointer,
  )
  const observationId = stringAt(observation.observationId, `${pointer}/observationId`)
  if (!OBSERVATION_ID_RE.test(observationId)) {
    invalid('invalid-observation-id', `${pointer}/observationId`, 'must be an Atlas observation ID')
  }
  const observedAt = timestampAt(observation.observedAt, `${pointer}/observedAt`)
  enumAt(observation.reviewState, ['complete'] as const, `${pointer}/reviewState`)
  const producer = parseProducer(observation.producer, `${pointer}/producer`)
  if (producer.completedAt !== undefined && observedAt !== producer.completedAt) {
    invalid(
      'timestamp-mismatch',
      `${pointer}/observedAt`,
      'must normalize the Codex source completedAt timestamp',
    )
  }
  const target = parseTarget(
    root,
    producer.kind,
    observation.target,
    `${pointer}/target`,
  )

  const scope = recordAt(observation.scope, `${pointer}/scope`)
  const identityBasis = enumAt(
    scope.identityBasis,
    ['exact-inventory', 'semantic-declaration'] as const,
    `${pointer}/scope/identityBasis`,
  )
  exactKeys(
    scope,
    [
      'mode',
      'identityDigest',
      'identityBasis',
      'includePaths',
      'excludePaths',
      ...(producer.kind === 'codex-security'
        ? []
        : ['artifactsReviewed', 'limitations']),
      ...(identityBasis === 'exact-inventory'
        ? ['scopeHash', 'inventoryDigest', 'fileCount', 'files']
        : ['inventoryStrategy', 'explicitExclusions']),
    ],
    [
      'summary',
      'runtimeStatus',
      'validationMode',
      'context',
      ...(producer.kind === 'codex-security'
        ? ['artifactsReviewed', 'limitations']
        : []),
    ],
    `${pointer}/scope`,
  )
  const identityDigest = sha256At(scope.identityDigest, `${pointer}/scope/identityDigest`)
  const includePaths = uniqueStringsAt(scope.includePaths, `${pointer}/scope/includePaths`)
  const excludePaths = uniqueStringsAt(scope.excludePaths, `${pointer}/scope/excludePaths`)
  const validateScopeSelector = identityBasis === 'semantic-declaration'
    ? assertSemanticSelector
    : assertPattern
  for (const [index, pattern] of includePaths.entries()) {
    try {
      validateScopeSelector(pattern, 'include path')
    } catch (error) {
      invalid('invalid-path', `${pointer}/scope/includePaths/${index}`, error instanceof Error ? error.message : String(error))
    }
  }
  for (const [index, pattern] of excludePaths.entries()) {
    try {
      validateScopeSelector(pattern, 'exclude path')
    } catch (error) {
      invalid('invalid-path', `${pointer}/scope/excludePaths/${index}`, error instanceof Error ? error.message : String(error))
    }
  }
  if (scope.artifactsReviewed !== undefined) {
    uniqueStringsAt(scope.artifactsReviewed, `${pointer}/scope/artifactsReviewed`)
  }
  if (scope.limitations !== undefined) {
    uniqueStringsAt(scope.limitations, `${pointer}/scope/limitations`)
  }
  for (const key of ['summary', 'runtimeStatus', 'validationMode', 'context']) {
    if (scope[key] !== undefined) stringAt(scope[key], `${pointer}/scope/${key}`)
  }

  const fileByPath = new Map<string, { receipt: AuditFileReceiptV3; bytes: Buffer }>()
  let fileCount = 0
  let scopeMode:
    | import('./audit-v3-types.js').AuditExactScopeMode
    | import('./audit-v3-types.js').AuditSemanticMode
  let semanticScope:
    | {
        inventoryStrategy: import('./audit-v3-types.js').AuditInventoryStrategy
        explicitExclusions: Array<{ pattern: string; reason: string }>
      }
    | undefined
  if (identityBasis === 'exact-inventory') {
    const mode = enumAt(
      scope.mode,
      ['repository', 'scoped_path', 'unit', 'diff', 'custom'] as const,
      `${pointer}/scope/mode`,
    )
    scopeMode = mode
    const fileRows = arrayAt(scope.files, `${pointer}/scope/files`)
    let previousPath: string | undefined
    for (const [index, row] of fileRows.entries()) {
      const parsed = parseFileReceipt(
        root,
        row,
        `${pointer}/scope/files/${index}`,
        context,
      )
      if (producer.rulesetId !== undefined) {
        if (
          parsed.receipt.status === 'reviewed' &&
          parsed.receipt.ruleset === undefined
        ) {
          invalid(
            'ruleset-receipt-mismatch',
            `${pointer}/scope/files/${index}/ruleset`,
            'reviewed file receipt requires the producer ruleset ID',
          )
        }
        if (
          parsed.receipt.ruleset !== undefined &&
          parsed.receipt.ruleset !== producer.rulesetId
        ) {
          invalid(
            'ruleset-receipt-mismatch',
            `${pointer}/scope/files/${index}/ruleset`,
            'file receipt ruleset must equal producer.ruleset.id',
          )
        }
      }
      if (
        previousPath !== undefined &&
        utf16Compare(previousPath, parsed.receipt.path) >= 0
      ) {
        invalid(
          'invalid-order',
          `${pointer}/scope/files/${index}/path`,
          'files must be uniquely sorted by path',
        )
      }
      previousPath = parsed.receipt.path
      fileByPath.set(parsed.receipt.path, parsed)
    }
    fileCount = safeIntegerAt(scope.fileCount, `${pointer}/scope/fileCount`)
    if (fileCount !== fileRows.length) {
      invalid('count-mismatch', `${pointer}/scope/fileCount`, 'must equal files.length')
    }
    const exactIdentity = computeExactScopeIdentityDigest({
      mode,
      includePaths,
      excludePaths,
      files: [...fileByPath.values()].map(({ receipt }) => ({
        path: receipt.path,
        blob: receipt.blob,
      })),
    })
    if (identityDigest !== exactIdentity) {
      invalid('identity-mismatch', `${pointer}/scope/identityDigest`, 'does not match the exact pre-result scope identity')
    }
    const inventoryDigest = sha256At(scope.inventoryDigest, `${pointer}/scope/inventoryDigest`)
    const expectedInventory = computeAuditInventoryDigest(
      [...fileByPath.values()].map(({ receipt }) => receipt),
    )
    if (inventoryDigest !== expectedInventory) {
      invalid('inventory-digest-mismatch', `${pointer}/scope/inventoryDigest`, 'does not seal the result receipts')
    }
    const scopeHash = sha256At(scope.scopeHash, `${pointer}/scope/scopeHash`)
    const expectedScopeHash = computeAuditScopeHash({
      mode,
      includePaths,
      excludePaths,
      inventoryDigest,
    })
    if (scopeHash !== expectedScopeHash) {
      invalid('scope-hash-mismatch', `${pointer}/scope/scopeHash`, 'does not seal the result scope')
    }
  } else {
    const mode = enumAt(
      scope.mode,
      ['repository', 'scoped_path', 'diff', 'commit', 'branch_diff', 'working_tree', 'deep_repository', 'unit', 'custom'] as const,
      `${pointer}/scope/mode`,
    )
    scopeMode = mode
    const inventoryStrategy = enumAt(
      scope.inventoryStrategy,
      ['repository', 'scoped_path', 'diff', 'directory', 'custom', 'unit'] as const,
      `${pointer}/scope/inventoryStrategy`,
    )
    const explicitExclusions = parseExplicitExclusions(
      scope.explicitExclusions,
      `${pointer}/scope/explicitExclusions`,
    )
    semanticScope = { inventoryStrategy, explicitExclusions }
    const expectedIdentity = computeSemanticScopeIdentityDigest({
      mode,
      inventoryStrategy,
      includePaths,
      excludePaths,
      explicitExclusions,
    })
    if (identityDigest !== expectedIdentity) {
      invalid(
        'identity-mismatch',
        `${pointer}/scope/identityDigest`,
        'does not match the semantic declaration identity',
      )
    }
  }

  const exactCoverage = recordAt(observation.exactCoverage, `${pointer}/exactCoverage`)
  const exactBasis = enumAt(
    exactCoverage.basis,
    ['full-read-receipts', 'unavailable'] as const,
    `${pointer}/exactCoverage/basis`,
  )
  if (exactBasis === 'unavailable') {
    exactKeys(
      exactCoverage,
      ['completeness', 'basis', 'reason'],
      [],
      `${pointer}/exactCoverage`,
    )
    enumAt(
      exactCoverage.completeness,
      ['unknown'] as const,
      `${pointer}/exactCoverage/completeness`,
    )
    const reason = stringAt(exactCoverage.reason, `${pointer}/exactCoverage/reason`)
    if (
      producer.kind === 'codex-security' &&
      identityBasis === 'semantic-declaration' &&
      reason !== 'Codex Security 1.0 did not supply exact per-file blob receipts.'
    ) {
      invalid(
        'invalid-reason',
        `${pointer}/exactCoverage/reason`,
        'semantic Codex coverage requires the stable unavailable reason',
      )
    }
  } else {
    exactKeys(
      exactCoverage,
      ['completeness', 'basis', 'reviewedFileCount', 'unreviewed'],
      [],
      `${pointer}/exactCoverage`,
    )
    if (identityBasis !== 'exact-inventory') {
      invalid(
        'coverage-basis-mismatch',
        `${pointer}/exactCoverage/basis`,
        'full-read receipts require an exact-inventory scope',
      )
    }
    const completeness = enumAt(
      exactCoverage.completeness,
      ['complete', 'partial'] as const,
      `${pointer}/exactCoverage/completeness`,
    )
    const reviewedFileCount = safeIntegerAt(
      exactCoverage.reviewedFileCount,
      `${pointer}/exactCoverage/reviewedFileCount`,
    )
    const unreviewed = arrayAt(
      exactCoverage.unreviewed,
      `${pointer}/exactCoverage/unreviewed`,
    )
    const unreviewedPaths = new Set<string>()
    let previousPath: string | undefined
    for (const [index, row] of unreviewed.entries()) {
      const itemPointer = `${pointer}/exactCoverage/unreviewed/${index}`
      const item = recordAt(row, itemPointer)
      exactKeys(item, ['path', 'reason'], [], itemPointer)
      const unreviewedPath = repoPathAt(item.path, `${itemPointer}/path`)
      stringAt(item.reason, `${itemPointer}/reason`)
      if (
        previousPath !== undefined &&
        utf16Compare(previousPath, unreviewedPath) >= 0
      ) {
        invalid('invalid-order', `${itemPointer}/path`, 'unreviewed rows must be uniquely sorted')
      }
      previousPath = unreviewedPath
      if (
        !fileByPath.has(unreviewedPath) ||
        fileByPath.get(unreviewedPath)?.receipt.status !== 'not-reviewed'
      ) {
        invalid(
          'invalid-reference',
          `${itemPointer}/path`,
          'must reference a not-reviewed scoped file',
        )
      }
      unreviewedPaths.add(unreviewedPath)
    }
    const receiptReviewedCount = [...fileByPath.values()]
      .filter(({ receipt }) => receipt.status === 'reviewed').length
    if (
      reviewedFileCount !== receiptReviewedCount ||
      reviewedFileCount + unreviewed.length !== fileCount
    ) {
      invalid('coverage-arithmetic', `${pointer}/exactCoverage`, 'reviewed and unreviewed counts must close over scope')
    }
    if (completeness === 'complete' && (unreviewed.length !== 0 || reviewedFileCount !== fileCount)) {
      invalid('coverage-closure', `${pointer}/exactCoverage`, 'complete exact coverage requires every file reviewed')
    }
  }

  const semanticCoverage = parseSemanticCoverage(
    observation.semanticCoverage,
    `${pointer}/semanticCoverage`,
  )
  if (
    semanticCoverage.mode !== scopeMode ||
    (
      semanticScope !== undefined &&
      (
        semanticCoverage.inventoryStrategy !== semanticScope.inventoryStrategy ||
        canonicalJson(semanticCoverage.explicitExclusions) !==
          canonicalJson(semanticScope.explicitExclusions)
      )
    )
  ) {
    invalid(
      'scope-coverage-mismatch',
      `${pointer}/semanticCoverage`,
      'must match the declared scope mode, strategy, and exclusions',
    )
  }

  const evidenceRefs = uniqueStringsAt(observation.evidenceRefs, `${pointer}/evidenceRefs`)
  for (const [index, ref] of evidenceRefs.entries()) repoPathAt(ref, `${pointer}/evidenceRefs/${index}`)
  if (observation.threatModel !== undefined) {
    parseThreatModel(observation.threatModel, `${pointer}/threatModel`)
  }
  const sourceArtifacts = parseSourceArtifacts(
    observation.sourceArtifacts,
    `${pointer}/sourceArtifacts`,
  )
  if (observation.hardening !== undefined) {
    const hardening = recordAt(
      observation.hardening,
      `${pointer}/hardening`,
    )
    exactKeys(
      hardening,
      ['portfolio'],
      [],
      `${pointer}/hardening`,
    )
    const portfolio = recordAt(
      hardening.portfolio,
      `${pointer}/hardening/portfolio`,
    )
    exactKeys(
      portfolio,
      [
        'kind',
        'sourceArtifactPath',
        'integrityKind',
        'sha256',
        'mediaType',
        'retainedInAtlas',
      ],
      [],
      `${pointer}/hardening/portfolio`,
    )
    enumAt(
      portfolio.kind,
      ['external'] as const,
      `${pointer}/hardening/portfolio/kind`,
    )
    const artifactPath = repoPathAt(
      portfolio.sourceArtifactPath,
      `${pointer}/hardening/portfolio/sourceArtifactPath`,
    )
    const integrityKind = enumAt(
      portfolio.integrityKind,
      ['producer-manifest', 'adapter-bundle'] as const,
      `${pointer}/hardening/portfolio/integrityKind`,
    )
    const sha256 = rawSha256At(
      portfolio.sha256,
      `${pointer}/hardening/portfolio/sha256`,
    )
    const mediaType = stringAt(
      portfolio.mediaType,
      `${pointer}/hardening/portfolio/mediaType`,
    )
    const retainedInAtlas = booleanAt(
      portfolio.retainedInAtlas,
      `${pointer}/hardening/portfolio/retainedInAtlas`,
    )
    const artifact = sourceArtifacts.get(artifactPath)
    if (
      !artifact ||
      artifact.integrityKind !== integrityKind ||
      artifact.sha256 !== sha256 ||
      artifact.mediaType !== mediaType ||
      artifact.retainedInAtlas !== retainedInAtlas
    ) {
      invalid(
        'artifact-reference-mismatch',
        `${pointer}/hardening/portfolio`,
        'does not match sourceArtifacts',
      )
    }
  }
  const extensionKeys = new Set<string>()
  parseExtensions(
    observation.producerExtensions,
    `${pointer}/producerExtensions`,
    producer.kind === 'codex-security',
    extensionKeys,
  )

  const findings = arrayAt(observation.findings, `${pointer}/findings`)
  const findingIds = new Set<string>()
  const occurrenceIds = new Set<string>()
  for (const [index, row] of findings.entries()) {
    const finding = parseFinding(
      root,
      index,
      observationId as AtlasObservationId,
      target.repositoryId,
      target.targetId,
      producer.kind,
      producer.runId,
      identityBasis === 'exact-inventory',
      row,
      `${pointer}/findings/${index}`,
      fileByPath,
      sourceArtifacts,
      extensionKeys,
    )
    if (findingIds.has(finding.findingId)) {
      invalid('duplicate', `${pointer}/findings/${index}/findingId`, 'duplicate finding ID')
    }
    if (occurrenceIds.has(finding.occurrenceId)) {
      invalid('duplicate', `${pointer}/findings/${index}/occurrenceId`, 'duplicate occurrence ID')
    }
    findingIds.add(finding.findingId)
    occurrenceIds.add(finding.occurrenceId)
  }
  if (producer.kind === 'codex-security') {
    validateCodexArtifactJoins(observation, sourceArtifacts)
  }
  for (const { receipt } of fileByPath.values()) {
    for (const occurrenceId of receipt.findingOccurrenceIds) {
      if (!occurrenceIds.has(occurrenceId)) {
        invalid('unknown-reference', `${pointer}/scope/files`, `unknown finding occurrence ${occurrenceId}`)
      }
    }
    if (receipt.outcome === 'findings' && receipt.findingOccurrenceIds.length === 0) {
      invalid('outcome-mismatch', `${pointer}/scope/files`, 'findings outcome requires an occurrence')
    }
    if (receipt.outcome === 'clean' && receipt.findingOccurrenceIds.length !== 0) {
      invalid('outcome-mismatch', `${pointer}/scope/files`, 'clean outcome forbids finding occurrences')
    }
  }
  if (identityBasis === 'exact-inventory') {
    for (const occurrenceId of occurrenceIds) {
      const referenced = [...fileByPath.values()].some(({ receipt }) =>
        receipt.findingOccurrenceIds.includes(occurrenceId)
      )
      if (!referenced) {
        invalid(
          'unknown-reference',
          `${pointer}/findings`,
          `occurrence ${occurrenceId} is not bound to a scoped file`,
        )
      }
    }
  }
  for (const [index, ref] of semanticCoverage.findingRefs.entries()) {
    const findingId = ref.slice('finding:'.length)
    if (!FINDING_ID_RE.test(findingId) || !findingIds.has(findingId)) {
      invalid(
        'unknown-reference',
        `${pointer}/semanticCoverage/surfaces`,
        `unknown finding receipt ${index}`,
      )
    }
  }

  const expectedObservationId = computeAtlasObservationId({
    slug,
    adapter: producer.adapter,
    runId: producer.runId,
    producerIdentityDigest: producer.identityDigest,
    targetId: target.targetId,
    targetIdentityDigest: target.identityDigest,
    scopeIdentityDigest: identityDigest,
  })
  if (observationId !== expectedObservationId) {
    invalid('observation-identity-mismatch', `${pointer}/observationId`, 'does not match the observation identity formula')
  }
  return observation as unknown as AtlasSecurityObservationV3
}

function diagnostic(error: unknown): AuditDiagnostic {
  if (error instanceof AuditValidationFailure) {
    return {
      code: error.code,
      path: error.pointer,
      message: error.message,
    }
  }
  return {
    code: 'invalid-audit-v3',
    path: '',
    message: error instanceof Error ? error.message : String(error),
  }
}

function parseAuditCurrentLedgerWithContext(
  root: string,
  repoPath: string,
  value: unknown,
  context: AuditValidationContext,
): AuditParseResult<AtlasSecurityCurrentLedgerV3> {
  try {
    const normalizedPath = normalizeAuditRepoPath(repoPath)
    const canonicalInput = canonicalJson(value)
    if (Buffer.byteLength(canonicalInput, 'utf8') > LEDGER_BYTE_LIMIT) {
      invalid(
        'ledger-byte-limit',
        '',
        `canonical ledger exceeds the ${LEDGER_BYTE_LIMIT}-byte limit`,
      )
    }
    const wrapper = recordAt(JSON.parse(canonicalInput), '')
    exactKeys(
      wrapper,
      ['formatVersion', 'format', 'domain', 'slug', 'title', 'current', 'currentDigest', 'history'],
      ['conceptSlug'],
      '',
    )
    if (wrapper.formatVersion !== 3) invalid('invalid-version', '/formatVersion', 'must equal 3')
    if (wrapper.format !== 'atlas-audit-v3') invalid('invalid-format', '/format', 'must equal atlas-audit-v3')
    if (wrapper.domain !== 'security') invalid('invalid-domain', '/domain', 'V3 currently supports security only')
    const slug = stringAt(wrapper.slug, '/slug')
    if (!SECURITY_SLUG_RE.test(slug)) invalid('invalid-slug', '/slug', 'must begin with security- and use lowercase kebab-case')
    const expectedPath = `.atlas/audits/${slug}.json`
    if (normalizedPath !== expectedPath) invalid('filename-mismatch', '/slug', `ledger path must be ${expectedPath}`)
    stringAt(wrapper.title, '/title')
    if (wrapper.conceptSlug !== undefined) {
      const conceptSlug = stringAt(wrapper.conceptSlug, '/conceptSlug')
      if (!KEBAB_RE.test(conceptSlug)) invalid('invalid-slug', '/conceptSlug', 'must use lowercase kebab-case')
    }
    const current = parseObservation(
      root,
      slug,
      wrapper.current,
      '/current',
      context,
    )
    const currentDigest = sha256At(wrapper.currentDigest, '/currentDigest')
    if (currentDigest !== computeAuditCanonicalDigest(current)) {
      invalid('current-digest-mismatch', '/currentDigest', 'does not match canonical current observation')
    }
    const history = recordAt(wrapper.history, '/history')
    exactKeys(history, ['path', 'observationId', 'entryDigest'], [], '/history')
    const historyPath = repoPathAt(history.path, '/history/path')
    const expectedHistoryPath = `.atlas/audit-history/${slug}.json`
    if (historyPath !== expectedHistoryPath) {
      invalid('history-path-mismatch', '/history/path', `must equal ${expectedHistoryPath}`)
    }
    if (history.observationId !== current.observationId) {
      invalid('history-observation-mismatch', '/history/observationId', 'must equal current.observationId')
    }
    sha256At(history.entryDigest, '/history/entryDigest')
    return { ok: true, value: wrapper as unknown as AtlasSecurityCurrentLedgerV3 }
  } catch (error) {
    return { ok: false, diagnostics: [diagnostic(error)] }
  }
}

export function parseAuditCurrentLedger(
  root: string,
  repoPath: string,
  value: unknown,
): AuditParseResult<AtlasSecurityCurrentLedgerV3> {
  return parseAuditCurrentLedgerWithContext(
    root,
    repoPath,
    value,
    createAuditValidationContext(),
  )
}

function parseAuditObservationHistoryWithContext(
  root: string,
  repoPath: string,
  value: unknown,
  context: AuditValidationContext,
): AuditParseResult<AuditObservationHistoryV3> {
  try {
    const normalizedPath = normalizeAuditRepoPath(repoPath)
    const canonicalInput = canonicalJson(value)
    const history = recordAt(JSON.parse(canonicalInput), '')
    exactKeys(
      history,
      ['formatVersion', 'format', 'domain', 'slug', 'entries'],
      [],
      '',
    )
    if (history.formatVersion !== 1) {
      invalid('invalid-version', '/formatVersion', 'must equal 1')
    }
    if (history.format !== 'atlas-audit-history-v1') {
      invalid(
        'invalid-format',
        '/format',
        'must equal atlas-audit-history-v1',
      )
    }
    if (history.domain !== 'security') {
      invalid('invalid-domain', '/domain', 'V3 history supports security only')
    }
    const slug = stringAt(history.slug, '/slug')
    if (!SECURITY_SLUG_RE.test(slug)) {
      invalid(
        'invalid-slug',
        '/slug',
        'must begin with security- and use lowercase kebab-case',
      )
    }
    const expectedPath = `.atlas/audit-history/${slug}.json`
    if (normalizedPath !== expectedPath) {
      invalid('filename-mismatch', '/slug', `history path must be ${expectedPath}`)
    }
    const entries = arrayAt(history.entries, '/entries')
    if (entries.length === 0) {
      invalid('missing-history-entry', '/entries', 'history must contain a genesis entry')
    }
    const observationIds = new Set<string>()
    const occurrenceIds = new Set<string>()
    let previousEntryDigest: AuditSha256 | null = null
    for (const [index, row] of entries.entries()) {
      const pointer = `/entries/${index}`
      const entry = recordAt(row, pointer)
      exactKeys(
        entry,
        [
          'observationId',
          'observationDigest',
          'previousEntryDigest',
          'observation',
          'entryDigest',
        ],
        [],
        pointer,
      )
      const observationId = stringAt(entry.observationId, `${pointer}/observationId`)
      if (!OBSERVATION_ID_RE.test(observationId)) {
        invalid(
          'invalid-observation-id',
          `${pointer}/observationId`,
          'must be an Atlas observation ID',
        )
      }
      if (observationIds.has(observationId)) {
        invalid(
          'duplicate',
          `${pointer}/observationId`,
          'history observation IDs must be unique',
        )
      }
      observationIds.add(observationId)
      const observationDigest = sha256At(
        entry.observationDigest,
        `${pointer}/observationDigest`,
      )
      const observationCanonical = canonicalJson(entry.observation)
      if (Buffer.byteLength(observationCanonical, 'utf8') > LEDGER_BYTE_LIMIT) {
        invalid(
          'ledger-byte-limit',
          `${pointer}/observation`,
          `canonical observation exceeds the ${LEDGER_BYTE_LIMIT}-byte limit`,
        )
      }
      const observation = parseObservation(
        root,
        slug,
        JSON.parse(observationCanonical),
        `${pointer}/observation`,
        context,
      )
      if (observation.observationId !== observationId) {
        invalid(
          'history-observation-mismatch',
          `${pointer}/observationId`,
          'must equal embedded observation.observationId',
        )
      }
      if (observationDigest !== computeAuditCanonicalDigest(observation)) {
        invalid(
          'history-observation-digest-mismatch',
          `${pointer}/observationDigest`,
          'does not seal the embedded observation',
        )
      }
      if (entry.previousEntryDigest !== previousEntryDigest) {
        invalid(
          'history-chain-mismatch',
          `${pointer}/previousEntryDigest`,
          index === 0
            ? 'genesis previousEntryDigest must be null'
            : 'must equal the prior entryDigest',
        )
      }
      const entryDigest = sha256At(entry.entryDigest, `${pointer}/entryDigest`)
      const expectedEntryDigest = computeAuditHistoryEntryDigest({
        observationId: observationId as AtlasObservationId,
        observationDigest,
        previousEntryDigest,
        observation,
      })
      if (entryDigest !== expectedEntryDigest) {
        invalid(
          'history-entry-digest-mismatch',
          `${pointer}/entryDigest`,
          'does not seal the history entry',
        )
      }
      for (const [findingIndex, finding] of observation.findings.entries()) {
        if (occurrenceIds.has(finding.occurrenceId)) {
          invalid(
            'duplicate',
            `${pointer}/observation/findings/${findingIndex}/occurrenceId`,
            'history occurrence IDs must be unique',
          )
        }
        occurrenceIds.add(finding.occurrenceId)
      }
      previousEntryDigest = entryDigest
    }
    return {
      ok: true,
      value: history as unknown as AuditObservationHistoryV3,
    }
  } catch (error) {
    return { ok: false, diagnostics: [diagnostic(error)] }
  }
}

export function parseAuditObservationHistory(
  root: string,
  repoPath: string,
  value: unknown,
): AuditParseResult<AuditObservationHistoryV3> {
  return parseAuditObservationHistoryWithContext(
    root,
    repoPath,
    value,
    createAuditValidationContext(),
  )
}

function safeAuditDirectoryPaths(root: string, repoDirectory: string): string[] {
  return listBoundedAuditDirectory(root, repoDirectory)
    .map((entry) => `${repoDirectory}/${entry}`)
}

function readOptionalAuditJson(
  root: string,
  repoPath: string,
  maxBytes?: number,
): unknown | null {
  return readOptionalAuditJsonDocument(root, repoPath, maxBytes)?.value ?? null
}

function readOptionalAuditJsonDocument(
  root: string,
  repoPath: string,
  maxBytes?: number,
): { bytes: Uint8Array; value: unknown } | null {
  const normalized = normalizeAuditRepoPath(repoPath)
  const parent = path.posix.dirname(normalized)
  const name = path.posix.basename(normalized)
  if (parent === '.') {
    throw new Error('optional audit JSON must live in a repository subdirectory')
  }
  const entries = listBoundedAuditDirectory(root, parent)
  if (!entries.includes(name)) return null
  return readBoundedAuditJsonDocument(root, normalized, maxBytes)
}

function resultError(
  result: { ok: false; diagnostics: AuditDiagnostic[] },
  subject: string,
): Error {
  return new Error(
    `${subject}: ${result.diagnostics.map((entry) =>
      `${entry.path || '/'} ${entry.message}`
    ).join('; ')}`,
  )
}

function stateDiagnostic(
  code: string,
  path: string,
  message: string,
): AuditDiagnostic {
  return { code, path, message }
}

function registerHistoryIdentityClaims(
  value: unknown,
  repoPath: string,
  context: AuditValidationContext,
): AuditDiagnostic[] {
  const diagnostics: AuditDiagnostic[] = []
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return diagnostics
  }
  const entries = (value as Record<string, unknown>).entries
  if (!Array.isArray(entries)) return diagnostics

  const register = (
    id: unknown,
    pointer: string,
    pattern: RegExp,
    owners: Map<string, string>,
    code: string,
    label: string,
  ): void => {
    if (typeof id !== 'string' || !pattern.test(id)) return
    const owner = owners.get(id)
    if (owner !== undefined && owner !== repoPath) {
      diagnostics.push(stateDiagnostic(
        code,
        `${repoPath}${pointer}`,
        `${label} ${id} collides across history ledgers ${owner} and ${repoPath}`,
      ))
      return
    }
    owners.set(id, repoPath)
  }

  for (const [entryIndex, candidate] of entries.entries()) {
    if (
      candidate === null ||
      typeof candidate !== 'object' ||
      Array.isArray(candidate)
    ) {
      continue
    }
    const entry = candidate as Record<string, unknown>
    register(
      entry.observationId,
      `/entries/${entryIndex}/observationId`,
      OBSERVATION_ID_RE,
      context.historyObservationIds,
      'audit-history-observation-id-collision',
      'observation ID',
    )
    const observation = entry.observation
    if (
      observation === null ||
      typeof observation !== 'object' ||
      Array.isArray(observation)
    ) {
      continue
    }
    const findings = (observation as Record<string, unknown>).findings
    if (!Array.isArray(findings)) continue
    for (const [findingIndex, findingCandidate] of findings.entries()) {
      if (
        findingCandidate === null ||
        typeof findingCandidate !== 'object' ||
        Array.isArray(findingCandidate)
      ) {
        continue
      }
      register(
        (findingCandidate as Record<string, unknown>).occurrenceId,
        `/entries/${entryIndex}/observation/findings/${findingIndex}/occurrenceId`,
        OCCURRENCE_ID_RE,
        context.historyOccurrenceIds,
        'audit-history-occurrence-id-collision',
        'occurrence ID',
      )
    }
  }
  return diagnostics
}

function currentHistoryIndex(
  ledger: AtlasSecurityCurrentLedgerV3,
  history: AuditObservationHistoryV3,
): number {
  if (
    ledger.slug !== history.slug ||
    ledger.history.path !== `.atlas/audit-history/${ledger.slug}.json`
  ) {
    throw new Error('current ledger and history slug/path do not match')
  }
  const index = history.entries.findIndex((entry) =>
    entry.entryDigest === ledger.history.entryDigest
  )
  if (index < 0) {
    throw new Error('current ledger history reference is missing from the history chain')
  }
  const entry = history.entries[index]
  if (
    entry.observationId !== ledger.current.observationId ||
    ledger.history.observationId !== ledger.current.observationId ||
    entry.observationDigest !== ledger.currentDigest ||
    canonicalJson(entry.observation) !== canonicalJson(ledger.current)
  ) {
    throw new Error('current observation does not exactly match its history entry')
  }
  return index
}

function loadAuditObservationHistoryWithContext(
  root: string,
  context: AuditValidationContext,
): AuditObservationHistoryLoadResult {
  const histories: AuditObservationHistoryV3[] = []
  const diagnostics: AuditDiagnostic[] = []
  let paths: string[]
  try {
    paths = safeAuditDirectoryPaths(root, '.atlas/audit-history')
  } catch (error) {
    return {
      histories,
      diagnostics: [stateDiagnostic(
        'audit-history-directory-invalid',
        '.atlas/audit-history',
        error instanceof Error ? error.message : String(error),
      )],
    }
  }
  for (const repoPath of paths) {
    if (!repoPath.endsWith('.json')) {
      diagnostics.push(stateDiagnostic(
        'audit-history-unexpected-entry',
        repoPath,
        'audit history directory entries must be JSON files',
      ))
      continue
    }
    try {
      const raw = readBoundedAuditJson(root, repoPath)
      const identityDiagnostics = registerHistoryIdentityClaims(
        raw,
        repoPath,
        context,
      )
      diagnostics.push(...identityDiagnostics)
      const parsed = parseAuditObservationHistoryWithContext(
        root,
        repoPath,
        raw,
        context,
      )
      if (parsed.ok && identityDiagnostics.length === 0) {
        histories.push(parsed.value)
      } else {
        if (!parsed.ok) {
          diagnostics.push(...parsed.diagnostics.map((entry) => ({
            ...entry,
            path: `${repoPath}${entry.path}`,
          })))
        }
      }
    } catch (error) {
      diagnostics.push(stateDiagnostic(
        'audit-history-read-failed',
        repoPath,
        error instanceof Error ? error.message : String(error),
      ))
    }
  }
  histories.sort((left, right) => utf16Compare(left.slug, right.slug))
  return { histories, diagnostics }
}

export function loadAuditObservationHistory(
  root: string,
): AuditObservationHistoryLoadResult {
  return loadAuditObservationHistoryWithContext(
    root,
    createAuditValidationContext(),
  )
}

export function loadAuditObservations(root: string): AuditObservationLoadResult {
  const observations: AtlasSecurityCurrentLedgerV3[] = []
  const historyAhead: string[] = []
  const context = createAuditValidationContext()
  const historyResult = loadAuditObservationHistoryWithContext(root, context)
  const diagnostics = [...historyResult.diagnostics]
  const historyBySlug = new Map(
    historyResult.histories.map((history) => [history.slug, history]),
  )
  const currentBySlug = new Map<string, AtlasSecurityCurrentLedgerV3>()
  let paths: string[]
  try {
    paths = safeAuditDirectoryPaths(root, '.atlas/audits')
  } catch (error) {
    return {
      observations,
      historyAhead,
      diagnostics: [...diagnostics, stateDiagnostic(
        'audit-current-directory-invalid',
        '.atlas/audits',
        error instanceof Error ? error.message : String(error),
      )],
    }
  }
  for (const repoPath of paths) {
    if (!repoPath.endsWith('.json')) {
      diagnostics.push(stateDiagnostic(
        'audit-current-unexpected-entry',
        repoPath,
        'audit current directory entries must be JSON files',
      ))
      continue
    }
    try {
      const raw = readBoundedAuditJson(root, repoPath, LEDGER_BYTE_LIMIT)
      if (
        !raw ||
        typeof raw !== 'object' ||
        Array.isArray(raw) ||
        (
          (raw as Record<string, unknown>).formatVersion !== 3 &&
          (raw as Record<string, unknown>).format !== 'atlas-audit-v3'
        )
      ) {
        continue
      }
      const parsed = parseAuditCurrentLedgerWithContext(
        root,
        repoPath,
        raw,
        context,
      )
      if (!parsed.ok) {
        diagnostics.push(...parsed.diagnostics.map((entry) => ({
          ...entry,
          path: `${repoPath}${entry.path}`,
        })))
        continue
      }
      currentBySlug.set(parsed.value.slug, parsed.value)
    } catch (error) {
      diagnostics.push(stateDiagnostic(
        'audit-current-read-failed',
        repoPath,
        error instanceof Error ? error.message : String(error),
      ))
    }
  }

  for (const [slug, ledger] of [...currentBySlug.entries()]
    .sort(([left], [right]) => utf16Compare(left, right))) {
    const history = historyBySlug.get(slug)
    if (!history) {
      diagnostics.push(stateDiagnostic(
        'audit-history-missing',
        ledger.history.path,
        'V3 current ledger has no valid observation history',
      ))
      continue
    }
    try {
      const index = currentHistoryIndex(ledger, history)
      const trailing = history.entries.length - index - 1
      if (trailing > 1) {
        throw new Error('more than one trailing history-ahead entry follows current')
      }
      observations.push(ledger)
      if (trailing === 1) historyAhead.push(slug)
      historyBySlug.delete(slug)
    } catch (error) {
      diagnostics.push(stateDiagnostic(
        'audit-current-history-mismatch',
        ledger.history.path,
        error instanceof Error ? error.message : String(error),
      ))
      historyBySlug.delete(slug)
    }
  }
  for (const [slug, history] of [...historyBySlug.entries()]
    .sort(([left], [right]) => utf16Compare(left, right))) {
    if (history.entries.length === 1) {
      historyAhead.push(slug)
    } else {
      diagnostics.push(stateDiagnostic(
        'audit-history-without-current',
        `.atlas/audit-history/${slug}.json`,
        'history without current may contain only one genesis history-ahead entry',
      ))
    }
  }
  observations.sort((left, right) => utf16Compare(left.slug, right.slug))
  historyAhead.sort(utf16Compare)
  return { observations, historyAhead, diagnostics }
}

function readHistoryForSlug(
  root: string,
  slug: string,
): AuditObservationHistoryV3 | null {
  const repoPath = `.atlas/audit-history/${slug}.json`
  const raw = readOptionalAuditJson(root, repoPath)
  if (raw === null) return null
  const parsed = parseAuditObservationHistory(root, repoPath, raw)
  if (!parsed.ok) throw resultError(parsed, 'invalid existing audit history')
  return parsed.value
}

function readCurrentForSlug(
  root: string,
  slug: string,
): AtlasSecurityCurrentLedgerV3 | null {
  const repoPath = `.atlas/audits/${slug}.json`
  const raw = readOptionalAuditJson(root, repoPath, LEDGER_BYTE_LIMIT)
  if (raw === null) return null
  const parsed = parseAuditCurrentLedger(root, repoPath, raw)
  if (!parsed.ok) throw resultError(parsed, 'invalid existing current ledger')
  return parsed.value
}

export function prepareAuditObservationPublication(
  root: string,
  observation: AtlasSecurityObservationV3,
  metadata: { slug: string; title?: string; conceptSlug?: string },
): PreparedAuditObservationPublication {
  assertSecuritySlug(metadata.slug)
  const slug = metadata.slug
  const title = metadata.title === undefined
    ? slug
    : stringAt(metadata.title, '/metadata/title')
  if (metadata.conceptSlug !== undefined && !KEBAB_RE.test(metadata.conceptSlug)) {
    throw new Error('publication conceptSlug must use lowercase kebab-case')
  }
  const observationCanonical = canonicalJson(observation)
  if (Buffer.byteLength(observationCanonical, 'utf8') > LEDGER_BYTE_LIMIT) {
    throw new Error(`canonical observation exceeds the ${LEDGER_BYTE_LIMIT}-byte limit`)
  }
  const observationSnapshot = JSON.parse(observationCanonical)
  let parsedObservation: AtlasSecurityObservationV3
  try {
    parsedObservation = parseObservation(
      root,
      slug,
      observationSnapshot,
      '/current',
      createAuditValidationContext(),
    )
  } catch (error) {
    throw new Error(
      `invalid observation for publication: ${diagnostic(error).path} ${diagnostic(error).message}`,
    )
  }
  const observationDigest = computeAuditCanonicalDigest(parsedObservation)
  const existingHistory = readHistoryForSlug(root, slug)
  const existingCurrent = readCurrentForSlug(root, slug)
  if (existingCurrent && !existingHistory) {
    throw new Error('existing V3 current ledger has no history')
  }
  if (
    existingCurrent?.current.observationId === parsedObservation.observationId &&
    (
      existingCurrent.title !== title ||
      existingCurrent.conceptSlug !== metadata.conceptSlug
    )
  ) {
    throw new Error(
      'same current observation conflicts with existing wrapper title or conceptSlug metadata',
    )
  }

  let existingEntry: AuditObservationHistoryEntryV3 | undefined
  if (existingHistory) {
    if (existingCurrent) {
      const currentIndex = currentHistoryIndex(existingCurrent, existingHistory)
      const trailing = existingHistory.entries.length - currentIndex - 1
      if (trailing > 1) {
        throw new Error('more than one trailing history-ahead entry follows current')
      }
      if (trailing === 1) {
        existingEntry = existingHistory.entries.at(-1)
        if (
          existingEntry?.observationId !== parsedObservation.observationId ||
          existingEntry.observationDigest !== observationDigest ||
          canonicalJson(existingEntry.observation) !== observationCanonical
        ) {
          throw new Error('publication must resume the existing trailing history-ahead entry')
        }
      }
    } else {
      if (existingHistory.entries.length !== 1) {
        throw new Error(
          'history without current may contain only one genesis history-ahead entry',
        )
      }
      existingEntry = existingHistory.entries[0]
      if (
        existingEntry.observationId !== parsedObservation.observationId ||
        existingEntry.observationDigest !== observationDigest ||
        canonicalJson(existingEntry.observation) !== observationCanonical
      ) {
        throw new Error('publication must resume the existing genesis history-ahead entry')
      }
    }
    const sameId = existingHistory.entries.find((entry) =>
      entry.observationId === parsedObservation.observationId
    )
    if (sameId) {
      if (
        sameId.observationDigest !== observationDigest ||
        canonicalJson(sameId.observation) !== observationCanonical
      ) {
        throw new Error('same observation ID conflicts with a different digest')
      }
      if (!existingEntry) {
        if (sameId !== existingHistory.entries.at(-1)) {
          throw new Error('publication cannot rewind to an older observation')
        }
        existingEntry = sameId
      }
    }
  }

  const previousEntryDigest = existingHistory?.entries.at(-1)?.entryDigest ?? null
  const entryCore = {
    observationId: parsedObservation.observationId,
    observationDigest,
    previousEntryDigest,
    observation: parsedObservation,
  }
  const historyEntry: AuditObservationHistoryEntryV3 = existingEntry ?? {
    ...entryCore,
    entryDigest: computeAuditHistoryEntryDigest(entryCore),
  }
  const entries = existingHistory
    ? (
        existingEntry
          ? [...existingHistory.entries]
          : [...existingHistory.entries, historyEntry]
      )
    : [historyEntry]
  const history: AuditObservationHistoryV3 = {
    formatVersion: 1,
    format: 'atlas-audit-history-v1',
    domain: 'security',
    slug,
    entries,
  }
  const ledger: AtlasSecurityCurrentLedgerV3 = {
    formatVersion: 3,
    format: 'atlas-audit-v3',
    domain: 'security',
    slug,
    title,
    ...(metadata.conceptSlug === undefined
      ? {}
      : { conceptSlug: metadata.conceptSlug }),
    current: parsedObservation,
    currentDigest: observationDigest,
    history: {
      path: `.atlas/audit-history/${slug}.json`,
      observationId: parsedObservation.observationId,
      entryDigest: historyEntry.entryDigest,
    },
  }
  const parsedLedger = parseAuditCurrentLedger(
    root,
    `.atlas/audits/${slug}.json`,
    ledger,
  )
  if (!parsedLedger.ok) throw resultError(parsedLedger, 'prepared current ledger is invalid')
  return {
    ledger: parsedLedger.value,
    historyEntry,
    currentBytes: `${canonicalJson(parsedLedger.value)}\n`,
    historyBytes: `${canonicalJson(history)}\n`,
  }
}

export function publishAuditObservation(
  root: string,
  ledger: AtlasSecurityCurrentLedgerV3,
): AuditObservationPublicationResult {
  return withAuditLock(root, () => {
    const candidateCanonical = canonicalJson(ledger)
    const candidateSnapshot = JSON.parse(candidateCanonical)
    const parsed = parseAuditCurrentLedger(
      root,
      `.atlas/audits/${candidateSnapshot.slug}.json`,
      candidateSnapshot,
    )
    if (!parsed.ok) throw resultError(parsed, 'publication ledger is invalid')
    const prepared = prepareAuditObservationPublication(
      root,
      parsed.value.current,
      {
        slug: parsed.value.slug,
        title: parsed.value.title,
        ...(parsed.value.conceptSlug === undefined
          ? {}
          : { conceptSlug: parsed.value.conceptSlug }),
      },
    )
    if (canonicalJson(prepared.ledger) !== canonicalJson(parsed.value)) {
      throw new Error('publication ledger no longer matches the live history head')
    }
    const historyPath = prepared.ledger.history.path
    const currentPath = `.atlas/audits/${prepared.ledger.slug}.json`
    const existingHistory = readOptionalAuditJsonDocument(root, historyPath)
    const historyLogicallyMatches = existingHistory !== null &&
      `${canonicalJson(existingHistory.value)}\n` === prepared.historyBytes
    const historyBytesMatch = existingHistory !== null &&
      Buffer.from(existingHistory.bytes).equals(
        Buffer.from(prepared.historyBytes, 'utf8'),
      )
    if (!historyBytesMatch) {
      atomicWriteAuditFile(root, historyPath, prepared.historyBytes)
    }
    const existingCurrent = readOptionalAuditJsonDocument(
      root,
      currentPath,
      LEDGER_BYTE_LIMIT,
    )
    const currentLogicallyMatches = existingCurrent !== null &&
      `${canonicalJson(existingCurrent.value)}\n` === prepared.currentBytes
    const currentBytesMatch = existingCurrent !== null &&
      Buffer.from(existingCurrent.bytes).equals(
        Buffer.from(prepared.currentBytes, 'utf8'),
      )
    if (!currentBytesMatch) {
      atomicWriteAuditFile(root, currentPath, prepared.currentBytes)
    }
    return {
      currentPath,
      historyPath,
      appendedObservationId: prepared.historyEntry.observationId,
      status: historyLogicallyMatches
        ? (currentLogicallyMatches ? 'already-current' : 'resumed')
        : 'appended',
    }
  })
}
