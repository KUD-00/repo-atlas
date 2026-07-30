import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import {
  AUDIT_LIMITS,
  atomicWriteAuditFile,
  canonicalJson,
  normalizeAuditRepoPath,
  parseBoundedAuditJsonBytes,
  readBoundedAuditBytes,
  readBoundedAuditJson,
  withAnchoredAuditGitCapability,
  withAnchoredAuditSupportSnapshot,
  withAuditLock,
} from './audit-core.js'
import type { AnchoredAuditGitCapability } from './audit-core.js'
import {
  computeAuditCanonicalDigest,
  computeAuditHistoryEntryDigest,
  computeAuditInventoryDigest,
  computeAuditScopeHash,
  computeAtlasFindingId,
  computeAtlasFingerprint,
  computeAtlasObservationId,
  computeAtlasOccurrenceId,
  computeExactScopeIdentityDigest,
  computeSemanticScopeIdentityDigest,
} from './audit-v3.js'
import {
  computeAuditDecisionEntryDigest,
  prepareAuditDecisionAppend,
} from './audit-decisions.js'
import { parseAuditReviewPolicyValue } from './audit-policy.js'
import type {
  AtlasFingerprintV1,
  AtlasSecurityCurrentLedgerV3,
  AtlasSecurityFindingV3,
  AtlasSecurityObservationV3,
  AuditDecisionEventInputV3,
  AuditDecisionEventV3,
  AuditDecisionLedgerV1,
  AuditFileReceiptV3,
  AuditFindingDispositionEventV3,
  AuditIdentityAliasReconciliationEventV3,
  AuditObservationHistoryEntryV3,
  AuditObservationHistoryV3,
  AuditScopeRetirementEventV3,
  AuditSha256,
} from './audit-v3-types.js'

const SOURCE_KIND = 'relayos-security-scan/v1'
const SOURCE_SCHEMA = 'relayos-security-scan/v1'
const CANDIDATE_SCHEMA = 'relayos-security-scan/candidates/v1'
const DISPOSITION_SCHEMA = 'relayos-security-scan/dispositions/v1'
const PROVENANCE_SCHEMA = 'relayos-security-scan/phase-zero-provenance/v1'
const CANONICAL_RULESET = 'relayos-security-v1'
const ADAPTER_NAME = 'repo-atlas/migration-v1'
const ADAPTER_VERSION = '0.1.0'
const CONVERTER_NAME = 'repo-atlas'
const CONVERTER_VERSION = '0.1.0'
const CONVERTER_COMMIT = 'unreleased'
const DEFAULT_SOURCE_ROOT = 'audits/security-scan'
const MIGRATION_ACTOR = 'migration:relayos-security-v1'
const SOURCE_NAMES = [
  'ledger.json',
  'candidates.v1.json',
  'dispositions.v1.json',
  'phase-zero-provenance.v1.json',
] as const
const SHA1_RE = /^[0-9a-f]{40}$/u
const SHA256_RE = /^[0-9a-f]{64}$/u
const FULL_REVISION_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u
const CANDIDATE_ID_RE = /^SEC-[0-9A-F]{12}$/u
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/u
const SOURCE_BYTES = 8 * 1024 * 1024
const POLICY_PATH = '.atlas/review-policy.json'
const POLICY_SCHEMA = 'atlas-review-policy-v1'
const LEGACY_POLICY_SCHEMA = 'relayos-review-policy-v1'
const POLICY_UNIT_RE = /^security-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u

type Picomatch = (
  glob: string,
  options?: { dot?: boolean },
) => (candidate: string) => boolean

const picomatch = createRequire(import.meta.url)('picomatch') as Picomatch

type JsonRecord = Record<string, unknown>
type LegacySeverity = 'high' | 'medium' | 'low' | 'info'
type LegacyDispositionStatus =
  | 'remediated'
  | 'separate_design'
  | 'accepted_risk'
  | 'false_positive'
  | 'superseded'

interface LegacyRetirement {
  reason: 'deleted' | 'uncommitted_snapshot_absent'
  retiredAt: string
  deletionCommit: string | null
  successorPath: string | null
  evidence: string
}

interface LegacyScan {
  sourceIndex: number
  path: string
  git_blob_sha1: string
  lines: number
  scanned_at: string
  scanned_by: string
  ruleset: string
  status: 'clean' | 'findings'
  max_severity: LegacySeverity | null
  finding_count: number
  findings_ref: string | null
  note?: string
  remediated?: {
    commit: string
    at: string
    fix_blob_sha1: string
    note?: string
  }
  retired?: LegacyRetirement
}

interface LegacyLedger {
  schema: typeof SOURCE_SCHEMA
  ruleset: {
    id: string
    categories: string[]
  }
  scanner: {
    name: string
    method: string
    run: string
  }
  note: string
  scans: LegacyScan[]
}

interface LegacyCandidate {
  sourceIndex: number
  recordKind: 'current_candidate' | 'historical_remediation'
  sourceKind: 'round9' | 'legacy_ledger' | 'atlas_import'
  sourceRound: string
  sourceOrdinal: number
  sourceLocator: string
  path: string
  symbolLocation: string
  category: string
  title: string
  normalizedTitle: string
  severity: LegacySeverity
  sourceBlob: string
  fixBlob: string | null
  identityKey: string
  detail: string
  recommendedFix: string
  id: string
  duplicateOf?: string
  remediationCommit?: string
}

interface LegacyCandidates {
  schema: typeof CANDIDATE_SCHEMA
  generatedFrom: {
    round9ResultFiles: string[]
    phaseZeroProvenance: string
    atlasImport: string
  }
  counts: {
    sourceRecords: number
    historicalRemediations: number
    currentCandidateRecords: number
    duplicateRecords: number
    canonicalCurrentFindings: number
    canonicalHistoricalFindings: number
    canonicalFindings: number
  }
  entries: LegacyCandidate[]
}

interface LegacyDisposition {
  sourceIndex: number
  id: string
  sourceBlob: string
  owner: string
  evidence: string[]
  status: LegacyDispositionStatus
  rationale: string
  fixBlob: string | null
  expiresAt: string | null
  postFixScan?: {
    artifact: string
    fixBlob: string
  }
  currentScan?: {
    artifact: string
    reviewedBlob: string
  } | null
  regression?: {
    kind: 'test' | 'guardrail' | 'check'
    name: string
    command: string
    result: 'passed'
  }
  reviewedBlob?: string | null
  sourceEvidence?: unknown
  deletionCommit?: string | null
  replacementId?: string | null
  noReplacementEvidence?: unknown
  reviews?: unknown[]
}

interface LegacyDispositions {
  schema: typeof DISPOSITION_SCHEMA
  dispositions: LegacyDisposition[]
}

interface LegacyProvenance {
  schema: typeof PROVENANCE_SCHEMA
  legacyRecords: JsonRecord[]
  round9SourceBlobs: Record<string, string>
}

interface SourceDocument {
  path: string
  bytes: Buffer
  sha256: string
  gitBlob: string
}

interface ParsedSource {
  ledger: LegacyLedger
  candidates: LegacyCandidates
  dispositions: LegacyDispositions
  provenance: LegacyProvenance
  policy: MigrationPolicy
  documents: SourceDocument[]
}

interface MigrationPolicyUnit {
  slug: string
  title: string
  include: string[]
  except: string[]
}

interface MigrationHistoricalAssignment {
  id: string
  unit: string
  include: string[]
}

interface MigrationPolicy {
  schema: typeof POLICY_SCHEMA | typeof LEGACY_POLICY_SCHEMA
  units: MigrationPolicyUnit[]
  historicalAssignments: MigrationHistoricalAssignment[]
  digest: AuditSha256
}

interface CurrentFileState {
  sha1: string
  sha256: string
  bytes?: Buffer
}

interface MigrationContext {
  root: string
  scanRoot: string
  repositoryId: string
  sourceRevision: string
  validationRevision: string
  recordedAt: string
  source: ParsedSource
  policySeal: { path: string; gitBlob: string; sha256: string }
  historicalAssignmentsDigest: AuditSha256
  sourceSemanticDigest: AuditSha256
  rulesetDigest: AuditSha256
  targetDigest: AuditSha256
  targetId: string
  migrationId: string
  currentFiles: Map<string, CurrentFileState | null>
  blobLineCounts: Map<string, number>
  pathUnits: Map<string, string>
  unitTitles: Map<string, string>
  policyDigest: AuditSha256
}

interface PlannedOutput {
  path: string
  bytes: string
  sha256: string
  family: 'history' | 'decision' | 'current' | 'receipt'
}

export interface RelayOSMigrationOptions {
  scanRoot?: string
  policyPath?: string
  sourceRevision: string
  validationRevision: string
  includeHistory?: boolean
  apply?: boolean
}

interface NormalizedMigrationOptions {
  scanRoot: string
  policyPath: string
  sourceRevision: string
  validationRevision: string
  includeHistory: boolean
  apply: boolean
}

export interface AuditMigrationReceiptV3 {
  formatVersion: 1
  format: 'atlas-audit-migration-v1'
  migrationId: string
  repositoryId: string
  source: {
    kind: typeof SOURCE_KIND
    repositoryRevision: string
    files: Array<{
      path: string
      gitBlob: string
      sha256: string
    }>
  }
  validation: {
    repositoryRevision: string
    policy: {
      path: string
      gitBlob: string
      sha256: string
    }
    historicalAssignmentsDigest: AuditSha256
    exactWorktreeMatches: number
    staleOrMissingPaths: number
    digest: AuditSha256
  }
  converter: {
    name: string
    version: string
    commit: string
  }
  recordedAt: string
  recordedAtBasis: 'source-revision'
  counts: {
    scanRecords: number
    activeScanRecords: number
    retiredScanRecords: number
    activeClean: number
    activeFindings: number
    activeFindingOccurrences: number
    candidateSourceRecords: number
    canonicalFindings: number
    duplicateCandidates: number
    dispositions: {
      remediated: number
      separateDesign: number
      acceptedRisk: number
      falsePositive: number
      superseded: number
    }
  }
  mappings: Array<{
    sourcePath: string
    sourcePointer: string
    sourceId: string
    destinationKind:
      | 'file-receipt'
      | 'finding'
      | 'identity-alias'
      | 'decision'
      | 'retirement'
    destinationIds: string[]
  }>
  unmapped: []
  outputs: Array<{ path: string; sha256: string }>
  parityChecks: Array<{
    name: string
    status: 'passed'
    details: string
  }>
  safeToDelete: []
  receiptDigest: AuditSha256
}

export interface RelayOSMigrationResult {
  migrationId: string
  receipt: AuditMigrationReceiptV3
  observations: AtlasSecurityObservationV3[]
  decisionEvents: AuditFindingDispositionEventV3[]
  retirementEvents: AuditScopeRetirementEventV3[]
  reconciliationEvents: AuditIdentityAliasReconciliationEventV3[]
  writes: Array<{ path: string; sha256: string }>
}

export class RelayOSMigrationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RelayOSMigrationError'
  }
}

function fail(pointer: string, message: string): never {
  throw new RelayOSMigrationError(
    `RelayOS legacy migration ${pointer}: ${message}`,
  )
}

function recordAt(value: unknown, pointer: string): JsonRecord {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(pointer, 'expected a plain JSON object')
  }
  return value as JsonRecord
}

function arrayAt(value: unknown, pointer: string): unknown[] {
  if (!Array.isArray(value)) fail(pointer, 'expected an array')
  return value
}

function exactKeys(
  value: JsonRecord,
  required: readonly string[],
  optional: readonly string[],
  pointer: string,
): void {
  const allowed = new Set([...required, ...optional])
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`${pointer}/${key}`, 'unknown source field')
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) fail(`${pointer}/${key}`, 'missing source field')
  }
}

function stringAt(value: unknown, pointer: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    fail(pointer, 'expected a nonempty string')
  }
  if (Buffer.byteLength(value, 'utf8') > 256 * 1024) {
    fail(pointer, 'text exceeds the 262144-byte migration limit')
  }
  return value
}

function integerAt(value: unknown, pointer: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    fail(pointer, `expected a safe integer >= ${minimum}`)
  }
  return value as number
}

function sha1At(value: unknown, pointer: string): string {
  const parsed = stringAt(value, pointer)
  if (!SHA1_RE.test(parsed)) fail(pointer, 'expected a lowercase Git SHA-1')
  return parsed
}

function nullableSha1At(value: unknown, pointer: string): string | null {
  return value === null ? null : sha1At(value, pointer)
}

function dateAt(value: unknown, pointer: string): string {
  const parsed = stringAt(value, pointer)
  if (
    !DATE_RE.test(parsed) ||
    new Date(`${parsed}T00:00:00.000Z`).toISOString() !==
      `${parsed}T00:00:00.000Z`
  ) {
    fail(pointer, 'expected a real YYYY-MM-DD calendar date')
  }
  return parsed
}

function timestampAt(value: unknown, pointer: string): string {
  const parsed = stringAt(value, pointer)
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(parsed) ||
    Number.isNaN(Date.parse(parsed))
  ) {
    fail(pointer, 'expected a canonical UTC timestamp')
  }
  return new Date(parsed).toISOString()
}

function repoPathAt(value: unknown, pointer: string): string {
  try {
    const parsed = normalizeAuditRepoPath(stringAt(value, pointer))
    if (parsed.normalize('NFC') !== parsed) {
      fail(pointer, 'repository path must use NFC normalization')
    }
    return parsed
  } catch (error) {
    fail(
      pointer,
      error instanceof Error ? error.message : 'invalid repository path',
    )
  }
}

function stringsAt(value: unknown, pointer: string): string[] {
  const rows = arrayAt(value, pointer).map((row, index) =>
    stringAt(row, `${pointer}/${index}`))
  if (new Set(rows).size !== rows.length) fail(pointer, 'contains duplicates')
  return rows
}

function rawSha256(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function prefixedSha256(value: unknown): AuditSha256 {
  return computeAuditCanonicalDigest(value)
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function normalizeDate(date: string): string {
  return `${date}T00:00:00.000Z`
}

function normalizeSeverity(value: LegacySeverity): AtlasSecurityFindingV3['severity']['level'] {
  return value === 'info' ? 'informational' : value
}

function normalizeRulePart(value: string): string {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9._/-]+/gu, '-')
    .replace(/-+/gu, '-')
    .replace(/^[-./]+|[-./]+$/gu, '')
  return normalized.length === 0 ? 'legacy-finding' : normalized
}

function gitText(bytes: Uint8Array, pointer: string): string {
  const text = Buffer.from(bytes).toString('utf8').trim()
  if (text.length === 0) fail(pointer, 'Git returned an empty value')
  return text
}

function parseRetirement(
  value: unknown,
  pointer: string,
): LegacyRetirement {
  const retirement = recordAt(value, pointer)
  exactKeys(
    retirement,
    ['reason', 'retiredAt', 'deletionCommit', 'successorPath', 'evidence'],
    [],
    pointer,
  )
  if (
    retirement.reason !== 'deleted' &&
    retirement.reason !== 'uncommitted_snapshot_absent'
  ) {
    fail(`${pointer}/reason`, 'unsupported retirement reason')
  }
  const retiredAt = dateAt(retirement.retiredAt, `${pointer}/retiredAt`)
  const deletionCommit = retirement.deletionCommit === null
    ? null
    : stringAt(retirement.deletionCommit, `${pointer}/deletionCommit`)
  if (
    retirement.reason === 'deleted' &&
    (deletionCommit === null || !FULL_REVISION_RE.test(deletionCommit))
  ) {
    fail(
      `${pointer}/deletionCommit`,
      'deleted retirement requires a full Git commit',
    )
  }
  if (
    retirement.reason === 'uncommitted_snapshot_absent' &&
    deletionCommit !== null
  ) {
    fail(
      `${pointer}/deletionCommit`,
      'uncommitted snapshot absence forbids a deletion commit',
    )
  }
  const successorPath = retirement.successorPath === null
    ? null
    : repoPathAt(retirement.successorPath, `${pointer}/successorPath`)
  return {
    reason: retirement.reason,
    retiredAt,
    deletionCommit,
    successorPath,
    evidence: stringAt(retirement.evidence, `${pointer}/evidence`),
  }
}

function parseScan(value: unknown, index: number): LegacyScan {
  const pointer = `/ledger.json/scans/${index}`
  const scan = recordAt(value, pointer)
  exactKeys(
    scan,
    [
      'path',
      'git_blob_sha1',
      'lines',
      'scanned_at',
      'scanned_by',
      'ruleset',
      'status',
      'max_severity',
      'finding_count',
      'findings_ref',
    ],
    ['note', 'remediated', 'retired'],
    pointer,
  )
  const status = scan.status
  if (status !== 'clean' && status !== 'findings') {
    fail(`${pointer}/status`, 'expected clean or findings')
  }
  const findingCount = integerAt(
    scan.finding_count,
    `${pointer}/finding_count`,
  )
  const maxSeverity = scan.max_severity === null
    ? null
    : stringAt(scan.max_severity, `${pointer}/max_severity`)
  if (
    maxSeverity !== null &&
    !['high', 'medium', 'low', 'info'].includes(maxSeverity)
  ) {
    fail(`${pointer}/max_severity`, 'unsupported legacy severity')
  }
  const findingsRef = scan.findings_ref === null
    ? null
    : stringAt(scan.findings_ref, `${pointer}/findings_ref`)
  if (
    (status === 'clean' &&
      (findingCount !== 0 || maxSeverity !== null)) ||
    (status === 'findings' &&
      (findingCount < 1 || maxSeverity === null || findingsRef === null))
  ) {
    fail(pointer, 'status, count, severity, and findings reference disagree')
  }
  const ruleset = stringAt(scan.ruleset, `${pointer}/ruleset`)
  if (ruleset !== 'relayos-secscan-v1') {
    fail(`${pointer}/ruleset`, 'unexpected legacy ruleset')
  }
  let remediated: LegacyScan['remediated']
  if (scan.remediated !== undefined) {
    const source = recordAt(scan.remediated, `${pointer}/remediated`)
    exactKeys(
      source,
      ['commit', 'at', 'fix_blob_sha1'],
      ['note'],
      `${pointer}/remediated`,
    )
    remediated = {
      commit: stringAt(source.commit, `${pointer}/remediated/commit`),
      at: dateAt(source.at, `${pointer}/remediated/at`),
      fix_blob_sha1: sha1At(
        source.fix_blob_sha1,
        `${pointer}/remediated/fix_blob_sha1`,
      ),
      ...(source.note === undefined
        ? {}
        : { note: stringAt(source.note, `${pointer}/remediated/note`) }),
    }
  }
  return {
    sourceIndex: index,
    path: repoPathAt(scan.path, `${pointer}/path`),
    git_blob_sha1: sha1At(
      scan.git_blob_sha1,
      `${pointer}/git_blob_sha1`,
    ),
    lines: integerAt(scan.lines, `${pointer}/lines`),
    scanned_at: dateAt(scan.scanned_at, `${pointer}/scanned_at`),
    scanned_by: stringAt(scan.scanned_by, `${pointer}/scanned_by`),
    ruleset,
    status,
    max_severity: maxSeverity as LegacySeverity | null,
    finding_count: findingCount,
    findings_ref: findingsRef,
    ...(scan.note === undefined
      ? {}
      : { note: stringAt(scan.note, `${pointer}/note`) }),
    ...(remediated === undefined ? {} : { remediated }),
    ...(scan.retired === undefined
      ? {}
      : { retired: parseRetirement(scan.retired, `${pointer}/retired`) }),
  }
}

function parseLedger(value: unknown): LegacyLedger {
  const ledger = recordAt(value, '/ledger.json')
  exactKeys(
    ledger,
    ['schema', 'ruleset', 'scanner', 'note', 'scans'],
    [],
    '/ledger.json',
  )
  if (ledger.schema !== SOURCE_SCHEMA) {
    fail('/ledger.json/schema', `expected ${SOURCE_SCHEMA}`)
  }
  const ruleset = recordAt(ledger.ruleset, '/ledger.json/ruleset')
  exactKeys(
    ruleset,
    ['id', 'categories'],
    [],
    '/ledger.json/ruleset',
  )
  const rulesetId = stringAt(ruleset.id, '/ledger.json/ruleset/id')
  if (rulesetId !== 'relayos-secscan-v1') {
    fail('/ledger.json/ruleset/id', 'unexpected legacy ruleset ID')
  }
  const categories = stringsAt(
    ruleset.categories,
    '/ledger.json/ruleset/categories',
  )
  const scanner = recordAt(ledger.scanner, '/ledger.json/scanner')
  exactKeys(
    scanner,
    ['name', 'method', 'run'],
    [],
    '/ledger.json/scanner',
  )
  const scans = arrayAt(ledger.scans, '/ledger.json/scans')
    .map(parseScan)
    .sort((left, right) => compareText(left.path, right.path))
  if (scans.length > 10_000) fail('/ledger.json/scans', 'exceeds 10000 rows')
  for (let index = 1; index < scans.length; index += 1) {
    if (scans[index].path === scans[index - 1].path) {
      fail('/ledger.json/scans', `duplicate scan path ${scans[index].path}`)
    }
  }
  return {
    schema: SOURCE_SCHEMA,
    ruleset: { id: rulesetId, categories },
    scanner: {
      name: stringAt(scanner.name, '/ledger.json/scanner/name'),
      method: stringAt(scanner.method, '/ledger.json/scanner/method'),
      run: stringAt(scanner.run, '/ledger.json/scanner/run'),
    },
    note: stringAt(ledger.note, '/ledger.json/note'),
    scans,
  }
}

function parseCandidate(value: unknown, index: number): LegacyCandidate {
  const pointer = `/candidates.v1.json/entries/${index}`
  const candidate = recordAt(value, pointer)
  exactKeys(
    candidate,
    [
      'recordKind',
      'sourceKind',
      'sourceRound',
      'sourceOrdinal',
      'sourceLocator',
      'path',
      'symbolLocation',
      'category',
      'title',
      'normalizedTitle',
      'severity',
      'sourceBlob',
      'fixBlob',
      'identityKey',
      'detail',
      'recommendedFix',
    ],
    ['id', 'duplicateOf', 'remediationCommit'],
    pointer,
  )
  if (
    candidate.recordKind !== 'current_candidate' &&
    candidate.recordKind !== 'historical_remediation'
  ) {
    fail(`${pointer}/recordKind`, 'unsupported candidate record kind')
  }
  if (
    candidate.sourceKind !== 'round9' &&
    candidate.sourceKind !== 'legacy_ledger' &&
    candidate.sourceKind !== 'atlas_import'
  ) {
    fail(`${pointer}/sourceKind`, 'unsupported candidate source kind')
  }
  const severity = stringAt(candidate.severity, `${pointer}/severity`)
  if (!['high', 'medium', 'low', 'info'].includes(severity)) {
    fail(`${pointer}/severity`, 'unsupported legacy severity')
  }
  const identityKey = stringAt(
    candidate.identityKey,
    `${pointer}/identityKey`,
  )
  if (!SHA256_RE.test(identityKey)) {
    fail(`${pointer}/identityKey`, 'expected a lowercase SHA-256 identity key')
  }
  const id = candidate.id === undefined
    ? `SEC-${identityKey.slice(0, 12).toUpperCase()}`
    : stringAt(candidate.id, `${pointer}/id`)
  if (candidate.id === undefined && candidate.duplicateOf === undefined) {
    fail(`${pointer}/id`, 'canonical candidate is missing its legacy ID')
  }
  if (
    !CANDIDATE_ID_RE.test(id) ||
    id !== `SEC-${identityKey.slice(0, 12).toUpperCase()}`
  ) {
    fail(`${pointer}/id`, 'does not match the legacy identity key')
  }
  const duplicateOf = candidate.duplicateOf === undefined
    ? undefined
    : stringAt(candidate.duplicateOf, `${pointer}/duplicateOf`)
  if (duplicateOf !== undefined && !CANDIDATE_ID_RE.test(duplicateOf)) {
    fail(`${pointer}/duplicateOf`, 'expected a legacy SEC-* candidate ID')
  }
  return {
    sourceIndex: index,
    recordKind: candidate.recordKind,
    sourceKind: candidate.sourceKind,
    sourceRound: stringAt(candidate.sourceRound, `${pointer}/sourceRound`),
    sourceOrdinal: integerAt(
      candidate.sourceOrdinal,
      `${pointer}/sourceOrdinal`,
      1,
    ),
    sourceLocator: stringAt(
      candidate.sourceLocator,
      `${pointer}/sourceLocator`,
    ),
    path: repoPathAt(candidate.path, `${pointer}/path`),
    symbolLocation: stringAt(
      candidate.symbolLocation,
      `${pointer}/symbolLocation`,
    ),
    category: stringAt(candidate.category, `${pointer}/category`),
    title: stringAt(candidate.title, `${pointer}/title`),
    normalizedTitle: stringAt(
      candidate.normalizedTitle,
      `${pointer}/normalizedTitle`,
    ),
    severity: severity as LegacySeverity,
    sourceBlob: sha1At(candidate.sourceBlob, `${pointer}/sourceBlob`),
    fixBlob: nullableSha1At(candidate.fixBlob, `${pointer}/fixBlob`),
    identityKey,
    detail: stringAt(candidate.detail, `${pointer}/detail`),
    recommendedFix: stringAt(
      candidate.recommendedFix,
      `${pointer}/recommendedFix`,
    ),
    id,
    ...(duplicateOf === undefined ? {} : { duplicateOf }),
    ...(candidate.remediationCommit === undefined
      ? {}
      : {
          remediationCommit: stringAt(
            candidate.remediationCommit,
            `${pointer}/remediationCommit`,
          ),
        }),
  }
}

function countAt(
  counts: JsonRecord,
  key: keyof LegacyCandidates['counts'],
): number {
  return integerAt(counts[key], `/candidates.v1.json/counts/${key}`)
}

function parseCandidates(value: unknown): LegacyCandidates {
  const candidates = recordAt(value, '/candidates.v1.json')
  exactKeys(
    candidates,
    ['schema', 'generatedFrom', 'counts', 'entries'],
    [],
    '/candidates.v1.json',
  )
  if (candidates.schema !== CANDIDATE_SCHEMA) {
    fail('/candidates.v1.json/schema', `expected ${CANDIDATE_SCHEMA}`)
  }
  const generated = recordAt(
    candidates.generatedFrom,
    '/candidates.v1.json/generatedFrom',
  )
  exactKeys(
    generated,
    ['round9ResultFiles', 'phaseZeroProvenance', 'atlasImport'],
    [],
    '/candidates.v1.json/generatedFrom',
  )
  const counts = recordAt(candidates.counts, '/candidates.v1.json/counts')
  exactKeys(
    counts,
    [
      'sourceRecords',
      'historicalRemediations',
      'currentCandidateRecords',
      'duplicateRecords',
      'canonicalCurrentFindings',
      'canonicalHistoricalFindings',
      'canonicalFindings',
    ],
    [],
    '/candidates.v1.json/counts',
  )
  const entries = arrayAt(candidates.entries, '/candidates.v1.json/entries')
    .map(parseCandidate)
    .sort((left, right) =>
      compareText(left.id, right.id) ||
      compareText(left.sourceLocator, right.sourceLocator))
  if (entries.length > 10_000) {
    fail('/candidates.v1.json/entries', 'exceeds 10000 rows')
  }
  const ids = new Set<string>()
  const locators = new Set<string>()
  for (const candidate of entries) {
    if (ids.has(candidate.id)) {
      fail('/candidates.v1.json/entries', `duplicate candidate ID ${candidate.id}`)
    }
    ids.add(candidate.id)
    if (locators.has(candidate.sourceLocator)) {
      fail(
        '/candidates.v1.json/entries',
        `duplicate source locator ${candidate.sourceLocator}`,
      )
    }
    locators.add(candidate.sourceLocator)
  }
  const canonicalIds = new Set(
    entries.filter((entry) => entry.duplicateOf === undefined)
      .map((entry) => entry.id),
  )
  for (const candidate of entries) {
    if (
      candidate.duplicateOf !== undefined &&
      !canonicalIds.has(candidate.duplicateOf)
    ) {
      fail(
        `/candidates.v1.json/entries/${candidate.sourceIndex}/duplicateOf`,
        'does not resolve to a canonical candidate',
      )
    }
  }
  const derived = {
    sourceRecords: entries.length,
    historicalRemediations: entries.filter((entry) =>
      entry.recordKind === 'historical_remediation').length,
    currentCandidateRecords: entries.filter((entry) =>
      entry.recordKind === 'current_candidate').length,
    duplicateRecords: entries.filter((entry) =>
      entry.duplicateOf !== undefined).length,
    canonicalCurrentFindings: entries.filter((entry) =>
      entry.recordKind === 'current_candidate' &&
      entry.duplicateOf === undefined).length,
    canonicalHistoricalFindings: entries.filter((entry) =>
      entry.recordKind === 'historical_remediation' &&
      entry.duplicateOf === undefined).length,
    canonicalFindings: canonicalIds.size,
  }
  for (const [key, expected] of Object.entries(derived)) {
    if (
      countAt(counts, key as keyof LegacyCandidates['counts']) !== expected
    ) {
      fail(
        `/candidates.v1.json/counts/${key}`,
        `declared count does not equal recomputed ${expected}`,
      )
    }
  }
  return {
    schema: CANDIDATE_SCHEMA,
    generatedFrom: {
      round9ResultFiles: stringsAt(
        generated.round9ResultFiles,
        '/candidates.v1.json/generatedFrom/round9ResultFiles',
      ),
      phaseZeroProvenance: repoPathAt(
        generated.phaseZeroProvenance,
        '/candidates.v1.json/generatedFrom/phaseZeroProvenance',
      ),
      atlasImport: repoPathAt(
        generated.atlasImport,
        '/candidates.v1.json/generatedFrom/atlasImport',
      ),
    },
    counts: derived,
    entries,
  }
}

function optionalArtifactBinding(
  value: unknown,
  pointer: string,
  blobKey: 'fixBlob' | 'reviewedBlob',
): { artifact: string; fixBlob: string } | {
  artifact: string
  reviewedBlob: string
} {
  const binding = recordAt(value, pointer)
  exactKeys(binding, ['artifact', blobKey], [], pointer)
  const common = {
    artifact: repoPathAt(binding.artifact, `${pointer}/artifact`),
  }
  return blobKey === 'fixBlob'
    ? {
        ...common,
        fixBlob: sha1At(binding.fixBlob, `${pointer}/fixBlob`),
      }
    : {
        ...common,
        reviewedBlob: sha1At(
          binding.reviewedBlob,
          `${pointer}/reviewedBlob`,
        ),
      }
}

function parseDisposition(
  value: unknown,
  index: number,
): LegacyDisposition {
  const pointer = `/dispositions.v1.json/dispositions/${index}`
  const disposition = recordAt(value, pointer)
  exactKeys(
    disposition,
    [
      'id',
      'sourceBlob',
      'owner',
      'evidence',
      'status',
      'rationale',
      'fixBlob',
      'expiresAt',
    ],
    [
      'postFixScan',
      'currentScan',
      'regression',
      'reviewedBlob',
      'sourceEvidence',
      'deletionCommit',
      'replacementId',
      'noReplacementEvidence',
      'reviews',
    ],
    pointer,
  )
  const id = stringAt(disposition.id, `${pointer}/id`)
  if (!CANDIDATE_ID_RE.test(id)) {
    fail(`${pointer}/id`, 'expected a legacy SEC-* candidate ID')
  }
  const status = stringAt(disposition.status, `${pointer}/status`)
  if (
    ![
      'remediated',
      'separate_design',
      'accepted_risk',
      'false_positive',
      'superseded',
    ].includes(status)
  ) {
    fail(`${pointer}/status`, 'unsupported legacy disposition')
  }
  const fixBlob = nullableSha1At(disposition.fixBlob, `${pointer}/fixBlob`)
  const expiresAt = disposition.expiresAt === null
    ? null
    : timestampAt(disposition.expiresAt, `${pointer}/expiresAt`)
  const evidence = stringsAt(disposition.evidence, `${pointer}/evidence`)
  const base: LegacyDisposition = {
    sourceIndex: index,
    id,
    sourceBlob: sha1At(disposition.sourceBlob, `${pointer}/sourceBlob`),
    owner: stringAt(disposition.owner, `${pointer}/owner`),
    evidence,
    status: status as LegacyDispositionStatus,
    rationale: stringAt(disposition.rationale, `${pointer}/rationale`),
    fixBlob,
    expiresAt,
  }
  if (disposition.reviewedBlob !== undefined) {
    base.reviewedBlob = nullableSha1At(
      disposition.reviewedBlob,
      `${pointer}/reviewedBlob`,
    )
  }
  if (disposition.postFixScan !== undefined) {
    base.postFixScan = optionalArtifactBinding(
      disposition.postFixScan,
      `${pointer}/postFixScan`,
      'fixBlob',
    ) as { artifact: string; fixBlob: string }
  }
  if (disposition.currentScan !== undefined) {
    base.currentScan = disposition.currentScan === null
      ? null
      : optionalArtifactBinding(
          disposition.currentScan,
          `${pointer}/currentScan`,
          'reviewedBlob',
        ) as { artifact: string; reviewedBlob: string }
  }
  if (disposition.regression !== undefined) {
    const regression = recordAt(
      disposition.regression,
      `${pointer}/regression`,
    )
    exactKeys(
      regression,
      ['kind', 'name', 'command', 'result'],
      [],
      `${pointer}/regression`,
    )
    if (
      regression.kind !== 'test' &&
      regression.kind !== 'guardrail' &&
      regression.kind !== 'check'
    ) {
      fail(`${pointer}/regression/kind`, 'unsupported regression kind')
    }
    if (regression.result !== 'passed') {
      fail(`${pointer}/regression/result`, 'migration requires a passing result')
    }
    base.regression = {
      kind: regression.kind,
      name: stringAt(regression.name, `${pointer}/regression/name`),
      command: stringAt(regression.command, `${pointer}/regression/command`),
      result: regression.result,
    }
  }
  if (Object.hasOwn(disposition, 'sourceEvidence')) {
    base.sourceEvidence = disposition.sourceEvidence
  }
  if (Object.hasOwn(disposition, 'deletionCommit')) {
    base.deletionCommit = disposition.deletionCommit === null
      ? null
      : stringAt(disposition.deletionCommit, `${pointer}/deletionCommit`)
  }
  if (Object.hasOwn(disposition, 'replacementId')) {
    base.replacementId = disposition.replacementId === null
      ? null
      : stringAt(disposition.replacementId, `${pointer}/replacementId`)
  }
  if (Object.hasOwn(disposition, 'noReplacementEvidence')) {
    base.noReplacementEvidence = disposition.noReplacementEvidence
  }
  if (Object.hasOwn(disposition, 'reviews')) {
    base.reviews = arrayAt(disposition.reviews, `${pointer}/reviews`)
  }

  if (base.status === 'remediated') {
    if (
      base.fixBlob === null ||
      base.postFixScan === undefined ||
      base.postFixScan.fixBlob !== base.fixBlob ||
      base.regression === undefined ||
      base.expiresAt !== null
    ) {
      fail(pointer, 'remediated disposition has inconsistent proof fields')
    }
  } else if (
    base.status === 'accepted_risk' ||
    base.status === 'separate_design'
  ) {
    if (
      base.reviewedBlob === undefined ||
      base.reviewedBlob === null ||
      base.currentScan === undefined ||
      base.currentScan === null ||
      base.currentScan.reviewedBlob !== base.reviewedBlob ||
      base.expiresAt === null
    ) {
      fail(pointer, 'current-review disposition has inconsistent proof fields')
    }
  } else if (base.status === 'false_positive') {
    if (
      base.reviewedBlob === undefined ||
      base.reviewedBlob === null ||
      base.currentScan === undefined ||
      base.currentScan === null ||
      base.currentScan.reviewedBlob !== base.reviewedBlob ||
      base.sourceEvidence === undefined ||
      base.expiresAt !== null
    ) {
      fail(pointer, 'false-positive disposition has inconsistent proof fields')
    }
  } else if (
    (
      base.replacementId === undefined ||
      base.replacementId === null
    ) &&
    (
      base.deletionCommit === undefined ||
      base.deletionCommit === null ||
      !FULL_REVISION_RE.test(base.deletionCommit) ||
      base.noReplacementEvidence === undefined
    )
  ) {
    fail(pointer, 'superseded disposition lacks replacement or deletion proof')
  }
  return base
}

function parseDispositions(value: unknown): LegacyDispositions {
  const document = recordAt(value, '/dispositions.v1.json')
  exactKeys(
    document,
    ['schema', 'dispositions'],
    [],
    '/dispositions.v1.json',
  )
  if (document.schema !== DISPOSITION_SCHEMA) {
    fail('/dispositions.v1.json/schema', `expected ${DISPOSITION_SCHEMA}`)
  }
  const dispositions = arrayAt(
    document.dispositions,
    '/dispositions.v1.json/dispositions',
  )
    .map(parseDisposition)
    .sort((left, right) => compareText(left.id, right.id))
  const ids = new Set<string>()
  for (const disposition of dispositions) {
    if (ids.has(disposition.id)) {
      fail(
        '/dispositions.v1.json/dispositions',
        `duplicate disposition ${disposition.id}`,
      )
    }
    ids.add(disposition.id)
  }
  return { schema: DISPOSITION_SCHEMA, dispositions }
}

function parseProvenance(value: unknown): LegacyProvenance {
  const document = recordAt(value, '/phase-zero-provenance.v1.json')
  exactKeys(
    document,
    ['schema', 'legacyRecords', 'round9SourceBlobs'],
    [],
    '/phase-zero-provenance.v1.json',
  )
  if (document.schema !== PROVENANCE_SCHEMA) {
    fail(
      '/phase-zero-provenance.v1.json/schema',
      `expected ${PROVENANCE_SCHEMA}`,
    )
  }
  const legacyRecords = arrayAt(
    document.legacyRecords,
    '/phase-zero-provenance.v1.json/legacyRecords',
  ).map((value_, index) =>
    recordAt(value_, `/phase-zero-provenance.v1.json/legacyRecords/${index}`))
  const sourceBlobs = recordAt(
    document.round9SourceBlobs,
    '/phase-zero-provenance.v1.json/round9SourceBlobs',
  )
  const round9SourceBlobs: Record<string, string> = {}
  for (const [unsafePath, value_] of Object.entries(sourceBlobs)) {
    const repoPath = repoPathAt(
      unsafePath,
      '/phase-zero-provenance.v1.json/round9SourceBlobs',
    )
    round9SourceBlobs[repoPath] = sha1At(
      value_,
      `/phase-zero-provenance.v1.json/round9SourceBlobs/${repoPath}`,
    )
  }
  return {
    schema: PROVENANCE_SCHEMA,
    legacyRecords,
    round9SourceBlobs,
  }
}

const RELAYOS_LEGACY_HISTORICAL_ASSIGNMENTS:
  readonly MigrationHistoricalAssignment[] = [
    {
      id: 'relayos-retired-daemon-host',
      unit: 'security-apps-runtime',
      include: ['apps/cloud-daemon-host/**'],
    },
    {
      id: 'relayos-retired-edge-apps',
      unit: 'security-apps-edge',
      include: [
        'apps/cloudflare-marketplace-worker/**',
        'apps/cloudflare-sandbox-worker/**',
        'apps/daemon-edge/**',
        'apps/telemetry-gateway-worker/**',
        'apps/telemetry-tail-worker/**',
      ],
    },
    {
      id: 'relayos-retired-web',
      unit: 'security-apps-product',
      include: ['apps/web/**'],
    },
  ]

function policyGlobsAt(
  value: unknown,
  pointer: string,
  nonempty: boolean,
): string[] {
  const rows = stringsAt(value, pointer)
  if (nonempty && rows.length === 0) fail(pointer, 'must not be empty')
  if (rows.length > 10_000) fail(pointer, 'contains too many globs')
  for (const [index, pattern] of rows.entries()) {
    if (
      pattern.includes('\0') ||
      Buffer.byteLength(pattern, 'utf8') > 4096
    ) {
      fail(`${pointer}/${index}`, 'glob is unsafe or exceeds 4096 bytes')
    }
    try {
      picomatch(pattern, { dot: true })
    } catch {
      fail(`${pointer}/${index}`, 'glob is invalid')
    }
  }
  return rows
}

function parseMigrationPolicy(
  value: unknown,
  policyPath: string,
): MigrationPolicy {
  const policy = recordAt(value, `/${policyPath}`)
  const schema = stringAt(policy.format, `/${policyPath}/format`)
  if (schema !== POLICY_SCHEMA && schema !== LEGACY_POLICY_SCHEMA) {
    fail(
      `/${policyPath}/format`,
      `expected ${POLICY_SCHEMA} or ${LEGACY_POLICY_SCHEMA}`,
    )
  }
  if (schema === POLICY_SCHEMA) {
    exactKeys(
      policy,
      ['formatVersion', 'format', 'rules', 'units', 'securityDecisions'],
      ['historicalUnitAssignments'],
      `/${policyPath}`,
    )
  } else {
    exactKeys(
      policy,
      ['formatVersion', 'format', 'rules', 'units'],
      [],
      `/${policyPath}`,
    )
  }
  if (policy.formatVersion !== 1) {
    fail(`/${policyPath}/formatVersion`, 'expected 1')
  }
  if (!Array.isArray(policy.rules)) {
    fail(`/${policyPath}/rules`, 'expected an array')
  }
  const units = arrayAt(policy.units, `/${policyPath}/units`)
    .map((value_, index): MigrationPolicyUnit | null => {
      const pointer = `/${policyPath}/units/${index}`
      const unit = recordAt(value_, pointer)
      exactKeys(
        unit,
        ['domain', 'slug', 'title', 'include'],
        ['except', 'context'],
        pointer,
      )
      if (unit.domain !== 'security' && unit.domain !== 'test') {
        fail(`${pointer}/domain`, 'expected security or test')
      }
      const slug = stringAt(unit.slug, `${pointer}/slug`)
      const title = stringAt(unit.title, `${pointer}/title`)
      const include = policyGlobsAt(
        unit.include,
        `${pointer}/include`,
        true,
      )
      const except = unit.except === undefined
        ? []
        : policyGlobsAt(unit.except, `${pointer}/except`, false)
      if (unit.context !== undefined) {
        policyGlobsAt(unit.context, `${pointer}/context`, false)
      }
      if (unit.domain === 'test') return null
      if (!POLICY_UNIT_RE.test(slug)) {
        fail(`${pointer}/slug`, 'expected a security-* kebab-case slug')
      }
      return { slug, title, include, except }
    })
    .filter((unit): unit is MigrationPolicyUnit => unit !== null)
    .sort((left, right) => compareText(left.slug, right.slug))
  const slugs = new Set<string>()
  for (const unit of units) {
    if (slugs.has(unit.slug)) {
      fail(`/${policyPath}/units`, `duplicate security unit ${unit.slug}`)
    }
    slugs.add(unit.slug)
  }
  if (units.length === 0) {
    fail(`/${policyPath}/units`, 'requires at least one security unit')
  }

  let historicalAssignments: MigrationHistoricalAssignment[]
  if (schema === POLICY_SCHEMA) {
    historicalAssignments = (
      policy.historicalUnitAssignments === undefined
        ? []
        : arrayAt(
            policy.historicalUnitAssignments,
            `/${policyPath}/historicalUnitAssignments`,
          ).map((value_, index) => {
            const pointer =
              `/${policyPath}/historicalUnitAssignments/${index}`
            const assignment = recordAt(value_, pointer)
            exactKeys(
              assignment,
              ['id', 'sourceKind', 'domain', 'unit', 'include'],
              [],
              pointer,
            )
            if (
              assignment.sourceKind !== SOURCE_KIND ||
              assignment.domain !== 'security'
            ) {
              fail(pointer, 'expected a RelayOS security assignment')
            }
            return {
              id: stringAt(assignment.id, `${pointer}/id`),
              unit: stringAt(assignment.unit, `${pointer}/unit`),
              include: policyGlobsAt(
                assignment.include,
                `${pointer}/include`,
                true,
              ),
            }
          })
    )
  } else {
    const legacyTargets = new Set(
      RELAYOS_LEGACY_HISTORICAL_ASSIGNMENTS.map(({ unit }) => unit),
    )
    historicalAssignments = [...legacyTargets].every((slug) =>
      slugs.has(slug))
      ? RELAYOS_LEGACY_HISTORICAL_ASSIGNMENTS.map((assignment) => ({
          ...assignment,
          include: [...assignment.include],
        }))
      : []
  }
  historicalAssignments.sort((left, right) =>
    compareText(left.id, right.id))
  const assignmentIds = new Set<string>()
  for (const assignment of historicalAssignments) {
    if (assignmentIds.has(assignment.id)) {
      fail(
        `/${policyPath}/historicalUnitAssignments`,
        `duplicate assignment ${assignment.id}`,
      )
    }
    assignmentIds.add(assignment.id)
    if (!slugs.has(assignment.unit)) {
      fail(
        `/${policyPath}/historicalUnitAssignments/${assignment.id}`,
        `references missing security unit ${assignment.unit}`,
      )
    }
  }
  return {
    schema,
    units,
    historicalAssignments,
    digest: computeAuditCanonicalDigest(value),
  }
}

function validateCrossSource(source: ParsedSource): void {
  const scansByPath = new Map(
    source.ledger.scans.map((scan) => [scan.path, scan]),
  )
  const canonicalCandidates = source.candidates.entries.filter(
    (candidate) => candidate.duplicateOf === undefined,
  )
  const canonicalIds = new Set(canonicalCandidates.map(({ id }) => id))
  const dispositions = new Map(
    source.dispositions.dispositions.map((disposition) => [
      disposition.id,
      disposition,
    ]),
  )
  if (
    dispositions.size !== canonicalIds.size ||
    [...canonicalIds].some((id) => !dispositions.has(id)) ||
    [...dispositions].some(([id]) => !canonicalIds.has(id))
  ) {
    fail(
      '/dispositions.v1.json/dispositions',
      'canonical candidates and dispositions are not one-to-one',
    )
  }
  for (const candidate of source.candidates.entries) {
    if (!scansByPath.has(candidate.path)) {
      fail(
        `/candidates.v1.json/entries/${candidate.sourceIndex}/path`,
        'candidate path has no legacy scan record',
      )
    }
    if (candidate.duplicateOf !== undefined) continue
    const disposition = dispositions.get(candidate.id)!
    if (disposition.sourceBlob !== candidate.sourceBlob) {
      fail(
        `/dispositions.v1.json/dispositions/${disposition.sourceIndex}/sourceBlob`,
        `does not match candidate ${candidate.id}`,
      )
    }
  }

  const legacyLocators = new Set<string>()
  for (const [index, row] of source.provenance.legacyRecords.entries()) {
    const sourceKind = stringAt(
      row.sourceKind,
      `/phase-zero-provenance.v1.json/legacyRecords/${index}/sourceKind`,
    )
    if (sourceKind !== 'legacy_ledger') {
      fail(
        `/phase-zero-provenance.v1.json/legacyRecords/${index}/sourceKind`,
        'expected legacy_ledger',
      )
    }
    legacyLocators.add(
      stringAt(
        row.sourceLocator,
        `/phase-zero-provenance.v1.json/legacyRecords/${index}/sourceLocator`,
      ),
    )
  }
  const candidateLegacyLocators = source.candidates.entries
    .filter(({ sourceKind }) => sourceKind === 'legacy_ledger')
    .map(({ sourceLocator }) => sourceLocator)
  if (
    legacyLocators.size !== candidateLegacyLocators.length ||
    candidateLegacyLocators.some((locator) => !legacyLocators.has(locator))
  ) {
    fail(
      '/phase-zero-provenance.v1.json/legacyRecords',
      'legacy candidate provenance is incomplete or inconsistent',
    )
  }
  for (const candidate of source.candidates.entries) {
    if (
      candidate.sourceKind === 'round9' &&
      source.provenance.round9SourceBlobs[candidate.path] !==
        candidate.sourceBlob
    ) {
      fail(
        `/phase-zero-provenance.v1.json/round9SourceBlobs/${candidate.path}`,
        `does not match round9 candidate ${candidate.id}`,
      )
    }
  }
}

function parseRepositoryId(root: string): string {
  const config = recordAt(
    readBoundedAuditJson(root, '.atlas/config.json', 1024 * 1024),
    '/.atlas/config.json',
  )
  const repositoryId = stringAt(
    config.repositoryId,
    '/.atlas/config.json/repositoryId',
  )
  if (!/^repo_[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/u.test(repositoryId)) {
    fail(
      '/.atlas/config.json/repositoryId',
      'expected a stable lowercase repo_ identity',
    )
  }
  return repositoryId
}

function semanticSourceValue(source: ParsedSource): unknown {
  return {
    ledger: {
      ...source.ledger,
      scans: source.ledger.scans.map(({ sourceIndex: _index, ...scan }) => scan),
    },
    candidates: {
      ...source.candidates,
      entries: source.candidates.entries.map(
        ({ sourceIndex: _index, ...candidate }) => candidate,
      ),
    },
    dispositions: {
      ...source.dispositions,
      dispositions: source.dispositions.dispositions.map(
        ({ sourceIndex: _index, ...disposition }) => disposition,
      ),
    },
    provenance: {
      ...source.provenance,
      legacyRecords: [...source.provenance.legacyRecords].sort((left, right) =>
        compareText(String(left.sourceLocator ?? ''), String(right.sourceLocator ?? ''))),
    },
    policy: source.policy,
  }
}

function verifyRevisionCommit(
  git: AnchoredAuditGitCapability,
  revision: string,
  role: 'sourceRevision' | 'validationRevision',
): void {
  let resolved: string
  try {
    resolved = gitText(
      git.gitBytes(['rev-parse', '--verify', `${revision}^{commit}`], 1024),
      `/git/${role}`,
    )
  } catch {
    fail(`/options/${role}`, 'does not name a commit in this repository')
  }
  if (resolved !== revision) {
    fail(`/options/${role}`, 'does not resolve to the exact named commit')
  }
}

function readVerifiedGitBlob(
  git: AnchoredAuditGitCapability,
  objectId: string,
  maxBytes: number,
  pointer: string,
): Buffer {
  if (!SHA1_RE.test(objectId)) {
    fail(pointer, 'expected a lowercase Git SHA-1 object identity')
  }
  let sizeText: string
  try {
    sizeText = gitText(
      git.gitBytes(['cat-file', '-s', objectId], 1024),
      pointer,
    )
  } catch {
    fail(pointer, 'listed Git blob is unreadable')
  }
  if (!/^(0|[1-9][0-9]*)$/u.test(sizeText)) {
    fail(pointer, 'Git returned an invalid blob size')
  }
  const size = Number(sizeText)
  if (!Number.isSafeInteger(size) || size > maxBytes) {
    fail(pointer, `Git blob exceeds the ${maxBytes}-byte limit`)
  }
  let bytes: Buffer
  try {
    bytes = Buffer.from(git.gitBytes(['cat-file', 'blob', objectId], maxBytes))
  } catch {
    fail(pointer, 'listed Git blob is unreadable')
  }
  if (bytes.byteLength !== size) {
    fail(pointer, 'Git blob byte length does not match its object size')
  }
  const verified = createHash('sha1')
    .update(`blob ${bytes.byteLength}\0`, 'utf8')
    .update(bytes)
    .digest('hex')
  if (verified !== objectId) {
    fail(pointer, 'Git returned bytes for a different blob')
  }
  return bytes
}

interface RevisionTreeFile {
  gitBlob: string
}

function resolveRevisionTreeFiles(
  git: AnchoredAuditGitCapability,
  revision: string,
  repoPaths: readonly string[],
  pointer: string,
): Map<string, RevisionTreeFile | null> {
  const requested = [...new Set(repoPaths)].sort(compareText)
  const resolved = new Map<string, RevisionTreeFile | null>()
  if (requested.length === 0) return resolved
  let listing: Buffer
  try {
    listing = Buffer.from(
      git.gitBytes(
        [
          'ls-tree',
          '--full-tree',
          '-z',
          revision,
          '--',
          ...requested.map((repoPath) => `:(literal)${repoPath}`),
        ],
        AUDIT_LIMITS.jsonBytes,
      ),
    )
  } catch {
    fail(pointer, 'unable to list the pinned revision tree')
  }
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(listing)
  } catch {
    fail(pointer, 'pinned revision tree listing is not strict UTF-8')
  }
  const records = text.split('\0')
  if (records.at(-1) === '') records.pop()
  const entries = new Map<string, RevisionTreeFile>()
  for (const record of records) {
    const match = /^([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40})\t([\s\S]+)$/u
      .exec(record)
    if (!match) {
      fail(pointer, 'Git returned a malformed tree entry')
    }
    const [, mode, type, objectId, entryPath] = match
    if (requested.includes(entryPath)) {
      if (type !== 'blob' || (mode !== '100644' && mode !== '100755')) {
        fail(
          `${pointer}/${entryPath}`,
          'revision tree entry is a symlink, gitlink, or non-regular file',
        )
      }
      const existing = entries.get(entryPath)
      if (existing !== undefined && existing.gitBlob !== objectId) {
        fail(`${pointer}/${entryPath}`, 'conflicting revision tree entries')
      }
      entries.set(entryPath, { gitBlob: objectId })
    }
  }
  for (const repoPath of requested) {
    const entry = entries.get(repoPath)
    if (entry !== undefined) {
      resolved.set(repoPath, entry)
      continue
    }
    const prefix = `${repoPath}/`
    if (records.some((record) => {
      const tab = record.indexOf('\t')
      return tab !== -1 && record.slice(tab + 1).startsWith(prefix)
    })) {
      fail(
        `${pointer}/${repoPath}`,
        'revision tree entry is a directory, not a regular file',
      )
    }
    resolved.set(repoPath, null)
  }
  return resolved
}

function readRevisionFile(
  git: AnchoredAuditGitCapability,
  revision: string,
  repoPath: string,
  maxBytes: number,
  pointer: string,
): { bytes: Buffer; gitBlob: string } | null {
  const entry = resolveRevisionTreeFiles(
    git,
    revision,
    [repoPath],
    pointer,
  ).get(repoPath)
  if (entry === undefined || entry === null) return null
  return {
    bytes: readVerifiedGitBlob(
      git,
      entry.gitBlob,
      maxBytes,
      `${pointer}/${repoPath}`,
    ),
    gitBlob: entry.gitBlob,
  }
}

function readSource(
  git: AnchoredAuditGitCapability,
  options: NormalizedMigrationOptions,
): Omit<ParsedSource, 'documents'> & {
  rawDocuments: Array<{ path: string; bytes: Buffer; gitBlob: string }>
  policySeal: { path: string; gitBlob: string; sha256: string }
} {
  const documents = new Map<
    string,
    { path: string; bytes: Buffer; gitBlob: string; value: unknown }
  >()
  for (const name of SOURCE_NAMES) {
    const repoPath = `${options.scanRoot}/${name}`
    const document = readRevisionFile(
      git,
      options.sourceRevision,
      repoPath,
      SOURCE_BYTES,
      '/source',
    )
    if (document === null) {
      fail(
        `/source/${repoPath}`,
        'canonical source file is missing at the source revision',
      )
    }
    documents.set(name, {
      path: repoPath,
      bytes: document.bytes,
      gitBlob: document.gitBlob,
      value: parseBoundedAuditJsonBytes(
        document.bytes,
        SOURCE_BYTES,
        repoPath,
      ),
    })
  }
  const policyDocument = readRevisionFile(
    git,
    options.validationRevision,
    options.policyPath,
    SOURCE_BYTES,
    `/${options.policyPath}`,
  )
  if (policyDocument === null) {
    fail(
      `/${options.policyPath}`,
      'review policy is missing at the validation revision',
    )
  }
  let policy = parseMigrationPolicy(
    parseBoundedAuditJsonBytes(
      policyDocument.bytes,
      SOURCE_BYTES,
      options.policyPath,
    ),
    options.policyPath,
  )
  if (policy.schema === POLICY_SCHEMA) {
    const loaded = parseAuditReviewPolicyValue(
      parseBoundedAuditJsonBytes(
        policyDocument.bytes,
        SOURCE_BYTES,
        options.policyPath,
      ),
    )
    if (
      loaded.policy === null ||
      loaded.policyHash === null ||
      loaded.diagnostics.length !== 0
    ) {
      fail(
        `/${options.policyPath}`,
        `Atlas policy validation failed: ${loaded.diagnostics
          .map(({ code, message }) => `${code}: ${message}`)
          .join('; ')}`,
      )
    }
    policy = {
      ...policy,
      digest: `sha256:${loaded.policyHash}` as AuditSha256,
    }
  }
  return {
    ledger: parseLedger(documents.get('ledger.json')!.value),
    candidates: parseCandidates(documents.get('candidates.v1.json')!.value),
    dispositions: parseDispositions(
      documents.get('dispositions.v1.json')!.value,
    ),
    provenance: parseProvenance(
      documents.get('phase-zero-provenance.v1.json')!.value,
    ),
    policy,
    rawDocuments: [...documents.values()].map(({ path, bytes, gitBlob }) => ({
      path,
      bytes,
      gitBlob,
    })),
    policySeal: {
      path: options.policyPath,
      gitBlob: policyDocument.gitBlob,
      sha256: rawSha256(policyDocument.bytes),
    },
  }
}

function snapshotOptions(
  unsafeOptions: RelayOSMigrationOptions | undefined,
): NormalizedMigrationOptions {
  if (unsafeOptions === undefined) {
    fail(
      '/options',
      'migration options with sourceRevision and validationRevision are required',
    )
  }
  const snapshot = JSON.parse(canonicalJson(unsafeOptions)) as unknown
  const options = recordAt(snapshot, '/options')
  exactKeys(
    options,
    ['sourceRevision', 'validationRevision'],
    ['scanRoot', 'policyPath', 'includeHistory', 'apply'],
    '/options',
  )
  const scanRoot = options.scanRoot === undefined
    ? DEFAULT_SOURCE_ROOT
    : repoPathAt(options.scanRoot, '/options/scanRoot')
  const policyPath = options.policyPath === undefined
    ? POLICY_PATH
    : repoPathAt(options.policyPath, '/options/policyPath')
  const sourceRevision = stringAt(
    options.sourceRevision,
    '/options/sourceRevision',
  )
  if (!FULL_REVISION_RE.test(sourceRevision)) {
    fail(
      '/options/sourceRevision',
      'expected a full lowercase Git commit revision',
    )
  }
  const validationRevision = stringAt(
    options.validationRevision,
    '/options/validationRevision',
  )
  if (!FULL_REVISION_RE.test(validationRevision)) {
    fail(
      '/options/validationRevision',
      'expected a full lowercase Git commit revision',
    )
  }
  if (
    options.includeHistory !== undefined &&
    typeof options.includeHistory !== 'boolean'
  ) {
    fail('/options/includeHistory', 'expected a boolean')
  }
  if (options.apply !== undefined && typeof options.apply !== 'boolean') {
    fail('/options/apply', 'expected a boolean')
  }
  return {
    scanRoot,
    policyPath,
    sourceRevision,
    validationRevision,
    includeHistory: options.includeHistory !== false,
    apply: options.apply === true,
  }
}

function policyMatcher(
  include: readonly string[],
  except: readonly string[] = [],
): (repoPath: string) => boolean {
  const includes = include.map((pattern) =>
    picomatch(pattern, { dot: true }))
  const exceptions = except.map((pattern) =>
    picomatch(pattern, { dot: true }))
  return (repoPath) =>
    includes.some((match) => match(repoPath)) &&
    !exceptions.some((match) => match(repoPath))
}

function partitionLegacyPaths(
  source: ParsedSource,
  policyPath: string,
): {
  pathUnits: Map<string, string>
  unitTitles: Map<string, string>
} {
  const units = source.policy.units.map((unit) => ({
    unit,
    matches: policyMatcher(unit.include, unit.except),
  }))
  const historical = source.policy.historicalAssignments.map(
    (assignment) => ({
      assignment,
      matches: policyMatcher(assignment.include),
    }),
  )
  const pathUnits = new Map<string, string>()
  for (const scan of source.ledger.scans) {
    const direct = units.filter(({ matches }) => matches(scan.path))
    const historicalMatches = historical.filter(({ matches }) =>
      matches(scan.path))
    if (
      scan.retired === undefined &&
      historicalMatches.length !== 0
    ) {
      fail(
        `/${policyPath}/historicalUnitAssignments`,
        `historical assignment matches active receipt ${scan.path}`,
      )
    }
    if (direct.length > 1) {
      fail(
        `/${policyPath}/units`,
        `legacy path ${scan.path} matches multiple security units`,
      )
    }
    if (direct.length === 1) {
      if (historicalMatches.length !== 0) {
        fail(
          `/${policyPath}/historicalUnitAssignments`,
          `historical assignment overlaps current ownership for ${scan.path}`,
        )
      }
      pathUnits.set(scan.path, direct[0].unit.slug)
      continue
    }
    if (scan.retired === undefined || historicalMatches.length !== 1) {
      fail(
        `/${policyPath}`,
        scan.retired === undefined
          ? `active legacy path ${scan.path} has no security unit`
          : `retired legacy path ${scan.path} must match exactly one ` +
            'historical assignment',
      )
    }
    pathUnits.set(scan.path, historicalMatches[0].assignment.unit)
  }
  for (const candidate of source.candidates.entries) {
    if (!pathUnits.has(candidate.path)) {
      fail(
        `/candidates.v1.json/entries/${candidate.sourceIndex}/path`,
        'candidate path has no policy-unit assignment',
      )
    }
  }
  return {
    pathUnits,
    unitTitles: new Map(
      source.policy.units.map(({ slug, title }) => [slug, title]),
    ),
  }
}

function evidenceRefs(values: readonly string[]): string[] {
  const refs = new Set<string>()
  for (const value of values) {
    if (
      !/^[A-Za-z0-9._/-]+$/u.test(value) ||
      (!value.endsWith('.json') && !value.endsWith('.md'))
    ) {
      continue
    }
    try {
      refs.add(normalizeAuditRepoPath(value))
    } catch {
      // Legacy evidence arrays intentionally mix paths and prose.
    }
  }
  return [...refs].sort(compareText)
}

function currentStateDigest(
  repositoryRevision: string,
  currentFiles: ReadonlyMap<string, CurrentFileState | null>,
): AuditSha256 {
  return prefixedSha256({
    namespace: 'repo-atlas/relayos-migration-validation/v1',
    repositoryRevision,
    files: [...currentFiles.entries()]
      .map(([path_, state]) => ({
        path: path_,
        sha1: state?.sha1 ?? null,
        sha256: state?.sha256 ?? null,
      }))
      .sort((left, right) => compareText(left.path, right.path)),
  })
}

function exactUtf8LineCount(bytes: Buffer, pointer: string): number {
  if (bytes.length === 0) return 0
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    fail(pointer, 'Git blob is not valid UTF-8 source text')
  }
  const lines = text.split('\n')
  if (lines.at(-1) === '') lines.pop()
  return lines.length
}

function buildContext(
  root: string,
  options: NormalizedMigrationOptions,
): MigrationContext {
  return withAnchoredAuditSupportSnapshot(root, () => {
    const repositoryId = parseRepositoryId(root)
    return withAnchoredAuditGitCapability(root, (git) => {
      verifyRevisionCommit(git, options.sourceRevision, 'sourceRevision')
      verifyRevisionCommit(
        git,
        options.validationRevision,
        'validationRevision',
      )
      const epochText = gitText(
        git.gitBytes(
          ['show', '-s', '--format=%ct', options.sourceRevision],
          1024,
        ),
        '/git/committer-time',
      )
      if (!/^\d+$/u.test(epochText)) {
        fail('/git/committer-time', 'expected an epoch second')
      }
      const recordedAt = new Date(Number(epochText) * 1000).toISOString()
      const parsed = readSource(git, options)
      const documents: SourceDocument[] = parsed.rawDocuments.map(
        ({ path: repoPath, bytes, gitBlob }) => ({
          path: repoPath,
          bytes,
          sha256: rawSha256(bytes),
          gitBlob,
        }),
      ).sort((left, right) => compareText(left.path, right.path))
      const source: ParsedSource = {
        ledger: parsed.ledger,
        candidates: parsed.candidates,
        dispositions: parsed.dispositions,
        provenance: parsed.provenance,
        policy: parsed.policy,
        documents,
      }
      validateCrossSource(source)
      const partition = partitionLegacyPaths(source, options.policyPath)

      const relevantPaths = new Set<string>()
      for (const scan of source.ledger.scans) {
        if (scan.retired === undefined) relevantPaths.add(scan.path)
        if (scan.retired?.successorPath != null) {
          relevantPaths.add(scan.retired.successorPath)
        }
      }
      for (const candidate of source.candidates.entries) {
        if (candidate.duplicateOf === undefined) {
          relevantPaths.add(candidate.path)
        }
      }
      const scansByPath = new Map(
        source.ledger.scans.map((scan) => [scan.path, scan]),
      )
      const treeFiles = resolveRevisionTreeFiles(
        git,
        options.validationRevision,
        [...relevantPaths],
        '/validation',
      )
      const currentFiles = new Map<string, CurrentFileState | null>()
      for (const repoPath of [...relevantPaths].sort(compareText)) {
        const entry = treeFiles.get(repoPath)
        if (entry === undefined) {
          fail(`/validation/${repoPath}`, 'revision tree entry was not resolved')
        }
        if (entry === null) {
          currentFiles.set(repoPath, null)
          continue
        }
        const bytes = readVerifiedGitBlob(
          git,
          entry.gitBlob,
          AUDIT_LIMITS.jsonBytes,
          `/validation/${repoPath}`,
        )
        const scan = scansByPath.get(repoPath)
        const needsExactBytes = source.candidates.entries.some((candidate) =>
          candidate.duplicateOf === undefined &&
          candidate.path === repoPath &&
          scan !== undefined &&
          scan.retired === undefined &&
          candidate.sourceBlob === scan.git_blob_sha1 &&
          candidate.sourceBlob === entry.gitBlob)
        currentFiles.set(repoPath, {
          sha1: entry.gitBlob,
          sha256: rawSha256(bytes),
          ...(needsExactBytes ? { bytes } : {}),
        })
      }
      const blobLineCounts = new Map<string, number>()
      const objectInventory = Buffer.from(
        git.gitBytes(
          [
            'cat-file',
            '--batch-all-objects',
            '--batch-check=%(objectname)',
          ],
          AUDIT_LIMITS.jsonBytes,
        ),
      ).toString('ascii').trim()
      const availableObjects = new Set(
        objectInventory.length === 0 ? [] : objectInventory.split(/\r?\n/u),
      )
      for (const objectId of availableObjects) {
        if (!SHA1_RE.test(objectId)) {
          fail('/git/objects', 'Git returned an invalid SHA-1 object identity')
        }
      }
      for (
        const blob of new Set(
          source.ledger.scans.map(({ git_blob_sha1 }) => git_blob_sha1),
        )
      ) {
        if (!availableObjects.has(blob)) continue
        const bytes = readVerifiedGitBlob(
          git,
          blob,
          AUDIT_LIMITS.jsonBytes,
          `/git/blobs/${blob}`,
        )
        blobLineCounts.set(
          blob,
          exactUtf8LineCount(bytes, `/git/blobs/${blob}`),
        )
      }
      const sourceSemanticDigest = prefixedSha256(
        semanticSourceValue(source),
      )
      const rulesetDigest = prefixedSha256({
        namespace: 'repo-atlas/relayos-security-ruleset/v1',
        sourceRuleset: source.ledger.ruleset,
        scanner: source.ledger.scanner,
        canonicalRuleset: CANONICAL_RULESET,
        policyDigest: source.policy.digest,
      })
      const historicalAssignmentsDigest = prefixedSha256({
        namespace: 'repo-atlas/relayos-migration-historical-assignments/v1',
        assignments: source.policy.historicalAssignments,
      })
      const validationDigest = currentStateDigest(
        options.validationRevision,
        currentFiles,
      )
      const targetDigest = prefixedSha256({
        namespace: 'repo-atlas/relayos-migration-target/v1',
        repositoryId,
        repositoryRevision: options.validationRevision,
        validationDigest,
      })
      const sortedInputSeals = documents.map(
        ({ path: repoPath, gitBlob, sha256 }) => ({
          path: repoPath,
          gitBlob,
          sha256,
        }),
      )
      const migrationId =
        `amig_${rawSha256([
          'atlas-migration/v1',
          SOURCE_KIND,
          repositoryId,
          options.sourceRevision,
          options.validationRevision,
          parsed.policySeal.sha256,
          historicalAssignmentsDigest,
          CONVERTER_NAME,
          CONVERTER_VERSION,
          CONVERTER_COMMIT,
          canonicalJson(sortedInputSeals),
        ].join('\0')).slice(0, 24)}`
      return {
        root,
        scanRoot: options.scanRoot,
        repositoryId,
        sourceRevision: options.sourceRevision,
        validationRevision: options.validationRevision,
        recordedAt,
        source,
        policySeal: parsed.policySeal,
        historicalAssignmentsDigest,
        sourceSemanticDigest,
        rulesetDigest,
        targetDigest,
        targetId: `relayos-security-v1:${options.validationRevision}`,
        migrationId,
        currentFiles,
        blobLineCounts,
        pathUnits: partition.pathUnits,
        unitTitles: partition.unitTitles,
        policyDigest: source.policy.digest,
      }
    })
  })
}

function producerFor(
  context: MigrationContext,
  layer: 'baseline' | 'candidates' | 'current',
): AtlasSecurityObservationV3['producer'] {
  return {
    kind: 'migration',
    name: context.source.ledger.scanner.name,
    version: '1',
    adapter: ADAPTER_NAME,
    adapterVersion: ADAPTER_VERSION,
    runId: `${context.sourceSemanticDigest.slice('sha256:'.length, 30)}/${layer}`,
    identityDigest: context.rulesetDigest,
    identityBasis: 'ruleset',
    ruleset: {
      id: CANONICAL_RULESET,
      digest: context.rulesetDigest,
    },
  }
}

function targetFor(
  context: MigrationContext,
): AtlasSecurityObservationV3['target'] {
  return {
    kind: 'git-revision',
    repositoryId: context.repositoryId,
    targetId: context.targetId,
    identityDigest: context.targetDigest,
    identityBasis: 'snapshot',
    snapshotDigest: context.targetDigest,
    revision: context.validationRevision,
    dirty: false,
    displayName: 'RelayOS legacy security migration',
  }
}

function semanticCoverage(): AtlasSecurityObservationV3['semanticCoverage'] {
  return {
    mode: 'unit',
    completeness: 'unknown',
    inventoryStrategy: 'unit',
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
  }
}

function locationFor(
  candidate: LegacyCandidate,
  maximumLine?: number,
): { path: string; startLine: number; endLine?: number } {
  const matches = [...candidate.symbolLocation.matchAll(
    /:(\d+)(?:-(\d+))?(?=$|[^0-9])/gu,
  )]
  const match = matches.at(-1)
  let startLine = match === undefined ? 1 : Number(match[1])
  let endLine = match?.[2] === undefined ? startLine : Number(match[2])
  if (
    !Number.isSafeInteger(startLine) ||
    !Number.isSafeInteger(endLine) ||
    startLine < 1 ||
    endLine < startLine
  ) {
    startLine = 1
    endLine = 1
  }
  if (maximumLine !== undefined && endLine > maximumLine) {
    startLine = 1
    endLine = 1
  }
  return {
    path: candidate.path,
    startLine,
    ...(endLine === startLine ? {} : { endLine }),
  }
}

function candidateFingerprint(
  context: MigrationContext,
  candidate: LegacyCandidate,
): AtlasFingerprintV1 {
  return computeAtlasFingerprint({
    repositoryId: context.repositoryId,
    domain: 'security',
    ruleId: `relayos-security-scan/${normalizeRulePart(candidate.category)}`,
    anchor: `legacy/${candidate.identityKey}`,
  })
}

function candidateFinding(
  context: MigrationContext,
  candidate: LegacyCandidate,
  observationId: AtlasSecurityObservationV3['observationId'],
  unit: string,
  options: {
    maximumLine?: number
    exactCode?: { bytes: Buffer; blob: string }
  } = {},
): AtlasSecurityFindingV3 {
  const ruleId =
    `relayos-security-scan/${normalizeRulePart(candidate.category)}`
  const fingerprint = candidateFingerprint(context, candidate)
  const location = locationFor(candidate, options.maximumLine)
  let codeEvidence: AtlasSecurityFindingV3['codeEvidence']
  if (options.exactCode !== undefined) {
    const text = options.exactCode.bytes.toString('utf8')
    const lines = text.split('\n')
    if (lines.at(-1) === '') lines.pop()
    const code = lines[location.startLine - 1]
    if (code !== undefined) {
      codeEvidence = [{
        evidenceBasis: 'exact-blob',
        id: `legacy-code-${candidate.id.toLowerCase()}`,
        label: 'Legacy candidate source line',
        path: candidate.path,
        startLine: location.startLine,
        blob: `git-sha1:${options.exactCode.blob}`,
        code,
        explanation:
          'Preserved only because the legacy source blob matches repository bytes.',
      }]
    }
  }
  return {
    findingId: computeAtlasFindingId(fingerprint),
    occurrenceId: computeAtlasOccurrenceId(observationId, fingerprint),
    decisionLedger: unit,
    ruleId,
    identity: {
      anchor: `legacy/${candidate.identityKey}`,
    },
    fingerprints: [
      {
        scheme: 'atlas/v1',
        value: fingerprint,
        role: 'canonical',
      },
      {
        scheme: 'relayos-security-scan/v1',
        value: candidate.id,
        role: 'producer',
      },
      {
        scheme: 'relayos-security-scan/identity-key/v1',
        value: candidate.identityKey,
        role: 'producer',
      },
    ],
    title: candidate.title,
    summary: candidate.detail,
    severity: {
      level: normalizeSeverity(candidate.severity),
    },
    taxonomy: {
      category: candidate.category,
    },
    locations: [location],
    ...(codeEvidence === undefined ? {} : { codeEvidence }),
    remediation: candidate.recommendedFix,
    provenance: {
      source: SOURCE_KIND,
      producerSource: candidate.sourceKind,
      sourceFindingId: candidate.id,
      candidateId: candidate.identityKey,
      reportId: candidate.sourceLocator,
    },
  }
}

function scanFingerprint(
  context: MigrationContext,
  scan: LegacyScan,
  ordinal: number,
): AtlasFingerprintV1 {
  return computeAtlasFingerprint({
    repositoryId: context.repositoryId,
    domain: 'security',
    ruleId: 'relayos-security-scan/opaque-legacy-finding',
    anchor: `legacy-scan/${scan.path}/${scan.git_blob_sha1}/${ordinal}`,
  })
}

function scanFinding(
  context: MigrationContext,
  scan: LegacyScan,
  ordinal: number,
  observationId: AtlasSecurityObservationV3['observationId'],
  unit: string,
): AtlasSecurityFindingV3 {
  const fingerprint = scanFingerprint(context, scan, ordinal)
  const sourceReference = scan.findings_ref ??
    `legacy scan ${scan.path}@${scan.git_blob_sha1}`
  return {
    findingId: computeAtlasFindingId(fingerprint),
    occurrenceId: computeAtlasOccurrenceId(observationId, fingerprint),
    decisionLedger: unit,
    ruleId: 'relayos-security-scan/opaque-legacy-finding',
    identity: {
      anchor: `legacy-scan/${scan.path}/${scan.git_blob_sha1}/${ordinal}`,
    },
    fingerprints: [{
      scheme: 'atlas/v1',
      value: fingerprint,
      role: 'canonical',
    }],
    title: `Legacy finding receipt ${ordinal}: ${sourceReference}`,
    summary:
      `The sealed RelayOS ledger recorded finding ${ordinal} of ` +
      `${scan.finding_count} for this exact file blob. Detailed structured ` +
      `facts are preserved by the candidate migration layer.`,
    severity: {
      level: normalizeSeverity(scan.max_severity ?? 'info'),
    },
    taxonomy: {
      category: 'legacy-ledger-finding',
    },
    locations: [{
      path: scan.path,
      startLine: scan.lines === 0 ? 1 : 1,
    }],
    remediation:
      `Consult the sealed legacy finding reference ${sourceReference}.`,
    provenance: {
      source: SOURCE_KIND,
      ledgerRowId: `${scan.path}@${scan.git_blob_sha1}:${ordinal}`,
      reportId: sourceReference,
    },
  }
}

function scanLineCount(
  context: MigrationContext,
  scan: LegacyScan,
): number {
  return context.blobLineCounts.get(scan.git_blob_sha1) ?? scan.lines
}

function exactObservation(
  context: MigrationContext,
  unit: string,
  layer: 'baseline' | 'current',
  scans: readonly LegacyScan[],
  findingBuilder: (
    observationId: AtlasSecurityObservationV3['observationId'],
  ) => AtlasSecurityFindingV3[],
): AtlasSecurityObservationV3 {
  const producer = producerFor(context, layer)
  const target = targetFor(context)
  const identityFiles = scans.map((scan) => ({
    path: scan.path,
    blob: `git-sha1:${scan.git_blob_sha1}` as const,
  }))
  const identityDigest = computeExactScopeIdentityDigest({
    mode: 'unit',
    includePaths: [],
    excludePaths: [],
    files: identityFiles,
  })
  const observationId = computeAtlasObservationId({
    slug: unit,
    adapter: producer.adapter,
    runId: producer.runId,
    producerIdentityDigest: producer.identityDigest,
    targetId: target.targetId,
    targetIdentityDigest: target.identityDigest,
    scopeIdentityDigest: identityDigest,
  })
  const findings = findingBuilder(observationId)
    .sort((left, right) => compareText(left.findingId, right.findingId))
  const occurrenceByPath = new Map<string, string[]>()
  for (const finding of findings) {
    const primaryPath = finding.locations[0].path
    const occurrences = occurrenceByPath.get(primaryPath) ?? []
    occurrences.push(finding.occurrenceId)
    occurrenceByPath.set(primaryPath, occurrences)
  }
  const files: AuditFileReceiptV3[] = scans.map((scan) => {
    const occurrences = [...(occurrenceByPath.get(scan.path) ?? [])]
      .sort(compareText)
    if (
      (scan.status === 'findings' && occurrences.length !== scan.finding_count) ||
      (scan.status === 'clean' && occurrences.length !== 0)
    ) {
      fail(
        `/ledger.json/scans/${scan.sourceIndex}`,
        `mapped occurrence count ${occurrences.length} does not equal ` +
          `legacy finding_count ${scan.finding_count}`,
      )
    }
    return {
      path: scan.path,
      blob: `git-sha1:${scan.git_blob_sha1}` as const,
      lines: scanLineCount(context, scan),
      status: 'reviewed' as const,
      outcome: scan.status,
      reviewedAt: normalizeDate(scan.scanned_at),
      reviewedAtPrecision: 'date' as const,
      reviewedBy: scan.scanned_by,
      ruleset: CANONICAL_RULESET,
      findingOccurrenceIds: occurrences,
      receiptRefs: ['migration:relayos-security-v1'],
    }
  }).sort((left, right) => compareText(left.path, right.path))
  const inventoryDigest = computeAuditInventoryDigest(files)
  const scopeHash = computeAuditScopeHash({
    mode: 'unit',
    includePaths: [],
    excludePaths: [],
    inventoryDigest,
  })
  const legacyLineDeclarations = scans.map((scan) => ({
    path: scan.path,
    blob: `git-sha1:${scan.git_blob_sha1}`,
    lines: scan.lines,
  }))
  const producerExtensions: AtlasSecurityObservationV3['producerExtensions'] =
    []
  if (layer === 'baseline') {
    for (let start = 0; start < legacyLineDeclarations.length; start += 200) {
      const value = legacyLineDeclarations.slice(start, start + 200)
      producerExtensions.push({
        namespace: SOURCE_KIND,
        path: `/ledger/scans/declared-lines/${String(start).padStart(4, '0')}`,
        value,
        digest: computeAuditCanonicalDigest(value),
      })
    }
  }
  return {
    observationId,
    observedAt: context.recordedAt,
    reviewState: 'complete',
    producer,
    target,
    scope: {
      mode: 'unit',
      identityDigest,
      identityBasis: 'exact-inventory',
      includePaths: [],
      excludePaths: [],
      scopeHash,
      inventoryDigest,
      fileCount: files.length,
      files,
      artifactsReviewed: [],
      limitations: [],
    },
    exactCoverage: {
      completeness: 'complete',
      basis: 'full-read-receipts',
      reviewedFileCount: files.length,
      unreviewed: [],
    },
    semanticCoverage: semanticCoverage(),
    findings,
    evidenceRefs: [],
    sourceArtifacts: [],
    producerExtensions,
  }
}

function candidateObservation(
  context: MigrationContext,
  unit: string,
  candidates: readonly LegacyCandidate[],
): AtlasSecurityObservationV3 {
  const producer = producerFor(context, 'candidates')
  const target = targetFor(context)
  const identityDigest = computeSemanticScopeIdentityDigest({
    mode: 'unit',
    inventoryStrategy: 'unit',
    includePaths: [],
    excludePaths: [],
    explicitExclusions: [],
  })
  const observationId = computeAtlasObservationId({
    slug: unit,
    adapter: producer.adapter,
    runId: producer.runId,
    producerIdentityDigest: producer.identityDigest,
    targetId: target.targetId,
    targetIdentityDigest: target.identityDigest,
    scopeIdentityDigest: identityDigest,
  })
  const findings = candidates.map((candidate) =>
    candidateFinding(context, candidate, observationId, unit))
    .sort((left, right) => compareText(left.findingId, right.findingId))
  return {
    observationId,
    observedAt: context.recordedAt,
    reviewState: 'complete',
    producer,
    target,
    scope: {
      mode: 'unit',
      identityDigest,
      identityBasis: 'semantic-declaration',
      includePaths: [],
      excludePaths: [],
      inventoryStrategy: 'unit',
      explicitExclusions: [],
      artifactsReviewed: [],
      limitations: [
        'Legacy candidates do not attest semantic surface closure.',
      ],
    },
    exactCoverage: {
      completeness: 'unknown',
      basis: 'unavailable',
      reason:
        'Candidate reconciliation is semantic evidence; exact file receipts ' +
        'are preserved in separate migration observations.',
    },
    semanticCoverage: semanticCoverage(),
    findings,
    evidenceRefs: [],
    sourceArtifacts: [],
    producerExtensions: [],
  }
}

function exactCodeFor(
  context: MigrationContext,
  candidate: LegacyCandidate,
  scan: LegacyScan,
): { bytes: Buffer; blob: string } | undefined {
  const current = context.currentFiles.get(candidate.path)
  if (
    current === undefined ||
    current === null ||
    candidate.sourceBlob !== scan.git_blob_sha1 ||
    current.sha1 !== candidate.sourceBlob
  ) {
    return undefined
  }
  if (current.bytes === undefined) {
    fail(
      `/validation/${candidate.path}`,
      'validation-revision bytes were not retained for an exact match',
    )
  }
  return { bytes: current.bytes, blob: candidate.sourceBlob }
}

interface ObservationBuild {
  observations: AtlasSecurityObservationV3[]
  byUnit: Map<string, {
    baseline: AtlasSecurityObservationV3
    candidates: AtlasSecurityObservationV3
    current: AtlasSecurityObservationV3
  }>
  candidateFindings: Map<string, AtlasSecurityFindingV3>
  currentFindings: Map<string, AtlasSecurityFindingV3>
  scanUnit: Map<string, string>
  candidateUnit: Map<string, string>
}

function buildObservations(context: MigrationContext): ObservationBuild {
  const canonicalCandidates = context.source.candidates.entries
    .filter((candidate) => candidate.duplicateOf === undefined)
  const dispositionById = new Map(
    context.source.dispositions.dispositions.map((disposition) => [
      disposition.id,
      disposition,
    ]),
  )
  const scansByUnit = new Map<string, LegacyScan[]>()
  const scanUnit = new Map<string, string>()
  for (const scan of context.source.ledger.scans) {
    const unit = context.pathUnits.get(scan.path)
    if (unit === undefined) {
      fail(`/policy/${scan.path}`, 'scan path has no policy unit')
    }
    const rows = scansByUnit.get(unit) ?? []
    rows.push(scan)
    scansByUnit.set(unit, rows)
    scanUnit.set(scan.path, unit)
  }
  const candidatesByUnit = new Map<string, LegacyCandidate[]>()
  const candidateUnit = new Map<string, string>()
  for (const candidate of canonicalCandidates) {
    const unit = scanUnit.get(candidate.path)
    if (unit === undefined) {
      fail(
        `/candidates.v1.json/entries/${candidate.sourceIndex}/path`,
        'candidate path has no scan policy unit',
      )
    }
    const rows = candidatesByUnit.get(unit) ?? []
    rows.push(candidate)
    candidatesByUnit.set(unit, rows)
    candidateUnit.set(candidate.id, unit)
  }
  const units = new Set([...scansByUnit.keys(), ...candidatesByUnit.keys()])
  const observations: AtlasSecurityObservationV3[] = []
  const byUnit: ObservationBuild['byUnit'] = new Map()
  const candidateFindings = new Map<string, AtlasSecurityFindingV3>()
  const currentFindings = new Map<string, AtlasSecurityFindingV3>()

  for (const unit of [...units].sort(compareText)) {
    const allScans = [...(scansByUnit.get(unit) ?? [])]
      .sort((left, right) => compareText(left.path, right.path))
    const unitCandidates = [...(candidatesByUnit.get(unit) ?? [])]
      .sort((left, right) => compareText(left.id, right.id))
    const baseline = exactObservation(
      context,
      unit,
      'baseline',
      allScans,
      (observationId) => allScans.flatMap((scan) =>
        Array.from({ length: scan.finding_count }, (_, index) =>
          scanFinding(context, scan, index + 1, observationId, unit))),
    )
    const candidates = candidateObservation(context, unit, unitCandidates)
    for (const finding of candidates.findings) {
      const alias = finding.fingerprints.find(
        ({ scheme }) => scheme === 'relayos-security-scan/v1',
      )?.value
      if (alias !== undefined) candidateFindings.set(alias, finding)
    }

    const activeScans = allScans.filter((scan) => scan.retired === undefined)
    const currentCandidates = unitCandidates.filter((candidate) => {
      const disposition = dispositionById.get(candidate.id)!
      return (
        disposition.status === 'accepted_risk' ||
        disposition.status === 'separate_design'
      ) &&
        disposition.currentScan !== undefined &&
        disposition.currentScan !== null &&
        activeScans.some((scan) =>
          scan.path === candidate.path &&
          scan.git_blob_sha1 === disposition.currentScan!.reviewedBlob)
    })
    const current = exactObservation(
      context,
      unit,
      'current',
      activeScans,
      (observationId) => currentCandidates.map((candidate) => {
        const scan = activeScans.find((row) => row.path === candidate.path)!
        return candidateFinding(
          context,
          candidate,
          observationId,
          unit,
          {
            maximumLine: scanLineCount(context, scan),
            exactCode: exactCodeFor(context, candidate, scan),
          },
        )
      }),
    )
    for (const finding of current.findings) {
      const alias = finding.fingerprints.find(
        ({ scheme }) => scheme === 'relayos-security-scan/v1',
      )?.value
      if (alias !== undefined) currentFindings.set(alias, finding)
    }
    observations.push(baseline, candidates, current)
    byUnit.set(unit, { baseline, candidates, current })
  }
  return {
    observations,
    byUnit,
    candidateFindings,
    currentFindings,
    scanUnit,
    candidateUnit,
  }
}

function decisionBinding(candidate: LegacyCandidate, blob: string) {
  return {
    path: candidate.path,
    blob: `git-sha1:${blob}` as const,
  }
}

function reviewContext(
  context: MigrationContext,
  candidate: LegacyCandidate,
  observationId: AtlasSecurityObservationV3['observationId'],
  blob: string,
) {
  return {
    observationId,
    bindings: [decisionBinding(candidate, blob)] as [
      ReturnType<typeof decisionBinding>,
    ],
    ruleset: {
      id: CANONICAL_RULESET,
      digest: context.rulesetDigest,
    },
    policyDigest: context.policyDigest,
  }
}

function buildDispositionInput(
  context: MigrationContext,
  observations: ObservationBuild,
  candidate: LegacyCandidate,
  disposition: LegacyDisposition,
): AuditDecisionEventInputV3 {
  const unit = observations.candidateUnit.get(candidate.id)!
  const layer = observations.byUnit.get(unit)!
  const sourceBinding = decisionBinding(candidate, candidate.sourceBlob)
  const dispositionArtifact = sourceArtifact(
    context,
    'dispositions.v1.json',
  )
  const reviewObservationId = (
    disposition.status === 'accepted_risk' ||
    disposition.status === 'separate_design' ||
    disposition.status === 'false_positive'
  )
    ? layer.current.observationId
    : layer.candidates.observationId
  const reviewBlob = (
    disposition.status === 'accepted_risk' ||
    disposition.status === 'separate_design' ||
    disposition.status === 'false_positive'
  )
    ? disposition.reviewedBlob!
    : candidate.sourceBlob
  const common = {
    type: 'finding-disposition' as const,
    findingId: observations.candidateFindings.get(candidate.id)!.findingId,
    occurrenceId:
      observations.candidateFindings.get(candidate.id)!.occurrenceId,
    actor: MIGRATION_ACTOR,
    owner: disposition.owner,
    reason: disposition.rationale,
    createdAt: context.recordedAt,
    createdAtBasis: 'source-revision-upper-bound' as const,
    reviewContext: reviewContext(
      context,
      candidate,
      reviewObservationId,
      reviewBlob,
    ),
    evidenceRefs: evidenceRefs(disposition.evidence),
    reviews: [],
  }
  if (
    disposition.status === 'accepted_risk' ||
    disposition.status === 'separate_design'
  ) {
    const reviewedBlob = disposition.reviewedBlob!
    return {
      ...common,
      action: disposition.status === 'accepted_risk'
        ? 'accepted-risk'
        : 'separate-design',
      expiresAt: disposition.expiresAt!,
      proofs: [{
        kind: 'current-review',
        observationId: layer.current.observationId,
        reviewedBindings: [decisionBinding(candidate, reviewedBlob)],
        outcome: 'finding-present',
        summary: disposition.rationale,
        sourceArtifact: dispositionArtifact,
      }],
    }
  }
  if (disposition.status === 'false_positive') {
    const reviewedBlob = disposition.reviewedBlob!
    return {
      ...common,
      action: 'false-positive',
      expiresAt: null,
      proofs: [{
        kind: 'source-evidence',
        observationId: layer.current.observationId,
        reviewedBindings: [decisionBinding(candidate, reviewedBlob)],
        outcome: 'not-reportable',
        summary: disposition.rationale,
        sourceArtifact: dispositionArtifact,
      }],
      actionEvidence: {
        kind: 'source-evidence',
        reviewedBindings: [decisionBinding(candidate, reviewedBlob)],
        conclusion: 'not-reportable',
        rationale: typeof disposition.sourceEvidence === 'string'
          ? disposition.sourceEvidence
          : disposition.rationale,
      },
    }
  }
  if (disposition.status === 'remediated') {
    const afterBinding = decisionBinding(candidate, disposition.fixBlob!)
    return {
      ...common,
      action: 'remediated',
      proofs: [{
        kind: 'post-fix',
        beforeObservationId: layer.candidates.observationId,
        afterObservationId: layer.current.observationId,
        beforeBindings: [sourceBinding],
        afterBindings: [afterBinding],
        fixRevision: context.validationRevision,
        outcome: 'finding-absent-after-fix',
        summary: disposition.rationale,
        sourceArtifact: dispositionArtifact,
      }],
      regression: {
        kind: disposition.regression!.kind,
        name: disposition.regression!.name,
        command: disposition.regression!.command,
        result: 'passed',
        binding: {
          repositoryRevision: context.validationRevision,
          observationId: layer.current.observationId,
          files: [afterBinding],
        },
      },
      actionEvidence: {
        kind: 'remediation',
        beforeBindings: [sourceBinding],
        afterBindings: [afterBinding],
        fixRevision: context.validationRevision,
      },
    }
  }
  if (
    disposition.replacementId !== undefined &&
    disposition.replacementId !== null
  ) {
    const replacement =
      observations.candidateFindings.get(disposition.replacementId)
    if (replacement === undefined) {
      fail(
        `/dispositions.v1.json/dispositions/${disposition.sourceIndex}/replacementId`,
        'does not resolve to a canonical finding',
      )
    }
    return {
      ...common,
      action: 'superseded',
      proofs: [{
        kind: 'replacement',
        observationId: layer.current.observationId,
        replacementFindingId: replacement.findingId,
        replacementOccurrenceId: replacement.occurrenceId,
        replacementBindings: [sourceBinding],
        outcome: 'replacement-tracks-root-cause',
        summary: disposition.rationale,
        sourceArtifact: dispositionArtifact,
      }],
      actionEvidence: {
        kind: 'replacement',
        replacementFindingId: replacement.findingId,
        replacementOccurrenceId: replacement.occurrenceId,
      },
    }
  }
  const deletionCommit = disposition.deletionCommit!
  return {
    ...common,
    action: 'superseded',
    proofs: [
      {
        kind: 'deletion',
        deletionCommit,
        parentRevision: context.validationRevision,
        deletedBindings: [sourceBinding],
        outcome: 'exact-source-deleted',
        summary: disposition.rationale,
        sourceArtifact: dispositionArtifact,
      },
      {
        kind: 'no-replacement',
        observationId: layer.current.observationId,
        searchRevision: context.validationRevision,
        reviewedBindings: [sourceBinding],
        outcome: 'no-reportable-replacement',
        summary: typeof disposition.noReplacementEvidence === 'string'
          ? disposition.noReplacementEvidence
          : disposition.rationale,
        sourceArtifact: dispositionArtifact,
      },
    ],
    actionEvidence: {
      kind: 'deletion',
      deletionCommit,
      deletedBindings: [sourceBinding],
      noReplacementEvidence: {
        observationId: layer.current.observationId,
        searchRevision: context.validationRevision,
        reviewedBindings: [sourceBinding],
        summary: typeof disposition.noReplacementEvidence === 'string'
          ? disposition.noReplacementEvidence
          : disposition.rationale,
      },
    },
  }
}

function sourceArtifact(
  context: MigrationContext,
  name: typeof SOURCE_NAMES[number],
) {
  const repoPath = `${context.scanRoot}/${name}`
  const document = context.source.documents.find(({ path: candidate }) =>
    candidate === repoPath)
  if (document === undefined) fail(`/source/${repoPath}`, 'missing source seal')
  return {
    path: repoPath,
    repositoryRevision: context.sourceRevision,
    gitBlob: `git-sha1:${document.gitBlob}` as const,
    sha256: `sha256:${document.sha256}` as AuditSha256,
  }
}

function buildRetirementInput(
  context: MigrationContext,
  observations: ObservationBuild,
  scan: LegacyScan,
): AuditDecisionEventInputV3 {
  const unit = observations.scanUnit.get(scan.path)!
  const baseline = observations.byUnit.get(unit)!.baseline
  const retirement = scan.retired!
  const common = {
    type: 'scope-retirement' as const,
    decisionLedger: unit,
    path: scan.path,
    blob: `git-sha1:${scan.git_blob_sha1}` as const,
    retiredAt: normalizeDate(retirement.retiredAt),
    retiredAtPrecision: 'date' as const,
    originalRetiredDate: retirement.retiredAt,
    actor: MIGRATION_ACTOR,
    createdAt: context.recordedAt,
    createdAtBasis: 'source-revision-upper-bound' as const,
    historyProof: {
      slug: unit,
      observationId: baseline.observationId,
      path: scan.path,
      blob: `git-sha1:${scan.git_blob_sha1}` as const,
    },
    evidenceRefs: [],
  }
  if (retirement.successorPath !== null) {
    const successorScan = context.source.ledger.scans.find((candidate) =>
      candidate.path === retirement.successorPath)
    const successorBlob = context.currentFiles.get(
      retirement.successorPath,
    )?.sha1 ?? successorScan?.git_blob_sha1
    if (successorBlob !== undefined) {
      return {
        ...common,
        reason: successorBlob === scan.git_blob_sha1
          ? 'moved'
          : 'superseded',
        successor: {
          path: retirement.successorPath,
          blob: `git-sha1:${successorBlob}`,
        },
        revisionProof: {
          kind: 'git-tree-state',
          repositoryRevision: context.validationRevision,
          presentBindings: [{
            path: retirement.successorPath,
            blob: `git-sha1:${successorBlob}`,
          }],
          absentPaths: [scan.path],
        },
      }
    }
  }
  if (retirement.reason === 'deleted') {
    return {
      ...common,
      reason: 'deleted',
      deletionCommit: retirement.deletionCommit!,
      deletionProof: {
        kind: 'git-deletion',
        parentRevision: context.validationRevision,
        parentBindings: [{
          path: scan.path,
          blob: `git-sha1:${scan.git_blob_sha1}`,
        }],
        absentPaths: [scan.path],
      },
    }
  }
  return {
    ...common,
    reason: 'uncommitted-snapshot-absent',
    migrationSourceProof: {
      kind: 'sealed-migration-source',
      sourceArtifact: sourceArtifact(context, 'ledger.json'),
      jsonPointer: `/scans/${scan.sourceIndex}/retired`,
      sourceReason: 'uncommitted_snapshot_absent',
      summary: retirement.evidence,
    },
  }
}

function buildAliasInput(
  context: MigrationContext,
  observations: ObservationBuild,
  candidate: LegacyCandidate,
): AuditDecisionEventInputV3 {
  const canonicalId = candidate.duplicateOf ?? candidate.id
  const canonicalFinding = observations.candidateFindings.get(canonicalId)
  if (canonicalFinding === undefined) {
    fail(
      `/candidates.v1.json/entries/${candidate.sourceIndex}`,
      'candidate alias has no canonical destination',
    )
  }
  return {
    type: 'identity-alias-reconciliation',
    decisionLedger: canonicalFinding.decisionLedger,
    aliases: [{
      scheme: 'relayos-security-scan/v1',
      value: candidate.id,
    }],
    findingId: canonicalFinding.findingId,
    occurrenceIds: [canonicalFinding.occurrenceId],
    relationship: candidate.duplicateOf === undefined
      ? 'canonical'
      : 'duplicate-of',
    source: {
      kind: 'migration',
      name: 'relayos-security-scan',
      version: '1',
      sourceArtifact: sourceArtifact(context, 'candidates.v1.json'),
    },
    createdAt: context.recordedAt,
    createdAtBasis: 'source-revision-upper-bound',
    evidenceRefs: [],
  }
}

interface EventBuild {
  decisionEvents: AuditFindingDispositionEventV3[]
  retirementEvents: AuditScopeRetirementEventV3[]
  reconciliationEvents: AuditIdentityAliasReconciliationEventV3[]
  ledgers: Map<string, AuditDecisionLedgerV1>
  bytes: Map<string, string>
}

function eventRank(event: AuditDecisionEventInputV3): number {
  if (event.type === 'scope-retirement') return 0
  if (event.type === 'identity-alias-reconciliation') return 1
  if (event.type === 'finding-reconciliation') return 2
  return 3
}

function eventSortKey(event: AuditDecisionEventInputV3): string {
  if (event.type === 'scope-retirement') {
    return `${event.retiredAt}\0${event.path}\0${event.blob}`
  }
  if (event.type === 'identity-alias-reconciliation') {
    const alias = event.aliases[0]
    return `${alias.scheme}\0${alias.value}\0${event.findingId}`
  }
  if (event.type === 'finding-reconciliation') {
    return `${event.comparisonId}\0${event.beforeOccurrenceIds.join('\0')}` +
      `\0${event.afterOccurrenceIds.join('\0')}`
  }
  return event.findingId
}

function buildEvents(
  context: MigrationContext,
  observations: ObservationBuild,
): EventBuild {
  const canonicalCandidates = new Map(
    context.source.candidates.entries
      .filter((candidate) => candidate.duplicateOf === undefined)
      .map((candidate) => [candidate.id, candidate]),
  )
  const inputs: Array<{
    input: AuditDecisionEventInputV3
    slug: string
  }> = []
  for (const scan of context.source.ledger.scans) {
    if (scan.retired !== undefined) {
      inputs.push({
        input: buildRetirementInput(context, observations, scan),
        slug: observations.scanUnit.get(scan.path)!,
      })
    }
  }
  for (const candidate of context.source.candidates.entries) {
    const input = buildAliasInput(context, observations, candidate)
    inputs.push({
      input,
      slug: observations.candidateFindings.get(
        candidate.duplicateOf ?? candidate.id,
      )!.decisionLedger,
    })
  }
  for (const disposition of context.source.dispositions.dispositions) {
    const candidate = canonicalCandidates.get(disposition.id)!
    inputs.push({
      input: buildDispositionInput(
        context,
        observations,
        candidate,
        disposition,
      ),
      slug: observations.candidateUnit.get(candidate.id)!,
    })
  }
  inputs.sort((left, right) =>
    compareText(left.slug, right.slug) ||
    eventRank(left.input) - eventRank(right.input) ||
    compareText(eventSortKey(left.input), eventSortKey(right.input)))

  const ledgers = new Map<string, AuditDecisionLedgerV1>()
  const decisionEvents: AuditFindingDispositionEventV3[] = []
  const retirementEvents: AuditScopeRetirementEventV3[] = []
  const reconciliationEvents: AuditIdentityAliasReconciliationEventV3[] = []
  for (const { input, slug } of inputs) {
    const event = prepareAuditDecisionAppend(
      null,
      'security',
      slug,
      input,
    ).event
    const { eventId } = event
    const ledger = ledgers.get(slug) ?? {
      formatVersion: 1,
      format: 'atlas-audit-decisions-v1',
      domain: 'security',
      slug,
      entries: [],
    }
    const entryCore = {
      eventId,
      previousEntryDigest: ledger.entries.at(-1)?.entryDigest ?? null,
      event,
    }
    ledger.entries.push({
      ...entryCore,
      entryDigest: computeAuditDecisionEntryDigest(entryCore),
    })
    ledgers.set(slug, ledger)
    if (event.type === 'finding-disposition') {
      decisionEvents.push(event)
    } else if (event.type === 'scope-retirement') {
      retirementEvents.push(event)
    } else if (event.type === 'identity-alias-reconciliation') {
      reconciliationEvents.push(event)
    }
  }
  const bytes = new Map(
    [...ledgers].map(([slug, ledger]) => [
      slug,
      `${canonicalJson(ledger)}\n`,
    ]),
  )
  return {
    decisionEvents,
    retirementEvents,
    reconciliationEvents,
    ledgers,
    bytes,
  }
}

function buildHistory(
  slug: string,
  title: string,
  observations: readonly AtlasSecurityObservationV3[],
): {
  history: AuditObservationHistoryV3
  current: AtlasSecurityCurrentLedgerV3
  historyBytes: string
  currentBytes: string
} {
  let previousEntryDigest: AuditSha256 | null = null
  const entries: AuditObservationHistoryEntryV3[] = []
  for (const observation of observations) {
    const core = {
      observationId: observation.observationId,
      observationDigest: computeAuditCanonicalDigest(observation),
      previousEntryDigest,
      observation,
    }
    const entry: AuditObservationHistoryEntryV3 = {
      ...core,
      entryDigest: computeAuditHistoryEntryDigest(core),
    }
    entries.push(entry)
    previousEntryDigest = entry.entryDigest
  }
  const currentObservation = observations.at(-1)
  const currentEntry = entries.at(-1)
  if (currentObservation === undefined || currentEntry === undefined) {
    fail(`/outputs/${slug}`, 'unit has no migration observations')
  }
  const history: AuditObservationHistoryV3 = {
    formatVersion: 1,
    format: 'atlas-audit-history-v1',
    domain: 'security',
    slug,
    entries,
  }
  const current: AtlasSecurityCurrentLedgerV3 = {
    formatVersion: 3,
    format: 'atlas-audit-v3',
    domain: 'security',
    slug,
    title,
    conceptSlug: 'security',
    current: currentObservation,
    currentDigest: computeAuditCanonicalDigest(currentObservation),
    history: {
      path: `.atlas/audit-history/${slug}.json`,
      observationId: currentObservation.observationId,
      entryDigest: currentEntry.entryDigest,
    },
  }
  return {
    history,
    current,
    historyBytes: `${canonicalJson(history)}\n`,
    currentBytes: `${canonicalJson(current)}\n`,
  }
}

function output(
  path: string,
  bytes: string,
  family: PlannedOutput['family'],
): PlannedOutput {
  return {
    path,
    bytes,
    sha256: rawSha256(bytes),
    family,
  }
}

function dispositionHistogram(
  dispositions: readonly LegacyDisposition[],
): AuditMigrationReceiptV3['counts']['dispositions'] {
  return {
    remediated: dispositions.filter(({ status }) =>
      status === 'remediated').length,
    separateDesign: dispositions.filter(({ status }) =>
      status === 'separate_design').length,
    acceptedRisk: dispositions.filter(({ status }) =>
      status === 'accepted_risk').length,
    falsePositive: dispositions.filter(({ status }) =>
      status === 'false_positive').length,
    superseded: dispositions.filter(({ status }) =>
      status === 'superseded').length,
  }
}

function buildMappings(
  context: MigrationContext,
  observations: ObservationBuild,
  events: EventBuild,
): AuditMigrationReceiptV3['mappings'] {
  const mappings: AuditMigrationReceiptV3['mappings'] = []
  for (const scan of context.source.ledger.scans) {
    const unit = observations.scanUnit.get(scan.path)!
    const baseline = observations.byUnit.get(unit)!.baseline
    mappings.push({
      sourcePath: `${context.scanRoot}/ledger.json`,
      sourcePointer: `/scans/${scan.sourceIndex}`,
      sourceId: `${scan.path}@${scan.git_blob_sha1}`,
      destinationKind: 'file-receipt',
      destinationIds: [baseline.observationId, scan.path],
    })
    if (scan.retired !== undefined) {
      const retirement = events.retirementEvents.find((event) =>
        event.path === scan.path && event.blob === `git-sha1:${scan.git_blob_sha1}`)
      if (retirement === undefined) {
        fail(
          `/ledger.json/scans/${scan.sourceIndex}/retired`,
          'retirement event was not generated',
        )
      }
      mappings.push({
        sourcePath: `${context.scanRoot}/ledger.json`,
        sourcePointer: `/scans/${scan.sourceIndex}/retired`,
        sourceId: `${scan.path}@${scan.git_blob_sha1}`,
        destinationKind: 'retirement',
        destinationIds: [retirement.eventId],
      })
    }
  }
  for (const candidate of context.source.candidates.entries) {
    const canonicalId = candidate.duplicateOf ?? candidate.id
    const finding = observations.candidateFindings.get(canonicalId)!
    const alias = events.reconciliationEvents.find((event) =>
      event.aliases.some(({ value }) => value === candidate.id))
    if (alias === undefined) {
      fail(
        `/candidates.v1.json/entries/${candidate.sourceIndex}`,
        'identity alias event was not generated',
      )
    }
    mappings.push({
      sourcePath: `${context.scanRoot}/candidates.v1.json`,
      sourcePointer: `/entries/${candidate.sourceIndex}`,
      sourceId: candidate.id,
      destinationKind: 'finding',
      destinationIds: [finding.findingId, finding.occurrenceId],
    })
    mappings.push({
      sourcePath: `${context.scanRoot}/candidates.v1.json`,
      sourcePointer: `/entries/${candidate.sourceIndex}/id`,
      sourceId: candidate.id,
      destinationKind: 'identity-alias',
      destinationIds: [alias.eventId],
    })
  }
  for (const disposition of context.source.dispositions.dispositions) {
    const event = events.decisionEvents.find((candidate) =>
      candidate.findingId ===
      observations.candidateFindings.get(disposition.id)!.findingId)
    if (event === undefined) {
      fail(
        `/dispositions.v1.json/dispositions/${disposition.sourceIndex}`,
        'disposition event was not generated',
      )
    }
    mappings.push({
      sourcePath: `${context.scanRoot}/dispositions.v1.json`,
      sourcePointer: `/dispositions/${disposition.sourceIndex}`,
      sourceId: disposition.id,
      destinationKind: 'decision',
      destinationIds: [event.eventId],
    })
  }
  return mappings.sort((left, right) =>
    compareText(left.sourcePath, right.sourcePath) ||
    compareText(left.sourcePointer, right.sourcePointer) ||
    compareText(left.destinationKind, right.destinationKind))
}

interface MigrationPlan {
  result: RelayOSMigrationResult
  outputs: PlannedOutput[]
}

function buildPlan(
  root: string,
  options: NormalizedMigrationOptions,
): MigrationPlan {
  const context = buildContext(root, options)
  const observations = buildObservations(context)
  const events = buildEvents(context, observations)
  const outputs: PlannedOutput[] = []
  for (const [unit, layers] of [...observations.byUnit.entries()]
    .sort(([left], [right]) => compareText(left, right))) {
    const title = context.unitTitles.get(unit)
    if (title === undefined) fail(`/outputs/${unit}`, 'missing policy unit title')
    const history = buildHistory(unit, title, [
      layers.baseline,
      layers.candidates,
      layers.current,
    ])
    if (options.includeHistory) {
      outputs.push(
        output(
          `.atlas/audit-history/${unit}.json`,
          history.historyBytes,
          'history',
        ),
      )
    }
    outputs.push(
      output(
        `.atlas/audits/${unit}.json`,
        history.currentBytes,
        'current',
      ),
    )
  }
  for (const [unit, bytes] of [...events.bytes.entries()]
    .sort(([left], [right]) => compareText(left, right))) {
    outputs.push(output(
      `.atlas/audit-decisions/${unit}.json`,
      bytes,
      'decision',
    ))
  }
  outputs.sort((left, right) => compareText(left.path, right.path))
  const active = context.source.ledger.scans.filter(
    (scan) => scan.retired === undefined,
  )
  const exactMatches = active.filter((scan) =>
    context.currentFiles.get(scan.path)?.sha1 === scan.git_blob_sha1).length
  const counts: AuditMigrationReceiptV3['counts'] = {
    scanRecords: context.source.ledger.scans.length,
    activeScanRecords: active.length,
    retiredScanRecords: context.source.ledger.scans.length - active.length,
    activeClean: active.filter(({ status }) => status === 'clean').length,
    activeFindings: active.filter(({ status }) => status === 'findings').length,
    activeFindingOccurrences: active.reduce(
      (sum, scan) => sum + scan.finding_count,
      0,
    ),
    candidateSourceRecords: context.source.candidates.entries.length,
    canonicalFindings: context.source.candidates.entries.filter(
      (candidate) => candidate.duplicateOf === undefined,
    ).length,
    duplicateCandidates: context.source.candidates.entries.filter(
      (candidate) => candidate.duplicateOf !== undefined,
    ).length,
    dispositions: dispositionHistogram(
      context.source.dispositions.dispositions,
    ),
  }
  const receiptCore = {
    formatVersion: 1 as const,
    format: 'atlas-audit-migration-v1' as const,
    migrationId: context.migrationId,
    repositoryId: context.repositoryId,
    source: {
      kind: SOURCE_KIND as typeof SOURCE_KIND,
      repositoryRevision: context.sourceRevision,
      files: context.source.documents.map(
        ({ path: repoPath, gitBlob, sha256 }) => ({
          path: repoPath,
          gitBlob,
          sha256,
        }),
      ),
    },
    validation: {
      repositoryRevision: context.validationRevision,
      policy: context.policySeal,
      historicalAssignmentsDigest: context.historicalAssignmentsDigest,
      exactWorktreeMatches: exactMatches,
      staleOrMissingPaths: active.length - exactMatches,
      digest: currentStateDigest(
        context.validationRevision,
        context.currentFiles,
      ),
    },
    converter: {
      name: CONVERTER_NAME,
      version: CONVERTER_VERSION,
      commit: CONVERTER_COMMIT,
    },
    recordedAt: context.recordedAt,
    recordedAtBasis: 'source-revision' as const,
    counts,
    mappings: buildMappings(context, observations, events),
    unmapped: [] as [],
    outputs: outputs.map(({ path: repoPath, sha256 }) => ({
      path: repoPath,
      sha256,
    })),
    parityChecks: [
      {
        name: 'all legacy scan records represented',
        status: 'passed' as const,
        details: `${counts.scanRecords} file receipts mapped with zero unmapped rows`,
      },
      {
        name: 'candidate reconciliation exact',
        status: 'passed' as const,
        details:
          `${counts.candidateSourceRecords} source candidates mapped to ` +
          `${counts.canonicalFindings} findings and ` +
          `${counts.duplicateCandidates} duplicate aliases`,
      },
      {
        name: 'all dispositions represented',
        status: 'passed' as const,
        details:
          `${counts.dispositions.remediated}/` +
          `${counts.dispositions.separateDesign}/` +
          `${counts.dispositions.acceptedRisk}/` +
          `${counts.dispositions.falsePositive}/` +
          `${counts.dispositions.superseded}`,
      },
    ],
    safeToDelete: [] as [],
  }
  const receipt: AuditMigrationReceiptV3 = {
    ...receiptCore,
    receiptDigest: computeAuditCanonicalDigest(receiptCore),
  }
  const receiptPath = `.atlas/migrations/${context.migrationId}.json`
  outputs.push(output(
    receiptPath,
    `${canonicalJson(receipt)}\n`,
    'receipt',
  ))
  const orderedOutputs = [...outputs].sort((left, right) =>
    compareText(left.path, right.path))
  const result: RelayOSMigrationResult = {
    migrationId: context.migrationId,
    receipt,
    observations: observations.observations,
    decisionEvents: events.decisionEvents,
    retirementEvents: events.retirementEvents,
    reconciliationEvents: events.reconciliationEvents,
    writes: orderedOutputs.map(({ path: repoPath, sha256 }) => ({
      path: repoPath,
      sha256,
    })),
  }
  return { result, outputs: orderedOutputs }
}

function applyPlan(
  root: string,
  options: NormalizedMigrationOptions,
  expected: MigrationPlan,
): void {
  const isMissingOutput = (error: unknown): boolean =>
    error instanceof Error &&
    (
      /missing or not a safe regular file/u.test(error.message) ||
      /audit parent is missing:/u.test(error.message)
    )

  withAuditLock(root, () => {
    const current = buildPlan(root, options)
    if (canonicalJson(current.result) !== canonicalJson(expected.result)) {
      fail('/apply', 'source or validation state changed after dry planning')
    }
    for (const output_ of current.outputs) {
      let existing: Uint8Array | null = null
      try {
        existing = readBoundedAuditBytes(
          root,
          output_.path,
          Math.max(
            Buffer.byteLength(output_.bytes, 'utf8'),
            AUDIT_LIMITS.jsonBytes,
          ),
        )
      } catch (error) {
        if (!isMissingOutput(error)) throw error
      }
      if (
        existing !== null &&
        !Buffer.from(existing).equals(Buffer.from(output_.bytes, 'utf8'))
      ) {
        fail(
          `/apply/${output_.path}`,
          'existing migration output diverges from the deterministic plan',
        )
      }
    }
    const applyOrder: PlannedOutput['family'][] = [
      'history',
      'decision',
      'current',
      'receipt',
    ]
    for (const family of applyOrder) {
      for (const output_ of current.outputs.filter(
        (candidate) => candidate.family === family,
      )) {
        let existingMatches = false
        try {
          existingMatches = Buffer.from(
            readBoundedAuditBytes(
              root,
              output_.path,
              Buffer.byteLength(output_.bytes, 'utf8'),
            ),
          ).equals(Buffer.from(output_.bytes, 'utf8'))
        } catch (error) {
          if (!isMissingOutput(error)) throw error
        }
        if (!existingMatches) {
          atomicWriteAuditFile(root, output_.path, output_.bytes)
        }
      }
    }
    for (const output_ of current.outputs) {
      const bytes = readBoundedAuditBytes(
        root,
        output_.path,
        Buffer.byteLength(output_.bytes, 'utf8'),
      )
      if (rawSha256(bytes) !== output_.sha256) {
        fail(`/apply/${output_.path}`, 'written output digest mismatch')
      }
    }
  })
}

export function buildRelayOSAuditMigration(
  root: string,
  unsafeOptions: RelayOSMigrationOptions,
): RelayOSMigrationResult {
  const options = snapshotOptions(unsafeOptions)
  return buildPlan(root, options).result
}

export function migrateRelayOSAudit(
  root: string,
  unsafeOptions: RelayOSMigrationOptions,
): RelayOSMigrationResult {
  const options = snapshotOptions(unsafeOptions)
  const plan = buildPlan(root, options)
  if (options.apply) applyPlan(root, options, plan)
  return plan.result
}
