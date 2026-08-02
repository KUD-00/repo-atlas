import { createHash } from 'node:crypto'
import {
  AUDIT_LIMITS,
  atomicWriteAuditFile,
  canonicalJson,
  normalizeAuditRepoPath,
  parseBoundedAuditJsonBytes,
  readBoundedAuditBytes,
  withAnchoredAuditGitCapability,
  withAnchoredAuditSupportSnapshot,
  withAuditLock,
} from './audit-core.js'
import type { AnchoredAuditGitCapability } from './audit-core.js'
import { computeAuditCanonicalDigest } from './audit-v3.js'
import type { AuditSha256 } from './audit-v3-types.js'
import {
  gitText,
  parseRepositoryId,
  readRevisionFile,
  RelayOSMigrationError,
  verifyRevisionCommit,
} from './audit-migrate-relayos.js'

const SOURCE_KIND = 'relayos-root-audits/v1'
const DESIGN_SOURCE_SCHEMA = 'relayos-design-scan/v1'
const DESIGN_RULESET = 'relayos-design-v1'
const DESIGN_FINDINGS_REF = 'findings.md'
const CONVERTER_NAME = 'repo-atlas'
const CONVERTER_VERSION = '0.1.0'
const CONVERTER_COMMIT = '39db1ac813dcf479b8fe9441aea1e8afbf85c2c9'
const DEFAULT_AUDITS_ROOT = 'audits'
const DEFAULT_DESIGN_LEDGERS_PATH = '.atlas/audits'
const DEFAULT_HISTORICAL_ARTIFACTS_PATH = '.atlas/artifacts/historical-audits'
const EGRESS_BOUNDARIES_NAME = 'security-egress-boundaries.json'
const EGRESS_POLICY_DESTINATION = `.atlas/policies/${EGRESS_BOUNDARIES_NAME}`
const DESIGN_SCAN_DIRECTORY = 'design-scan'
const DESIGN_SCAN_FILES = [
  'README.md',
  'findings.md',
  'ledger.json',
  'check.mjs',
  'to-atlas-ledger.mjs',
] as const
const DESIGN_PROSE_FILES = ['README.md', 'findings.md'] as const
const HISTORICAL_REPORTS = [
  {
    source: 'atlas-suspicion-audit/2026-07-05-report.md',
    artifact: 'atlas-suspicion-report.md',
  },
  {
    source: 'atlas-suspicion-audit/2026-07-05-solutions.md',
    artifact: 'atlas-suspicion-solutions.md',
  },
  {
    source: 'mobile-responsive-audit/findings.md',
    artifact: 'mobile-responsive-findings.md',
  },
] as const
const FULL_REVISION_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u
const SHA1_RE = /^[0-9a-f]{40}$/u
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/u
const DESIGN_LEDGER_NAME_RE = /^design-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.json$/u
const DESIGN_SLUG_RE = /^design-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u
const SOURCE_BYTES = 8 * 1024 * 1024
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true })

type JsonRecord = Record<string, unknown>
type DesignSeverity = 'high' | 'medium' | 'low'
type DesignConfidence = 'high' | 'medium' | 'low'

interface FileSeal {
  path: string
  gitBlob: string
  sha256: string
}

interface DesignScanRecord {
  sourceIndex: number
  path: string
  gitBlobSha1: string
  lines: number
  scannedAt: string
  scannedBy: string
  ruleset: string
  status: 'clean' | 'findings'
  maxSeverity: DesignSeverity | 'info' | null
  findingCount: number
  findingsRef: string | null
}

interface DesignScanLedger {
  note: string
  rulesetId: string
  categories: string[]
  scanner: {
    by: string
    method: string
    run: string
  }
  scans: DesignScanRecord[]
}

interface ParsedDesignFinding {
  severity: DesignSeverity
  category: string
  confidence: DesignConfidence
  locations: string[]
  evidence: string
  fix: string
}

interface ParsedDesignDropped {
  subject: string
  reason: string
  outcome: 'bar-held'
}

interface DesignV2Finding extends ParsedDesignFinding {
  title: string
  disposition: 'open'
}

interface DesignV2Ledger {
  seal: FileSeal
  slug: string
  title: string
  reviewState: string
  ruleset: string
  scannedAt: string
  scopeHash: string
  files: string[]
  hashes: Map<string, string>
  evidenceRefs: string[]
  findings: DesignV2Finding[]
  dropped: ParsedDesignDropped[]
}

interface HistoricalReport {
  sourcePath: string
  artifactPath: string
  gitBlob: string
  sha256: string
  text: string
}

interface RootAuditsContext {
  options: NormalizedRootAuditsOptions
  repositoryId: string
  recordedAt: string
  sourceFiles: FileSeal[]
  designScan: DesignScanLedger
  parsedFindings: ParsedDesignFinding[]
  parsedDropped: ParsedDesignDropped[]
  proseArtifacts: Array<FileSeal & { bytes: number }>
  historicalReports: HistoricalReport[]
  egressBefore: FileSeal
  egressAfter: FileSeal
  designLedgers: FileSeal[]
  claimingLedger: DesignV2Ledger
  historicalAssignmentsDigest: AuditSha256
  validationDigest: AuditSha256
  migrationId: string
}

interface PlannedOutput {
  path: string
  bytes: string
  sha256: string
  family: 'artifact' | 'receipt'
}

export interface RelayOSRootAuditsMigrationOptions {
  auditsRoot?: string
  designLedgersPath?: string
  historicalArtifactsPath?: string
  sourceRevision: string
  validationRevision: string
  apply?: boolean
}

interface NormalizedRootAuditsOptions {
  auditsRoot: string
  designLedgersPath: string
  historicalArtifactsPath: string
  sourceRevision: string
  validationRevision: string
  apply: boolean
}

export interface AuditRootAuditsMigrationReceiptV1 {
  formatVersion: 1
  format: 'atlas-audit-migration-v1'
  migrationId: string
  repositoryId: string
  source: {
    kind: typeof SOURCE_KIND
    repositoryRevision: string
    files: FileSeal[]
  }
  validation: {
    repositoryRevision: string
    policy: FileSeal
    historicalAssignmentsDigest: AuditSha256
    designLedgers: FileSeal[]
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
    sourceFiles: number
    designScanRecords: number
    designFindings: number
    designDropped: number
    historicalReports: number
    proseRecords: number
  }
  designParity: {
    ledger: FileSeal
    slug: string
    scopeHash: string
    filesMatched: number
    hashesMatched: number
    findingsMatched: number
    droppedMatched: number
    proseArtifacts: Array<FileSeal & { bytes: number }>
  }
  egressPolicy: {
    before: FileSeal
    after: FileSeal
    byteIdentical: true
    relocatedByThisMigrator: false
  }
  mappings: Array<{
    sourcePath: string
    sourcePointer: string
    sourceId: string
    destinationKind:
      | 'design-v2-scope'
      | 'design-v2-finding'
      | 'design-v2-dropped'
      | 'historical-artifact'
      | 'policy-relocation'
      | 'sealed-context'
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

export interface RelayOSRootAuditsMigrationResult {
  migrationId: string
  receipt: AuditRootAuditsMigrationReceiptV1
  historicalArtifacts: Array<{
    sourcePath: string
    path: string
    gitBlob: string
    sha256: string
  }>
  writes: Array<{ path: string; sha256: string }>
}

export class RelayOSRootAuditsMigrationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RelayOSRootAuditsMigrationError'
  }
}

function fail(pointer: string, message: string): never {
  throw new RelayOSRootAuditsMigrationError(
    `RelayOS root-audits migration ${pointer}: ${message}`,
  )
}

function translateSharedFailure(error: unknown): never {
  if (error instanceof RelayOSMigrationError) {
    throw new RelayOSRootAuditsMigrationError(
      error.message.replace(
        /^RelayOS legacy migration/u,
        'RelayOS root-audits migration',
      ),
    )
  }
  throw error
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

function repoPathAt(value: unknown, pointer: string): string {
  try {
    const parsed = normalizeAuditRepoPath(stringAt(value, pointer))
    if (parsed.normalize('NFC') !== parsed) {
      fail(pointer, 'repository path must use NFC normalization')
    }
    return parsed
  } catch (error) {
    if (error instanceof RelayOSRootAuditsMigrationError) throw error
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

function parseJsonDocument(
  bytes: Buffer,
  repoPath: string,
  pointer: string,
): unknown {
  try {
    return parseBoundedAuditJsonBytes(bytes, SOURCE_BYTES, repoPath)
  } catch (error) {
    fail(
      pointer,
      error instanceof Error ? error.message : 'is not valid bounded JSON',
    )
  }
}

function parseDesignScan(value: unknown, index: number): DesignScanRecord {
  const pointer = `/design-scan/ledger.json/scans/${index}`
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
    [],
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
    status === 'clean' &&
    (findingCount !== 0 || maxSeverity !== null || findingsRef !== null)
  ) {
    fail(pointer, 'a clean record forbids counts, severity, and references')
  }
  if (
    status === 'findings' &&
    (findingCount < 1 || maxSeverity === null || findingsRef === null)
  ) {
    fail(pointer, 'status, count, severity, and findings reference disagree')
  }
  if (findingsRef !== null && findingsRef !== DESIGN_FINDINGS_REF) {
    fail(`${pointer}/findings_ref`, `expected ${DESIGN_FINDINGS_REF}`)
  }
  const ruleset = stringAt(scan.ruleset, `${pointer}/ruleset`)
  if (ruleset !== DESIGN_RULESET) {
    fail(`${pointer}/ruleset`, 'unexpected legacy design ruleset')
  }
  return {
    sourceIndex: index,
    path: repoPathAt(scan.path, `${pointer}/path`),
    gitBlobSha1: sha1At(scan.git_blob_sha1, `${pointer}/git_blob_sha1`),
    lines: integerAt(scan.lines, `${pointer}/lines`),
    scannedAt: dateAt(scan.scanned_at, `${pointer}/scanned_at`),
    scannedBy: stringAt(scan.scanned_by, `${pointer}/scanned_by`),
    ruleset,
    status,
    maxSeverity: maxSeverity as DesignScanRecord['maxSeverity'],
    findingCount,
    findingsRef,
  }
}

function parseDesignScanLedger(value: unknown): DesignScanLedger {
  const pointer = '/design-scan/ledger.json'
  const ledger = recordAt(value, pointer)
  exactKeys(
    ledger,
    ['schema', 'note', 'ruleset', 'scanner', 'scans'],
    [],
    pointer,
  )
  if (ledger.schema !== DESIGN_SOURCE_SCHEMA) {
    fail(`${pointer}/schema`, `expected ${DESIGN_SOURCE_SCHEMA}`)
  }
  const ruleset = recordAt(ledger.ruleset, `${pointer}/ruleset`)
  exactKeys(ruleset, ['id', 'categories'], [], `${pointer}/ruleset`)
  const rulesetId = stringAt(ruleset.id, `${pointer}/ruleset/id`)
  if (rulesetId !== DESIGN_RULESET) {
    fail(`${pointer}/ruleset/id`, 'unexpected legacy design ruleset ID')
  }
  const categories = stringsAt(
    ruleset.categories,
    `${pointer}/ruleset/categories`,
  )
  const scanner = recordAt(ledger.scanner, `${pointer}/scanner`)
  exactKeys(scanner, ['by', 'method', 'run'], [], `${pointer}/scanner`)
  const scans = arrayAt(ledger.scans, `${pointer}/scans`)
    .map(parseDesignScan)
    .sort((left, right) => compareText(left.path, right.path))
  if (scans.length > 10_000) fail(`${pointer}/scans`, 'exceeds 10000 rows')
  for (let index = 1; index < scans.length; index += 1) {
    if (scans[index].path === scans[index - 1].path) {
      fail(`${pointer}/scans`, `duplicate scan path ${scans[index].path}`)
    }
  }
  return {
    note: stringAt(ledger.note, `${pointer}/note`),
    rulesetId,
    categories,
    scanner: {
      by: stringAt(scanner.by, `${pointer}/scanner/by`),
      method: stringAt(scanner.method, `${pointer}/scanner/method`),
      run: stringAt(scanner.run, `${pointer}/scanner/run`),
    },
    scans,
  }
}

function headingPaths(
  heading: string,
  scannedPaths: ReadonlySet<string>,
  pointer: string,
): string[] {
  const parts = heading
    .split('·')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
  const first = parts[0]
  if (first === undefined || !scannedPaths.has(first)) {
    fail(
      pointer,
      `heading path is outside the audited scope: ${first ?? heading}`,
    )
  }
  const directory = first.includes('/')
    ? first.slice(0, first.lastIndexOf('/'))
    : '.'
  return parts.map((part, index) =>
    index === 0 ? part : directory === '.' ? part : `${directory}/${part}`)
}

function resolveLocationPath(
  token: string,
  candidates: readonly string[],
  pointer: string,
): string {
  const hit = candidates.filter(
    (candidate) => candidate === token || candidate.endsWith(`/${token}`),
  )
  if (hit.length !== 1) {
    fail(
      pointer,
      `location "${token}" resolves to ${hit.length} scope paths ` +
        `(candidates: ${candidates.join(', ')})`,
    )
  }
  return hit[0]
}

// Parses findings.md with the exact algorithm the sealed historical converter
// `to-atlas-ledger.mjs` used, so parity compares source-derived facts instead
// of trusting either document. Authored titles are the only V2-only field.
function parseDesignFindingsDocument(
  text: string,
  scannedPaths: ReadonlySet<string>,
  categories: ReadonlySet<string>,
  pointer: string,
): { findings: ParsedDesignFinding[]; dropped: ParsedDesignDropped[] } {
  const findings: ParsedDesignFinding[] = []
  const dropped: ParsedDesignDropped[] = []
  let heading: string | null = null
  let section: string | null = null
  const lines = text.split('\n')
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    const linePointer = `${pointer}/${index + 1}`
    const sectionMatch = /^## (.+)$/u.exec(line)
    if (sectionMatch) {
      section = sectionMatch[1]
      heading = null
      continue
    }
    const headingMatch = /^### (.+)$/u.exec(line)
    if (headingMatch) {
      heading = headingMatch[1]
      continue
    }
    if (!line.startsWith('- ')) continue
    if (section !== null && section.startsWith('Deliberately not flagged')) {
      const parts = line.slice(2).split(' — ')
      if (parts.length < 2) {
        fail(linePointer, 'unparsable bar-held entry')
      }
      dropped.push({
        subject: parts[0].trim(),
        reason: parts.slice(1).join(' — ').trim(),
        outcome: 'bar-held',
      })
      continue
    }
    const bullet =
      /^- \*\*\[(MEDIUM|LOW|HIGH)\]\[([a-z-]+)\]\[(high|medium|low)\]\*\*\s+(.+)$/u
        .exec(line)
    if (bullet === null) continue
    if (heading === null) {
      fail(linePointer, 'finding bullet before any file heading')
    }
    const [, severityLabel, category, confidence, rest] = bullet
    if (!categories.has(category)) {
      fail(linePointer, `category ${category} is outside the legacy ruleset`)
    }
    const split = rest.indexOf(' — ')
    if (split < 0) {
      fail(linePointer, 'finding has no " — " evidence separator')
    }
    const locationSegment = rest.slice(0, split)
    const body = rest.slice(split + 3).trim()
    const candidates = headingPaths(heading, scannedPaths, linePointer)
    const locations: string[] = []
    for (
      const match of locationSegment.matchAll(
        /`([^`:]+):([0-9,\-–]+)`/gu,
      )
    ) {
      const [, token, lineSpec] = match
      const repoPath = resolveLocationPath(token, candidates, linePointer)
      for (const part of lineSpec.split(',')) {
        const start = part.split(/[-–]/u)[0].trim()
        if (!/^[1-9][0-9]*$/u.test(start)) {
          fail(linePointer, `unparsable line spec "${part}"`)
        }
        locations.push(`${repoPath}:${start}`)
      }
    }
    if (locations.length === 0) {
      fail(linePointer, 'finding has no parsable location')
    }
    const fixAt = body.indexOf('**Fix:**')
    if (fixAt < 0) {
      fail(linePointer, 'finding has no **Fix:**')
    }
    const evidence = body.slice(0, fixAt).trim()
    const fix = body.slice(fixAt + '**Fix:**'.length).trim()
    if (evidence.length === 0 || fix.length === 0) {
      fail(linePointer, 'finding has an empty evidence or fix')
    }
    findings.push({
      severity: severityLabel.toLowerCase() as DesignSeverity,
      category,
      confidence: confidence as DesignConfidence,
      locations: [...new Set(locations)],
      evidence,
      fix,
    })
  }
  for (const finding of findings) {
    const paths = finding.locations.map((location) =>
      location.slice(0, location.lastIndexOf(':')))
    if (!paths.some((repoPath) => scannedPaths.has(repoPath))) {
      fail(
        pointer,
        `finding lands entirely outside the audited scope: ${finding.locations.join(', ')}`,
      )
    }
  }
  return { findings, dropped }
}

function parseDesignV2Finding(
  value: unknown,
  index: number,
  scannedPaths: ReadonlySet<string>,
  pointer: string,
): DesignV2Finding {
  const findingPointer = `${pointer}/findings/${index}`
  const finding = recordAt(value, findingPointer)
  exactKeys(
    finding,
    [
      'severity',
      'category',
      'title',
      'locations',
      'evidence',
      'fix',
      'confidence',
      'disposition',
    ],
    [],
    findingPointer,
  )
  const severity = stringAt(finding.severity, `${findingPointer}/severity`)
  if (!['high', 'medium', 'low'].includes(severity)) {
    fail(`${findingPointer}/severity`, 'unsupported design severity')
  }
  const confidence = stringAt(
    finding.confidence,
    `${findingPointer}/confidence`,
  )
  if (!['high', 'medium', 'low'].includes(confidence)) {
    fail(`${findingPointer}/confidence`, 'unsupported design confidence')
  }
  if (finding.disposition !== 'open') {
    fail(`${findingPointer}/disposition`, 'expected the historical open state')
  }
  const locations = stringsAt(
    finding.locations,
    `${findingPointer}/locations`,
  ).map((location, locationIndex) => {
    const locationPointer = `${findingPointer}/locations/${locationIndex}`
    const separator = location.lastIndexOf(':')
    if (separator <= 0) {
      fail(locationPointer, 'expected a <repo path>:<line> location')
    }
    const repoPath = location.slice(0, separator)
    const line = location.slice(separator + 1)
    if (!/^[1-9][0-9]*$/u.test(line)) {
      fail(locationPointer, 'expected a positive line number')
    }
    if (!scannedPaths.has(repoPath)) {
      fail(locationPointer, `location is outside the audited scope: ${repoPath}`)
    }
    return location
  })
  return {
    severity: severity as DesignSeverity,
    category: stringAt(finding.category, `${findingPointer}/category`),
    title: stringAt(finding.title, `${findingPointer}/title`),
    locations,
    evidence: stringAt(finding.evidence, `${findingPointer}/evidence`),
    fix: stringAt(finding.fix, `${findingPointer}/fix`),
    confidence: confidence as DesignConfidence,
    disposition: 'open',
  }
}

function parseDesignV2Dropped(
  value: unknown,
  index: number,
  pointer: string,
): ParsedDesignDropped {
  const droppedPointer = `${pointer}/dropped/${index}`
  const dropped = recordAt(value, droppedPointer)
  exactKeys(dropped, ['subject', 'reason', 'outcome'], [], droppedPointer)
  if (dropped.outcome !== 'bar-held') {
    fail(`${droppedPointer}/outcome`, 'expected the historical bar-held state')
  }
  return {
    subject: stringAt(dropped.subject, `${droppedPointer}/subject`),
    reason: stringAt(dropped.reason, `${droppedPointer}/reason`),
    outcome: 'bar-held',
  }
}

function designScopeHash(
  files: readonly string[],
  hashes: ReadonlyMap<string, string>,
): string {
  const lines = files.map((file) => `${hashes.get(file) ?? ''}  ${file}`)
  return createHash('sha1')
    .update([...lines].sort().join('\n') + '\n', 'utf8')
    .digest('hex')
}

function validateDesignV2Ledger(
  value: unknown,
  seal: FileSeal,
  designLedgersPath: string,
  designScan: DesignScanLedger,
  expectedEvidenceRefs: readonly string[],
): DesignV2Ledger {
  const pointer = `/${seal.path}`
  const ledger = recordAt(value, pointer)
  exactKeys(
    ledger,
    [
      'formatVersion',
      'format',
      'domain',
      'reviewState',
      'slug',
      'title',
      'ruleset',
      'scanned_at',
      'scope_hash',
      'file_count',
      'files',
      'hashes',
      'evidenceRefs',
      'findings',
      'dropped',
    ],
    [],
    pointer,
  )
  if (ledger.formatVersion !== 2) {
    fail(`${pointer}/formatVersion`, 'expected the V2 ledger format version')
  }
  if (ledger.format !== 'atlas-audit-v2') {
    fail(`${pointer}/format`, 'expected atlas-audit-v2')
  }
  if (ledger.domain !== 'design') {
    fail(`${pointer}/domain`, 'expected the design domain')
  }
  const reviewState = stringAt(ledger.reviewState, `${pointer}/reviewState`)
  if (reviewState !== 'complete') {
    fail(`${pointer}/reviewState`, 'expected the historical complete state')
  }
  const slug = stringAt(ledger.slug, `${pointer}/slug`)
  if (!DESIGN_SLUG_RE.test(slug)) {
    fail(`${pointer}/slug`, 'expected a design-<unit> slug')
  }
  if (seal.path !== `${designLedgersPath}/${slug}.json`) {
    fail(`${pointer}/slug`, 'slug does not match the ledger filename')
  }
  const ruleset = stringAt(ledger.ruleset, `${pointer}/ruleset`)
  if (ruleset !== designScan.rulesetId) {
    fail(`${pointer}/ruleset`, 'does not match the legacy design ruleset')
  }
  const scannedAt = dateAt(ledger.scanned_at, `${pointer}/scanned_at`)
  const latestScan = designScan.scans.map((scan) => scan.scannedAt).sort().at(-1)
  if (latestScan !== undefined && scannedAt !== latestScan) {
    fail(
      `${pointer}/scanned_at`,
      'does not match the latest legacy scan date',
    )
  }
  const scopeHash = sha1At(ledger.scope_hash, `${pointer}/scope_hash`)
  const files = stringsAt(ledger.files, `${pointer}/files`).map((file, index) =>
    repoPathAt(file, `${pointer}/files/${index}`))
  const sortedFiles = [...files].sort(compareText)
  if (
    files.length !== sortedFiles.length ||
    files.some((file, index) => file !== sortedFiles[index])
  ) {
    fail(`${pointer}/files`, 'expected a sorted file list')
  }
  const fileCount = integerAt(ledger.file_count, `${pointer}/file_count`)
  if (fileCount !== files.length) {
    fail(`${pointer}/file_count`, 'does not match the file list')
  }
  const hashesValue = recordAt(ledger.hashes, `${pointer}/hashes`)
  const hashes = new Map<string, string>()
  for (const [key, hash] of Object.entries(hashesValue)) {
    hashes.set(
      repoPathAt(key, `${pointer}/hashes/${key}`),
      sha1At(hash, `${pointer}/hashes/${key}`),
    )
  }
  if (hashes.size !== files.length) {
    fail(`${pointer}/hashes`, 'hash count does not match the file list')
  }
  for (const file of files) {
    if (!hashes.has(file)) {
      fail(`${pointer}/hashes/${file}`, 'missing file hash')
    }
  }
  const evidenceRefs = stringsAt(
    ledger.evidenceRefs,
    `${pointer}/evidenceRefs`,
  ).map((ref, index) => repoPathAt(ref, `${pointer}/evidenceRefs/${index}`))
  if (
    [...evidenceRefs].sort(compareText).join('\n') !==
      [...expectedEvidenceRefs].sort(compareText).join('\n')
  ) {
    fail(
      `${pointer}/evidenceRefs`,
      'does not name exactly the legacy design-scan sources',
    )
  }
  const scannedPaths = new Set(designScan.scans.map((scan) => scan.path))
  const findings = arrayAt(ledger.findings, `${pointer}/findings`).map(
    (finding, index) =>
      parseDesignV2Finding(finding, index, scannedPaths, pointer),
  )
  const dropped = arrayAt(ledger.dropped, `${pointer}/dropped`).map(
    (entry, index) => parseDesignV2Dropped(entry, index, pointer),
  )
  return {
    seal,
    slug,
    title: stringAt(ledger.title, `${pointer}/title`),
    reviewState,
    ruleset,
    scannedAt,
    scopeHash,
    files,
    hashes,
    evidenceRefs,
    findings,
    dropped,
  }
}

function verifyDesignParity(
  context: RootAuditsContext,
): void {
  const ledger = context.claimingLedger
  const pointer = `/${ledger.seal.path}`
  const scans = context.designScan.scans
  const scanPaths = scans.map((scan) => scan.path)
  if (
    ledger.files.length !== scanPaths.length ||
    ledger.files.some((file, index) => file !== scanPaths[index])
  ) {
    fail(
      `${pointer}/files`,
      'V2 scope does not equal the sorted legacy scan paths',
    )
  }
  for (const scan of scans) {
    const hash = ledger.hashes.get(scan.path)
    if (hash !== scan.gitBlobSha1) {
      fail(
        `${pointer}/hashes/${scan.path}`,
        'V2 file hash does not match the legacy scan seal',
      )
    }
  }
  const recomputed = designScopeHash(ledger.files, ledger.hashes)
  if (recomputed !== ledger.scopeHash) {
    fail(
      `${pointer}/scope_hash`,
      'V2 scope hash does not match its own file seals',
    )
  }
  if (ledger.findings.length !== context.parsedFindings.length) {
    fail(
      `${pointer}/findings`,
      `V2 records ${ledger.findings.length} findings but ` +
        `${context.parsedFindings.length} parse from the legacy findings document`,
    )
  }
  for (const [index, parsed] of context.parsedFindings.entries()) {
    const candidate = ledger.findings[index]
    const findingPointer = `${pointer}/findings/${index}`
    if (
      candidate.severity !== parsed.severity ||
      candidate.category !== parsed.category ||
      candidate.confidence !== parsed.confidence ||
      candidate.evidence !== parsed.evidence ||
      candidate.fix !== parsed.fix ||
      candidate.locations.length !== parsed.locations.length ||
      candidate.locations.some(
        (location, locationIndex) =>
          location !== parsed.locations[locationIndex],
      )
    ) {
      fail(
        findingPointer,
        'V2 finding does not match the exact legacy prose parse',
      )
    }
  }
  if (ledger.dropped.length !== context.parsedDropped.length) {
    fail(
      `${pointer}/dropped`,
      'V2 bar-held entries do not match the legacy prose parse',
    )
  }
  for (const [index, parsed] of context.parsedDropped.entries()) {
    const candidate = ledger.dropped[index]
    if (
      candidate.subject !== parsed.subject ||
      candidate.reason !== parsed.reason ||
      candidate.outcome !== parsed.outcome
    ) {
      fail(
        `${pointer}/dropped/${index}`,
        'V2 bar-held entry does not match the exact legacy prose parse',
      )
    }
  }
  const findingsByPath = new Map<string, number>()
  for (const finding of context.parsedFindings) {
    const files = new Set(
      finding.locations.map((location) =>
        location.slice(0, location.lastIndexOf(':'))),
    )
    for (const file of files) {
      findingsByPath.set(file, (findingsByPath.get(file) ?? 0) + 1)
    }
  }
  for (const scan of scans) {
    const actual = findingsByPath.get(scan.path) ?? 0
    if (actual !== scan.findingCount) {
      fail(
        `/design-scan/ledger.json/scans/${scan.sourceIndex}/finding_count`,
        `declares ${scan.findingCount} findings but ${actual} parsed findings ` +
          `cite ${scan.path}`,
      )
    }
  }
}

function listDesignLedgerSeals(
  git: AnchoredAuditGitCapability,
  revision: string,
  designLedgersPath: string,
): FileSeal[] {
  const pointer = `/validation/${designLedgersPath}`
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
          `:(literal)${designLedgersPath}/`,
        ],
        AUDIT_LIMITS.jsonBytes,
      ),
    )
  } catch {
    fail(pointer, 'unable to list the pinned revision tree')
  }
  let text: string
  try {
    text = UTF8_STRICT.decode(listing)
  } catch {
    fail(pointer, 'pinned revision tree listing is not strict UTF-8')
  }
  const records = text.split('\0')
  if (records.at(-1) === '') records.pop()
  const candidates: Array<{ path: string; gitBlob: string }> = []
  for (const record of records) {
    const match = /^([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40})\t([\s\S]+)$/u
      .exec(record)
    if (!match) {
      fail(pointer, 'Git returned a malformed tree entry')
    }
    const [, mode, type, objectId, entryPath] = match
    const prefix = `${designLedgersPath}/`
    if (!entryPath.startsWith(prefix)) continue
    const name = entryPath.slice(prefix.length)
    if (name.includes('/') || !DESIGN_LEDGER_NAME_RE.test(name)) continue
    if (type !== 'blob' || (mode !== '100644' && mode !== '100755')) {
      fail(
        `${pointer}/${entryPath}`,
        'revision tree entry is a symlink, gitlink, or non-regular file',
      )
    }
    candidates.push({ path: entryPath, gitBlob: objectId })
  }
  candidates.sort((left, right) => compareText(left.path, right.path))
  const seals: FileSeal[] = []
  for (const candidate of candidates) {
    const document = readRevisionFile(
      git,
      revision,
      candidate.path,
      SOURCE_BYTES,
      '/validation',
    )
    if (document === null) {
      fail(
        `/validation/${candidate.path}`,
        'design ledger vanished from the pinned revision tree',
      )
    }
    seals.push({
      path: candidate.path,
      gitBlob: document.gitBlob,
      sha256: rawSha256(document.bytes),
    })
  }
  return seals
}

function snapshotOptions(
  unsafeOptions: RelayOSRootAuditsMigrationOptions | undefined,
): NormalizedRootAuditsOptions {
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
    ['auditsRoot', 'designLedgersPath', 'historicalArtifactsPath', 'apply'],
    '/options',
  )
  const auditsRoot = options.auditsRoot === undefined
    ? DEFAULT_AUDITS_ROOT
    : repoPathAt(options.auditsRoot, '/options/auditsRoot')
  const designLedgersPath = options.designLedgersPath === undefined
    ? DEFAULT_DESIGN_LEDGERS_PATH
    : repoPathAt(options.designLedgersPath, '/options/designLedgersPath')
  const historicalArtifactsPath = options.historicalArtifactsPath === undefined
    ? DEFAULT_HISTORICAL_ARTIFACTS_PATH
    : repoPathAt(
      options.historicalArtifactsPath,
      '/options/historicalArtifactsPath',
    )
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
  if (options.apply !== undefined && typeof options.apply !== 'boolean') {
    fail('/options/apply', 'expected a boolean')
  }
  return {
    auditsRoot,
    designLedgersPath,
    historicalArtifactsPath,
    sourceRevision,
    validationRevision,
    apply: options.apply === true,
  }
}

function readSourceDocument(
  git: AnchoredAuditGitCapability,
  revision: string,
  repoPath: string,
): { bytes: Buffer; gitBlob: string } {
  const document = readRevisionFile(
    git,
    revision,
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
  return document
}

function sealOf(repoPath: string, bytes: Buffer, gitBlob: string): FileSeal {
  return { path: repoPath, gitBlob, sha256: rawSha256(bytes) }
}

function buildContext(
  root: string,
  options: NormalizedRootAuditsOptions,
): RootAuditsContext {
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

      const designScanRoot = `${options.auditsRoot}/${DESIGN_SCAN_DIRECTORY}`
      const sourceFiles = new Map<string, FileSeal & { bytes: Buffer }>()
      const sealSource = (repoPath: string): Buffer => {
        const document = readSourceDocument(
          git,
          options.sourceRevision,
          repoPath,
        )
        sourceFiles.set(repoPath, {
          ...sealOf(repoPath, document.bytes, document.gitBlob),
          bytes: document.bytes,
        })
        return document.bytes
      }

      const designBytes = new Map<string, Buffer>()
      for (const name of DESIGN_SCAN_FILES) {
        designBytes.set(name, sealSource(`${designScanRoot}/${name}`))
      }
      const historicalReports: HistoricalReport[] = HISTORICAL_REPORTS.map(
        ({ source, artifact }) => {
          const sourcePath = `${options.auditsRoot}/${source}`
          const bytes = sealSource(sourcePath)
          let text: string
          try {
            text = UTF8_STRICT.decode(bytes)
          } catch {
            fail(
              `/source/${sourcePath}`,
              'historical report is not strict UTF-8',
            )
          }
          const sealed = sourceFiles.get(sourcePath)!
          return {
            sourcePath,
            artifactPath: `${options.historicalArtifactsPath}/${artifact}`,
            gitBlob: sealed.gitBlob,
            sha256: sealed.sha256,
            text,
          }
        },
      )
      const egressBeforePath = `${options.auditsRoot}/${EGRESS_BOUNDARIES_NAME}`
      const egressBeforeBytes = sealSource(egressBeforePath)
      const egressBefore = sealOf(
        egressBeforePath,
        egressBeforeBytes,
        sourceFiles.get(egressBeforePath)!.gitBlob,
      )

      const designScan = parseDesignScanLedger(
        parseJsonDocument(
          designBytes.get('ledger.json')!,
          `${designScanRoot}/ledger.json`,
          `/source/${designScanRoot}/ledger.json`,
        ),
      )
      let findingsText: string
      try {
        findingsText = UTF8_STRICT.decode(designBytes.get('findings.md')!)
      } catch {
        fail(
          `/source/${designScanRoot}/findings.md`,
          'findings document is not strict UTF-8',
        )
      }
      const scannedPaths = new Set(designScan.scans.map((scan) => scan.path))
      const { findings: parsedFindings, dropped: parsedDropped } =
        parseDesignFindingsDocument(
          findingsText,
          scannedPaths,
          new Set(designScan.categories),
          `/source/${designScanRoot}/findings.md`,
        )
      const proseArtifacts = DESIGN_PROSE_FILES.map((name) => {
        const repoPath = `${designScanRoot}/${name}`
        const sealed = sourceFiles.get(repoPath)!
        return {
          path: sealed.path,
          gitBlob: sealed.gitBlob,
          sha256: sealed.sha256,
          bytes: sealed.bytes.byteLength,
        }
      }).sort((left, right) => compareText(left.path, right.path))

      const egressAfterDocument = readRevisionFile(
        git,
        options.validationRevision,
        EGRESS_POLICY_DESTINATION,
        SOURCE_BYTES,
        '/validation',
      )
      if (egressAfterDocument === null) {
        fail(
          `/validation/${EGRESS_POLICY_DESTINATION}`,
          'egress policy destination is missing at the validation revision; ' +
            'the reviewed RelayOS product edit must land first',
        )
      }
      const egressAfter = sealOf(
        EGRESS_POLICY_DESTINATION,
        egressAfterDocument.bytes,
        egressAfterDocument.gitBlob,
      )
      if (egressAfter.gitBlob !== egressBefore.gitBlob) {
        fail(
          `/validation/${EGRESS_POLICY_DESTINATION}`,
          'egress policy destination bytes differ from the sealed source bytes',
        )
      }

      const designLedgers = listDesignLedgerSeals(
        git,
        options.validationRevision,
        options.designLedgersPath,
      )
      const expectedEvidenceRefs = [
        `${designScanRoot}/ledger.json`,
        `${designScanRoot}/findings.md`,
      ]
      const claiming: DesignV2Ledger[] = []
      for (const seal of designLedgers) {
        const document = readRevisionFile(
          git,
          options.validationRevision,
          seal.path,
          SOURCE_BYTES,
          '/validation',
        )
        if (document === null) {
          fail(
            `/validation/${seal.path}`,
            'design ledger vanished from the pinned revision tree',
          )
        }
        const value = parseJsonDocument(
          document.bytes,
          seal.path,
          `/validation/${seal.path}`,
        )
        const record = recordAt(value, `/validation/${seal.path}`)
        if (record.format !== 'atlas-audit-v2' || record.domain !== 'design') {
          fail(
            `/validation/${seal.path}`,
            'design-*.json is not an atlas-audit-v2 design ledger',
          )
        }
        const refs = arrayAt(
          record.evidenceRefs,
          `/validation/${seal.path}/evidenceRefs`,
        ).map((ref, index) =>
          stringAt(ref, `/validation/${seal.path}/evidenceRefs/${index}`))
        if (
          expectedEvidenceRefs.every((expected) => refs.includes(expected))
        ) {
          claiming.push(
            validateDesignV2Ledger(
              value,
              seal,
              options.designLedgersPath,
              designScan,
              expectedEvidenceRefs,
            ),
          )
        }
      }
      if (claiming.length === 0) {
        fail(
          `/validation/${options.designLedgersPath}`,
          'no design V2 ledger claims the legacy design scan; every legacy ' +
            'unit and finding would be unmapped',
        )
      }
      if (claiming.length > 1) {
        fail(
          `/validation/${options.designLedgersPath}`,
          `multiple design V2 ledgers claim the legacy design scan: ${claiming
            .map(({ seal }) => seal.path)
            .join(', ')}`,
        )
      }

      const sortedInputSeals = [...sourceFiles.values()]
        .map(({ path, gitBlob, sha256 }) => ({ path, gitBlob, sha256 }))
        .sort((left, right) => compareText(left.path, right.path))
      const historicalAssignmentsDigest = prefixedSha256({
        namespace: 'repo-atlas/relayos-root-audits-historical-assignments/v1',
        assignments: historicalReports
          .map(({ sourcePath, artifactPath }) => ({
            from: sourcePath,
            to: artifactPath,
          }))
          .sort((left, right) => compareText(left.from, right.from)),
      })
      const validationDigest = prefixedSha256({
        namespace: 'repo-atlas/relayos-root-audits-validation/v1',
        repositoryRevision: options.validationRevision,
        policy: egressAfter,
        designLedgers,
        historicalAssignmentsDigest,
      })
      const migrationId =
        `amig_${rawSha256([
          'atlas-migration/v1',
          SOURCE_KIND,
          repositoryId,
          options.sourceRevision,
          options.validationRevision,
          egressAfter.sha256,
          historicalAssignmentsDigest,
          CONVERTER_NAME,
          CONVERTER_VERSION,
          CONVERTER_COMMIT,
          canonicalJson(sortedInputSeals),
        ].join('\0')).slice(0, 24)}`
      return {
        options,
        repositoryId,
        recordedAt,
        sourceFiles: sortedInputSeals,
        designScan,
        parsedFindings,
        parsedDropped,
        proseArtifacts,
        historicalReports,
        egressBefore,
        egressAfter,
        designLedgers,
        claimingLedger: claiming[0],
        historicalAssignmentsDigest,
        validationDigest,
        migrationId,
      }
    })
  })
}

function output(
  path: string,
  bytes: string,
  sha256: string,
  family: PlannedOutput['family'],
): PlannedOutput {
  return {
    path,
    bytes,
    sha256,
    family,
  }
}

function buildMappings(
  context: RootAuditsContext,
  receiptPath: string,
): AuditRootAuditsMigrationReceiptV1['mappings'] {
  const mappings: AuditRootAuditsMigrationReceiptV1['mappings'] = []
  const designScanRoot = `${context.options.auditsRoot}/${DESIGN_SCAN_DIRECTORY}`
  const ledgerPath = context.claimingLedger.seal.path
  for (const scan of context.designScan.scans) {
    mappings.push({
      sourcePath: `${designScanRoot}/ledger.json`,
      sourcePointer: `/scans/${scan.sourceIndex}`,
      sourceId: `${scan.path}@${scan.gitBlobSha1}`,
      destinationKind: 'design-v2-scope',
      destinationIds: [ledgerPath],
    })
  }
  for (const [index, finding] of context.parsedFindings.entries()) {
    const key = `${finding.category}@${finding.locations[0]}`
    mappings.push({
      sourcePath: `${designScanRoot}/findings.md`,
      sourcePointer: `/findings/${index}`,
      sourceId: key,
      destinationKind: 'design-v2-finding',
      destinationIds: [ledgerPath, key],
    })
  }
  for (const [index, dropped] of context.parsedDropped.entries()) {
    mappings.push({
      sourcePath: `${designScanRoot}/findings.md`,
      sourcePointer: `/dropped/${index}`,
      sourceId: dropped.subject,
      destinationKind: 'design-v2-dropped',
      destinationIds: [ledgerPath],
    })
  }
  for (const name of ['check.mjs', 'to-atlas-ledger.mjs'] as const) {
    const sourcePath = `${designScanRoot}/${name}`
    mappings.push({
      sourcePath,
      sourcePointer: '/',
      sourceId: context.sourceFiles.find(({ path }) => path === sourcePath)!
        .gitBlob,
      destinationKind: 'sealed-context',
      destinationIds: [receiptPath],
    })
  }
  for (const prose of context.proseArtifacts) {
    mappings.push({
      sourcePath: prose.path,
      sourcePointer: '/',
      sourceId: prose.gitBlob,
      destinationKind: 'sealed-context',
      destinationIds: [receiptPath],
    })
  }
  for (const report of context.historicalReports) {
    mappings.push({
      sourcePath: report.sourcePath,
      sourcePointer: '/',
      sourceId: report.gitBlob,
      destinationKind: 'historical-artifact',
      destinationIds: [report.artifactPath],
    })
  }
  mappings.push({
    sourcePath: context.egressBefore.path,
    sourcePointer: '/',
    sourceId: context.egressBefore.gitBlob,
    destinationKind: 'policy-relocation',
    destinationIds: [context.egressAfter.path],
  })
  return mappings.sort((left, right) =>
    compareText(left.sourcePath, right.sourcePath) ||
    compareText(left.sourcePointer, right.sourcePointer) ||
    compareText(left.destinationKind, right.destinationKind))
}

interface MigrationPlan {
  result: RelayOSRootAuditsMigrationResult
  outputs: PlannedOutput[]
}

function buildPlan(
  root: string,
  options: NormalizedRootAuditsOptions,
): MigrationPlan {
  const context = buildContext(root, options)
  verifyDesignParity(context)
  const outputs: PlannedOutput[] = []
  for (const report of context.historicalReports) {
    outputs.push(
      output(report.artifactPath, report.text, report.sha256, 'artifact'),
    )
  }
  const counts: AuditRootAuditsMigrationReceiptV1['counts'] = {
    sourceFiles: context.sourceFiles.length,
    designScanRecords: context.designScan.scans.length,
    designFindings: context.parsedFindings.length,
    designDropped: context.parsedDropped.length,
    historicalReports: context.historicalReports.length,
    proseRecords: context.proseArtifacts.length,
  }
  const receiptPath = `.atlas/migrations/${context.migrationId}.json`
  const receiptCore = {
    formatVersion: 1 as const,
    format: 'atlas-audit-migration-v1' as const,
    migrationId: context.migrationId,
    repositoryId: context.repositoryId,
    source: {
      kind: SOURCE_KIND as typeof SOURCE_KIND,
      repositoryRevision: options.sourceRevision,
      files: context.sourceFiles,
    },
    validation: {
      repositoryRevision: options.validationRevision,
      policy: context.egressAfter,
      historicalAssignmentsDigest: context.historicalAssignmentsDigest,
      designLedgers: context.designLedgers,
      digest: context.validationDigest,
    },
    converter: {
      name: CONVERTER_NAME,
      version: CONVERTER_VERSION,
      commit: CONVERTER_COMMIT,
    },
    recordedAt: context.recordedAt,
    recordedAtBasis: 'source-revision' as const,
    counts,
    designParity: {
      ledger: context.claimingLedger.seal,
      slug: context.claimingLedger.slug,
      scopeHash: context.claimingLedger.scopeHash,
      filesMatched: context.claimingLedger.files.length,
      hashesMatched: context.designScan.scans.length,
      findingsMatched: context.parsedFindings.length,
      droppedMatched: context.parsedDropped.length,
      proseArtifacts: context.proseArtifacts,
    },
    egressPolicy: {
      before: context.egressBefore,
      after: context.egressAfter,
      byteIdentical: true as const,
      relocatedByThisMigrator: false as const,
    },
    mappings: buildMappings(context, receiptPath),
    unmapped: [] as [],
    outputs: outputs.map(({ path, sha256 }) => ({ path, sha256 })),
    parityChecks: [
      {
        name: 'design scan corpus sealed',
        status: 'passed' as const,
        details:
          `${DESIGN_SCAN_FILES.length} design-scan files sealed by Git blob ` +
          'and SHA-256 at the source revision',
      },
      {
        name: 'design V2 ledger parity exact',
        status: 'passed' as const,
        details:
          `${counts.designScanRecords} scan records, ` +
          `${counts.designFindings} findings, and ${counts.designDropped} ` +
          `bar-held entries map exactly to ${context.claimingLedger.seal.path}`,
      },
      {
        name: 'historical reports projected byte-for-byte',
        status: 'passed' as const,
        details:
          `${counts.historicalReports} final reports projected to ` +
          `${context.options.historicalArtifactsPath} with original Git blobs`,
      },
      {
        name: 'egress policy relocation recorded',
        status: 'passed' as const,
        details:
          `${context.egressBefore.path} -> ${context.egressAfter.path} is ` +
          'byte-identical; the move itself remains a reviewed RelayOS ' +
          'product edit',
      },
    ],
    safeToDelete: [] as [],
  }
  const receipt: AuditRootAuditsMigrationReceiptV1 = {
    ...receiptCore,
    receiptDigest: computeAuditCanonicalDigest(receiptCore),
  }
  outputs.push(
    output(
      receiptPath,
      `${canonicalJson(receipt)}\n`,
      rawSha256(`${canonicalJson(receipt)}\n`),
      'receipt',
    ),
  )
  const orderedOutputs = [...outputs].sort((left, right) =>
    compareText(left.path, right.path))
  const result: RelayOSRootAuditsMigrationResult = {
    migrationId: context.migrationId,
    receipt,
    historicalArtifacts: context.historicalReports
      .map(({ sourcePath, artifactPath, gitBlob, sha256 }) => ({
        sourcePath,
        path: artifactPath,
        gitBlob,
        sha256,
      }))
      .sort((left, right) => compareText(left.sourcePath, right.sourcePath)),
    writes: orderedOutputs.map(({ path, sha256 }) => ({ path, sha256 })),
  }
  return { result, outputs: orderedOutputs }
}

function applyPlan(
  root: string,
  options: NormalizedRootAuditsOptions,
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
    const applyOrder: PlannedOutput['family'][] = ['artifact', 'receipt']
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

export function buildRelayOSRootAuditsMigration(
  root: string,
  unsafeOptions: RelayOSRootAuditsMigrationOptions,
): RelayOSRootAuditsMigrationResult {
  try {
    const options = snapshotOptions(unsafeOptions)
    return buildPlan(root, options).result
  } catch (error) {
    return translateSharedFailure(error)
  }
}

export function migrateRelayOSRootAudits(
  root: string,
  unsafeOptions: RelayOSRootAuditsMigrationOptions,
): RelayOSRootAuditsMigrationResult {
  try {
    const options = snapshotOptions(unsafeOptions)
    const plan = buildPlan(root, options)
    if (options.apply) applyPlan(root, options, plan)
    return plan.result
  } catch (error) {
    return translateSharedFailure(error)
  }
}
