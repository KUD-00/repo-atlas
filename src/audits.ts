import fs from 'node:fs'
import path from 'node:path'
import { createHash, randomUUID } from 'node:crypto'
import { atlasDir, hashFilePaths, isSafeRepoFile, readRepoFile } from './scan.js'
import type {
  AuditFinding,
  AuditUnit,
  ScanResult,
  SecurityAuditUnit,
  TestAuditFinding,
  TestAuditUnit,
} from './types.js'

/**
 * Audit ledger loader + freshness for `.atlas/audits/<slug>.json`.
 * Shared envelope (`atlas-audit-v1` / `atlas-audit-v2`) owns freshness;
 * domain validators decide which complete units enter viewer portfolios.
 *
 * scope_hash = sorted "<blobSha>  <path>" 行的 sha1（与 qa/audit.ts 同一算法）——
 * 加载时重算：scope 字节漂移或文件消失 → stale → 该重审了。
 *
 * `audit-stamp` 的可选增强：往 ledger 里写 per-file `hashes`，status 就能报
 * "哪些文件变了、几个 finding 指着它们"，而不只是整体 stale 布尔。
 * 重审会重写 ledger（hashes 丢），需要时重新 stamp 即可。
 */

export interface AuditStatusEntry {
  name: string
  title: string
  ruleset: string | null
  scannedAt: string | null
  fileCount: number
  findingCount: number
  status: 'fresh' | 'stale'
  /** files in scope that no longer exist */
  missingFiles: string[]
  /** files whose hash changed since `audit-stamp`（空 = 未 stamp，无法逐文件） */
  changedFiles: string[]
  /** regular contained files that could not be hashed */
  failedFiles: string[]
  /** findings whose locations point at changed/missing files */
  /** null when the scope drifted but there is no complete per-file hash set. */
  findingsWithDrift: number | null
  detailAvailable: boolean
  invalidReason: string | null
  file: string
}

interface RawLedger {
  formatVersion?: number
  format?: string
  domain?: string
  reviewState?: string
  conceptSlug?: string
  slug: string
  name?: string
  title: string
  ruleset: string
  scanned_at: string
  scope_hash?: string
  file_count?: number
  files: string[]
  findings?: unknown
  dropped?: unknown[]
  rounds?: unknown[]
  hashes?: Record<string, string>
  stamped?: string
  hashes_stamped?: string
  finalPass?: boolean
}

export interface AuditPortfolios {
  security: SecurityAuditUnit[]
  tests: TestAuditUnit[]
}

const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical'])
const TEST_IMPACTS = new Set(['blocking', 'warning', 'advisory'])
const TEST_CATEGORIES = new Set([
  'missing-invariant', 'weak-assertion', 'mock-only', 'nondeterminism',
  'isolation-leak', 'fixture-drift', 'coverage-gap', 'privileged-side-effect',
])

export function auditsRoot(root: string): string {
  return path.join(atlasDir(root), 'audits')
}

function existingAuditsRoot(root: string, warn = false): string | null {
  const atlas = atlasDir(root)
  const base = auditsRoot(root)
  if (!fs.existsSync(base)) return null
  try {
    const atlasStat = fs.lstatSync(atlas)
    const baseStat = fs.lstatSync(base)
    const atlasReal = fs.realpathSync(atlas)
    const baseReal = fs.realpathSync(base)
    if (!atlasStat.isDirectory() || atlasStat.isSymbolicLink() ||
        !baseStat.isDirectory() || baseStat.isSymbolicLink() ||
        baseReal === atlasReal || !baseReal.startsWith(atlasReal + path.sep)) {
      throw new Error('audit directory is symlinked or outside .atlas')
    }
    return base
  } catch (error) {
    if (warn) console.warn(`  ⚠ .atlas/audits: unsafe audit directory, skipped (${error instanceof Error ? error.message : String(error)})`)
    return null
  }
}

function writableAuditsRoot(root: string): string {
  const atlas = atlasDir(root)
  try {
    const stat = fs.lstatSync(atlas)
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('.atlas is not a regular directory')
  } catch (error) {
    throw new Error(`unsafe audit directory: ${error instanceof Error ? error.message : String(error)}`)
  }
  const base = auditsRoot(root)
  if (!fs.existsSync(base)) fs.mkdirSync(base)
  if (!existingAuditsRoot(root)) throw new Error('unsafe audit directory: .atlas/audits must be a regular in-repository directory')
  return base
}

function isRegularLedgerFile(file: string): boolean {
  try {
    const stat = fs.lstatSync(file)
    return stat.isFile() && !stat.isSymbolicLink()
  } catch {
    return false
  }
}

/** Refuse parent/file symlinks before an audit producer reads or replaces an output. */
export function assertSafeAuditLedgerOutput(root: string, file: string): void {
  const base = writableAuditsRoot(root)
  if (path.dirname(path.resolve(file)) !== path.resolve(base)) throw new Error(`unsafe audit output path: ${file}`)
  if (fs.existsSync(file) && !isRegularLedgerFile(file)) throw new Error(`unsafe audit ledger: ${path.relative(root, file)} must be a regular file, not a symlink`)
}

/** Atomic audit-ledger replacement that never follows an existing symlink. */
export function writeAuditLedgerFile(root: string, file: string, contents: string): void {
  assertSafeAuditLedgerOutput(root, file)
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${randomUUID()}.tmp`)
  try {
    fs.writeFileSync(tmp, contents, { flag: 'wx', mode: 0o600 })
    fs.renameSync(tmp, file)
  } finally {
    try { fs.unlinkSync(tmp) } catch { /* renamed or never created */ }
  }
}

/** qa/audit.ts 的 scope 指纹算法：sorted "<blobSha>  <path>" 行的 sha1。 */
function scopeHash(root: string, files: string[]): { hash: string | null; missing: string[] } {
  const snapshot = hashFilePaths(root, files)
  if (snapshot.missing.length || snapshot.failed.length || snapshot.hashes.size !== new Set(files).size) {
    return { hash: null, missing: snapshot.missing }
  }
  const lines = files.map((file) => `${snapshot.hashes.get(file)}  ${file}`).sort()
  return { hash: createHash('sha1').update(lines.join('\n') + '\n').digest('hex'), missing: [] }
}

function scopeHashFromScan(root: string, scanResult: ScanResult, files: string[]): {
  hash: string | null
  missing: string[]
  failed: string[]
  hashes: Map<string, string>
} {
  const snapshot = hashFilePaths(root, files, scanResult)
  if (snapshot.missing.length || snapshot.failed.length || snapshot.hashes.size !== new Set(files).size) {
    return { hash: null, missing: snapshot.missing, failed: snapshot.failed, hashes: snapshot.hashes }
  }
  const lines = files.map((file) => `${snapshot.hashes.get(file)}  ${file}`).sort()
  return {
    hash: createHash('sha1').update(lines.join('\n') + '\n').digest('hex'),
    missing: [],
    failed: [],
    hashes: snapshot.hashes,
  }
}

function normalizeLedger(value: unknown, file: string): RawLedger | null {
  if (!value || typeof value !== 'object') return null
  const j = value as Record<string, unknown>
  const name = typeof j.slug === 'string' ? j.slug : typeof j.name === 'string' ? j.name : path.basename(file, '.json')
  if (!name || !Array.isArray(j.files) || !j.files.every((item: unknown) => typeof item === 'string')) return null
  return { ...j, slug: name } as unknown as RawLedger
}

function readAuditJson(root: string, file: string): { raw: unknown; text: string } {
  const base = existingAuditsRoot(root)
  if (!base || path.dirname(path.resolve(file)) !== path.resolve(base)) throw new Error('file is outside .atlas/audits')
  const rel = path.relative(root, file).replace(/\\/g, '/')
  const opened = readRepoFile(root, rel)
  if (!opened) throw new Error('file is not a safe regular in-repository file')
  const text = opened.buffer.toString('utf8')
  return { raw: JSON.parse(text), text }
}

interface LedgerRead {
  ledger: RawLedger | null
  raw: unknown
  text: string | null
  error: string | null
}

function validRepoPath(repoPath: string): boolean {
  return !!repoPath && !path.isAbsolute(repoPath) && !repoPath.includes('\\') && !repoPath.includes('\0') &&
    path.posix.normalize(repoPath) === repoPath && repoPath !== '.' && !repoPath.startsWith('../')
}

function isV2(j: RawLedger): boolean {
  return j.formatVersion === 2 && j.format === 'atlas-audit-v2'
}

function isV1(j: RawLedger): boolean {
  return (j.formatVersion ?? 1) === 1 && (!j.format || j.format === 'atlas-audit-v1')
}

/** v2 unit slugs must be route-safe lowercase kebab (audit:domain/<slug>). */
const V2_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u

function v2EnvelopeError(j: RawLedger): string | null {
  if (j.formatVersion === 2 && j.format !== 'atlas-audit-v2') {
    return 'version 2 ledgers must use format atlas-audit-v2'
  }
  if (!isV2(j)) return 'version 2 ledgers must use format atlas-audit-v2'
  if (j.domain !== 'security' && j.domain !== 'test') return 'unsupported audit domain'
  if (j.reviewState !== 'complete') return 'reviewState must be complete'
  if (!V2_SLUG_RE.test(j.slug)) return 'slug must be lowercase kebab-case for namespaced routes'
  return null
}

function ledgerContractError(j: RawLedger): string | null {
  const version = j.formatVersion ?? 1
  if (version === 1) {
    if (j.format && j.format !== 'atlas-audit-v1') return `format ${j.format} is unsupported`
  } else if (version === 2) {
    if (j.format !== 'atlas-audit-v2') return 'version 2 ledgers must use format atlas-audit-v2'
  } else {
    return `formatVersion ${String(j.formatVersion)} is unsupported (known: 1, 2)`
  }
  if (!j.files.every(validRepoPath) || new Set(j.files).size !== j.files.length) return 'files must be unique normalized repository-relative paths'
  if (typeof j.scope_hash !== 'string' || !/^[0-9a-f]{40}$/u.test(j.scope_hash)) return 'scope_hash must be a lowercase SHA-1'
  if (j.file_count !== undefined && (nonnegativeInteger(j.file_count) === null || j.file_count !== j.files.length)) return 'file_count must equal files.length'
  if (!Array.isArray(j.findings)) return 'findings must be an array'
  const findings = findingsOf(j)
  if (!hasValidFindingCounts(findings)) return 'finding count must be a finite nonnegative integer'
  if (j.hashes !== undefined) {
    if (!j.hashes || typeof j.hashes !== 'object' || Array.isArray(j.hashes)) return 'hashes must be an object'
    const keys = Object.keys(j.hashes)
    if (keys.length !== j.files.length || keys.some((repoPath) => !j.files.includes(repoPath)) ||
        j.files.some((repoPath) => !/^[0-9a-f]{40}$/u.test(j.hashes![repoPath] ?? ''))) {
      return 'hashes must contain one lowercase SHA-1 for every scope file'
    }
  }
  if (version === 2) {
    const envelope = v2EnvelopeError(j)
    if (envelope) return envelope
  }
  return null
}

function readLedger(root: string, file: string): LedgerRead {
  try {
    const { raw, text } = readAuditJson(root, file)
    const ledger = normalizeLedger(raw, file)
    if (!ledger) return { ledger: null, raw, text, error: 'malformed audit ledger' }
    const error = ledgerContractError(ledger)
    return { ledger: error ? null : ledger, raw, text, error }
  } catch (error) {
    return { ledger: null, raw: null, text: null, error: error instanceof SyntaxError ? 'parse failed' : error instanceof Error ? error.message : String(error) }
  }
}

function nonemptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

/** v2 finding location: repo-relative path, optional `:positive-line` or `#nonempty-symbol`. */
function validAuditLocation(location: unknown): location is string {
  if (typeof location !== 'string' || !location.trim()) return false
  const match = /^([^:#]+)(?::([0-9]+)|#(.+))?$/u.exec(location)
  if (!match) return false
  if (!validRepoPath(match[1])) return false
  if (match[2] !== undefined && !/^[1-9]\d*$/u.test(match[2])) return false
  if (location.includes('#') && !(match[3] && match[3].length > 0)) return false
  return true
}

function normalizedLocations(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every(validAuditLocation)
}

function validFinding(f: unknown): f is AuditFinding {
  if (!f || typeof f !== 'object') return false
  const finding = f as Partial<AuditFinding>
  return typeof finding.severity === 'string' && SEVERITIES.has(finding.severity) &&
    typeof finding.category === 'string' && typeof finding.title === 'string' &&
    Array.isArray(finding.locations) && finding.locations.every((loc) => typeof loc === 'string') &&
    typeof finding.dataflow === 'string' && typeof finding.fix === 'string'
}

function validStrictSecurityFinding(f: unknown): f is AuditFinding {
  if (!f || typeof f !== 'object') return false
  const finding = f as Partial<AuditFinding>
  return typeof finding.severity === 'string' && SEVERITIES.has(finding.severity) &&
    nonemptyString(finding.category) && nonemptyString(finding.title) &&
    normalizedLocations(finding.locations) &&
    nonemptyString(finding.dataflow) && nonemptyString(finding.fix) &&
    (finding.confidence === undefined || nonemptyString(finding.confidence))
}

function validTestFinding(f: unknown): f is TestAuditFinding {
  if (!f || typeof f !== 'object') return false
  const finding = f as Partial<TestAuditFinding>
  return typeof finding.impact === 'string' && TEST_IMPACTS.has(finding.impact) &&
    typeof finding.category === 'string' && TEST_CATEGORIES.has(finding.category) &&
    nonemptyString(finding.title) && nonemptyString(finding.invariant) &&
    nonemptyString(finding.evidence) && nonemptyString(finding.fix) &&
    normalizedLocations(finding.locations) &&
    (finding.confidence === undefined || nonemptyString(finding.confidence))
}

function isSupportedFormat(j: RawLedger): boolean {
  return isV1(j) || isV2(j)
}

function isLegacySecurityLedger(j: RawLedger): boolean {
  return isV1(j) && j.finalPass === true && Array.isArray(j.findings)
}

function isStatusLedger(j: RawLedger): boolean {
  if (isV2(j)) return true
  return isV1(j) && j.finalPass !== false
}

function findingPaths(finding: unknown): string[] {
  if (typeof finding === 'string') return [finding]
  if (!finding || typeof finding !== 'object') return []
  const value = finding as Record<string, unknown>
  const paths = [value.path, value.file].filter((item): item is string => typeof item === 'string')
  for (const key of ['locations', 'files']) {
    if (Array.isArray(value[key])) paths.push(...value[key].filter((item): item is string => typeof item === 'string'))
  }
  return paths.map((location) => location.replace(/#.*$/, '').replace(/:\d+$/, ''))
}

function nonnegativeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null
}

function findingCount(finding: unknown): number {
  if (!finding || typeof finding !== 'object' || !Object.hasOwn(finding, 'count')) return 1
  return nonnegativeInteger((finding as Record<string, unknown>).count) ?? 1
}

function findingsOf(j: RawLedger): unknown[] {
  return Array.isArray(j.findings) ? j.findings : []
}

function hasValidFindingCounts(findings: unknown[]): boolean {
  let total = 0
  for (const finding of findings) {
    if (finding && typeof finding === 'object' && Object.hasOwn(finding, 'count') &&
        nonnegativeInteger((finding as Record<string, unknown>).count) === null) return false
    const count = findingCount(finding)
    if (!Number.isSafeInteger(total + count)) return false
    total += count
  }
  return true
}

function viewerMetadataError(root: string, j: RawLedger, entry: string, label: string): string | null {
  if (j.slug !== path.basename(entry, '.json')) return `${label} slug must match its ledger filename`
  if (![j.title, j.ruleset, j.scanned_at].every((value) => typeof value === 'string' && value.trim())) {
    return `${label} title, ruleset, and scanned_at must be nonempty strings`
  }
  if (!j.files.length) return `${label} scope must contain at least one file`
  for (const repoPath of j.files) {
    try {
      fs.lstatSync(path.resolve(root, repoPath))
      if (!isSafeRepoFile(root, repoPath)) return `${label} scope path is not a safe regular file: ${repoPath}`
    } catch { /* a formerly audited file may be gone; freshness reports it stale */ }
  }
  if (!Array.isArray(j.findings)) return `${label} findings must be an array`
  if (j.findings.length > 100_000) return `${label} findings exceed the 100000 entry limit`
  if (j.dropped !== undefined && !Array.isArray(j.dropped)) return `${label} dropped must be an array`
  if (j.rounds !== undefined && !Array.isArray(j.rounds)) return `${label} rounds must be an array`
  return null
}

function securityLedgerError(root: string, j: RawLedger, raw: unknown, entry: string): string | null {
  const record = raw && typeof raw === 'object' ? raw as Record<string, unknown> : null
  if (isV2(j)) {
    if (j.domain !== 'security') return 'unsupported audit domain'
    const meta = viewerMetadataError(root, j, entry, 'security')
    if (meta) return meta
    if (j.conceptSlug !== undefined && !nonemptyString(j.conceptSlug)) {
      return 'security conceptSlug must be a nonempty string when present'
    }
    if (!findingsOf(j).every(validStrictSecurityFinding)) {
      return 'every security finding must satisfy the strict viewer schema'
    }
    return null
  }
  if (record?.formatVersion !== 1) return 'security formatVersion must be 1'
  if (record.format !== undefined && record.format !== 'atlas-audit-v1') return 'unsupported security format'
  const meta = viewerMetadataError(root, j, entry, 'security')
  if (meta) return meta
  if (!findingsOf(j).every(validFinding)) return 'every security finding must satisfy the strict viewer schema'
  return null
}

function testLedgerError(root: string, j: RawLedger, entry: string): string | null {
  if (!isV2(j) || j.domain !== 'test') return 'unsupported audit domain'
  const meta = viewerMetadataError(root, j, entry, 'test')
  if (meta) return meta
  if (!findingsOf(j).every(validTestFinding)) {
    return 'every test finding must satisfy the strict test schema (impact, category, locations)'
  }
  return null
}

function domainLedgerError(root: string, j: RawLedger, raw: unknown, entry: string): string | null {
  if (isV2(j)) {
    if (j.domain === 'security') return securityLedgerError(root, j, raw, entry)
    if (j.domain === 'test') return testLedgerError(root, j, entry)
    return 'unsupported audit domain'
  }
  if (isLegacySecurityLedger(j)) return securityLedgerError(root, j, raw, entry)
  return null
}

function unitStale(
  root: string,
  j: RawLedger,
  file: string,
  statusByFile: Map<string, AuditStatusEntry> | null,
): boolean {
  const knownStatus = statusByFile?.get(path.resolve(file))
  if (knownStatus) return knownStatus.status !== 'fresh'
  const current = scopeHash(root, j.files)
  return current.missing.length > 0 || current.hash !== j.scope_hash
}

function toSecurityUnit(root: string, j: RawLedger, file: string, statusByFile: Map<string, AuditStatusEntry> | null): SecurityAuditUnit {
  const findings = findingsOf(j) as AuditFinding[]
  const unit: SecurityAuditUnit = {
    formatVersion: isV2(j) ? 2 : 1,
    domain: 'security',
    slug: j.slug,
    title: typeof j.title === 'string' ? j.title : j.slug,
    ruleset: typeof j.ruleset === 'string' ? j.ruleset : 'unknown',
    scannedAt: typeof j.scanned_at === 'string' ? j.scanned_at : '',
    fileCount: j.files.length,
    findings,
    droppedCount: Array.isArray(j.dropped) ? j.dropped.length : 0,
    roundCount: Array.isArray(j.rounds) ? j.rounds.length : 0,
    stale: unitStale(root, j, file, statusByFile),
  }
  if (isV2(j) && nonemptyString(j.conceptSlug)) unit.conceptSlug = j.conceptSlug
  return unit
}

function toTestUnit(root: string, j: RawLedger, file: string, statusByFile: Map<string, AuditStatusEntry> | null): TestAuditUnit {
  return {
    formatVersion: 2,
    domain: 'test',
    slug: j.slug,
    title: typeof j.title === 'string' ? j.title : j.slug,
    ruleset: typeof j.ruleset === 'string' ? j.ruleset : 'unknown',
    scannedAt: typeof j.scanned_at === 'string' ? j.scanned_at : '',
    fileCount: j.files.length,
    findings: findingsOf(j) as TestAuditFinding[],
    droppedCount: Array.isArray(j.dropped) ? j.dropped.length : 0,
    roundCount: Array.isArray(j.rounds) ? j.rounds.length : 0,
    stale: unitStale(root, j, file, statusByFile),
  }
}

function invalidStatus(file: string, reason: string): AuditStatusEntry {
  const name = path.basename(file, '.json')
  return {
    name,
    title: name,
    ruleset: null,
    scannedAt: null,
    fileCount: 0,
    findingCount: 0,
    status: 'stale',
    missingFiles: [],
    changedFiles: [],
    failedFiles: [],
    findingsWithDrift: null,
    detailAvailable: false,
    invalidReason: reason,
    file,
  }
}

/** Build/serve 契约：一次目录遍历加载 security + test 两个 portfolio。 */
export function loadAuditPortfolios(root: string, statuses?: AuditStatusEntry[]): AuditPortfolios {
  const base = existingAuditsRoot(root, true)
  if (!base) return { security: [], tests: [] }
  const security: SecurityAuditUnit[] = []
  const tests: TestAuditUnit[] = []
  const statusByFile = statuses ? new Map(statuses.map((status) => [path.resolve(status.file), status])) : null
  for (const entry of fs.readdirSync(base).sort()) {
    if (!entry.endsWith('.json')) continue
    const file = path.join(base, entry)
    const read = readLedger(root, file)
    if (!read.ledger) {
      console.warn(`  ⚠ .atlas/audits/${entry}: ${read.error ?? 'malformed ledger'}, skipped`)
      continue
    }
    const j = read.ledger
    if (isV2(j)) {
      if (j.domain === 'security') {
        const securityError = securityLedgerError(root, j, read.raw, entry)
        if (securityError) {
          console.warn(`  ⚠ .atlas/audits/${entry}: malformed security ledger (${securityError}), skipped`)
          continue
        }
        security.push(toSecurityUnit(root, j, file, statusByFile))
      } else if (j.domain === 'test') {
        const testError = testLedgerError(root, j, entry)
        if (testError) {
          console.warn(`  ⚠ .atlas/audits/${entry}: malformed test ledger (${testError}), skipped`)
          continue
        }
        tests.push(toTestUnit(root, j, file, statusByFile))
      } else {
        console.warn(`  ⚠ .atlas/audits/${entry}: unsupported audit domain, skipped`)
      }
      continue
    }
    if (!isLegacySecurityLedger(j)) continue
    const securityError = securityLedgerError(root, j, read.raw, entry)
    if (securityError) {
      console.warn(`  ⚠ .atlas/audits/${entry}: malformed security ledger (${securityError}), skipped`)
      continue
    }
    security.push(toSecurityUnit(root, j, file, statusByFile))
  }
  const severityRank = (severity: string) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(severity)
  security.sort((left, right) => {
    const worst = (findings: AuditFinding[]) => findings.reduce((value, finding) => Math.min(value, severityRank(finding.severity)), 5)
    return worst(left.findings) - worst(right.findings) || left.slug.localeCompare(right.slug)
  })
  const impactRank = (impact: string) => ['blocking', 'warning', 'advisory'].indexOf(impact)
  tests.sort((left, right) => {
    const staleRank = Number(right.stale) - Number(left.stale)
    if (staleRank) return staleRank
    const worst = (findings: TestAuditFinding[]) => findings.reduce((value, finding) => {
      const rank = impactRank(finding.impact)
      return rank === -1 ? value : Math.min(value, rank)
    }, 3)
    return worst(left.findings) - worst(right.findings) || left.slug.localeCompare(right.slug)
  })
  return { security, tests }
}

/** Build/serve 契约：security portfolio（types.ts 的 AuditUnit）。 */
export function loadAudits(root: string, statuses?: AuditStatusEntry[]): AuditUnit[] {
  return loadAuditPortfolios(root, statuses).security
}

/** status 的细节层：fresh/stale + （stamp 后的）逐文件漂移。 */
export function auditStatusEntries(root: string, scanResult: ScanResult): AuditStatusEntry[] {
  const expectedBase = auditsRoot(root)
  const base = existingAuditsRoot(root, true)
  if (!base) return fs.existsSync(expectedBase) ? [invalidStatus(expectedBase, 'unsafe audit directory')] : []
  const out: AuditStatusEntry[] = []
  for (const entry of fs.readdirSync(base).sort()) {
    if (!entry.endsWith('.json')) continue
    const file = path.join(base, entry)
    const read = readLedger(root, file)
    if (!read.ledger) {
      const reason = read.error ?? 'malformed audit ledger'
      console.warn(`  ⚠ .atlas/audits/${entry}: ${reason}; reported stale/invalid`)
      out.push(invalidStatus(file, reason))
      continue
    }
    const j = read.ledger
    if (!isStatusLedger(j)) continue
    const domainError = domainLedgerError(root, j, read.raw, entry)
    if (domainError) {
      const kind = isV2(j) && j.domain === 'test' ? 'test' : 'security'
      console.warn(`  ⚠ .atlas/audits/${entry}: malformed ${kind} ledger (${domainError}); reported stale/invalid`)
      out.push(invalidStatus(file, domainError))
      continue
    }
    const findings = findingsOf(j)
    const currentScope = scopeHashFromScan(root, scanResult, j.files)
    const missingFiles = currentScope.missing
    const changedFiles: string[] = []
    if (j.hashes) {
      for (const f of j.files) {
        const current = currentScope.hashes.get(f)
        if (current && typeof j.hashes[f] === 'string' && j.hashes[f] !== current) changedFiles.push(f)
      }
    }
    const drifted = new Set([...missingFiles, ...changedFiles])
    const scopeDrifted = currentScope.hash === null || currentScope.hash !== j.scope_hash
    const detailAvailable = currentScope.failed.length === 0 && (!scopeDrifted || j.hashes !== undefined)
    const findingsWithDrift = detailAvailable
      ? findings.filter((finding) => findingPaths(finding).some((repoPath) => drifted.has(repoPath)))
        .reduce<number>((total, finding) => total + findingCount(finding), 0)
      : null
    out.push({
      name: j.slug,
      title: typeof j.title === 'string' ? j.title : j.slug,
      ruleset: typeof j.ruleset === 'string' ? j.ruleset : null,
      scannedAt: typeof j.scanned_at === 'string' ? j.scanned_at : null,
      fileCount: j.files.length,
      findingCount: findings.reduce<number>((total, finding) => total + findingCount(finding), 0),
      status: scopeDrifted || changedFiles.length || currentScope.failed.length ? 'stale' : 'fresh',
      missingFiles,
      changedFiles,
      failedFiles: currentScope.failed,
      findingsWithDrift,
      detailAvailable,
      invalidReason: null,
      file,
    })
  }
  return out
}

/** 往 ledger 里写 per-file hashes（status 的逐文件漂移由此而来）。重审会覆盖，需重 stamp。 */
export function stampAudits(root: string, scanResult: ScanResult, names?: string[]): { stamped: string[]; skipped: string[]; notFound: string[] } {
  const base = existingAuditsRoot(root)
  const stamped: string[] = []
  const skipped: string[] = []
  const matched = new Set<string>()
  if (!base) return { stamped, skipped, notFound: names ? [...names] : [] }
  for (const entry of fs.readdirSync(base).sort()) {
    if (!entry.endsWith('.json')) continue
    const file = path.join(base, entry)
    const read = readLedger(root, file)
    if (!read.ledger) {
      const candidate = normalizeLedger(read.raw, file)
      if (!candidate || (names?.length && !names.includes(candidate.slug))) continue
      matched.add(candidate.slug)
      skipped.push(`${candidate.slug}: ${read.error ?? 'malformed audit ledger'}`)
      continue
    }
    const j = read.ledger
    if (!isStatusLedger(j) || (names?.length && !names.includes(j.slug))) continue
    matched.add(j.slug)
    const currentScope = scopeHashFromScan(root, scanResult, j.files)
    if (currentScope.hash === null || currentScope.hash !== j.scope_hash) {
      skipped.push(`${j.slug}: scope drifted; re-run the audit before stamping`)
      continue
    }
    const hashes = Object.fromEntries(j.files.map((repoPath) => [repoPath, currentScope.hashes.get(repoPath)!]))
    const latest = readLedger(root, file)
    if (!latest.ledger || latest.text !== read.text) {
      skipped.push(`${j.slug}: ledger changed while stamping; retry`)
      continue
    }
    const raw = latest.raw as Record<string, unknown>
    raw.hashes = hashes
    raw.stamped = new Date().toISOString()
    if ('hashes_stamped' in raw) raw.hashes_stamped = raw.stamped
    writeAuditLedgerFile(root, file, JSON.stringify(raw, null, 2) + '\n')
    stamped.push(j.slug)
  }
  const notFound = names ? names.filter((name) => !matched.has(name)) : []
  return { stamped, skipped, notFound }
}

interface LegacyScan {
  path?: unknown
  git_blob_sha1?: unknown
  scanned_at?: unknown
  max_severity?: unknown
  finding_count?: unknown
  findings_ref?: unknown
}

/** Import the historical `{ scans: [{ path, git_blob_sha1, ... }] }` shape
 * used by file-at-a-time audit scripts. Scan-time hashes are preserved, so the
 * imported ledger has useful drift detail immediately and never needs a
 * potentially unsafe after-the-fact stamp. */
export function importLegacyAudit(root: string, source: string): { name: string; file: string; fileCount: number; findingCount: number } {
  const sourceFile = path.resolve(root, source)
  const sourceRel = path.relative(root, sourceFile).replace(/\\/g, '/')
  if (!sourceRel || sourceRel.startsWith('../') || path.isAbsolute(sourceRel)) {
    throw new Error(`audit ledger must be inside the repository: ${source}`)
  }
  const sourceRead = readRepoFile(root, sourceRel)
  if (!sourceRead) throw new Error(`audit ledger must be a regular file inside the repository: ${sourceRel}`)
  const raw = JSON.parse(sourceRead.buffer.toString('utf8')) as { ruleset?: unknown; scans?: unknown }
  if (!Array.isArray(raw.scans)) throw new Error(`legacy audit ledger has no scans[]: ${sourceRel}`)

  const scans = new Map<string, LegacyScan>()
  for (const [index, candidate] of (raw.scans as LegacyScan[]).entries()) {
    const repoPath = candidate?.path
    const count = nonnegativeInteger(candidate?.finding_count)
    const validPath = typeof repoPath === 'string' && validRepoPath(repoPath)
    const reason = !validPath ? 'path must be a normalized repository-relative path'
      : typeof candidate.git_blob_sha1 !== 'string' || !/^[0-9a-f]{40}$/iu.test(candidate.git_blob_sha1) ? 'git_blob_sha1 must be 40 hex characters'
        : count === null ? 'finding_count must be a finite nonnegative integer'
          : scans.has(repoPath) ? `duplicate path ${repoPath}`
            : null
    if (reason) throw new Error(`invalid legacy scan #${index + 1}: ${reason}`)
    scans.set(repoPath as string, candidate)
  }
  if (!scans.size) throw new Error(`legacy audit ledger has no scan entries: ${sourceRel}`)

  const name = path.basename(path.dirname(sourceFile)).replace(/[^a-zA-Z0-9._-]+/g, '-')
  const files = [...scans.keys()].sort()
  const hashes = Object.fromEntries(files.map((repoPath) => [repoPath, (scans.get(repoPath)!.git_blob_sha1 as string).toLowerCase()]))
  const scopeLines = files.map((repoPath) => `${hashes[repoPath]}  ${repoPath}`).sort()
  const findings = files.flatMap((repoPath) => {
    const item = scans.get(repoPath)!
    const count = nonnegativeInteger(item.finding_count)!
    if (!(count > 0)) return []
    return [{
      path: repoPath,
      severity: typeof item.max_severity === 'string' ? item.max_severity : 'info',
      count,
      ref: typeof item.findings_ref === 'string' ? item.findings_ref : null,
    }]
  })
  const findingTotal = findings.reduce((total, finding) => total + finding.count, 0)
  if (!Number.isSafeInteger(findingTotal)) throw new Error('legacy audit aggregate finding count exceeds the safe integer range')
  const dates = [...scans.values()].map((item) => item.scanned_at).filter((value): value is string => typeof value === 'string').sort()
  const output = path.join(auditsRoot(root), `${name}.json`)
  assertSafeAuditLedgerOutput(root, output)
  if (fs.existsSync(output)) {
    let existing: unknown
    try {
      existing = readAuditJson(root, output).raw
    } catch {
      throw new Error(`refusing to overwrite unreadable audit ledger: ${path.relative(root, output)}`)
    }
    const owned = existing !== null && typeof existing === 'object' &&
      (existing as Record<string, unknown>).format === 'atlas-audit-v1' &&
      (existing as Record<string, unknown>).formatVersion === 1 &&
      (existing as Record<string, unknown>).slug === name &&
      (existing as Record<string, unknown>).source_ledger === sourceRel
    if (!owned) throw new Error(`refusing to overwrite unrelated audit ledger: ${path.relative(root, output)}`)
  }
  writeAuditLedgerFile(root, output, JSON.stringify({
    formatVersion: 1,
    format: 'atlas-audit-v1',
    slug: name,
    title: name,
    ruleset: typeof raw.ruleset === 'string' ? raw.ruleset : 'unknown',
    scanned_at: dates.at(-1) ?? null,
    stamped: new Date().toISOString(),
    scope_hash: createHash('sha1').update(scopeLines.join('\n') + '\n').digest('hex'),
    source_ledger: sourceRel,
    file_count: files.length,
    files,
    hashes,
    findings,
  }, null, 2) + '\n')
  return { name, file: output, fileCount: files.length, findingCount: findingTotal }
}
