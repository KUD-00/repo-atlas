import fs from 'node:fs'
import path from 'node:path'
import type { AuditPortfolios } from './audits.js'
import { atlasDir, readRepoFile } from './scan.js'
import type {
  AuditDomain,
  CoverageClassification,
  CoverageDiagnostic,
  CoverageEntry,
  CoverageEvidenceStatus,
  CoverageUnitRef,
  ReviewCoveragePortfolio,
  ReviewCoverageReport,
  ReviewCoverageSummary,
  ReviewCoverageVerdict,
} from './types.js'

/**
 * Strict fail-closed loader for `.atlas/review-coverage.json`.
 *
 * Task 2: structural validation only (shape, summary arithmetic, unit ownership).
 * Task 3 will revalidate Git inventory blobs and ledger freshness through the
 * internal seam below `loadReviewCoverage` without changing the public API.
 */

const COVERAGE_REL = '.atlas/review-coverage.json'
const SELF_PATH = COVERAGE_REL
const FORMAT = 'atlas-review-coverage-v1' as const
const MAX_REPORT_BYTES = 32 * 1024 * 1024
const MAX_ENTRIES = 1_000_000
const MAX_DIAGNOSTICS = 100_000
const MAX_UNITS = 100_000

const TOP_LEVEL_KEYS = [
  'formatVersion',
  'format',
  'verdict',
  'policy',
  'inventoryHash',
  'units',
  'summary',
  'entries',
  'invalidLedgerDetails',
  'reportErrors',
] as const

const SUMMARY_KEYS = [
  'tracked',
  'securityRequired',
  'securityFresh',
  'securityMissing',
  'securityStale',
  'securityInvalid',
  'testRequired',
  'testFresh',
  'testMissing',
  'testStale',
  'testInvalid',
  'dualRequired',
  'excluded',
  'unclassified',
  'conflicted',
  'invalidLedgers',
] as const

const VERDICTS = new Set<ReviewCoverageVerdict>(['complete', 'incomplete', 'invalid'])
const EVIDENCE_STATUSES = new Set<CoverageEvidenceStatus>(['fresh', 'missing', 'stale', 'invalid'])
const UNIT_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u
const SHA1_RE = /^[0-9a-f]{40}$/u
const SHA256_RE = /^[0-9a-f]{64}$/u

const emptyDrift = (): ReviewCoveragePortfolio['drift'] => ({
  added: [],
  removed: [],
  changed: [],
})

function diagnostic(code: string, message: string, extra: { path?: string; slug?: string } = {}): CoverageDiagnostic {
  const out: CoverageDiagnostic = { code, message }
  if (extra.path !== undefined) out.path = extra.path
  if (extra.slug !== undefined) out.slug = extra.slug
  return out
}

function missingPortfolio(): ReviewCoveragePortfolio {
  return { state: 'missing', report: null, errors: [], drift: emptyDrift() }
}

function invalidPortfolio(errors: CoverageDiagnostic[]): ReviewCoveragePortfolio {
  return { state: 'invalid', report: null, errors, drift: emptyDrift() }
}

export function reviewCoveragePath(root: string): string {
  return path.join(atlasDir(root), 'review-coverage.json')
}

function isSymlinkOrMissingDir(target: string): 'missing' | 'symlink' | 'ok' {
  try {
    const stat = fs.lstatSync(target)
    if (stat.isSymbolicLink()) return 'symlink'
    if (!stat.isDirectory()) return 'symlink'
    return 'ok'
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return 'missing'
    return 'symlink'
  }
}

function validRepoPath(repoPath: string): boolean {
  return !!repoPath &&
    !path.isAbsolute(repoPath) &&
    !repoPath.includes('\\') &&
    !repoPath.includes('\0') &&
    path.posix.normalize(repoPath) === repoPath &&
    repoPath !== '.' &&
    !repoPath.startsWith('./') &&
    !repoPath.startsWith('../') &&
    !repoPath.includes('/../') &&
    !repoPath.includes('/./')
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value)
  if (actual.length !== keys.length) return false
  return keys.every((key) => Object.prototype.hasOwnProperty.call(value, key))
}

function nonnegativeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null
}

function nonemptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

function parseDiagnostic(value: unknown, label: string): CoverageDiagnostic | string {
  if (!isPlainObject(value)) return `${label} entries must be objects`
  const keys = Object.keys(value)
  for (const key of keys) {
    if (key !== 'code' && key !== 'message' && key !== 'path' && key !== 'slug') {
      return `${label} entries have unknown fields`
    }
  }
  if (typeof value.code !== 'string' || value.code.length === 0) return `${label} code must be a nonempty string`
  if (typeof value.message !== 'string' || value.message.length === 0) return `${label} message must be a nonempty string`
  if (value.path !== undefined && (typeof value.path !== 'string' || !validRepoPath(value.path))) {
    return `${label} path must be a normalized repository-relative path`
  }
  if (value.slug !== undefined && (typeof value.slug !== 'string' || !UNIT_SLUG_RE.test(value.slug))) {
    return `${label} slug must be a route-safe unit slug`
  }
  const out: CoverageDiagnostic = {
    code: value.code,
    message: value.message,
  }
  if (typeof value.path === 'string') out.path = value.path
  if (typeof value.slug === 'string') out.slug = value.slug
  return out
}

function parseDiagnostics(value: unknown, label: string): CoverageDiagnostic[] | string {
  if (!Array.isArray(value)) return `${label} must be an array`
  if (value.length > MAX_DIAGNOSTICS) return `${label} exceeds the ${MAX_DIAGNOSTICS} diagnostic limit`
  const out: CoverageDiagnostic[] = []
  for (let i = 0; i < value.length; i++) {
    const parsed = parseDiagnostic(value[i], label)
    if (typeof parsed === 'string') return parsed
    out.push(parsed)
  }
  return out
}

function parseUnit(value: unknown): CoverageUnitRef | string {
  if (!isPlainObject(value)) return 'units entries must be objects'
  if (!exactKeys(value, ['domain', 'slug', 'title'])) return 'units entries must have exact domain, slug, and title fields'
  if (value.domain !== 'security' && value.domain !== 'test') return 'units domain must be security or test'
  if (typeof value.slug !== 'string' || !UNIT_SLUG_RE.test(value.slug)) {
    return 'units slug must be lowercase kebab-case for namespaced routes'
  }
  if (!nonemptyString(value.title)) return 'units title must be a nonempty string'
  return {
    domain: value.domain,
    slug: value.slug,
    title: value.title,
  }
}

function parseUnits(value: unknown): CoverageUnitRef[] | string {
  if (!Array.isArray(value)) return 'units must be an array'
  if (value.length > MAX_UNITS) return `units exceeds the ${MAX_UNITS} unit limit`
  const out: CoverageUnitRef[] = []
  const seen = new Set<string>()
  for (const item of value) {
    const parsed = parseUnit(item)
    if (typeof parsed === 'string') return parsed
    const key = `${parsed.domain}:${parsed.slug}`
    if (seen.has(key)) return `duplicate unit ${key}`
    seen.add(key)
    out.push(parsed)
  }
  return out
}

function parseSummary(value: unknown): ReviewCoverageSummary | string {
  if (!isPlainObject(value)) return 'summary must be an object'
  if (!exactKeys(value, SUMMARY_KEYS)) return 'summary must have exact known identity fields'
  const out: Partial<ReviewCoverageSummary> = {}
  for (const key of SUMMARY_KEYS) {
    const count = nonnegativeInteger(value[key])
    if (count === null) return `summary.${key} must be a finite nonnegative integer`
    out[key] = count
  }
  return out as ReviewCoverageSummary
}

function parseEvidenceStatus(value: unknown): CoverageEvidenceStatus | null {
  return typeof value === 'string' && EVIDENCE_STATUSES.has(value as CoverageEvidenceStatus)
    ? value as CoverageEvidenceStatus
    : null
}

function parseDomainEvidence(value: unknown, domain: AuditDomain): { status: CoverageEvidenceStatus; ledgers: string[] } | string {
  if (!isPlainObject(value)) return `evidence.${domain} must be an object`
  if (!exactKeys(value, ['status', 'ledgers'])) return `evidence.${domain} must have exact status and ledgers fields`
  const status = parseEvidenceStatus(value.status)
  if (!status) return `evidence.${domain}.status is unknown`
  if (!Array.isArray(value.ledgers) || !value.ledgers.every((item) => typeof item === 'string')) {
    return `evidence.${domain}.ledgers must be an array of strings`
  }
  if (value.ledgers.some((slug) => !UNIT_SLUG_RE.test(slug))) {
    return `evidence.${domain}.ledgers must contain route-safe unit slugs`
  }
  if (new Set(value.ledgers).size !== value.ledgers.length) {
    return `evidence.${domain}.ledgers must be unique`
  }
  return { status, ledgers: [...value.ledgers] }
}

function parseEvidence(value: unknown): CoverageEntry['evidence'] | string {
  if (!isPlainObject(value)) return 'evidence must be an object'
  const out: CoverageEntry['evidence'] = {}
  for (const key of Object.keys(value)) {
    if (key !== 'security' && key !== 'test') return `evidence has unknown domain ${key}`
    const domain = key as AuditDomain
    const parsed = parseDomainEvidence(value[key], domain)
    if (typeof parsed === 'string') return parsed
    out[domain] = parsed
  }
  return out
}

function parseReviewDomains(value: unknown): Extract<CoverageClassification, { kind: 'review' }>['domains'] | string {
  if (!isPlainObject(value)) return 'review classification domains must be an object'
  const keys = Object.keys(value)
  if (keys.length === 0) return 'review classification must name at least one domain'
  const out: Extract<CoverageClassification, { kind: 'review' }>['domains'] = {}
  for (const key of keys) {
    if (key !== 'security' && key !== 'test') return `review classification has unknown domain ${key}`
    const domain = key as AuditDomain
    const ref = value[key]
    if (!isPlainObject(ref) || !exactKeys(ref, ['unit'])) {
      return `review classification.${domain} must have exact unit field`
    }
    if (typeof ref.unit !== 'string' || !UNIT_SLUG_RE.test(ref.unit)) {
      return `review classification.${domain}.unit must be a route-safe unit slug`
    }
    out[domain] = { unit: ref.unit }
  }
  return out
}

function parseClassification(value: unknown): CoverageClassification | string {
  if (!isPlainObject(value) || typeof value.kind !== 'string') return 'classification must be an object with a kind'
  if (value.kind === 'review') {
    if (!exactKeys(value, ['kind', 'domains'])) return 'review classification must have exact kind and domains fields'
    const domains = parseReviewDomains(value.domains)
    if (typeof domains === 'string') return domains
    return { kind: 'review', domains }
  }
  if (value.kind === 'excluded') {
    const keys = Object.keys(value)
    for (const key of keys) {
      if (key !== 'kind' && key !== 'ruleId' && key !== 'category' && key !== 'reason' && key !== 'owner') {
        return 'excluded classification has unknown fields'
      }
    }
    if (!nonemptyString(value.ruleId) || !nonemptyString(value.category) || !nonemptyString(value.reason)) {
      return 'excluded classification requires nonempty ruleId, category, and reason'
    }
    if (value.owner !== undefined && !nonemptyString(value.owner)) {
      return 'excluded classification owner must be a nonempty string when present'
    }
    const out: Extract<CoverageClassification, { kind: 'excluded' }> = {
      kind: 'excluded',
      ruleId: value.ruleId,
      category: value.category,
      reason: value.reason,
    }
    if (typeof value.owner === 'string') out.owner = value.owner
    return out
  }
  if (value.kind === 'unclassified') {
    if (!exactKeys(value, ['kind'])) return 'unclassified classification must have exact kind field'
    return { kind: 'unclassified' }
  }
  if (value.kind === 'conflict') {
    if (!exactKeys(value, ['kind'])) return 'conflict classification must have exact kind field'
    return { kind: 'conflict' }
  }
  return `classification kind ${String(value.kind)} is unknown`
}

function parseEntry(value: unknown): CoverageEntry | string {
  if (!isPlainObject(value)) return 'entries must be objects'
  const keys = Object.keys(value)
  for (const key of keys) {
    if (key !== 'path' && key !== 'blob' && key !== 'ruleIds' && key !== 'classification' && key !== 'evidence') {
      return 'entries have unknown fields'
    }
  }
  if (typeof value.path !== 'string' || !validRepoPath(value.path)) {
    return 'entry path must be a unique normalized repository-relative path'
  }
  if (value.blob !== undefined) {
    if (typeof value.blob !== 'string' || !SHA1_RE.test(value.blob)) {
      return `entry blob must be a lowercase 40-hex git blob id (${value.path})`
    }
  } else if (value.path !== SELF_PATH) {
    return `entry blob is required except for the generated-proof self path (${value.path})`
  }
  if (!Array.isArray(value.ruleIds) || value.ruleIds.length === 0 || !value.ruleIds.every((item) => nonemptyString(item))) {
    return `entry ruleIds must be a nonempty string array (${value.path})`
  }
  const classification = parseClassification(value.classification)
  if (typeof classification === 'string') return `${classification} (${value.path})`
  const evidence = parseEvidence(value.evidence)
  if (typeof evidence === 'string') return `${evidence} (${value.path})`

  // Non-review classifications carry no domain evidence.
  if (classification.kind !== 'review') {
    if (Object.keys(evidence).length > 0) {
      return `excluded, unclassified, and conflict entries carry no domain evidence (${value.path})`
    }
  } else {
    const requiredDomains = Object.keys(classification.domains) as AuditDomain[]
    for (const domain of requiredDomains) {
      if (!evidence[domain]) {
        return `missing required domain evidence for ${domain} (${value.path})`
      }
    }
    for (const domain of Object.keys(evidence) as AuditDomain[]) {
      if (!classification.domains[domain]) {
        return `evidence domain ${domain} is not required by classification (${value.path})`
      }
    }
  }

  const entry: CoverageEntry = {
    path: value.path,
    ruleIds: [...value.ruleIds],
    classification,
    evidence,
  }
  if (typeof value.blob === 'string') entry.blob = value.blob
  return entry
}

function parseEntries(value: unknown): CoverageEntry[] | string {
  if (!Array.isArray(value)) return 'entries must be an array'
  if (value.length > MAX_ENTRIES) return `entries exceeds the ${MAX_ENTRIES} entry limit`
  const out: CoverageEntry[] = []
  const seen = new Set<string>()
  for (const item of value) {
    const parsed = parseEntry(item)
    if (typeof parsed === 'string') return parsed
    if (seen.has(parsed.path)) return `duplicate path ${parsed.path}`
    seen.add(parsed.path)
    out.push(parsed)
  }
  return out
}

function recomputeSummary(entries: CoverageEntry[], invalidLedgerDetails: CoverageDiagnostic[]): ReviewCoverageSummary {
  let securityRequired = 0
  let securityFresh = 0
  let securityMissing = 0
  let securityStale = 0
  let securityInvalid = 0
  let testRequired = 0
  let testFresh = 0
  let testMissing = 0
  let testStale = 0
  let testInvalid = 0
  let dualRequired = 0
  let excluded = 0
  let unclassified = 0
  let conflicted = 0

  for (const entry of entries) {
    const kind = entry.classification.kind
    if (kind === 'excluded') {
      excluded += 1
      continue
    }
    if (kind === 'unclassified') {
      unclassified += 1
      continue
    }
    if (kind === 'conflict') {
      conflicted += 1
      continue
    }
    const domains = entry.classification.domains
    const hasSecurity = Boolean(domains.security)
    const hasTest = Boolean(domains.test)
    if (hasSecurity && hasTest) dualRequired += 1
    if (hasSecurity) {
      securityRequired += 1
      const status = entry.evidence.security?.status
      if (status === 'fresh') securityFresh += 1
      else if (status === 'missing') securityMissing += 1
      else if (status === 'stale') securityStale += 1
      else if (status === 'invalid') securityInvalid += 1
    }
    if (hasTest) {
      testRequired += 1
      const status = entry.evidence.test?.status
      if (status === 'fresh') testFresh += 1
      else if (status === 'missing') testMissing += 1
      else if (status === 'stale') testStale += 1
      else if (status === 'invalid') testInvalid += 1
    }
  }

  return {
    tracked: entries.length,
    securityRequired,
    securityFresh,
    securityMissing,
    securityStale,
    securityInvalid,
    testRequired,
    testFresh,
    testMissing,
    testStale,
    testInvalid,
    dualRequired,
    excluded,
    unclassified,
    conflicted,
    invalidLedgers: invalidLedgerDetails.length,
  }
}

function summaryMatches(actual: ReviewCoverageSummary, expected: ReviewCoverageSummary): boolean {
  return SUMMARY_KEYS.every((key) => actual[key] === expected[key])
}

function summaryIdentitiesHold(summary: ReviewCoverageSummary): boolean {
  return summary.securityFresh + summary.securityMissing + summary.securityStale + summary.securityInvalid === summary.securityRequired &&
    summary.testFresh + summary.testMissing + summary.testStale + summary.testInvalid === summary.testRequired
}

function gapCount(summary: ReviewCoverageSummary): number {
  return summary.securityMissing +
    summary.securityStale +
    summary.securityInvalid +
    summary.testMissing +
    summary.testStale +
    summary.testInvalid +
    summary.unclassified +
    summary.conflicted +
    summary.invalidLedgers
}

function unitOwnershipErrors(
  entries: CoverageEntry[],
  units: CoverageUnitRef[],
): CoverageDiagnostic[] {
  const byDomainSlug = new Map<string, CoverageUnitRef>()
  for (const unit of units) {
    byDomainSlug.set(`${unit.domain}:${unit.slug}`, unit)
  }
  const errors: CoverageDiagnostic[] = []
  for (const entry of entries) {
    if (entry.classification.kind !== 'review') continue
    for (const domain of Object.keys(entry.classification.domains) as AuditDomain[]) {
      const unitSlug = entry.classification.domains[domain]?.unit
      if (!unitSlug) continue
      const registered = byDomainSlug.get(`${domain}:${unitSlug}`)
      if (!registered) {
        // Same slug registered under another domain is still wrong ownership.
        const cross = units.find((unit) => unit.slug === unitSlug)
        if (cross && cross.domain !== domain) {
          errors.push(diagnostic(
            'unit-ownership',
            `review domain ${domain} names cross-domain unit ${unitSlug} registered under ${cross.domain}`,
            { path: entry.path, slug: unitSlug },
          ))
        } else {
          errors.push(diagnostic(
            'unit-ownership',
            `review domain ${domain} names unregistered unit ${unitSlug}`,
            { path: entry.path, slug: unitSlug },
          ))
        }
      }
    }
  }
  return errors
}

function parsePolicy(value: unknown): ReviewCoverageReport['policy'] | string {
  if (!isPlainObject(value)) return 'policy must be an object'
  if (!exactKeys(value, ['format', 'hash'])) return 'policy must have exact format and hash fields'
  if (!nonemptyString(value.format)) return 'policy.format must be a nonempty string'
  if (typeof value.hash !== 'string' || !SHA256_RE.test(value.hash)) {
    return 'policy.hash must be a lowercase 64-hex sha256'
  }
  return { format: value.format, hash: value.hash }
}

interface StructuralParseOk {
  ok: true
  report: ReviewCoverageReport
}

interface StructuralParseErr {
  ok: false
  errors: CoverageDiagnostic[]
  /** Declared invalid reports may surface their own diagnostics without trusting the report body. */
  declaredInvalid?: boolean
}

type StructuralParseResult = StructuralParseOk | StructuralParseErr

function parseStructure(raw: unknown): StructuralParseResult {
  if (!isPlainObject(raw)) {
    return { ok: false, errors: [diagnostic('malformed-report', 'coverage report must be a JSON object')] }
  }
  if (!exactKeys(raw, TOP_LEVEL_KEYS)) {
    return {
      ok: false,
      errors: [diagnostic('malformed-report', 'coverage report must have exact known top-level fields')],
    }
  }

  if (raw.formatVersion !== 1) {
    return {
      ok: false,
      errors: [diagnostic(
        'unsupported-version',
        `formatVersion ${String(raw.formatVersion)} is unsupported (known: 1)`,
      )],
    }
  }
  if (raw.format !== FORMAT) {
    return {
      ok: false,
      errors: [diagnostic(
        'unsupported-format',
        `format must be ${FORMAT}`,
      )],
    }
  }
  if (typeof raw.verdict !== 'string' || !VERDICTS.has(raw.verdict as ReviewCoverageVerdict)) {
    return {
      ok: false,
      errors: [diagnostic('malformed-report', 'verdict must be complete, incomplete, or invalid')],
    }
  }
  const verdict = raw.verdict as ReviewCoverageVerdict

  const policy = parsePolicy(raw.policy)
  if (typeof policy === 'string') {
    return { ok: false, errors: [diagnostic('malformed-report', policy)] }
  }
  if (typeof raw.inventoryHash !== 'string' || !SHA256_RE.test(raw.inventoryHash)) {
    return {
      ok: false,
      errors: [diagnostic('malformed-report', 'inventoryHash must be a lowercase 64-hex sha256')],
    }
  }

  // Parse reportErrors early so a declared invalid verdict can fail closed
  // without trusting embedded summary/fresh claims.
  const reportErrors = parseDiagnostics(raw.reportErrors, 'reportErrors')
  if (typeof reportErrors === 'string') {
    return { ok: false, errors: [diagnostic('malformed-report', reportErrors)] }
  }
  if (verdict === 'invalid') {
    if (reportErrors.length === 0) {
      return {
        ok: false,
        errors: [diagnostic('invalid-verdict', 'invalid verdict requires at least one reportErrors item')],
      }
    }
    // Never project the body: embedded fresh counts and summary lies are untrusted.
    return {
      ok: false,
      declaredInvalid: true,
      errors: reportErrors.map((error) => diagnostic(
        error.code || 'report-error',
        error.message || 'coverage report declared invalid',
        { path: error.path, slug: error.slug },
      )),
    }
  }

  if (reportErrors.length > 0) {
    return {
      ok: false,
      errors: [diagnostic(
        'invalid-verdict',
        'complete and incomplete verdicts require an empty reportErrors array',
      )],
    }
  }

  const units = parseUnits(raw.units)
  if (typeof units === 'string') {
    return { ok: false, errors: [diagnostic('malformed-report', units)] }
  }
  const summary = parseSummary(raw.summary)
  if (typeof summary === 'string') {
    return { ok: false, errors: [diagnostic('summary-mismatch', summary)] }
  }
  const entries = parseEntries(raw.entries)
  if (typeof entries === 'string') {
    const code = /duplicate path|unsafe|normalized|path/i.test(entries) ? 'invalid-path' : 'malformed-report'
    return { ok: false, errors: [diagnostic(code, entries)] }
  }
  const invalidLedgerDetails = parseDiagnostics(raw.invalidLedgerDetails, 'invalidLedgerDetails')
  if (typeof invalidLedgerDetails === 'string') {
    return { ok: false, errors: [diagnostic('malformed-report', invalidLedgerDetails)] }
  }

  const expectedSummary = recomputeSummary(entries, invalidLedgerDetails)
  if (!summaryMatches(summary, expectedSummary) || !summaryIdentitiesHold(summary)) {
    return {
      ok: false,
      errors: [diagnostic(
        'summary-mismatch',
        'summary identities do not match recomputed coverage totals',
      )],
    }
  }

  const ownership = unitOwnershipErrors(entries, units)
  if (ownership.length) {
    return { ok: false, errors: ownership }
  }

  const gaps = gapCount(summary)
  if (verdict === 'complete' && gaps !== 0) {
    return {
      ok: false,
      errors: [diagnostic(
        'invalid-verdict',
        'complete verdict requires zero missing, stale, invalid, unclassified, conflicted, and invalid ledgers',
      )],
    }
  }
  if (verdict === 'incomplete' && gaps === 0) {
    return {
      ok: false,
      errors: [diagnostic(
        'invalid-verdict',
        'incomplete verdict requires at least one explicit gap',
      )],
    }
  }

  const report: ReviewCoverageReport = {
    formatVersion: 1,
    format: FORMAT,
    verdict,
    policy,
    inventoryHash: raw.inventoryHash,
    units,
    summary,
    entries,
    invalidLedgerDetails,
    reportErrors,
  }
  return { ok: true, report }
}

/**
 * Task 3 seam: revalidate inventory freshness and ledger evidence against Git
 * and audit portfolios. Structural Task 2 returns the report as `current` with
 * empty drift; later work overlays stale/invalid diagnostics here.
 */
function revalidateAgainstRepository(
  _root: string,
  report: ReviewCoverageReport,
  _portfolios: AuditPortfolios,
): ReviewCoveragePortfolio {
  return {
    state: 'current',
    report,
    errors: [],
    drift: emptyDrift(),
  }
}

export function loadReviewCoverage(
  root: string,
  portfolios: AuditPortfolios,
): ReviewCoveragePortfolio {
  const atlas = atlasDir(root)
  const atlasState = isSymlinkOrMissingDir(atlas)
  if (atlasState === 'symlink') {
    return invalidPortfolio([diagnostic(
      'unsafe-path',
      '.atlas directory is symlinked or not a regular directory',
    )])
  }

  const absolute = reviewCoveragePath(root)
  if (!fs.existsSync(absolute)) {
    return missingPortfolio()
  }

  try {
    const linkStat = fs.lstatSync(absolute)
    if (linkStat.isSymbolicLink() || !linkStat.isFile()) {
      return invalidPortfolio([diagnostic(
        'unsafe-path',
        'coverage report path is symlinked or not a regular file',
        { path: COVERAGE_REL },
      )])
    }
  } catch {
    return missingPortfolio()
  }

  // Bound bytes before JSON.parse; reject truncated/oversized reports.
  const opened = readRepoFile(root, COVERAGE_REL, MAX_REPORT_BYTES + 1)
  if (!opened) {
    return invalidPortfolio([diagnostic(
      'unsafe-path',
      'coverage report is not a safe regular in-repository file',
      { path: COVERAGE_REL },
    )])
  }
  if (opened.truncated || opened.size > MAX_REPORT_BYTES) {
    return invalidPortfolio([diagnostic(
      'report-too-large',
      `coverage report exceeds the ${MAX_REPORT_BYTES} byte limit`,
      { path: COVERAGE_REL },
    )])
  }

  let raw: unknown
  try {
    raw = JSON.parse(opened.buffer.toString('utf8'))
  } catch {
    return invalidPortfolio([diagnostic(
      'malformed-json',
      'coverage report is malformed JSON',
      { path: COVERAGE_REL },
    )])
  }

  const parsed = parseStructure(raw)
  if (!parsed.ok) {
    return invalidPortfolio(parsed.errors)
  }

  // Structural layer passed. Task 3 overlays Git inventory + ledger revalidation.
  return revalidateAgainstRepository(root, parsed.report, portfolios)
}
