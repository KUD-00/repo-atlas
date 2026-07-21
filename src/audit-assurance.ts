import type {
  AuditDomain,
  AuditFinding,
  CoverageDiagnostic,
  CoverageEntry,
  CoverageEvidenceStatus,
  CoverageUnitRef,
  ReviewCoveragePortfolio,
  ReviewCoverageReport,
  ReviewCoverageVerdict,
  SecurityAuditUnit,
  SecurityFindingDisposition,
  TestAuditFinding,
  TestAuditImpact,
  TestAuditUnit,
} from './types.js'

export type FindingSeverity = AuditFinding['severity']

export type UnitCoverageState = 'invalid' | 'unknown' | 'gap' | 'fresh'

export type AuditFileStatus =
  | CoverageEvidenceStatus
  | 'unclassified'
  | 'conflict'
  | 'unknown'

export interface UnitCoverageSummary {
  state: UnitCoverageState
  required: number
  fresh: number
  missing: number
  stale: number
  invalid: number
  label: string
}

/** Security risk uses severity + disposition; Test risk uses impact only. */
export type UnitRiskSummary =
  | {
      domain: 'security'
      kind: 'none' | 'open' | 'retained'
      openCount: number
      acceptedRiskCount: number
      separateDesignCount: number
      highestOpen: FindingSeverity | null
      label: string
    }
  | {
      domain: 'test'
      kind: 'none' | 'open'
      openCount: number
      highestOpen: TestAuditImpact | null
      label: string
    }

export interface AuditUnitRow {
  slug: string
  title: string
  domain: AuditDomain
  coverage: UnitCoverageSummary
  risk: UnitRiskSummary
  hasLedger: boolean
  stale: boolean
  ruleset: string | null
  scannedAt: string | null
  fileCount: number
  evidenceAccepted: boolean
  outcomeLabel: string
}

export type AuditAction =
  | {
      kind: 'coverage'
      id: string
      unitSlug: string
      path: string
      status: Exclude<AuditFileStatus, 'fresh' | 'unknown'>
      label: string
    }
  | {
      kind: 'finding'
      domain: 'security'
      id: string
      unitSlug: string
      severity: FindingSeverity
      title: string
      disposition: SecurityFindingDisposition
      label: string
    }
  | {
      kind: 'finding'
      domain: 'test'
      id: string
      unitSlug: string
      impact: TestAuditImpact
      title: string
      label: string
    }

export interface AuditFileRow {
  path: string
  status: AuditFileStatus
  unitSlug: string
  label: string
}

/** Exact ledger evidence metadata for unit detail Evidence sections. */
export interface AuditUnitEvidence {
  slug: string
  title: string
  ruleset: string | null
  scannedAt: string | null
  scopeHash: string | null
  roundCount: number | null
  evidenceRefs: string[]
  evidenceAccepted: boolean
  hasLedger: boolean
  stale: boolean
  acceptanceLabel: string
}

export type CoverageStatementKind =
  | 'complete'
  | 'incomplete'
  | 'stale'
  | 'invalid'
  | 'missing'

export interface CoverageStatementText {
  kind: CoverageStatementKind
  text: string
}

export interface GapsModeProjection {
  required: number
  fresh: number
  missing: number
  stale: number
  invalid: number
  /** Alias of fresh — already-covered numerator for gaps mode. */
  numerator: number
  /** Alias of required — domain denominator for gaps mode. */
  denominator: number
  /** Explicit non-fresh gap rows only (missing/stale/invalid/unclassified/conflict). */
  rows: AuditFileRow[]
}

interface DomainAssuranceShared {
  portfolioState: ReviewCoveragePortfolio['state']
  verdict: ReviewCoverageVerdict | null
  required: number
  fresh: number
  missing: number
  stale: number
  invalid: number
  gapCount: number
  openCount: number
  /** Repository-level excluded path count from the coverage report summary. */
  excluded: number
  /** Paths that require both Security and Tests review. */
  dualRequired: number
  unclassified: number
  conflicted: number
  /** Portfolio diagnostics (invalid report errors or invalid ledger details). */
  diagnostics: CoverageDiagnostic[]
  /** Precomputed ordered unit rows for this domain. */
  unitRows: AuditUnitRow[]
  /** Prioritized action queue (coverage before findings). */
  actions: AuditAction[]
  /** Domain-owned file rows keyed by unit slug. */
  filesByUnit: ReadonlyMap<string, AuditFileRow[]>
  /** Orphan unclassified/conflict gaps not owned by a domain unit. */
  orphanGaps: AuditFileRow[]
  /** Exact unit evidence metadata keyed by slug. */
  evidenceByUnit: ReadonlyMap<string, AuditUnitEvidence>
  /** Current accepted completed units, newest first. */
  recent: AuditUnitRow[]
}

export type DomainAssurance =
  | (DomainAssuranceShared & {
      domain: 'security'
      domainLabel: 'Security'
      openBySeverity: Record<FindingSeverity, number>
      acceptedRiskCount: number
      separateDesignCount: number
    })
  | (DomainAssuranceShared & {
      domain: 'test'
      domainLabel: 'Tests'
      openByImpact: Record<TestAuditImpact, number>
    })

const SEVERITY_ORDER: readonly FindingSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
]

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

const IMPACT_ORDER: readonly TestAuditImpact[] = ['blocking', 'warning', 'advisory']

const IMPACT_RANK: Record<TestAuditImpact, number> = {
  blocking: 0,
  warning: 1,
  advisory: 2,
}

const COVERAGE_STATE_RANK: Record<UnitCoverageState, number> = {
  invalid: 0,
  unknown: 1,
  gap: 2,
  fresh: 3,
}

const GAP_STATUSES = new Set<AuditFileStatus>([
  'missing',
  'stale',
  'invalid',
  'unclassified',
  'conflict',
])

const NO_ACTIONABLE =
  'No actionable findings in current completed review'
const NO_OPEN_RECORDED = 'No open findings recorded'
const NO_COMPLETED_EVIDENCE = 'No completed audit evidence'
const MISSING_COVERAGE_STATEMENT =
  'Coverage unknown because no review coverage report exists'
const STALE_COVERAGE_STATEMENT =
  'Coverage stale — recorded evidence is visible but not current'
const INVALID_COVERAGE_STATEMENT =
  'Coverage invalid — diagnostics present; no trusted coverage numerator'
const COMPLETE_COVERAGE_STATEMENT = 'Coverage complete and current'

function incompleteCoverageStatement(missingCount: number): string {
  if (missingCount <= 0) return 'Coverage incomplete — required reviews are missing'
  return missingCount === 1
    ? 'Coverage incomplete — 1 required review is missing'
    : `Coverage incomplete — ${missingCount} required reviews are missing`
}

function acceptanceLabel(evidenceAccepted: boolean, hasLedger: boolean): string {
  if (!hasLedger) return NO_COMPLETED_EVIDENCE
  return evidenceAccepted
    ? 'Accepted by current coverage report'
    : 'Not accepted by current coverage report'
}

function domainLabel(domain: AuditDomain): 'Security' | 'Tests' {
  return domain === 'security' ? 'Security' : 'Tests'
}

function emptySeverityCounts(): Record<FindingSeverity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
}

function emptyImpactCounts(): Record<TestAuditImpact, number> {
  return { blocking: 0, warning: 0, advisory: 0 }
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

function unitBySlug<T extends { slug: string }>(
  units: ReadonlyArray<T>,
): Map<string, T> {
  const map = new Map<string, T>()
  for (const unit of units) map.set(unit.slug, unit)
  return map
}

function effectiveFileStatus(
  domain: AuditDomain,
  entry: CoverageEntry,
  portfolioState: ReviewCoveragePortfolio['state'],
): AuditFileStatus {
  if (portfolioState === 'missing' || portfolioState === 'invalid') return 'unknown'
  const classification = entry.classification
  if (classification.kind === 'unclassified') return 'unclassified'
  if (classification.kind === 'conflict') return 'conflict'
  if (classification.kind === 'excluded') return 'unknown'
  if (!classification.domains[domain]) return 'unknown'
  if (portfolioState === 'stale') {
    // Inventory drift untrusts embedded fresh claims for presentation.
    const status = entry.evidence[domain]?.status
    if (status === 'missing' || status === 'stale' || status === 'invalid') return status
    return 'stale'
  }
  return entry.evidence[domain]?.status ?? 'missing'
}

function coverageLabel(summary: Omit<UnitCoverageSummary, 'label'>): string {
  switch (summary.state) {
    case 'invalid':
      return summary.invalid > 0
        ? `${summary.invalid} invalid evidence`
        : 'invalid coverage'
    case 'unknown':
      return 'coverage unknown'
    case 'gap': {
      const parts: string[] = []
      if (summary.missing > 0) parts.push(`${summary.missing} missing`)
      if (summary.stale > 0) parts.push(`${summary.stale} stale`)
      if (summary.invalid > 0) parts.push(`${summary.invalid} invalid`)
      if (parts.length === 0) {
        return `${summary.required - summary.fresh} coverage gaps`
      }
      return parts.join(', ')
    }
    case 'fresh':
      return `${summary.fresh}/${summary.required} fresh`
  }
}

function securityRiskLabel(risk: {
  openCount: number
  acceptedRiskCount: number
  separateDesignCount: number
  highestOpen: FindingSeverity | null
}): Pick<Extract<UnitRiskSummary, { domain: 'security' }>, 'kind' | 'label'> {
  if (risk.openCount > 0) {
    const highest = risk.highestOpen ?? 'info'
    return {
      kind: 'open',
      label:
        risk.openCount === 1
          ? `1 open (${highest})`
          : `${risk.openCount} open (highest ${highest})`,
    }
  }
  if (risk.acceptedRiskCount > 0 || risk.separateDesignCount > 0) {
    const parts: string[] = []
    if (risk.acceptedRiskCount > 0) {
      parts.push(
        risk.acceptedRiskCount === 1
          ? '1 accepted risk'
          : `${risk.acceptedRiskCount} accepted risk`,
      )
    }
    if (risk.separateDesignCount > 0) {
      parts.push(
        risk.separateDesignCount === 1
          ? '1 separate design'
          : `${risk.separateDesignCount} separate design`,
      )
    }
    return { kind: 'retained', label: parts.join(', ') }
  }
  return { kind: 'none', label: NO_OPEN_RECORDED }
}

function testRiskLabel(risk: {
  openCount: number
  highestOpen: TestAuditImpact | null
}): Pick<Extract<UnitRiskSummary, { domain: 'test' }>, 'kind' | 'label'> {
  if (risk.openCount > 0) {
    const highest = risk.highestOpen ?? 'advisory'
    return {
      kind: 'open',
      label:
        risk.openCount === 1
          ? `1 open (${highest})`
          : `${risk.openCount} open (highest ${highest})`,
    }
  }
  return { kind: 'none', label: NO_OPEN_RECORDED }
}

function outcomeLabel(row: {
  evidenceAccepted: boolean
  coverage: UnitCoverageSummary
  risk: UnitRiskSummary
  hasLedger: boolean
  stale: boolean
}, verdict: ReviewCoverageVerdict | null): string {
  if (!row.hasLedger) return 'No completed audit evidence'
  if (row.stale) return 'Stale audit evidence — re-audit needed'
  if (row.coverage.state === 'unknown') return 'Coverage has not been established'
  if (row.coverage.state === 'invalid') return 'Coverage invalid for this unit'
  if (row.coverage.state === 'gap') return 'Coverage incomplete for this unit'
  if (row.risk.openCount > 0) {
    return row.risk.highestOpen
      ? `${row.risk.openCount} open findings (highest ${row.risk.highestOpen})`
      : `${row.risk.openCount} open findings`
  }
  if (
    verdict === 'complete' &&
    row.evidenceAccepted &&
    row.coverage.state === 'fresh'
  ) {
    return NO_ACTIONABLE
  }
  return 'Recorded audit evidence'
}

function summarizeSecurityRisk(
  findings: ReadonlyArray<AuditFinding>,
): Extract<UnitRiskSummary, { domain: 'security' }> {
  let openCount = 0
  let acceptedRiskCount = 0
  let separateDesignCount = 0
  let highestOpen: FindingSeverity | null = null
  for (const finding of findings) {
    if (finding.disposition === 'accepted-risk') {
      acceptedRiskCount += 1
      continue
    }
    if (finding.disposition === 'separate-design') {
      separateDesignCount += 1
      continue
    }
    openCount += 1
    if (
      highestOpen === null ||
      SEVERITY_RANK[finding.severity] < SEVERITY_RANK[highestOpen]
    ) {
      highestOpen = finding.severity
    }
  }
  const base = { openCount, acceptedRiskCount, separateDesignCount, highestOpen }
  return { domain: 'security', ...base, ...securityRiskLabel(base) }
}

function summarizeTestRisk(
  findings: ReadonlyArray<TestAuditFinding>,
): Extract<UnitRiskSummary, { domain: 'test' }> {
  // Test findings have no disposition; every finding is actionable.
  // Keep impact vocabulary — never map into Security severity labels.
  let openCount = 0
  let highestOpen: TestAuditImpact | null = null
  for (const finding of findings) {
    openCount += 1
    if (
      highestOpen === null ||
      IMPACT_RANK[finding.impact] < IMPACT_RANK[highestOpen]
    ) {
      highestOpen = finding.impact
    }
  }
  const base = { openCount, highestOpen }
  return { domain: 'test', ...base, ...testRiskLabel(base) }
}

function buildCoverageSummary(
  counts: { required: number; fresh: number; missing: number; stale: number; invalid: number },
  portfolioState: ReviewCoveragePortfolio['state'],
  hasDomainAssignment: boolean,
): UnitCoverageSummary {
  let state: UnitCoverageState
  if (portfolioState === 'missing' || portfolioState === 'invalid') {
    state = 'unknown'
  } else if (!hasDomainAssignment && counts.required === 0) {
    // Ledger-only unit with no coverage ownership is unknown, not fresh zero.
    state = 'unknown'
  } else if (counts.invalid > 0) {
    state = 'invalid'
  } else if (counts.missing > 0 || counts.stale > 0 || portfolioState === 'stale') {
    state = 'gap'
  } else if (counts.required === 0) {
    // Registered unit with no paths yet — treat as gap until required scope exists.
    state = portfolioState === 'current' ? 'gap' : 'unknown'
  } else if (counts.fresh === counts.required) {
    state = 'fresh'
  } else {
    state = 'gap'
  }
  const base = { state, ...counts }
  return { ...base, label: coverageLabel(base) }
}

function collectDomainFiles(
  domain: AuditDomain,
  report: ReviewCoverageReport | null,
  portfolioState: ReviewCoveragePortfolio['state'],
): {
  filesByUnit: Map<string, AuditFileRow[]>
  unitCounts: Map<
    string,
    { required: number; fresh: number; missing: number; stale: number; invalid: number }
  >
  orphanGaps: AuditFileRow[]
  required: number
  fresh: number
  missing: number
  stale: number
  invalid: number
  gapCount: number
} {
  const filesByUnit = new Map<string, AuditFileRow[]>()
  const unitCounts = new Map<
    string,
    { required: number; fresh: number; missing: number; stale: number; invalid: number }
  >()
  const orphanGaps: AuditFileRow[] = []
  let required = 0
  let fresh = 0
  let missing = 0
  let stale = 0
  let invalid = 0
  let gapCount = 0

  const bump = (
    slug: string | null,
    status: AuditFileStatus,
  ): void => {
    if (slug) {
      const counts = unitCounts.get(slug) ?? {
        required: 0,
        fresh: 0,
        missing: 0,
        stale: 0,
        invalid: 0,
      }
      counts.required += 1
      if (status === 'fresh') counts.fresh += 1
      else if (status === 'missing') counts.missing += 1
      else if (status === 'stale') counts.stale += 1
      else if (status === 'invalid') counts.invalid += 1
      else if (status === 'unclassified' || status === 'conflict') counts.missing += 1
      unitCounts.set(slug, counts)
    }
  }

  if (!report || portfolioState === 'missing' || portfolioState === 'invalid') {
    return {
      filesByUnit,
      unitCounts,
      orphanGaps,
      required: 0,
      fresh: 0,
      missing: 0,
      stale: 0,
      invalid: 0,
      gapCount: 0,
    }
  }

  for (const entry of report.entries) {
    const classification = entry.classification
    if (classification.kind === 'excluded') continue

    if (classification.kind === 'unclassified' || classification.kind === 'conflict') {
      const status = classification.kind
      gapCount += 1
      orphanGaps.push({
        path: entry.path,
        status,
        unitSlug: '',
        label: status === 'conflict' ? 'policy conflict' : 'unclassified path',
      })
      continue
    }

    const unitRef = classification.domains[domain]
    if (!unitRef) continue

    const status = effectiveFileStatus(domain, entry, portfolioState)
    const slug = unitRef.unit
    required += 1
    if (status === 'fresh') fresh += 1
    else if (status === 'missing') {
      missing += 1
      gapCount += 1
    } else if (status === 'stale') {
      stale += 1
      gapCount += 1
    } else if (status === 'invalid') {
      invalid += 1
      gapCount += 1
    } else if (GAP_STATUSES.has(status)) {
      gapCount += 1
    }

    bump(slug, status)
    const rows = filesByUnit.get(slug) ?? []
    rows.push({
      path: entry.path,
      status,
      unitSlug: slug,
      label: statusLabel(status),
    })
    filesByUnit.set(slug, rows)
  }

  for (const [slug, rows] of filesByUnit) {
    rows.sort((a, b) => compareText(a.path, b.path))
    filesByUnit.set(slug, rows)
  }
  orphanGaps.sort((a, b) => compareText(a.path, b.path))

  return {
    filesByUnit,
    unitCounts,
    orphanGaps,
    required,
    fresh,
    missing,
    stale,
    invalid,
    gapCount,
  }
}

function statusLabel(status: AuditFileStatus): string {
  switch (status) {
    case 'fresh':
      return 'fresh evidence'
    case 'missing':
      return 'missing evidence'
    case 'stale':
      return 'stale evidence'
    case 'invalid':
      return 'invalid evidence'
    case 'unclassified':
      return 'unclassified path'
    case 'conflict':
      return 'policy conflict'
    case 'unknown':
      return 'coverage unknown'
  }
}

function registeredUnits(
  domain: AuditDomain,
  report: ReviewCoverageReport | null,
  ledgers: ReadonlyArray<SecurityAuditUnit | TestAuditUnit>,
): CoverageUnitRef[] {
  const bySlug = new Map<string, CoverageUnitRef>()
  if (report) {
    for (const unit of report.units) {
      if (unit.domain === domain) bySlug.set(unit.slug, unit)
    }
  }
  for (const unit of ledgers) {
    if (!bySlug.has(unit.slug)) {
      bySlug.set(unit.slug, {
        domain,
        slug: unit.slug,
        title: unit.title,
      })
    }
  }
  return [...bySlug.values()]
}

/**
 * A ledger is evidence-accepted only when a current portfolio has at least one
 * fresh same-domain claim that explicitly names its slug and the ledger is a
 * non-stale v2 unit whose files/hashes contain that exact report blob.
 * Unit coverage completeness is orthogonal and does not imply acceptance.
 */
function acceptedLedgerSlugs(
  domain: AuditDomain,
  report: ReviewCoverageReport | null,
  portfolioState: ReviewCoveragePortfolio['state'],
  ledgers: Map<string, SecurityAuditUnit | TestAuditUnit>,
): Set<string> {
  const accepted = new Set<string>()
  if (!report || portfolioState !== 'current') return accepted

  for (const entry of report.entries) {
    if (entry.classification.kind !== 'review') continue
    if (!entry.classification.domains[domain]) continue
    const claim = entry.evidence[domain]
    if (!claim || claim.status !== 'fresh') continue
    const reportBlob = entry.blob
    if (!reportBlob) continue

    for (const slug of claim.ledgers) {
      if (accepted.has(slug)) continue
      const unit = ledgers.get(slug)
      if (!unit) continue
      if (unit.formatVersion !== 2 || unit.stale) continue
      if (!unit.files.includes(entry.path)) continue
      if (unit.hashes === null || unit.hashes[entry.path] !== reportBlob) continue
      accepted.add(slug)
    }
  }
  return accepted
}

function buildUnitEvidence(
  ref: CoverageUnitRef,
  ledger: SecurityAuditUnit | TestAuditUnit | undefined,
  evidenceAccepted: boolean,
): AuditUnitEvidence {
  const hasLedger = ledger !== undefined
  return {
    slug: ref.slug,
    title: ref.title,
    ruleset: ledger?.ruleset ?? null,
    scannedAt: ledger?.scannedAt ?? null,
    scopeHash: ledger?.scopeHash ?? null,
    roundCount: ledger?.roundCount ?? null,
    evidenceRefs: ledger ? ledger.evidenceRefs.slice() : [],
    evidenceAccepted,
    hasLedger,
    stale: ledger?.stale ?? false,
    acceptanceLabel: acceptanceLabel(evidenceAccepted, hasLedger),
  }
}

function buildUnitRow(
  domain: AuditDomain,
  ref: CoverageUnitRef,
  ledger: SecurityAuditUnit | TestAuditUnit | undefined,
  counts: { required: number; fresh: number; missing: number; stale: number; invalid: number },
  portfolioState: ReviewCoveragePortfolio['state'],
  hasDomainAssignment: boolean,
  evidenceAccepted: boolean,
  verdict: ReviewCoverageVerdict | null,
): AuditUnitRow {
  const coverage = buildCoverageSummary(counts, portfolioState, hasDomainAssignment)
  const risk: UnitRiskSummary =
    domain === 'security'
      ? summarizeSecurityRisk(
          ((ledger as SecurityAuditUnit | undefined)?.findings ?? []) as AuditFinding[],
        )
      : summarizeTestRisk(
          ((ledger as TestAuditUnit | undefined)?.findings ?? []) as TestAuditFinding[],
        )
  const hasLedger = ledger !== undefined
  const stale = ledger?.stale ?? false

  const row: AuditUnitRow = {
    slug: ref.slug,
    title: ref.title,
    domain,
    coverage,
    risk,
    hasLedger,
    stale,
    ruleset: ledger?.ruleset ?? null,
    scannedAt: ledger?.scannedAt ?? null,
    fileCount: coverage.required > 0 ? coverage.required : ledger?.fileCount ?? 0,
    evidenceAccepted,
    outcomeLabel: '',
  }
  row.outcomeLabel = outcomeLabel(row, verdict)
  return row
}

function openRank(risk: UnitRiskSummary): number {
  if (risk.openCount <= 0 || risk.highestOpen === null) {
    return risk.domain === 'security' ? SEVERITY_ORDER.length : IMPACT_ORDER.length
  }
  if (risk.domain === 'security') return SEVERITY_RANK[risk.highestOpen]
  return IMPACT_RANK[risk.highestOpen]
}

function compareUnitRows(a: AuditUnitRow, b: AuditUnitRow): number {
  const cov = COVERAGE_STATE_RANK[a.coverage.state] - COVERAGE_STATE_RANK[b.coverage.state]
  if (cov !== 0) return cov

  const aSev = openRank(a.risk)
  const bSev = openRank(b.risk)
  if (aSev !== bSev) return aSev - bSev

  const title = compareText(a.title, b.title)
  if (title !== 0) return title
  return compareText(a.slug, b.slug)
}

function buildActions(
  domain: AuditDomain,
  unitRows: ReadonlyArray<AuditUnitRow>,
  filesByUnit: ReadonlyMap<string, AuditFileRow[]>,
  orphanGaps: ReadonlyArray<AuditFileRow>,
  ledgers: Map<string, SecurityAuditUnit | TestAuditUnit>,
): AuditAction[] {
  const coverageActions: AuditAction[] = []

  for (const gap of orphanGaps) {
    if (!GAP_STATUSES.has(gap.status) || gap.status === 'unknown') continue
    coverageActions.push({
      kind: 'coverage',
      id: `coverage::${gap.status}::${gap.path}`,
      unitSlug: gap.unitSlug,
      path: gap.path,
      status: gap.status as Exclude<AuditFileStatus, 'fresh' | 'unknown'>,
      label: `${gap.path}: ${gap.label}`,
    })
  }

  for (const row of unitRows) {
    const files = filesByUnit.get(row.slug) ?? []
    for (const file of files) {
      if (file.status === 'fresh' || file.status === 'unknown') continue
      if (!GAP_STATUSES.has(file.status)) continue
      coverageActions.push({
        kind: 'coverage',
        id: `coverage::${row.slug}::${file.path}`,
        unitSlug: row.slug,
        path: file.path,
        status: file.status as Exclude<AuditFileStatus, 'fresh' | 'unknown'>,
        label: `${row.title}: ${file.path} ${file.label}`,
      })
    }
  }

  coverageActions.sort((a, b) => {
    if (a.kind !== 'coverage' || b.kind !== 'coverage') return 0
    const pathCmp = compareText(a.path, b.path)
    if (pathCmp !== 0) return pathCmp
    return compareText(a.unitSlug, b.unitSlug)
  })

  const findingActions: AuditAction[] = []
  if (domain === 'security') {
    for (const row of unitRows) {
      const ledger = ledgers.get(row.slug) as SecurityAuditUnit | undefined
      if (!ledger) continue
      for (const finding of ledger.findings) {
        if (finding.disposition !== 'open') continue
        const id = finding.id ?? `${row.slug}:${finding.title}:${finding.severity}`
        findingActions.push({
          kind: 'finding',
          domain: 'security',
          id,
          unitSlug: row.slug,
          severity: finding.severity,
          title: finding.title,
          disposition: finding.disposition,
          label: `${finding.severity}: ${finding.title}`,
        })
      }
    }
    findingActions.sort((a, b) => {
      if (a.kind !== 'finding' || b.kind !== 'finding') return 0
      if (a.domain !== 'security' || b.domain !== 'security') return 0
      const sev = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
      if (sev !== 0) return sev
      const title = compareText(a.title, b.title)
      if (title !== 0) return title
      return compareText(a.id, b.id)
    })
  } else {
    for (const row of unitRows) {
      const ledger = ledgers.get(row.slug) as TestAuditUnit | undefined
      if (!ledger) continue
      for (const finding of ledger.findings) {
        const id = `${row.slug}:${finding.title}:${finding.impact}`
        findingActions.push({
          kind: 'finding',
          domain: 'test',
          id,
          unitSlug: row.slug,
          impact: finding.impact,
          title: finding.title,
          label: `${finding.impact}: ${finding.title}`,
        })
      }
    }
    findingActions.sort((a, b) => {
      if (a.kind !== 'finding' || b.kind !== 'finding') return 0
      if (a.domain !== 'test' || b.domain !== 'test') return 0
      const imp = IMPACT_RANK[a.impact] - IMPACT_RANK[b.impact]
      if (imp !== 0) return imp
      const title = compareText(a.title, b.title)
      if (title !== 0) return title
      return compareText(a.id, b.id)
    })
  }

  return [...coverageActions, ...findingActions]
}

/**
 * Pure domain-level coverage/risk/evidence model.
 * React and route helpers must not invent coverage; they render this model.
 */
export function domainAssurance(
  domain: AuditDomain,
  coverage: ReviewCoveragePortfolio,
  units: ReadonlyArray<SecurityAuditUnit | TestAuditUnit>,
): DomainAssurance {
  const domainUnits = units.filter((unit) => unit.domain === domain)
  const ledgers = unitBySlug(domainUnits)
  const report = coverage.report
  const collected = collectDomainFiles(domain, report, coverage.state)
  const refs = registeredUnits(domain, report, domainUnits)
  const acceptedSlugs = acceptedLedgerSlugs(domain, report, coverage.state, ledgers)

  // Ensure registered units appear in unitCounts even with zero owned files.
  for (const ref of refs) {
    if (!collected.unitCounts.has(ref.slug)) {
      collected.unitCounts.set(ref.slug, {
        required: 0,
        fresh: 0,
        missing: 0,
        stale: 0,
        invalid: 0,
      })
    }
  }

  const registeredSlugs = new Set(
    (report?.units ?? [])
      .filter((unit) => unit.domain === domain)
      .map((unit) => unit.slug),
  )

  const evidenceByUnit = new Map<string, AuditUnitEvidence>()
  const unitRows = refs
    .map((ref) => {
      const counts = collected.unitCounts.get(ref.slug) ?? {
        required: 0,
        fresh: 0,
        missing: 0,
        stale: 0,
        invalid: 0,
      }
      // Ownership comes from the coverage registry/classification, never ledger membership.
      const hasDomainAssignment =
        registeredSlugs.has(ref.slug) || counts.required > 0
      const accepted = acceptedSlugs.has(ref.slug)
      const ledger = ledgers.get(ref.slug)
      evidenceByUnit.set(ref.slug, buildUnitEvidence(ref, ledger, accepted))
      return buildUnitRow(
        domain,
        ref,
        ledger,
        counts,
        coverage.state,
        hasDomainAssignment,
        accepted,
        report?.verdict ?? null,
      )
    })
    .sort(compareUnitRows)

  let openCount = 0
  for (const row of unitRows) {
    openCount += row.risk.openCount
  }

  const actions = buildActions(
    domain,
    unitRows,
    collected.filesByUnit,
    collected.orphanGaps,
    ledgers,
  )

  const recent = unitRows
    .filter((row) => row.evidenceAccepted)
    .sort((a, b) => {
      const at = a.scannedAt ?? ''
      const bt = b.scannedAt ?? ''
      if (at !== bt) return bt < at ? -1 : bt > at ? 1 : 0
      return compareText(a.slug, b.slug)
    })

  // When inventory is stale, never report zero gaps as "covered".
  // Invalid ledgers are repository-level coverage gaps. Diagnostics do not
  // carry a trustworthy domain, so both domain portfolios must fail safe.
  let gapCount = collected.gapCount + (report?.invalidLedgerDetails.length ?? 0)
  if (coverage.state === 'stale') {
    const drift =
      coverage.drift.added.length +
      coverage.drift.removed.length +
      coverage.drift.changed.length
    gapCount = Math.max(gapCount, drift, 1)
  }

  const summary = report?.summary
  const diagnostics: CoverageDiagnostic[] =
    coverage.state === 'invalid'
      ? coverage.errors.slice()
      : (report?.invalidLedgerDetails ?? []).concat(report?.reportErrors ?? [])

  const shared: DomainAssuranceShared = {
    portfolioState: coverage.state,
    verdict: report?.verdict ?? null,
    required: collected.required,
    fresh: collected.fresh,
    missing: collected.missing,
    stale: collected.stale,
    invalid: collected.invalid,
    gapCount,
    openCount,
    excluded: summary?.excluded ?? 0,
    dualRequired: summary?.dualRequired ?? 0,
    unclassified: summary?.unclassified ?? 0,
    conflicted: summary?.conflicted ?? 0,
    diagnostics,
    unitRows,
    actions,
    filesByUnit: collected.filesByUnit,
    orphanGaps: collected.orphanGaps.slice(),
    evidenceByUnit,
    recent,
  }

  if (domain === 'security') {
    const openBySeverity = emptySeverityCounts()
    let acceptedRiskCount = 0
    let separateDesignCount = 0
    for (const row of unitRows) {
      if (row.risk.domain !== 'security') continue
      acceptedRiskCount += row.risk.acceptedRiskCount
      separateDesignCount += row.risk.separateDesignCount
    }
    for (const unit of domainUnits as SecurityAuditUnit[]) {
      for (const finding of unit.findings) {
        if (finding.disposition === 'open') {
          openBySeverity[finding.severity] += 1
        }
      }
    }
    return {
      ...shared,
      domain: 'security',
      domainLabel: 'Security',
      openBySeverity,
      acceptedRiskCount,
      separateDesignCount,
    }
  }

  const openByImpact = emptyImpactCounts()
  for (const unit of domainUnits as TestAuditUnit[]) {
    for (const finding of unit.findings) {
      openByImpact[finding.impact] += 1
    }
  }
  return {
    ...shared,
    domain: 'test',
    domainLabel: 'Tests',
    openByImpact,
  }
}

export function domainNavSuffix(model: DomainAssurance): {
  text: string
  ariaLabel: string
  kind: 'unknown' | 'gap' | 'open' | 'covered'
} {
  const name = model.domainLabel
  if (
    model.portfolioState === 'missing' ||
    model.portfolioState === 'invalid' ||
    model.verdict === 'invalid'
  ) {
    return {
      text: 'unknown',
      kind: 'unknown',
      ariaLabel: `${name} coverage unknown or unavailable`,
    }
  }

  // Domain suffix is domain-local: a fully fresh Security domain stays covered
  // even when Tests still has gaps on a dual-domain incomplete report.
  if (model.portfolioState === 'stale' || model.gapCount > 0) {
    const n = Math.max(model.gapCount, 1)
    return {
      text: `${n} gaps`,
      kind: 'gap',
      ariaLabel: `${name} ${n} coverage gaps`,
    }
  }

  if (model.openCount > 0) {
    return {
      text: `${model.openCount} open`,
      kind: 'open',
      ariaLabel: `${name} ${model.openCount} open findings`,
    }
  }

  return {
    text: 'covered',
    kind: 'covered',
    ariaLabel: `${name} coverage complete`,
  }
}

export function auditUnitRows(model: DomainAssurance): AuditUnitRow[] {
  return model.unitRows.slice()
}

export function auditActionQueue(model: DomainAssurance): AuditAction[] {
  return model.actions.slice()
}

export function auditFilesForUnit(model: DomainAssurance, slug: string): AuditFileRow[] {
  return (model.filesByUnit.get(slug) ?? []).slice()
}

export function recentAuditUnits(model: DomainAssurance): AuditUnitRow[] {
  return model.recent.slice()
}

/**
 * Attention mode: coverage gaps before open findings.
 * Accepted-risk and separate-design findings are never actionable.
 */
export function attentionActions(model: DomainAssurance): AuditAction[] {
  return model.actions.slice()
}

/**
 * Gaps mode: keep already-fresh numerator and required denominator explicit,
 * plus a stable list of only the non-fresh gap rows.
 */
export function gapsModeProjection(model: DomainAssurance): GapsModeProjection {
  const rows: AuditFileRow[] = []
  for (const gap of model.orphanGaps) {
    if (gap.status === 'fresh' || gap.status === 'unknown') continue
    rows.push({ ...gap })
  }
  for (const unit of model.unitRows) {
    for (const file of model.filesByUnit.get(unit.slug) ?? []) {
      if (file.status === 'fresh' || file.status === 'unknown') continue
      if (!GAP_STATUSES.has(file.status)) continue
      rows.push({ ...file })
    }
  }
  rows.sort((a, b) => {
    const pathCmp = compareText(a.path, b.path)
    if (pathCmp !== 0) return pathCmp
    return compareText(a.unitSlug, b.unitSlug)
  })
  return {
    required: model.required,
    fresh: model.fresh,
    missing: model.missing,
    stale: model.stale,
    invalid: model.invalid,
    numerator: model.fresh,
    denominator: model.required,
    rows,
  }
}

/** Case-insensitive substring filter over unit file paths; empty query returns all. */
export function searchUnitFiles(
  model: DomainAssurance,
  slug: string,
  query: string,
): AuditFileRow[] {
  const rows = auditFilesForUnit(model, slug)
  const q = query.trim().toLowerCase()
  if (!q) return rows
  return rows.filter((row) => row.path.toLowerCase().includes(q))
}

/** Exact unit evidence metadata (ruleset, scan, scope, rounds, refs, acceptance). */
export function auditUnitEvidence(
  model: DomainAssurance,
  slug: string,
): AuditUnitEvidence | null {
  return model.evidenceByUnit.get(slug) ?? null
}

/**
 * Repository-level coverage statement. Missing/invalid/stale/incomplete/complete
 * are distinct; never invents a trusted denominator.
 */
export function coverageStatementText(model: DomainAssurance): CoverageStatementText {
  if (model.portfolioState === 'missing') {
    return { kind: 'missing', text: MISSING_COVERAGE_STATEMENT }
  }
  if (model.portfolioState === 'invalid' || model.verdict === 'invalid') {
    const first = model.diagnostics[0]
    const detail = first?.message?.trim()
    return {
      kind: 'invalid',
      text: detail
        ? `${INVALID_COVERAGE_STATEMENT} (${detail})`
        : INVALID_COVERAGE_STATEMENT,
    }
  }
  if (model.portfolioState === 'stale') {
    return { kind: 'stale', text: STALE_COVERAGE_STATEMENT }
  }
  if (model.verdict === 'incomplete' || model.gapCount > 0) {
    return {
      kind: 'incomplete',
      text: incompleteCoverageStatement(Math.max(model.missing, model.gapCount)),
    }
  }
  return { kind: 'complete', text: COMPLETE_COVERAGE_STATEMENT }
}

/**
 * Strong zero-finding phrase only when coverage is current + complete,
 * there are zero open findings, and at least one accepted exact evidence unit.
 * Never for missing, invalid, incomplete, or stale portfolios.
 */
export function strongZeroFindingPhrase(model: DomainAssurance): string | null {
  if (model.portfolioState !== 'current') return null
  if (model.verdict !== 'complete') return null
  if (model.gapCount > 0) return null
  if (model.openCount > 0) return null
  if (model.unitRows.length === 0) return null
  if (!model.unitRows.some((row) => row.evidenceAccepted)) return null
  return NO_ACTIONABLE
}

/**
 * Whether repository-level coverage counts are trusted for presentation.
 * Missing and invalid portfolios have no trustworthy denominator — UI must not
 * render synthetic 0/0 required/fresh/gap facts. Current and stale portfolios
 * may show counts (stale still has a report body; presentation marks drift).
 */
export function coverageCountsAvailable(model: DomainAssurance): boolean {
  return model.portfolioState === 'current' || model.portfolioState === 'stale'
}

/**
 * Where an attention/coverage action should navigate.
 * Coverage with a nonempty path always code-jumps (even when unitSlug is set);
 * coverage without a path falls back to gaps mode; findings select their unit.
 */
export type AuditActionTarget =
  | { kind: 'code-jump'; path: string }
  | { kind: 'unit'; unitSlug: string }
  | { kind: 'gaps' }

export function auditActionTarget(action: AuditAction): AuditActionTarget {
  if (action.kind === 'coverage') {
    if (action.path.length > 0) {
      return { kind: 'code-jump', path: action.path }
    }
    return { kind: 'gaps' }
  }
  return { kind: 'unit', unitSlug: action.unitSlug }
}

/** Local domain view modes for overview / attention / gaps sidebar controls. */
export type AuditViewMode = 'overview' | 'attention' | 'gaps'

export type AuditSidebarModeRow = {
  kind: AuditViewMode
  mode: AuditViewMode
  label: string
  /** Compact textual status (actionable or gap count); never a raw finding total alone. */
  suffix: string | null
}

export type AuditSidebarUnitRow = {
  kind: 'unit'
  slug: string
  title: string
  coverageLabel: string
  riskLabel: string
}

export type AuditSidebarRow = AuditSidebarModeRow | AuditSidebarUnitRow

/**
 * UI-ready sidebar projection: fixed Overview / Needs attention / Coverage gaps,
 * then stable registered units with separate coverage and risk labels.
 */
export function auditSidebarRows(model: DomainAssurance): AuditSidebarRow[] {
  const actionable = model.actions.length
  const gapCount = model.gapCount
  const coverageUnknown =
    model.portfolioState === 'missing' || model.portfolioState === 'invalid'
  const fixed: AuditSidebarModeRow[] = [
    {
      kind: 'overview',
      mode: 'overview',
      label: 'Overview',
      suffix: null,
    },
    {
      kind: 'attention',
      mode: 'attention',
      label: 'Needs attention',
      suffix: coverageUnknown && actionable === 0 ? 'unknown' : String(actionable),
    },
    {
      kind: 'gaps',
      mode: 'gaps',
      label: 'Coverage gaps',
      suffix: coverageUnknown ? 'unknown' : String(gapCount),
    },
  ]

  const units: AuditSidebarUnitRow[] = model.unitRows.map((row) => ({
    kind: 'unit',
    slug: row.slug,
    title: row.title,
    coverageLabel: row.coverage.label,
    riskLabel: row.risk.label,
  }))

  return [...fixed, ...units]
}
