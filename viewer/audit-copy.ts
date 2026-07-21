/**
 * Viewer-only semantic → localized copy for audit assurance.
 *
 * Derives display strings from typed semantic fields (portfolio state, verdict,
 * coverage/risk summaries, file status, action kind, suffix kind/count).
 * Never passes model-owned English labels into i18n — all msgids are
 * compile-time Lingui `t` macros.
 */
import type { I18n } from '@lingui/core'
import { t } from '@lingui/core/macro'
import type {
  AuditAction,
  AuditFileStatus,
  AuditSidebarModeRow,
  AuditUnitEvidence,
  AuditUnitRow,
  CoverageStatementKind,
  DomainAssurance,
  UnitCoverageSummary,
  UnitRiskSummary,
} from '../src/audit-assurance'
import type { ReviewCoverageVerdict } from '../src/types'

export type LocalizedCoverageStatement = {
  kind: CoverageStatementKind
  text: string
}

export type LocalizedDomainNavSuffix = {
  text: string
  kind: 'unknown' | 'gap' | 'open' | 'covered'
  ariaLabel: string
}

function domainName(i18n: I18n, domain: DomainAssurance['domain']): string {
  return domain === 'security' ? t(i18n)`Security` : t(i18n)`Tests`
}

/** Repository-level coverage statement from portfolio/verdict/gaps/diagnostics. */
export function localizedCoverageStatement(
  i18n: I18n,
  model: DomainAssurance,
): LocalizedCoverageStatement {
  if (model.portfolioState === 'missing') {
    return {
      kind: 'missing',
      text: t(i18n)`Coverage unknown because no review coverage report exists`,
    }
  }
  if (model.portfolioState === 'invalid' || model.verdict === 'invalid') {
    const prefix = t(
      i18n,
    )`Coverage invalid — diagnostics present; no trusted coverage numerator`
    const detail = model.diagnostics[0]?.message?.trim()
    return {
      kind: 'invalid',
      text: detail ? `${prefix} (${detail})` : prefix,
    }
  }
  if (model.portfolioState === 'stale') {
    return {
      kind: 'stale',
      text: t(i18n)`Coverage stale — recorded evidence is visible but not current`,
    }
  }
  if (model.verdict === 'incomplete' || model.gapCount > 0) {
    const missingCount = Math.max(model.missing, model.gapCount)
    let text: string
    if (missingCount <= 0) {
      text = t(i18n)`Coverage incomplete — required reviews are missing`
    } else if (missingCount === 1) {
      text = t(i18n)`Coverage incomplete — 1 required review is missing`
    } else {
      text = t(i18n)`Coverage incomplete — ${missingCount} required reviews are missing`
    }
    return { kind: 'incomplete', text }
  }
  return {
    kind: 'complete',
    text: t(i18n)`Coverage complete and current`,
  }
}

/** Unit coverage compact label from typed UnitCoverageSummary fields. */
export function localizedCoverageLabel(
  i18n: I18n,
  coverage: UnitCoverageSummary,
): string {
  switch (coverage.state) {
    case 'invalid':
      return coverage.invalid > 0
        ? t(i18n)`${coverage.invalid} invalid evidence`
        : t(i18n)`invalid coverage`
    case 'unknown':
      return t(i18n)`coverage unknown`
    case 'gap': {
      const parts: string[] = []
      if (coverage.missing > 0) parts.push(t(i18n)`${coverage.missing} missing`)
      if (coverage.stale > 0) parts.push(t(i18n)`${coverage.stale} stale`)
      if (coverage.invalid > 0) parts.push(t(i18n)`${coverage.invalid} invalid`)
      if (parts.length === 0) {
        const n = coverage.required - coverage.fresh
        return t(i18n)`${n} coverage gaps`
      }
      return parts.join(', ')
    }
    case 'fresh':
      return t(i18n)`${coverage.fresh}/${coverage.required} fresh`
  }
}

/** Unit risk compact label; preserves Security disposition vs Test impact. */
export function localizedRiskLabel(i18n: I18n, risk: UnitRiskSummary): string {
  if (risk.openCount > 0) {
    const highest = risk.highestOpen ?? (risk.domain === 'security' ? 'info' : 'advisory')
    return risk.openCount === 1
      ? t(i18n)`1 open (${highest})`
      : t(i18n)`${risk.openCount} open (highest ${highest})`
  }
  if (risk.domain === 'security') {
    if (risk.acceptedRiskCount > 0 || risk.separateDesignCount > 0) {
      const parts: string[] = []
      if (risk.acceptedRiskCount > 0) {
        parts.push(
          risk.acceptedRiskCount === 1
            ? t(i18n)`1 accepted risk`
            : t(i18n)`${risk.acceptedRiskCount} accepted risk`,
        )
      }
      if (risk.separateDesignCount > 0) {
        parts.push(
          risk.separateDesignCount === 1
            ? t(i18n)`1 separate design`
            : t(i18n)`${risk.separateDesignCount} separate design`,
        )
      }
      return parts.join(', ')
    }
  }
  return t(i18n)`No open findings recorded`
}

/** File-row status from typed AuditFileStatus (never row.label). */
export function localizedFileStatusLabel(
  i18n: I18n,
  status: AuditFileStatus,
): string {
  switch (status) {
    case 'fresh':
      return t(i18n)`fresh evidence`
    case 'missing':
      return t(i18n)`missing evidence`
    case 'stale':
      return t(i18n)`stale evidence`
    case 'invalid':
      return t(i18n)`invalid evidence`
    case 'unclassified':
      return t(i18n)`unclassified path`
    case 'conflict':
      return t(i18n)`policy conflict`
    case 'unknown':
      return t(i18n)`coverage unknown`
  }
}

/** Evidence acceptance from flags (never acceptanceLabel). */
export function localizedAcceptanceLabel(
  i18n: I18n,
  row: Pick<AuditUnitEvidence, 'evidenceAccepted' | 'hasLedger'>,
): string {
  if (!row.hasLedger) return t(i18n)`No completed audit evidence`
  return row.evidenceAccepted
    ? t(i18n)`Accepted by current coverage report`
    : t(i18n)`Not accepted by current coverage report`
}

/** Unit outcome from row semantics + model verdict (never outcomeLabel). */
export function localizedOutcomeLabel(
  i18n: I18n,
  row: AuditUnitRow,
  verdict: ReviewCoverageVerdict | null,
): string {
  if (!row.hasLedger) return t(i18n)`No completed audit evidence`
  if (row.stale) return t(i18n)`Stale audit evidence — re-audit needed`
  if (row.coverage.state === 'unknown') return t(i18n)`Coverage has not been established`
  if (row.coverage.state === 'invalid') return t(i18n)`Coverage invalid for this unit`
  if (row.coverage.state === 'gap') return t(i18n)`Coverage incomplete for this unit`
  if (row.risk.openCount > 0) {
    return row.risk.highestOpen
      ? t(i18n)`${row.risk.openCount} open findings (highest ${row.risk.highestOpen})`
      : t(i18n)`${row.risk.openCount} open findings`
  }
  if (
    verdict === 'complete' &&
    row.evidenceAccepted &&
    row.coverage.state === 'fresh'
  ) {
    return t(i18n)`No actionable findings in current completed review`
  }
  return t(i18n)`Recorded audit evidence`
}

/**
 * Action queue copy from kind + typed status/severity/impact/path/title.
 * Paths, titles, severity, and impact remain raw technical/user content.
 * Optional unitTitle preserves assigned-unit context without reading action.label.
 */
export function localizedActionLabel(
  i18n: I18n,
  action: AuditAction,
  unitTitle?: string | null,
): string {
  if (action.kind === 'coverage') {
    const status = localizedFileStatusLabel(i18n, action.status)
    if (unitTitle) {
      return t(i18n)`${unitTitle}: ${action.path} ${status}`
    }
    return t(i18n)`${action.path}: ${status}`
  }
  if (action.domain === 'security') {
    return t(i18n)`${action.severity}: ${action.title}`
  }
  return t(i18n)`${action.impact}: ${action.title}`
}

/**
 * Compile-time strong zero-finding phrase. Callers gate with
 * `strongZeroFindingPhrase(model)` (boolean presence only) and render this.
 */
export function localizedStrongZeroFindingPhrase(i18n: I18n): string {
  return t(i18n)`No actionable findings in current completed review`
}

/** Sidebar mode suffixes are numeric counts or the semantic unknown state. */
export function localizedSidebarSuffix(
  i18n: I18n,
  suffix: AuditSidebarModeRow['suffix'],
): string | null {
  return suffix === 'unknown' ? t(i18n)`unknown` : suffix
}

/**
 * Primary nav suffix text + ARIA from semantic model kind/count.
 * Priority: unknown → gaps → open → covered.
 */
export function localizedDomainNavSuffix(
  i18n: I18n,
  model: DomainAssurance,
): LocalizedDomainNavSuffix {
  const name = domainName(i18n, model.domain)
  if (
    model.portfolioState === 'missing' ||
    model.portfolioState === 'invalid' ||
    model.verdict === 'invalid'
  ) {
    return {
      text: t(i18n)`unknown`,
      kind: 'unknown',
      ariaLabel: t(i18n)`${name} coverage unknown or unavailable`,
    }
  }
  if (model.portfolioState === 'stale' || model.gapCount > 0) {
    const n = Math.max(model.gapCount, 1)
    return {
      text: t(i18n)`${n} gaps`,
      kind: 'gap',
      ariaLabel: t(i18n)`${name} ${n} coverage gaps`,
    }
  }
  if (model.openCount > 0) {
    return {
      text: t(i18n)`${model.openCount} open`,
      kind: 'open',
      ariaLabel: t(i18n)`${name} ${model.openCount} open findings`,
    }
  }
  return {
    text: t(i18n)`covered`,
    kind: 'covered',
    ariaLabel: t(i18n)`${name} coverage complete`,
  }
}
