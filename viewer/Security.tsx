import { useMemo, useState } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { ShieldAlert } from 'lucide-react'
import {
  attentionActions,
  auditActionTarget,
  auditFilesForUnit,
  auditUnitEvidence,
  gapsModeProjection,
  recentAuditUnits,
  strongZeroFindingPhrase,
  type AuditAction,
  type AuditViewMode,
  type DomainAssurance,
} from '../src/audit-assurance'
import { auditFilterChipAriaPressed } from '../src/audit-a11y'
import { visibleFilterOptions } from '../src/audit-filters'
import { auditRoute, auditUnitRoute } from '../src/audit-routes'
import type { AuditFinding, SecurityAuditUnit, SecurityFindingDisposition } from '../src/types'
import {
  AuditEvidenceSummary,
  AuditFileTable,
  AuditUnitPortfolio,
  CoverageStatement,
  CoverageSummary,
} from './AuditCoverage'
import { AuditLocation } from './AuditLocation'
import { conceptRoute } from './Concept'

/**
 * Security portfolio — coverage-first assurance view of `.atlas/audits/`
 * plus `.atlas/review-coverage.json`. Renders derived DomainAssurance only;
 * never invents coverage from the Code tree.
 */

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
type Severity = (typeof SEV_ORDER)[number]

const SEV_STYLE: Record<Severity, string> = {
  critical: 'text-[#c4222e] bg-[#c4222e14] border-[#c4222e40]',
  high: 'text-[#c4222e] bg-[#c4222e0d] border-[#c4222e30]',
  medium: 'text-[#b8790a] bg-[#d9930d14] border-[#d9930d40]',
  low: 'text-[#3d6b54] bg-[#3d6b540d] border-[#3d6b5430]',
  info: 'text-muted bg-panel border-border',
}

const DISP_STYLE: Record<SecurityFindingDisposition, string> = {
  open: 'text-[#c4222e] bg-[#c4222e0d] border-[#c4222e30]',
  'accepted-risk': 'text-[#b8790a] bg-[#d9930d14] border-[#d9930d40]',
  'separate-design': 'text-muted bg-panel border-border',
}

const CHIP =
  'inline-flex items-center gap-1 text-[0.68rem] font-semibold py-px px-[7px] rounded-md border whitespace-nowrap'
const SECTION =
  'mb-6 pb-5 border-b border-border last:border-b-0 last:pb-0 last:mb-0'
const META = 'text-[0.78rem] text-muted'
const FACT =
  'inline-flex items-baseline gap-1.5 text-[0.78rem] text-muted mr-3 mb-1'
const FACT_VALUE = 'text-text font-semibold tabular-nums'
const ACTION_BTN =
  'w-full text-left font-inherit text-[0.82rem] py-1.5 px-0 border-none bg-transparent cursor-pointer text-text hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 rounded-sm'
const PANE =
  'max-w-[860px] py-9 px-12 pb-24 max-md:py-5 max-md:px-4 max-md:pb-16'

function SevBadge({ sev }: { sev: Severity }) {
  return <span className={CHIP + ' ' + SEV_STYLE[sev]}>{sev}</span>
}

function DispositionBadge({ disposition }: { disposition: SecurityFindingDisposition }) {
  const { i18n } = useLingui()
  const label =
    disposition === 'accepted-risk'
      ? t(i18n)`accepted risk`
      : disposition === 'separate-design'
        ? t(i18n)`separate design`
        : t(i18n)`open`
  return <span className={CHIP + ' ' + DISP_STYLE[disposition]}>{label}</span>
}

export function FindingCard({ finding }: { finding: AuditFinding }) {
  const { i18n } = useLingui()
  return (
    <article className="border border-border rounded-lg py-2.5 px-3 mb-2 bg-panel">
      <div className="flex items-center gap-1.5 flex-wrap">
        <SevBadge sev={finding.severity as Severity} />
        <DispositionBadge disposition={finding.disposition} />
        <span className={CHIP + ' text-muted bg-panel border-border'}>{finding.category}</span>
        {finding.confidence === 'unverified' && (
          <span
            className={CHIP + ' text-[#b8790a] bg-[#d9930d14] border-[#d9930d40]'}
            title={t(i18n)`the factcheck gate could not confirm this from source`}
          >
            ⚠ {t(i18n)`unverified`}
          </span>
        )}
      </div>
      <div className="text-[0.85rem] font-semibold mt-1.5">{finding.title}</div>
      <div className="text-[0.78rem] text-muted mt-1">
        <b className="text-text font-semibold">{t(i18n)`dataflow`}</b> {finding.dataflow}
      </div>
      <div className="text-[0.78rem] text-muted mt-1">
        <b className="text-text font-semibold">{t(i18n)`fix`}</b> {finding.fix}
      </div>
      <div className="flex gap-1 flex-wrap mt-2">
        {finding.locations.map((l) => (
          <AuditLocation key={l} loc={l} />
        ))}
      </div>
    </article>
  )
}

export const tallyOf = (findings: AuditFinding[]): Map<Severity, number> => {
  const m = new Map<Severity, number>()
  for (const f of findings) m.set(f.severity as Severity, (m.get(f.severity as Severity) ?? 0) + 1)
  return m
}

function conceptHrefFor(unit: SecurityAuditUnit): string | null {
  if (unit.formatVersion === 1) return conceptRoute(unit.slug)
  if (unit.conceptSlug) return conceptRoute(unit.conceptSlug)
  return null
}

function RiskSummary({ model }: { model: Extract<DomainAssurance, { domain: 'security' }> }) {
  const { i18n } = useLingui()
  return (
    <div className={SECTION}>
      <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Risk`}</h2>
      <div className="flex flex-wrap">
        <span className={FACT}>
          <span className={FACT_VALUE}>{model.openCount}</span>
          {t(i18n)`open`}
        </span>
        {SEV_ORDER.map((sev) =>
          model.openBySeverity[sev] > 0 ? (
            <span key={sev} className={FACT}>
              <span className={FACT_VALUE}>{model.openBySeverity[sev]}</span>
              {sev}
            </span>
          ) : null,
        )}
        <span className={FACT}>
          <span className={FACT_VALUE}>{model.acceptedRiskCount}</span>
          {t(i18n)`accepted risk`}
        </span>
        <span className={FACT}>
          <span className={FACT_VALUE}>{model.separateDesignCount}</span>
          {t(i18n)`separate design`}
        </span>
      </div>
    </div>
  )
}

function EvidenceFacts({ model }: { model: DomainAssurance }) {
  const { i18n } = useLingui()
  const recent = recentAuditUnits(model)
  const completed = model.unitRows.filter((r) => r.hasLedger).length
  const accepted = recent.length
  const invalidUnits = model.unitRows.filter((r) => r.coverage.state === 'invalid').length
  const latest = recent[0]?.scannedAt ?? null
  const rulesets = [
    ...new Set(
      model.unitRows.map((r) => r.ruleset).filter((r): r is string => typeof r === 'string' && r.length > 0),
    ),
  ]
  return (
    <div className={SECTION}>
      <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Evidence`}</h2>
      <div className="flex flex-wrap">
        <span className={FACT}>
          <span className={FACT_VALUE}>{completed}</span>
          {t(i18n)`completed units`}
        </span>
        <span className={FACT}>
          <span className={FACT_VALUE}>{accepted}</span>
          {t(i18n)`accepted`}
        </span>
        {invalidUnits > 0 && (
          <span className={FACT}>
            <span className={FACT_VALUE}>{invalidUnits}</span>
            {t(i18n)`invalid units`}
          </span>
        )}
        {latest && (
          <span className={FACT}>
            <span className="text-text font-semibold">{latest}</span>
            {t(i18n)`latest scan`}
          </span>
        )}
      </div>
      {rulesets.length > 0 && (
        <p className={META + ' m-0 mt-1'}>
          {t(i18n)`rulesets`}: {rulesets.join(', ')}
        </p>
      )}
    </div>
  )
}

function ActionQueue({
  actions,
  onAction,
}: {
  actions: AuditAction[]
  onAction: (action: AuditAction) => void
}) {
  const { i18n } = useLingui()
  return (
    <div className={SECTION}>
      <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Needs attention`}</h2>
      {actions.length === 0 ? (
        <p className={META + ' m-0'}>{t(i18n)`No open actions in this view`}</p>
      ) : (
        <ul className="list-none p-0 m-0 flex flex-col gap-1">
          {actions.map((action) => (
            <li key={action.id} className="border-b border-border last:border-b-0">
              <button type="button" className={ACTION_BTN} onClick={() => onAction(action)}>
                {action.label}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function RecentAudits({
  model,
  onSelect,
}: {
  model: DomainAssurance
  onSelect: (slug: string) => void
}) {
  const { i18n } = useLingui()
  const recent = recentAuditUnits(model)
  if (recent.length === 0) return null
  return (
    <div className={SECTION}>
      <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Recent accepted audits`}</h2>
      <ul className="list-none p-0 m-0 flex flex-col gap-2">
        {recent.map((row) => (
          <li key={row.slug} className="flex flex-col gap-0.5">
            <button
              type="button"
              className="font-inherit text-[0.85rem] font-semibold text-accent bg-transparent border-none p-0 cursor-pointer text-left hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 rounded-sm w-fit"
              onClick={() => onSelect(row.slug)}
            >
              {row.title}
            </button>
            <span className={META}>
              {row.scannedAt ?? '—'}
              {' · '}
              {row.fileCount} {t(i18n)`files`}
              {row.ruleset ? ` · ${row.ruleset}` : ''}
              {' · '}
              {row.outcomeLabel}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function UnitDetail({
  model,
  unit,
  onBack,
}: {
  model: Extract<DomainAssurance, { domain: 'security' }>
  unit: SecurityAuditUnit
  onBack: () => void
}) {
  const { i18n } = useLingui()
  const [sevFilter, setSevFilter] = useState<ReadonlySet<Severity>>(new Set())
  const [fileQuery, setFileQuery] = useState('')
  const evidence = auditUnitEvidence(model, unit.slug)
  const fileRows = auditFilesForUnit(model, unit.slug)
  const openFindings = unit.findings.filter((f) => f.disposition === 'open')
  const retained = unit.findings.filter((f) => f.disposition !== 'open')
  const filteredOpen = sevFilter.size
    ? openFindings.filter((f) => sevFilter.has(f.severity as Severity))
    : openFindings
  const totals = tallyOf(openFindings)
  const conceptHref = conceptHrefFor(unit)
  const unitRow = model.unitRows.find((r) => r.slug === unit.slug)

  const toggleSev = (s: Severity) =>
    setSevFilter((prev) => {
      const next = new Set(prev)
      next.has(s) ? next.delete(s) : next.add(s)
      return next
    })

  return (
    <div className={PANE}>
      <div className="text-[0.78rem] text-muted flex items-center gap-1.5">
        <ShieldAlert className="w-3.5 h-3.5" aria-hidden /> {t(i18n)`security`}
      </div>
      <div className="flex items-center gap-2 flex-wrap my-1 mb-3">
        <button
          type="button"
          className="font-inherit text-[0.78rem] text-muted bg-transparent border-none p-0 cursor-pointer hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 rounded-sm"
          onClick={onBack}
        >
          {t(i18n)`← overview`}
        </button>
      </div>
      <h1 className="text-[1.25rem] font-[650] m-0 mb-1">
        {conceptHref ? (
          <a
            className="text-accent no-underline hover:underline"
            href={'#' + encodeURI(conceptHref)}
          >
            {unit.title}
          </a>
        ) : (
          unit.title
        )}
      </h1>
      {unit.stale && (
        <p className={META + ' m-0 mb-3 text-[#c4222e]'}>{t(i18n)`stale — re-audit needed`}</p>
      )}
      {unitRow && <p className={META + ' m-0 mb-4'}>{unitRow.outcomeLabel}</p>}

      <section className={SECTION} aria-labelledby="sec-findings">
        <h2 id="sec-findings" className="text-[0.85rem] font-semibold m-0 mb-2">
          {t(i18n)`Findings`}
        </h2>
        <div className="flex items-center gap-1.5 flex-wrap mb-3">
          {visibleFilterOptions(totals.keys(), sevFilter, SEV_ORDER).map((s) => (
            <button
              key={s}
              type="button"
              className={
                CHIP +
                ' cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 ' +
                SEV_STYLE[s] +
                (sevFilter.size && !sevFilter.has(s) ? ' opacity-40' : '')
              }
              onClick={() => toggleSev(s)}
              title={t(i18n)`filter by severity`}
              aria-pressed={auditFilterChipAriaPressed(sevFilter.has(s))}
            >
              {totals.get(s) ?? 0} {s}
            </button>
          ))}
        </div>
        {filteredOpen.map((f) => (
          <FindingCard key={f.id ?? f.title + f.severity} finding={f} />
        ))}
        {filteredOpen.length === 0 && openFindings.length === 0 && (
          <p className={META + ' m-0'}>{t(i18n)`No open findings recorded`}</p>
        )}
        {filteredOpen.length === 0 && openFindings.length > 0 && (
          <p className={META + ' m-0'}>{t(i18n)`no findings match the current filter`}</p>
        )}
        {retained.length > 0 && (
          <div className="mt-4">
            <h3 className="text-[0.78rem] font-semibold m-0 mb-2 text-muted">
              {t(i18n)`Retained risk`}
            </h3>
            {retained.map((f) => (
              <FindingCard key={f.id ?? f.title + f.disposition} finding={f} />
            ))}
          </div>
        )}
      </section>

      <section className={SECTION} aria-labelledby="sec-coverage">
        <h2 id="sec-coverage" className="text-[0.85rem] font-semibold m-0 mb-2">
          {t(i18n)`Coverage`}
        </h2>
        {unitRow && (
          <p className={META + ' m-0 mb-2'}>
            {unitRow.coverage.fresh}/{unitRow.coverage.required} {t(i18n)`fresh`}
            {' · '}
            {unitRow.coverage.label}
          </p>
        )}
        <AuditFileTable rows={fileRows} query={fileQuery} onQueryChange={setFileQuery} />
      </section>

      <section className={SECTION} aria-labelledby="sec-evidence">
        <h2 id="sec-evidence" className="text-[0.85rem] font-semibold m-0 mb-2">
          {t(i18n)`Evidence`}
        </h2>
        {evidence ? (
          <AuditEvidenceSummary row={evidence} />
        ) : (
          <p className={META + ' m-0'}>{t(i18n)`No completed audit evidence`}</p>
        )}
      </section>
    </div>
  )
}

function OverviewHome({
  model,
  mode,
  onSelectUnit,
  onAction,
}: {
  model: Extract<DomainAssurance, { domain: 'security' }>
  mode: AuditViewMode
  onSelectUnit: (slug: string) => void
  onAction: (action: AuditAction) => void
}) {
  const { i18n } = useLingui()
  const actions = attentionActions(model)
  const gaps = gapsModeProjection(model)
  const strong = strongZeroFindingPhrase(model)

  if (mode === 'attention') {
    return (
      <div className={PANE}>
        <div className="text-[0.78rem] text-muted flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5" aria-hidden /> {t(i18n)`security`}
        </div>
        <h1 className="text-[1.25rem] font-[650] my-1 mb-3">{t(i18n)`Needs attention`}</h1>
        <CoverageStatement model={model} />
        {strong && <p className={META + ' m-0 mb-4'}>{strong}</p>}
        <ActionQueue actions={actions} onAction={onAction} />
      </div>
    )
  }

  if (mode === 'gaps') {
    return (
      <div className={PANE}>
        <div className="text-[0.78rem] text-muted flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5" aria-hidden /> {t(i18n)`security`}
        </div>
        <h1 className="text-[1.25rem] font-[650] my-1 mb-3">{t(i18n)`Coverage gaps`}</h1>
        <CoverageStatement model={model} />
        <p className={META + ' m-0 mb-4'}>
          <span className="text-text font-semibold tabular-nums">
            {gaps.numerator}/{gaps.denominator}
          </span>{' '}
          {t(i18n)`fresh`}
          {' · '}
          <span className="text-text font-semibold tabular-nums">{gaps.missing}</span>{' '}
          {t(i18n)`missing`}
        </p>
        <AuditFileTable rows={gaps.rows} />
      </div>
    )
  }

  return (
    <div className={PANE}>
      <div className="text-[0.78rem] text-muted flex items-center gap-1.5">
        <ShieldAlert className="w-3.5 h-3.5" aria-hidden /> {t(i18n)`security`}
      </div>
      <h1 className="text-[1.25rem] font-[650] my-1 mb-3">{t(i18n)`security audit`}</h1>
      <CoverageStatement model={model} />
      {strong && <p className="text-[0.9rem] font-semibold m-0 mb-4">{strong}</p>}
      <CoverageSummary model={model} />
      <RiskSummary model={model} />
      <EvidenceFacts model={model} />
      <ActionQueue actions={actions} onAction={onAction} />
      <AuditUnitPortfolio model={model} onSelect={onSelectUnit} />
      <RecentAudits model={model} onSelect={onSelectUnit} />
    </div>
  )
}

/** Global `#audit:security` home and unit deep-links. Unit route wins over mode. */
export function SecurityPane({
  model,
  audits,
  mode = 'overview',
  focusSlug = null,
  onSelectUnit,
  onMode,
}: {
  model: DomainAssurance
  audits: SecurityAuditUnit[]
  mode?: AuditViewMode
  focusSlug?: string | null
  onSelectUnit?: (slug: string) => void
  onMode?: (mode: AuditViewMode) => void
}) {
  const securityModel = model.domain === 'security' ? model : null
  const auditsBySlug = useMemo(() => new Map(audits.map((u) => [u.slug, u])), [audits])
  const focusedUnit = focusSlug ? auditsBySlug.get(focusSlug) ?? null : null

  if (!securityModel) {
    return null
  }

  const selectUnit = (slug: string) => {
    if (onSelectUnit) {
      onSelectUnit(slug)
      return
    }
    const route = auditUnitRoute('security', slug)
    if (route) location.hash = '#' + encodeURI(route)
  }

  const onAction = (action: AuditAction) => {
    const target = auditActionTarget(action)
    if (target.kind === 'code-jump') {
      window.dispatchEvent(
        new CustomEvent('atlas-code-jump', {
          detail: { path: target.path, line: 1, endLine: 1 },
        }),
      )
      return
    }
    if (target.kind === 'unit') {
      selectUnit(target.unitSlug)
      return
    }
    onMode?.('gaps')
  }

  if (focusSlug) {
    if (focusedUnit) {
      return (
        <UnitDetail
          model={securityModel}
          unit={focusedUnit}
          onBack={() => {
            onMode?.('overview')
            if (onSelectUnit) onSelectUnit('')
            else location.hash = '#' + encodeURI(auditRoute('security'))
          }}
        />
      )
    }
    // Registered unit without a completed ledger — still show coverage/evidence.
    const row = securityModel.unitRows.find((r) => r.slug === focusSlug)
    if (row) {
      return (
        <RegisteredUnitShell
          model={securityModel}
          slug={focusSlug}
          title={row.title}
          onBack={() => {
            onMode?.('overview')
            if (onSelectUnit) onSelectUnit('')
            else location.hash = '#' + encodeURI(auditRoute('security'))
          }}
        />
      )
    }
  }

  return (
    <OverviewHome
      model={securityModel}
      mode={mode}
      onSelectUnit={selectUnit}
      onAction={onAction}
    />
  )
}

function RegisteredUnitShell({
  model,
  slug,
  title,
  onBack,
}: {
  model: Extract<DomainAssurance, { domain: 'security' }>
  slug: string
  title: string
  onBack: () => void
}) {
  const { i18n } = useLingui()
  const [fileQuery, setFileQuery] = useState('')
  const evidence = auditUnitEvidence(model, slug)
  const fileRows = auditFilesForUnit(model, slug)
  const unitRow = model.unitRows.find((r) => r.slug === slug)
  return (
    <div className={PANE}>
      <div className="text-[0.78rem] text-muted flex items-center gap-1.5">
        <ShieldAlert className="w-3.5 h-3.5" aria-hidden /> {t(i18n)`security`}
      </div>
      <button
        type="button"
        className="font-inherit text-[0.78rem] text-muted bg-transparent border-none p-0 cursor-pointer hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 rounded-sm my-1"
        onClick={onBack}
      >
        {t(i18n)`← overview`}
      </button>
      <h1 className="text-[1.25rem] font-[650] m-0 mb-3">{title}</h1>
      {unitRow && <p className={META + ' m-0 mb-4'}>{unitRow.outcomeLabel}</p>}
      <section className={SECTION}>
        <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Findings`}</h2>
        <p className={META + ' m-0'}>{t(i18n)`No completed audit evidence`}</p>
      </section>
      <section className={SECTION}>
        <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Coverage`}</h2>
        <AuditFileTable rows={fileRows} query={fileQuery} onQueryChange={setFileQuery} />
      </section>
      <section className={SECTION}>
        <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Evidence`}</h2>
        {evidence ? (
          <AuditEvidenceSummary row={evidence} />
        ) : (
          <p className={META + ' m-0'}>{t(i18n)`No completed audit evidence`}</p>
        )}
      </section>
    </div>
  )
}

/**
 * Concept-page section: this trust boundary's own posture, compact.
 * No coverage portfolio context — zero findings say "No open findings recorded",
 * never the strong completed-review phrase.
 */
export function ConceptSecuritySection({ unit }: { unit: SecurityAuditUnit }) {
  const { i18n } = useLingui()
  const openFindings = unit.findings.filter((f) => f.disposition === 'open')
  const retained = unit.findings.filter((f) => f.disposition !== 'open')
  return (
    <div className="mt-10 pt-5 border-t border-border">
      <div className="flex items-center gap-2 flex-wrap mb-3">
        <ShieldAlert className="w-4 h-4 text-muted" aria-hidden />
        <h2 className="text-[1rem] font-semibold m-0">{t(i18n)`security audit`}</h2>
        {unit.stale && (
          <span className={CHIP + ' text-[#c4222e] bg-[#c4222e0d] border-[#c4222e30]'}>
            {t(i18n)`stale — re-audit needed`}
          </span>
        )}
        <span className="text-[0.7rem] text-muted">
          {t(i18n)`scanned`} {unit.scannedAt} · {unit.fileCount} {t(i18n)`files`}
        </span>
        <a
          className="text-[0.72rem] text-accent no-underline hover:underline ml-auto focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 rounded-sm"
          href={'#' + encodeURI(auditRoute('security'))}
        >
          {t(i18n)`all units →`}
        </a>
      </div>
      {openFindings.length === 0 ? (
        <div className="text-[0.82rem] text-muted mb-2">
          {unit.stale && retained.length === 0
            ? t(i18n)`stale — re-audit needed`
            : t(i18n)`No open findings recorded`}
        </div>
      ) : (
        openFindings.map((f) => <FindingCard key={f.id ?? f.title} finding={f} />)
      )}
      {retained.map((f) => (
        <FindingCard key={f.id ?? f.title + f.disposition} finding={f} />
      ))}
    </div>
  )
}
