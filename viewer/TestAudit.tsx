import { useMemo, useState } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { FlaskConical } from 'lucide-react'
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
import type {
  TestAuditCategory,
  TestAuditFinding,
  TestAuditImpact,
  TestAuditUnit,
} from '../src/types'
import {
  AuditEvidenceSummary,
  AuditFileTable,
  AuditUnitPortfolio,
  CoverageStatement,
  CoverageSummary,
} from './AuditCoverage'
import { AuditLocation } from './AuditLocation'

/**
 * Tests portfolio — same coverage shell as Security, with Tests impact/category/
 * invariant/evidence/fix vocabulary. Never reuses Security severity words or
 * a generic Security finding card.
 */

const IMPACT_ORDER = ['blocking', 'warning', 'advisory'] as const
type Impact = (typeof IMPACT_ORDER)[number]

const IMPACT_STYLE: Record<Impact, string> = {
  blocking: 'text-[#c4222e] bg-[#c4222e14] border-[#c4222e40]',
  warning: 'text-[#b8790a] bg-[#d9930d14] border-[#d9930d40]',
  advisory: 'text-muted bg-panel border-border',
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

function ImpactBadge({ impact }: { impact: Impact }) {
  return <span className={CHIP + ' ' + IMPACT_STYLE[impact]}>{impact}</span>
}

function TestFindingCard({ finding }: { finding: TestAuditFinding }) {
  const { i18n } = useLingui()
  return (
    <article className="border border-border rounded-lg py-2.5 px-3 mb-2 bg-panel">
      <div className="flex items-center gap-1.5 flex-wrap">
        <ImpactBadge impact={finding.impact as Impact} />
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
        <b className="text-text font-semibold">{t(i18n)`invariant`}</b> {finding.invariant}
      </div>
      <div className="text-[0.78rem] text-muted mt-1">
        <b className="text-text font-semibold">{t(i18n)`evidence`}</b> {finding.evidence}
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

const tallyImpact = (findings: TestAuditFinding[]): Map<Impact, number> => {
  const m = new Map<Impact, number>()
  for (const f of findings) m.set(f.impact as Impact, (m.get(f.impact as Impact) ?? 0) + 1)
  return m
}

const tallyCategory = (findings: TestAuditFinding[]): Map<string, number> => {
  const m = new Map<string, number>()
  for (const f of findings) m.set(f.category, (m.get(f.category) ?? 0) + 1)
  return m
}

function RiskSummary({ model }: { model: Extract<DomainAssurance, { domain: 'test' }> }) {
  const { i18n } = useLingui()
  return (
    <div className={SECTION}>
      <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Risk`}</h2>
      <div className="flex flex-wrap">
        <span className={FACT}>
          <span className={FACT_VALUE}>{model.openCount}</span>
          {t(i18n)`open`}
        </span>
        {IMPACT_ORDER.map((impact) =>
          model.openByImpact[impact] > 0 ? (
            <span key={impact} className={FACT}>
              <span className={FACT_VALUE}>{model.openByImpact[impact]}</span>
              {impact}
            </span>
          ) : null,
        )}
      </div>
    </div>
  )
}

function EvidenceFacts({ model }: { model: DomainAssurance }) {
  const { i18n } = useLingui()
  const recent = recentAuditUnits(model)
  const completed = model.unitRows.filter((r) => r.hasLedger).length
  const accepted = recent.length
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
  model: Extract<DomainAssurance, { domain: 'test' }>
  unit: TestAuditUnit
  onBack: () => void
}) {
  const { i18n } = useLingui()
  const [impactFilter, setImpactFilter] = useState<ReadonlySet<TestAuditImpact>>(new Set())
  const [categoryFilter, setCategoryFilter] = useState<ReadonlySet<TestAuditCategory>>(new Set())
  const [fileQuery, setFileQuery] = useState('')
  const evidence = auditUnitEvidence(model, unit.slug)
  const fileRows = auditFilesForUnit(model, unit.slug)
  const findings = unit.findings.filter((f) => {
    if (impactFilter.size && !impactFilter.has(f.impact)) return false
    if (categoryFilter.size && !categoryFilter.has(f.category)) return false
    return true
  })
  const impactTotals = tallyImpact(unit.findings)
  const categoryTotals = tallyCategory(unit.findings)
  const unitRow = model.unitRows.find((r) => r.slug === unit.slug)

  const toggleImpact = (s: TestAuditImpact) =>
    setImpactFilter((prev) => {
      const next = new Set(prev)
      next.has(s) ? next.delete(s) : next.add(s)
      return next
    })
  const toggleCategory = (c: TestAuditCategory) =>
    setCategoryFilter((prev) => {
      const next = new Set(prev)
      next.has(c) ? next.delete(c) : next.add(c)
      return next
    })

  return (
    <div className={PANE}>
      <div className="text-[0.78rem] text-muted flex items-center gap-1.5">
        <FlaskConical className="w-3.5 h-3.5" aria-hidden /> {t(i18n)`tests`}
      </div>
      <button
        type="button"
        className="font-inherit text-[0.78rem] text-muted bg-transparent border-none p-0 cursor-pointer hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 rounded-sm my-1"
        onClick={onBack}
      >
        {t(i18n)`← overview`}
      </button>
      <h1 className="text-[1.25rem] font-[650] m-0 mb-1">{unit.title}</h1>
      {unit.stale && (
        <p className={META + ' m-0 mb-3 text-[#c4222e]'}>{t(i18n)`stale — re-audit needed`}</p>
      )}
      {unitRow && <p className={META + ' m-0 mb-4'}>{unitRow.outcomeLabel}</p>}

      <section className={SECTION} aria-labelledby="test-findings">
        <h2 id="test-findings" className="text-[0.85rem] font-semibold m-0 mb-2">
          {t(i18n)`Findings`}
        </h2>
        <div className="flex items-center gap-1.5 flex-wrap mb-3">
          {visibleFilterOptions(impactTotals.keys(), impactFilter, IMPACT_ORDER).map((s) => (
            <button
              key={s}
              type="button"
              className={
                CHIP +
                ' cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 ' +
                IMPACT_STYLE[s] +
                (impactFilter.size && !impactFilter.has(s) ? ' opacity-40' : '')
              }
              onClick={() => toggleImpact(s)}
              title={t(i18n)`filter by impact`}
              aria-pressed={auditFilterChipAriaPressed(impactFilter.has(s))}
            >
              {impactTotals.get(s) ?? 0} {s}
            </button>
          ))}
          {visibleFilterOptions(
            categoryTotals.keys(),
            categoryFilter,
            [...new Set([...categoryTotals.keys(), ...categoryFilter])].sort(),
          ).map((c) => (
            <button
              key={c}
              type="button"
              className={
                CHIP +
                ' cursor-pointer text-muted bg-panel border-border focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30' +
                (categoryFilter.size && !categoryFilter.has(c as TestAuditCategory)
                  ? ' opacity-40'
                  : '')
              }
              onClick={() => toggleCategory(c as TestAuditCategory)}
              title={t(i18n)`filter by category`}
              aria-pressed={auditFilterChipAriaPressed(categoryFilter.has(c as TestAuditCategory))}
            >
              {categoryTotals.get(c) ?? 0} {c}
            </button>
          ))}
        </div>
        {findings.map((f) => (
          <TestFindingCard key={f.title + f.category + f.impact} finding={f} />
        ))}
        {findings.length === 0 && unit.findings.length === 0 && (
          <p className={META + ' m-0'}>{t(i18n)`No open findings recorded`}</p>
        )}
        {findings.length === 0 && unit.findings.length > 0 && (
          <p className={META + ' m-0'}>{t(i18n)`no findings match the current filter`}</p>
        )}
      </section>

      <section className={SECTION} aria-labelledby="test-coverage">
        <h2 id="test-coverage" className="text-[0.85rem] font-semibold m-0 mb-2">
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

      <section className={SECTION} aria-labelledby="test-evidence">
        <h2 id="test-evidence" className="text-[0.85rem] font-semibold m-0 mb-2">
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
  model: Extract<DomainAssurance, { domain: 'test' }>
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
          <FlaskConical className="w-3.5 h-3.5" aria-hidden /> {t(i18n)`tests`}
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
          <FlaskConical className="w-3.5 h-3.5" aria-hidden /> {t(i18n)`tests`}
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
        <FlaskConical className="w-3.5 h-3.5" aria-hidden /> {t(i18n)`tests`}
      </div>
      <h1 className="text-[1.25rem] font-[650] my-1 mb-3">{t(i18n)`test audit`}</h1>
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

function RegisteredUnitShell({
  model,
  slug,
  title,
  onBack,
}: {
  model: Extract<DomainAssurance, { domain: 'test' }>
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
        <FlaskConical className="w-3.5 h-3.5" aria-hidden /> {t(i18n)`tests`}
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

/** Global `#audit:test` home and unit deep-links. Unit route wins over mode. */
export function TestAuditPane({
  model,
  audits,
  mode = 'overview',
  focusSlug = null,
  onSelectUnit,
  onMode,
}: {
  model: DomainAssurance
  audits: TestAuditUnit[]
  mode?: AuditViewMode
  focusSlug?: string | null
  onSelectUnit?: (slug: string) => void
  onMode?: (mode: AuditViewMode) => void
}) {
  const testModel = model.domain === 'test' ? model : null
  const auditsBySlug = useMemo(() => new Map(audits.map((u) => [u.slug, u])), [audits])
  const focusedUnit = focusSlug ? auditsBySlug.get(focusSlug) ?? null : null

  if (!testModel) return null

  const selectUnit = (slug: string) => {
    if (onSelectUnit) {
      onSelectUnit(slug)
      return
    }
    const route = auditUnitRoute('test', slug)
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
          model={testModel}
          unit={focusedUnit}
          onBack={() => {
            onMode?.('overview')
            if (onSelectUnit) onSelectUnit('')
            else location.hash = '#' + encodeURI(auditRoute('test'))
          }}
        />
      )
    }
    const row = testModel.unitRows.find((r) => r.slug === focusSlug)
    if (row) {
      return (
        <RegisteredUnitShell
          model={testModel}
          slug={focusSlug}
          title={row.title}
          onBack={() => {
            onMode?.('overview')
            if (onSelectUnit) onSelectUnit('')
            else location.hash = '#' + encodeURI(auditRoute('test'))
          }}
        />
      )
    }
  }

  return (
    <OverviewHome
      model={testModel}
      mode={mode}
      onSelectUnit={selectUnit}
      onAction={onAction}
    />
  )
}
