import { useMemo, useState } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { FlaskConical, ShieldCheck } from 'lucide-react'
import { auditUnitsForRoute, isCleanAuditUnit } from '../src/audit-routes'
import type { TestAuditCategory, TestAuditFinding, TestAuditImpact, TestAuditUnit } from '../src/types'
import { AuditLocation } from './AuditLocation'
import type { AppLocale } from './i18n'

const IMPACT_ORDER = ['blocking', 'warning', 'advisory'] as const
type Impact = (typeof IMPACT_ORDER)[number]

const IMPACT_STYLE: Record<Impact, string> = {
  blocking: 'text-[#c4222e] bg-[#c4222e14] border-[#c4222e40]',
  warning: 'text-[#b8790a] bg-[#d9930d14] border-[#d9930d40]',
  advisory: 'text-muted bg-panel border-border',
}

const CHIP =
  'inline-flex items-center gap-1 text-[0.68rem] font-semibold py-px px-[7px] rounded-md border whitespace-nowrap'

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

function UnitSection({
  unit,
  impactFilter,
  categoryFilter,
  locale,
}: {
  unit: TestAuditUnit
  impactFilter: ReadonlySet<TestAuditImpact>
  categoryFilter: ReadonlySet<TestAuditCategory>
  locale: AppLocale
}) {
  const { i18n } = useLingui()
  const [open, setOpen] = useState(true)
  const findings = unit.findings.filter((f) => {
    if (impactFilter.size && !impactFilter.has(f.impact)) return false
    if (categoryFilter.size && !categoryFilter.has(f.category)) return false
    return true
  })
  const impactTally = tallyImpact(unit.findings)
  const clean = isCleanAuditUnit(unit)
  return (
    <section className="mb-4">
      <div
        className="flex items-center gap-2 flex-wrap cursor-pointer select-none py-1"
        onClick={() => setOpen(!open)}
      >
        <span
          className={
            'text-muted text-[0.7rem] inline-block transition-transform duration-150' +
            (open ? ' rotate-90' : '')
          }
        >
          ▶
        </span>
        <span className="text-[0.92rem] font-semibold">{unit.title}</span>
        {unit.stale && (
          <span className={CHIP + ' text-[#c4222e] bg-[#c4222e0d] border-[#c4222e30]'}>
            {t(i18n)`stale — re-audit needed`}
          </span>
        )}
        {IMPACT_ORDER.filter((s) => impactTally.has(s)).map((s) => (
          <span key={s} className={CHIP + ' ' + IMPACT_STYLE[s]}>
            {impactTally.get(s)} {s}
          </span>
        ))}
        {clean && (
          <span className="inline-flex items-center gap-1 text-[0.72rem] text-[#3d6b54]">
            <ShieldCheck className="w-3.5 h-3.5" /> {t(i18n)`clean`}
          </span>
        )}
        <span className="text-[0.7rem] text-muted">
          {t(i18n)`scanned`} {unit.scannedAt} · {unit.fileCount} {t(i18n)`files`} · {unit.ruleset}
          {unit.droppedCount > 0 ? ` · ${unit.droppedCount} ${t(i18n)`dropped by factcheck`}` : ''}
        </span>
      </div>
      {open && (
        <div className="mt-1.5 ml-4">
          {findings.map((f) => (
            <TestFindingCard key={f.title + f.category} finding={f} />
          ))}
          {findings.length === 0 && unit.findings.length > 0 && (
            <div className="text-[0.78rem] text-muted py-1">
              {t(i18n)`no findings match the current filter`}
            </div>
          )}
        </div>
      )}
      <span className="hidden">{locale}</span>
    </section>
  )
}

/** Global `#audit:test` home and unit deep-links. */
export function TestAuditPane({
  audits,
  focusSlug = null,
}: {
  audits: TestAuditUnit[]
  focusSlug?: string | null
}) {
  const { i18n } = useLingui()
  const [impactFilter, setImpactFilter] = useState<ReadonlySet<TestAuditImpact>>(new Set())
  const [categoryFilter, setCategoryFilter] = useState<ReadonlySet<TestAuditCategory>>(new Set())
  const [onlyStale, setOnlyStale] = useState(false)

  const focused = useMemo(() => auditUnitsForRoute(audits, focusSlug ?? null), [audits, focusSlug])
  const totals = useMemo(() => tallyImpact(focused.flatMap((u) => u.findings)), [focused])
  const categoryTotals = useMemo(
    () => tallyCategory(focused.flatMap((u) => u.findings)),
    [focused],
  )
  const staleCount = focused.filter((u) => u.stale).length

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

  const units = onlyStale ? focused.filter((u) => u.stale) : focused

  return (
    <div className="max-w-[860px] py-9 px-12 pb-24 max-md:py-5 max-md:px-4 max-md:pb-16">
      <div className="text-[0.78rem] text-muted flex items-center gap-1.5">
        <FlaskConical className="w-3.5 h-3.5" /> {t(i18n)`tests`}
      </div>
      <h1 className="text-[1.25rem] font-[650] my-1 mb-3">{t(i18n)`test audit`}</h1>
      <div className="flex items-center gap-1.5 flex-wrap mb-1.5">
        {IMPACT_ORDER.filter((s) => totals.has(s)).map((s) => (
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
          >
            {totals.get(s)} {s}
          </button>
        ))}
        {[...categoryTotals.keys()].sort().map((c) => (
          <button
            key={c}
            type="button"
            className={
              CHIP +
              ' cursor-pointer text-muted bg-panel border-border focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30' +
              (categoryFilter.size && !categoryFilter.has(c as TestAuditCategory) ? ' opacity-40' : '')
            }
            onClick={() => toggleCategory(c as TestAuditCategory)}
            title={t(i18n)`filter by category`}
          >
            {categoryTotals.get(c)} {c}
          </button>
        ))}
        {staleCount > 0 && (
          <button
            type="button"
            className={
              CHIP +
              ' cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 ' +
              (onlyStale
                ? 'text-[#c4222e] bg-[#c4222e14] border-[#c4222e40]'
                : 'text-muted bg-panel border-border')
            }
            onClick={() => setOnlyStale(!onlyStale)}
          >
            {staleCount} {t(i18n)`stale`}
          </button>
        )}
      </div>
      <div className="text-[0.72rem] text-muted mb-5">
        {focused.length} {t(i18n)`audited units`}
        {impactFilter.size > 0 || categoryFilter.size > 0 ? ` · ${t(i18n)`filtered`}` : ''}
      </div>
      {units.map((u) => (
        <UnitSection
          key={u.slug}
          unit={u}
          impactFilter={impactFilter}
          categoryFilter={categoryFilter}
          locale={i18n.locale as AppLocale}
        />
      ))}
      {audits.length === 0 && (
        <div className="text-[0.85rem] text-muted">{t(i18n)`No completed audits yet`}</div>
      )}
      {audits.length > 0 && units.length === 0 && (
        <div className="text-[0.85rem] text-muted">{t(i18n)`no findings match the current filter`}</div>
      )}
    </div>
  )
}
