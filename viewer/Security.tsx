import { useMemo, useState } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { ShieldAlert, ShieldCheck } from 'lucide-react'
import { auditRoute, auditUnitsForRoute, isCleanAuditUnit } from '../src/audit-routes'
import type { AuditFinding, SecurityAuditUnit } from '../src/types'
import { AuditLocation } from './AuditLocation'
import { conceptRoute } from './Concept'
import type { AppLocale } from './i18n'

/**
 * Security view — the interactive face of `.atlas/audits/` (verdict archives
 * produced by qa/audit.ts). Two surfaces share FindingCard: the global
 * `#audit:security` home (portfolio: all units, severity filters) and the section
 * embedded in concept pages (this boundary's posture). Locations use AuditLocation
 * so a finding's evidence opens in the code panel.
 * Print/PDF stays with the artifacts projection — this view is for browsing.
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

const CHIP = 'inline-flex items-center gap-1 text-[0.68rem] font-semibold py-px px-[7px] rounded-md border whitespace-nowrap'

function SevBadge({ sev }: { sev: Severity }) {
  return <span className={CHIP + ' ' + SEV_STYLE[sev]}>{sev}</span>
}

export function FindingCard({ finding }: { finding: AuditFinding }) {
  const { i18n } = useLingui()
  return (
    <article className="border border-border rounded-lg py-2.5 px-3 mb-2 bg-panel">
      <div className="flex items-center gap-1.5 flex-wrap">
        <SevBadge sev={finding.severity as Severity} />
        <span className={CHIP + ' text-muted bg-panel border-border'}>{finding.category}</span>
        {finding.confidence === 'unverified' && (
          <span className={CHIP + ' text-[#b8790a] bg-[#d9930d14] border-[#d9930d40]'} title={t(i18n)`the factcheck gate could not confirm this from source`}>
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

function UnitSection({
  unit, sevFilter, locale,
}: {
  unit: SecurityAuditUnit
  sevFilter: ReadonlySet<Severity>
  locale: AppLocale
}) {
  const { i18n } = useLingui()
  const [open, setOpen] = useState(true)
  const findings = sevFilter.size ? unit.findings.filter((f) => sevFilter.has(f.severity as Severity)) : unit.findings
  const tally = tallyOf(unit.findings)
  const clean = isCleanAuditUnit(unit)
  const conceptHref = conceptHrefFor(unit)
  return (
    <section className="mb-4">
      <div
        className="flex items-center gap-2 flex-wrap cursor-pointer select-none py-1"
        onClick={() => setOpen(!open)}
      >
        <span className={'text-muted text-[0.7rem] inline-block transition-transform duration-150' + (open ? ' rotate-90' : '')}>▶</span>
        {conceptHref ? (
          <a
            className="text-[0.92rem] font-semibold text-accent no-underline hover:underline"
            href={'#' + encodeURI(conceptHref)}
            onClick={(e) => e.stopPropagation()}
          >
            {unit.title}
          </a>
        ) : (
          <span className="text-[0.92rem] font-semibold">{unit.title}</span>
        )}
        {unit.stale && (
          <span className={CHIP + ' text-[#c4222e] bg-[#c4222e0d] border-[#c4222e30]'}>
            {t(i18n)`stale — re-audit needed`}
          </span>
        )}
        {SEV_ORDER.filter((s) => tally.has(s)).map((s) => (
          <span key={s} className={CHIP + ' ' + SEV_STYLE[s]}>
            {tally.get(s)} {s}
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
            <FindingCard key={f.title} finding={f} />
          ))}
          {findings.length === 0 && unit.findings.length > 0 && (
            <div className="text-[0.78rem] text-muted py-1">{t(i18n)`no findings match the current filter`}</div>
          )}
        </div>
      )}
      <span className="hidden">{locale}</span>
    </section>
  )
}

/** Global `#audit:security` home: the repo's security posture as a portfolio. */
export function SecurityPane({
  audits,
  focusSlug = null,
}: {
  audits: SecurityAuditUnit[]
  focusSlug?: string | null
}) {
  const { i18n } = useLingui()
  const [sevFilter, setSevFilter] = useState<ReadonlySet<Severity>>(new Set())
  const [onlyStale, setOnlyStale] = useState(false)
  const focused = useMemo(() => auditUnitsForRoute(audits, focusSlug ?? null), [audits, focusSlug])
  const totals = useMemo(() => tallyOf(focused.flatMap((u) => u.findings)), [focused])
  const staleCount = focused.filter((u) => u.stale).length
  const toggleSev = (s: Severity) =>
    setSevFilter((prev) => {
      const next = new Set(prev)
      next.has(s) ? next.delete(s) : next.add(s)
      return next
    })
  const units = onlyStale ? focused.filter((u) => u.stale) : focused
  return (
    <div className="max-w-[860px] py-9 px-12 pb-24 max-md:py-5 max-md:px-4 max-md:pb-16">
      <div className="text-[0.78rem] text-muted flex items-center gap-1.5">
        <ShieldAlert className="w-3.5 h-3.5" /> {t(i18n)`security`}
      </div>
      <h1 className="text-[1.25rem] font-[650] my-1 mb-3">{t(i18n)`security audit`}</h1>
      <div className="flex items-center gap-1.5 flex-wrap mb-1.5">
        {SEV_ORDER.filter((s) => totals.has(s)).map((s) => (
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
          >
            {totals.get(s)} {s}
          </button>
        ))}
        {staleCount > 0 && (
          <button
            type="button"
            className={
              CHIP +
              ' cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 ' +
              (onlyStale ? 'text-[#c4222e] bg-[#c4222e14] border-[#c4222e40]' : 'text-muted bg-panel border-border')
            }
            onClick={() => setOnlyStale(!onlyStale)}
          >
            {staleCount} {t(i18n)`stale`}
          </button>
        )}
      </div>
      <div className="text-[0.72rem] text-muted mb-5">
        {focused.length} {t(i18n)`audited units`}
        {sevFilter.size > 0 ? ` · ${t(i18n)`filtered`}` : ''}
      </div>
      {units.map((u) => (
        <UnitSection key={u.slug} unit={u} sevFilter={sevFilter} locale={i18n.locale as AppLocale} />
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

/** Concept-page section: this trust boundary's own posture, compact. */
export function ConceptSecuritySection({ unit }: { unit: SecurityAuditUnit }) {
  const { i18n } = useLingui()
  const clean = isCleanAuditUnit(unit)
  return (
    <div className="mt-10 pt-5 border-t border-border">
      <div className="flex items-center gap-2 flex-wrap mb-3">
        <ShieldAlert className="w-4 h-4 text-muted" />
        <h2 className="text-[1rem] font-semibold m-0">{t(i18n)`security audit`}</h2>
        {unit.stale && (
          <span className={CHIP + ' text-[#c4222e] bg-[#c4222e0d] border-[#c4222e30]'}>
            {t(i18n)`stale — re-audit needed`}
          </span>
        )}
        <span className="text-[0.7rem] text-muted">
          {t(i18n)`scanned`} {unit.scannedAt} · {unit.fileCount} {t(i18n)`files`}
        </span>
        <a className="text-[0.72rem] text-accent no-underline hover:underline ml-auto" href={'#' + encodeURI(auditRoute('security'))}>
          {t(i18n)`all units →`}
        </a>
      </div>
      {clean ? (
        <div className="flex items-center gap-1.5 text-[0.82rem] text-[#3d6b54]">
          <ShieldCheck className="w-4 h-4" /> {t(i18n)`no findings — clean`}
        </div>
      ) : unit.findings.length === 0 ? (
        <div className="text-[0.82rem] text-muted">
          {unit.stale ? t(i18n)`stale — re-audit needed` : t(i18n)`no findings`}
        </div>
      ) : (
        unit.findings.map((f) => <FindingCard key={f.title} finding={f} />)
      )}
    </div>
  )
}
