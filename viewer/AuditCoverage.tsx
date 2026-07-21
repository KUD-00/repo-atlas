import { useMemo } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import {
  auditUnitRows,
  coverageCountsAvailable,
  type AuditFileRow,
  type AuditUnitEvidence,
  type DomainAssurance,
} from '../src/audit-assurance'
import {
  localizedAcceptanceLabel,
  localizedCoverageLabel,
  localizedCoverageStatement,
  localizedFileStatusLabel,
  localizedRiskLabel,
} from './audit-copy'
import { AuditLocation } from './AuditLocation'

const SECTION =
  'mb-6 pb-5 border-b border-border last:border-b-0 last:pb-0 last:mb-0'
const META = 'text-[0.78rem] text-muted'
const FACT =
  'inline-flex items-baseline gap-1.5 text-[0.78rem] text-muted mr-3 mb-1'
const FACT_VALUE = 'text-text font-semibold tabular-nums'
const TABLE =
  'w-full border-collapse text-[0.8rem] text-left'
const TH =
  'py-1.5 px-2 border-b border-border text-muted font-semibold text-[0.72rem]'
const TD = 'py-1.5 px-2 border-b border-border align-top'
const BTN =
  'font-inherit text-[0.85rem] text-accent bg-transparent border-none p-0 cursor-pointer text-left hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 rounded-sm'
const INPUT =
  'w-full min-w-0 font-inherit text-[0.8rem] py-1 px-2 border border-border rounded-md bg-bg text-text focus:outline-none focus:border-accent focus-visible:ring-2 focus-visible:ring-accent/30'

/**
 * One primary repository-level coverage statement.
 * Receives derived DomainAssurance only — never invents coverage.
 */
export function CoverageStatement({ model }: { model: DomainAssurance }) {
  const { i18n } = useLingui()
  const statement = localizedCoverageStatement(i18n, model)
  return (
    <p
      className="text-[0.95rem] font-semibold m-0 mb-4 leading-snug"
      data-coverage-kind={statement.kind}
    >
      {statement.text}
    </p>
  )
}

/**
 * Separate Coverage facts: required/fresh/gap/excluded/dual counts.
 * Risk and Evidence stay outside this block.
 * Untrusted portfolios never render synthetic numeric denominators.
 */
export function CoverageSummary({ model }: { model: DomainAssurance }) {
  const { i18n } = useLingui()
  const countsAvailable = coverageCountsAvailable(model)
  return (
    <div className={SECTION}>
      <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Coverage`}</h2>
      {countsAvailable ? (
        <div className="flex flex-wrap">
          <span className={FACT}>
            <span className={FACT_VALUE}>{model.required}</span>
            {t(i18n)`required`}
          </span>
          <span className={FACT}>
            <span className={FACT_VALUE}>{model.fresh}</span>
            {t(i18n)`fresh`}
          </span>
          <span className={FACT}>
            <span className={FACT_VALUE}>{model.gapCount}</span>
            {t(i18n)`gaps`}
          </span>
          <span className={FACT}>
            <span className={FACT_VALUE}>{model.missing}</span>
            {t(i18n)`missing`}
          </span>
          {model.stale > 0 && (
            <span className={FACT}>
              <span className={FACT_VALUE}>{model.stale}</span>
              {t(i18n)`stale`}
            </span>
          )}
          {model.invalid > 0 && (
            <span className={FACT}>
              <span className={FACT_VALUE}>{model.invalid}</span>
              {t(i18n)`invalid`}
            </span>
          )}
          <span className={FACT}>
            <span className={FACT_VALUE}>{model.excluded}</span>
            {t(i18n)`excluded`}
          </span>
          {model.dualRequired > 0 && (
            <span className={FACT}>
              <span className={FACT_VALUE}>{model.dualRequired}</span>
              {t(i18n)`dual-domain`}
            </span>
          )}
          {model.unclassified > 0 && (
            <span className={FACT}>
              <span className={FACT_VALUE}>{model.unclassified}</span>
              {t(i18n)`unclassified`}
            </span>
          )}
          {model.conflicted > 0 && (
            <span className={FACT}>
              <span className={FACT_VALUE}>{model.conflicted}</span>
              {t(i18n)`conflicted`}
            </span>
          )}
        </div>
      ) : (
        <p className={META + ' m-0'}>{t(i18n)`Coverage counts unavailable`}</p>
      )}
      {model.diagnostics.length > 0 && (
        <ul className="list-none p-0 m-0 mt-2 flex flex-col gap-1">
          {model.diagnostics.map((d, i) => (
            <li key={`${d.code}-${d.path ?? ''}-${d.slug ?? ''}-${i}`} className={META}>
              <span className="font-semibold text-text">{d.code}</span>
              {': '}
              {d.message}
              {d.path ? ` (${d.path})` : ''}
              {d.slug ? ` [${d.slug}]` : ''}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/**
 * Stable registered unit portfolio — coverage and risk as separate text labels.
 */
export function AuditUnitPortfolio({
  model,
  onSelect,
}: {
  model: DomainAssurance
  onSelect?: (slug: string) => void
}) {
  const { i18n } = useLingui()
  const rows = auditUnitRows(model)
  if (rows.length === 0) {
    return (
      <div className={SECTION}>
        <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Units`}</h2>
        <p className={META + ' m-0'}>{t(i18n)`No completed audit evidence`}</p>
      </div>
    )
  }
  return (
    <div className={SECTION}>
      <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`Units`}</h2>
      <table className={TABLE}>
        <thead>
          <tr>
            <th className={TH} scope="col">{t(i18n)`unit`}</th>
            <th className={TH} scope="col">{t(i18n)`coverage`}</th>
            <th className={TH} scope="col">{t(i18n)`risk`}</th>
            <th className={TH} scope="col">{t(i18n)`evidence`}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.slug}>
              <td className={TD}>
                {onSelect ? (
                  <button type="button" className={BTN} onClick={() => onSelect(row.slug)}>
                    {row.title}
                  </button>
                ) : (
                  <span className="font-semibold">{row.title}</span>
                )}
              </td>
              <td className={TD + ' text-muted'}>{localizedCoverageLabel(i18n, row.coverage)}</td>
              <td className={TD + ' text-muted'}>{localizedRiskLabel(i18n, row.risk)}</td>
              <td className={TD + ' text-muted'}>
                {row.evidenceAccepted
                  ? t(i18n)`accepted`
                  : row.hasLedger
                    ? t(i18n)`recorded`
                    : t(i18n)`none`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/**
 * Flat searchable file/status table for unit coverage drill-down.
 * Receives already-derived rows; optional query filters client-side when
 * rows come from a parent that already applied searchUnitFiles.
 */
export function AuditFileTable({
  rows,
  query = '',
  onQueryChange,
}: {
  rows: AuditFileRow[]
  query?: string
  onQueryChange?: (query: string) => void
}) {
  const { i18n } = useLingui()
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return rows
    return rows.filter((row) => row.path.toLowerCase().includes(q))
  }, [rows, query])

  return (
    <div>
      {onQueryChange !== undefined && (
        <div className="mb-2">
          <input
            type="search"
            className={INPUT}
            placeholder={t(i18n)`filter files…`}
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            aria-label={t(i18n)`filter files`}
          />
        </div>
      )}
      {filtered.length === 0 ? (
        <p className={META + ' m-0'}>
          {rows.length === 0
            ? t(i18n)`No unit file coverage rows`
            : t(i18n)`no files match the current filter`}
        </p>
      ) : (
        <table className={TABLE}>
          <thead>
            <tr>
              <th className={TH} scope="col">{t(i18n)`path`}</th>
              <th className={TH} scope="col">{t(i18n)`status`}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => (
              <tr key={`${row.unitSlug}::${row.path}`}>
                <td className={TD}>
                  <AuditLocation loc={row.path} />
                </td>
                <td className={TD + ' text-muted'}>
                  {localizedFileStatusLabel(i18n, row.status)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

/**
 * Exact unit evidence: ruleset, scan time, scope hash, rounds, refs, acceptance.
 * Call sites pass AuditUnitEvidence only — no row-union casting.
 */
export function AuditEvidenceSummary({ row }: { row: AuditUnitEvidence }) {
  const { i18n } = useLingui()

  if (!row.hasLedger) {
    return <p className={META + ' m-0'}>{t(i18n)`No completed audit evidence`}</p>
  }

  return (
    <dl className="m-0 grid gap-1.5 text-[0.78rem]">
      <div className="flex flex-wrap gap-x-2">
        <dt className="text-muted font-semibold m-0">{t(i18n)`ruleset`}</dt>
        <dd className="m-0 text-text">{row.ruleset ?? '—'}</dd>
      </div>
      <div className="flex flex-wrap gap-x-2">
        <dt className="text-muted font-semibold m-0">{t(i18n)`scanned`}</dt>
        <dd className="m-0 text-text">{row.scannedAt ?? '—'}</dd>
      </div>
      <div className="flex flex-wrap gap-x-2">
        <dt className="text-muted font-semibold m-0">{t(i18n)`scope hash`}</dt>
        <dd className="m-0 text-text font-mono text-[0.72rem] break-all">
          {row.scopeHash ?? '—'}
        </dd>
      </div>
      <div className="flex flex-wrap gap-x-2">
        <dt className="text-muted font-semibold m-0">{t(i18n)`rounds`}</dt>
        <dd className="m-0 text-text tabular-nums">
          {row.roundCount === null ? '—' : row.roundCount}
        </dd>
      </div>
      <div className="flex flex-wrap gap-x-2">
        <dt className="text-muted font-semibold m-0">{t(i18n)`acceptance`}</dt>
        <dd className="m-0 text-text">{localizedAcceptanceLabel(i18n, row)}</dd>
      </div>
      <div>
        <dt className="text-muted font-semibold m-0 mb-1">{t(i18n)`evidence refs`}</dt>
        <dd className="m-0">
          {row.evidenceRefs.length === 0 ? (
            <span className="text-muted">—</span>
          ) : (
            <ul className="list-none p-0 m-0 flex flex-col gap-1">
              {row.evidenceRefs.map((ref) => (
                <li key={ref}>
                  <AuditLocation loc={ref} />
                </li>
              ))}
            </ul>
          )}
        </dd>
      </div>
    </dl>
  )
}
