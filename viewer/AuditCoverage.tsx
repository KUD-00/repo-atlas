import { type ReactNode } from 'react'
import type { I18n } from '@lingui/core'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import {
  auditUnitRows,
  coverageCountsAvailable,
  type AuditFileRow,
  type AuditUnitEvidence,
  type AuditV3ExactState,
  type AuditV3FindingPresentation,
  type AuditV3FindingStatus,
  type AuditV3Lifecycle,
  type AuditV3PortfolioPresentation,
  type AuditV3ProducerPresentation,
  type AuditV3SemanticState,
  type AuditV3UnitPresentation,
  type DomainAssurance,
} from '../src/audit-assurance'
import type { AuditConfidence } from '../src/audit-v3-types'
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
  const q = query.trim().toLowerCase()
  const filtered = !q
    ? rows
    : rows.filter((row) => row.path.toLowerCase().includes(q))

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

// ---------------------------------------------------------------------------
// V3 assurance presentation — renders the derived AuditV3PortfolioPresentation
// only. No coverage or lifecycle is invented here; labels come from typed
// model fields via compile-time msgids.
// ---------------------------------------------------------------------------

const V3_CHIP =
  'inline-flex items-center gap-1 text-[0.68rem] font-semibold py-px px-[7px] rounded-md border whitespace-nowrap'
const V3_TONE = {
  good: 'text-[#3d6b54] bg-[#3d6b540d] border-[#3d6b5430]',
  warn: 'text-[#b8790a] bg-[#d9930d14] border-[#d9930d40]',
  bad: 'text-[#c4222e] bg-[#c4222e0d] border-[#c4222e30]',
  muted: 'text-muted bg-panel border-border',
} as const
type V3Tone = keyof typeof V3_TONE

export function V3StateChip({ tone, children }: { tone: V3Tone; children: ReactNode }) {
  return <span className={V3_CHIP + ' ' + V3_TONE[tone]}>{children}</span>
}

export function localizedV3ExactStateLabel(i18n: I18n, state: AuditV3ExactState): string {
  switch (state) {
    case 'complete':
      return t(i18n)`exact complete`
    case 'incomplete':
      return t(i18n)`exact incomplete`
    case 'invalid':
      return t(i18n)`exact invalid`
    case 'unknown':
      return t(i18n)`exact unknown`
  }
}

export function localizedV3SemanticStateLabel(i18n: I18n, state: AuditV3SemanticState): string {
  switch (state) {
    case 'covered':
      return t(i18n)`semantic covered`
    case 'gap':
      return t(i18n)`semantic gap`
    case 'unknown':
      return t(i18n)`semantic unknown`
  }
}

export function localizedV3FindingStatusLabel(i18n: I18n, status: AuditV3FindingStatus): string {
  switch (status) {
    case 'open':
      return t(i18n)`open`
    case 'accepted':
      return t(i18n)`accepted`
    case 'expired':
      return t(i18n)`expired`
    case 'reopened':
      return t(i18n)`reopened`
    case 'remediated':
      return t(i18n)`remediated`
    case 'false-positive':
      return t(i18n)`false positive`
    case 'superseded':
      return t(i18n)`superseded`
    case 'separate-design':
      return t(i18n)`separate design`
    case 'unknown':
      return t(i18n)`unknown`
  }
}

export function localizedV3LifecycleLabel(i18n: I18n, lifecycle: AuditV3Lifecycle): string {
  switch (lifecycle) {
    case 'new':
      return t(i18n)`lifecycle new`
    case 'persisting':
      return t(i18n)`lifecycle persisting`
    case 'resolved':
      return t(i18n)`lifecycle resolved`
    case 'reopened':
      return t(i18n)`lifecycle reopened`
    case 'unknown':
      return t(i18n)`lifecycle unknown`
  }
}

export function localizedV3ProducerKindLabel(
  i18n: I18n,
  kind: AuditV3ProducerPresentation['kind'],
): string {
  switch (kind) {
    case 'grok-cli':
      return t(i18n)`Grok CLI`
    case 'codex-security':
      return t(i18n)`Codex Security`
    case 'migration':
      return t(i18n)`migration`
    case 'manual':
      return t(i18n)`manual`
  }
}

/** Absent confidence is "not supplied" — never presented as low confidence. */
export function localizedV3ConfidenceLabel(
  i18n: I18n,
  confidence: AuditConfidence | null,
): string {
  return confidence ?? t(i18n)`not supplied`
}

export function v3ExactStateTone(state: AuditV3ExactState): V3Tone {
  switch (state) {
    case 'complete':
      return 'good'
    case 'incomplete':
      return 'warn'
    case 'invalid':
      return 'bad'
    case 'unknown':
      return 'warn'
  }
}

export function v3SemanticStateTone(state: AuditV3SemanticState): V3Tone {
  switch (state) {
    case 'covered':
      return 'good'
    case 'gap':
      return 'warn'
    case 'unknown':
      return 'warn'
  }
}

export function v3FindingStatusTone(status: AuditV3FindingStatus): V3Tone {
  switch (status) {
    case 'open':
    case 'reopened':
    case 'expired':
      return 'bad'
    case 'accepted':
    case 'unknown':
      return 'warn'
    case 'remediated':
    case 'false-positive':
    case 'superseded':
    case 'separate-design':
      return 'muted'
  }
}

const V3_STATUS_ORDER: readonly AuditV3FindingStatus[] = [
  'open',
  'reopened',
  'expired',
  'accepted',
  'remediated',
  'false-positive',
  'superseded',
  'separate-design',
  'unknown',
]

/** Compact "1 open · 2 accepted" status roll-up from typed counts. */
export function localizedV3StatusSummary(
  i18n: I18n,
  counts: AuditV3UnitPresentation['countsByStatus'],
): string {
  const parts: string[] = []
  for (const status of V3_STATUS_ORDER) {
    const count = counts[status]
    if (count > 0) parts.push(`${count} ${localizedV3FindingStatusLabel(i18n, status)}`)
  }
  return parts.join(' · ')
}

/**
 * Exact coverage panel from the observation's own receipts — distinct from
 * semantic coverage and from the portfolio coverage pipeline. Stale exact
 * bytes and unknown availability stay visually prominent.
 */
export function AuditV3ExactPanel({ unit }: { unit: AuditV3UnitPresentation }) {
  const { i18n } = useLingui()
  const exact = unit.exact
  return (
    <section className={SECTION} aria-labelledby="sec-v3-exact">
      <h2 id="sec-v3-exact" className="text-[0.85rem] font-semibold m-0 mb-2">
        {t(i18n)`Exact coverage`}
      </h2>
      <div className="flex items-center gap-1.5 flex-wrap mb-2">
        <V3StateChip tone={v3ExactStateTone(exact.state)}>
          {localizedV3ExactStateLabel(i18n, exact.state)}
        </V3StateChip>
      </div>
      {unit.staleExactBytes && (
        <p className={META + ' m-0 mb-2 text-[#c4222e]'}>
          {t(i18n)`stale exact bytes — re-audit needed`}
        </p>
      )}
      <div className="flex flex-wrap">
        {exact.reviewedFileCount !== null && exact.fileCount !== null && (
          <span className={FACT}>
            <span className={FACT_VALUE}>
              {t(i18n)`${exact.reviewedFileCount} of ${exact.fileCount} files reviewed`}
            </span>
          </span>
        )}
        {exact.unreviewedCount > 0 && (
          <span className={FACT}>
            <span className={FACT_VALUE}>
              {t(i18n)`${exact.unreviewedCount} unreviewed`}
            </span>
          </span>
        )}
        {exact.state === 'unknown' && (
          <span className={META}>{t(i18n)`exact review coverage unavailable`}</span>
        )}
      </div>
    </section>
  )
}

/**
 * Semantic (threat-surface) coverage panel. Migrated evidence keeps its
 * unknown semantic state and its migration producer chip — it is never
 * presented as covered or as Codex-equivalent.
 */
export function AuditV3SemanticPanel({ unit }: { unit: AuditV3UnitPresentation }) {
  const { i18n } = useLingui()
  const semantic = unit.semantic
  return (
    <section className={SECTION} aria-labelledby="sec-v3-semantic">
      <h2 id="sec-v3-semantic" className="text-[0.85rem] font-semibold m-0 mb-2">
        {t(i18n)`Semantic coverage`}
      </h2>
      <div className="flex items-center gap-1.5 flex-wrap mb-2">
        <V3StateChip tone={v3SemanticStateTone(semantic.state)}>
          {localizedV3SemanticStateLabel(i18n, semantic.state)}
        </V3StateChip>
        {semantic.migrated && (
          <V3StateChip tone="muted">{t(i18n)`migration`}</V3StateChip>
        )}
      </div>
      <div className="flex flex-wrap">
        <span className={FACT}>
          <span className={FACT_VALUE}>{t(i18n)`${semantic.surfaces.total} surfaces`}</span>
        </span>
        {semantic.surfaces.needsFollowUp > 0 && (
          <span className={FACT}>
            <span className={FACT_VALUE}>
              {t(i18n)`${semantic.surfaces.needsFollowUp} need follow-up`}
            </span>
          </span>
        )}
        {semantic.deferredCount > 0 && (
          <span className={FACT}>
            <span className={FACT_VALUE}>{t(i18n)`${semantic.deferredCount} deferred`}</span>
          </span>
        )}
      </div>
    </section>
  )
}

/**
 * Producer integrity: which producer, adapter, run, ruleset/prompt, and
 * transcript proof created this observation.
 */
export function AuditV3ProducerPanel({ producer }: { producer: AuditV3ProducerPresentation }) {
  const { i18n } = useLingui()
  return (
    <section className={SECTION} aria-labelledby="sec-v3-producer">
      <h2 id="sec-v3-producer" className="text-[0.85rem] font-semibold m-0 mb-2">
        {t(i18n)`Producer`}
      </h2>
      <dl className="m-0 grid gap-1.5 text-[0.78rem]">
        <div className="flex flex-wrap gap-x-2">
          <dt className="text-muted font-semibold m-0">{t(i18n)`producer`}</dt>
          <dd className="m-0 text-text">
            {localizedV3ProducerKindLabel(i18n, producer.kind)} · {producer.name} {producer.version}
          </dd>
        </div>
        <div className="flex flex-wrap gap-x-2">
          <dt className="text-muted font-semibold m-0">{t(i18n)`adapter`}</dt>
          <dd className="m-0 text-text">
            {producer.adapter} {producer.adapterVersion}
          </dd>
        </div>
        <div className="flex flex-wrap gap-x-2">
          <dt className="text-muted font-semibold m-0">{t(i18n)`run`}</dt>
          <dd className="m-0 text-text font-mono text-[0.72rem] break-all">{producer.runId}</dd>
        </div>
        <div className="flex flex-wrap gap-x-2">
          <dt className="text-muted font-semibold m-0">{t(i18n)`ruleset`}</dt>
          <dd className="m-0 text-text">{producer.ruleset ? producer.ruleset.id : '—'}</dd>
        </div>
        <div className="flex flex-wrap gap-x-2">
          <dt className="text-muted font-semibold m-0">{t(i18n)`prompt`}</dt>
          <dd className="m-0 text-text font-mono text-[0.72rem] break-all">
            {producer.prompt ? producer.prompt.digest : '—'}
          </dd>
        </div>
        <div className="flex flex-wrap gap-x-2">
          <dt className="text-muted font-semibold m-0">{t(i18n)`transcript digest`}</dt>
          <dd className="m-0 text-text font-mono text-[0.72rem] break-all">
            {producer.transcriptDigest ?? '—'}
          </dd>
        </div>
        {producer.sourceContract && (
          <div className="flex flex-wrap gap-x-2">
            <dt className="text-muted font-semibold m-0">{t(i18n)`source contract`}</dt>
            <dd className="m-0 text-text">
              {producer.sourceContract.namespace} · {producer.sourceContract.sealedAt}
            </dd>
          </div>
        )}
      </dl>
    </section>
  )
}

/** Current observation versus history; a history-ahead chain stays prominent. */
export function AuditV3HistorySection({ unit }: { unit: AuditV3UnitPresentation }) {
  const { i18n } = useLingui()
  return (
    <section className={SECTION} aria-labelledby="sec-v3-history">
      <h2 id="sec-v3-history" className="text-[0.85rem] font-semibold m-0 mb-2">
        {t(i18n)`Observation history`}
      </h2>
      {unit.historyAhead && (
        <p className={META + ' m-0 mb-2'}>
          <V3StateChip tone="warn">{t(i18n)`history ahead`}</V3StateChip>
        </p>
      )}
      {unit.history.length === 0 ? (
        <p className={META + ' m-0'}>—</p>
      ) : (
        <table className={TABLE}>
          <thead>
            <tr>
              <th className={TH} scope="col">{t(i18n)`observation`}</th>
              <th className={TH} scope="col">{t(i18n)`findings`}</th>
              <th className={TH} scope="col">{t(i18n)`state`}</th>
            </tr>
          </thead>
          <tbody>
            {[...unit.history].reverse().map((entry) => (
              <tr key={entry.observationId}>
                <td className={TD}>
                  <span className="font-mono text-[0.72rem] break-all">{entry.observationId}</span>
                  <span className="text-muted"> · {entry.observedAt}</span>
                </td>
                <td className={TD + ' text-muted'}>
                  {t(i18n)`${entry.findingCount} findings`}
                </td>
                <td className={TD}>
                  {entry.publicationState === 'current' ? (
                    <V3StateChip tone="good">{t(i18n)`current observation`}</V3StateChip>
                  ) : entry.publicationState === 'history-ahead' ? (
                    <V3StateChip tone="warn">{t(i18n)`history ahead`}</V3StateChip>
                  ) : (
                    <V3StateChip tone="muted">{t(i18n)`historical`}</V3StateChip>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

/**
 * V3 portfolio table: per-unit exact/semantic states, producer kind, and the
 * lifecycle-aware finding status roll-up. Diagnostics and an unavailable
 * decision state stay visually prominent.
 */
export function AuditV3PortfolioSection({
  model,
  onSelect,
}: {
  model: AuditV3PortfolioPresentation
  onSelect?: (slug: string) => void
}) {
  const { i18n } = useLingui()
  return (
    <div className={SECTION}>
      <h2 className="text-[0.85rem] font-semibold m-0 mb-2">{t(i18n)`V3 observations`}</h2>
      {!model.decisionStateAvailable && (
        <p className={META + ' m-0 mb-2'}>
          <V3StateChip tone="warn">
            {t(i18n)`decision state unavailable — finding statuses shown as unknown`}
          </V3StateChip>
        </p>
      )}
      {model.diagnostics.length > 0 && (
        <ul className="list-none p-0 m-0 mb-2 flex flex-col gap-1">
          {model.diagnostics.map((d, i) => (
            <li key={`${d.code}-${d.path}-${i}`} className={META}>
              <span className="font-semibold text-text">{d.code}</span>
              {': '}
              {d.message}
              {d.path ? ` (${d.path})` : ''}
            </li>
          ))}
        </ul>
      )}
      <table className={TABLE}>
        <thead>
          <tr>
            <th className={TH} scope="col">{t(i18n)`unit`}</th>
            <th className={TH} scope="col">{t(i18n)`exact`}</th>
            <th className={TH} scope="col">{t(i18n)`semantic`}</th>
            <th className={TH} scope="col">{t(i18n)`producer`}</th>
            <th className={TH} scope="col">{t(i18n)`findings`}</th>
          </tr>
        </thead>
        <tbody>
          {model.units.map((unit) => (
            <tr key={unit.slug}>
              <td className={TD}>
                {onSelect && unit.current !== null ? (
                  <button type="button" className={BTN} onClick={() => onSelect(unit.slug)}>
                    {unit.title}
                  </button>
                ) : (
                  <span className="font-semibold">{unit.title}</span>
                )}
              </td>
              <td className={TD}>
                <V3StateChip tone={v3ExactStateTone(unit.exact.state)}>
                  {localizedV3ExactStateLabel(i18n, unit.exact.state)}
                </V3StateChip>
              </td>
              <td className={TD}>
                <V3StateChip tone={v3SemanticStateTone(unit.semantic.state)}>
                  {localizedV3SemanticStateLabel(i18n, unit.semantic.state)}
                </V3StateChip>
              </td>
              <td className={TD + ' text-muted'}>
                {unit.producer ? localizedV3ProducerKindLabel(i18n, unit.producer.kind) : '—'}
              </td>
              <td className={TD + ' text-muted'}>
                {unit.zeroFindings
                  ? t(i18n)`No reportable findings in this evidenced scope.`
                  : localizedV3StatusSummary(i18n, unit.countsByStatus)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/**
 * V3 finding card: severity, lifecycle-aware status, confidence honesty
 * ("not supplied" when absent), provenance, and policy-drift prominence.
 */
export function AuditV3FindingCard({ finding }: { finding: AuditV3FindingPresentation }) {
  const { i18n } = useLingui()
  return (
    <article className="border border-border rounded-lg py-2.5 px-3 mb-2 bg-panel">
      <div className="flex items-center gap-1.5 flex-wrap">
        <V3StateChip tone="muted">{finding.severity}</V3StateChip>
        <V3StateChip tone={v3FindingStatusTone(finding.status)}>
          {localizedV3FindingStatusLabel(i18n, finding.status)}
        </V3StateChip>
        <V3StateChip tone="muted">{localizedV3LifecycleLabel(i18n, finding.lifecycle)}</V3StateChip>
        <V3StateChip tone="muted">{finding.category}</V3StateChip>
      </div>
      <div className="text-[0.85rem] font-semibold mt-1.5">{finding.title}</div>
      {finding.policyDrift && (
        <p className={META + ' m-0 mt-1 text-[#c4222e]'}>
          {t(i18n)`policy drift — decision predates current policy`}
        </p>
      )}
      <div className="text-[0.78rem] text-muted mt-1">
        <b className="text-text font-semibold">{t(i18n)`confidence`}</b>{' '}
        {localizedV3ConfidenceLabel(i18n, finding.confidence)}
        {finding.expiresAt !== null && (
          <>
            {' · '}
            {t(i18n)`expires ${finding.expiresAt}`}
          </>
        )}
      </div>
      <div className="text-[0.78rem] text-muted mt-1">
        <b className="text-text font-semibold">{t(i18n)`source`}</b>{' '}
        {finding.provenance.source}
        {finding.provenance.producerSource !== null && ` · ${finding.provenance.producerSource}`}
        {finding.provenance.sourceFindingId !== null && ` · ${finding.provenance.sourceFindingId}`}
      </div>
      <div className="flex gap-1 flex-wrap mt-2">
        {finding.locations.map((l) => (
          <AuditLocation key={l} loc={l} />
        ))}
      </div>
    </article>
  )
}
