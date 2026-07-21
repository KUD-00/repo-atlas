import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import {
  coverageCountsAvailable,
  type DomainAssurance,
  type GapsModeProjection,
  type UnitCoverageSummary,
} from '../src/audit-assurance'
import { localizedCoverageLabel } from './audit-copy'

const META = 'text-[0.78rem] text-muted m-0 mb-2'

function UnavailableCoverageFacts({ className = META }: { className?: string }) {
  const { i18n } = useLingui()
  return <p className={className}>{t(i18n)`Coverage counts unavailable`}</p>
}

/**
 * Unit-level coverage facts. Numeric placeholders from missing or invalid
 * portfolios never cross this rendering boundary.
 */
export function AuditUnitCoverageFacts({
  model,
  coverage,
}: {
  model: DomainAssurance
  coverage: UnitCoverageSummary
}) {
  const { i18n } = useLingui()
  if (!coverageCountsAvailable(model)) return <UnavailableCoverageFacts />
  return (
    <p className={META}>
      {coverage.fresh}/{coverage.required} {t(i18n)`fresh`}
      {' · '}
      {localizedCoverageLabel(i18n, coverage)}
    </p>
  )
}

/**
 * Domain gaps-mode facts. The projection may contain zero placeholders, so
 * the portfolio trust decision is made here before any number is rendered.
 */
export function AuditGapCoverageFacts({
  model,
  projection,
}: {
  model: DomainAssurance
  projection: GapsModeProjection
}) {
  const { i18n } = useLingui()
  if (!coverageCountsAvailable(model)) {
    return <UnavailableCoverageFacts className="text-[0.78rem] text-muted m-0 mb-4" />
  }
  return (
    <p className="text-[0.78rem] text-muted m-0 mb-4">
      <span className="text-text font-semibold tabular-nums">
        {projection.numerator}/{projection.denominator}
      </span>{' '}
      {t(i18n)`fresh`}
      {' · '}
      <span className="text-text font-semibold tabular-nums">{projection.missing}</span>{' '}
      {t(i18n)`missing`}
    </p>
  )
}
