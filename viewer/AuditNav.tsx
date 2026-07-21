import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import {
  auditSidebarRows,
  type AuditSidebarModeRow,
  type AuditSidebarUnitRow,
  type AuditViewMode,
  type DomainAssurance,
} from '../src/audit-assurance'
import { auditRoute, auditUnitRoute } from '../src/audit-routes'

const ROW =
  'w-full flex items-center gap-1.5 py-1 pr-2 pl-1.5 rounded-md select-none text-[0.8rem] text-left font-inherit border-none'
const ROW_BTN =
  ROW +
  ' cursor-pointer bg-transparent text-text hover:bg-[#00000006] focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 focus-visible:bg-[#3d6b540d]'
const ROW_STATIC = ROW + ' bg-transparent text-text cursor-default'
const ROW_ACTIVE = ' sel bg-[#3d6b5414]'
const META = 'shrink-0 text-[0.68rem] text-muted tabular-nums'
const UNIT_META = 'shrink-0 text-[0.68rem] text-muted max-w-32 overflow-hidden text-ellipsis whitespace-nowrap text-right'

/**
 * Coverage-aware Security / Tests sidebar: Overview, Needs attention,
 * Coverage gaps, then registered units with separate coverage and risk text.
 * Receives already-derived DomainAssurance — does not infer coverage.
 */
export function AuditNav({
  model,
  selectedMode,
  selectedUnitSlug,
  onMode,
  onSelect,
}: {
  model: DomainAssurance
  selectedMode: AuditViewMode
  selectedUnitSlug: string | null
  onMode: (mode: AuditViewMode) => void
  onSelect: (route: string) => void
}) {
  const { i18n } = useLingui()
  const rows = auditSidebarRows(model)
  const domain = model.domain
  const modeActive = selectedUnitSlug === null
  const modeRows = rows.filter((row): row is AuditSidebarModeRow => row.kind !== 'unit')
  const unitRows = rows.filter((row): row is AuditSidebarUnitRow => row.kind === 'unit')

  return (
    <div className="flex flex-col gap-0.5">
      {modeRows.map((row) => {
        const selected = modeActive && selectedMode === row.mode
        const label =
          row.kind === 'overview'
            ? t(i18n)`Overview`
            : row.kind === 'attention'
              ? t(i18n)`Needs attention`
              : t(i18n)`Coverage gaps`
        return (
          <button
            key={row.kind}
            type="button"
            className={ROW_BTN + (selected ? ROW_ACTIVE : '')}
            aria-pressed={selected}
            aria-current={selected ? 'page' : undefined}
            onClick={() => {
              onMode(row.mode)
              onSelect(auditRoute(domain))
            }}
          >
            <span className="flex-1 min-w-0 overflow-hidden text-ellipsis font-semibold">
              {label}
            </span>
            {row.suffix !== null && (
              <span className={META}>{row.suffix}</span>
            )}
          </button>
        )
      })}

      {unitRows.length > 0 && (
        <div
          role="separator"
          className="my-1.5 mx-2 border-t border-border"
          aria-hidden
        />
      )}

      {unitRows.map((row) => {
        const selected = selectedUnitSlug === row.slug
        const route = auditUnitRoute(domain, row.slug)
        const body = (
          <>
            <span className="flex-1 min-w-0 overflow-hidden text-ellipsis">{row.title}</span>
            <span className="flex flex-col items-end gap-0.5 min-w-0 shrink-0">
              <span className={UNIT_META} title={row.coverageLabel}>
                {row.coverageLabel}
              </span>
              <span className={UNIT_META} title={row.riskLabel}>
                {row.riskLabel}
              </span>
            </span>
          </>
        )
        // Legacy non-kebab slugs remain visible but cannot deep-link.
        if (route === null) {
          return (
            <div
              key={row.slug}
              className={ROW_STATIC + (selected ? ROW_ACTIVE : '')}
              title={row.slug}
            >
              {body}
            </div>
          )
        }
        return (
          <button
            key={row.slug}
            type="button"
            className={ROW_BTN + (selected ? ROW_ACTIVE : '')}
            aria-current={selected ? 'page' : undefined}
            onClick={() => onSelect(route)}
            title={row.slug}
          >
            {body}
          </button>
        )
      })}

      {unitRows.length === 0 && (
        <div className="text-[0.78rem] text-muted px-2 py-3">
          {t(i18n)`No completed audits yet`}
        </div>
      )}
    </div>
  )
}
