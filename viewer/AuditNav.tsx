import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { auditRoute, auditUnitRoute } from '../src/audit-routes'
import type { AuditDomain } from '../src/types'

const ROW =
  'w-full flex items-center gap-1.5 py-1 pr-2 pl-1.5 rounded-md select-none text-[0.8rem] text-left font-inherit border-none'
const ROW_BTN =
  ROW +
  ' cursor-pointer bg-transparent text-text hover:bg-[#00000006] focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 focus-visible:bg-[#3d6b540d]'
const ROW_STATIC = ROW + ' bg-transparent text-text cursor-default'

export interface AuditNavUnit {
  slug: string
  title: string
  findings: ReadonlyArray<unknown>
  stale: boolean
}

/** Domain unit list for the Security / Tests sidebar sections. */
export function AuditNav({
  domain,
  units,
  selectedSlug,
  onSelect,
}: {
  domain: AuditDomain
  units: ReadonlyArray<AuditNavUnit>
  selectedSlug: string | null
  onSelect: (route: string) => void
}) {
  const { i18n } = useLingui()
  if (units.length === 0) {
    return (
      <div className="text-[0.78rem] text-muted px-2 py-3">{t(i18n)`No completed audits yet`}</div>
    )
  }
  return (
    <div className="flex flex-col gap-0.5">
      <button
        type="button"
        className={ROW_BTN + (selectedSlug === null ? ' sel bg-[#3d6b5414]' : '')}
        aria-current={selectedSlug === null ? 'page' : undefined}
        onClick={() => onSelect(auditRoute(domain))}
      >
        <span className="flex-1 min-w-0 overflow-hidden text-ellipsis font-semibold">
          {domain === 'security' ? t(i18n)`all security units` : t(i18n)`all test units`}
        </span>
        <span className="shrink-0 text-[0.7rem] text-muted">
          {units.reduce((n, u) => n + u.findings.length, 0)}
        </span>
      </button>
      {units.map((u) => {
        const selected = selectedSlug === u.slug
        const route = auditUnitRoute(domain, u.slug)
        const body = (
          <>
            <span className="flex-1 min-w-0 overflow-hidden text-ellipsis">{u.title}</span>
            {u.stale && (
              <span className="shrink-0 text-[0.68rem] text-[#c4222e] font-semibold">{t(i18n)`stale`}</span>
            )}
            <span className="shrink-0 text-[0.7rem] text-muted">{u.findings.length}</span>
          </>
        )
        // Legacy non-kebab slugs remain visible but cannot deep-link.
        if (route === null) {
          return (
            <div
              key={u.slug}
              className={ROW_STATIC + (selected ? ' sel bg-[#3d6b5414]' : '')}
              title={u.slug}
            >
              {body}
            </div>
          )
        }
        return (
          <button
            key={u.slug}
            type="button"
            className={ROW_BTN + (selected ? ' sel bg-[#3d6b5414]' : '')}
            aria-current={selected ? 'page' : undefined}
            onClick={() => onSelect(route)}
            title={u.slug}
          >
            {body}
          </button>
        )
      })}
    </div>
  )
}
