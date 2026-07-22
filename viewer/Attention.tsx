import { useMemo, useState } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import {
  Activity,
  CheckCircle2,
  Clock3,
  History,
  Inbox,
  RotateCcw,
} from 'lucide-react'
import type { AttentionSection } from '../src/audit-routes'
import { attentionItemBuckets } from '../src/attention-presentation'
import type {
  AttentionAction,
  AttentionEvent,
  AttentionItem,
  AttentionOutcome,
  AttentionPayload,
} from '../src/types'

const NAV_ROW =
  'w-full flex items-center gap-2 py-1.5 px-2 rounded-md border-none cursor-pointer font-inherit text-[0.8rem] text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30'
const SECONDARY_BUTTON =
  'font-inherit text-[0.75rem] py-1.5 px-2.5 rounded-md border border-border bg-panel text-muted cursor-pointer hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-45 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30'
const PRIMARY_BUTTON =
  'font-inherit text-[0.75rem] py-1.5 px-2.5 rounded-md border border-accent bg-accent text-white cursor-pointer hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30'

function formatTime(value: string, locale: string): string {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString(locale)
}

function shortVersion(value: string): string {
  return value.slice(0, 10)
}

async function sendAttentionAction(
  item: AttentionItem,
  action: AttentionAction,
  note?: string,
  until?: string,
): Promise<AttentionPayload> {
  const response = await fetch('attention/action', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      slug: item.slug,
      snapshot: item.snapshot,
      action,
      ...(note ? { note } : {}),
      ...(until ? { until } : {}),
    }),
  })
  if (!response.ok) throw new Error((await response.text()) || `${response.status}`)
  return await response.json() as AttentionPayload
}

function outcomeLabel(outcome: AttentionOutcome, i18n: Parameters<typeof t>[0]): string {
  switch (outcome) {
    case 'acknowledged': return t(i18n)`acknowledged`
    case 'understood': return t(i18n)`understood`
    case 'decided': return t(i18n)`decision recorded`
    case 'not-relevant': return t(i18n)`not relevant`
  }
}

function workflowLabel(item: AttentionItem, i18n: Parameters<typeof t>[0]): string {
  if (item.workflow === 'snoozed') return t(i18n)`snoozed`
  if (item.workflow === 'done' && item.lastOutcome) return outcomeLabel(item.lastOutcome, i18n)
  if (item.conceptStatus === 'broken-source') return t(i18n)`broken source`
  if (item.conceptStatus === 'outdated') return t(i18n)`page is outdated`
  return t(i18n)`new source snapshot`
}

export function AttentionNav({
  attention,
  section,
  onSelect,
}: {
  attention: AttentionPayload
  section: AttentionSection
  onSelect: (section: AttentionSection) => void
}) {
  const { i18n } = useLingui()
  const healthIssues =
    attention.health.documents.outdated +
    attention.health.documents.missing +
    attention.health.concepts.outdated +
    attention.health.concepts.brokenSource +
    attention.health.brokenReferences +
    attention.health.orphans
  const rows = [
    { section: 'needs' as const, icon: Inbox, label: t(i18n)`needs attention`, count: attention.summary.open },
    { section: 'history' as const, icon: History, label: t(i18n)`review history`, count: attention.summary.history },
    { section: 'health' as const, icon: Activity, label: t(i18n)`system health`, count: healthIssues },
  ]
  return (
    <div className="flex flex-col gap-0.5 px-0.5" aria-label={t(i18n)`attention views`}>
      {rows.map((row) => {
        const active = section === row.section
        const Icon = row.icon
        return (
          <button
            key={row.section}
            type="button"
            className={
              NAV_ROW +
              (active
                ? ' bg-[#3d6b5414] text-accent'
                : ' bg-transparent text-muted hover:text-text hover:bg-[#00000006]')
            }
            aria-current={active ? 'page' : undefined}
            onClick={() => onSelect(row.section)}
          >
            <Icon className="w-4 h-4 shrink-0" aria-hidden />
            <span className="flex-1 min-w-0 font-semibold">{row.label}</span>
            <span className="text-[0.7rem] tabular-nums">{row.count}</span>
          </button>
        )
      })}
    </div>
  )
}

function DiagnosticBanner({ attention }: { attention: AttentionPayload }) {
  const { i18n } = useLingui()
  if (attention.state === 'ready' && attention.diagnostics.length === 0) return null
  return (
    <div role="alert" className="mb-5 rounded-lg border border-[#c4222e55] bg-[#c4222e0d] py-3 px-4 text-[0.82rem]">
      <div className="font-semibold text-[#a02832]">{t(i18n)`review state is unavailable`}</div>
      <p className="mt-1 text-muted">
        {t(i18n)`Atlas will not overwrite the local review file. Fix or move it, then restart the live server.`}
      </p>
      {attention.diagnostics.map((entry, index) => (
        <code key={`${entry.code}-${index}`} className="mt-1 block text-[0.72rem] break-all">{entry.code}: {entry.message}</code>
      ))}
    </div>
  )
}

function SummaryStrip({ attention }: { attention: AttentionPayload }) {
  const { i18n } = useLingui()
  const buckets = attentionItemBuckets(attention.items)
  const stats = [
    [t(i18n)`open`, attention.summary.open],
    [t(i18n)`snoozed`, attention.summary.snoozed],
    [t(i18n)`reviewed`, buckets.reviewed.length],
  ] as const
  return (
    <div className="grid grid-cols-3 gap-2 mb-7 max-sm:grid-cols-1">
      {stats.map(([label, value]) => (
        <div key={label} className="rounded-lg border border-border bg-panel py-3 px-4">
          <div className="text-[1.25rem] font-[650] tabular-nums">{value}</div>
          <div className="text-[0.72rem] text-muted mt-0.5">{label}</div>
        </div>
      ))}
    </div>
  )
}

function ReviewControls({
  item,
  attention,
  onUpdate,
}: {
  item: AttentionItem
  attention: AttentionPayload
  onUpdate: (attention: AttentionPayload) => void
}) {
  const { i18n } = useLingui()
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState<AttentionAction | null>(null)
  const [error, setError] = useState<string | null>(null)
  const enabled = attention.mode === 'live' && attention.state === 'ready'

  const act = async (action: AttentionAction, until?: string) => {
    if (!enabled || busy) return
    if ((action === 'understood' || action === 'decided') && !note.trim()) {
      setError(t(i18n)`Write what changed or what you decided before recording this outcome.`)
      return
    }
    setBusy(action)
    setError(null)
    try {
      const next = await sendAttentionAction(item, action, note.trim() || undefined, until)
      setNote('')
      onUpdate(next)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught))
    } finally {
      setBusy(null)
    }
  }

  if (!enabled) {
    return (
      <p className="mt-4 text-[0.75rem] text-muted" role="status">
        {attention.mode === 'static'
          ? t(i18n)`Persistent review actions are available when this atlas is opened with atlas serve.`
          : t(i18n)`Review actions are disabled until the local review state is repaired.`}
      </p>
    )
  }

  if (item.workflow === 'done') {
    return (
      <div className="mt-4 flex items-center gap-2">
        <button type="button" className={SECONDARY_BUTTON} disabled={busy !== null} onClick={() => void act('reopen')}>
          <RotateCcw className="inline-block w-3.5 h-3.5 mr-1 align-[-2px]" aria-hidden />
          {t(i18n)`reopen`}
        </button>
      </div>
    )
  }

  return (
    <div className="mt-4 border-t border-border pt-4">
      <label className="block text-[0.75rem] font-semibold" htmlFor={`attention-note-${item.slug}`}>
        {t(i18n)`Review note`}
      </label>
      <p className="text-[0.72rem] text-muted mt-1">
        {t(i18n)`Required for “understood” and “decision”; optional for the other outcomes.`}
      </p>
      <textarea
        id={`attention-note-${item.slug}`}
        className="mt-2 min-h-20 w-full resize-y rounded-md border border-border bg-bg py-2 px-2.5 font-inherit text-[0.8rem] text-text focus:outline-none focus:border-accent"
        maxLength={10_000}
        value={note}
        onChange={(event) => setNote(event.target.value)}
        placeholder={t(i18n)`What changed, why it matters, or what you decided…`}
      />
      <div className="mt-2 flex flex-wrap gap-2">
        <button type="button" className={SECONDARY_BUTTON} disabled={busy !== null} onClick={() => void act('acknowledged')}>
          {t(i18n)`acknowledge`}
        </button>
        <button type="button" className={PRIMARY_BUTTON} disabled={busy !== null} onClick={() => void act('understood')}>
          {t(i18n)`I understand`}
        </button>
        <button type="button" className={PRIMARY_BUTTON} disabled={busy !== null} onClick={() => void act('decided')}>
          {t(i18n)`record decision`}
        </button>
        <button type="button" className={SECONDARY_BUTTON} disabled={busy !== null} onClick={() => void act('not-relevant')}>
          {t(i18n)`not relevant`}
        </button>
        {item.workflow === 'snoozed' && (
          <button type="button" className={SECONDARY_BUTTON} disabled={busy !== null} onClick={() => void act('reopen')}>
            {t(i18n)`resume now`}
          </button>
        )}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[0.72rem] text-muted">
        <span>{t(i18n)`snooze`}</span>
        {[1, 7, 30].map((days) => (
          <button
            key={days}
            type="button"
            className={SECONDARY_BUTTON + ' !py-1'}
            disabled={busy !== null}
            onClick={() => void act('snooze', new Date(Date.now() + days * 86_400_000).toISOString())}
          >
            {days === 1 ? t(i18n)`1 day` : t(i18n)`${days} days`}
          </button>
        ))}
      </div>
      <div className="min-h-5 mt-1 text-[0.72rem] text-[#a02832]" role="status" aria-live="polite">
        {error}
      </div>
    </div>
  )
}

function QuickReopen({
  item,
  attention,
  onUpdate,
}: {
  item: AttentionItem
  attention: AttentionPayload
  onUpdate: (attention: AttentionPayload) => void
}) {
  const { i18n } = useLingui()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  if (attention.mode !== 'live' || attention.state !== 'ready') return null
  const reopen = async () => {
    setBusy(true)
    setError(null)
    try {
      onUpdate(await sendAttentionAction(item, 'reopen'))
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught))
    } finally {
      setBusy(false)
    }
  }
  return (
    <span className="shrink-0">
      <button type="button" className={SECONDARY_BUTTON + ' !py-1'} disabled={busy} onClick={() => void reopen()}>
        {t(i18n)`reopen`}
      </button>
      {error && <span className="sr-only" role="status">{error}</span>}
    </span>
  )
}

function AttentionCard({
  item,
  attention,
  onSelectConcept,
  onUpdate,
}: {
  item: AttentionItem
  attention: AttentionPayload
  onSelectConcept: (slug: string) => void
  onUpdate: (attention: AttentionPayload) => void
}) {
  const { i18n } = useLingui()
  const evidence = item.changedPaths.length > 0 ? item.changedPaths : item.sources
  const evidenceLabel = item.changedPaths.length > 0 ? t(i18n)`changed paths` : t(i18n)`declared source scope`
  return (
    <article className="rounded-xl border border-border bg-panel py-5 px-5 shadow-[0_1px_2px_#00000008]">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <button
            type="button"
            className="border-none bg-transparent p-0 text-left font-inherit text-[1rem] font-[650] text-text cursor-pointer hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 rounded-sm"
            onClick={() => onSelectConcept(item.slug)}
          >
            {item.title}
          </button>
          <div className="mt-1 text-[0.72rem] text-muted">
            {item.chapter ? `${item.chapter} · ` : ''}{t(i18n)`first seen`} {formatTime(item.firstSeenAt, i18n.locale)}
          </div>
        </div>
        <span className={
          'shrink-0 rounded-full border py-1 px-2 text-[0.7rem] font-semibold ' +
          (item.workflow === 'done'
            ? 'border-[#4a9d6e55] bg-[#4a9d6e0d] text-[#2c6647]'
            : item.workflow === 'snoozed'
              ? 'border-[#d9930d55] bg-[#d9930d0d] text-[#8a6105]'
              : item.conceptStatus === 'broken-source'
                ? 'border-[#c4222e55] bg-[#c4222e0d] text-[#a02832]'
                : 'border-[#d9930d55] bg-[#d9930d0d] text-[#8a6105]')
        }>
          {workflowLabel(item, i18n)}
        </span>
      </div>

      <div className="mt-4 rounded-lg bg-bg border border-border py-3 px-3.5 text-[0.76rem]">
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[0.7rem] text-muted">
          <span>{item.anchor ? shortVersion(item.anchor) : t(i18n)`unstamped`}</span>
          <span aria-hidden>→</span>
          <span className="text-text">{shortVersion(item.snapshot)}</span>
        </div>
        <div className="mt-2 text-muted">{evidenceLabel}</div>
        {evidence.length > 0 ? (
          <ul className="mt-1.5 list-none p-0 flex flex-wrap gap-1.5">
            {evidence.map((source) => (
              <li key={source}>
                <code className={
                  'inline-block rounded-md border py-0.5 px-1.5 text-[0.7rem] break-all ' +
                  (item.brokenSources.includes(source)
                    ? 'border-[#c4222e33] bg-[#c4222e0d] text-[#a02832] line-through'
                    : 'border-border bg-panel text-text')
                }>{source}</code>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-1 text-muted">{t(i18n)`No path-level diff is available; inspect the declared concept sources.`}</p>
        )}
      </div>
      {item.snoozedUntil && (
        <p className="mt-3 text-[0.75rem] text-muted">
          <Clock3 className="inline-block w-3.5 h-3.5 mr-1 align-[-2px]" aria-hidden />
          {t(i18n)`snoozed until`} {formatTime(item.snoozedUntil, i18n.locale)}
        </p>
      )}
      <ReviewControls item={item} attention={attention} onUpdate={onUpdate} />
    </article>
  )
}

function NeedsAttention({
  attention,
  onSelectConcept,
  onUpdate,
}: {
  attention: AttentionPayload
  onSelectConcept: (slug: string) => void
  onUpdate: (attention: AttentionPayload) => void
}) {
  const { i18n } = useLingui()
  const { open, snoozed, reviewed, baselines } = attentionItemBuckets(attention.items)
  return (
    <>
      <SummaryStrip attention={attention} />
      <section aria-labelledby="attention-open-heading">
        <div className="flex items-baseline justify-between gap-3 mb-3">
          <h2 id="attention-open-heading" className="text-[0.95rem] font-[650]">{t(i18n)`Needs review`}</h2>
          <span className="text-[0.72rem] text-muted tabular-nums">{open.length}</span>
        </div>
        {open.length === 0 ? (
          <div className="rounded-xl border border-[#4a9d6e44] bg-[#4a9d6e0a] py-5 px-5 text-[0.82rem]">
            <CheckCircle2 className="inline-block w-4 h-4 mr-2 align-[-3px] text-[#2c6647]" aria-hidden />
            {t(i18n)`No current concept snapshot is waiting for you.`}
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {open.map((item) => (
              <AttentionCard key={item.id} item={item} attention={attention} onSelectConcept={onSelectConcept} onUpdate={onUpdate} />
            ))}
          </div>
        )}
      </section>

      {snoozed.length > 0 && (
        <section className="mt-8" aria-labelledby="attention-snoozed-heading">
          <div className="flex items-baseline justify-between gap-3 mb-3">
            <h2 id="attention-snoozed-heading" className="text-[0.95rem] font-[650]">{t(i18n)`Snoozed`}</h2>
            <span className="text-[0.72rem] text-muted tabular-nums">{snoozed.length}</span>
          </div>
          <div className="flex flex-col gap-3">
            {snoozed.map((item) => (
              <AttentionCard key={item.id} item={item} attention={attention} onSelectConcept={onSelectConcept} onUpdate={onUpdate} />
            ))}
          </div>
        </section>
      )}

      <details className="mt-8 rounded-xl border border-border bg-panel py-3 px-4">
        <summary className="cursor-pointer text-[0.82rem] font-semibold">
          {t(i18n)`Reviewed current versions`} ({reviewed.length})
        </summary>
        <div className="mt-3 flex flex-col divide-y divide-border">
          {reviewed.length === 0 ? (
            <p className="py-2 text-[0.78rem] text-muted">{t(i18n)`Nothing has been reviewed yet.`}</p>
          ) : reviewed.map((item) => (
            <div key={item.id} className="flex items-center gap-3 py-2.5">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-[#2c6647]" aria-hidden />
              <button
                type="button"
                className="min-w-0 flex-1 border-none bg-transparent p-0 text-left font-inherit text-[0.8rem] text-text cursor-pointer hover:text-accent"
                onClick={() => onSelectConcept(item.slug)}
              >
                {item.title}
              </button>
              <span className="text-[0.7rem] text-muted">{item.lastOutcome ? outcomeLabel(item.lastOutcome, i18n) : t(i18n)`baseline`}</span>
              <QuickReopen item={item} attention={attention} onUpdate={onUpdate} />
            </div>
          ))}
        </div>
      </details>
      {baselines.length > 0 && (
        <details className="mt-3 rounded-xl border border-border bg-panel py-3 px-4">
          <summary className="cursor-pointer text-[0.78rem] text-muted">
            {t(i18n)`Quiet baselines`} ({baselines.length})
          </summary>
          <p className="mt-2 text-[0.75rem] text-muted">
            {t(i18n)`Fresh when first observed; these versions have no human review receipt.`}
          </p>
          <ul className="mt-2 mb-0 pl-5 text-[0.78rem] text-muted">
            {baselines.map((item) => <li key={item.id}>{item.title}</li>)}
          </ul>
        </details>
      )}
    </>
  )
}

function eventLabel(event: AttentionEvent, i18n: Parameters<typeof t>[0]): string {
  if (event.type === 'source-reopened') return t(i18n)`reopened by a new source snapshot`
  if (event.type === 'snoozed') return t(i18n)`snoozed`
  if (event.type === 'reopened') return t(i18n)`reopened`
  return event.outcome ? outcomeLabel(event.outcome, i18n) : t(i18n)`reviewed`
}

function ReviewHistory({
  attention,
  onSelectConcept,
}: {
  attention: AttentionPayload
  onSelectConcept: (slug: string) => void
}) {
  const { i18n } = useLingui()
  const items = useMemo(() => new Map(attention.items.map((item) => [item.slug, item])), [attention.items])
  const events = [...attention.events].reverse()
  if (events.length === 0) {
    return <div className="rounded-xl border border-border bg-panel py-6 px-5 text-[0.82rem] text-muted">{t(i18n)`No review events yet.`}</div>
  }
  return (
    <ol className="list-none p-0 m-0 flex flex-col gap-3">
      {events.map((event) => {
        const item = items.get(event.slug)
        return (
          <li key={event.id} className="rounded-xl border border-border bg-panel py-4 px-5">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                {item ? (
                  <button
                    type="button"
                    className="border-none bg-transparent p-0 text-left font-inherit text-[0.88rem] font-semibold text-text cursor-pointer hover:text-accent"
                    onClick={() => onSelectConcept(event.slug)}
                  >
                    {item.title}
                  </button>
                ) : (
                  <span className="text-[0.88rem] font-semibold">{event.slug}</span>
                )}
                <div className="mt-1 text-[0.75rem] text-muted">{eventLabel(event, i18n)}</div>
              </div>
              <time className="shrink-0 text-[0.7rem] text-muted" dateTime={event.at}>{formatTime(event.at, i18n.locale)}</time>
            </div>
            <div className="mt-2 font-mono text-[0.68rem] text-muted">{shortVersion(event.snapshot)}</div>
            {event.note && <p className="mt-3 text-[0.82rem] leading-relaxed whitespace-pre-wrap">{event.note}</p>}
            {event.until && <p className="mt-2 text-[0.72rem] text-muted">{t(i18n)`until`} {formatTime(event.until, i18n.locale)}</p>}
          </li>
        )
      })}
    </ol>
  )
}

function HealthMetric({ label, value, tone = 'normal' }: { label: string; value: number; tone?: 'normal' | 'warning' }) {
  return (
    <div className="rounded-lg border border-border bg-panel py-4 px-4">
      <div className={'text-[1.3rem] font-[650] tabular-nums ' + (tone === 'warning' && value > 0 ? 'text-[#a06b00]' : '')}>{value}</div>
      <div className="mt-1 text-[0.72rem] text-muted">{label}</div>
    </div>
  )
}

function SystemHealth({ attention }: { attention: AttentionPayload }) {
  const { i18n } = useLingui()
  const { documents, concepts } = attention.health
  const freshDocuments = Math.max(0, documents.total - documents.outdated - documents.missing - documents.ignored)
  return (
    <div className="flex flex-col gap-7">
      <section>
        <h2 className="text-[0.95rem] font-[650] mb-3">{t(i18n)`Documentation artifacts`}</h2>
        <div className="grid grid-cols-4 gap-2 max-sm:grid-cols-2">
          <HealthMetric label={t(i18n)`fresh`} value={freshDocuments} />
          <HealthMetric label={t(i18n)`outdated`} value={documents.outdated} tone="warning" />
          <HealthMetric label={t(i18n)`missing`} value={documents.missing} tone="warning" />
          <HealthMetric label={t(i18n)`ignored`} value={documents.ignored} />
        </div>
      </section>
      <section>
        <h2 className="text-[0.95rem] font-[650] mb-3">{t(i18n)`Concept pages`}</h2>
        <div className="grid grid-cols-3 gap-2 max-sm:grid-cols-1">
          <HealthMetric label={t(i18n)`fresh`} value={concepts.fresh} />
          <HealthMetric label={t(i18n)`outdated`} value={concepts.outdated} tone="warning" />
          <HealthMetric label={t(i18n)`broken source`} value={concepts.brokenSource} tone="warning" />
        </div>
      </section>
      <section>
        <h2 className="text-[0.95rem] font-[650] mb-3">{t(i18n)`Structure`}</h2>
        <div className="grid grid-cols-2 gap-2 max-sm:grid-cols-1">
          <HealthMetric label={t(i18n)`broken references`} value={attention.health.brokenReferences} tone="warning" />
          <HealthMetric label={t(i18n)`orphan notes`} value={attention.health.orphans} tone="warning" />
        </div>
      </section>
    </div>
  )
}

export function AttentionPane({
  attention,
  section,
  onSelectConcept,
  onUpdate,
}: {
  attention: AttentionPayload
  section: AttentionSection
  onSelectConcept: (slug: string) => void
  onUpdate: (attention: AttentionPayload) => void
}) {
  const { i18n } = useLingui()
  const title = section === 'needs'
    ? t(i18n)`Needs your attention`
    : section === 'history'
      ? t(i18n)`Review history`
      : t(i18n)`System health`
  const explanation = section === 'needs'
    ? t(i18n)`A source can be fresh while your understanding is not. Only an explicit review outcome closes an item; a new source snapshot reopens it.`
    : section === 'history'
      ? t(i18n)`Durable, version-bound receipts show what you followed up and what conclusion you recorded.`
      : t(i18n)`Machine freshness is kept separate from human understanding. These counts diagnose Atlas artifacts only.`
  return (
    <div className="max-w-[920px] py-9 px-12 pb-24 max-md:py-5 max-md:px-4 max-md:pb-16">
      <div className="text-[0.78rem] text-muted">{t(i18n)`attention`}</div>
      <h1 className="text-[1.35rem] font-[650] mt-1 mb-2">{title}</h1>
      <p className="max-w-[720px] text-[0.82rem] leading-relaxed text-muted mb-6">{explanation}</p>
      <DiagnosticBanner attention={attention} />
      {section === 'needs' ? (
        <NeedsAttention attention={attention} onSelectConcept={onSelectConcept} onUpdate={onUpdate} />
      ) : section === 'history' ? (
        <ReviewHistory attention={attention} onSelectConcept={onSelectConcept} />
      ) : (
        <SystemHealth attention={attention} />
      )}
    </div>
  )
}
