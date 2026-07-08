import {
  useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState,
  type CSSProperties, type KeyboardEvent,
} from 'react'
import { t } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import type { EntryStatus, GlossaryEntry, TreeNode } from '../src/types'
import {
  linkifyPaths, renderMermaidIn, noteFileFor, relationsFor, annotateGlossary,
  annotateCodeAnchors, degradeCodeEmbeds, readingSequence, firstFileWithin, enhanceSections,
} from './lib'
import { useLive } from './live'

const BTN =
  'btn font-inherit text-[0.75rem] py-[5px] px-3 rounded-lg border border-border bg-panel text-text cursor-pointer whitespace-nowrap hover:border-accent hover:text-accent disabled:opacity-50 disabled:cursor-default'
const EMPTY =
  'text-muted text-[0.9rem] mt-2 [&_code]:bg-[#00000009] [&_code]:py-[0.1em] [&_code]:px-[0.4em] [&_code]:rounded [&_code]:text-[0.85em]'

function stateLabel(status: EntryStatus, i18n: Parameters<typeof t>[0]): string {
  switch (status) {
    case 'fresh': return t(i18n)`up to date`
    case 'outdated': return t(i18n)`outdated — code changed since this was written`
    case 'missing': return t(i18n)`no description yet`
    case 'ignored': return t(i18n)`ignored — excluded by .atlas/config.json`
    case 'moved': return t(i18n)`moved`
  }
}

function dotClass(status: EntryStatus): string {
  const base = 'w-2 h-2 rounded-full shrink-0 '
  switch (status) {
    case 'fresh': return base + 'bg-fresh'
    case 'outdated': return base + 'bg-outdated'
    case 'missing': return base + 'bg-none border-[1.5px] border-missing'
    case 'ignored': return base + 'bg-missing opacity-[0.55]'
    default: return base
  }
}

function Breadcrumb({ node, repoName }: { node: TreeNode; repoName: string }) {
  const segs = node.path === '' ? [] : node.path.split('/')
  const crumbs = [{ label: repoName, path: '' }]
  let p = ''
  for (const seg of segs) {
    p = p ? p + '/' + seg : seg
    crumbs.push({ label: seg, path: p })
  }
  return (
    <h1 className="text-[1.25rem] font-[650] my-1 mb-3 break-all">
      {crumbs.map((c, i) => (
        <span key={c.path}>
          {i > 0 && ' / '}
          {i === crumbs.length - 1 ? (
            <span>{c.label}</span>
          ) : (
            <a
              className="text-inherit no-underline opacity-50 hover:opacity-100 hover:underline"
              href={'#' + encodeURI(c.path)}
            >
              {c.label}
            </a>
          )}
        </span>
      ))}
    </h1>
  )
}

const REL_LINES = 4

/** Count chips past REL_LINES wrapped rows; maxH clips through the bottom of line REL_LINES. */
function measureChips(el: HTMLElement): { hidden: number; maxH: number } {
  const chips = el.querySelectorAll<HTMLElement>('.rel-chip')
  if (!chips.length) return { hidden: 0, maxH: 0 }
  const chipH = chips[0].offsetHeight
  const tops: number[] = []
  for (const chip of chips) {
    const t = chip.offsetTop
    if (!tops.some((x) => Math.abs(x - t) <= 1)) tops.push(t)
  }
  tops.sort((a, b) => a - b)
  if (tops.length <= REL_LINES) return { hidden: 0, maxH: 0 }
  const cutoff = tops[REL_LINES]
  let hidden = 0
  for (const chip of chips) {
    if (chip.offsetTop >= cutoff - 1) hidden++
  }
  return { hidden, maxH: tops[REL_LINES - 1] + chipH - tops[0] }
}

function RelationChips({ items }: { items: string[] }) {
  const { i18n } = useLingui()
  const [expanded, setExpanded] = useState(false)
  const [hidden, setHidden] = useState(0)
  const [maxH, setMaxH] = useState(0)
  const ref = useRef<HTMLSpanElement>(null)

  useEffect(() => setExpanded(false), [items])

  const measure = useCallback(() => {
    const el = ref.current
    if (!el) return
    const { hidden: h, maxH: mh } = measureChips(el)
    setHidden(h)
    setMaxH(mh)
  }, [items])

  useLayoutEffect(() => {
    measure()
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [items, measure])

  const collapsed = !expanded && hidden > 0

  return (
    <span className="flex flex-col gap-0.5 min-w-0 flex-1">
      <span
        ref={ref}
        className={
          'flex flex-wrap gap-1 min-w-0' + (collapsed ? ' overflow-hidden' : '')
        }
        style={collapsed && maxH ? { maxHeight: maxH } as CSSProperties : undefined}
      >
        {items.map((p) => (
          <a
            key={p}
            className="rel-chip text-accent no-underline bg-[#3d6b540d] border border-[#3d6b5426] rounded-md py-px px-[7px] font-mono text-[0.72rem] whitespace-nowrap hover:bg-[#3d6b541f]"
            href={'#' + encodeURI(p)}
          >
            {p}
          </a>
        ))}
      </span>
      {hidden > 0 && (
        <button
          type="button"
          className="text-muted text-[0.72rem] bg-transparent border-none py-px px-0 cursor-pointer font-inherit hover:text-accent"
          onClick={() => setExpanded((e) => !e)}
        >
          {expanded ? t(i18n)`show less` : t(i18n)`+${hidden} more`}
        </button>
      )}
    </span>
  )
}

function Relations({
  node, rel, nodesByPath,
}: {
  node: TreeNode
  rel: ReturnType<typeof import('./lib').buildRelationIndex>
  nodesByPath: Map<string, TreeNode>
}) {
  const { deps, dependents } = useMemo(
    () => relationsFor(node, rel, nodesByPath),
    [node, rel, nodesByPath],
  )
  const { i18n } = useLingui()
  if (!deps.length && !dependents.length) return null
  return (
    <div className="-mt-2 mb-5 flex flex-col gap-1">
      {deps.length > 0 && (
        <div className="flex gap-2 items-baseline text-[0.75rem]">
          <span className="text-muted shrink-0 w-[92px] text-right">{t(i18n)`uses →`}</span>
          <RelationChips items={deps} />
        </div>
      )}
      {dependents.length > 0 && (
        <div className="flex gap-2 items-baseline text-[0.75rem]">
          <span className="text-muted shrink-0 w-[92px] text-right">{t(i18n)`← used by`}</span>
          <RelationChips items={dependents} />
        </div>
      )}
    </div>
  )
}

function Prose({
  node, nodesByPath, glossary,
}: {
  node: TreeNode
  nodesByPath: Map<string, TreeNode>
  glossary: GlossaryEntry[]
}) {
  const ref = useRef<HTMLDivElement>(null)
  const last = useRef<string | null>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    // live data refreshes hand us a NEW node object every time anything in the
    // repo changes — but if THIS page's html is byte-identical, rebuilding the
    // DOM (and re-running mermaid) would just flash the reader for nothing.
    const key = node.path + '\0' + (node.html ?? '')
    if (last.current === key) return
    last.current = key
    el.innerHTML = node.html ?? ''
    linkifyPaths(el, node, nodesByPath)
    annotateGlossary(el, glossary)
    renderMermaidIn(el)
    enhanceSections(el) // fold sections + collapse callout + section nav
    // code anchors need the file's current source — fetched, so they resolve
    // against what the code looks like NOW, not when the note was written
    if (node.type !== 'file') {
      degradeCodeEmbeds(el)
      return
    }
    let alive = true
    fetch('raw?p=' + encodeURIComponent(node.path))
      .then((res) => (res.ok && !res.headers.get('x-atlas-binary') ? res.text() : null))
      .catch(() => null)
      .then((src) => {
        if (!alive || ref.current !== el) return
        if (src) annotateCodeAnchors(el, node.path, src)
        else degradeCodeEmbeds(el) // static build / unreadable source
      })
    return () => { alive = false }
  }, [node, nodesByPath, glossary])
  return <div className="prose" ref={ref} />
}

function Editor({ node, onClose }: { node: TreeNode; onClose: () => void }) {
  const { i18n } = useLingui()
  const [text, setText] = useState(node.source ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const save = () => {
    setBusy(true)
    setError(null)
    fetch('note', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: node.path, body: text }),
    })
      .then(async (res) => {
        if (!res.ok) throw new Error(await res.text())
      })
      .catch((err: unknown) => {
        setError(String(err instanceof Error ? err.message : err))
        setBusy(false)
      })
  }
  const onKey = (e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') save()
    if (e.key === 'Escape' && !busy) onClose()
  }
  return (
    <div className="flex flex-col gap-2 mt-2">
      <div className="text-[0.72rem] text-muted [&_code]:bg-[#00000009] [&_code]:py-[0.1em] [&_code]:px-[0.4em] [&_code]:rounded">
        <code>{noteFileFor(node)}</code>
      </div>
      <textarea
        autoFocus
        spellCheck={false}
        className="w-full min-h-[420px] resize-y text-[0.82rem] leading-[1.6] font-mono py-3 px-3.5 border border-border rounded-lg bg-panel text-text focus:outline-none focus:border-accent"
        value={text}
        placeholder={t(i18n)`Markdown note for this path…`}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={onKey}
      />
      <div className="flex items-center gap-2">
        <button className={BTN + ' bg-accent border-accent text-white hover:opacity-90'} onClick={save} disabled={busy}>
          {busy ? t(i18n)`saving…` : t(i18n)`save & stamp`}
        </button>
        <button className={BTN} onClick={onClose} disabled={busy}>{t(i18n)`cancel`}</button>
        <span className="text-[0.7rem] text-muted">{t(i18n)`⌘⏎ save · esc cancel`}</span>
        {error && <span className="text-[0.75rem] text-[#c4222e]">{error}</span>}
      </div>
    </div>
  )
}

const parentOf = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '')

/** Last two path segments — enough to recognize a page without the noise. */
function shortLabel(p: string, repoName: string): string {
  if (!p) return repoName
  return p.split('/').slice(-2).join('/')
}

export function DocPane({
  node, repoName, nodesByPath, rel, glossary, onContents,
}: {
  node: TreeNode
  repoName: string
  nodesByPath: Map<string, TreeNode>
  rel: ReturnType<typeof import('./lib').buildRelationIndex>
  glossary: GlossaryEntry[]
  onContents: () => void
}) {
  const { i18n } = useLingui()
  const live = useLive()
  const [editing, setEditing] = useState(false)
  useEffect(() => {
    setEditing(false)
  }, [node])
  const seq = useMemo(() => readingSequence(nodesByPath.get('')!), [nodesByPath])
  const seqAt = seq.indexOf(node.path)
  const prev = seqAt > 0 ? seq[seqAt - 1] : null
  const next = seqAt >= 0 && seqAt < seq.length - 1 ? seq[seqAt + 1] : null
  const dive = useMemo(() => firstFileWithin(node, seq, nodesByPath), [node, seq, nodesByPath])
  // ← / → page through the reading order (unless focus is in an input)
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || e.shiftKey) return
      const t = e.target as HTMLElement | null
      if (t?.closest('input, textarea, [contenteditable]')) return
      if (e.key === 'ArrowRight' && next !== null) location.hash = '#' + encodeURI(next)
      if (e.key === 'ArrowLeft' && prev !== null) location.hash = '#' + encodeURI(prev)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [prev, next])
  return (
    <div className="max-w-[760px] py-9 px-12 pb-24 max-md:py-5 max-md:px-4 max-md:pb-16">
      <div className="text-[0.78rem] text-muted break-all">
        {node.type === 'dir' ? t(i18n)`directory` : t(i18n)`file`}
      </div>
      <Breadcrumb node={node} repoName={repoName} />
      <div className="flex items-center gap-2.5 mb-5">
        <div
          className={
            'inline-flex items-center gap-[7px] text-[0.75rem] border border-border rounded-lg py-[5px] px-2.5 bg-panel' +
            (node.status === 'outdated' ? ' border-[#d9930d55] bg-[#d9930d0d]' : '')
          }
        >
          <span className={dotClass(node.status)} />
          {stateLabel(node.status, i18n)}
          {node.stamped ? ` · ${t(i18n)`stamped`} ${new Date(node.stamped).toLocaleDateString(i18n.locale)}` : ''}
        </div>
        {dive && (
          <a
            className={BTN + ' no-underline text-accent border-[#3d6b5455] hover:bg-[#3d6b540d]'}
            href={'#' + encodeURI(dive)}
            title={dive}
          >
            {t(i18n)`start reading ↘`}
          </a>
        )}
        {live && !editing && node.status !== 'ignored' && (
          <button className={BTN + ' text-muted hover:text-accent'} onClick={() => setEditing(true)}>
            {node.source ? t(i18n)`edit` : t(i18n)`write note`}
          </button>
        )}
      </div>
      {glossary.some((g) => g.home === node.path) && (
        <div className="text-[0.75rem] text-muted mb-4 flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-accent">{t(i18n)`canonical home for`}</span>
          {glossary
            .filter((g) => g.home === node.path)
            .map((g) => (
              <span
                key={g.term}
                className="inline-flex items-center gap-1 border border-border rounded-md py-[2px] px-2 bg-panel"
                title={g.refs?.length ? t(i18n)`referenced in ${g.refs.length} notes` : undefined}
              >
                {g.term}
                {g.refs?.length ? <span className="text-muted"> · {g.refs.length}</span> : null}
              </span>
            ))}
        </div>
      )}
      <Relations node={node} rel={rel} nodesByPath={nodesByPath} />
      {editing ? (
        <Editor node={node} onClose={() => setEditing(false)} />
      ) : node.html ? (
        <Prose node={node} nodesByPath={nodesByPath} glossary={glossary} />
      ) : (
        <div className={EMPTY}>
          <Trans>
            No note for this path. Write one at <code>{noteFileFor(node)}</code> and run{' '}
            <code>repo-atlas stamp</code>.
          </Trans>
        </div>
      )}
      {!editing && (prev !== null || next !== null) && (
        <nav className="flex gap-2.5 mt-12 pt-3.5 border-t border-border">
          {prev !== null ? (
            <a
              className="group flex-1 min-w-0 flex flex-col gap-0.5 no-underline py-2 px-3 border border-border rounded-lg font-inherit bg-transparent cursor-pointer text-left hover:border-accent"
              href={'#' + encodeURI(prev)}
              title={prev || '(root)'}
            >
              <span className="text-[0.7rem] text-muted group-hover:text-accent">{t(i18n)`← prev`}</span>
              <span className="text-[0.76rem] text-text font-mono overflow-hidden text-ellipsis whitespace-nowrap">
                {shortLabel(prev, repoName)}
              </span>
            </a>
          ) : <span className="flex-1 min-w-0" />}
          <button
            className="group flex-1 min-w-0 flex flex-col gap-0.5 py-2 px-3 border border-border rounded-lg font-inherit bg-transparent cursor-pointer text-center hover:border-accent"
            onClick={onContents}
          >
            <span className="text-[0.7rem] text-muted group-hover:text-accent">{t(i18n)`contents`}</span>
            <span className="text-[0.76rem] text-text font-mono overflow-hidden text-ellipsis whitespace-nowrap">
              {shortLabel(node.type === 'dir' ? node.path : parentOf(node.path), repoName)}
            </span>
          </button>
          {next !== null ? (
            <a
              className="group flex-1 min-w-0 flex flex-col gap-0.5 no-underline py-2 px-3 border border-border rounded-lg font-inherit bg-transparent cursor-pointer text-right hover:border-accent"
              href={'#' + encodeURI(next)}
              title={next}
            >
              <span className="text-[0.7rem] text-muted group-hover:text-accent">{t(i18n)`next →`}</span>
              <span className="text-[0.76rem] text-text font-mono overflow-hidden text-ellipsis whitespace-nowrap">
                {shortLabel(next, repoName)}
              </span>
            </a>
          ) : <span className="flex-1 min-w-0" />}
        </nav>
      )}
    </div>
  )
}