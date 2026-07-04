import {
  useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState,
  type CSSProperties, type KeyboardEvent,
} from 'react'
import { t } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import type { EntryStatus, GlossaryEntry, TreeNode } from '../src/types'
import {
  linkifyPaths, renderMermaidIn, noteFileFor, relationsFor, annotateGlossary,
  annotateCodeAnchors, degradeCodeEmbeds, readingSequence, firstFileWithin,
} from './lib'
import { useLive } from './live'

function stateLabel(status: EntryStatus, i18n: Parameters<typeof t>[0]): string {
  switch (status) {
    case 'fresh': return t(i18n)`up to date`
    case 'outdated': return t(i18n)`outdated — code changed since this was written`
    case 'missing': return t(i18n)`no description yet`
    case 'ignored': return t(i18n)`ignored — excluded by .atlas/config.json`
    case 'moved': return t(i18n)`moved`
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
    <h1 className="path">
      {crumbs.map((c, i) => (
        <span key={c.path}>
          {i > 0 && ' / '}
          {i === crumbs.length - 1 ? (
            <span>{c.label}</span>
          ) : (
            <a className="seg" href={'#' + encodeURI(c.path)}>{c.label}</a>
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
    <span className="chips-wrap">
      <span
        ref={ref}
        className={'chips' + (collapsed ? ' chips-collapsed' : '')}
        style={collapsed && maxH ? { '--chips-max-h': `${maxH}px` } as CSSProperties : undefined}
      >
        {items.map((p) => (
          <a key={p} className="rel-chip" href={'#' + encodeURI(p)}>{p}</a>
        ))}
      </span>
      {hidden > 0 && (
        <button type="button" className="rel-more" onClick={() => setExpanded((e) => !e)}>
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
    <div className="relations">
      {deps.length > 0 && (
        <div className="rel-row"><span className="rel-label">{t(i18n)`uses →`}</span><RelationChips items={deps} /></div>
      )}
      {dependents.length > 0 && (
        <div className="rel-row"><span className="rel-label">{t(i18n)`← used by`}</span><RelationChips items={dependents} /></div>
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
  useEffect(() => {
    const el = ref.current
    if (!el) return
    el.innerHTML = node.html ?? ''
    linkifyPaths(el, node, nodesByPath)
    annotateGlossary(el, glossary)
    renderMermaidIn(el)
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
    <div className="editor">
      <div className="editor-file"><code>{noteFileFor(node)}</code></div>
      <textarea
        autoFocus
        spellCheck={false}
        value={text}
        placeholder={t(i18n)`Markdown note for this path…`}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={onKey}
      />
      <div className="editor-bar">
        <button className="btn primary" onClick={save} disabled={busy}>
          {busy ? t(i18n)`saving…` : t(i18n)`save & stamp`}
        </button>
        <button className="btn" onClick={onClose} disabled={busy}>{t(i18n)`cancel`}</button>
        <span className="editor-hint">{t(i18n)`⌘⏎ save · esc cancel`}</span>
        {error && <span className="editor-error">{error}</span>}
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
    <div className="doc">
      <div className="crumb">{node.type === 'dir' ? t(i18n)`directory` : t(i18n)`file`}</div>
      <Breadcrumb node={node} repoName={repoName} />
      <div className="state-row">
        <div className={'state ' + node.status}>
          <span className={'dot ' + node.status} />
          {stateLabel(node.status, i18n)}
          {node.stamped ? ` · ${t(i18n)`stamped`} ${new Date(node.stamped).toLocaleDateString(i18n.locale)}` : ''}
        </div>
        {dive && (
          <a className="btn start-read" href={'#' + encodeURI(dive)} title={dive}>
            {t(i18n)`start reading ↘`}
          </a>
        )}
        {live && !editing && node.status !== 'ignored' && (
          <button className="btn edit" onClick={() => setEditing(true)}>
            {node.source ? t(i18n)`edit` : t(i18n)`write note`}
          </button>
        )}
      </div>
      <Relations node={node} rel={rel} nodesByPath={nodesByPath} />
      {editing ? (
        <Editor node={node} onClose={() => setEditing(false)} />
      ) : node.html ? (
        <Prose node={node} nodesByPath={nodesByPath} glossary={glossary} />
      ) : (
        <div className="empty">
          <Trans>
            No note for this path. Write one at <code>{noteFileFor(node)}</code> and run{' '}
            <code>repo-atlas stamp</code>.
          </Trans>
        </div>
      )}
      {!editing && (prev !== null || next !== null) && (
        <nav className="read-nav">
          {prev !== null ? (
            <a className="read-link prev" href={'#' + encodeURI(prev)} title={prev || '(root)'}>
              <span className="read-dir">{t(i18n)`← prev`}</span>
              <span className="read-target">{shortLabel(prev, repoName)}</span>
            </a>
          ) : <span className="read-spacer" />}
          <button className="read-link toc" onClick={onContents}>
            <span className="read-dir">{t(i18n)`contents`}</span>
            <span className="read-target">
              {shortLabel(node.type === 'dir' ? node.path : parentOf(node.path), repoName)}
            </span>
          </button>
          {next !== null ? (
            <a className="read-link next" href={'#' + encodeURI(next)} title={next}>
              <span className="read-dir">{t(i18n)`next →`}</span>
              <span className="read-target">{shortLabel(next, repoName)}</span>
            </a>
          ) : <span className="read-spacer" />}
        </nav>
      )}
    </div>
  )
}