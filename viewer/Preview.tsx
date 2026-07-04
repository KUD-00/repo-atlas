import { useEffect, useRef, useState } from 'react'
import { t } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import { Code, FileDiff, TableOfContents, PanelRightClose } from 'lucide-react'
import type { TreeNode } from '../src/types'
import { languageFor } from './lib'
import { TocView, baseFor } from './Toc'

export type PanelMode = 'code' | 'diff' | 'toc'

export interface CodeJump {
  path: string
  line: number
  endLine: number
  seq: number
}

/** The right-hand panel: one surface, three ways of looking at the current
 * page — the source itself, what changed since the note's anchor, or the
 * contents of the book (base point) the page belongs to. */
export function PanelPane({
  node, nodesByPath, basePoints, repoName, mode, onMode, onCollapse, jump,
}: {
  node: TreeNode
  nodesByPath: Map<string, TreeNode>
  basePoints: string[]
  repoName: string
  mode: PanelMode
  onMode: (m: PanelMode) => void
  onCollapse: () => void
  jump: CodeJump | null
}) {
  const { i18n } = useLingui()
  const isDir = node.type === 'dir'
  const effective: PanelMode = isDir ? 'toc' : mode
  const tab = (m: PanelMode, icon: React.ReactNode, label: string) => (
    <button
      className={'pv-tab' + (effective === m ? ' on' : '')}
      disabled={isDir && m !== 'toc'}
      onClick={() => onMode(m)}
    >
      {icon}
      {label}
    </button>
  )
  const base = baseFor(node.path, basePoints)
  return (
    <section className="preview">
      <div className="pv-tabs">
        {tab('code', <Code />, t(i18n)`Code`)}
        {tab('diff', <FileDiff />, t(i18n)`Changes`)}
        {tab('toc', <TableOfContents />, t(i18n)`Contents`)}
        <span className="pv-tabs-spacer" />
        <button className="pv-icon" title={t(i18n)`collapse panel`} onClick={onCollapse}>
          <PanelRightClose />
        </button>
      </div>
      {effective === 'code' && <CodeView path={node.path} jump={jump} />}
      {effective === 'diff' && <DiffView path={node.path} status={node.status} />}
      {effective === 'toc' && (
        <>
          <div className="pv-head">
            <span className="pv-name">{base || repoName}</span>
            <span className="pv-meta">{t(i18n)`reading order`}</span>
          </div>
          <div className="pv-body">
            <TocView node={node} nodesByPath={nodesByPath} basePoints={basePoints} repoName={repoName} />
          </div>
        </>
      )}
    </section>
  )
}

type CodeState =
  | { kind: 'loading' }
  | { kind: 'binary' }
  | { kind: 'unavailable' }
  | { kind: 'text'; text: string; truncated: boolean }

function CodeView({ path, jump }: { path: string; jump: CodeJump | null }) {
  const { i18n } = useLingui()
  const [state, setState] = useState<CodeState>({ kind: 'loading' })
  const bodyRef = useRef<HTMLDivElement>(null)
  const appliedSeq = useRef(0)

  useEffect(() => {
    if (!jump || jump.path !== path || state.kind !== 'text') return
    if (jump.seq === appliedSeq.current) return
    const body = bodyRef.current
    const pre = body?.querySelector('pre')
    if (!body || !pre) return
    appliedSeq.current = jump.seq
    const cs = getComputedStyle(pre)
    const lineHeight = parseFloat(cs.lineHeight)
    const y = parseFloat(cs.paddingTop) + (jump.line - 1) * lineHeight
    body.scrollTo({ top: Math.max(0, y - body.clientHeight / 3), behavior: 'smooth' })
    pre.style.position = 'relative'
    pre.querySelector('.pv-mark')?.remove()
    const mark = document.createElement('div')
    mark.className = 'pv-mark'
    mark.style.top = y + 'px'
    mark.style.height = (Math.max(jump.endLine, jump.line) - jump.line + 1) * lineHeight + 'px'
    pre.appendChild(mark)
  }, [jump, path, state])

  useEffect(() => {
    let alive = true
    setState({ kind: 'loading' })
    fetch('raw?p=' + encodeURIComponent(path))
      .then(async (res) => {
        if (!res.ok) throw new Error('http ' + res.status)
        if (res.headers.get('x-atlas-binary')) return { kind: 'binary' as const }
        return {
          kind: 'text' as const,
          text: await res.text(),
          truncated: Boolean(res.headers.get('x-atlas-truncated')),
        }
      })
      .catch(() => ({ kind: 'unavailable' as const }))
      .then((next) => alive && setState(next))
    return () => { alive = false }
  }, [path])

  const lang = languageFor(path)
  const meta =
    state.kind === 'text'
      ? `${state.text.split('\n').length} ${t(i18n)`lines`}` +
        (state.truncated ? ` · ${t(i18n)`truncated`}` : '') +
        (lang ? ` · ${lang}` : '')
      : ''

  return (
    <>
      <div className="pv-head">
        <span className="pv-name">{path}</span>
        <span className="pv-meta">{meta}</span>
      </div>
      <div className="pv-body" ref={bodyRef}>
        {state.kind === 'loading' && <div className="empty">{t(i18n)`loading…`}</div>}
        {state.kind === 'binary' && <div className="empty">{t(i18n)`binary file — no preview`}</div>}
        {state.kind === 'unavailable' && (
          <div className="empty">
            <Trans>
              no preview — file contents are served by <code>repo-atlas serve</code>; the static
              build only carries descriptions
            </Trans>
          </div>
        )}
        {state.kind === 'text' && <CodeBlock text={state.text} lang={lang} />}
      </div>
    </>
  )
}

function CodeBlock({ text, lang }: { text: string; lang: string | null }) {
  const hljs = window.hljs
  if (lang && hljs?.getLanguage(lang)) {
    const html = hljs.highlight(text, { language: lang, ignoreIllegals: true }).value
    return (
      <pre>
        <code className="hljs" dangerouslySetInnerHTML={{ __html: html }} />
      </pre>
    )
  }
  return (
    <pre>
      <code className="hljs">{text}</code>
    </pre>
  )
}

type DiffState =
  | { kind: 'loading' }
  | { kind: 'no-anchor' }
  | { kind: 'clean'; anchor: string }
  | { kind: 'diff'; text: string; anchor: string }
  | { kind: 'unavailable' }

function DiffView({ path, status }: { path: string; status: TreeNode['status'] }) {
  const { i18n } = useLingui()
  const [state, setState] = useState<DiffState>({ kind: 'loading' })

  useEffect(() => {
    let alive = true
    setState({ kind: 'loading' })
    fetch('diff?p=' + encodeURIComponent(path))
      .then(async (res) => {
        if (!res.ok) throw new Error('http ' + res.status)
        if (res.headers.get('x-atlas-no-anchor')) return { kind: 'no-anchor' as const }
        const anchor = res.headers.get('x-atlas-anchor') ?? ''
        const text = await res.text()
        return text.trim()
          ? { kind: 'diff' as const, text, anchor }
          : { kind: 'clean' as const, anchor }
      })
      .catch(() => ({ kind: 'unavailable' as const }))
      .then((next) => alive && setState(next))
    return () => { alive = false }
  }, [path])

  const counts =
    state.kind === 'diff'
      ? state.text.split('\n').reduce(
          (acc, l) => {
            if (l.startsWith('+') && !l.startsWith('+++')) acc.add++
            else if (l.startsWith('-') && !l.startsWith('---')) acc.del++
            return acc
          },
          { add: 0, del: 0 },
        )
      : null

  return (
    <>
      <div className="pv-head">
        <span className="pv-name">{path}</span>
        <span className="pv-meta">
          {(state.kind === 'diff' || state.kind === 'clean') &&
            t(i18n)`since ${state.anchor} (note's anchor)`}
          {counts && (
            <>
              {' · '}
              <span className="d-count-add">+{counts.add}</span>{' '}
              <span className="d-count-del">−{counts.del}</span>
            </>
          )}
        </span>
      </div>
      <div className="pv-body">
        {state.kind === 'loading' && <div className="empty">{t(i18n)`loading…`}</div>}
        {state.kind === 'no-anchor' && (
          <div className="empty">{t(i18n)`no anchor — this note has never been stamped`}</div>
        )}
        {state.kind === 'clean' && (
          <div className="empty">
            {status === 'outdated'
              ? t(i18n)`content hash changed but git shows no diff against the anchor`
              : t(i18n)`no changes since the note was stamped`}
          </div>
        )}
        {state.kind === 'unavailable' && (
          <div className="empty">
            <Trans>
              no diff — change review needs <code>repo-atlas serve</code> (the static build has
              no git access)
            </Trans>
          </div>
        )}
        {state.kind === 'diff' && <DiffBlock text={state.text} />}
      </div>
    </>
  )
}

function DiffBlock({ text }: { text: string }) {
  const lines = text.replace(/\n$/, '').split('\n')
  const cls = (l: string) => {
    if (l.startsWith('@@')) return 'd-hunk'
    if (/^(diff |index |--- |\+\+\+ |new file|deleted file|similarity|rename )/.test(l)) return 'd-meta'
    if (l.startsWith('+')) return 'd-add'
    if (l.startsWith('-')) return 'd-del'
    return 'd-ctx'
  }
  return (
    <pre className="diff">
      {lines.map((l, i) => (
        <div key={i} className={'d-line ' + cls(l)}>
          {l || ' '}
        </div>
      ))}
    </pre>
  )
}
