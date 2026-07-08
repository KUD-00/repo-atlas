import { useEffect, useRef, useState } from 'react'
import { t } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import { Code, FileDiff, TableOfContents, PanelRightClose } from 'lucide-react'
import type { TreeNode } from '../src/types'
import { languageFor } from './lib'
import { TocView, baseFor } from './Toc'

const PV_ICON =
  'pv-icon flex items-center justify-center w-[26px] h-[26px] border-none rounded-md bg-transparent text-muted cursor-pointer p-0 shrink-0 hover:text-accent hover:bg-[#3d6b540d] [&_svg]:w-4 [&_svg]:h-4'
const EMPTY = 'text-muted text-[0.9rem] mt-2 p-4 [&_code]:bg-[#00000009] [&_code]:py-[0.1em] [&_code]:px-[0.4em] [&_code]:rounded [&_code]:text-[0.85em]'

export type PanelMode = 'code' | 'diff' | 'toc'

export interface CodeJump {
  path: string
  line: number
  endLine: number
  seq: number
}

/** This-page outline: the current note's own headings (## / ### / ####) + the
 * 进阶细节 callout, so you can see the page's structure at a glance and jump.
 * Clicking scrolls the main `.prose` doc to that heading. */
function PageOutline({ node }: { node: TreeNode }) {
  const src = node.source ?? ''
  const items: { depth: number; text: string }[] = []
  for (const line of src.split('\n')) {
    const m = /^(#{2,4})\s+(.+)$/.exec(line)
    if (m) {
      const text = m[2].replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').replace(/[*`]/g, '').trim()
      if (text) items.push({ depth: m[1].length, text })
    } else if (line.includes('class="callout"')) {
      items.push({ depth: 4, text: '进阶细节' })
    }
  }
  if (items.length < 2) return null
  const jump = (text: string) => {
    const prose = document.querySelector('.prose')
    if (!prose) return
    const key = text.slice(0, 12)
    for (const h of prose.querySelectorAll('h1,h2,h3,h4,.callout-toggle')) {
      if ((h.textContent ?? '').replace(/^💡\s*/u, '').trim().startsWith(key)) {
        h.scrollIntoView({ behavior: 'smooth', block: 'start' })
        return
      }
    }
    if (text === '进阶细节') prose.querySelector('.callout')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
  return (
    <div className="border-b border-border py-2 shrink-0 max-h-[45%] overflow-auto">
      <div className="text-[0.72rem] text-muted px-4 pb-1">本页大纲</div>
      {items.map((it, i) => (
        <button
          key={i}
          className="block w-full text-left text-[0.8rem] py-[3px] px-4 bg-transparent border-none cursor-pointer text-text hover:text-accent hover:bg-[#3d6b540d] truncate"
          style={{ paddingLeft: `${16 + (it.depth - 2) * 12}px` }}
          onClick={() => jump(it.text)}
        >
          {it.text}
        </button>
      ))}
    </div>
  )
}

/** The right-hand panel: one surface, three ways of looking at the current
 * page — the source itself, what changed since the note's anchor, or the
 * contents of the book (base point) the page belongs to. */
export function PanelPane({
  node, nodesByPath, basePoints, repoName, mode, onMode, onCollapse, jump, overlay, closing, onCloseEnd,
}: {
  node: TreeNode
  nodesByPath: Map<string, TreeNode>
  basePoints: string[]
  repoName: string
  mode: PanelMode
  onMode: (m: PanelMode) => void
  onCollapse: () => void
  jump: CodeJump | null
  overlay?: boolean
  closing?: boolean
  onCloseEnd?: () => void
}) {
  const { i18n } = useLingui()
  const isDir = node.type === 'dir'
  const effective: PanelMode = isDir ? 'toc' : mode
  const tab = (m: PanelMode, icon: React.ReactNode, label: string) => (
    <button
      className={
        'pv-tab flex items-center gap-[5px] font-inherit text-[0.76rem] border border-transparent rounded-[7px] bg-transparent text-muted cursor-pointer py-1 px-[9px] [&_svg]:w-3.5 [&_svg]:h-3.5 hover:enabled:text-text disabled:opacity-40 disabled:cursor-default' +
        (effective === m ? ' on text-text bg-panel border-border' : '')
      }
      disabled={isDir && m !== 'toc'}
      onClick={() => onMode(m)}
    >
      {icon}
      {label}
    </button>
  )
  const base = baseFor(node.path, basePoints)
  return (
    <section
      className={
        overlay
          ? 'panel-drawer fixed inset-y-0 right-0 z-50 w-[min(480px,92vw)] flex flex-col min-h-0 overflow-hidden bg-panel border-l border-border shadow-[-4px_0_24px_#00000022] ' +
            (closing
              ? 'animate-[drawer-out-right_0.16s_ease_forwards]'
              : 'animate-[drawer-in-right_0.22s_ease]')
          : 'border-l border-border bg-panel flex flex-col min-h-0 overflow-hidden'
      }
      onAnimationEnd={(e) => {
        if (closing && e.target === e.currentTarget) onCloseEnd?.()
      }}
    >
      <div className="flex items-center gap-0.5 py-1.5 px-2 border-b border-border bg-bg">
        {tab('code', <Code />, t(i18n)`Code`)}
        {tab('diff', <FileDiff />, t(i18n)`Changes`)}
        {tab('toc', <TableOfContents />, t(i18n)`Contents`)}
        <span className="flex-1" />
        <button className={PV_ICON} title={t(i18n)`collapse panel`} onClick={onCollapse}>
          <PanelRightClose />
        </button>
      </div>
      {effective === 'code' && <CodeView path={node.path} jump={jump} />}
      {effective === 'diff' && <DiffView path={node.path} status={node.status} />}
      {effective === 'toc' && (
        <>
          <PageOutline node={node} />
          <div className="flex items-baseline gap-2.5 py-2.5 px-4 border-b border-border text-[0.78rem] shrink-0">
            <span className="font-semibold overflow-hidden text-ellipsis whitespace-nowrap">{base || repoName}</span>
            <span className="text-muted shrink-0 ml-auto text-[0.72rem]">{t(i18n)`reading order`}</span>
          </div>
          <div className="flex-1 min-h-0 overflow-auto">
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
      <div className="flex items-baseline gap-2.5 py-2.5 px-4 border-b border-border text-[0.78rem] shrink-0">
        <span className="font-semibold overflow-hidden text-ellipsis whitespace-nowrap">{path}</span>
        <span className="text-muted shrink-0 ml-auto text-[0.72rem]">{meta}</span>
      </div>
      <div className="flex-1 min-h-0 overflow-auto pv-body" ref={bodyRef}>
        {state.kind === 'loading' && <div className={EMPTY}>{t(i18n)`loading…`}</div>}
        {state.kind === 'binary' && <div className={EMPTY}>{t(i18n)`binary file — no preview`}</div>}
        {state.kind === 'unavailable' && (
          <div className={EMPTY}>
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
      <pre className="m-0 py-3.5 px-4 pb-12 text-[0.78rem] leading-[1.55]">
        <code className="hljs" dangerouslySetInnerHTML={{ __html: html }} />
      </pre>
    )
  }
  return (
    <pre className="m-0 py-3.5 px-4 pb-12 text-[0.78rem] leading-[1.55]">
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
      <div className="flex items-baseline gap-2.5 py-2.5 px-4 border-b border-border text-[0.78rem] shrink-0">
        <span className="font-semibold overflow-hidden text-ellipsis whitespace-nowrap">{path}</span>
        <span className="text-muted shrink-0 ml-auto text-[0.72rem]">
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
      <div className="flex-1 min-h-0 overflow-auto pv-body">
        {state.kind === 'loading' && <div className={EMPTY}>{t(i18n)`loading…`}</div>}
        {state.kind === 'no-anchor' && (
          <div className={EMPTY}>{t(i18n)`no anchor — this note has never been stamped`}</div>
        )}
        {state.kind === 'clean' && (
          <div className={EMPTY}>
            {status === 'outdated'
              ? t(i18n)`content hash changed but git shows no diff against the anchor`
              : t(i18n)`no changes since the note was stamped`}
          </div>
        )}
        {state.kind === 'unavailable' && (
          <div className={EMPTY}>
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