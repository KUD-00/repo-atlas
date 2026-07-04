import { useEffect, useRef, useState } from 'react'
import { t } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import { languageFor } from './lib'

type PreviewState =
  | { kind: 'loading' }
  | { kind: 'binary' }
  | { kind: 'unavailable' }
  | { kind: 'text'; text: string; truncated: boolean }

export function PreviewPane({ path }: { path: string }) {
  const { i18n } = useLingui()
  const [state, setState] = useState<PreviewState>({ kind: 'loading' })
  const bodyRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const jump = (line: number, endLine: number, retried = false) => {
      const body = bodyRef.current
      const pre = body?.querySelector('pre')
      if (!body || !pre) {
        if (!retried) setTimeout(() => jump(line, endLine, true), 400)
        return
      }
      const cs = getComputedStyle(pre)
      const lineHeight = parseFloat(cs.lineHeight)
      const y = parseFloat(cs.paddingTop) + (line - 1) * lineHeight
      body.scrollTo({ top: Math.max(0, y - body.clientHeight / 3), behavior: 'smooth' })
      pre.style.position = 'relative'
      pre.querySelector('.pv-mark')?.remove()
      const mark = document.createElement('div')
      mark.className = 'pv-mark'
      mark.style.top = y + 'px'
      mark.style.height = (Math.max(endLine, line) - line + 1) * lineHeight + 'px'
      pre.appendChild(mark)
    }
    const onJump = (e: Event) => {
      const detail = (e as CustomEvent<{ path: string; line: number; endLine?: number }>).detail
      if (detail.path === path) jump(detail.line, detail.endLine ?? detail.line)
    }
    window.addEventListener('atlas-code-jump', onJump)
    return () => window.removeEventListener('atlas-code-jump', onJump)
  }, [path])

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
    <section className="preview">
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
        {state.kind === 'text' && <Code text={state.text} lang={lang} />}
      </div>
    </section>
  )
}

function Code({ text, lang }: { text: string; lang: string | null }) {
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