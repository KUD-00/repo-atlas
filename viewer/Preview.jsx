import { useEffect, useState } from 'react'
import { languageFor } from './lib.js'

/** Right-hand source preview for files. Contents come from the dev server's
 * /raw endpoint (scan-scoped); the static build has no server, so the fetch
 * fails there and we show a hint instead. */
export function PreviewPane({ path }) {
  const [state, setState] = useState({ kind: 'loading' })

  useEffect(() => {
    let alive = true
    setState({ kind: 'loading' })
    fetch('raw?p=' + encodeURIComponent(path))
      .then(async (res) => {
        if (!res.ok) throw new Error('http ' + res.status)
        if (res.headers.get('x-atlas-binary')) return { kind: 'binary' }
        return {
          kind: 'text',
          text: await res.text(),
          truncated: Boolean(res.headers.get('x-atlas-truncated')),
        }
      })
      .catch(() => ({ kind: 'unavailable' }))
      .then((next) => alive && setState(next))
    return () => { alive = false }
  }, [path])

  const lang = languageFor(path)
  const meta =
    state.kind === 'text'
      ? `${state.text.split('\n').length} lines` +
        (state.truncated ? ' · truncated' : '') +
        (lang ? ' · ' + lang : '')
      : ''

  return (
    <section className="preview">
      <div className="pv-head">
        <span className="pv-name">{path}</span>
        <span className="pv-meta">{meta}</span>
      </div>
      <div className="pv-body">
        {state.kind === 'loading' && <div className="empty">loading…</div>}
        {state.kind === 'binary' && <div className="empty">binary file — no preview</div>}
        {state.kind === 'unavailable' && (
          <div className="empty">
            no preview — file contents are served by <code>repo-atlas serve</code>; the static
            build only carries descriptions
          </div>
        )}
        {state.kind === 'text' && <Code text={state.text} lang={lang} />}
      </div>
    </section>
  )
}

function Code({ text, lang }) {
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
