import { useEffect, useRef } from 'react'
import { linkifyPaths, renderMermaidIn, noteFileFor } from './lib.js'

const STATE_LABELS = {
  fresh: 'up to date',
  outdated: 'outdated — code changed since this was written',
  missing: 'no description yet',
}

/** Header breadcrumb: repo name = root; every ancestor segment navigates. */
function Breadcrumb({ node, repoName }) {
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

/** Markdown body, pre-rendered to HTML at build time. Path-linking and
 * mermaid rendering are DOM post-passes over the injected HTML. */
function Prose({ node, nodesByPath }) {
  const ref = useRef(null)
  useEffect(() => {
    const el = ref.current
    el.innerHTML = node.html
    linkifyPaths(el, node, nodesByPath)
    renderMermaidIn(el)
  }, [node, nodesByPath])
  return <div className="prose" ref={ref} />
}

export function DocPane({ node, repoName, nodesByPath }) {
  return (
    <div className="doc">
      <div className="crumb">{node.type === 'dir' ? 'directory' : 'file'}</div>
      <Breadcrumb node={node} repoName={repoName} />
      <div className={'state ' + node.status}>
        <span className={'dot ' + node.status} />
        {STATE_LABELS[node.status]}
        {node.stamped ? ` · stamped ${new Date(node.stamped).toLocaleDateString()}` : ''}
      </div>
      {node.html ? (
        <Prose node={node} nodesByPath={nodesByPath} />
      ) : (
        <div className="empty">
          No note for this path. Write one at <code>{noteFileFor(node)}</code> and run{' '}
          <code>repo-atlas stamp</code>.
        </div>
      )}
    </div>
  )
}
