import { useEffect, useMemo, useRef } from 'react'
import { linkifyPaths, renderMermaidIn, noteFileFor, relationsFor, annotateGlossary } from './lib.js'

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

/** Import relations derived from the code, not from the note: what this path
 * imports (grouped to package roots for dirs, exact for files) and who
 * imports it. Every chip navigates. */
function Relations({ node, rel, nodesByPath }) {
  const { deps, dependents } = useMemo(
    () => relationsFor(node, rel, nodesByPath),
    [node, rel, nodesByPath],
  )
  if (!deps.length && !dependents.length) return null
  const CAP = 24
  const Chips = ({ items }) => (
    <span className="chips">
      {items.slice(0, CAP).map((p) => (
        <a key={p} className="rel-chip" href={'#' + encodeURI(p)}>{p}</a>
      ))}
      {items.length > CAP && <span className="rel-more">+{items.length - CAP} more</span>}
    </span>
  )
  return (
    <div className="relations">
      {deps.length > 0 && (
        <div className="rel-row"><span className="rel-label">imports →</span><Chips items={deps} /></div>
      )}
      {dependents.length > 0 && (
        <div className="rel-row"><span className="rel-label">← imported by</span><Chips items={dependents} /></div>
      )}
    </div>
  )
}

/** Markdown body, pre-rendered to HTML at build time. Path-linking, glossary
 * annotation and mermaid rendering are DOM post-passes over the injected HTML. */
function Prose({ node, nodesByPath, glossary }) {
  const ref = useRef(null)
  useEffect(() => {
    const el = ref.current
    el.innerHTML = node.html
    linkifyPaths(el, node, nodesByPath)
    annotateGlossary(el, glossary)
    renderMermaidIn(el)
  }, [node, nodesByPath, glossary])
  return <div className="prose" ref={ref} />
}

export function DocPane({ node, repoName, nodesByPath, rel, glossary }) {
  return (
    <div className="doc">
      <div className="crumb">{node.type === 'dir' ? 'directory' : 'file'}</div>
      <Breadcrumb node={node} repoName={repoName} />
      <div className={'state ' + node.status}>
        <span className={'dot ' + node.status} />
        {STATE_LABELS[node.status]}
        {node.stamped ? ` · stamped ${new Date(node.stamped).toLocaleDateString()}` : ''}
      </div>
      <Relations node={node} rel={rel} nodesByPath={nodesByPath} />
      {node.html ? (
        <Prose node={node} nodesByPath={nodesByPath} glossary={glossary} />
      ) : (
        <div className="empty">
          No note for this path. Write one at <code>{noteFileFor(node)}</code> and run{' '}
          <code>repo-atlas stamp</code>.
        </div>
      )}
    </div>
  )
}
