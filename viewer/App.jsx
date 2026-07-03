import { useEffect, useMemo, useState } from 'react'
import { indexTree, ancestorsOf, buildRelationIndex } from './lib.js'
import { Tree } from './Tree.jsx'
import { DocPane } from './Doc.jsx'
import { PreviewPane } from './Preview.jsx'

/** Selected path lives in the URL hash: deep-linkable, back/forward work. */
function useRoute(nodesByPath) {
  const read = () => {
    const p = decodeURI(location.hash.slice(1))
    return nodesByPath.has(p) ? p : ''
  }
  const [path, setPath] = useState(read)
  useEffect(() => {
    const onChange = () => setPath(read())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  const navigate = (p) => {
    if (decodeURI(location.hash.slice(1)) !== p) {
      // pushState (not location.hash=) so navigation does not scroll-jump
      history.pushState(null, '', p ? '#' + encodeURI(p) : location.pathname + location.search)
    }
    setPath(p)
  }
  return [path, navigate]
}

export function App({ data }) {
  const nodesByPath = useMemo(() => indexTree(data.tree), [data])
  const rel = useMemo(() => buildRelationIndex(data.graph), [data])
  const [path, navigate] = useRoute(nodesByPath)
  const [expanded, setExpanded] = useState(() => new Set(ancestorsOf(path)))
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState(null)

  // whatever the route says, its ancestors must be open in the tree
  useEffect(() => {
    setExpanded((prev) => {
      const next = new Set(prev)
      for (const p of ancestorsOf(path)) next.add(p)
      return next
    })
    document.querySelector('.row.sel')?.scrollIntoView({ block: 'nearest' })
  }, [path])

  const node = nodesByPath.get(path) ?? data.tree
  const agg = data.tree.agg

  const toggle = (p) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(p) ? next.delete(p) : next.add(p)
      return next
    })

  return (
    <>
      <aside>
        <div className="side-head">
          <h1>{data.repoName}</h1>
          <div className="meta">
            {data.commit ? `@ ${data.commit} · ` : ''}
            {new Date(data.generatedAt).toLocaleString()}
          </div>
          <div className="counts">
            <span><b>{agg.total - agg.outdated - agg.missing}</b> fresh</span>
            <span><b>{agg.outdated}</b> outdated</span>
            <span><b>{agg.missing}</b> missing</span>
          </div>
        </div>
        <div className="filters">
          <input
            type="search"
            placeholder="filter paths…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {['outdated', 'missing'].map((st) => (
            <button
              key={st}
              className={'chip' + (statusFilter === st ? ' on' : '')}
              onClick={() => setStatusFilter(statusFilter === st ? null : st)}
            >
              {st}
            </button>
          ))}
        </div>
        <nav>
          <Tree
            root={data.tree}
            selected={path}
            expanded={expanded}
            query={query.trim().toLowerCase()}
            statusFilter={statusFilter}
            onSelect={navigate}
            onToggle={toggle}
          />
        </nav>
      </aside>
      <main className={node.type === 'file' ? 'with-preview' : ''}>
        <div className="pane">
          <DocPane
            node={node}
            repoName={data.repoName}
            nodesByPath={nodesByPath}
            rel={rel}
            glossary={data.glossary}
          />
        </div>
        {node.type === 'file' && <PreviewPane path={node.path} />}
      </main>
    </>
  )
}
