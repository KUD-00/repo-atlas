import { useEffect, useMemo, useState } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import type { AtlasPayload } from '../src/types'
import { activateLocale, type AppLocale, getStoredLocale } from './i18n'
import { indexTree, ancestorsOf, buildRelationIndex } from './lib'
import { Tree } from './Tree'
import { DocPane } from './Doc'
import { PreviewPane } from './Preview'
import { ChatDock } from './Chat'
import { SettingsButton, SettingsDialog } from './Settings'

function useRoute(nodesByPath: Map<string, { path: string }>) {
  const read = () => {
    const p = decodeURI(location.hash.slice(1))
    return nodesByPath.has(p) ? p : ''
  }
  const [path, setPath] = useState(read)
  useEffect(() => {
    const onChange = () => setPath(read())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [nodesByPath])
  const navigate = (p: string) => {
    if (decodeURI(location.hash.slice(1)) !== p) {
      history.pushState(null, '', p ? '#' + encodeURI(p) : location.pathname + location.search)
    }
    setPath(p)
  }
  return [path, navigate] as const
}

export function App({ data }: { data: AtlasPayload }) {
  const { i18n } = useLingui()
  const nodesByPath = useMemo(() => indexTree(data.tree), [data])
  const rel = useMemo(() => buildRelationIndex(data.graph), [data])
  const [path, navigate] = useRoute(nodesByPath)
  const [expanded, setExpanded] = useState(() => new Set(ancestorsOf(path)))
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string | null>(null)
  const [showIgnored, setShowIgnored] = useState(false)
  const [sortMode, setSortMode] = useState<'az' | 'read'>('az')
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [locale, setLocale] = useState<AppLocale>(getStoredLocale)

  useEffect(() => {
    setExpanded((prev) => {
      const next = new Set(prev)
      for (const p of ancestorsOf(path)) next.add(p)
      return next
    })
    document.querySelector('.row.sel')?.scrollIntoView({ block: 'nearest' })
  }, [path])

  const node = nodesByPath.get(path) ?? data.tree
  const agg = data.tree.agg!
  const fresh = agg.total - agg.outdated - agg.missing

  const toggle = (p: string) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(p) ? next.delete(p) : next.add(p)
      return next
    })

  const onLocale = (l: AppLocale) => {
    activateLocale(l)
    setLocale(l)
  }

  return (
    <>
      <aside>
        <div className="side-head">
          <h1>{data.repoName}</h1>
          <div className="meta">
            {data.commit ? `@ ${data.commit} · ` : ''}
            {new Date(data.generatedAt).toLocaleString(i18n.locale)}
          </div>
          <div className="side-foot">
            <div className="counts">
              <span><b>{fresh}</b> {t(i18n)`fresh`}</span>
              <span><b>{agg.outdated}</b> {t(i18n)`outdated`}</span>
              <span><b>{agg.missing}</b> {t(i18n)`missing`}</span>
            </div>
            <SettingsButton onClick={() => setSettingsOpen(true)} />
          </div>
        </div>
        <div className="filters">
          <input
            type="search"
            placeholder={t(i18n)`filter paths…`}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="filter-chips">
            <button
              className={'chip' + (statusFilter === 'outdated' ? ' on' : '')}
              onClick={() => setStatusFilter(statusFilter === 'outdated' ? null : 'outdated')}
            >
              {t(i18n)`outdated`}
            </button>
            <button
              className={'chip' + (statusFilter === 'missing' ? ' on' : '')}
              onClick={() => setStatusFilter(statusFilter === 'missing' ? null : 'missing')}
            >
              {t(i18n)`missing`}
            </button>
            <button
              className={'chip' + (showIgnored ? ' on' : '')}
              onClick={() => setShowIgnored(!showIgnored)}
              title={t(i18n)`also show config-excluded paths, greyed out`}
            >
              {t(i18n)`ignored`}
            </button>
            <button
              className="chip sort"
              onClick={() => setSortMode(sortMode === 'az' ? 'read' : 'az')}
              title={t(i18n)`tree layout: alphabetical or reading order`}
            >
              {sortMode === 'az' ? t(i18n)`sort: a–z` : t(i18n)`sort: reading`}
            </button>
          </div>
        </div>
        <nav>
          <Tree
            root={data.tree}
            selected={path}
            expanded={expanded}
            query={query.trim().toLowerCase()}
            statusFilter={statusFilter}
            showIgnored={showIgnored}
            sortMode={sortMode}
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
      <ChatDock currentPath={path} />
      {settingsOpen && (
        <SettingsDialog
          locale={locale}
          onLocale={onLocale}
          onClose={() => setSettingsOpen(false)}
        />
      )}
    </>
  )
}