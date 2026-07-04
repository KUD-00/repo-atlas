import { useEffect, useMemo, useRef, useState } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { PanelLeftClose, PanelLeftOpen, PanelRightOpen } from 'lucide-react'
import type { AtlasPayload } from '../src/types'
import { activateLocale, type AppLocale, getStoredLocale } from './i18n'
import { indexTree, ancestorsOf, buildRelationIndex, useCompact } from './lib'
import { Tree } from './Tree'
import { DocPane } from './Doc'
import { PanelPane, type CodeJump, type PanelMode } from './Preview'
import { ChatDock } from './Chat'
import { SettingsButton, SettingsDialog } from './Settings'

const PV_ICON =
  'pv-icon flex items-center justify-center w-[26px] h-[26px] border-none rounded-md bg-transparent text-muted cursor-pointer p-0 shrink-0 hover:text-accent hover:bg-[#3d6b540d] [&_svg]:w-4 [&_svg]:h-4'
const CHIP =
  'chip text-[0.7rem] py-0.5 px-2 rounded-full border border-border bg-transparent text-muted cursor-pointer whitespace-nowrap'
const CHIP_ON = 'border-accent text-accent bg-[#3d6b540f]'

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
  const compact = useCompact()
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
  const [sideOpen, setSideOpen] = useState(
    () => !(typeof window !== 'undefined' && window.matchMedia('(max-width: 768px)').matches),
  )
  const [panelOpen, setPanelOpen] = useState(
    () => !(typeof window !== 'undefined' && window.matchMedia('(max-width: 768px)').matches),
  )
  const [panelMode, setPanelMode] = useState<PanelMode>('code')
  const [jump, setJump] = useState<CodeJump | null>(null)
  const jumpSeq = useRef(0)

  const onSelect = (p: string) => {
    navigate(p)
    if (compact) setSideOpen(false)
  }

  // single entry point for code-anchor jumps: reveal the panel, force code
  // mode, then hand the jump to CodeView as data (it may not be mounted yet)
  useEffect(() => {
    const onJump = (e: Event) => {
      const d = (e as CustomEvent<{ path: string; line: number; endLine?: number }>).detail
      setPanelOpen(true)
      setPanelMode('code')
      setJump({ path: d.path, line: d.line, endLine: d.endLine ?? d.line, seq: ++jumpSeq.current })
    }
    window.addEventListener('atlas-code-jump', onJump)
    return () => window.removeEventListener('atlas-code-jump', onJump)
  }, [])

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

  const mainCols = compact
    ? 'grid-cols-1'
    : panelOpen
      ? 'grid-cols-[minmax(0,1fr)_minmax(320px,45%)] min-[1100px]:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]'
      : 'grid-cols-[minmax(0,1fr)_auto]'

  const panelProps = {
    node,
    nodesByPath,
    basePoints: data.basePoints ?? [],
    repoName: data.repoName,
    mode: panelMode,
    onMode: setPanelMode,
    onCollapse: () => setPanelOpen(false),
    jump,
  }

  return (
    <>
      {!sideOpen && (
        <div className="flex flex-col items-center pt-2.5 bg-panel w-10 border-r border-border">
          <button className={PV_ICON} title={t(i18n)`expand sidebar`} onClick={() => setSideOpen(true)}>
            <PanelLeftOpen />
          </button>
        </div>
      )}
      {compact && sideOpen && (
        <div
          className="fixed inset-0 z-30 bg-[#00000033]"
          onClick={() => setSideOpen(false)}
          aria-hidden
        />
      )}
      <aside
        hidden={!compact && !sideOpen}
        className={
          compact
            ? 'fixed inset-y-0 left-0 z-40 flex flex-col min-w-0 min-h-0 w-[min(340px,85vw)] border-r border-border bg-panel transition-transform duration-200 ease-out ' +
              (sideOpen ? 'translate-x-0' : '-translate-x-full pointer-events-none')
            : 'w-[340px] border-r border-border bg-panel flex flex-col min-w-0 min-h-0 [hidden]:hidden'
        }
      >
        <div className="px-4 pt-3.5 pb-2.5 border-b border-border">
          <div className="flex items-center justify-between gap-2">
            <h1 className="text-[0.95rem] font-semibold">{data.repoName}</h1>
            <button className={PV_ICON} title={t(i18n)`collapse sidebar`} onClick={() => setSideOpen(false)}>
              <PanelLeftClose />
            </button>
          </div>
          <div className="text-[0.72rem] text-muted mt-0.5">
            {data.commit ? `@ ${data.commit} · ` : ''}
            {new Date(data.generatedAt).toLocaleString(i18n.locale)}
          </div>
          <div className="flex items-end justify-between gap-2 mt-2">
            <div className="flex gap-2.5 text-[0.72rem] text-muted flex-wrap [&_b]:text-text [&_b]:font-semibold">
              <span><b>{fresh}</b> {t(i18n)`fresh`}</span>
              <span><b>{agg.outdated}</b> {t(i18n)`outdated`}</span>
              <span><b>{agg.missing}</b> {t(i18n)`missing`}</span>
            </div>
            <SettingsButton onClick={() => setSettingsOpen(true)} />
          </div>
        </div>
        <div className="px-3 py-2 border-b border-border flex flex-col gap-1.5">
          <input
            type="search"
            className="w-full min-w-0 font-inherit text-[0.8rem] py-1 px-2 border border-border rounded-md bg-bg text-text focus:outline-none focus:border-accent"
            placeholder={t(i18n)`filter paths…`}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="flex gap-1.5 flex-wrap">
            <button
              className={CHIP + (statusFilter === 'outdated' ? ' ' + CHIP_ON : '')}
              onClick={() => setStatusFilter(statusFilter === 'outdated' ? null : 'outdated')}
            >
              {t(i18n)`outdated`}
            </button>
            <button
              className={CHIP + (statusFilter === 'missing' ? ' ' + CHIP_ON : '')}
              onClick={() => setStatusFilter(statusFilter === 'missing' ? null : 'missing')}
            >
              {t(i18n)`missing`}
            </button>
            <button
              className={CHIP + (showIgnored ? ' ' + CHIP_ON : '')}
              onClick={() => setShowIgnored(!showIgnored)}
              title={t(i18n)`also show config-excluded paths, greyed out`}
            >
              {t(i18n)`ignored`}
            </button>
            <button
              className={CHIP + ' sort'}
              onClick={() => setSortMode(sortMode === 'az' ? 'read' : 'az')}
              title={t(i18n)`tree layout: alphabetical or reading order`}
            >
              {sortMode === 'az' ? t(i18n)`sort: a–z` : t(i18n)`sort: reading`}
            </button>
          </div>
        </div>
        <nav className="flex-1 min-h-0 overflow-auto px-1.5 pt-2 pb-6">
          <Tree
            root={data.tree}
            selected={path}
            expanded={expanded}
            query={query.trim().toLowerCase()}
            statusFilter={statusFilter}
            showIgnored={showIgnored}
            sortMode={sortMode}
            onSelect={onSelect}
            onToggle={toggle}
          />
        </nav>
      </aside>
      <main className={'min-w-0 min-h-0 grid overflow-hidden ' + mainCols}>
        <div className="overflow-auto min-w-0">
          <DocPane
            node={node}
            repoName={data.repoName}
            nodesByPath={nodesByPath}
            rel={rel}
            glossary={data.glossary}
            onContents={() => {
              setPanelOpen(true)
              setPanelMode('toc')
            }}
          />
        </div>
        {!compact && panelOpen && <PanelPane {...panelProps} />}
        {!compact && !panelOpen && (
          <div className="flex flex-col items-center pt-2.5 bg-panel w-10 border-l border-border">
            <button className={PV_ICON} title={t(i18n)`expand panel`} onClick={() => setPanelOpen(true)}>
              <PanelRightOpen />
            </button>
          </div>
        )}
        {compact && !panelOpen && (
          <div className="fixed right-0 top-1/2 -translate-y-1/2 z-10 flex flex-col items-center pt-2.5 bg-panel w-10 border-l border-border rounded-l-lg shadow-[0_2px_8px_#00000012]">
            <button className={PV_ICON} title={t(i18n)`expand panel`} onClick={() => setPanelOpen(true)}>
              <PanelRightOpen />
            </button>
          </div>
        )}
      </main>
      {compact && panelOpen && <PanelPane {...panelProps} overlay />}
      <ChatDock currentPath={path} compact={compact} />
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