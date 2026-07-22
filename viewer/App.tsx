import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import {
  Code2,
  FlaskConical,
  Inbox,
  LibraryBig,
  MessageCircle,
  PanelLeftClose,
  PanelLeftOpen,
  PanelRightOpen,
  ShieldAlert,
} from 'lucide-react'
import {
  compactSidebarA11y,
  shouldRestoreCompactSidebarFocus,
} from '../src/audit-a11y'
import {
  domainAssurance,
  type AuditAction,
  type AuditViewMode,
} from '../src/audit-assurance'
import { localizeAuditPresentation } from '../src/audit-localization-presentation'
import { localizedDomainNavSuffix } from './audit-copy'
import {
  initialPanelOpen,
  shouldClosePanelOnPrimaryTransition,
} from '../src/audit-panel'
import {
  attentionRoute,
  auditRoute,
  auditUnitRoute,
  isNamespacedOrPathRoute,
  parseAuditRoute,
  parseAttentionRoute,
  primaryNavRoute,
  primaryViewForRoute,
  rememberPrimaryRoutes,
  securityUnitForConcept,
  type PrimaryView,
  type RememberedPrimaryRoutes,
} from '../src/audit-routes'
import type { AtlasPayload } from '../src/types'
import { activateLocale, type AppLocale, getStoredLocale } from './i18n'
import { indexTree, ancestorsOf, buildRelationIndex, useCompact } from './lib'
import { useLive } from './live'
import { Tree } from './Tree'
import { DocPane } from './Doc'
import { ConceptList, ConceptPane, conceptRoute, conceptSlugOf } from './Concept'
import { SecurityPane } from './Security'
import { TestAuditPane } from './TestAudit'
import { AuditNav } from './AuditNav'
import { isPrintScope, printScopeOf, PrintView } from './Print'
import { PanelPane, type CodeJump, type PanelMode } from './Preview'
import { ChatDock } from './Chat'
import { SettingsButton, SettingsDialog } from './Settings'
import { AttentionNav, AttentionPane } from './Attention'

const PV_ICON =
  'pv-icon flex items-center justify-center w-[26px] h-[26px] border-none rounded-md bg-transparent text-muted cursor-pointer p-0 shrink-0 hover:text-accent hover:bg-[#3d6b540d] [&_svg]:w-4 [&_svg]:h-4'
const TOPBAR_ICON =
  'flex items-center justify-center w-9 h-9 border-none rounded-md bg-transparent text-muted cursor-pointer p-0 shrink-0 hover:text-accent hover:bg-[#3d6b540d] [&_svg]:w-[18px] [&_svg]:h-[18px]'
const CHIP =
  'chip text-[0.7rem] py-0.5 px-2 rounded-full border border-border bg-transparent text-muted cursor-pointer whitespace-nowrap focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30'
const CHIP_ON = 'border-accent text-accent bg-[#3d6b540f]'
const PRIMARY_BTN =
  'w-full flex items-center gap-2 py-1.5 px-2 rounded-md border-none cursor-pointer font-inherit text-[0.8rem] text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30'
const PRIMARY = [
  ['attention', Inbox],
  ['code', Code2],
  ['concepts', LibraryBig],
  ['security', ShieldAlert],
  ['tests', FlaskConical],
] as const

function useRoute(valid: (route: string) => boolean) {
  const read = () => {
    const p = decodeURI(location.hash.slice(1))
    return valid(p) ? p : ''
  }
  const [path, setPath] = useState(read)
  useEffect(() => {
    const onChange = () => setPath(read())
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [valid])
  const navigate = (p: string) => {
    if (decodeURI(location.hash.slice(1)) !== p) {
      history.pushState(null, '', p ? '#' + encodeURI(p) : location.pathname + location.search)
    }
    setPath(p)
  }
  return [path, navigate] as const
}

function primaryLabel(view: PrimaryView, i18n: Parameters<typeof t>[0]): string {
  switch (view) {
    case 'attention':
      return t(i18n)`attention`
    case 'code':
      return t(i18n)`code`
    case 'concepts':
      return t(i18n)`concepts`
    case 'security':
      return t(i18n)`security`
    case 'tests':
      return t(i18n)`tests`
  }
}

export function App({ data: initialData }: { data: AtlasPayload }) {
  const { i18n } = useLingui()
  const compact = useCompact()
  const live = useLive()
  const [data, setData] = useState(initialData)
  const [locale, setLocale] = useState<AppLocale>(
    () => getStoredLocale(initialData.defaultLocale),
  )

  // live refresh, in place: when anything in the scan changes, serve emits a
  // change event and we swap in a fresh payload via setState. React re-renders
  // what differs — the page itself never reloads, so scroll position, panel
  // mode and tree state survive changes to unrelated files.
  useEffect(() => {
    if (!live) return
    const es = new EventSource('events')
    let cancelled = false
    es.addEventListener('reload', () => {
      fetch('data')
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => d && !cancelled && setData(d))
        .catch(() => {})
    })
    return () => {
      cancelled = true
      es.close()
    }
  }, [live])

  const nodesByPath = useMemo(() => indexTree(data.tree), [data])
  const rel = useMemo(() => buildRelationIndex(data.graph), [data])
  const concepts = data.concepts ?? []
  const conceptsBySlug = useMemo(() => new Map(concepts.map((c) => [c.slug, c])), [data])
  const artifacts = data.artifacts ?? {}
  const auditPresentation = useMemo(
    () => localizeAuditPresentation({
      locale,
      sourceLocale: data.auditSourceLocale ?? 'en',
      localizations: data.auditLocalizations ?? {},
      audits: data.audits ?? [],
      testAudits: data.testAudits ?? [],
      reviewCoverage: data.reviewCoverage,
    }),
    [locale, data.auditSourceLocale, data.auditLocalizations, data.audits, data.testAudits, data.reviewCoverage],
  )
  const audits = auditPresentation.audits
  const testAudits = auditPresentation.testAudits
  const reviewCoverage = auditPresentation.reviewCoverage
  const securityModel = useMemo(
    () => domainAssurance('security', reviewCoverage, audits),
    [reviewCoverage, audits],
  )
  const testModel = useMemo(
    () => domainAssurance('test', reviewCoverage, testAudits),
    [reviewCoverage, testAudits],
  )
  const localizedSecuritySuffix = useMemo(
    () => localizedDomainNavSuffix(i18n, securityModel),
    [i18n, securityModel],
  )
  const localizedTestSuffix = useMemo(
    () => localizedDomainNavSuffix(i18n, testModel),
    [i18n, testModel],
  )
  const [securityMode, setSecurityMode] = useState<AuditViewMode>('overview')
  const [testMode, setTestMode] = useState<AuditViewMode>('overview')
  const isRoute = useCallback(
    (p: string) => {
      const printScope = printScopeOf(p)
      if (printScope !== null) return isPrintScope(printScope, nodesByPath, conceptsBySlug, artifacts)
      // Reserved namespaces (audit:*, view:concepts, concept:*) win over path collisions.
      // Bare `security` is only Code when a real repo path exists.
      return isNamespacedOrPathRoute(
        p,
        (path) => nodesByPath.has(path),
        { security: audits, tests: testAudits },
        (slug) => conceptsBySlug.has(slug),
      )
    },
    [nodesByPath, conceptsBySlug, artifacts, audits, testAudits],
  )
  const [path, navigate] = useRoute(isRoute)

  // When there is human follow-up, make it the first thing a reader sees on a
  // bare URL. An explicit hash always wins, including a deliberate Code route.
  const initialAttentionRedirected = useRef(false)
  useEffect(() => {
    if (initialAttentionRedirected.current) return
    initialAttentionRedirected.current = true
    if (decodeURI(location.hash.slice(1)) !== '' || data.attention.summary.open === 0) return
    history.replaceState(null, '', '#' + encodeURI(attentionRoute()))
    window.dispatchEvent(new HashChangeEvent('hashchange'))
  }, [data.attention.summary.open])

  // Legacy `#security` → `#audit:security` only when it is not a real repo path.
  useEffect(() => {
    const raw = decodeURI(location.hash.slice(1))
    if (raw !== 'security' || nodesByPath.has('security')) return
    history.replaceState(null, '', '#' + encodeURI(auditRoute('security')))
    window.dispatchEvent(new HashChangeEvent('hashchange'))
  }, [nodesByPath])

  const primaryView = primaryViewForRoute(path, (p) => nodesByPath.has(p))
  const auditRouteInfo = parseAuditRoute(path)
  const attentionRouteInfo = parseAttentionRoute(path)
  const [remembered, setRemembered] = useState<RememberedPrimaryRoutes>(() => ({
    code: primaryView === 'code' ? path : '',
    concepts: primaryView === 'concepts' ? path || 'view:concepts' : 'view:concepts',
  }))

  useEffect(() => {
    setRemembered((prev) => rememberPrimaryRoutes(prev, path))
  }, [path])

  const [expanded, setExpanded] = useState(() => new Set(ancestorsOf(path)))
  // Code controls — isolated from Concepts / Security / Tests.
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string | null>(null)
  const [showIgnored, setShowIgnored] = useState(false)
  const [sortMode, setSortMode] = useState<'az' | 'read'>('az')
  // Concepts controls — isolated from Code.
  const [conceptQuery, setConceptQuery] = useState('')
  const [conceptStatusFilter, setConceptStatusFilter] = useState<string | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [sideOpen, setSideOpen] = useState(
    () => !(typeof window !== 'undefined' && window.matchMedia('(max-width: 768px)').matches),
  )
  // Desktop Code/Concepts open; operational entry and compact start closed.
  const [panelOpen, setPanelOpen] = useState(() =>
    initialPanelOpen(
      typeof window !== 'undefined' && window.matchMedia('(max-width: 768px)').matches,
      primaryView,
    ),
  )
  const [panelMode, setPanelMode] = useState<PanelMode>('code')
  const [panelClosing, setPanelClosing] = useState(false)
  const [jump, setJump] = useState<CodeJump | null>(null)
  const jumpSeq = useRef(0)
  const compactExpandRef = useRef<HTMLButtonElement>(null)
  const wasSideOpenRef = useRef(sideOpen)
  // Tracks primary view so operational entry closes the panel once.
  const prevPrimaryViewRef = useRef(primaryView)
  // Concept pages have no path of their own, so the panel needs a repo file to
  // show: the first file-typed source by default, then whatever code anchors jump to.
  // Audit jumps also land here; returning to overview must keep the chosen source.
  const [conceptCodePath, setConceptCodePath] = useState<string | null>(null)

  const concept = useMemo(() => {
    const slug = conceptSlugOf(path)
    return slug !== null ? conceptsBySlug.get(slug) : undefined
  }, [path, conceptsBySlug])

  const conceptAudit = useMemo(() => {
    if (!concept) return undefined
    return securityUnitForConcept(concept.slug, audits)
  }, [concept, audits])

  const conceptAttention = useMemo(() => {
    if (!concept) return undefined
    return data.attention.items.find((item) => item.slug === concept.slug)
  }, [concept, data.attention.items])

  useEffect(() => {
    if (!concept) return
    setConceptCodePath(concept.sources.find((s) => nodesByPath.get(s)?.type === 'file') ?? null)
    // keyed by route: a live data refresh must not reset a jump the reader followed
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path])

  const onSelect = (p: string) => {
    navigate(p)
    if (compact) setSideOpen(false)
  }

  const onPrimary = (view: PrimaryView) => {
    // Primary Security/Tests click resets that domain to overview and routes home.
    if (view === 'security') setSecurityMode('overview')
    if (view === 'tests') setTestMode('overview')
    onSelect(primaryNavRoute(view, remembered))
  }

  const headerDomainPresent =
    securityModel.unitRows.length > 0 || securityModel.portfolioState !== 'missing'
  const headerDomainAction = useMemo(
    (): AuditAction | null => securityModel.actions[0] ?? null,
    [securityModel],
  )

  const onHeaderDomainAction = (action: AuditAction) => {
    setSecurityMode(action.kind === 'coverage' ? 'gaps' : 'attention')
    if (action.unitSlug) {
      const route = auditUnitRoute('security', action.unitSlug)
      if (route) {
        onSelect(route)
        return
      }
    }
    onSelect(auditRoute('security'))
  }

  const onHeaderDomainShortcut = () => {
    if (headerDomainAction) {
      onHeaderDomainAction(headerDomainAction)
      return
    }
    setSecurityMode('overview')
    onSelect(auditRoute('security'))
  }

  // Compact drawer close (overlay / collapse / route select) returns focus to the
  // header expand control so keyboard users do not land in the inert drawer.
  useEffect(() => {
    if (shouldRestoreCompactSidebarFocus(compact, wasSideOpenRef.current, sideOpen)) {
      compactExpandRef.current?.focus()
    }
    wasSideOpenRef.current = sideOpen
  }, [compact, sideOpen])

  // single entry point for code-anchor jumps: reveal the panel, force code
  // mode, then hand the jump to CodeView as data (it may not be mounted yet)
  useEffect(() => {
    const onJump = (e: Event) => {
      const d = (e as CustomEvent<{ path: string; line: number; endLine?: number }>).detail
      setPanelClosing(false)
      setPanelOpen(true)
      setPanelMode('code')
      setConceptCodePath(d.path) // concept anchors jump across files — follow them
      setJump({ path: d.path, line: d.line, endLine: d.endLine ?? d.line, seq: ++jumpSeq.current })
    }
    window.addEventListener('atlas-code-jump', onJump)
    return () => window.removeEventListener('atlas-code-jump', onJump)
  }, [])

  // Close the generic panel only when first entering an operational view from
  // Code/Concepts. Moving among operations keeps an explicit reopen.
  useEffect(() => {
    const previous = prevPrimaryViewRef.current
    if (shouldClosePanelOnPrimaryTransition(previous, primaryView)) {
      if (compact) setPanelClosing(true)
      else setPanelOpen(false)
    }
    prevPrimaryViewRef.current = primaryView
  }, [primaryView, compact])

  useEffect(() => {
    setExpanded((prev) => {
      const next = new Set(prev)
      for (const p of ancestorsOf(path)) next.add(p)
      return next
    })
    document.querySelector('.row.sel')?.scrollIntoView({ block: 'nearest' })
  }, [path])

  // a page turn (prev/next, tree click, link) starts reading the NEW page from
  // its top — without this the doc pane keeps the previous page's scrollTop
  const docRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    docRef.current?.scrollTo({ top: 0 })
  }, [path])

  const node = nodesByPath.get(path) ?? data.tree
  const security = primaryView === 'security'
  const testsView = primaryView === 'tests'
  const conceptsView = primaryView === 'concepts'
  const attentionView = primaryView === 'attention'
  // for a concept page (or audit homes) the side panel shows the source a
  // code anchor jumped to (or the first file source); else it falls back to the root toc
  const panelNode = concept || attentionView || security || testsView || (conceptsView && !concept)
    ? (conceptCodePath !== null ? nodesByPath.get(conceptCodePath) : undefined) ?? data.tree
    : node
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

  // compact closes through the slide-out animation; desktop collapses instantly
  const closePanel = () => (compact ? setPanelClosing(true) : setPanelOpen(false))
  const openPanel = () => {
    setPanelClosing(false)
    setPanelOpen(true)
  }

  // print route: a chrome-less document view (cover, toc, sections, glossary)
  // that auto-opens the browser's print dialog once rendering settles
  const printScope = printScopeOf(path)
  if (printScope !== null) {
    return (
      <PrintView
        scope={printScope}
        data={data}
        nodesByPath={nodesByPath}
        conceptsBySlug={conceptsBySlug}
      />
    )
  }

  // artifacts hang off the PAGE (path note or concept page), not the panel's
  // node — key: repo path verbatim, or concepts/<slug> for concept pages
  const pageKey = concept ? 'concepts/' + concept.slug : path
  const panelProps = {
    node: panelNode,
    nodesByPath,
    basePoints: data.basePoints ?? [],
    repoName: data.repoName,
    artifacts: artifacts[pageKey] ?? [],
    pageKey,
    mode: panelMode,
    onMode: setPanelMode,
    onCollapse: closePanel,
    jump,
  }

  const primaryCount = (view: PrimaryView): string | null => {
    switch (view) {
      case 'attention':
        return String(data.attention.summary.open)
      case 'code':
        return String(agg.total)
      case 'concepts':
        return String(concepts.length)
      case 'security':
        return localizedSecuritySuffix.text
      case 'tests':
        return localizedTestSuffix.text
    }
  }

  const primaryAriaLabel = (view: PrimaryView, label: string): string | undefined => {
    if (view === 'security') return `${label}: ${localizedSecuritySuffix.ariaLabel}`
    if (view === 'tests') return `${label}: ${localizedTestSuffix.ariaLabel}`
    return undefined
  }

  const topTitle = concept
    ? concept.title
    : attentionView
      ? t(i18n)`attention`
      : security
      ? t(i18n)`security`
      : testsView
        ? t(i18n)`tests`
        : conceptsView
          ? t(i18n)`concepts`
          : node.path
            ? node.path.split('/').pop()
            : data.repoName

  return (
    <>
      {compact && (
        <header className="flex items-center gap-1 h-11 px-1.5 border-b border-border bg-panel">
          <button
            ref={compactExpandRef}
            type="button"
            className={TOPBAR_ICON}
            title={t(i18n)`expand sidebar`}
            onClick={() => setSideOpen(true)}
          >
            <PanelLeftOpen />
          </button>
          <span className="flex-1 min-w-0 text-[0.85rem] font-semibold text-center overflow-hidden text-ellipsis whitespace-nowrap">
            {topTitle}
          </span>
          {live && (
            <button
              type="button"
              className={TOPBAR_ICON}
              title={t(i18n)`chat with the attached agent session`}
              onClick={() => window.dispatchEvent(new CustomEvent('atlas-chat-toggle'))}
            >
              <MessageCircle />
            </button>
          )}
          <button type="button" className={TOPBAR_ICON} title={t(i18n)`expand panel`} onClick={openPanel}>
            <PanelRightOpen />
          </button>
        </header>
      )}
      {!compact && !sideOpen && (
        <div className="flex flex-col items-center pt-2.5 bg-panel w-10 border-r border-border">
          <button type="button" className={PV_ICON} title={t(i18n)`expand sidebar`} onClick={() => setSideOpen(true)}>
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
        {...(compact ? compactSidebarA11y(sideOpen) : {})}
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
            <button type="button" className={PV_ICON} title={t(i18n)`collapse sidebar`} onClick={() => setSideOpen(false)}>
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
              {headerDomainPresent && (
                <button
                  type="button"
                  className="font-inherit bg-transparent border-none p-0 cursor-pointer text-[0.72rem] text-muted hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 focus-visible:text-accent [&_b]:font-semibold"
                  onClick={onHeaderDomainShortcut}
                  title={
                    headerDomainAction?.kind === 'coverage'
                      ? t(i18n)`coverage action — open the relevant security coverage view`
                      : headerDomainAction?.kind === 'finding'
                        ? t(i18n)`open finding — open the relevant security unit`
                        : t(i18n)`open the security assurance overview`
                  }
                >
                  {headerDomainAction?.kind === 'coverage' ? (
                    <>
                      <b className="text-text">{securityModel.gapCount}</b> {t(i18n)`coverage gaps`}
                    </>
                  ) : headerDomainAction?.kind === 'finding' ? (
                    <>
                      <b className="text-text">{securityModel.openCount}</b> {t(i18n)`open findings`}
                    </>
                  ) : (
                    <>
                      {t(i18n)`security`} · {localizedSecuritySuffix.text}
                    </>
                  )}
                </button>
              )}
            </div>
            <SettingsButton onClick={() => setSettingsOpen(true)} />
          </div>
        </div>

        <div className="px-2 py-2 border-b border-border flex flex-col gap-0.5" role="navigation" aria-label={t(i18n)`primary`}>
          {PRIMARY.map(([view, Icon]) => {
            const active = primaryView === view
            const count = primaryCount(view)
            const label = primaryLabel(view, i18n)
            return (
              <button
                key={view}
                type="button"
                className={
                  PRIMARY_BTN +
                  (active
                    ? ' bg-[#3d6b5414] text-accent'
                    : ' bg-transparent text-muted hover:text-text hover:bg-[#00000006]')
                }
                aria-current={active ? 'page' : undefined}
                aria-label={primaryAriaLabel(view, label)}
                onClick={() => onPrimary(view)}
              >
                <Icon className="w-4 h-4 shrink-0" aria-hidden />
                <span className="flex-1 min-w-0 font-semibold">{label}</span>
                {count !== null && (
                  <span className={'shrink-0 text-[0.7rem] tabular-nums ' + (active ? 'text-accent' : 'text-muted')}>
                    {count}
                  </span>
                )}
              </button>
            )
          })}
        </div>

        {primaryView === 'code' && (
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
                type="button"
                className={CHIP + (statusFilter === 'outdated' ? ' ' + CHIP_ON : '')}
                onClick={() => setStatusFilter(statusFilter === 'outdated' ? null : 'outdated')}
              >
                {t(i18n)`outdated`}
              </button>
              <button
                type="button"
                className={CHIP + (statusFilter === 'missing' ? ' ' + CHIP_ON : '')}
                onClick={() => setStatusFilter(statusFilter === 'missing' ? null : 'missing')}
              >
                {t(i18n)`missing`}
              </button>
              <button
                type="button"
                className={CHIP + (showIgnored ? ' ' + CHIP_ON : '')}
                onClick={() => setShowIgnored(!showIgnored)}
                title={t(i18n)`also show config-excluded paths, greyed out`}
              >
                {t(i18n)`ignored`}
              </button>
              <button
                type="button"
                className={CHIP + ' sort'}
                onClick={() => setSortMode(sortMode === 'az' ? 'read' : 'az')}
                title={t(i18n)`tree layout: alphabetical or reading order`}
              >
                {sortMode === 'az' ? t(i18n)`sort: a–z` : t(i18n)`sort: reading`}
              </button>
            </div>
          </div>
        )}

        {primaryView === 'concepts' && (
          <div className="px-3 py-2 border-b border-border flex flex-col gap-1.5">
            <input
              type="search"
              className="w-full min-w-0 font-inherit text-[0.8rem] py-1 px-2 border border-border rounded-md bg-bg text-text focus:outline-none focus:border-accent"
              placeholder={t(i18n)`filter concepts…`}
              value={conceptQuery}
              onChange={(e) => setConceptQuery(e.target.value)}
            />
            <div className="flex gap-1.5 flex-wrap">
              <button
                type="button"
                className={CHIP + (conceptStatusFilter === 'outdated' ? ' ' + CHIP_ON : '')}
                onClick={() =>
                  setConceptStatusFilter(conceptStatusFilter === 'outdated' ? null : 'outdated')
                }
              >
                {t(i18n)`outdated`}
              </button>
            </div>
          </div>
        )}

        <nav className="flex-1 min-h-0 overflow-auto px-1.5 pt-2 pb-6">
          {primaryView === 'attention' ? (
            <AttentionNav
              attention={data.attention}
              section={attentionRouteInfo?.section ?? 'needs'}
              onSelect={(section) => onSelect(attentionRoute(section))}
            />
          ) : primaryView === 'concepts' ? (
            <ConceptList
              concepts={concepts}
              selected={path}
              query={conceptQuery.trim().toLowerCase()}
              statusFilter={conceptStatusFilter}
              onSelect={onSelect}
            />
          ) : primaryView === 'security' ? (
            <AuditNav
              model={securityModel}
              selectedMode={securityMode}
              selectedUnitSlug={auditRouteInfo?.domain === 'security' ? auditRouteInfo.slug : null}
              onMode={setSecurityMode}
              onSelect={onSelect}
            />
          ) : primaryView === 'tests' ? (
            <AuditNav
              model={testModel}
              selectedMode={testMode}
              selectedUnitSlug={auditRouteInfo?.domain === 'test' ? auditRouteInfo.slug : null}
              onMode={setTestMode}
              onSelect={onSelect}
            />
          ) : (
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
          )}
        </nav>
      </aside>
      <main className={'min-w-0 min-h-0 grid overflow-hidden ' + mainCols}>
        <div className="overflow-auto min-w-0" ref={docRef}>
          {attentionView ? (
            <AttentionPane
              attention={data.attention}
              section={attentionRouteInfo?.section ?? 'needs'}
              onSelectConcept={(slug) => onSelect(conceptRoute(slug))}
              onUpdate={(attention) => setData((current) => ({ ...current, attention }))}
            />
          ) : concept ? (
            <ConceptPane
              concept={concept}
              nodesByPath={nodesByPath}
              glossary={data.glossary}
              audit={conceptAudit}
              attentionItem={conceptAttention}
              onOpenAttention={() => onSelect(attentionRoute())}
            />
          ) : conceptsView ? (
            <ConceptsIndex concepts={concepts} onSelect={onSelect} />
          ) : security ? (
            <div className="min-h-full">
              {auditPresentation.state === 'fallback' && (
                <p
                  role="status"
                  className="mx-12 mt-5 mb-0 max-md:mx-4 text-[0.78rem] text-muted border border-border rounded-lg py-2 px-3 bg-panel"
                >
                  {t(i18n)`Audit content translation is unavailable or incomplete; canonical source text is shown.`}
                </p>
              )}
              <SecurityPane
                model={securityModel}
                audits={audits}
                mode={securityMode}
                focusSlug={auditRouteInfo?.domain === 'security' ? auditRouteInfo.slug : null}
                onMode={setSecurityMode}
                onSelectUnit={(slug) => {
                  if (!slug) {
                    onSelect(auditRoute('security'))
                    return
                  }
                  const route = auditUnitRoute('security', slug)
                  if (route) onSelect(route)
                }}
              />
            </div>
          ) : testsView ? (
            <div className="min-h-full">
              {auditPresentation.state === 'fallback' && (
                <p
                  role="status"
                  className="mx-12 mt-5 mb-0 max-md:mx-4 text-[0.78rem] text-muted border border-border rounded-lg py-2 px-3 bg-panel"
                >
                  {t(i18n)`Audit content translation is unavailable or incomplete; canonical source text is shown.`}
                </p>
              )}
              <TestAuditPane
                model={testModel}
                audits={testAudits}
                mode={testMode}
                focusSlug={auditRouteInfo?.domain === 'test' ? auditRouteInfo.slug : null}
                onMode={setTestMode}
                onSelectUnit={(slug) => {
                  if (!slug) {
                    onSelect(auditRoute('test'))
                    return
                  }
                  const route = auditUnitRoute('test', slug)
                  if (route) onSelect(route)
                }}
              />
            </div>
          ) : (
            <DocPane
              node={node}
              repoName={data.repoName}
              nodesByPath={nodesByPath}
              rel={rel}
              glossary={data.glossary}
              onContents={() => {
                openPanel()
                setPanelMode('toc')
              }}
            />
          )}
        </div>
        {!compact && panelOpen && <PanelPane {...panelProps} />}
        {!compact && !panelOpen && (
          <div className="flex flex-col items-center pt-2.5 bg-panel w-10 border-l border-border">
            <button type="button" className={PV_ICON} title={t(i18n)`expand panel`} onClick={() => setPanelOpen(true)}>
              <PanelRightOpen />
            </button>
          </div>
        )}
      </main>
      {compact && panelOpen && (
        <div
          className={
            'fixed inset-0 z-40 bg-[#00000033] ' +
            (panelClosing ? 'animate-[fade-out_0.16s_ease_forwards]' : 'animate-[fade-in_0.2s_ease]')
          }
          onClick={closePanel}
          aria-hidden
        />
      )}
      {compact && panelOpen && (
        <PanelPane
          {...panelProps}
          overlay
          closing={panelClosing}
          onCloseEnd={() => {
            setPanelClosing(false)
            setPanelOpen(false)
          }}
        />
      )}
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

function ConceptsIndex({
  concepts,
  onSelect,
}: {
  concepts: AtlasPayload['concepts']
  onSelect: (route: string) => void
}) {
  const { i18n } = useLingui()
  return (
    <div className="max-w-[760px] py-9 px-12 pb-24 max-md:py-5 max-md:px-4 max-md:pb-16">
      <div className="text-[0.78rem] text-muted">{t(i18n)`concepts`}</div>
      <h1 className="text-[1.25rem] font-[650] my-1 mb-3">{t(i18n)`concept index`}</h1>
      {concepts.length === 0 ? (
        <div className="text-[0.85rem] text-muted">{t(i18n)`no concept pages yet`}</div>
      ) : (
        <ul className="list-none p-0 m-0 flex flex-col gap-1.5">
          {concepts.map((c) => (
            <li key={c.slug}>
              <button
                type="button"
                className="font-inherit text-[0.9rem] text-accent bg-transparent border-none p-0 cursor-pointer hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/30 rounded-sm"
                onClick={() => onSelect(conceptRoute(c.slug))}
              >
                {c.title}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
