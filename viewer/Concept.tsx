import { useEffect, useRef } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { Printer } from 'lucide-react'
import type { AuditUnit, ConceptNode, ConceptState, GlossaryEntry, TreeNode } from '../src/types'
import {
  annotateConceptCodeAnchors, annotateGlossary, linkifyPaths, renderMermaidIn,
} from './lib'
import { ConceptSecuritySection } from './Security'

const ROW =
  'row flex items-center gap-1.5 py-0.5 pr-2 pl-0 rounded-md cursor-pointer select-none text-[0.82rem] whitespace-nowrap hover:bg-[#00000006]'

export const conceptRoute = (slug: string) => 'concept:' + slug

/** The concept slug a route addresses, or null for ordinary path routes. */
export function conceptSlugOf(route: string): string | null {
  return route.startsWith('concept:') ? route.slice('concept:'.length) : null
}

function dotClass(status: ConceptState): string {
  const base = 'w-2 h-2 rounded-full shrink-0 '
  switch (status) {
    case 'fresh': return base + 'bg-fresh'
    case 'outdated': return base + 'bg-outdated'
    case 'broken-source': return base + 'bg-[#c4222e]'
  }
}

function stateLabel(status: ConceptState, i18n: Parameters<typeof t>[0]): string {
  switch (status) {
    case 'fresh': return t(i18n)`up to date`
    case 'outdated': return t(i18n)`outdated — a source changed since this page was stamped`
    case 'broken-source': return t(i18n)`broken source — a source path is gone from the scan`
  }
}

/** The concepts sidebar tab: a curriculum tree — chapters as group headings,
 * pages inside in reading order with ①② position badges. Concepts and the code
 * tree are different kinds of structure, so they live on separate tabs. */
export function ConceptList({
  concepts, selected, query, statusFilter, onSelect,
}: {
  concepts: ConceptNode[]
  selected: string
  query: string
  statusFilter: string | null
  onSelect: (route: string) => void
}) {
  const { i18n } = useLingui()
  const shown = concepts.filter((c) => {
    if (query && !(c.title + ' ' + c.slug).toLowerCase().includes(query)) return false
    // the tree's filter chips: "outdated" also surfaces broken sources (both
    // mean "needs attention"); concepts are never "missing"
    if (statusFilter === 'outdated') return c.status !== 'fresh'
    if (statusFilter) return false
    return true
  })
  if (!shown.length) {
    return <div className="text-[0.78rem] text-muted px-2 py-3">{t(i18n)`no concept pages yet`}</div>
  }
  // Group by chapter, preserving payload order (already curriculum-sorted).
  const chapters: { name: string | null; items: ConceptNode[] }[] = []
  for (const c of shown) {
    const last = chapters[chapters.length - 1]
    if (last && last.name === c.chapter) last.items.push(c)
    else chapters.push({ name: c.chapter, items: [c] })
  }
  // Reading-position badge = index in the FULL curriculum (not the filtered view)
  const posOf = new Map(concepts.map((c, i) => [c.slug, i + 1]))
  return (
    <div>
      {chapters.map((ch, gi) => (
        <div key={gi} className="mb-2">
          {ch.name && (
            <div className="text-[0.7rem] text-muted px-2 pt-1 pb-0.5 font-[600]">{ch.name}</div>
          )}
          {ch.items.map((c) => (
            <div
              key={c.slug}
              className={ROW + (selected === conceptRoute(c.slug) ? ' sel bg-[#3d6b5414]' : '')}
              style={{ paddingLeft: ch.name ? 10 : 4 }}
              onClick={() => onSelect(conceptRoute(c.slug))}
            >
              <span className="shrink-0 text-[0.68rem] text-muted w-4 text-right">{posOf.get(c.slug)}</span>
              <span className={dotClass(c.status)} />
              <span className="overflow-hidden text-ellipsis">{c.title}</span>
              {c.audience === 'general' && (
                <span className="shrink-0 text-[0.7rem]" title={t(i18n)`written for a general audience`}>
                  👥
                </span>
              )}
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

function ConceptProse({
  concept, nodesByPath, glossary,
}: {
  concept: ConceptNode
  nodesByPath: Map<string, TreeNode>
  glossary: GlossaryEntry[]
}) {
  const ref = useRef<HTMLDivElement>(null)
  const last = useRef<string | null>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    // same idempotence dance as file/dir Prose: live refreshes hand us a new
    // object every time; only rebuild the DOM when this page actually changed
    const key = concept.slug + '\0' + (concept.html ?? '')
    if (last.current === key) return
    last.current = key
    el.innerHTML = concept.html ?? ''
    linkifyPaths(el, nodesByPath.get('')!, nodesByPath) // resolve repo paths from the root
    annotateGlossary(el, glossary)
    renderMermaidIn(el)
    // concept anchors carry their own file (code:<path>#marker) — fetched per
    // file; in the static build the fetch fails and they degrade gracefully
    annotateConceptCodeAnchors(el)
  }, [concept, nodesByPath, glossary])
  return <div className="prose" ref={ref} />
}

export function ConceptPane({
  concept, nodesByPath, glossary, audit,
}: {
  concept: ConceptNode
  nodesByPath: Map<string, TreeNode>
  glossary: GlossaryEntry[]
  audit?: AuditUnit
}) {
  const { i18n } = useLingui()
  const broken = new Set(concept.brokenSources)
  return (
    <div className="max-w-[760px] py-9 px-12 pb-24 max-md:py-5 max-md:px-4 max-md:pb-16">
      <div className="text-[0.78rem] text-muted break-all">{t(i18n)`concept`}</div>
      <h1 className="text-[1.25rem] font-[650] my-1 mb-3 break-all">
        {concept.title}
        {concept.audience === 'general' && (
          <span className="ml-2 text-[1rem]" title={t(i18n)`written for a general audience`}>👥</span>
        )}
      </h1>
      <div className="flex items-center gap-2.5 mb-5">
        <div
          className={
            'inline-flex items-center gap-[7px] text-[0.75rem] border border-border rounded-lg py-[5px] px-2.5 bg-panel' +
            (concept.status === 'outdated' ? ' border-[#d9930d55] bg-[#d9930d0d]' : '') +
            (concept.status === 'broken-source' ? ' border-[#c4222e55] bg-[#c4222e0d]' : '')
          }
        >
          <span className={dotClass(concept.status)} />
          {stateLabel(concept.status, i18n)}
          {concept.stamped
            ? ` · ${t(i18n)`stamped`} ${new Date(concept.stamped).toLocaleDateString(i18n.locale)}`
            : ''}
        </div>
        <a
          className="btn font-inherit text-[0.75rem] py-[5px] px-3 rounded-lg border border-border bg-panel no-underline text-muted cursor-pointer whitespace-nowrap hover:border-accent hover:text-accent inline-flex items-center [&_svg]:w-3.5 [&_svg]:h-3.5"
          // literal prefix: importing printRoute from Print.tsx would cycle
          // (Print.tsx already imports conceptSlugOf from this module)
          href={'#' + encodeURI('print:' + conceptRoute(concept.slug))}
          title={t(i18n)`print this page as a PDF`}
        >
          <Printer />
        </a>
      </div>
      {concept.sources.length > 0 && (
        <div className="-mt-2 mb-5 flex gap-2 items-baseline text-[0.75rem]">
          <span className="text-muted shrink-0 w-[92px] text-right">{t(i18n)`sources →`}</span>
          <span className="flex flex-wrap gap-1 min-w-0 flex-1">
            {concept.sources.map((p) =>
              broken.has(p) ? (
                <span
                  key={p}
                  className="rel-chip text-[#c4222e] line-through bg-[#c4222e0d] border border-[#c4222e26] rounded-md py-px px-[7px] font-mono text-[0.72rem] whitespace-nowrap"
                  title={t(i18n)`gone from the scan`}
                >
                  {p}
                </span>
              ) : (
                <a
                  key={p}
                  className="rel-chip text-accent no-underline bg-[#3d6b540d] border border-[#3d6b5426] rounded-md py-px px-[7px] font-mono text-[0.72rem] whitespace-nowrap hover:bg-[#3d6b541f]"
                  href={'#' + encodeURI(p)}
                >
                  {p}
                </a>
              ),
            )}
          </span>
        </div>
      )}
      <ConceptProse concept={concept} nodesByPath={nodesByPath} glossary={glossary} />
      {audit && <ConceptSecuritySection unit={audit} />}
    </div>
  )
}
