import { useEffect, useMemo, useRef, type MouseEvent } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { Printer } from 'lucide-react'
import type { AtlasPayload, ConceptNode, GlossaryEntry, TreeNode } from '../src/types'
import {
  annotateCodeAnchors, annotateConceptCodeAnchors, degradeCodeEmbeds,
  linkifyPaths, readingSequence, renderMermaidIn,
} from './lib'
import { conceptSlugOf } from './Concept'

export const printRoute = (scope: string) => 'print:' + scope

/** The scope a print route addresses, or null for ordinary routes. */
export function printScopeOf(route: string): string | null {
  return route.startsWith('print:') ? route.slice('print:'.length) : null
}

/** A print route is valid when its scope is `all`, a known path, or a known concept. */
export function isPrintScope(
  scope: string,
  nodesByPath: Map<string, TreeNode>,
  conceptsBySlug: Map<string, ConceptNode>,
): boolean {
  if (scope === 'all') return true
  const slug = conceptSlugOf(scope)
  return slug !== null ? conceptsBySlug.has(slug) : nodesByPath.has(scope)
}

type PrintPage =
  | { kind: 'node'; id: string; node: TreeNode; depth: number }
  | { kind: 'concept'; id: string; concept: ConceptNode; depth: number }

interface PrintModel {
  /** Cover headline: the path, the concept title, or "entire repository". */
  label: string
  pages: PrintPage[]
  showToc: boolean
  showGlossary: boolean
  /** Route to leave the print view towards — the page that was being printed. */
  backRoute: string
  /** Repo path → section id, for rewriting in-range pathlinks to anchors. */
  idByPath: Map<string, string>
}

const GLOSSARY_ID = 'print-glossary'

function buildModel(
  scope: string,
  data: AtlasPayload,
  nodesByPath: Map<string, TreeNode>,
  conceptsBySlug: Map<string, ConceptNode>,
  entireRepoLabel: string,
): PrintModel {
  const idByPath = new Map<string, string>()
  const slug = conceptSlugOf(scope)
  if (slug !== null) {
    const concept = conceptsBySlug.get(slug)!
    const page: PrintPage = { kind: 'concept', id: 'psec-0', concept, depth: 0 }
    return {
      label: concept.title, pages: [page], showToc: false, showGlossary: false,
      backRoute: scope, idByPath,
    }
  }
  const isAll = scope === 'all'
  const root = isAll ? data.tree : nodesByPath.get(scope)!
  if (!isAll && root.type === 'file') {
    idByPath.set(root.path, 'psec-0')
    return {
      label: scope,
      pages: [{ kind: 'node', id: 'psec-0', node: root, depth: 0 }],
      showToc: false, showGlossary: false, backRoute: scope, idByPath,
    }
  }
  // directory subtree (or the whole atlas): reading order, notes only —
  // readingSequence already excludes ignored paths and honours dir `order:`
  const seq = readingSequence(data.tree)
  const prefix = root.path ? root.path + '/' : ''
  const depthOf = (p: string) => (p === '' ? 0 : p.split('/').length)
  const base = depthOf(root.path)
  const pages: PrintPage[] = []
  for (const p of seq) {
    if (!isAll && p !== root.path && !p.startsWith(prefix)) continue
    const node = nodesByPath.get(p)
    if (!node?.html) continue // nothing written — no page to print
    const id = 'psec-' + pages.length
    idByPath.set(p, id)
    pages.push({ kind: 'node', id, node, depth: Math.max(0, depthOf(p) - base) })
  }
  return {
    label: isAll ? entireRepoLabel : scope,
    pages,
    showToc: true,
    showGlossary: data.glossary.length > 0,
    backRoute: isAll ? '' : scope,
    idByPath,
  }
}

/** On screen, anchor clicks scroll instead of touching the hash (which would
 * re-route the SPA); in the exported PDF the plain fragment href becomes an
 * internal document link. */
function wireAnchorScroll(a: HTMLAnchorElement, id: string): void {
  a.addEventListener('click', (e) => {
    e.preventDefault()
    document.getElementById(id)?.scrollIntoView()
  })
}

/**
 * Paper has no side panel to jump to and no hover UI: unwrap code anchors to
 * plain code, freeze embed line-number links to text, expand collapsed
 * embeds/details so nothing is clipped on the page.
 */
function stripInteractive(el: HTMLElement): void {
  for (const a of el.querySelectorAll('.code-anchor')) {
    a.querySelector(':scope > svg')?.remove()
    a.replaceWith(...a.childNodes)
  }
  for (const loc of el.querySelectorAll('.code-embed-loc')) {
    const s = document.createElement('span')
    s.className = 'code-embed-loc-print'
    s.textContent = loc.textContent ?? ''
    loc.replaceWith(s)
  }
  for (const fig of el.querySelectorAll('.code-embed.collapsed')) fig.classList.remove('collapsed')
  for (const btn of el.querySelectorAll('.code-embed-more')) btn.remove()
  for (const d of el.querySelectorAll('details')) d.setAttribute('open', '')
}

/** In-range page links become in-document anchors; everything else that points
 * back into the app degrades to plain text (no dead links in the PDF). */
function rewriteHashLinks(el: HTMLElement, idByPath: Map<string, string>): void {
  for (const a of el.querySelectorAll<HTMLAnchorElement>('a[href^="#"]')) {
    let target: string
    try {
      target = decodeURI(a.getAttribute('href')!.slice(1))
    } catch {
      target = ''
    }
    const id = idByPath.get(target)
    if (id !== undefined) {
      a.setAttribute('href', '#' + id)
      a.classList.add('print-internal')
      wireAnchorScroll(a, id)
    } else {
      a.replaceWith(...a.childNodes)
    }
  }
}

function PrintSection({
  page, repoName, nodesByPath, idByPath, onReady,
}: {
  page: PrintPage
  repoName: string
  nodesByPath: Map<string, TreeNode>
  idByPath: Map<string, string>
  onReady: () => void
}) {
  const { i18n } = useLingui()
  const ref = useRef<HTMLDivElement>(null)
  const last = useRef<string | null>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const html = page.kind === 'node' ? page.node.html : page.concept.html
    const key = page.id + '\0' + (html ?? '')
    if (last.current === key) return
    last.current = key
    el.innerHTML = html ?? ''
    const jobs: Promise<unknown>[] = [renderMermaidIn(el, { zoomable: false })]
    if (page.kind === 'concept') {
      linkifyPaths(el, nodesByPath.get('')!, nodesByPath)
      jobs.push(annotateConceptCodeAnchors(el))
    } else {
      linkifyPaths(el, page.node, nodesByPath)
      if (page.node.type === 'file') {
        jobs.push(
          fetch('raw?p=' + encodeURIComponent(page.node.path))
            .then((res) => (res.ok && !res.headers.get('x-atlas-binary') ? res.text() : null))
            .catch(() => null)
            .then((src) => {
              if (src) annotateCodeAnchors(el, page.node.path, src)
              else degradeCodeEmbeds(el) // static build / unreadable source
            }),
        )
      } else {
        degradeCodeEmbeds(el)
      }
    }
    Promise.allSettled(jobs).then(() => {
      if (ref.current !== el) return
      stripInteractive(el)
      rewriteHashLinks(el, idByPath)
      onReady()
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, nodesByPath, idByPath])
  return (
    <section id={page.id} className="print-section mt-10">
      <h2 className="print-sec-title text-[1.05rem] font-[650] break-all border-b border-border pb-1.5 mb-3">
        {page.kind === 'concept' ? (
          page.concept.title
        ) : (
          <>
            <span className="font-mono">{page.node.path || repoName}</span>
            {page.node.type === 'dir' && (
              <span className="text-muted font-normal text-[0.85rem]"> {t(i18n)`(directory)`}</span>
            )}
          </>
        )}
      </h2>
      <div className="prose" ref={ref} />
    </section>
  )
}

function GlossarySection({ glossary }: { glossary: GlossaryEntry[] }) {
  const { i18n } = useLingui()
  return (
    <section id={GLOSSARY_ID} className="print-section mt-10">
      <h2 className="print-sec-title text-[1.05rem] font-[650] border-b border-border pb-1.5 mb-3">
        {t(i18n)`glossary`}
      </h2>
      <dl className="print-glossary-list">
        {glossary.map((g) => (
          <div key={g.term} className="mb-3">
            <dt className="font-semibold">
              {g.term}
              {g.aliases?.length ? (
                <span className="text-muted font-normal text-[0.85em]"> · {g.aliases.join(' · ')}</span>
              ) : null}
            </dt>
            <dd className="ml-0 whitespace-pre-wrap text-[0.92em]">{g.def}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

const AUTO_PRINT_SETTLE_MS = 500

export function PrintView({
  scope, data, nodesByPath, conceptsBySlug,
}: {
  scope: string
  data: AtlasPayload
  nodesByPath: Map<string, TreeNode>
  conceptsBySlug: Map<string, ConceptNode>
}) {
  const { i18n } = useLingui()
  const model = useMemo(
    () => buildModel(scope, data, nodesByPath, conceptsBySlug, t(i18n)`entire repository`),
    [scope, data, nodesByPath, conceptsBySlug, i18n],
  )

  // fire the print dialog once, after every section has settled (mermaid
  // rendered, code anchors resolved) plus a short layout-settle grace
  const readyCount = useRef(0)
  const printed = useRef(false)
  const total = model.pages.length
  const onSectionReady = () => {
    readyCount.current++
    if (readyCount.current >= total && !printed.current) {
      printed.current = true
      setTimeout(() => window.print(), AUTO_PRINT_SETTLE_MS)
    }
  }
  useEffect(() => {
    if (total === 0 && !printed.current) {
      printed.current = true
      setTimeout(() => window.print(), AUTO_PRINT_SETTLE_MS)
    }
  }, [total])

  const tocJump = (id: string) => (e: MouseEvent) => {
    e.preventDefault()
    document.getElementById(id)?.scrollIntoView()
  }

  return (
    <div className="print-view col-span-full h-dvh overflow-auto bg-white">
      <div className="print-toolbar sticky top-0 z-10 flex items-center gap-3 px-5 py-2 border-b border-border bg-panel">
        <a className="text-accent no-underline text-[0.82rem] hover:underline" href={'#' + encodeURI(model.backRoute)}>
          ← {t(i18n)`back`}
        </a>
        <span className="flex-1" />
        <button
          className="btn flex items-center gap-1.5 font-inherit text-[0.78rem] py-[5px] px-3 rounded-lg border border-accent bg-accent text-white cursor-pointer hover:opacity-90 [&_svg]:w-3.5 [&_svg]:h-3.5"
          onClick={() => window.print()}
        >
          <Printer /> {t(i18n)`print`}
        </button>
      </div>
      <div className="print-body max-w-[820px] mx-auto px-10 py-10 max-md:px-4">
        <section className="print-cover">
          <div className="text-[0.85rem] text-muted">{data.repoName}</div>
          <h1 className="text-[1.7rem] font-[700] my-2 break-all">{model.label}</h1>
          <div className="text-[0.82rem] text-muted mt-4 flex flex-col gap-1">
            {data.commit && (
              <div>
                {t(i18n)`commit`} <span className="font-mono">{data.commit.slice(0, 7)}</span>
              </div>
            )}
            <div>
              {t(i18n)`generated`} {new Date(data.generatedAt).toLocaleString(i18n.locale)}
            </div>
          </div>
        </section>
        {model.showToc && (
          <nav className="print-toc mt-10">
            <h2 className="text-[1.05rem] font-[650] border-b border-border pb-1.5 mb-3">
              {t(i18n)`contents`}
            </h2>
            {model.pages.map((pg) => (
              <a
                key={pg.id}
                className="print-toc-row block text-inherit no-underline py-[3px] text-[0.85rem] font-mono break-all hover:text-accent"
                style={{ paddingLeft: pg.depth * 16 }}
                href={'#' + pg.id}
                onClick={tocJump(pg.id)}
              >
                {pg.kind === 'concept'
                  ? pg.concept.title
                  : (pg.node.path ? pg.node.name : data.repoName) + (pg.node.type === 'dir' ? '/' : '')}
              </a>
            ))}
            {model.showGlossary && (
              <a
                className="print-toc-row block text-inherit no-underline py-[3px] text-[0.85rem] font-mono hover:text-accent"
                href={'#' + GLOSSARY_ID}
                onClick={tocJump(GLOSSARY_ID)}
              >
                {t(i18n)`glossary`}
              </a>
            )}
          </nav>
        )}
        {model.pages.map((pg) => (
          <PrintSection
            key={pg.id}
            page={pg}
            repoName={data.repoName}
            nodesByPath={nodesByPath}
            idByPath={model.idByPath}
            onReady={onSectionReady}
          />
        ))}
        {model.showGlossary && <GlossarySection glossary={data.glossary} />}
      </div>
    </div>
  )
}
