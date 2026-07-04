import { useEffect, useState } from 'react'
import type { EntryStatus, GlossaryEntry, ImportGraph, TreeAgg, TreeNode } from '../src/types'

/** Subscribe to a CSS media query; re-renders when it crosses the breakpoint. */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(
    () => typeof window !== 'undefined' && window.matchMedia(query).matches,
  )
  useEffect(() => {
    const mq = window.matchMedia(query)
    const onChange = () => setMatches(mq.matches)
    onChange()
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [query])
  return matches
}

/** Narrow / phone layout — sidebar drawer, preview overlay, full-width chat. */
export function useCompact(): boolean {
  return useMediaQuery('(max-width: 768px)')
}
import { findLine as findLineInSource } from '../src/findLine'

export function indexTree(root: TreeNode): Map<string, TreeNode> {
  const nodesByPath = new Map<string, TreeNode>()
  ;(function walk(n: TreeNode) {
    n.agg = {
      outdated: n.status === 'outdated' ? 1 : 0,
      missing: n.status === 'missing' ? 1 : 0,
      ignored: n.status === 'ignored' ? 1 : 0,
      total: n.status === 'ignored' ? 0 : 1,
    }
    nodesByPath.set(n.path, n)
    for (const c of n.children) {
      walk(c)
      const agg = n.agg as TreeAgg
      agg.outdated += c.agg!.outdated
      agg.missing += c.agg!.missing
      agg.ignored += c.agg!.ignored
      agg.total += c.agg!.total
    }
  })(root)
  return nodesByPath
}

/**
 * The atlas as a book: DFS preorder over the (already reading-ordered) tree.
 * Dir pages are chapter intros, files are the content; ignored paths are not
 * part of the story. Drives prev/next paging and "start reading".
 */
export function readingSequence(root: TreeNode): string[] {
  const seq: string[] = []
  ;(function walk(n: TreeNode) {
    if (n.status === 'ignored') return
    seq.push(n.path)
    n.children.forEach(walk)
  })(root)
  return seq
}

/** First FILE page inside a dir's subtree, reading order — the deep-dive target. */
export function firstFileWithin(
  node: TreeNode,
  seq: string[],
  nodesByPath: Map<string, TreeNode>,
): string | null {
  if (node.type !== 'dir') return null
  const prefix = node.path ? node.path + '/' : ''
  const i = seq.indexOf(node.path)
  if (i < 0) return null
  for (let j = i + 1; j < seq.length && seq[j].startsWith(prefix); j++) {
    if (nodesByPath.get(seq[j])?.type === 'file') return seq[j]
  }
  return null
}

export function ancestorsOf(path: string): string[] {
  const out = ['']
  if (!path) return out
  const segs = path.split('/')
  let p = ''
  for (let i = 0; i < segs.length - 1; i++) {
    p = p ? p + '/' + segs[i] : segs[i]
    out.push(p)
  }
  return out
}

export function noteFileFor(node: TreeNode): string {
  if (node.type === 'dir') return '.atlas/notes/' + (node.path ? node.path + '/' : '') + '__dir__.md'
  return '.atlas/notes/' + node.path + '.md'
}

export function linkifyPaths(
  container: HTMLElement,
  node: TreeNode,
  nodesByPath: Map<string, TreeNode>,
): void {
  const base = node.type === 'dir' ? node.path : node.path.slice(0, node.path.lastIndexOf('/'))
  for (const code of container.querySelectorAll('code')) {
    if (code.parentElement?.closest('a, pre')) continue
    const raw = code.textContent?.trim() ?? ''
    if (!raw || raw.length > 120 || /[\s`$(){}"']/.test(raw)) continue
    const t = raw.replace(/\/$/, '').replace(/\/?\*$/, '').replace(/-\*$/, '')
    if (!t) continue
    const candidates = [t, base ? base + '/' + t : t]
    if (base.includes('/')) candidates.push(base.slice(0, base.lastIndexOf('/')) + '/' + t)
    const hit = candidates.find((c) => c !== node.path && nodesByPath.has(c))
    if (!hit) continue
    const a = document.createElement('a')
    a.href = '#' + encodeURI(hit)
    a.className = 'pathlink'
    code.replaceWith(a)
    a.appendChild(code)
  }
}

const MERMAID_PREVIEW_MAX_H = 340
const MERMAID_VIEWPORT_FRAC = 0.88 // leaves room for the lightbox card's padding

let mermaidSeq = 0
let mermaidReady = false

function mermaidSvgBox(svg: SVGSVGElement): { w: number; h: number } {
  const vb = svg.viewBox?.baseVal
  if (vb?.width && vb.height) return { w: vb.width, h: vb.height }
  const w = parseFloat(svg.getAttribute('width') ?? '')
  const h = parseFloat(svg.getAttribute('height') ?? '')
  if (w > 0 && h > 0) return { w, h }
  try {
    const b = svg.getBBox()
    if (b.width > 0 && b.height > 0) return { w: b.width, h: b.height }
  } catch { /* detached or zero-sized */ }
  return { w: 800, h: 600 }
}

function clearMermaidSvgSize(svg: SVGSVGElement): void {
  svg.removeAttribute('width')
  svg.removeAttribute('height')
  svg.style.width = ''
  svg.style.height = ''
}

function fitMermaidPreview(svg: SVGSVGElement): void {
  clearMermaidSvgSize(svg)
  svg.style.display = 'block'
  svg.style.maxHeight = MERMAID_PREVIEW_MAX_H + 'px'
  svg.style.maxWidth = '100%'
  svg.style.width = 'auto'
  svg.style.height = 'auto'
}

let lightboxEl: HTMLDivElement | null = null
let lightboxReturnFocus: HTMLElement | null = null
let lightboxTransform: HTMLDivElement | null = null
let lightboxScale = 1
let lightboxPanX = 0
let lightboxPanY = 0
let lightboxDrag: { x: number; y: number; panX: number; panY: number } | null = null
// live pointers on the viewport; two of them = pinch gesture
const lightboxPointers = new Map<number, { x: number; y: number }>()
let lightboxPinch: {
  dist: number
  midX: number
  midY: number
  scale: number
  panX: number
  panY: number
} | null = null
let lightboxMoved = false

const LIGHTBOX_MIN_SCALE = 0.4
const LIGHTBOX_MAX_SCALE = 5

function applyLightboxTransform(): void {
  if (!lightboxTransform) return
  lightboxTransform.style.transform = `translate(${lightboxPanX}px, ${lightboxPanY}px) scale(${lightboxScale})`
}

function resetLightboxTransform(): void {
  lightboxScale = 1
  lightboxPanX = 0
  lightboxPanY = 0
  applyLightboxTransform()
}

function closeMermaidLightbox(): void {
  if (!lightboxEl || lightboxEl.hidden) return
  lightboxEl.hidden = true
  lightboxDrag = null
  lightboxPinch = null
  lightboxPointers.clear()
  const back = lightboxReturnFocus
  lightboxReturnFocus = null
  if (back?.isConnected) back.focus()
}

function mermaidLightbox(): HTMLDivElement {
  if (lightboxEl) return lightboxEl
  const el = document.createElement('div')
  el.className = 'mermaid-lightbox'
  el.hidden = true
  el.setAttribute('role', 'dialog')
  el.setAttribute('aria-modal', 'true')
  el.setAttribute('aria-label', 'Diagram fullscreen')

  const backdrop = document.createElement('div')
  backdrop.className = 'mermaid-lightbox-backdrop'

  const close = document.createElement('button')
  close.type = 'button'
  close.className = 'mermaid-lightbox-close'
  close.setAttribute('aria-label', 'Close')
  close.textContent = '\u00d7'

  const viewport = document.createElement('div')
  viewport.className = 'mermaid-lightbox-viewport'
  const transform = document.createElement('div')
  transform.className = 'mermaid-lightbox-transform'
  viewport.appendChild(transform)
  lightboxTransform = transform

  el.append(backdrop, close, viewport)

  backdrop.addEventListener('click', closeMermaidLightbox)
  close.addEventListener('click', closeMermaidLightbox)
  viewport.addEventListener('click', (e) => {
    // a drag or pinch that started on the background must not count as a
    // "tap outside" — only a clean tap closes
    if (e.target === viewport && !lightboxMoved) closeMermaidLightbox()
  })

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && lightboxEl && !lightboxEl.hidden) {
      e.preventDefault()
      e.stopPropagation()
      closeMermaidLightbox()
    }
  })

  viewport.addEventListener(
    'wheel',
    (e) => {
      if (lightboxEl?.hidden) return
      e.preventDefault()
      const factor = e.deltaY < 0 ? 1.1 : 1 / 1.1
      lightboxScale = Math.min(5, Math.max(0.4, lightboxScale * factor))
      applyLightboxTransform()
    },
    { passive: false },
  )

  // one pointer pans; two pointers pinch-zoom around their midpoint. The
  // midpoint math works in coordinates relative to the viewport centre,
  // because the transform element is centred there and scales about itself:
  // screen = centre + pan + scale * contentOffset.
  const relToCenter = (x: number, y: number) => {
    const r = viewport.getBoundingClientRect()
    return { x: x - (r.left + r.width / 2), y: y - (r.top + r.height / 2) }
  }
  const startPinch = () => {
    const [a, b] = [...lightboxPointers.values()]
    const dist = Math.hypot(b.x - a.x, b.y - a.y)
    const mid = relToCenter((a.x + b.x) / 2, (a.y + b.y) / 2)
    lightboxPinch = {
      dist: Math.max(dist, 1),
      midX: mid.x,
      midY: mid.y,
      scale: lightboxScale,
      panX: lightboxPanX,
      panY: lightboxPanY,
    }
    lightboxDrag = null
  }

  viewport.addEventListener('pointerdown', (e) => {
    if (lightboxEl?.hidden || (e.pointerType === 'mouse' && e.button !== 0)) return
    lightboxPointers.set(e.pointerId, { x: e.clientX, y: e.clientY })
    viewport.setPointerCapture(e.pointerId)
    if (lightboxPointers.size === 1) lightboxMoved = false
    if (lightboxPointers.size === 2) {
      startPinch()
    } else if (lightboxPointers.size === 1) {
      lightboxDrag = { x: e.clientX, y: e.clientY, panX: lightboxPanX, panY: lightboxPanY }
      viewport.classList.add('dragging')
    }
  })
  viewport.addEventListener('pointermove', (e) => {
    const p = lightboxPointers.get(e.pointerId)
    if (!p) return
    p.x = e.clientX
    p.y = e.clientY
    if (lightboxPinch && lightboxPointers.size >= 2) {
      const [a, b] = [...lightboxPointers.values()]
      const dist = Math.max(Math.hypot(b.x - a.x, b.y - a.y), 1)
      const mid = relToCenter((a.x + b.x) / 2, (a.y + b.y) / 2)
      const next = Math.min(
        LIGHTBOX_MAX_SCALE,
        Math.max(LIGHTBOX_MIN_SCALE, lightboxPinch.scale * (dist / lightboxPinch.dist)),
      )
      // keep the content point under the (moving) midpoint pinned
      const k = next / lightboxPinch.scale
      lightboxScale = next
      lightboxPanX = mid.x - k * (lightboxPinch.midX - lightboxPinch.panX)
      lightboxPanY = mid.y - k * (lightboxPinch.midY - lightboxPinch.panY)
      lightboxMoved = true
      applyLightboxTransform()
    } else if (lightboxDrag) {
      lightboxPanX = lightboxDrag.panX + (e.clientX - lightboxDrag.x)
      lightboxPanY = lightboxDrag.panY + (e.clientY - lightboxDrag.y)
      if (Math.hypot(e.clientX - lightboxDrag.x, e.clientY - lightboxDrag.y) > 6) lightboxMoved = true
      applyLightboxTransform()
    }
  })
  const endPointer = (e: PointerEvent) => {
    if (!lightboxPointers.delete(e.pointerId)) return
    try { viewport.releasePointerCapture(e.pointerId) } catch { /* already released */ }
    if (lightboxPinch && lightboxPointers.size < 2) {
      lightboxPinch = null
      // hand off to a single-finger pan from the remaining pointer
      const rest = [...lightboxPointers.values()][0]
      lightboxDrag = rest
        ? { x: rest.x, y: rest.y, panX: lightboxPanX, panY: lightboxPanY }
        : null
    } else if (lightboxPointers.size === 0) {
      lightboxDrag = null
    }
    if (lightboxPointers.size === 0) viewport.classList.remove('dragging')
  }
  viewport.addEventListener('pointerup', endPointer)
  viewport.addEventListener('pointercancel', endPointer)

  document.body.appendChild(el)
  lightboxEl = el
  return el
}

function openMermaidLightbox(svg: SVGSVGElement, trigger: HTMLElement): void {
  const lb = mermaidLightbox()
  const clone = svg.cloneNode(true) as SVGSVGElement
  clearMermaidSvgSize(clone)
  const { w, h } = mermaidSvgBox(svg)
  const maxW = window.innerWidth * MERMAID_VIEWPORT_FRAC
  const maxH = window.innerHeight * MERMAID_VIEWPORT_FRAC
  const fit = Math.min(maxW / w, maxH / h)
  clone.style.width = w * fit + 'px'
  clone.style.height = h * fit + 'px'
  clone.style.maxWidth = 'none'
  clone.style.maxHeight = 'none'
  clone.style.display = 'block'
  clone.style.pointerEvents = 'none'

  lightboxTransform!.replaceChildren(clone)
  resetLightboxTransform()
  lightboxReturnFocus = trigger
  lb.hidden = false
  lb.querySelector<HTMLButtonElement>('.mermaid-lightbox-close')?.focus()
}

function wireMermaidDiagram(holder: HTMLElement, svg: SVGSVGElement): void {
  holder.classList.add('mermaid-diagram-zoomable')
  holder.setAttribute('role', 'button')
  holder.tabIndex = 0
  holder.setAttribute('aria-label', 'Open diagram fullscreen')
  const open = () => openMermaidLightbox(svg, holder)
  holder.addEventListener('click', open)
  holder.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      open()
    }
  })
}

export async function renderMermaidIn(container: HTMLElement): Promise<void> {
  if (!window.mermaid) return
  const blocks = container.querySelectorAll('pre > code.language-mermaid')
  if (!blocks.length) return
  if (!mermaidReady) {
    window.mermaid.initialize({ startOnLoad: false, theme: 'neutral' })
    mermaidReady = true
  }
  for (const code of blocks) {
    const src = code.textContent ?? ''
    const holder = document.createElement('div')
    holder.className = 'mermaid-diagram'
    code.parentElement?.replaceWith(holder)
    try {
      const { svg } = await window.mermaid.render('mmd-' + ++mermaidSeq, src)
      holder.innerHTML = svg
      const el = holder.querySelector('svg')
      if (el) {
        fitMermaidPreview(el)
        wireMermaidDiagram(holder, el)
      }
    } catch (err: unknown) {
      const pre = document.createElement('pre')
      pre.className = 'mermaid-error'
      pre.textContent = 'mermaid: ' + (err instanceof Error ? err.message : String(err)) + '\n\n' + src
      holder.replaceChildren(pre)
      document.getElementById('mmd-' + mermaidSeq)?.remove()
    }
  }
}

const PV_LANG: Record<string, string> = {
  ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript',
  js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
  json: 'json', jsonc: 'json', md: 'markdown', mdx: 'markdown',
  css: 'css', html: 'xml', xml: 'xml', svg: 'xml', astro: 'xml', vue: 'xml',
  py: 'python', sh: 'bash', bash: 'bash', zsh: 'bash', yml: 'yaml', yaml: 'yaml',
  sql: 'sql', rs: 'rust', go: 'go', nix: 'nix', toml: 'ini', ini: 'ini', diff: 'diff',
}

export function languageFor(path: string): string | null {
  const name = path.slice(path.lastIndexOf('/') + 1).toLowerCase()
  if (name.startsWith('dockerfile')) return 'dockerfile'
  const ext = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1) : ''
  return PV_LANG[ext] ?? null
}

export interface RelationIndex {
  edges: [string, string][]
  packageRoots: Set<string>
}

export function buildRelationIndex(graph: ImportGraph | null): RelationIndex | null {
  if (!graph) return null
  const paths = graph.paths
  return {
    edges: graph.edges.map(([s, d]) => [paths[s], paths[d]]),
    packageRoots: new Set(graph.packageRoots),
  }
}

export function relationsFor(
  node: TreeNode,
  rel: RelationIndex | null,
  nodesByPath: Map<string, TreeNode>,
): { deps: string[]; dependents: string[] } {
  if (!rel || node.path === '') return { deps: [], dependents: [] }
  const prefix = node.path + '/'
  const inside = (p: string) => p === node.path || p.startsWith(prefix)
  const groupOf = (p: string) => {
    let cur = p
    while (cur) {
      if (rel.packageRoots.has(cur)) return cur
      cur = cur.includes('/') ? cur.slice(0, cur.lastIndexOf('/')) : ''
    }
    return p.includes('/') ? p.split('/')[0] : p
  }
  const isFile = node.type === 'file'
  const ownGroup = groupOf(node.path)
  const deps = new Set<string>()
  const dependents = new Set<string>()
  for (const [src, dst] of rel.edges) {
    const srcIn = inside(src)
    const dstIn = inside(dst)
    if (srcIn === dstIn) continue
    if (srcIn) {
      const t = isFile ? dst : groupOf(dst)
      if (isFile || t !== ownGroup) deps.add(t)
    } else {
      const t = isFile ? src : groupOf(src)
      if (isFile || t !== ownGroup) dependents.add(t)
    }
  }
  const clean = (set: Set<string>) => [...set].filter((p) => p !== node.path && nodesByPath.has(p)).sort()
  return { deps: clean(deps), dependents: clean(dependents) }
}

// lucide arrow-right-to-line, inlined (self-contained page: no external assets)
const JUMP_ICON =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 12H3"/><path d="m11 18 6-6-6-6"/><path d="M21 5v14"/></svg>'

/**
 * From startLine (1-based), if the code opens a bracket, run until it
 * balances back out — "the whole block". A bare line stays one line.
 * Heuristic (ignores brackets in strings/comments) but self-correcting:
 * embeds re-resolve on every render, so a bad guess never persists.
 */
export function blockEndFor(lines: string[], startLine: number, maxLines = 200): number {
  let depth = 0
  let opened = false
  const last = Math.min(lines.length, startLine - 1 + maxLines)
  for (let i = startLine - 1; i < last; i++) {
    for (const ch of lines[i]) {
      if (ch === '{' || ch === '(' || ch === '[') { depth++; opened = true }
      else if (ch === '}' || ch === ')' || ch === ']') depth--
    }
    if (opened && depth <= 0) return i + 1
  }
  return opened ? last : startLine
}

const EMBED_COLLAPSE_LINES = 32

function degradeEmbed(img: HTMLImageElement): void {
  img.replaceWith(document.createTextNode(img.getAttribute('alt') ?? ''))
}

/** Static build (or unreadable source): no code to slice, drop embeds to their labels. */
export function degradeCodeEmbeds(container: HTMLElement): void {
  for (const img of container.querySelectorAll<HTMLImageElement>('img[src^="code:"]')) degradeEmbed(img)
}

function buildCodeEmbed(
  img: HTMLImageElement,
  path: string,
  lines: string[],
  line: number,
  endLine: number,
): void {
  const slice = lines.slice(line - 1, endLine).join('\n')
  const fig = document.createElement('figure')
  fig.className = 'code-embed'

  const head = document.createElement('figcaption')
  head.className = 'code-embed-head'
  const label = document.createElement('span')
  label.className = 'code-embed-label'
  label.textContent = img.getAttribute('alt') ?? ''
  const loc = document.createElement('a')
  loc.className = 'code-embed-loc'
  loc.textContent = endLine > line ? `L${line}–${endLine}` : `L${line}`
  loc.title = 'jump to source in preview'
  loc.insertAdjacentHTML('beforeend', JUMP_ICON)
  loc.addEventListener('click', (e) => {
    e.preventDefault()
    window.dispatchEvent(new CustomEvent('atlas-code-jump', { detail: { path, line, endLine } }))
  })
  head.append(label, loc)

  const pre = document.createElement('pre')
  const code = document.createElement('code')
  code.className = 'hljs'
  const lang = languageFor(path)
  if (lang && window.hljs?.getLanguage(lang)) {
    code.innerHTML = window.hljs.highlight(slice, { language: lang, ignoreIllegals: true }).value
  } else {
    code.textContent = slice
  }
  pre.appendChild(code)
  fig.append(head, pre)

  const total = endLine - line + 1
  if (total > EMBED_COLLAPSE_LINES) {
    fig.classList.add('collapsed')
    const more = document.createElement('button')
    more.type = 'button'
    more.className = 'code-embed-more'
    more.textContent = `show all ${total} lines`
    more.addEventListener('click', () => {
      fig.classList.remove('collapsed')
      more.remove()
    })
    fig.appendChild(more)
  }

  // markdown wraps a lone image in a <p>; block content can't live inside it
  const p = img.parentElement
  if (p?.tagName === 'P' && p.childNodes.length === 1) p.replaceWith(fig)
  else img.replaceWith(fig)
}

/**
 * Code anchors: on a FILE page, an inline `code` naming something that occurs
 * in the file becomes a jump link — click scrolls the preview pane to it.
 *
 * Anchors are content-addressed and resolved at render time against the
 * CURRENT source (definition-shaped line first, first mention otherwise), so
 * they follow the code as it moves — no stored line numbers to rot. If the
 * symbol disappears (renamed/deleted) the link silently degrades back to
 * plain code, and the note's own staleness flag is what says "re-read me".
 */
export function annotateCodeAnchors(container: HTMLElement, path: string, source: string): void {
  const lines = source.split('\n')
  const findLine = (name: string): number | null => findLineInSource(lines, name)
  const wire = (a: HTMLElement, line: number, endLine: number, implicit = false) => {
    a.className = 'code-anchor' + (implicit ? ' implicit' : '')
    a.title = endLine > line ? `jump to lines ${line}–${endLine}` : `jump to line ${line}`
    a.insertAdjacentHTML('beforeend', JUMP_ICON)
    a.addEventListener('click', (e) => {
      e.preventDefault()
      window.dispatchEvent(new CustomEvent('atlas-code-jump', { detail: { path, line, endLine } }))
    })
  }

  // embedded code: ![label](code:startMarker..endMarker) — same markers as the
  // link form, but rendered in place as a highlighted slice of the CURRENT
  // source (transclusion, never a stored copy — it can't go stale). A single
  // marker embeds its whole brace-balanced block. Unresolved → label text.
  for (const img of container.querySelectorAll<HTMLImageElement>('img[src^="code:"]')) {
    const spec = decodeURIComponent(img.getAttribute('src')!.slice('code:'.length))
    const [startMarker, endMarker] = spec.split('..')
    const line = startMarker ? findLine(startMarker.trim()) : null
    if (line === null) {
      degradeEmbed(img)
      continue
    }
    const e = endMarker?.trim() ? findLine(endMarker.trim()) : null
    // rotted end marker falls back to the block — still useful, and `check` flags the rot
    const endLine = e !== null && e > line ? e - 1 : blockEndFor(lines, line)
    buildCodeEmbed(img, path, lines, line, endLine)
  }

  // explicit anchors: [label](code:startMarker..endMarker) — both markers are
  // content-resolved against the current source; the range runs from the start
  // marker's line up to just before the end marker's ("until the next section
  // begins"). A single marker is a one-line anchor. Unresolved → plain text.
  for (const a of container.querySelectorAll<HTMLAnchorElement>('a[href^="code:"]')) {
    if (a.closest('pre')) continue
    const spec = decodeURIComponent(a.getAttribute('href')!.slice('code:'.length))
    const [startMarker, endMarker] = spec.split('..')
    const line = startMarker ? findLine(startMarker.trim()) : null
    if (line === null) {
      a.replaceWith(...a.childNodes) // marker rotted away — degrade to plain text
      continue
    }
    let endLine = line
    if (endMarker?.trim()) {
      const e = findLine(endMarker.trim())
      if (e !== null && e > line) endLine = e - 1
    }
    a.removeAttribute('href')
    wire(a, line, endLine)
  }

  // implicit anchors: inline `code` naming something present in this file
  for (const code of container.querySelectorAll('code')) {
    if (code.parentElement?.closest('a, pre')) continue
    const raw = code.textContent?.trim() ?? ''
    const name = raw.replace(/\(\)$/, '')
    if (!name || name.length < 3 || /[\s`"'{}<>]/.test(name) || !/[A-Za-z]/.test(name)) continue
    const line = findLine(name)
    if (line === null) continue
    const a = document.createElement('a')
    code.replaceWith(a)
    a.appendChild(code)
    wire(a, line, line, true)
  }
}

let popoverEl: HTMLDivElement | null = null
let pinned: { anchor: HTMLElement; entry: GlossaryEntry } | null = null

function popover(): HTMLDivElement {
  if (!popoverEl) {
    popoverEl = document.createElement('div')
    popoverEl.className = 'glossary-pop'
    popoverEl.hidden = true
    document.body.appendChild(popoverEl)
    document.addEventListener('click', (e) => {
      if (!pinned) return
      if (popoverEl!.contains(e.target as Node) || (e.target as Element).closest?.('.term')) return
      unpin()
    })
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') unpin()
    })
    document.addEventListener(
      'scroll',
      () => {
        if (!pinned) return
        const a = pinned.anchor
        if (!a.isConnected) return unpin()
        const r = a.getBoundingClientRect()
        if (r.bottom < 0 || r.top > window.innerHeight) return unpin()
        placePopover(a)
      },
      true,
    )
  }
  return popoverEl
}

function unpin(): void {
  pinned = null
  if (popoverEl) {
    popoverEl.hidden = true
    popoverEl.classList.remove('pinned')
  }
}

function placePopover(anchor: HTMLElement): void {
  const r = anchor.getBoundingClientRect()
  popoverEl!.style.left = Math.max(8, Math.min(r.left, window.innerWidth - 356)) + 'px'
  popoverEl!.style.top = r.bottom + 6 + 'px'
}

function showPopover(anchor: HTMLElement, entry: GlossaryEntry): void {
  const pop = popover()
  pop.textContent = ''
  const term = document.createElement('b')
  term.textContent = entry.term
  const def = document.createElement('div')
  def.textContent = entry.def
  pop.append(term, def)
  pop.hidden = false
  placePopover(anchor)
}

const escapeReg = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

export function annotateGlossary(container: HTMLElement, glossary: GlossaryEntry[]): void {
  if (pinned && !pinned.anchor.isConnected) unpin()
  if (!glossary?.length) return
  const entries: [string, GlossaryEntry][] = []
  for (const g of glossary) for (const t of [g.term, ...(g.aliases ?? [])]) if (t) entries.push([t, g])
  if (!entries.length) return
  entries.sort((a, b) => b[0].length - a[0].length)
  const byText = new Map(entries.slice().reverse())
  const pattern = new RegExp(entries.map(([t]) => escapeReg(t)).join('|'), 'g')

  const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, {
    acceptNode(n) {
      if (!n.nodeValue?.trim()) return NodeFilter.FILTER_REJECT
      if (n.parentElement?.closest('a, pre, .term, .mermaid-diagram')) return NodeFilter.FILTER_REJECT
      return NodeFilter.FILTER_ACCEPT
    },
  })
  const textNodes: Text[] = []
  while (walker.nextNode()) textNodes.push(walker.currentNode as Text)

  for (const tn of textNodes) {
    const text = tn.nodeValue ?? ''
    pattern.lastIndex = 0
    let m: RegExpExecArray | null
    let last = 0
    let frag: DocumentFragment | null = null
    while ((m = pattern.exec(text)) !== null) {
      // word-boundary guard for Latin/numeric terms: "L1" must not match
      // inside "L114" or "XL1". CJK needs no boundary — no spaces to key on.
      const hit = m[0]
      const before = text[m.index - 1]
      const after = text[m.index + hit.length]
      const wordChar = (ch: string | undefined) => !!ch && /[A-Za-z0-9_]/.test(ch)
      if (
        (/[A-Za-z0-9]/.test(hit[0]) && wordChar(before)) ||
        (/[A-Za-z0-9]/.test(hit[hit.length - 1]) && wordChar(after))
      ) continue
      frag ??= document.createDocumentFragment()
      if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)))
      const span = document.createElement('span')
      span.className = 'term'
      span.textContent = m[0]
      const entry = byText.get(m[0])!
      span.addEventListener('mouseenter', () => { if (!pinned) showPopover(span, entry) })
      span.addEventListener('mouseleave', () => { if (!pinned) popover().hidden = true })
      span.addEventListener('click', (e) => {
        e.stopPropagation()
        if (pinned?.anchor === span) return unpin()
        pinned = { anchor: span, entry }
        showPopover(span, entry)
        popover().classList.add('pinned')
      })
      frag.appendChild(span)
      last = m.index + m[0].length
    }
    if (frag) {
      if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)))
      tn.replaceWith(frag)
    }
  }
}