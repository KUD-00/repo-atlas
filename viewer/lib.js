// Pure helpers shared by the viewer components. No React in here.

/** Flatten the tree into path->node, and give every node subtree rollups. */
export function indexTree(root) {
  const nodesByPath = new Map()
  ;(function walk(n) {
    n.agg = {
      outdated: n.status === 'outdated' ? 1 : 0,
      missing: n.status === 'missing' ? 1 : 0,
      total: 1,
    }
    nodesByPath.set(n.path, n)
    for (const c of n.children) {
      walk(c)
      n.agg.outdated += c.agg.outdated
      n.agg.missing += c.agg.missing
      n.agg.total += c.agg.total
    }
  })(root)
  return nodesByPath
}

/** Ancestor dir paths of a repo path, root ('') first — the path itself excluded. */
export function ancestorsOf(path) {
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

/** Where the note file for a path lives — shown in the empty-note hint. */
export function noteFileFor(node) {
  if (node.type === 'dir') return '.atlas/notes/' + (node.path ? node.path + '/' : '') + '__dir__.md'
  return '.atlas/notes/' + node.path + '.md'
}

/**
 * Inline-code path linking: a <code> whose text resolves to a scanned path —
 * absolute (packages/kernel/core), relative to the note's directory (core,
 * src/queue.ts), or with a trailing / or * tail (drivers/, sandbox-provider*)
 * — becomes a link to that path's page. View-side only; notes stay plain.
 */
export function linkifyPaths(container, node, nodesByPath) {
  const base = node.type === 'dir' ? node.path : node.path.slice(0, node.path.lastIndexOf('/'))
  for (const code of container.querySelectorAll('code')) {
    if (code.parentElement.closest('a, pre')) continue
    const raw = code.textContent.trim()
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

/** Swap ```mermaid fences (already rendered to pre>code) for SVG diagrams. */
let mermaidSeq = 0
let mermaidReady = false
export async function renderMermaidIn(container) {
  if (!window.mermaid) return // bundle is embedded only when some note uses a fence
  const blocks = container.querySelectorAll('pre > code.language-mermaid')
  if (!blocks.length) return
  if (!mermaidReady) {
    window.mermaid.initialize({ startOnLoad: false, theme: 'neutral' })
    mermaidReady = true
  }
  for (const code of blocks) {
    const src = code.textContent
    const holder = document.createElement('div')
    holder.className = 'mermaid-diagram'
    code.parentElement.replaceWith(holder)
    try {
      const { svg } = await window.mermaid.render('mmd-' + ++mermaidSeq, src)
      holder.innerHTML = svg
    } catch (err) {
      const pre = document.createElement('pre')
      pre.className = 'mermaid-error'
      pre.textContent = 'mermaid: ' + (err.message ?? err) + '\n\n' + src
      holder.replaceChildren(pre)
      document.getElementById('mmd-' + mermaidSeq)?.remove()
    }
  }
}

/** File extension → highlight.js language for the source preview pane. */
const PV_LANG = {
  ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript',
  js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
  json: 'json', jsonc: 'json', md: 'markdown', mdx: 'markdown',
  css: 'css', html: 'xml', xml: 'xml', svg: 'xml', astro: 'xml', vue: 'xml',
  py: 'python', sh: 'bash', bash: 'bash', zsh: 'bash', yml: 'yaml', yaml: 'yaml',
  sql: 'sql', rs: 'rust', go: 'go', nix: 'nix', toml: 'ini', ini: 'ini', diff: 'diff',
}

export function languageFor(path) {
  const name = path.slice(path.lastIndexOf('/') + 1).toLowerCase()
  if (name.startsWith('dockerfile')) return 'dockerfile'
  const ext = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1) : ''
  return PV_LANG[ext] ?? null
}

/** Decode the embedded import graph into path-pair edges + package-root set. */
export function buildRelationIndex(graph) {
  if (!graph) return null
  const paths = graph.paths
  return {
    edges: graph.edges.map(([s, d]) => [paths[s], paths[d]]),
    packageRoots: new Set(graph.packageRoots),
  }
}

/**
 * Dependencies / dependents of a node, from the import graph. File nodes get
 * exact endpoint paths; directory nodes get endpoints grouped to their nearest
 * package root (own package excluded — internal wiring is not a relation).
 */
export function relationsFor(node, rel, nodesByPath) {
  if (!rel || node.path === '') return { deps: [], dependents: [] }
  const prefix = node.path + '/'
  const inside = (p) => p === node.path || p.startsWith(prefix)
  const groupOf = (p) => {
    let cur = p
    while (cur) {
      if (rel.packageRoots.has(cur)) return cur
      cur = cur.includes('/') ? cur.slice(0, cur.lastIndexOf('/')) : ''
    }
    return p.includes('/') ? p.split('/')[0] : p
  }
  const isFile = node.type === 'file'
  const ownGroup = groupOf(node.path)
  const deps = new Set()
  const dependents = new Set()
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
  const clean = (set) => [...set].filter((p) => p !== node.path && nodesByPath.has(p)).sort()
  return { deps: clean(deps), dependents: clean(dependents) }
}

// ---------------------------------------------------------------------------
// Glossary: highlight known terms in prose, define them in a hover popover.
// ---------------------------------------------------------------------------

let popoverEl = null
function popover() {
  if (!popoverEl) {
    popoverEl = document.createElement('div')
    popoverEl.className = 'glossary-pop'
    popoverEl.hidden = true
    document.body.appendChild(popoverEl)
  }
  return popoverEl
}

function showPopover(anchor, entry) {
  const pop = popover()
  pop.textContent = ''
  const term = document.createElement('b')
  term.textContent = entry.term
  const def = document.createElement('div')
  def.textContent = entry.def
  pop.append(term, def)
  pop.hidden = false
  const r = anchor.getBoundingClientRect()
  pop.style.left = Math.max(8, Math.min(r.left, window.innerWidth - 356)) + 'px'
  pop.style.top = r.bottom + 6 + 'px'
}

const escapeReg = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** Wrap every glossary term/alias occurrence in prose text with a hover span. */
export function annotateGlossary(container, glossary) {
  if (!glossary?.length) return
  const entries = []
  for (const g of glossary) for (const t of [g.term, ...(g.aliases ?? [])]) if (t) entries.push([t, g])
  if (!entries.length) return
  entries.sort((a, b) => b[0].length - a[0].length)
  const byText = new Map(entries.slice().reverse()) // longest wins on ties
  const pattern = new RegExp(entries.map(([t]) => escapeReg(t)).join('|'), 'g')

  const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, {
    acceptNode(n) {
      if (!n.nodeValue.trim()) return NodeFilter.FILTER_REJECT
      if (n.parentElement?.closest('a, pre, .term, .mermaid-diagram')) return NodeFilter.FILTER_REJECT
      return NodeFilter.FILTER_ACCEPT
    },
  })
  const textNodes = []
  while (walker.nextNode()) textNodes.push(walker.currentNode)

  for (const tn of textNodes) {
    const text = tn.nodeValue
    pattern.lastIndex = 0
    let m
    let last = 0
    let frag = null
    while ((m = pattern.exec(text)) !== null) {
      frag ??= document.createDocumentFragment()
      if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)))
      const span = document.createElement('span')
      span.className = 'term'
      span.textContent = m[0]
      const entry = byText.get(m[0])
      span.addEventListener('mouseenter', () => showPopover(span, entry))
      span.addEventListener('mouseleave', () => { popover().hidden = true })
      frag.appendChild(span)
      last = m.index + m[0].length
    }
    if (frag) {
      if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)))
      tn.replaceWith(frag)
    }
  }
}
