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
