import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { marked } from 'marked'

const VENDOR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'vendor')

/**
 * The viewer is a React app (viewer/*.jsx) prebuilt into src/vendor/viewer.js
 * + viewer.css by `pnpm build:viewer` and COMMITTED — so target repos still run
 * the tool with zero install/build. Hack on viewer/, run `pnpm dev:viewer`
 * (esbuild --watch), and commit the regenerated bundle alongside.
 */
function readVendor(name) {
  const file = path.join(VENDOR, name)
  try {
    return fs.readFileSync(file, 'utf8')
  } catch {
    throw new Error(`${file} missing — run \`pnpm build:viewer\` in the repo-atlas checkout`)
  }
}

const hljsJs = fs.readFileSync(path.join(VENDOR, 'hljs.js'), 'utf8')
const hljsCss = fs.readFileSync(path.join(VENDOR, 'hljs-theme.css'), 'utf8')

// mermaid is ~3.4MB, so it is embedded only when at least one note actually
// contains a ```mermaid fence; read lazily and cached.
let mermaidJs = null
function loadMermaid() {
  return (mermaidJs ??= fs.readFileSync(path.join(VENDOR, 'mermaid.js'), 'utf8'))
}

/**
 * Build a self-contained HTML atlas from a status result.
 * Tree data is embedded as JSON; markdown bodies are pre-rendered at build time.
 */
export function buildHtml({ repoName, commit, status, graph = null, glossary = [] }) {
  const byPath = new Map(status.entries.map((e) => [e.path, e]))

  // nested tree from flat paths; root is ''
  const makeNode = (p) => {
    const e = byPath.get(p)
    return {
      name: p === '' ? repoName : p.slice(p.lastIndexOf('/') + 1),
      path: p,
      type: e.type,
      status: e.status,
      stamped: e.stamped ?? null,
      html: e.body ? marked.parse(e.body) : null,
      children: [],
    }
  }
  const nodes = new Map()
  for (const e of status.entries) nodes.set(e.path, makeNode(e.path))
  const root = nodes.get('')
  for (const [p, node] of nodes) {
    if (p === '') continue
    const parent = nodes.get(p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '')
    parent.children.push(node)
  }
  const sortChildren = (n) => {
    n.children.sort((a, b) =>
      a.type !== b.type ? (a.type === 'dir' ? -1 : 1) : a.name < b.name ? -1 : 1,
    )
    n.children.forEach(sortChildren)
  }
  sortChildren(root)

  const data = {
    repoName,
    commit,
    generatedAt: new Date().toISOString(),
    tree: root,
    orphans: status.orphans.map((o) => o.path),
    graph,
    glossary,
  }
  const json = JSON.stringify(data).replace(/</g, '\\u003c')
  const usesMermaid = status.entries.some((e) => e.body?.includes('```mermaid'))

  // function-form replacements: the payloads may contain `$&`-style sequences
  // that String.replace would otherwise interpret
  return TEMPLATE.replace('__TITLE__', () => escapeHtml(repoName))
    .replace('/*__VIEWER_CSS__*/', () => readVendor('viewer.css'))
    .replace('/*__HLJS_CSS__*/', () => hljsCss)
    .replace('"__DATA__"', () => json)
    .replace('/*__HLJS_JS__*/', () => hljsJs)
    .replace('/*__MERMAID_JS__*/', () => (usesMermaid ? loadMermaid() : ''))
    .replace('/*__VIEWER_JS__*/', () => readVendor('viewer.js'))
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

const TEMPLATE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ · atlas</title>
<style>/*__VIEWER_CSS__*/</style>
<style>/*__HLJS_CSS__*/</style>
</head>
<body>
<div id="root"></div>
<script>window.__ATLAS__ = "__DATA__";</script>
<script>/*__HLJS_JS__*/</script>
<script>/*__MERMAID_JS__*/</script>
<script>/*__VIEWER_JS__*/</script>
</body>
</html>`

export function writeAtlas(root, outFile, html) {
  const target = path.isAbsolute(outFile) ? outFile : path.join(root, outFile)
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, html)
  return target
}
