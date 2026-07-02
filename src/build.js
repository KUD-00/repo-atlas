import fs from 'node:fs'
import path from 'node:path'
import { marked } from 'marked'

/**
 * Build a self-contained HTML atlas from a status result.
 * Tree data is embedded as JSON; markdown bodies are pre-rendered at build time.
 */
export function buildHtml({ repoName, commit, status }) {
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
  }
  const json = JSON.stringify(data).replace(/</g, '\\u003c')

  return TEMPLATE.replace('__TITLE__', escapeHtml(repoName)).replace('"__DATA__"', json)
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
<style>
  :root {
    --bg: #fbfbfa; --panel: #ffffff; --border: #e7e5e1; --text: #1f1e1c;
    --muted: #8a867e; --accent: #3d6b54;
    --fresh: #4a9d6e; --outdated: #d9930d; --missing: #c4c0b8;
    font-size: 15px;
  }
  * { box-sizing: border-box; margin: 0; }
  body {
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    background: var(--bg); color: var(--text); height: 100vh;
    display: grid; grid-template-columns: 340px 1fr; overflow: hidden;
  }
  aside { border-right: 1px solid var(--border); background: var(--panel); display: flex; flex-direction: column; min-width: 0; }
  .side-head { padding: 14px 16px 10px; border-bottom: 1px solid var(--border); }
  .side-head h1 { font-size: 0.95rem; font-weight: 600; }
  .side-head .meta { font-size: 0.72rem; color: var(--muted); margin-top: 2px; }
  .counts { display: flex; gap: 10px; margin-top: 8px; font-size: 0.72rem; color: var(--muted); }
  .counts b { color: var(--text); font-weight: 600; }
  .filters { padding: 8px 12px; border-bottom: 1px solid var(--border); display: flex; gap: 6px; align-items: center; }
  .filters input {
    flex: 1; min-width: 0; font: inherit; font-size: 0.8rem; padding: 4px 8px;
    border: 1px solid var(--border); border-radius: 6px; background: var(--bg); color: var(--text);
  }
  .filters input:focus { outline: none; border-color: var(--accent); }
  .chip {
    font-size: 0.7rem; padding: 3px 8px; border-radius: 99px; border: 1px solid var(--border);
    background: none; color: var(--muted); cursor: pointer; white-space: nowrap;
  }
  .chip.on { border-color: var(--accent); color: var(--accent); background: #3d6b540f; }
  nav { flex: 1; overflow: auto; padding: 8px 6px 24px; }
  .row {
    display: flex; align-items: center; gap: 6px; padding: 2px 8px 2px 0; border-radius: 6px;
    cursor: pointer; user-select: none; font-size: 0.82rem; white-space: nowrap;
  }
  .row:hover { background: #00000006; }
  .row.sel { background: #3d6b5414; }
  .twist { width: 16px; flex: none; text-align: center; color: var(--muted); font-size: 0.65rem; }
  .dot { width: 8px; height: 8px; border-radius: 99px; flex: none; }
  .dot.fresh { background: var(--fresh); }
  .dot.outdated { background: var(--outdated); }
  .dot.missing { background: none; border: 1.5px solid var(--missing); }
  .row .name { overflow: hidden; text-overflow: ellipsis; }
  .row .name.dir { font-weight: 550; }
  .badge {
    margin-left: auto; font-size: 0.65rem; padding: 0 6px; border-radius: 99px; flex: none;
    color: var(--muted); background: #00000008;
  }
  .badge.warn { color: #9a6a06; background: #d9930d1a; }
  main { overflow: auto; min-width: 0; }
  .doc { max-width: 760px; padding: 36px 48px 96px; }
  .crumb { font-size: 0.78rem; color: var(--muted); word-break: break-all; }
  .doc h1.path { font-size: 1.25rem; font-weight: 650; margin: 4px 0 12px; word-break: break-all; }
  .state {
    display: inline-flex; align-items: center; gap: 7px; font-size: 0.75rem;
    border: 1px solid var(--border); border-radius: 8px; padding: 5px 10px; margin-bottom: 20px;
    background: var(--panel);
  }
  .state.outdated { border-color: #d9930d55; background: #d9930d0d; }
  .prose { line-height: 1.65; font-size: 0.92rem; }
  .prose h1, .prose h2, .prose h3 { margin: 1.4em 0 0.5em; line-height: 1.3; }
  .prose h1 { font-size: 1.15rem; } .prose h2 { font-size: 1.05rem; } .prose h3 { font-size: 0.95rem; }
  .prose p, .prose ul, .prose ol, .prose pre, .prose table { margin: 0.7em 0; }
  .prose ul, .prose ol { padding-left: 1.4em; }
  .prose code { background: #00000009; border: 1px solid var(--border); border-radius: 4px; padding: 0.05em 0.35em; font-size: 0.85em; }
  .prose pre { background: #f4f3f1; border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; overflow-x: auto; }
  .prose pre code { background: none; border: none; padding: 0; }
  .prose a { color: var(--accent); }
  .prose blockquote { border-left: 3px solid var(--border); padding-left: 1em; color: var(--muted); }
  .empty { color: var(--muted); font-size: 0.9rem; margin-top: 8px; }
  .empty code { background: #00000009; padding: 0.1em 0.4em; border-radius: 4px; font-size: 0.85em; }
</style>
</head>
<body>
<aside>
  <div class="side-head">
    <h1 id="repoName"></h1>
    <div class="meta" id="meta"></div>
    <div class="counts" id="counts"></div>
  </div>
  <div class="filters">
    <input id="q" type="search" placeholder="filter paths…">
    <button class="chip" id="chipOutdated">outdated</button>
    <button class="chip" id="chipMissing">missing</button>
  </div>
  <nav id="tree"></nav>
</aside>
<main><div class="doc" id="doc"></div></main>
<script>
const DATA = "__DATA__";
const treeEl = document.getElementById('tree');
const docEl = document.getElementById('doc');
let selected = null;
let filterText = '';
let filterStatus = null;

// subtree rollups
(function roll(n) {
  n.agg = { outdated: n.status === 'outdated' ? 1 : 0, missing: n.status === 'missing' ? 1 : 0 };
  for (const c of n.children) { roll(c); n.agg.outdated += c.agg.outdated; n.agg.missing += c.agg.missing; }
})(DATA.tree);

document.getElementById('repoName').textContent = DATA.repoName;
document.getElementById('meta').textContent =
  (DATA.commit ? '@ ' + DATA.commit + ' · ' : '') + new Date(DATA.generatedAt).toLocaleString();
{
  const a = DATA.tree.agg, total = countNodes(DATA.tree);
  document.getElementById('counts').innerHTML =
    '<span><b>' + (total - a.outdated - a.missing) + '</b> fresh</span>' +
    '<span><b>' + a.outdated + '</b> outdated</span>' +
    '<span><b>' + a.missing + '</b> missing</span>';
}
function countNodes(n) { return 1 + n.children.reduce((s, c) => s + countNodes(c), 0); }

function dot(status) { const d = document.createElement('span'); d.className = 'dot ' + status; return d; }

function makeRow(node, depth, expandable) {
  const row = document.createElement('div');
  row.className = 'row';
  row.style.paddingLeft = (depth * 14) + 'px';
  const twist = document.createElement('span');
  twist.className = 'twist';
  twist.textContent = expandable ? '▸' : '';
  row.appendChild(twist);
  row.appendChild(dot(node.status));
  const name = document.createElement('span');
  name.className = 'name' + (node.type === 'dir' ? ' dir' : '');
  name.textContent = node.name + (node.type === 'dir' ? '/' : '');
  row.appendChild(name);
  if (node.type === 'dir' && (node.agg.outdated || node.agg.missing)) {
    if (node.agg.outdated) {
      const b = document.createElement('span'); b.className = 'badge warn';
      b.textContent = node.agg.outdated; row.appendChild(b);
    }
    if (node.agg.missing) {
      const b = document.createElement('span'); b.className = 'badge';
      b.textContent = node.agg.missing; row.appendChild(b);
    }
  }
  return { row, twist };
}

// lazy tree rendering
function renderNode(node, depth, container) {
  const expandable = node.children.length > 0;
  const { row, twist } = makeRow(node, depth, expandable);
  container.appendChild(row);
  let childBox = null, open = false;
  const toggle = () => {
    if (!expandable) return;
    open = !open;
    twist.textContent = open ? '▾' : '▸';
    if (open && !childBox) {
      childBox = document.createElement('div');
      row.after(childBox);
      for (const c of node.children) renderNode(c, depth + 1, childBox);
    } else if (childBox) {
      childBox.style.display = open ? '' : 'none';
    }
  };
  row.addEventListener('click', (ev) => {
    select(node, row);
    if (node.type === 'dir') toggle();
  });
  twist.addEventListener('click', (ev) => { ev.stopPropagation(); toggle(); });
  if (depth === 0) toggle();
  return row;
}

function renderTree() {
  treeEl.textContent = '';
  if (!filterText && !filterStatus) { renderNode(DATA.tree, 0, treeEl); return; }
  // flat filtered list
  const q = filterText.toLowerCase();
  const walk = (n) => {
    const hit = (!q || n.path.toLowerCase().includes(q)) && (!filterStatus || n.status === filterStatus);
    if (hit && n.path !== '') {
      const { row } = makeRow(n, 0, false);
      row.querySelector('.name').textContent = n.path + (n.type === 'dir' ? '/' : '');
      row.addEventListener('click', () => select(n, row));
      treeEl.appendChild(row);
    }
    n.children.forEach(walk);
  };
  walk(DATA.tree);
  if (!treeEl.children.length) {
    const e = document.createElement('div'); e.className = 'empty'; e.style.padding = '8px 12px';
    e.textContent = 'no matches'; treeEl.appendChild(e);
  }
}

let selRow = null;
function select(node, row) {
  selected = node;
  if (selRow) selRow.classList.remove('sel');
  selRow = row; row.classList.add('sel');
  renderDoc(node);
}

function renderDoc(node) {
  const labels = { fresh: 'up to date', outdated: 'outdated — code changed since this was written', missing: 'no description yet' };
  docEl.innerHTML = '';
  const crumb = document.createElement('div'); crumb.className = 'crumb';
  crumb.textContent = node.type === 'dir' ? 'directory' : 'file';
  docEl.appendChild(crumb);
  const h = document.createElement('h1'); h.className = 'path';
  h.textContent = node.path === '' ? DATA.repoName : node.path;
  docEl.appendChild(h);
  const state = document.createElement('div'); state.className = 'state ' + node.status;
  state.appendChild(dot(node.status));
  state.appendChild(document.createTextNode(labels[node.status] +
    (node.stamped ? ' · stamped ' + new Date(node.stamped).toLocaleDateString() : '')));
  docEl.appendChild(state);
  if (node.html) {
    const prose = document.createElement('div'); prose.className = 'prose';
    prose.innerHTML = node.html;
    docEl.appendChild(prose);
  } else {
    const e = document.createElement('div'); e.className = 'empty';
    e.innerHTML = 'No note for this path. Write one at <code></code> and run <code>repo-atlas stamp</code>.';
    e.querySelector('code').textContent = '.atlas/notes/' +
      (node.type === 'dir' ? (node.path ? node.path + '/' : '') + '__dir__.md' : node.path + '.md');
    docEl.appendChild(e);
  }
}

document.getElementById('q').addEventListener('input', (e) => { filterText = e.target.value.trim(); renderTree(); });
for (const [id, st] of [['chipOutdated', 'outdated'], ['chipMissing', 'missing']]) {
  const el = document.getElementById(id);
  el.addEventListener('click', () => {
    filterStatus = filterStatus === st ? null : st;
    document.getElementById('chipOutdated').classList.toggle('on', filterStatus === 'outdated');
    document.getElementById('chipMissing').classList.toggle('on', filterStatus === 'missing');
    renderTree();
  });
}

renderTree();
select(DATA.tree, treeEl.firstChild);
</script>
</body>
</html>`

export function writeAtlas(root, outFile, html) {
  const target = path.isAbsolute(outFile) ? outFile : path.join(root, outFile)
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, html)
  return target
}
