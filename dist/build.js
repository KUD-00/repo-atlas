import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { marked } from 'marked';
const VENDOR = path.join(path.dirname(fileURLToPath(import.meta.url)), '../src/vendor');
function readVendor(name) {
    const file = path.join(VENDOR, name);
    try {
        return fs.readFileSync(file, 'utf8');
    }
    catch {
        throw new Error(`${file} missing — run \`pnpm build:viewer\` in the repo-atlas checkout`);
    }
}
const hljsJs = fs.readFileSync(path.join(VENDOR, 'hljs.js'), 'utf8');
const hljsCss = fs.readFileSync(path.join(VENDOR, 'hljs-theme.css'), 'utf8');
let mermaidJs = null;
function loadMermaid() {
    return (mermaidJs ??= fs.readFileSync(path.join(VENDOR, 'mermaid.js'), 'utf8'));
}
export function buildHtml({ repoName, commit, status, graph = null, glossary = [], }) {
    const byPath = new Map(status.entries.map((e) => [e.path, e]));
    const makeNode = (p) => {
        const e = byPath.get(p);
        return {
            name: p === '' ? repoName : p.slice(p.lastIndexOf('/') + 1),
            path: p,
            type: e.type,
            status: e.status,
            stamped: e.stamped ?? null,
            html: e.body ? String(marked.parse(e.body)) : null,
            source: e.body ?? null,
            order: e.type === 'dir' ? e.order ?? null : null,
            children: [],
        };
    };
    const nodes = new Map();
    for (const e of status.entries)
        nodes.set(e.path, makeNode(e.path));
    const root = nodes.get('');
    for (const [p, node] of nodes) {
        if (p === '')
            continue;
        const parent = nodes.get(p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
        parent.children.push(node);
    }
    const imports = siblingImports(graph);
    const sortChildren = (n) => {
        n.children = orderChildren(n, imports.get(n.path));
        n.children.forEach(sortChildren);
    };
    sortChildren(root);
    const data = {
        repoName,
        commit,
        generatedAt: new Date().toISOString(),
        tree: root,
        orphans: status.orphans.map((o) => o.path),
        graph,
        glossary,
    };
    const json = JSON.stringify(data).replace(/</g, '\\u003c');
    const usesMermaid = status.entries.some((e) => e.body?.includes('```mermaid'));
    return TEMPLATE.replace('__TITLE__', () => escapeHtml(repoName))
        .replace('/*__VIEWER_CSS__*/', () => readVendor('viewer.css'))
        .replace('/*__HLJS_CSS__*/', () => hljsCss)
        .replace('"__DATA__"', () => json)
        .replace('/*__HLJS_JS__*/', () => hljsJs)
        .replace('/*__MERMAID_JS__*/', () => (usesMermaid ? loadMermaid() : ''))
        .replace('/*__VIEWER_JS__*/', () => readVendor('viewer.js'));
}
/**
 * Reading order of a directory's children.
 *
 * 1. Children named in the dir note's `order` frontmatter come first, in that
 *    order (a PARTIAL list — names that don't exist are skipped here and
 *    reported as broken refs by status).
 * 2. The rest follow a top-down import heuristic: a child no sibling imports
 *    is an entry point and reads first; then Kahn's algorithm walks the
 *    sibling import edges. Ties (and cycles) break dirs-first, then alpha —
 *    which is also the fallback when there is no graph signal at all.
 */
function orderChildren(n, edges) {
    const byName = new Map(n.children.map((c) => [c.name, c]));
    const head = (n.order ?? []).map((name) => byName.get(name)).filter((c) => !!c);
    const placed = new Set(head);
    const rest = n.children.filter((c) => !placed.has(c));
    // imported-by counts among the remaining siblings; entry points have zero.
    // Tests also have zero (nobody imports a test) — the isTest flag keeps them
    // from posing as entry points, and out-degree ranks the child that pulls in
    // the most siblings (the real composition root) first among the rest.
    const isTest = (c) => /\.(test|spec)\.|^tests?$|^__tests__$|fixtures/.test(c.name);
    const inDeg = new Map(rest.map((c) => [c.name, 0]));
    const outDeg = new Map(rest.map((c) => [c.name, 0]));
    if (edges) {
        for (const [from, tos] of edges) {
            if (!inDeg.has(from))
                continue;
            let n = 0;
            for (const to of tos)
                if (inDeg.has(to) && from !== to) {
                    inDeg.set(to, inDeg.get(to) + 1);
                    n++;
                }
            outDeg.set(from, n);
        }
    }
    const better = (a, b) => {
        if (isTest(a) !== isTest(b))
            return !isTest(a);
        const ao = outDeg.get(a.name) ?? 0;
        const bo = outDeg.get(b.name) ?? 0;
        if (ao !== bo)
            return ao > bo;
        return a.type !== b.type ? a.type === 'dir' : a.name < b.name;
    };
    const remaining = new Set(rest);
    const out = [...head];
    while (remaining.size) {
        let pick = null;
        let pickBlocked = true;
        for (const c of remaining) {
            const blocked = inDeg.get(c.name) > 0;
            if (pick === null ||
                (blocked !== pickBlocked ? !blocked : better(c, pick))) {
                pick = c;
                pickBlocked = blocked;
            }
        }
        remaining.delete(pick);
        out.push(pick);
        const tos = edges?.get(pick.name);
        if (tos)
            for (const to of tos)
                if (inDeg.has(to))
                    inDeg.set(to, Math.max(0, inDeg.get(to) - 1));
    }
    return out;
}
/**
 * Fold the file-level import graph up to sibling edges: every edge contributes
 * one `childA imports childB` relation inside the directory where the two
 * paths diverge. dir -> (child name -> imported sibling names).
 */
function siblingImports(graph) {
    const out = new Map();
    if (!graph)
        return out;
    for (const [si, di] of graph.edges) {
        const s = graph.paths[si].split('/');
        const d = graph.paths[di].split('/');
        let k = 0;
        while (k < s.length && k < d.length && s[k] === d[k])
            k++;
        if (k >= s.length || k >= d.length)
            continue; // one path contains the other
        const dir = s.slice(0, k).join('/');
        let sib = out.get(dir);
        if (!sib)
            out.set(dir, (sib = new Map()));
        let tos = sib.get(s[k]);
        if (!tos)
            sib.set(s[k], (tos = new Set()));
        tos.add(d[k]);
    }
    return out;
}
function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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
</html>`;
export function writeAtlas(root, outFile, html) {
    const target = path.isAbsolute(outFile) ? outFile : path.join(root, outFile);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, html);
    return target;
}
