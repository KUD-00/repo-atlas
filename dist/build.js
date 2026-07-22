import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { marked } from 'marked';
import { fillGlossaryRefs } from './glossary.js';
import { buildAttentionPayload } from './attention.js';
import { missingReviewCoverage } from './review-coverage.js';
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
function conceptProjection(body) {
    const tokens = marked.lexer(body);
    const headings = [];
    let offset = 0;
    for (const token of tokens) {
        if (token.type === 'heading' && token.depth >= 2 && token.depth <= 6) {
            headings.push({ offset, level: token.depth, title: token.text.trim() });
        }
        offset += token.raw.length;
    }
    if (headings.length === 0)
        return { overview: body, sections: [] };
    const opening = body.slice(0, headings[0].offset);
    // Pages that begin immediately with a section still need a useful entry:
    // use that first section, not an empty overview or the entire long page.
    const overview = opening.trim()
        ? opening
        : body.slice(0, headings[1]?.offset ?? body.length);
    return {
        overview,
        sections: headings.map(({ level, title }) => ({ level, title })),
    };
}
/** The data the viewer runs on — also served as JSON by `serve`'s /data so
 * open pages can refresh in place instead of reloading. */
export function buildPayload({ repoName, commit, status, graph = null, glossary = [], basePoints = [], artifacts = [], audits = [], testAudits = [], reviewCoverage = missingReviewCoverage(), defaultLocale = 'en', auditSourceLocale = 'en', auditLocalizations = {}, attention, }) {
    const generatedAt = new Date().toISOString();
    const byPath = new Map(status.entries.map((e) => [e.path, e]));
    const makeNode = (p) => {
        const e = byPath.get(p);
        return {
            name: p === '' ? repoName : p.slice(p.lastIndexOf('/') + 1),
            path: p,
            type: e.type,
            status: e.status,
            stamped: e.stamped ?? null,
            anchor: e.anchor ?? null,
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
    // Fill each glossary term's reverse index (which notes reference it) from the
    // note bodies we already have. `home` was parsed from glossary.md upstream.
    fillGlossaryRefs(glossary, status.entries.map((e) => ({ path: e.path, body: e.body })));
    const concepts = status.concepts.map((c) => {
        const projection = conceptProjection(c.body);
        return {
            slug: c.slug,
            title: c.title,
            audience: c.audience,
            chapter: c.chapter,
            status: c.status,
            sources: c.sources,
            currentSourcesHash: c.currentSourcesHash,
            snapshot: c.snapshot,
            brokenSources: c.brokenSources,
            stamped: c.stamped,
            anchor: c.anchor,
            html: c.body ? String(marked.parse(c.body)) : null,
            briefHtml: c.body ? String(marked.parse(projection.overview)) : null,
            sections: projection.sections,
            source: c.body || null,
        };
    });
    // Resolve `home: concept:<slug>` to the concept's title so the glossary popover
    // renders "canonical home → 《title》" and links to the concept page — concepts
    // become the expand target for any note (code doc included) that uses the term.
    const conceptTitleBySlug = new Map(concepts.map((c) => [c.slug, c.title]));
    for (const g of glossary) {
        if (g.home?.startsWith('concept:')) {
            const title = conceptTitleBySlug.get(g.home.slice('concept:'.length));
            if (title)
                g.homeTitle = title;
        }
    }
    // md artifacts render through the same markdown pipeline as notes; json
    // stays raw — the viewer shows it as a (collapsible) code block
    const artifactIndex = {};
    for (const a of artifacts) {
        const node = {
            name: a.name,
            kind: a.kind,
            html: a.kind === 'md' ? String(marked.parse(a.body)) : null,
            raw: a.kind === 'json' ? a.body : null,
        };
        (artifactIndex[a.pageKey] ??= []).push(node);
    }
    return {
        repoName,
        commit,
        generatedAt,
        tree: root,
        orphans: status.orphans.map((o) => o.path),
        graph,
        glossary,
        basePoints,
        concepts,
        attention: attention ?? buildAttentionPayload(status, { mode: 'static', now: generatedAt }),
        artifacts: artifactIndex,
        audits,
        testAudits,
        reviewCoverage,
        defaultLocale,
        auditSourceLocale,
        auditLocalizations,
    };
}
export function buildHtml(input) {
    const data = input.payload ?? buildPayload(input);
    const json = JSON.stringify(data).replace(/</g, '\\u003c');
    const usesMermaid = input.status.entries.some((e) => e.body?.includes('```mermaid')) ||
        input.status.concepts.some((c) => c.body.includes('```mermaid')) ||
        (input.artifacts ?? []).some((a) => a.kind === 'md' && a.body.includes('```mermaid'));
    return TEMPLATE.replace('__TITLE__', () => escapeHtml(data.repoName))
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
    // Auxiliary children (tests, build scripts, tools, migrations) also have zero
    // in-degree — nobody imports them — but they are NOT entry points: a build
    // script imports INTO src, which would otherwise (a) make the script pose as
    // the entry point and read first, and (b) mark src as a mere "dependency" and
    // sink it. So aux children neither contribute in-degree (they don't block real
    // source) nor rank as entry points (isAux sinks them in `better`). Out-degree
    // then ranks the child that pulls in the most siblings (the real composition
    // root) first among what remains.
    const isAux = (c) => /\.(test|spec)\.|^tests?$|^__tests__$|fixtures|^test-(helpers|fixtures|utils)$|^scripts?$|^bin$|^tools?$|^examples?$|^benchmarks?$|^drizzle$|^migrations?$/.test(c.name);
    const inDeg = new Map(rest.map((c) => [c.name, 0]));
    const outDeg = new Map(rest.map((c) => [c.name, 0]));
    if (edges) {
        for (const [from, tos] of edges) {
            if (!inDeg.has(from))
                continue;
            if (isAux(byName.get(from)))
                continue; // aux consumers don't block real source
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
        if (isAux(a) !== isAux(b))
            return !isAux(a);
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
        // aux picks never counted toward in-degree, so they must not decrement it
        // either (that would prematurely unblock a target imported by real source).
        const tos = isAux(pick) ? undefined : edges?.get(pick.name);
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
