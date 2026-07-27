import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { assertSafeAuditLedgerOutput, writeAuditLedgerFile } from './audits.js';
import { buildImportGraph } from './deps.js';
import { maskedLinesOf } from './readability.js';
import { DEFAULT_EXCLUDE, atlasDir, readRepoFile, scan } from './scan.js';
const picomatch = createRequire(import.meta.url)('picomatch');
const MAX_FILE_BYTES = 512 * 1024;
const CODE_EXT = /\.(?:[cm]?[jt]sx?)$/u;
function blobHash(buffer) {
    return createHash('sha1').update(`blob ${buffer.length}\0`).update(buffer).digest('hex');
}
function extOf(repoPath) {
    return repoPath.includes('.') ? repoPath.slice(repoPath.lastIndexOf('.') + 1).toLowerCase() : '';
}
function loadCode(root, scanResult) {
    const out = new Map();
    for (const rel of scanResult.files.keys()) {
        let opened;
        try {
            opened = readRepoFile(root, rel, MAX_FILE_BYTES + 1);
        }
        catch {
            continue;
        }
        if (!opened || opened.truncated || opened.buffer.length > MAX_FILE_BYTES)
            continue;
        if (opened.buffer.subarray(0, 8192).includes(0))
            continue;
        const lines = maskedLinesOf(opened.buffer.toString('utf8'), extOf(rel));
        if (!lines)
            continue;
        out.set(rel, { hash: blobHash(opened.buffer), lines });
    }
    return out;
}
// ---------- structure: cycles and layers ----------
/** Tarjan SCC over an adjacency map; returns components of size >= 2 plus
 * self-loops, each sorted for stable output. */
function stronglyConnected(nodes, edgesFrom) {
    const index = new Map();
    const low = new Map();
    const onStack = new Set();
    const stack = [];
    const out = [];
    let counter = 0;
    for (const start of nodes) {
        if (index.has(start))
            continue;
        // iterative Tarjan: a deep monorepo graph overflows a recursive one.
        const work = [];
        index.set(start, counter);
        low.set(start, counter);
        counter++;
        stack.push(start);
        onStack.add(start);
        work.push({ node: start, iter: (edgesFrom.get(start) ?? new Set()).values() });
        while (work.length) {
            const frame = work[work.length - 1];
            const next = frame.iter.next();
            if (!next.done) {
                const child = next.value;
                if (!index.has(child)) {
                    index.set(child, counter);
                    low.set(child, counter);
                    counter++;
                    stack.push(child);
                    onStack.add(child);
                    work.push({ node: child, iter: (edgesFrom.get(child) ?? new Set()).values() });
                }
                else if (onStack.has(child)) {
                    low.set(frame.node, Math.min(low.get(frame.node), index.get(child)));
                }
                continue;
            }
            work.pop();
            const parent = work.at(-1);
            if (parent)
                low.set(parent.node, Math.min(low.get(parent.node), low.get(frame.node)));
            if (low.get(frame.node) === index.get(frame.node)) {
                const component = [];
                for (;;) {
                    const popped = stack.pop();
                    onStack.delete(popped);
                    component.push(popped);
                    if (popped === frame.node)
                        break;
                }
                const selfLoop = component.length === 1 && edgesFrom.get(component[0])?.has(component[0]);
                if (component.length > 1 || selfLoop)
                    out.push(component.sort());
            }
        }
    }
    return out.sort((left, right) => right.length - left.length || left[0].localeCompare(right[0]));
}
/** Comments off, STRING BODIES KEPT: `MaskedLine.code` drops string contents,
 * which is exactly where a module specifier lives. */
function withoutComment(line) {
    if (!line.comment)
        return line.raw;
    const at = line.raw.indexOf(line.comment);
    return at < 0 ? '' : line.raw.slice(0, at);
}
const SPECIFIER_ON_LINE = /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["']([^"']+)["']/gu;
/** Would a module specifier written on this line resolve to `to`? Matching the
 * PARSED specifier (not a substring of the line) is what keeps a string literal
 * like `"provider-binding"` from passing for an import of `provider.ts`. */
function specifierResolvesTo(spec, to, packageName) {
    if (packageName && (spec === packageName || spec.startsWith(`${packageName}/`)))
        return true;
    const tail = spec.replace(/\.[cm]?[jt]sx?$/u, '').replace(/^(?:\.\.?\/)+/u, '');
    if (!tail || tail.startsWith('.'))
        return false;
    const target = to.replace(/\.[cm]?[jt]sx?$/u, '');
    const indexless = target.replace(/\/index$/u, '');
    return target === tail || target.endsWith(`/${tail}`) || indexless === tail || indexless.endsWith(`/${tail}`);
}
/**
 * Re-derive one import edge from comment-free source.
 *
 * `found` guards against deps.ts inventing an edge from a commented-out import
 * (it extracts specifiers from raw bytes). `typeOnly` says every statement that
 * imports the target is `import type` — such a cycle is erased at build time, so
 * the defect is conceptual rather than an initialization-order hazard, and the
 * finding should not claim otherwise. Conservative: an inline `{ type A }` mix
 * counts as a value import.
 */
function inspectEdge(from, to, code, packageName) {
    const loaded = code.get(from);
    // not a language we can lex: keep the graph's answer, claim nothing about types
    if (!loaded)
        return { found: true, typeOnly: false };
    let statementStart = null;
    let found = false;
    let typeOnly = true;
    for (const line of loaded.lines) {
        const text = withoutComment(line);
        if (/^\s*(?:import|export)\b/u.test(text))
            statementStart = text;
        SPECIFIER_ON_LINE.lastIndex = 0;
        for (const match of text.matchAll(SPECIFIER_ON_LINE)) {
            if (!specifierResolvesTo(match[1], to, packageName))
                continue;
            found = true;
            const head = statementStart ?? text;
            if (!/^\s*(?:import|export)\s+type\b/u.test(head))
                typeOnly = false;
        }
        if (statementStart && /\bfrom\b/u.test(text))
            statementStart = null;
    }
    return { found, typeOnly: found && typeOnly };
}
function packageOf(repoPath, packageRoots) {
    let best = '';
    for (const rootPath of packageRoots) {
        if (repoPath === rootPath || repoPath.startsWith(rootPath + '/')) {
            if (rootPath.length > best.length)
                best = rootPath;
        }
    }
    return best;
}
/** The workspace package name a cross-package specifier would use, if `to` is a
 * package root. Read off disk once per target, cached by the caller. */
function packageNameOf(root, to, packageRoots) {
    if (!packageRoots.includes(to))
        return null;
    try {
        const manifest = JSON.parse(fs.readFileSync(path.join(root, to, 'package.json'), 'utf8'));
        return typeof manifest.name === 'string' ? manifest.name : null;
    }
    catch {
        return null;
    }
}
function cycleFindings(root, graph, code) {
    const isFile = (candidate) => code.has(candidate) || CODE_EXT.test(candidate);
    const fileEdges = new Map();
    const packageEdges = new Map();
    const packageRoots = graph.packageRoots;
    for (const [fromIndex, toIndex] of graph.edges) {
        const from = graph.paths[fromIndex];
        const to = graph.paths[toIndex];
        if (isFile(to)) {
            if (!fileEdges.has(from))
                fileEdges.set(from, new Set());
            fileEdges.get(from).add(to);
        }
        const fromPackage = packageOf(from, packageRoots);
        const toPackage = isFile(to) ? packageOf(to, packageRoots) : to;
        if (fromPackage && toPackage && fromPackage !== toPackage) {
            if (!packageEdges.has(fromPackage))
                packageEdges.set(fromPackage, new Set());
            packageEdges.get(fromPackage).add(toPackage);
        }
    }
    const findings = [];
    for (const component of stronglyConnected([...packageEdges.keys()], packageEdges)) {
        findings.push({
            detector: 'import-cycle',
            category: 'layering-violation',
            severity: 'high',
            title: `${component.length} packages import each other in a cycle`,
            locations: component.map((pkg) => `${pkg}/package.json`).filter((candidate) => fs.existsSync(path.join(root, candidate))),
            evidence: `package import cycle: ${component.join(' → ')} → ${component[0]}. ` +
                'A cycle means no build, test, or reasoning order exists for these packages.',
            fix: 'break the cycle: move the shared piece down into a package both can depend on, ' +
                'or invert one direction with a port the lower package defines.',
        });
    }
    const fileComponents = stronglyConnected([...fileEdges.keys()], fileEdges);
    for (const component of fileComponents.slice(0, 50)) {
        const edgesIn = (from) => [...(fileEdges.get(from) ?? [])].filter((to) => component.includes(to));
        const inspected = component.flatMap((from) => edgesIn(from).map((to) => inspectEdge(from, to, code, packageNameOf(root, to, packageRoots))));
        if (!inspected.every((edge) => edge.found))
            continue;
        const typeOnly = inspected.every((edge) => edge.typeOnly);
        findings.push({
            detector: 'import-cycle',
            category: 'layering-violation',
            severity: typeOnly ? 'low' : component.length > 4 ? 'high' : 'medium',
            title: typeOnly
                ? `${component.length} modules form a type-only cycle`
                : `${component.length} modules import each other in a cycle`,
            locations: component.slice(0, 12),
            evidence: `module import cycle: ${component.slice(0, 8).join(' → ')}` +
                `${component.length > 8 ? ' → …' : ''} → ${component[0]}. Every edge was re-checked ` +
                'against comment-free source, so no commented-out import invented it. ' +
                (typeOnly
                    ? 'Every edge is `import type`, so the cycle is erased at build time — the defect is ' +
                        'that these files are one concept split in two, not a runtime hazard.'
                    : 'At least one edge is a value import, so module initialization order decides ' +
                        'which half sees an incomplete module.'),
            fix: typeOnly
                ? 'move the shared types into one module both import, or merge the pair — a type-only ' +
                    'cycle means neither file is readable without the other.'
                : 'extract what the cycle shares into its own module, or make one direction type-only ' +
                    'if it exists purely for a type.',
        });
    }
    const packageCount = new Set(packageRoots).size;
    return { findings, packages: packageCount };
}
function layerFindings(root, graph, code, layers) {
    if (!layers.length)
        return [];
    const matchers = layers.map((layer) => ({
        name: layer.name,
        isMatch: picomatch(layer.paths, { dot: true }),
    }));
    const layerOf = (repoPath) => matchers.findIndex((layer) => layer.isMatch(repoPath));
    const byPair = new Map();
    for (const [fromIndex, toIndex] of graph.edges) {
        const from = graph.paths[fromIndex];
        const to = graph.paths[toIndex];
        const fromLayer = layerOf(from);
        const toLayer = layerOf(to);
        if (fromLayer < 0 || toLayer < 0 || toLayer >= fromLayer)
            continue;
        if (!inspectEdge(from, to, code, packageNameOf(root, to, graph.packageRoots)).found)
            continue;
        const key = `${fromLayer} ${toLayer}`;
        if (!byPair.has(key))
            byPair.set(key, []);
        byPair.get(key).push({ from, to });
    }
    const findings = [];
    for (const [key, edges] of [...byPair.entries()].sort()) {
        const [fromLayer, toLayer] = key.split(' ').map(Number);
        const sorted = edges.sort((left, right) => left.from.localeCompare(right.from));
        findings.push({
            detector: 'layer-violation',
            category: 'layering-violation',
            severity: 'high',
            title: `${layers[fromLayer].name} imports upward into ${layers[toLayer].name}`,
            locations: [...new Set(sorted.map((edge) => edge.from))].slice(0, 20),
            evidence: `${sorted.length} import(s) climb from ${layers[fromLayer].name} to ` +
                `${layers[toLayer].name}, which the declared layer order puts above it. ` +
                `First: ${sorted.slice(0, 5).map((edge) => `${edge.from} → ${edge.to}`).join('; ')}.`,
            fix: `depend downward only: move the shared piece into ${layers[fromLayer].name} or below, ` +
                `or have ${layers[toLayer].name} call in through a port that ${layers[fromLayer].name} owns.`,
        });
    }
    return findings;
}
// ---------- line-level detectors ----------
// No TEMP: it matches prose about `CREATE TEMP TABLE`. The rest are unambiguous.
const MARKER_RE = /\b(TODO|FIXME|HACK|XXX|KLUDGE)\b/u;
const ESCAPES = [
    { id: 'as-unknown-as', re: /\bas\s+unknown\s+as\b/gu, what: 'as unknown as' },
    { id: 'as-any', re: /\bas\s+any\b/gu, what: 'as any' },
    { id: 'explicit-any', re: /:\s*any\b/gu, what: ': any' },
    { id: 'ts-suppress', re: /@ts-(?:ignore|expect-error|nocheck)\b/gu, what: '@ts-ignore / @ts-expect-error' },
    { id: 'loose-record', re: /\bRecord<\s*string\s*,\s*(?:unknown|any)\s*>/gu, what: 'Record<string, unknown>' },
];
/** `git log -1 --format=%ad -L<line>,<line>:<file>` per marker would be O(markers)
 * git invocations; one blame per FILE with markers is enough for an age signal. */
function blameYears(root, repoPath, now) {
    const out = new Map();
    try {
        const raw = execFileSync('git', ['blame', '--line-porcelain', '--', repoPath], {
            cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'],
        });
        let line = 0;
        for (const entry of raw.split('\n')) {
            const header = /^[0-9a-f]{40} \d+ (\d+)/u.exec(entry);
            if (header) {
                line = Number(header[1]);
                continue;
            }
            const time = /^author-time (\d+)$/u.exec(entry);
            if (time && line)
                out.set(line, (now.getTime() / 1000 - Number(time[1])) / (365.25 * 24 * 3600));
        }
    }
    catch {
        // uncommitted file, shallow clone, or no git: age is UNKNOWN, not zero.
        // Returning null keeps that distinct so the summary can say so out loud.
        return null;
    }
    return out;
}
function markerFindings(root, code, staleDays, now) {
    const findings = [];
    const staleYears = staleDays / 365.25;
    let markerFiles = 0;
    let unknownAge = 0;
    for (const [repoPath, loaded] of [...code].sort(([left], [right]) => left.localeCompare(right))) {
        const hits = [];
        loaded.lines.forEach((line, index) => {
            if (line.comment && MARKER_RE.test(line.comment))
                hits.push({ line: index + 1, text: line.comment.trim() });
        });
        if (!hits.length)
            continue;
        markerFiles++;
        const ages = blameYears(root, repoPath, now);
        if (!ages) {
            unknownAge++;
            continue;
        }
        const stale = hits.filter((hit) => (ages.get(hit.line) ?? 0) >= staleYears);
        if (!stale.length)
            continue;
        const oldest = stale.reduce((worst, hit) => (ages.get(hit.line) ?? 0) > (ages.get(worst.line) ?? 0) ? hit : worst);
        findings.push({
            detector: 'stale-marker',
            category: 'stale-marker',
            severity: (ages.get(oldest.line) ?? 0) >= 2 ? 'medium' : 'low',
            title: `${stale.length} marker comment(s) unchanged for over ${Math.round(staleDays)} days`,
            locations: stale.slice(0, 10).map((hit) => `${repoPath}:${hit.line}`),
            evidence: `oldest is ${(ages.get(oldest.line) ?? 0).toFixed(1)}y old at line ${oldest.line}: ` +
                `${oldest.text.slice(0, 160)}`,
            fix: 'do it, delete it, or move it to a tracked issue — a marker that survives years ' +
                'is a decision nobody is making, and it stops being read.',
        });
    }
    return { findings, markerFiles, unknownAge };
}
function escapeFindings(code) {
    const findings = [];
    for (const [repoPath, loaded] of [...code].sort(([left], [right]) => left.localeCompare(right))) {
        const ext = extOf(repoPath);
        if (ext !== 'ts' && ext !== 'tsx' && ext !== 'mts' && ext !== 'cts')
            continue;
        const hits = [];
        loaded.lines.forEach((line, index) => {
            // @ts-* directives live in comments; the rest must be real code.
            for (const escape of ESCAPES) {
                const haystack = escape.id === 'ts-suppress' ? line.comment : line.code;
                if (!haystack)
                    continue;
                escape.re.lastIndex = 0;
                if (escape.re.test(haystack))
                    hits.push({ line: index + 1, what: escape.what });
            }
        });
        if (hits.length < 3)
            continue; // one cast is a decision; a cluster is a shape
        const kinds = [...new Set(hits.map((hit) => hit.what))].sort();
        findings.push({
            detector: 'type-escape',
            category: 'type-escape',
            severity: hits.length >= 10 ? 'medium' : 'low',
            title: `${hits.length} places opt out of the type system`,
            locations: hits.slice(0, 10).map((hit) => `${repoPath}:${hit.line}`),
            evidence: `${kinds.join(', ')} — ${hits.length} occurrence(s) in this file. ` +
                'Each one is a place the compiler stopped checking and a reader has to verify by hand.',
            fix: 'give the value a real type at the boundary it enters, then delete the escapes ' +
                'behind it. Where the shape genuinely is unknown, parse it once and narrow.',
        });
    }
    return findings;
}
const MEMBER_OPTIONAL_RE = /^\s*(?:readonly\s+)?(?:\[[^\]]+\]|[A-Za-z_$][\w$]*)\?\s*:/u;
const MEMBER_NULLABLE_RE = /^\s*(?:readonly\s+)?(?:\[[^\]]+\]|[A-Za-z_$][\w$]*)\s*:[^=]*\|\s*null\b/u;
/** One interface spelling absence two ways (`x?: T` beside `y: T | null`) is a
 * convention that was never decided — a reader cannot tell which means what. */
function absenceFindings(code) {
    const findings = [];
    for (const [repoPath, loaded] of [...code].sort(([left], [right]) => left.localeCompare(right))) {
        const ext = extOf(repoPath);
        if (ext !== 'ts' && ext !== 'tsx' && ext !== 'mts' && ext !== 'cts')
            continue;
        let current = null;
        let depth = 0;
        loaded.lines.forEach((line, index) => {
            const text = line.code;
            if (!current) {
                const open = /^\s*(?:export\s+)?(?:declare\s+)?interface\s+([A-Za-z_$][\w$]*)/u.exec(text) ??
                    /^\s*(?:export\s+)?(?:declare\s+)?type\s+([A-Za-z_$][\w$]*)\s*(?:<[^=]*>)?\s*=\s*\{/u.exec(text);
                if (open && text.includes('{')) {
                    depth = 0;
                    current = { name: open[1], line: index + 1, optional: [], nullable: [], depth: 0 };
                }
                else if (open) {
                    return; // multi-line header; the body opens on a later line
                }
            }
            if (!current)
                return;
            const before = depth;
            for (const character of text) {
                if (character === '{')
                    depth++;
                else if (character === '}')
                    depth--;
            }
            if (before === 1 && depth === 1) {
                // only direct members count, and a member whose TYPE is an inline object
                // (`inner: { deep: string | null }`) declares nothing about itself.
                const typePart = text.slice(text.indexOf(':') + 1);
                if (!typePart.includes('{')) {
                    if (MEMBER_OPTIONAL_RE.test(text))
                        current.optional.push(index + 1);
                    else if (MEMBER_NULLABLE_RE.test(text))
                        current.nullable.push(index + 1);
                }
            }
            if (depth <= 0 && before > 0) {
                const done = current;
                current = null;
                depth = 0;
                if (done.optional.length && done.nullable.length) {
                    findings.push({
                        detector: 'absence-mixing',
                        category: 'absence-semantics',
                        severity: Math.min(done.optional.length, done.nullable.length) >= 3 ? 'medium' : 'low',
                        title: `${done.name} spells absence two ways`,
                        locations: [`${repoPath}:${done.line}`,
                            ...[...done.optional.slice(0, 3), ...done.nullable.slice(0, 3)].sort((a, b) => a - b)
                                .map((memberLine) => `${repoPath}:${memberLine}`)],
                        evidence: `${done.optional.length} member(s) use \`?:\` and ${done.nullable.length} use ` +
                            `\`| null\` inside one declaration (${done.optional.slice(0, 3).map((value) => `L${value}`).join(', ')} vs ` +
                            `${done.nullable.slice(0, 3).map((value) => `L${value}`).join(', ')}). Absent, null, and ` +
                            'missing-key are three different states to a consumer.',
                        fix: 'pick one spelling for "no value" in this declaration. Reserve the other for a ' +
                            'genuinely different state, and say which is which.',
                    });
                }
            }
        });
    }
    return findings;
}
const BOOLEAN_PARAM_RE = /\(([^()]*)\)\s*(?::[^{;]*)?[{;=]/u;
const NOT_A_DECLARATION = new Set([
    'if', 'for', 'while', 'switch', 'catch', 'return', 'function', 'do', 'else', 'await', 'typeof',
]);
/** `render(node, true)` — the call site cannot say what `true` means. Only
 * POSITIONAL booleans qualify: an object parameter (`{ compact }: Props`, a
 * React component, an options bag) names the argument at the call site, so it
 * is the fix, not the defect. */
function booleanTrapFindings(code) {
    const findings = [];
    for (const [repoPath, loaded] of [...code].sort(([left], [right]) => left.localeCompare(right))) {
        const ext = extOf(repoPath);
        if (ext !== 'ts' && ext !== 'tsx' && ext !== 'mts' && ext !== 'cts')
            continue;
        const hits = [];
        loaded.lines.forEach((line, index) => {
            const text = line.code;
            const declaration = /^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/u.exec(text) ??
                /^\s*(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(/u.exec(text);
            if (!declaration || NOT_A_DECLARATION.has(declaration[1]))
                return;
            const params = BOOLEAN_PARAM_RE.exec(text)?.[1];
            if (!params)
                return;
            if (params.includes('{') || params.includes('}'))
                return; // object parameter: already named
            const list = params.split(',');
            if (list.length < 2)
                return; // a lone boolean argument still reads at the call site
            for (const parameter of list.slice(1)) {
                const optional = /([A-Za-z_$][\w$]*)\s*\?\s*:\s*boolean\b/u.exec(parameter) ??
                    /([A-Za-z_$][\w$]*)\s*(?::\s*boolean\s*)?=\s*(?:true|false)\b/u.exec(parameter);
                if (optional)
                    hits.push({ line: index + 1, name: declaration[1], param: optional[1] });
            }
        });
        if (!hits.length)
            continue;
        findings.push({
            detector: 'boolean-trap',
            category: 'boolean-trap',
            severity: 'low',
            title: `${hits.length} signature(s) take a trailing optional boolean`,
            locations: hits.slice(0, 10).map((hit) => `${repoPath}:${hit.line}`),
            evidence: hits.slice(0, 5).map((hit) => `${hit.name}(…, ${hit.param}?: boolean)`).join('; ') +
                ' — at the call site the argument is a bare `true`/`false` with no name attached.',
            fix: 'name the axis: take an options object, or split into two functions whose names say ' +
                'what each does.',
        });
    }
    return findings;
}
const CATEGORIES = new Set([
    'optionality', 'absence-semantics', 'boolean-trap', 'type-escape',
    'over-abstraction', 'layering-violation', 'duplicate-logic', 'dead-code',
    'redundant-fields', 'over-complication', 'first-principles',
    'masking-default', 'swallowed-failure', 'magic-constant',
    'dead-forward-compat', 'compat-shim', 'stale-marker',
    'naming-drift', 'unexplained-export',
]);
function validLocationPath(repoPath) {
    return !!repoPath && !path.isAbsolute(repoPath) && !repoPath.includes('\\') && !repoPath.includes('\0') &&
        path.posix.normalize(repoPath) === repoPath && repoPath !== '.' && !repoPath.startsWith('../');
}
function relativeTo(root, candidate) {
    const value = path.isAbsolute(candidate) ? path.relative(root, candidate) : candidate;
    const normalized = value.split(path.sep).join('/');
    return validLocationPath(normalized) ? normalized : null;
}
/** The documented neutral shape: any tool becomes ingestible with a few lines
 * of jq, and atlas owns no zoo of fragile per-tool parsers. */
function ingestGeneric(root, payload, source) {
    const record = payload && typeof payload === 'object' ? payload : {};
    const tool = typeof record.tool === 'string' && record.tool.trim() ? record.tool.trim() : 'generic';
    const rows = Array.isArray(record.findings) ? record.findings : [];
    const findings = [];
    let dropped = 0;
    for (const row of rows) {
        const repoPath = typeof row.path === 'string' ? relativeTo(root, row.path) : null;
        const category = typeof row.category === 'string' && CATEGORIES.has(row.category)
            ? row.category : null;
        const title = typeof row.title === 'string' && row.title.trim() ? row.title.trim() : null;
        const evidence = typeof row.evidence === 'string' && row.evidence.trim() ? row.evidence.trim() : null;
        if (!repoPath || !category || !title || !evidence) {
            dropped++;
            continue;
        }
        const line = typeof row.line === 'number' && Number.isSafeInteger(row.line) && row.line > 0 ? row.line : null;
        const severity = row.severity === 'high' || row.severity === 'medium' || row.severity === 'low'
            ? row.severity : 'low';
        findings.push({
            detector: typeof row.detector === 'string' && row.detector.trim() ? `${tool}:${row.detector.trim()}` : `${tool}:ingest`,
            category,
            severity,
            title,
            locations: [line ? `${repoPath}:${line}` : repoPath],
            evidence,
            fix: typeof row.fix === 'string' && row.fix.trim() ? row.fix.trim() : 'decide whether this shape is intended, then fix or record it.',
        });
    }
    return { findings, stat: { tool, source, accepted: findings.length, dropped } };
}
/** ESLint rules that carry a design claim, not a style one. Anything unmapped
 * is dropped and counted — atlas never relabels a style warning as a design defect. */
const ESLINT_CATEGORY = {
    '@typescript-eslint/no-explicit-any': 'type-escape',
    '@typescript-eslint/no-unsafe-assignment': 'type-escape',
    '@typescript-eslint/no-non-null-assertion': 'type-escape',
    '@typescript-eslint/no-unnecessary-condition': 'over-complication',
    '@typescript-eslint/no-unnecessary-type-assertion': 'type-escape',
    '@typescript-eslint/no-empty-interface': 'over-abstraction',
    '@typescript-eslint/no-useless-constructor': 'over-abstraction',
    '@typescript-eslint/no-unused-vars': 'dead-code',
    'no-unused-vars': 'dead-code',
    'no-empty': 'swallowed-failure',
    'no-fallthrough': 'swallowed-failure',
    'import/no-cycle': 'layering-violation',
    'import/no-restricted-paths': 'layering-violation',
    'no-magic-numbers': 'magic-constant',
    'eqeqeq': 'absence-semantics',
};
function ingestEslint(root, payload, source) {
    const rows = Array.isArray(payload) ? payload : [];
    const byRule = new Map();
    let dropped = 0;
    for (const row of rows) {
        const repoPath = typeof row.filePath === 'string' ? relativeTo(root, row.filePath) : null;
        const messages = Array.isArray(row.messages) ? row.messages : [];
        for (const message of messages) {
            const ruleId = typeof message.ruleId === 'string' ? message.ruleId : null;
            if (!repoPath || !ruleId || !ESLINT_CATEGORY[ruleId]) {
                dropped++;
                continue;
            }
            const key = ruleId;
            if (!byRule.has(key))
                byRule.set(key, []);
            byRule.get(key).push({
                repoPath,
                line: typeof message.line === 'number' && message.line > 0 ? message.line : 1,
                message: typeof message.message === 'string' ? message.message : ruleId,
            });
        }
    }
    const findings = [];
    for (const [ruleId, hits] of [...byRule.entries()].sort()) {
        findings.push({
            detector: `eslint:${ruleId}`,
            category: ESLINT_CATEGORY[ruleId],
            severity: 'low',
            title: `${hits.length} ${ruleId} violation(s)`,
            locations: hits.slice(0, 20).map((hit) => `${hit.repoPath}:${hit.line}`),
            evidence: `eslint reported ${hits.length} occurrence(s); first: ${hits[0].message}`,
            fix: `resolve the rule, or record why this repository accepts ${ruleId}.`,
        });
    }
    return { findings, stat: { tool: 'eslint', source, accepted: findings.length, dropped } };
}
function ingestKnip(root, payload, source) {
    const record = payload && typeof payload === 'object' ? payload : {};
    const findings = [];
    let dropped = 0;
    const unusedFiles = (Array.isArray(record.files) ? record.files : [])
        .map((value) => (typeof value === 'string' ? relativeTo(root, value) : null))
        .filter((value) => !!value);
    if (unusedFiles.length) {
        findings.push({
            detector: 'knip:files',
            category: 'dead-code',
            severity: 'medium',
            title: `${unusedFiles.length} file(s) nothing imports`,
            locations: unusedFiles.slice(0, 20),
            evidence: `knip found no importer and no entry-point claim for these files: ` +
                `${unusedFiles.slice(0, 8).join(', ')}${unusedFiles.length > 8 ? ', …' : ''}`,
            fix: 'delete them, or declare the entry point that makes them reachable.',
        });
    }
    // knip --reporter json: `issues: [{ file, exports: [{symbol, line}], ... }]`
    const issues = Array.isArray(record.issues) ? record.issues : [];
    const deadExports = [];
    for (const issue of issues) {
        const repoPath = typeof issue.file === 'string' ? relativeTo(root, issue.file) : null;
        if (!repoPath) {
            dropped++;
            continue;
        }
        for (const key of ['exports', 'types', 'enumMembers']) {
            const entries = Array.isArray(issue[key]) ? issue[key] : [];
            for (const entry of entries) {
                const line = typeof entry.line === 'number' && entry.line > 0 ? entry.line : null;
                deadExports.push(line ? `${repoPath}:${line}` : repoPath);
            }
        }
    }
    if (deadExports.length) {
        findings.push({
            detector: 'knip:exports',
            category: 'dead-code',
            severity: 'low',
            title: `${deadExports.length} export(s) nothing imports`,
            locations: [...new Set(deadExports)].slice(0, 20),
            evidence: `knip found ${deadExports.length} exported symbol(s) with no importer. ` +
                'An export with no consumer is API surface that cannot be wrong yet, so it never gets corrected.',
            fix: 'unexport it (or delete it) until a caller exists.',
        });
    }
    return { findings, stat: { tool: 'knip', source, accepted: findings.length, dropped } };
}
export function ingestReport(root, tool, file) {
    const source = path.relative(root, path.resolve(file)).split(path.sep).join('/');
    const payload = JSON.parse(fs.readFileSync(path.resolve(file), 'utf8'));
    if (tool === 'eslint')
        return ingestEslint(root, payload, source);
    if (tool === 'knip')
        return ingestKnip(root, payload, source);
    return ingestGeneric(root, payload, source);
}
// ---------- report ----------
export function parseLayers(value) {
    if (!Array.isArray(value))
        return [];
    const out = [];
    for (const entry of value) {
        if (!entry || typeof entry !== 'object')
            throw new Error('each layer must be an object { name, paths }');
        const layer = entry;
        if (typeof layer.name !== 'string' || !layer.name.trim())
            throw new Error('each layer needs a nonempty name');
        if (!Array.isArray(layer.paths) || !layer.paths.length || !layer.paths.every((item) => typeof item === 'string' && item.trim())) {
            throw new Error(`layer ${layer.name} needs a nonempty paths array of globs`);
        }
        out.push({ name: layer.name.trim(), paths: layer.paths });
    }
    return out;
}
const SEVERITY_RANK = { high: 0, medium: 1, low: 2 };
export function computeQuality(root, config, options = {}) {
    const scanResult = scan(root, { exclude: [...DEFAULT_EXCLUDE, ...(config.exclude ?? []), ...(options.exclude ?? [])] });
    const code = loadCode(root, scanResult);
    const graph = buildImportGraph(root, scanResult);
    const layers = options.layers ?? [];
    const now = options.now ?? new Date();
    const staleDays = options.staleMarkerDays ?? 180;
    const findings = [];
    const detectors = {};
    const record = (id, scanned, produced, note) => {
        detectors[id] = { scanned, findings: produced.length, ...(note ? { note } : {}) };
        findings.push(...produced);
    };
    const cycles = cycleFindings(root, graph, code);
    record('import-cycle', graph.edges.length, cycles.findings);
    record('layer-violation', layers.length ? graph.edges.length : 0, layerFindings(root, graph, code, layers), layers.length ? undefined : 'no layers declared in .atlas/config.json — detector inactive');
    const markers = markerFindings(root, code, staleDays, now);
    record('stale-marker', markers.markerFiles, markers.findings, markers.unknownAge
        ? `${markers.unknownAge} file(s) with markers have no git history — age unknown, not counted`
        : undefined);
    record('type-escape', code.size, escapeFindings(code));
    record('absence-mixing', code.size, absenceFindings(code));
    record('boolean-trap', code.size, booleanTrapFindings(code));
    const ingested = [];
    for (const entry of options.ingest ?? []) {
        const result = ingestReport(root, entry.tool, entry.file);
        ingested.push(result.stat);
        findings.push(...result.findings);
    }
    findings.sort((left, right) => SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity] ||
        left.detector.localeCompare(right.detector) ||
        (left.locations[0] ?? '').localeCompare(right.locations[0] ?? ''));
    return {
        format: 'repo-atlas-quality-v1',
        formatVersion: 1,
        generatedAt: now.toISOString(),
        repo: {
            files: scanResult.files.size,
            codeFiles: code.size,
            packages: cycles.packages,
            layers: layers.length,
        },
        detectors,
        ingested,
        findings,
        files: Object.fromEntries([...code].map(([repoPath, loaded]) => [repoPath, loaded.hash]).sort(([left], [right]) => left.localeCompare(right))),
    };
}
export function isSupportedQualityReport(value) {
    if (!value || typeof value !== 'object')
        return false;
    const report = value;
    return report.format === 'repo-atlas-quality-v1' && (report.formatVersion ?? 1) === 1 &&
        typeof report.generatedAt === 'string' && Array.isArray(report.findings) &&
        !!report.files && typeof report.files === 'object';
}
/** Paths a finding touches, deduped — the join key for artifacts and the ledger. */
export function findingPaths(finding) {
    return [...new Set(finding.locations.map((location) => location.replace(/:\d+$/u, '')))];
}
function safeQualityDirectory(root, segments, create) {
    const rootReal = fs.realpathSync(root);
    const atlas = atlasDir(root);
    const atlasStat = fs.lstatSync(atlas);
    const atlasReal = fs.realpathSync(atlas);
    if (!atlasStat.isDirectory() || atlasStat.isSymbolicLink() ||
        (atlasReal !== rootReal && !atlasReal.startsWith(rootReal + path.sep))) {
        throw new Error('unsafe .atlas directory: expected a regular in-repository directory');
    }
    let current = atlas;
    for (const segment of segments) {
        if (!segment || segment === '.' || segment === '..' || segment.includes(path.sep)) {
            throw new Error(`unsafe .atlas path segment: ${segment}`);
        }
        current = path.join(current, segment);
        if (!fs.existsSync(current)) {
            if (!create)
                throw new Error(`missing .atlas directory: ${path.relative(root, current)}`);
            fs.mkdirSync(current);
        }
        const stat = fs.lstatSync(current);
        const real = fs.realpathSync(current);
        if (!stat.isDirectory() || stat.isSymbolicLink() ||
            (real !== atlasReal && !real.startsWith(atlasReal + path.sep))) {
            throw new Error(`unsafe .atlas directory: ${path.relative(root, current)}`);
        }
    }
    return current;
}
function assertSafeQualityFile(root, file, parentSegments, createParent) {
    const parent = safeQualityDirectory(root, parentSegments, createParent);
    if (path.dirname(path.resolve(file)) !== path.resolve(parent))
        throw new Error(`unsafe .atlas output path: ${file}`);
    if (!fs.existsSync(file))
        return;
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink()) {
        throw new Error(`unsafe .atlas output: ${path.relative(root, file)} must be a regular file, not a symlink`);
    }
}
function atomicWrite(file, contents) {
    const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${randomUUID()}.tmp`);
    try {
        fs.writeFileSync(tmp, contents, { flag: 'wx', mode: 0o600 });
        fs.renameSync(tmp, file);
    }
    finally {
        try {
            fs.unlinkSync(tmp);
        }
        catch { /* renamed or never created */ }
    }
}
export function writeQualityReport(root, report) {
    const file = path.join(atlasDir(root), 'quality.json');
    assertSafeQualityFile(root, file, [], false);
    atomicWrite(file, JSON.stringify(report, null, 2) + '\n');
    return file;
}
/** Refuse to overwrite a ledger this pipeline does not own. */
export function assertQualityAuditOwnership(root) {
    const file = path.join(atlasDir(root), 'audits', 'quality.json');
    assertSafeAuditLedgerOutput(root, file);
    if (!fs.existsSync(file))
        return;
    let existing;
    try {
        const opened = readRepoFile(root, '.atlas/audits/quality.json');
        if (!opened)
            throw new Error('unsafe quality audit ledger');
        existing = JSON.parse(opened.buffer.toString('utf8'));
    }
    catch {
        throw new Error(`refusing to overwrite unreadable audit ledger: ${path.relative(root, file)}`);
    }
    const record = existing && typeof existing === 'object' ? existing : null;
    const owned = record?.format === 'atlas-audit-v1' && record.formatVersion === 1 &&
        record.slug === 'quality' && record.ruleset === 'repo-atlas-quality-v1';
    if (!owned)
        throw new Error(`refusing to overwrite unrelated audit ledger: ${path.relative(root, file)}`);
}
/**
 * Thin `atlas-audit-v1` index: hashes bind the verdict to exact bytes so
 * `status` reports drift without reparsing the report. Deliberately v1 generic
 * rather than a v2 `design` ledger — a detector run is not a review, and only a
 * review may claim `reviewState: complete`.
 */
export function writeQualityAuditLedger(root, report) {
    if (!fs.existsSync(atlasDir(root)))
        return null;
    assertQualityAuditOwnership(root);
    const files = Object.keys(report.files).sort();
    const hashes = Object.fromEntries(files.map((repoPath) => [repoPath, report.files[repoPath]]));
    const scopeLines = files.map((repoPath) => `${hashes[repoPath]}  ${repoPath}`).sort();
    const byPath = new Map();
    for (const finding of report.findings) {
        for (const repoPath of findingPaths(finding)) {
            if (!report.files[repoPath])
                continue; // findings may cite package.json etc.
            const entry = byPath.get(repoPath) ?? { detectors: new Set(), severity: 'low', count: 0 };
            entry.detectors.add(finding.detector);
            entry.count++;
            if (SEVERITY_RANK[finding.severity] < SEVERITY_RANK[entry.severity])
                entry.severity = finding.severity;
            byPath.set(repoPath, entry);
        }
    }
    const findings = [...byPath.entries()].sort(([left], [right]) => left.localeCompare(right))
        .map(([repoPath, entry]) => ({
        path: repoPath,
        severity: entry.severity,
        count: entry.count,
        summary: `mechanical: ${[...entry.detectors].sort().join(', ')}`,
    }));
    const file = path.join(atlasDir(root), 'audits', 'quality.json');
    writeAuditLedgerFile(root, file, JSON.stringify({
        formatVersion: 1,
        format: 'atlas-audit-v1',
        slug: 'quality',
        title: 'Mechanical design quality',
        ruleset: 'repo-atlas-quality-v1',
        scanned_at: report.generatedAt,
        stamped: report.generatedAt,
        scope_hash: createHash('sha1').update(scopeLines.join('\n') + '\n').digest('hex'),
        file_count: files.length,
        files,
        hashes,
        findings,
        quality: {
            formatVersion: 1,
            generatedAt: report.generatedAt,
            totals: {
                findings: report.findings.length,
                high: report.findings.filter((finding) => finding.severity === 'high').length,
                medium: report.findings.filter((finding) => finding.severity === 'medium').length,
                low: report.findings.filter((finding) => finding.severity === 'low').length,
            },
        },
    }, null, 2) + '\n');
    return file;
}
function markdownText(value) {
    return [...value.replace(/[\r\n]+/gu, ' ')].map((character) => /^[\p{L}\p{N}\p{P} ]$/u.test(character) && character !== '|' ? character : `&#${character.codePointAt(0)};`).join('');
}
/** One card per page that has findings, pruning cards from earlier runs. */
export function writeQualityArtifacts(root, report) {
    if (!fs.existsSync(atlasDir(root)))
        return 0;
    const base = safeQualityDirectory(root, ['artifacts'], true);
    const byPath = new Map();
    for (const finding of report.findings) {
        for (const repoPath of findingPaths(finding)) {
            if (!byPath.has(repoPath))
                byPath.set(repoPath, []);
            byPath.get(repoPath).push(finding);
        }
    }
    const wanted = new Set();
    let written = 0;
    for (const [pageKey, pageFindings] of byPath) {
        const segments = pageKey.split('/').filter(Boolean);
        const dir = safeQualityDirectory(root, ['artifacts', ...segments], true);
        const file = path.join(dir, 'quality.md');
        assertSafeQualityFile(root, file, ['artifacts', ...segments], true);
        wanted.add(file);
        const body = [
            '# mechanical quality',
            '',
            '机械检测（无 LLM）。判断类的设计合理性走 `design` 审计域，不在这里。',
            '',
            ...pageFindings.flatMap((finding) => [
                `## ${markdownText(finding.title)}`,
                '',
                `- 检测器 \`${finding.detector}\` · 类别 \`${finding.category}\` · 严重度 **${finding.severity}**`,
                `- 位置：${finding.locations.map((location) => `\`${markdownText(location)}\``).join(' · ')}`,
                `- 证据：${markdownText(finding.evidence)}`,
                `- 修法：${markdownText(finding.fix)}`,
                '',
            ]),
        ].join('\n');
        const existing = fs.existsSync(file) ? readRepoFile(root, path.relative(root, file).replace(/\\/g, '/')) : null;
        if (existing && existing.buffer.toString('utf8') === body)
            continue;
        atomicWrite(file, body);
        written++;
    }
    if (fs.existsSync(base)) {
        const walk = (dir) => {
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                const full = path.join(dir, entry.name);
                if (entry.isDirectory()) {
                    walk(full);
                    if (fs.readdirSync(full).length === 0)
                        fs.rmdirSync(full);
                }
                else if (entry.name === 'quality.md' && !wanted.has(full)) {
                    fs.unlinkSync(full);
                }
            }
        };
        walk(base);
    }
    return written;
}
export function formatQualitySummary(report, top = 10) {
    const out = [];
    out.push(`quality: ${report.repo.codeFiles} code files · ${report.repo.packages} packages · ` +
        `${report.repo.layers} declared layer(s)`);
    const counts = { high: 0, medium: 0, low: 0 };
    for (const finding of report.findings)
        counts[finding.severity]++;
    out.push(`findings: ${report.findings.length} (${counts.high} high · ${counts.medium} medium · ${counts.low} low)`);
    out.push('');
    out.push('detectors:');
    for (const [id, stat] of Object.entries(report.detectors)) {
        out.push(`  ${id.padEnd(16)} ${String(stat.findings).padStart(4)} finding(s) over ${stat.scanned} unit(s)` +
            (stat.note ? `  — ${stat.note}` : ''));
    }
    for (const stat of report.ingested) {
        out.push(`  ${`${stat.tool} (ingest)`.padEnd(16)} ${String(stat.accepted).padStart(4)} accepted · ${stat.dropped} unmapped  — ${stat.source}`);
    }
    if (report.findings.length) {
        out.push('');
        out.push(`worst ${Math.min(top, report.findings.length)}:`);
        for (const finding of report.findings.slice(0, top)) {
            out.push(`  [${finding.severity}] ${finding.detector} — ${finding.title}`);
            out.push(`      ${finding.locations.slice(0, 3).join(' · ')}${finding.locations.length > 3 ? ` (+${finding.locations.length - 3})` : ''}`);
        }
    }
    return out.join('\n');
}
/** CI gate: only ever pass detector ids or categories whose precision you trust. */
export function failingFindings(report, selectors) {
    if (!selectors.length)
        return [];
    const wanted = new Set(selectors);
    return report.findings.filter((finding) => wanted.has(finding.detector) || wanted.has(finding.category) ||
        wanted.has(finding.detector.split(':')[0]) || wanted.has(finding.severity));
}
