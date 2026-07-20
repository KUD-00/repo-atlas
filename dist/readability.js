import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { assertSafeAuditLedgerOutput, writeAuditLedgerFile } from './audits.js';
import { scan, DEFAULT_EXCLUDE, atlasDir, hashFilePaths, readRepoFile } from './scan.js';
function maxOf(values, fallback = 0) {
    let maximum = fallback;
    for (const value of values)
        if (value > maximum)
            maximum = value;
    return maximum;
}
const CLIKE = {
    line: ['//'], block: [['/*', '*/']], strings: ['"', "'", '`'], spanStrings: ['`'],
    triple: false, braces: true,
};
const PY = {
    line: ['#'], block: [], strings: ['"', "'"], spanStrings: [],
    triple: true, braces: false,
};
const HASH = { ...PY, triple: false };
const LANGS = {
    ts: CLIKE, tsx: CLIKE, js: CLIKE, jsx: CLIKE, mjs: CLIKE, cjs: CLIKE, mts: CLIKE, cts: CLIKE,
    java: CLIKE, c: CLIKE, h: CLIKE, cpp: CLIKE, cc: CLIKE, cxx: CLIKE, hpp: CLIKE, hh: CLIKE,
    cs: CLIKE, go: CLIKE, rs: CLIKE, kt: CLIKE, kts: CLIKE, swift: CLIKE, php: CLIKE,
    scala: CLIKE, sc: CLIKE, dart: CLIKE, m: CLIKE, mm: CLIKE,
    css: { line: [], block: [['/*', '*/']], strings: ['"', "'"], spanStrings: [], triple: false, braces: true },
    py: PY, pyi: PY,
    sh: HASH, bash: HASH, zsh: HASH, yaml: HASH, yml: HASH, toml: HASH, pl: HASH, pm: HASH, r: HASH,
    rb: { line: ['#'], block: [['=begin', '=end']], strings: ['"', "'"], spanStrings: [], triple: false, braces: false },
    sql: { line: ['--'], block: [['/*', '*/']], strings: ["'"], spanStrings: [], triple: false, braces: false },
    lua: { line: ['--'], block: [['--[[', ']]']], strings: ['"', "'"], spanStrings: [], triple: false, braces: false },
    hs: { line: ['--'], block: [['{-', '-}']], strings: ['"'], spanStrings: [], triple: false, braces: false },
    html: { line: [], block: [['<!--', '-->']], strings: [], spanStrings: [], triple: false, braces: false },
    htm: { line: [], block: [['<!--', '-->']], strings: [], spanStrings: [], triple: false, braces: false },
    xml: { line: [], block: [['<!--', '-->']], strings: [], spanStrings: [], triple: false, braces: false },
    vue: { line: [], block: [['<!--', '-->']], strings: [], spanStrings: [], triple: false, braces: false },
};
const KEYWORDS = new Set(('if else elif for while do switch case default try catch except finally with return break continue ' +
    'throw throws new delete typeof instanceof in of const let var function class extends implements ' +
    'interface enum struct trait fn func def lambda async await yield go defer public private protected ' +
    'static final abstract override virtual internal readonly namespace package import from export as ' +
    'using use mod pub self this super null nil true false undefined none pass raise and or not is ' +
    'impl where match select chan range type record sealed get set void int long float double char bool').split(' '));
function maskSource(text, lang) {
    const out = [];
    let state = { kind: 'code' };
    for (const raw of text.split('\n')) {
        let code = '';
        let comment = '';
        let i = 0;
        const n = raw.length;
        while (i < n) {
            if (state.kind === 'block') {
                const end = raw.indexOf(state.closer, i);
                if (end < 0) {
                    comment += raw.slice(i);
                    i = n;
                }
                else {
                    comment += raw.slice(i, end + state.closer.length);
                    i = end + state.closer.length;
                    state = { kind: 'code' };
                }
            }
            else if (state.kind === 'str') {
                let j = i;
                while (j < n) {
                    if (raw[j] === '\\') {
                        j += 2;
                        continue;
                    }
                    if (state.quote.length === 3 ? raw.startsWith(state.quote, j) : raw[j] === state.quote)
                        break;
                    j++;
                }
                if (j >= n) {
                    i = n;
                    if (!state.span)
                        state = { kind: 'code' }; // unterminated EOL string: pretend closed
                }
                else {
                    i = j + state.quote.length;
                    state = { kind: 'code' };
                }
            }
            else {
                let hit = false;
                for (const lc of lang.line) {
                    if (raw.startsWith(lc, i)) {
                        comment += raw.slice(i);
                        i = n;
                        hit = true;
                        break;
                    }
                }
                if (!hit) {
                    for (const [op, cl] of lang.block) {
                        if (raw.startsWith(op, i)) {
                            state = { kind: 'block', closer: cl };
                            comment += op;
                            i += op.length;
                            hit = true;
                            break;
                        }
                    }
                }
                if (!hit) {
                    const tri = lang.triple && (raw.startsWith("'''", i) || raw.startsWith('"""', i));
                    if (tri) {
                        state = { kind: 'str', quote: raw.slice(i, i + 3), span: true };
                        code += "''";
                        i += 3;
                    }
                    else if (lang.strings.includes(raw[i])) {
                        const q = raw[i];
                        state = { kind: 'str', quote: q, span: lang.spanStrings.includes(q) };
                        code += "''";
                        i++;
                    }
                    else {
                        code += raw[i];
                        i++;
                    }
                }
            }
        }
        out.push({ raw, code, comment });
    }
    return out;
}
function dist(xs) {
    if (!xs.length)
        return { mean: 0, sd: 0, p50: 0, p95: 0, max: 0 };
    const s = [...xs].sort((a, b) => a - b);
    const pick = (q) => s[Math.min(s.length - 1, Math.floor(q * s.length))];
    const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
    const sd = Math.sqrt(xs.reduce((a, b) => a + (b - mean) ** 2, 0) / xs.length);
    return { mean, sd, p50: pick(0.5), p95: pick(0.95), max: s[s.length - 1] };
}
function entropy(tokens) {
    if (!tokens.length)
        return 0;
    const freq = new Map();
    for (const t of tokens)
        freq.set(t, (freq.get(t) ?? 0) + 1);
    let h = 0;
    for (const c of freq.values()) {
        const p = c / tokens.length;
        h -= p * Math.log2(p);
    }
    return h;
}
function fnv1a(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
    }
    return h >>> 0;
}
function styleOf(id) {
    const core = id.replace(/^_+|_+$/g, '');
    if (!core)
        return 'other';
    if (core.length === 1)
        return 'other';
    if (/^[A-Z0-9_]+$/.test(core))
        return 'upper';
    const hasUnder = core.includes('_');
    if (hasUnder && /^[a-z0-9_]+$/.test(core))
        return 'snake';
    if (hasUnder)
        return 'mixed';
    if (/^[a-z0-9]/.test(core))
        return 'camel';
    if (/^[A-Z]/.test(core) && /[a-z]/.test(core))
        return 'pascal';
    return 'other';
}
const IDENT_RE = /[A-Za-z_$][A-Za-z0-9_$]*/g;
const TOKEN_RE = /[A-Za-z_$][A-Za-z0-9_$]*|\d+(?:\.\d+)?|[^\sA-Za-z0-9_$]+/g;
const STOPWORDS = new Set(('the and for with this that from are was were not but when then else here there which would ' +
    'should could will can must only also into over under between because instead without within ' +
    'before after each every used uses use see note todo fixme true false null undefined let const ' +
    'var return new get set has have had its their our your out off per via than them they you all ' +
    'any both few more most other some such nor own same too very just like make makes made need').split(' '));
/** split identifiers into lowercase words (camel/snake/digit boundaries) */
function splitIdentWords(id) {
    return id
        .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
        .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
        .toLowerCase()
        .split(/[^a-z]+/)
        .filter((w) => w.length >= 3 && !STOPWORDS.has(w));
}
// looks like commented-out code (heuristic; doc-tags and URLs excluded).
// Note the call pattern requires NO space before '(' — "foo(...)" is code,
// but "CA (PEM contents)" is plain English and must not fire.
const CODEISH_RE = /([{}]|;\s*$|==|!=|<=|>=|=>|->|\w+\([^)]*\)|\)\s*$)/;
const FN_RES = [
    /\b(?:async\s+)?function\s*\*?\s*([\w$]+)\s*\(/,
    /\bfunc\s*\([^)]*\)\s*([\w$]+)\s*\(/, // go method with receiver
    /\b(?:func|fn|fun)\s+([\w$]+)\s*\(/, // go / rust / kotlin
    /\b(?:const|let|var)\s+([\w$]+)\s*(?::[^=;]+)?=\s*(?:async\s*)?(?:\([^()]*\)|[\w$]+)\s*=>/,
    /^\s*(?:(?:public|private|protected|static|async|override|abstract|final|virtual|inline|suspend|export|readonly)\s+)*([\w$]+)\s*\([^()]*\)\s*(?::\s*[^{}]+?)?\s*\{?\s*$/,
];
const PY_DEF_RE = /^\s*(?:async\s+)?def\s+([\w$]+)\s*\(/;
const BRANCH_RE = /\b(if|elif|else|for|while|case|catch|except|when|guard|match)\b|&&|\|\|/g;
function braceDepths(lines) {
    const depths = [];
    let d = 0;
    for (const l of lines) {
        depths.push(d);
        for (const ch of l.code) {
            if (ch === '{')
                d++;
            else if (ch === '}')
                d = Math.max(0, d - 1);
        }
    }
    return depths;
}
function indentWidths(lines) {
    return lines.map((l) => {
        const m = /^[ \t]*/.exec(l.code)[0];
        let w = 0;
        for (const ch of m)
            w += ch === '\t' ? 4 : 1;
        return w;
    });
}
function countBranches(code) {
    const m = code.match(BRANCH_RE);
    return m ? m.length : 0;
}
function detectFunctions(lines, lang) {
    const fns = [];
    if (lang.braces) {
        const depths = braceDepths(lines);
        let i = 0;
        while (i < lines.length && fns.length < 500) {
            const code = lines[i].code;
            let name = null;
            for (const re of FN_RES) {
                const m = re.exec(code);
                if (m && !KEYWORDS.has(m[1])) {
                    name = m[1];
                    break;
                }
            }
            if (!name || !code.includes('{')) {
                i++;
                continue;
            }
            const startDepth = depths[i];
            // first line where depth rises above startDepth marks the opened body;
            // region ends at the line that brings depth back to startDepth
            let end = i;
            let opened = false;
            for (let j = i; j < lines.length; j++) {
                const nextDepth = j + 1 < lines.length ? depths[j + 1] : depths[j];
                if (!opened && nextDepth > startDepth)
                    opened = true;
                if (opened && nextDepth <= startDepth) {
                    end = j;
                    break;
                }
                end = j;
            }
            const region = lines.slice(i, end + 1);
            fns.push({
                name,
                line: i + 1,
                lines: end - i + 1,
                maxLineLen: maxOf(region.map((l) => l.raw.length)),
                maxNesting: maxOf(depths.slice(i, end + 1)) - startDepth,
                branches: region.reduce((a, l) => a + countBranches(l.code), 0),
                commentLines: region.filter((l) => l.comment.trim()).length,
            });
            // skip past this region so nested arrows don't double-report the same body
            i = Math.max(i + 1, end + 1);
        }
    }
    else if (lang === PY || !lang.braces) {
        const indents = indentWidths(lines);
        for (let i = 0; i < lines.length && fns.length < 500; i++) {
            const m = PY_DEF_RE.exec(lines[i].code);
            if (!m)
                continue;
            const base = indents[i];
            let end = i;
            for (let j = i + 1; j < lines.length; j++) {
                const l = lines[j];
                if (!l.code.trim()) {
                    end = j;
                    continue;
                }
                if (indents[j] <= base)
                    break;
                end = j;
            }
            if (end === i)
                continue;
            const region = lines.slice(i, end + 1);
            const bodyDepths = region
                .filter((l) => l.code.trim())
                .map((l) => (/^[ \t]*/.exec(l.code)[0].replace(/\t/g, '    ').length - base));
            fns.push({
                name: m[1],
                line: i + 1,
                lines: end - i + 1,
                maxLineLen: maxOf(region.map((l) => l.raw.length)),
                maxNesting: maxOf(bodyDepths.map((w) => Math.floor((w - 1) / 4))),
                branches: region.reduce((a, l) => a + countBranches(l.code), 0),
                commentLines: region.filter((l) => l.comment.trim()).length,
            });
            i = end;
        }
    }
    return fns;
}
function analyzeFile(text, langKey) {
    const lang = LANGS[langKey];
    const masked = maskSource(text, lang);
    const nonBlank = masked.filter((l) => l.raw.trim() !== '');
    const lens = nonBlank.map((l) => l.raw.length);
    const longest = masked
        .map((l, idx) => ({ line: idx + 1, len: l.raw.trim() === '' ? -1 : l.raw.length }))
        .filter((l) => l.len >= 0)
        .sort((a, b) => b.len - a.len)
        .slice(0, 3);
    const codeLines = masked.filter((l) => l.code.trim()).length;
    const commentOnly = masked.filter((l) => !l.code.trim() && l.comment.trim()).length;
    const inline = masked.filter((l) => l.code.trim() && l.comment.trim()).length;
    const commentedOut = masked.filter((l) => {
        const c = l.comment.trim();
        if (!c)
            return false;
        if (/^(@|#+\s|\*|todo|fixme|note|https?:|<reference\b|@ts-)/i.test(c.replace(/^\/+\s*|^--\s*/, '')))
            return false;
        return CODEISH_RE.test(c);
    }).length;
    // identifiers from code (strings already masked)
    let identCount = 0;
    let identLenSum = 0;
    let shortCount = 0;
    const identWordsByLine = [];
    const styles = { camel: 0, snake: 0, pascal: 0, upper: 0, mixed: 0, other: 0 };
    for (const l of masked) {
        const lineWords = new Set();
        const ids = l.code.match(IDENT_RE);
        if (ids) {
            for (const id of ids) {
                if (KEYWORDS.has(id.toLowerCase()) || KEYWORDS.has(id))
                    continue;
                identCount++;
                identLenSum += id.length;
                if (id.length <= 2)
                    shortCount++;
                styles[styleOf(id)]++;
                for (const w of splitIdentWords(id))
                    lineWords.add(w);
            }
        }
        identWordsByLine.push(lineWords);
    }
    let coherenceWords = 0;
    let coherenceHits = 0;
    for (let line = 0; line < masked.length; line++) {
        const words = new Set((masked[line].comment.toLowerCase().match(/[a-z]{3,}/g) ?? [])
            .filter((word) => !STOPWORDS.has(word)));
        if (!words.size)
            continue;
        const nearby = new Set();
        for (let other = Math.max(0, line - 2); other <= Math.min(masked.length - 1, line + 2); other++) {
            for (const word of identWordsByLine[other])
                nearby.add(word);
        }
        for (const word of words) {
            coherenceWords++;
            if (nearby.has(word))
                coherenceHits++;
        }
    }
    const commentCoherence = coherenceWords ? coherenceHits / coherenceWords : null;
    const styleEntries = Object.entries(styles)
        .filter(([k]) => k !== 'other' && k !== 'mixed')
        .sort((a, b) => b[1] - a[1]);
    const styleTotal = styleEntries.reduce((a, [, c]) => a + c, 0);
    const [dominantStyle, dominantCount] = styleEntries[0] ?? ['other', 0];
    // nesting
    let maxNesting = 0;
    if (lang.braces) {
        maxNesting = maxOf(braceDepths(masked));
    }
    else if (lang === PY) {
        const stack = [];
        for (const [li, l] of masked.entries()) {
            if (!l.code.trim())
                continue;
            const w = indentWidths([l])[0];
            while (stack.length && stack[stack.length - 1] >= w)
                stack.pop();
            stack.push(w);
            maxNesting = Math.max(maxNesting, stack.length - 1);
            void li;
        }
    }
    // tokens: entropy + crude Halstead
    const codeText = masked.map((l) => l.code).join('\n');
    const tokens = codeText.match(TOKEN_RE) ?? [];
    const operands = [];
    const operators = [];
    for (const t of tokens) {
        if (/^[A-Za-z_$]/.test(t) || /^\d/.test(t)) {
            if (KEYWORDS.has(t))
                operators.push(t);
            else
                operands.push(t);
        }
        else
            operators.push(t);
    }
    const vocab = new Set(operators).size + new Set(operands).size;
    const volume = tokens.length * Math.log2(Math.max(2, vocab));
    const functions = detectFunctions(masked, lang);
    return {
        lang: langKey,
        lines: masked.length,
        nonBlankLines: nonBlank.length,
        codeLines,
        blankRatio: masked.length ? (masked.length - nonBlank.length) / masked.length : 0,
        commentRatio: nonBlank.length ? commentOnly / nonBlank.length : 0,
        inlineCommentRatio: codeLines ? inline / codeLines : 0,
        commentedOutRatio: nonBlank.length ? commentedOut / nonBlank.length : 0,
        lineLen: dist(lens),
        longestLines: longest,
        maxNesting,
        branchesPer100: codeLines ? (masked.reduce((a, l) => a + countBranches(l.code), 0) / codeLines) * 100 : 0,
        ident: {
            count: identCount,
            avgLen: identCount ? identLenSum / identCount : 0,
            shortRatio: identCount ? shortCount / identCount : 0,
            dominantStyle,
            dominantShare: styleTotal ? dominantCount / styleTotal : 0,
        },
        tokenEntropy: entropy(tokens),
        halsteadPerLine: codeLines ? volume / codeLines : 0,
        commentCoherence,
        dupRatio: null,
        barrelRatio: codeLines
            ? masked.filter((l) => l.code.trim() && /^\s*export\s+.*\bfrom\b/.test(l.code)).length / codeLines
            : 0,
        hash: '',
        functions,
        fnLinesMax: Math.max(0, ...functions.map((f) => f.lines)),
        fnNestingMax: Math.max(0, ...functions.map((f) => f.maxNesting)),
    };
}
function normalizeReadabilityTrend(value) {
    if (!value || typeof value !== 'object')
        return null;
    const trend = value;
    if (!((trend.comparedTo === null || typeof trend.comparedTo === 'string') &&
        typeof trend.changedFiles === 'number' && Number.isFinite(trend.changedFiles) &&
        Array.isArray(trend.improved) && Array.isArray(trend.worsened)))
        return null;
    const improvedCount = typeof trend.improvedCount === 'number' && Number.isSafeInteger(trend.improvedCount) && trend.improvedCount >= trend.improved.length
        ? trend.improvedCount : trend.improved.length;
    const worsenedCount = typeof trend.worsenedCount === 'number' && Number.isSafeInteger(trend.worsenedCount) && trend.worsenedCount >= trend.worsened.length
        ? trend.worsenedCount : trend.worsened.length;
    const addedFiles = Array.isArray(trend.addedFiles) && trend.addedFiles.every((item) => typeof item === 'string') ? trend.addedFiles : [];
    const removedFiles = Array.isArray(trend.removedFiles) && trend.removedFiles.every((item) => typeof item === 'string') ? trend.removedFiles : [];
    return { ...trend, addedFiles, removedFiles, improvedCount, worsenedCount };
}
export function isSupportedReadabilityReport(value) {
    if (!value || typeof value !== 'object')
        return false;
    const report = value;
    const version = report.formatVersion ?? 1;
    const format = report.format ?? 'repo-atlas-readability-v1';
    return version === 1 && format === 'repo-atlas-readability-v1' &&
        typeof report.generatedAt === 'string' && !!report.files && typeof report.files === 'object' &&
        !!report.norms && typeof report.norms === 'object';
}
const MAX_FILE_BYTES = 512 * 1024;
/** metric -> [extractor, tail] ; tail 'high' flags z >= 2, 'low' flags z <= -2.
 *  Extractors may return NaN to exclude a file from that metric (e.g. files
 *  with too few identifiers produce degenerate naming stats). */
const METRICS = {
    lineLenP95: [(f) => f.lineLen.p95, 'high'],
    lineLenMax: [(f) => f.lineLen.max, 'high'],
    lineLenMean: [(f) => f.lineLen.mean, 'high'],
    maxNesting: [(f) => f.maxNesting, 'high'],
    branchesPer100: [(f) => f.branchesPer100, 'high'],
    commentRatio: [(f) => (f.nonBlankLines >= 10 ? f.commentRatio : NaN), 'high'],
    commentedOutRatio: [(f) => (f.nonBlankLines >= 10 ? f.commentedOutRatio : NaN), 'high'],
    identAvgLen: [(f) => (f.ident.count >= 20 ? f.ident.avgLen : NaN), 'low'],
    identShortRatio: [(f) => (f.ident.count >= 20 ? f.ident.shortRatio : NaN), 'high'],
    identStyleMixing: [(f) => (f.ident.count >= 20 ? 1 - f.ident.dominantShare : NaN), 'high'],
    tokenEntropy: [(f) => f.tokenEntropy, 'high'],
    halsteadPerLine: [(f) => f.halsteadPerLine, 'high'],
    dupRatio: [(f) => f.dupRatio ?? NaN, 'high'],
    barrelRatio: [(f) => (f.codeLines >= 30 ? f.barrelRatio : NaN), 'high'],
    fnLinesMax: [(f) => f.fnLinesMax, 'high'],
    fnNestingMax: [(f) => f.fnNestingMax, 'high'],
};
/** Calibrated surface-readability composite (docs/readability-audit.md §5):
 *  equal-weight z-sum of +commentRatio −halsteadPerLine −lineLenMean −tokenEntropy.
 *  ρ≈0.51–0.69 vs human snippet ratings, held out across B&W/Scalabrino/Dorn. */
export function surfaceCompositeOf(f, norms) {
    return (f.commentRatio - norms.commentRatio.mean) / (norms.commentRatio.sd || 1) -
        (f.halsteadPerLine - norms.halsteadPerLine.mean) / (norms.halsteadPerLine.sd || 1) -
        (f.lineLen.mean - norms.lineLenMean.mean) / (norms.lineLenMean.sd || 1) -
        (f.tokenEntropy - norms.tokenEntropy.mean) / (norms.tokenEntropy.sd || 1);
}
/** Trend between two reports (same repo, different runs): per-file hash picks
 *  out changed files, composite delta says which way they moved. */
export function diffReadabilityReports(prev, curr, topN = 10, minDelta = 1) {
    const rows = [];
    const addedFiles = Object.keys(curr.files).filter((repoPath) => !prev.files[repoPath]).sort();
    const removedFiles = Object.keys(prev.files).filter((repoPath) => !curr.files[repoPath]).sort();
    let changedFiles = 0;
    for (const [p, f] of Object.entries(curr.files)) {
        const pf = prev.files[p];
        if (!pf?.hash || !f.hash || pf.hash === f.hash)
            continue;
        changedFiles++;
        rows.push({ path: p, before: surfaceCompositeOf(pf, prev.norms), after: surfaceCompositeOf(f, curr.norms) });
    }
    const allWorsened = rows.filter((r) => r.before - r.after >= minDelta)
        .sort((a, b) => (a.after - a.before) - (b.after - b.before));
    const allImproved = rows.filter((r) => r.after - r.before >= minDelta)
        .sort((a, b) => (b.after - b.before) - (a.after - a.before));
    return {
        improved: allImproved.slice(0, topN),
        worsened: allWorsened.slice(0, topN),
        improvedCount: allImproved.length,
        worsenedCount: allWorsened.length,
        changedFiles,
        addedFiles,
        removedFiles,
    };
}
/** Hash-only freshness for `atlas status`; the expensive feature pass stays in
 * `readability`. The latest completed trend remains visible after a new report
 * is written, while changed/missing lists identify work since that report. */
export function readabilityStatus(root, scanResult) {
    const file = path.join(atlasDir(root), 'readability.json');
    const indexFile = path.join(atlasDir(root), 'audits', 'readability.json');
    let generatedAt = null;
    let latestTrend = null;
    let hashes = null;
    try {
        const opened = readRepoFile(root, '.atlas/audits/readability.json');
        if (opened) {
            const index = JSON.parse(opened.buffer.toString('utf8'));
            const rawFiles = index.files;
            const rawHashes = index.hashes;
            const validFiles = Array.isArray(rawFiles) && rawFiles.every((value) => typeof value === 'string' && validRepoPathForReadability(value)) &&
                new Set(rawFiles).size === rawFiles.length;
            const filesList = validFiles ? rawFiles : [];
            const validHashes = validFiles && rawHashes && typeof rawHashes === 'object' && !Array.isArray(rawHashes) &&
                Object.keys(rawHashes).length === filesList.length &&
                filesList.every((repoPath) => /^[0-9a-f]{40}$/u.test(rawHashes[repoPath] ?? '')) &&
                Object.keys(rawHashes).every((repoPath) => filesList.includes(repoPath));
            const scopeLines = validHashes
                ? filesList.map((repoPath) => `${rawHashes[repoPath]}  ${repoPath}`).sort()
                : [];
            const expectedScope = validHashes ? createHash('sha1').update(scopeLines.join('\n') + '\n').digest('hex') : null;
            if (index.format === 'atlas-audit-v1' && index.formatVersion === 1 &&
                index.slug === 'readability' && index.ruleset === 'repo-atlas-readability-v1' &&
                index.file_count === filesList.length && index.scope_hash === expectedScope && validHashes) {
                hashes = rawHashes;
                generatedAt = typeof index.scanned_at === 'string' ? index.scanned_at : null;
                const summary = index.readability;
                if (summary && typeof summary === 'object') {
                    const value = summary;
                    if (value.formatVersion === 1) {
                        if (typeof value.generatedAt === 'string')
                            generatedAt = value.generatedAt;
                        latestTrend = normalizeReadabilityTrend(value.trend);
                    }
                }
            }
        }
    }
    catch { /* no usable thin index — fall back to the historical report */ }
    if (!hashes) {
        try {
            const opened = readRepoFile(root, '.atlas/readability.json');
            if (!opened)
                return null;
            const report = JSON.parse(opened.buffer.toString('utf8'));
            if (!isSupportedReadabilityReport(report))
                return null;
            const entries = Object.entries(report.files);
            if (entries.some(([repoPath, features]) => !validRepoPathForReadability(repoPath) || !/^[0-9a-f]{40}$/u.test(features?.hash ?? '')))
                return null;
            hashes = Object.fromEntries(entries.map(([repoPath, features]) => [repoPath, features.hash]));
            generatedAt = report.generatedAt;
            latestTrend = normalizeReadabilityTrend(report.trend);
        }
        catch {
            return null;
        }
    }
    try {
        const repoPaths = Object.keys(hashes);
        const current = hashFilePaths(root, repoPaths, scanResult);
        const changedFiles = [];
        for (const [repoPath, previous] of Object.entries(hashes)) {
            const hash = current.hashes.get(repoPath);
            if (hash && previous !== hash)
                changedFiles.push(repoPath);
        }
        return {
            file,
            generatedAt,
            trackedFiles: repoPaths.length,
            changedFiles: changedFiles.sort(),
            missingFiles: current.missing.sort(),
            failedFiles: current.failed.sort(),
            latestTrend,
        };
    }
    catch {
        return null;
    }
}
function validRepoPathForReadability(repoPath) {
    return !!repoPath && !path.isAbsolute(repoPath) && !repoPath.includes('\\') && !repoPath.includes('\0') &&
        path.posix.normalize(repoPath) === repoPath && repoPath !== '.' && !repoPath.startsWith('../');
}
/** Thin atlas-audit-v1 index for the canonical readability report. The full
 * feature vectors stay in readability.json; this ledger contributes the same
 * hash/finding freshness contract as every other audit. */
function safeAtlasDirectory(root, segments, create) {
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
function assertSafeAtlasFile(root, file, parentSegments, createParent) {
    const parent = safeAtlasDirectory(root, parentSegments, createParent);
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
export function assertCanonicalReadabilityOutput(root) {
    const file = path.join(atlasDir(root), 'readability.json');
    assertSafeAtlasFile(root, file, [], false);
}
export function assertReadabilityReportOutput(root, file) {
    const target = path.resolve(file);
    const parent = path.dirname(target);
    const parentStat = fs.lstatSync(parent);
    if (!parentStat.isDirectory() || parentStat.isSymbolicLink())
        throw new Error(`unsafe readability output directory: ${parent}`);
    const rootPath = path.resolve(root);
    if (target !== rootPath && target.startsWith(rootPath + path.sep)) {
        const rootReal = fs.realpathSync(rootPath);
        const parentReal = fs.realpathSync(parent);
        if (parentReal !== rootReal && !parentReal.startsWith(rootReal + path.sep)) {
            throw new Error(`unsafe readability output path outside repository: ${file}`);
        }
    }
    if (fs.existsSync(target)) {
        const stat = fs.lstatSync(target);
        if (!stat.isFile() || stat.isSymbolicLink())
            throw new Error(`unsafe readability output: ${file} must be a regular file, not a symlink`);
    }
}
/** Read an existing report through a verified no-follow descriptor. This is
 * called after the feature pass too, so a target swapped during computation is
 * never followed for trend input. */
export function readReadabilityReport(root, file) {
    assertReadabilityReportOutput(root, file);
    const target = path.resolve(file);
    const rootPath = path.resolve(root);
    if (target !== rootPath && target.startsWith(rootPath + path.sep)) {
        const rel = path.relative(rootPath, target).replace(/\\/g, '/');
        const opened = readRepoFile(root, rel);
        if (!opened)
            throw new Error(`unsafe readability report: ${file}`);
        return JSON.parse(opened.buffer.toString('utf8'));
    }
    let fd = null;
    try {
        fd = fs.openSync(target, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
        const opened = fs.fstatSync(fd);
        const real = fs.realpathSync(target);
        const expected = path.join(fs.realpathSync(path.dirname(target)), path.basename(target));
        const resolved = fs.statSync(real);
        if (!opened.isFile() || real !== expected || opened.dev !== resolved.dev || opened.ino !== resolved.ino) {
            throw new Error(`unsafe readability report: ${file}`);
        }
        return JSON.parse(fs.readFileSync(fd, 'utf8'));
    }
    finally {
        if (fd !== null)
            fs.closeSync(fd);
    }
}
export function writeReadabilityReport(root, file, report) {
    assertReadabilityReportOutput(root, file);
    atomicWrite(path.resolve(file), JSON.stringify(report, null, 2) + '\n');
    return path.resolve(file);
}
export function writeCanonicalReadabilityReport(root, report) {
    const file = path.join(atlasDir(root), 'readability.json');
    assertCanonicalReadabilityOutput(root);
    return writeReadabilityReport(root, file, report);
}
export function assertReadabilityAuditOwnership(root) {
    const file = path.join(atlasDir(root), 'audits', 'readability.json');
    assertSafeAuditLedgerOutput(root, file);
    if (!fs.existsSync(file))
        return;
    let existing;
    try {
        const opened = readRepoFile(root, '.atlas/audits/readability.json');
        if (!opened)
            throw new Error('unsafe readability audit ledger');
        existing = JSON.parse(opened.buffer.toString('utf8'));
    }
    catch {
        throw new Error(`refusing to overwrite unreadable audit ledger: ${path.relative(root, file)}`);
    }
    const owned = existing !== null && typeof existing === 'object' &&
        existing.format === 'atlas-audit-v1' &&
        existing.formatVersion === 1 &&
        existing.slug === 'readability' &&
        existing.ruleset === 'repo-atlas-readability-v1';
    if (!owned)
        throw new Error(`refusing to overwrite unrelated audit ledger: ${path.relative(root, file)}`);
}
export function writeReadabilityAuditLedger(root, report) {
    if (!fs.existsSync(atlasDir(root)))
        return null;
    assertReadabilityAuditOwnership(root);
    const files = Object.keys(report.files).sort();
    const hashes = Object.fromEntries(files.map((repoPath) => [repoPath, report.files[repoPath].hash]));
    const scopeLines = files.map((repoPath) => `${hashes[repoPath]}  ${repoPath}`).sort();
    const metricsByFile = new Map();
    for (const [metric, rows] of Object.entries(report.outliers)) {
        for (const row of rows) {
            if (!metricsByFile.has(row.path))
                metricsByFile.set(row.path, []);
            metricsByFile.get(row.path).push(metric);
        }
    }
    const findings = [...metricsByFile.entries()].sort(([left], [right]) => left.localeCompare(right))
        .map(([repoPath, metrics]) => ({ path: repoPath, severity: 'info', summary: `repo-relative outlier: ${metrics.sort().join(', ')}` }));
    const file = path.join(atlasDir(root), 'audits', 'readability.json');
    writeAuditLedgerFile(root, file, JSON.stringify({
        formatVersion: 1,
        format: 'atlas-audit-v1',
        slug: 'readability',
        title: 'Code readability',
        ruleset: 'repo-atlas-readability-v1',
        scanned_at: report.generatedAt,
        stamped: report.generatedAt,
        scope_hash: createHash('sha1').update(scopeLines.join('\n') + '\n').digest('hex'),
        file_count: files.length,
        files,
        hashes,
        findings,
        readability: {
            formatVersion: 1,
            generatedAt: report.generatedAt,
            trend: report.trend ?? null,
        },
    }, null, 2) + '\n');
    return file;
}
export function computeReadability(root, config, topN = 10) {
    const scanResult = scan(root, { exclude: [...DEFAULT_EXCLUDE, ...(config.exclude ?? [])] });
    const files = {};
    const shinglesByFile = new Map();
    const shingleCounts = new Map();
    const langs = {};
    let skippedNonCode = 0;
    let skippedLarge = 0;
    for (const rel of scanResult.files.keys()) {
        const ext = rel.includes('.') ? rel.slice(rel.lastIndexOf('.') + 1).toLowerCase() : '';
        const lang = Object.hasOwn(LANGS, ext) ? LANGS[ext] : undefined;
        if (!lang) {
            skippedNonCode++;
            continue;
        }
        let text;
        let blobHash;
        try {
            const opened = readRepoFile(root, rel, MAX_FILE_BYTES + 1);
            if (!opened) {
                skippedNonCode++;
                continue;
            }
            const buf = opened.buffer;
            if (opened.truncated || buf.length > MAX_FILE_BYTES) {
                skippedLarge++;
                continue;
            }
            if (buf.subarray(0, 8192).includes(0)) {
                skippedNonCode++;
                continue;
            }
            text = buf.toString('utf8');
            blobHash = createHash('sha1').update(`blob ${buf.length}\0`).update(buf).digest('hex');
        }
        catch {
            skippedNonCode++;
            continue;
        }
        const features = analyzeFile(text, ext);
        features.hash = blobHash;
        files[rel] = features;
        langs[ext] = (langs[ext] ?? 0) + 1;
        // duplication shingles over normalised code lines (>= 25 chars)
        const normLines = maskSource(text, lang)
            .map((l) => l.code.trim().replace(/\s+/g, ' '))
            .filter((l) => l.length >= 25);
        const set = new Set();
        for (let i = 0; i + 4 <= normLines.length; i++) {
            const h = fnv1a(normLines.slice(i, i + 4).join('\n'));
            set.add(h);
            shingleCounts.set(h, (shingleCounts.get(h) ?? 0) + 1);
        }
        shinglesByFile.set(rel, set);
    }
    for (const [rel, set] of shinglesByFile) {
        // 小文件 shingle 太少时 dupRatio 统计上不可靠（公式化内容误报）——保持 null
        if (set.size < 8)
            continue;
        let dup = 0;
        for (const h of set)
            if ((shingleCounts.get(h) ?? 0) > 1)
                dup++;
        files[rel].dupRatio = dup / set.size;
    }
    // norms + outliers
    const norms = {};
    const outliers = {};
    for (const [metric, [get, tail]] of Object.entries(METRICS)) {
        const vals = Object.values(files).map(get).filter((v) => Number.isFinite(v));
        const { mean, sd } = dist(vals);
        norms[metric] = { mean, sd };
        if (sd === 0) {
            outliers[metric] = [];
            continue;
        }
        const rows = Object.entries(files)
            .map(([p, f]) => ({ path: p, value: get(f), z: (get(f) - mean) / sd }))
            .filter((r) => Number.isFinite(r.z) && (tail === 'high' ? r.z >= 2 : r.z <= -2))
            .sort((a, b) => (tail === 'high' ? b.z - a.z : a.z - b.z));
        outliers[metric] = rows.slice(0, topN);
    }
    const compositeOf = (f) => surfaceCompositeOf(f, norms);
    const compDist = dist(Object.values(files).map(compositeOf));
    norms.surfaceComposite = { mean: compDist.mean, sd: compDist.sd };
    outliers.surfaceComposite = compDist.sd === 0 ? [] : Object.entries(files)
        .map(([p, f]) => ({ path: p, value: compositeOf(f), z: (compositeOf(f) - compDist.mean) / compDist.sd }))
        .filter((r) => r.z <= -2)
        .sort((a, b) => a.z - b.z)
        .slice(0, topN);
    // directory rollup (2-level: apps/x, packages/y; shallow repos fall back to
    // the first segment, flat repos to '(root)')
    const dirMap = new Map();
    for (const [p, f] of Object.entries(files)) {
        const parts = p.split('/');
        const key = parts.length >= 3 ? parts.slice(0, 2).join('/') : parts.length === 2 ? parts[0] : '(root)';
        if (!dirMap.has(key))
            dirMap.set(key, { files: 0, sum: 0, low: 0, worst: null, worstV: Number.POSITIVE_INFINITY });
        const d = dirMap.get(key);
        const c = compositeOf(f);
        d.files++;
        d.sum += c;
        if (compDist.sd > 0 && (c - compDist.mean) / compDist.sd <= -2)
            d.low++;
        if (c < d.worstV) {
            d.worstV = c;
            d.worst = p;
        }
    }
    const dirs = [...dirMap.entries()]
        .filter(([, v]) => v.files >= 5)
        .map(([k, v]) => ({ path: k, files: v.files, meanComposite: v.sum / v.files, lowFiles: v.low, worst: v.worst, worstComposite: v.worstV }))
        .sort((a, b) => a.meanComposite - b.meanComposite);
    const longestLines = Object.entries(files)
        .flatMap(([p, f]) => f.longestLines.map((l) => ({ path: p, ...l })))
        .sort((a, b) => b.len - a.len)
        .slice(0, topN);
    const worstFunctions = Object.entries(files)
        .flatMap(([p, f]) => f.functions.map((fn) => ({ path: p, ...fn })))
        .sort((a, b) => b.lines - a.lines || b.maxNesting - a.maxNesting)
        .slice(0, topN);
    return {
        format: 'repo-atlas-readability-v1',
        formatVersion: 1,
        generatedAt: new Date().toISOString(),
        repo: {
            files: Object.keys(files).length,
            skippedNonCode,
            skippedLarge,
            functions: Object.values(files).reduce((a, f) => a + f.functions.length, 0),
            langs,
        },
        norms,
        outliers,
        dirs,
        longestLines,
        worstFunctions,
        files,
    };
}
// ---------- console summary ----------
const fmt = (x, d = 1) => x.toFixed(d);
export function formatReadabilitySummary(report, topN = 10) {
    const out = [];
    const r = report.repo;
    out.push(`readability: ${r.files} files analysed · ${r.skippedNonCode} non-code skipped` +
        (r.skippedLarge ? ` · ${r.skippedLarge} >512KB skipped` : '') +
        ` · ${r.functions} functions detected (heuristic)`);
    out.push(`langs: ${Object.entries(r.langs).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(' · ')}`);
    out.push('');
    out.push(`repo-relative outliers (|z| >= 2 vs repo norm; top ${topN} per dimension — no absolute score, see docs/readability-audit.md):`);
    const badDirs = report.dirs.filter((d) => d.meanComposite < 0).slice(0, 6);
    if (badDirs.length) {
        out.push('');
        out.push('  worst areas (mean composite):');
        for (const d of badDirs) {
            out.push(`    ${d.path}  files=${d.files} mean=${fmt(d.meanComposite)} 低分=${d.lowFiles}  worst: ${d.worst}`);
        }
    }
    const labels = {
        surfaceComposite: ['surface readability composite (calibrated, worst tail)', (v) => `score=${fmt(v)}`],
        lineLenP95: ['long lines (p95 chars/file)', (v) => `p95=${fmt(v, 0)}`],
        lineLenMax: ['extreme single line (max chars/file)', (v) => `max=${fmt(v, 0)}`],
        lineLenMean: ['long lines (mean chars/file)', (v) => `mean=${fmt(v, 0)}`],
        maxNesting: ['deep nesting', (v) => `depth=${fmt(v, 0)}`],
        branchesPer100: ['branch density', (v) => `${fmt(v)} branches/100 code lines`],
        commentRatio: ['heavy comment density', (v) => `${fmt(v * 100)}% of non-blank lines`],
        commentedOutRatio: ['commented-out code', (v) => `${fmt(v * 100)}% of non-blank lines`],
        identAvgLen: ['cryptic identifiers (avg len, low tail)', (v) => `avg=${fmt(v)} chars`],
        identShortRatio: ['short identifier ratio', (v) => `${fmt(v * 100)}% <=2 chars`],
        identStyleMixing: ['naming-style mixing', (v) => `${fmt((1 - v) * 100)}% dominant style`],
        tokenEntropy: ['token entropy', (v) => `${fmt(v)} bits/token`],
        halsteadPerLine: ['information density (Halstead/line)', (v) => fmt(v, 0)],
        dupRatio: ['duplication (4-line shingles)', (v) => `${fmt(v * 100)}% shingles shared`],
        barrelRatio: ['barrel (re-export wall)', (v) => `${fmt(v * 100)}% re-export lines`],
        fnLinesMax: ['largest function (lines)', (v) => `${fmt(v, 0)} lines`],
        fnNestingMax: ['deepest function nesting', (v) => `depth=${fmt(v, 0)}`],
    };
    for (const [metric, rows] of Object.entries(report.outliers)) {
        if (!rows.length)
            continue;
        const [label, show] = labels[metric] ?? [metric, (v) => fmt(v)];
        out.push('');
        out.push(`  ${label}:`);
        for (const row of rows) {
            out.push(`    ${row.path}  ${show(row.value)}  z=${fmt(row.z)}`);
        }
    }
    if (report.longestLines.length) {
        out.push('');
        out.push('  longest single lines in repo:');
        for (const l of report.longestLines)
            out.push(`    ${l.path}:${l.line}  ${l.len} chars`);
    }
    if (report.worstFunctions.length) {
        out.push('');
        out.push('  largest functions:');
        for (const f of report.worstFunctions) {
            out.push(`    ${f.path}:${f.line}  ${f.name}()  ${f.lines} lines · nesting ${f.maxNesting} · branches ${f.branches}`);
        }
    }
    return out.join('\n');
}
// ---------- viewer artifacts (.atlas/artifacts/<page>/readability.md) ----------
function markdownPathText(value) {
    return [...value.replace(/[\r\n]+/gu, ' ')].map((character) => /^[\p{L}\p{N} /._:@=-]$/u.test(character) ? character : `&#${character.codePointAt(0)};`).join('');
}
/**
 * Write readability cards as viewer artifacts: one per outlier file, one per
 * affected directory roll-up. Requires an initialized .atlas/ (returns 0
 * otherwise). Stale cards from earlier runs are pruned — artifacts mirror the
 * CURRENT report, freshness stays the producing pipeline's business (see
 * artifacts.ts).
 */
export function writeReadabilityArtifacts(root, report) {
    if (!fs.existsSync(atlasDir(root)))
        return 0;
    const base = safeAtlasDirectory(root, ['artifacts'], true);
    const wanted = new Set();
    let written = 0;
    const emit = (pageKey, body) => {
        const segments = pageKey.split('/').filter(Boolean);
        const dir = safeAtlasDirectory(root, ['artifacts', ...segments], true);
        const file = path.join(dir, 'readability.md');
        assertSafeAtlasFile(root, file, ['artifacts', ...segments], true);
        wanted.add(file);
        const existing = fs.existsSync(file) ? readRepoFile(root, path.relative(root, file).replace(/\\/g, '/')) : null;
        if (existing && existing.buffer.toString('utf8') === body)
            return;
        atomicWrite(file, body);
        written++;
    };
    // per-file cards: every file appearing in any outlier list
    const flagged = new Map();
    for (const [metric, rows] of Object.entries(report.outliers)) {
        for (const r of rows) {
            if (!flagged.has(r.path))
                flagged.set(r.path, []);
            flagged.get(r.path).push({ metric, value: r.value, z: r.z });
        }
    }
    for (const [p, dims] of flagged) {
        const f = report.files[p];
        if (!f)
            continue;
        const comp = report.outliers.surfaceComposite.find((r) => r.path === p);
        const rows = dims.map((d) => `| ${d.metric} | ${d.value.toFixed(2)} | ${d.z.toFixed(1)} |`).join('\n');
        const fn = f.functions.length ? f.functions.reduce((a, b) => (a.lines >= b.lines ? a : b)) : null;
        emit(p, [
            `# readability`,
            ``,
            comp ? `surfaceComposite z=${comp.z.toFixed(1)}（负 = 相对 repo 难读；校准依据见 repo-atlas docs/readability-audit.md）` : `surfaceComposite 未上榜；以下为单维离群`,
            ``,
            `| 维度 | 值 | z |`,
            `|---|---|---|`,
            rows,
            ``,
            `- 行数 ${f.lines} · 注释率 ${(f.commentRatio * 100).toFixed(1)}% · 命名主导风格 ${f.ident.dominantStyle}(${(f.ident.dominantShare * 100).toFixed(0)}%) · 重复率 ${typeof f.dupRatio === 'number' ? (f.dupRatio * 100).toFixed(0) + '%' : 'n/a'} · 注释-代码一致性 ${typeof f.commentCoherence === 'number' ? (f.commentCoherence * 100).toFixed(0) + '%' : 'n/a'}`,
            fn ? `- 最大函数 ${markdownPathText(fn.name)}() ${fn.lines} 行 · nesting ${fn.maxNesting}（第 ${fn.line} 行起）` : `- 未检测到函数区`,
            f.longestLines[0] ? `- 最长行 L${f.longestLines[0].line}（${f.longestLines[0].len} chars）` : ``,
            ``,
        ].join('\n'));
    }
    // per-dir cards: any dir containing a flagged file, or with low-composite files
    const byDir = new Map();
    for (const [p, dims] of flagged) {
        const parts = p.split('/');
        const key = parts.length >= 3 ? parts.slice(0, 2).join('/') : parts.length === 2 ? parts[0] : '(root)';
        if (!byDir.has(key))
            byDir.set(key, []);
        for (const d of dims)
            byDir.get(key).push({ path: p, ...d });
    }
    for (const d of report.dirs) {
        if (d.path === '(root)')
            continue;
        const rows = byDir.get(d.path);
        if (!rows && d.lowFiles === 0)
            continue;
        const table = (rows ?? [])
            .sort((a, b) => Math.abs(b.z) - Math.abs(a.z))
            .slice(0, 30)
            .map((r) => `| ${markdownPathText(r.path)} | ${r.metric} | ${r.value.toFixed(2)} | ${r.z.toFixed(1)} |`)
            .join('\n');
        emit(d.path, [
            `# readability: ${markdownPathText(d.path)}`,
            ``,
            `files=${d.files} · meanComposite=${d.meanComposite.toFixed(2)} · 低分文件=${d.lowFiles} · 最差: ${markdownPathText(d.worst ?? '-')}`,
            ``,
            rows ? `| 文件 | 维度 | 值 | z |\n|---|---|---|---|\n${table}` : `_无单维离群文件_`,
            ``,
        ].join('\n'));
    }
    // prune stale cards
    if (fs.existsSync(base)) {
        const walk = (dir) => {
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                const full = path.join(dir, entry.name);
                if (entry.isDirectory()) {
                    walk(full);
                    if (fs.readdirSync(full).length === 0)
                        fs.rmdirSync(full);
                }
                else if (entry.name === 'readability.md' && !wanted.has(full)) {
                    fs.unlinkSync(full);
                }
            }
        };
        walk(base);
    }
    return written;
}
