import fs from 'node:fs';
import path from 'node:path';
import { marked } from 'marked';
import { loadNotes } from './notes.js';
import { findLine } from './findLine.js';
function lineOf(body, raw, from = 0) {
    const idx = body.indexOf(raw, from);
    if (idx < 0)
        return 1;
    return body.slice(0, idx).split('\n').length;
}
function walkTokens(tokens, visit) {
    for (const t of tokens) {
        visit(t);
        if ('tokens' in t && Array.isArray(t.tokens))
            walkTokens(t.tokens, visit);
        if (t.type === 'list') {
            for (const item of t.items)
                walkTokens(item.tokens, visit);
        }
    }
}
function collectCodeLinks(body) {
    const links = [];
    walkTokens(marked.lexer(body), (t) => {
        // link anchors [x](code:..) and embeds ![x](code:..) share marker semantics
        if ((t.type === 'link' || t.type === 'image') && t.href?.startsWith('code:')) {
            links.push({ href: t.href, raw: t.raw });
        }
    });
    return links;
}
function checkParseFailures(notePath, note) {
    const failures = [];
    const lines = note.body.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line.includes('](code:'))
            continue;
        const html = String(marked.parse(line));
        if (!html.includes('](code:'))
            continue;
        failures.push({
            kind: 'parse',
            note: notePath,
            noteFile: note.file,
            line: i + 1,
            anchor: line.trim(),
        });
    }
    return failures;
}
function checkMarkers(root, notePath, note) {
    if (note.type === 'dir')
        return [];
    const sourcePath = path.join(root, notePath);
    if (!fs.existsSync(sourcePath)) {
        return [{
                kind: 'missing-source',
                note: notePath,
                noteFile: note.file,
                path: notePath,
            }];
    }
    const lines = fs.readFileSync(sourcePath, 'utf8').split('\n');
    const findings = [];
    let searchFrom = 0;
    for (const link of collectCodeLinks(note.body)) {
        const idx = note.body.indexOf(link.raw, searchFrom);
        const line = idx < 0 ? 1 : lineOf(note.body, link.raw, idx);
        if (idx >= 0)
            searchFrom = idx + link.raw.length;
        const spec = decodeURIComponent(link.href.slice('code:'.length));
        const [startMarker, endMarker] = spec.split('..');
        const start = startMarker?.trim();
        if (start && findLine(lines, start) === null) {
            findings.push({
                kind: 'rot',
                note: notePath,
                noteFile: note.file,
                line,
                marker: start,
                anchor: link.raw,
            });
        }
        const end = endMarker?.trim();
        if (end && findLine(lines, end) === null) {
            findings.push({
                kind: 'rot',
                note: notePath,
                noteFile: note.file,
                line,
                marker: end,
                anchor: link.raw,
            });
        }
    }
    return findings;
}
export function computeCheck(root) {
    const notes = loadNotes(root);
    const findings = [];
    for (const [notePath, note] of notes) {
        findings.push(...checkParseFailures(notePath, note));
        findings.push(...checkMarkers(root, notePath, note));
    }
    const parseFailures = findings.filter((f) => f.kind === 'parse').length;
    const rotMarkers = findings.filter((f) => f.kind === 'rot').length;
    const missingSources = findings.filter((f) => f.kind === 'missing-source').length;
    return {
        summary: { total: findings.length, parseFailures, rotMarkers, missingSources },
        findings,
    };
}
export function summarizeCheck(result) {
    return result.summary;
}
