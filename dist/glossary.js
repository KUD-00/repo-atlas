import fs from 'node:fs';
import path from 'node:path';
import { atlasDir } from './scan.js';
export function loadGlossaryRaw(root) {
    try {
        return fs.readFileSync(path.join(atlasDir(root), 'glossary.md'), 'utf8');
    }
    catch {
        return '';
    }
}
export function parseGlossary(raw) {
    if (!raw.trim())
        return [];
    const terms = [];
    const sections = raw.split(/^##\s+/mu).slice(1);
    for (const section of sections) {
        const nl = section.indexOf('\n');
        const term = (nl === -1 ? section : section.slice(0, nl)).trim();
        if (!term)
            continue;
        let body = nl === -1 ? '' : section.slice(nl + 1).trim();
        let aliases = [];
        const aliasMatch = body.match(/^(?:别名|aliases)[:：]\s*(.+)$/mu);
        if (aliasMatch) {
            aliases = aliasMatch[1].split(/[,、]/u).map((s) => s.trim()).filter(Boolean);
            body = body.replace(aliasMatch[0], '').trim();
        }
        let home;
        const homeMatch = body.match(/^(?:归属|home)[:：]\s*(.+)$/mu);
        if (homeMatch) {
            home = homeMatch[1].trim().replace(/^`|`$/gu, '').trim() || undefined;
            body = body.replace(homeMatch[0], '').trim();
        }
        terms.push({ term, aliases, def: body, ...(home ? { home } : {}) });
    }
    return terms;
}
const escapeReg = (s) => s.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
/**
 * Fill each entry's `refs` — repo paths of notes whose prose references the
 * term (or an alias). Mirrors the viewer's annotateGlossary matching so "refs"
 * means exactly the notes where the term would be highlighted: a single term|alias
 * regex, with a word-boundary guard for Latin/numeric terms ("L1" ∉ "L114").
 * Runs at build time; no LLM, same as the rest of the tool.
 */
export function fillGlossaryRefs(glossary, notes) {
    if (!glossary.length)
        return;
    const names = [];
    for (const g of glossary)
        for (const t of [g.term, ...g.aliases])
            if (t)
                names.push([t, g]);
    names.sort((a, b) => b[0].length - a[0].length);
    const byText = new Map(names.map(([t, g]) => [t, g]));
    const pattern = new RegExp(names.map(([t]) => escapeReg(t)).join('|'), 'gu');
    const isWord = (ch) => !!ch && /[A-Za-z0-9_]/u.test(ch);
    const refs = new Map();
    for (const note of notes) {
        const repoPath = note.path;
        const body = note.body ?? '';
        if (!body)
            continue;
        pattern.lastIndex = 0;
        let m;
        while ((m = pattern.exec(body)) !== null) {
            const hit = m[0];
            const before = body[m.index - 1];
            const after = body[m.index + hit.length];
            if ((/[A-Za-z0-9]/u.test(hit[0]) && isWord(before)) ||
                (/[A-Za-z0-9]/u.test(hit[hit.length - 1]) && isWord(after)))
                continue;
            const entry = byText.get(hit);
            if (!entry)
                continue;
            let s = refs.get(entry);
            if (!s)
                refs.set(entry, (s = new Set()));
            // A note is not its own concept's "reference" — the home note owns it.
            if (repoPath !== entry.home)
                s.add(repoPath);
        }
    }
    for (const g of glossary) {
        const s = refs.get(g);
        if (s && s.size)
            g.refs = [...s].sort();
    }
}
