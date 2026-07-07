import { loadNotes } from './notes.js';
import { loadGlossaryRaw, parseGlossary } from './glossary.js';
// A bolded span is the corpus's own signal of "this is a concept worth naming".
// Strip a wrapping code span (**`X`**) and surrounding punctuation; keep the term.
function boldedTerms(body) {
    const out = new Set();
    for (const m of body.matchAll(/\*\*(`?[^*\n]+?`?)\*\*/gu)) {
        const t = m[1].replace(/`/gu, '').trim().replace(/[，。；：、,.;:]+$/u, '').trim();
        // length >= 2 and contains a letter or CJK char (skip pure punctuation/digits)
        if (t.length >= 2 && /[\p{L}]/u.test(t))
            out.add(t);
    }
    return out;
}
export function computeConcepts(root, min) {
    const notes = loadNotes(root);
    const glossary = parseGlossary(loadGlossaryRaw(root));
    const glossaryNames = new Set();
    for (const g of glossary) {
        glossaryNames.add(g.term.toLowerCase());
        for (const a of g.aliases)
            glossaryNames.add(a.toLowerCase());
    }
    // doc-frequency of each bolded term (distinct notes), plus which notes.
    const byTerm = new Map();
    for (const [repoPath, note] of notes) {
        if (!note.body)
            continue;
        for (const t of boldedTerms(note.body)) {
            let s = byTerm.get(t);
            if (!s)
                byTerm.set(t, (s = new Set()));
            s.add(repoPath);
        }
    }
    const candidates = [];
    for (const [term, noteSet] of byTerm) {
        if (noteSet.size < min)
            continue;
        candidates.push({
            term,
            noteCount: noteSet.size,
            inGlossary: glossaryNames.has(term.toLowerCase()),
            notes: [...noteSet].sort().slice(0, 5),
        });
    }
    candidates.sort((a, b) => b.noteCount - a.noteCount || a.term.localeCompare(b.term));
    const glossaryGaps = candidates.filter((c) => !c.inGlossary);
    // dead glossary: term (or alias) whose substring never appears in any body.
    const allBodies = [...notes.values()].map((n) => n.body ?? '').join('\n');
    const deadGlossary = [];
    for (const g of glossary) {
        const names = [g.term, ...g.aliases];
        if (!names.some((n) => n && allBodies.includes(n)))
            deadGlossary.push(g.term);
    }
    return { candidates, glossaryGaps, deadGlossary, min };
}
export function concepts(root, args) {
    const minIdx = args.indexOf('--min');
    const min = minIdx >= 0 ? Math.max(2, Number(args[minIdx + 1]) || 4) : 4;
    const result = computeConcepts(root, min);
    if (args.includes('--json')) {
        console.log(JSON.stringify(result, null, 2));
        return;
    }
    const { candidates, glossaryGaps, deadGlossary } = result;
    console.log(`\nConcept candidates — terms bolded across >= ${min} notes (${candidates.length}):`);
    console.log('  a concept re-emphasized this widely usually wants one canonical home note + a glossary essence.\n');
    for (const c of candidates) {
        const tag = c.inGlossary ? '  ' : '⚠ '; // gap = referenced widely, no glossary essence
        console.log(`  ${tag}${String(c.noteCount).padStart(3)}  ${c.term}`);
        console.log(`        ${c.notes.join(', ')}${c.noteCount > c.notes.length ? ', …' : ''}`);
    }
    if (glossaryGaps.length) {
        console.log(`\nGlossary gaps (${glossaryGaps.length}) — widely referenced, no glossary entry:`);
        console.log('  a thinned "see <home>" reference to these reads as undefined; add an essence line.');
        for (const g of glossaryGaps)
            console.log(`  ⚠ ${g.term} (${g.noteCount} notes)`);
    }
    if (deadGlossary.length) {
        console.log(`\nDead glossary (${deadGlossary.length}) — defined but the term appears in no note body:`);
        for (const t of deadGlossary)
            console.log(`  · ${t}`);
    }
    console.log(`\n(no-LLM heuristic; tune with --min N, machine-read with --json)`);
}
