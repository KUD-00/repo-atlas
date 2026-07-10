import fs from 'node:fs';
import path from 'node:path';
import { atlasDir } from './scan.js';
export function artifactsRoot(root) {
    return path.join(atlasDir(root), 'artifacts');
}
/** All artifacts under .atlas/artifacts/, sorted by page key then name.
 * Anything that isn't `.md`/`.json` (or sits directly under artifacts/,
 * i.e. belongs to no page) is skipped. */
export function loadArtifacts(root) {
    const base = artifactsRoot(root);
    if (!fs.existsSync(base))
        return [];
    const out = [];
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                walk(full);
                continue;
            }
            if (!entry.isFile())
                continue;
            const ext = entry.name.endsWith('.md') ? 'md' : entry.name.endsWith('.json') ? 'json' : null;
            if (!ext)
                continue;
            const pageKey = path.relative(base, dir).split(path.sep).join('/');
            if (!pageKey || pageKey.startsWith('..'))
                continue;
            out.push({
                pageKey,
                name: entry.name.slice(0, -(ext.length + 1)),
                kind: ext,
                body: fs.readFileSync(full, 'utf8'),
            });
        }
    };
    walk(base);
    return out.sort((a, b) => a.pageKey !== b.pageKey ? (a.pageKey < b.pageKey ? -1 : 1) : a.name < b.name ? -1 : 1);
}
