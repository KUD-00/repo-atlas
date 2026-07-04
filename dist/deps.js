import fs from 'node:fs';
import path from 'node:path';
const IMPORT_SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["']([^"']+)["']/gu;
const CODE_EXT = /\.[cm]?[jt]sx?$/u;
const specifierCache = new Map();
function extractSpecifiers(absFile, hash) {
    const hit = specifierCache.get(hash);
    if (hit)
        return hit;
    let body;
    try {
        body = fs.readFileSync(absFile, 'utf8');
    }
    catch {
        return [];
    }
    const out = [];
    IMPORT_SPECIFIER.lastIndex = 0;
    let m;
    while ((m = IMPORT_SPECIFIER.exec(body)) !== null)
        out.push(m[1]);
    specifierCache.set(hash, out);
    return out;
}
function workspacePackages(root, scanResult) {
    const byName = new Map();
    // manifests may be config-excluded (ignored) — they still name the packages
    for (const p of [...scanResult.files.keys(), ...scanResult.ignored]) {
        if (p !== 'package.json' && !p.endsWith('/package.json'))
            continue;
        try {
            const pkg = JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
            if (pkg.name)
                byName.set(pkg.name, p === 'package.json' ? '' : p.slice(0, -'/package.json'.length));
        }
        catch {
            /* unparsable manifest — skip */
        }
    }
    return byName;
}
function resolveRelative(fromFile, spec, files) {
    const dir = fromFile.includes('/') ? fromFile.slice(0, fromFile.lastIndexOf('/')) : '';
    const joined = path.posix.normalize(path.posix.join(dir, spec));
    if (joined.startsWith('..'))
        return null;
    const candidates = [joined];
    if (/\.[cm]?js$/u.test(joined)) {
        candidates.push(joined.replace(/\.([cm]?)js$/u, '.$1ts'), joined.replace(/\.js$/u, '.tsx'));
    }
    else if (!/\.\w+$/u.test(joined)) {
        for (const ext of ['.ts', '.tsx', '.js', '.mjs', '.cjs', '.jsx'])
            candidates.push(joined + ext);
        for (const ext of ['.ts', '.tsx', '.js'])
            candidates.push(joined + '/index' + ext);
    }
    return candidates.find((c) => files.has(c)) ?? null;
}
export function buildImportGraph(root, scanResult) {
    const files = scanResult.files;
    const byName = workspacePackages(root, scanResult);
    const pathIndex = new Map();
    const paths = [];
    const idx = (p) => {
        let i = pathIndex.get(p);
        if (i === undefined) {
            i = paths.length;
            paths.push(p);
            pathIndex.set(p, i);
        }
        return i;
    };
    const edges = [];
    const seen = new Set();
    for (const [file, hash] of files) {
        if (!CODE_EXT.test(file))
            continue;
        for (const spec of extractSpecifiers(path.join(root, file), hash)) {
            let target = null;
            if (spec.startsWith('.')) {
                target = resolveRelative(file, spec, files);
            }
            else {
                const name = spec.startsWith('@')
                    ? spec.split('/').slice(0, 2).join('/')
                    : spec.split('/')[0];
                target = byName.get(name) ?? null;
            }
            if (target === null || target === file)
                continue;
            const key = file + '\0' + target;
            if (seen.has(key))
                continue;
            seen.add(key);
            edges.push([idx(file), idx(target)]);
        }
    }
    return { paths, edges, packageRoots: [...byName.values()].filter((p) => p !== '').sort() };
}
