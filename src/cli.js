#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import {
  repoRoot, headCommit, headCommitFull, dirtyPaths, atlasDir, loadConfig, scan, hashFor,
  DEFAULT_EXCLUDE, DATA_FORMAT,
} from './scan.js'
import { noteFileFor, loadNotes, stampNote, moveNoteFile, notesRoot } from './notes.js'
import { computeStatus, summarize } from './status.js'
import { buildHtml, writeAtlas } from './build.js'
import { serve } from './serve.js'
import { buildImportGraph } from './deps.js'
import { loadGlossaryRaw, parseGlossary } from './glossary.js'

const USAGE = `repo-atlas — incremental codebase atlas with staleness tracking

usage: repo-atlas <command> [args]

  init                     create .atlas/ in the current git repo
  status [--json]          compare notes ledger against the working tree
                           (reports moved paths and broken note references too)
  notepath <path>          print the note file location for a repo path
  stamp [paths...|--all]   stamp note(s) with the current git hash + HEAD anchor
  migrate [--apply]        relocate notes whose targets moved (dry-run by default);
                           also rewrites references to the old paths in note prose
  build [-o <file>]        generate the self-contained HTML atlas (default .atlas/atlas.html)
  serve [-p <port>] [--host [addr]]
                           dev server with auto-reload (default 127.0.0.1:4400;
                           --host with no addr binds 0.0.0.0 for LAN access)

Notes live in .atlas/notes/ — one markdown file per described path:
  directory apps/daemon   -> .atlas/notes/apps/daemon/__dir__.md
  file      apps/x.ts     -> .atlas/notes/apps/x.ts.md
Frontmatter (hash, anchor, dirty, stamped) is managed by 'stamp'; you write the body.

Agent loop: status --json  ->  migrate --apply  ->  read diffs, revise note bodies  ->  stamp  ->  build`

function main() {
  const [cmd, ...args] = process.argv.slice(2)
  try {
    dispatch(cmd, args)
  } catch (err) {
    console.error(err.message)
    process.exit(1)
  }
}

function dispatch(cmd, args) {
  const root = cmd && cmd !== 'help' ? repoRoot() : null
  switch (cmd) {
    case 'init': return init(root)
    case 'status': return status(root, args)
    case 'notepath': return notepath(root, args)
    case 'stamp': return stamp(root, args)
    case 'migrate': return migrate(root, args)
    case 'build': return build(root, args)
    case 'serve': {
      const pIdx = args.indexOf('-p')
      const hIdx = args.indexOf('--host')
      const host = hIdx >= 0 ? (args[hIdx + 1]?.startsWith('-') || !args[hIdx + 1] ? '0.0.0.0' : args[hIdx + 1]) : '127.0.0.1'
      return serve(root, requireConfig(root), pIdx >= 0 ? Number(args[pIdx + 1]) : 4400, host)
    }
    default:
      console.log(USAGE)
      process.exitCode = cmd && cmd !== 'help' ? 1 : 0
  }
}

function requireConfig(root) {
  const config = loadConfig(root)
  if (!config) {
    console.error(`no .atlas/config.json in ${root} — run 'repo-atlas init' first`)
    process.exit(1)
  }
  return config
}

function init(root) {
  const dir = atlasDir(root)
  const configFile = path.join(dir, 'config.json')
  if (fs.existsSync(configFile)) {
    console.log(`already initialized: ${configFile}`)
    return
  }
  fs.mkdirSync(notesRoot(root), { recursive: true })
  fs.writeFileSync(configFile, JSON.stringify({ formatVersion: DATA_FORMAT, exclude: DEFAULT_EXCLUDE, output: '.atlas/atlas.html' }, null, 2) + '\n')
  fs.writeFileSync(path.join(dir, '.gitignore'), 'atlas.html\n')
  console.log(`initialized ${dir}`)
  console.log(`- edit config.json to tune excludes (picomatch patterns, on top of .gitignore)`)
  console.log(`- commit .atlas/ so descriptions are versioned with the code`)
}

function status(root, args) {
  const config = requireConfig(root)
  const result = computeStatus(root, scan(root, config), { deltas: true })
  const sum = summarize(result)
  const fmtDelta = (d) => (d ? ` (+${d.added}/-${d.removed}${d.files > 1 ? ` in ${d.files} files` : ''})` : '')
  if (args.includes('--json')) {
    const pick = (st) => result.entries.filter((e) => e.status === st).map(({ path, type }) => ({ path, type }))
    console.log(JSON.stringify({
      summary: sum,
      missing: pick('missing'),
      outdated: result.entries.filter((e) => e.status === 'outdated')
        .map(({ path, type, stamped, noteFile, delta }) => ({ path, type, stamped, noteFile, delta })),
      moved: result.entries.filter((e) => e.status === 'moved')
        .map(({ path, type, movedFrom, similarity, noteFile, expectedNoteFile }) =>
          ({ from: movedFrom, to: path, type, similarity, noteFile, expectedNoteFile })),
      orphans: result.orphans,
      brokenRefs: result.brokenRefs,
    }, null, 2))
    return
  }
  console.log(`${sum.total} paths · ${sum.fresh} fresh · ${sum.outdated} outdated · ${sum.missing} missing` +
    (sum.moved ? ` · ${sum.moved} moved` : '') +
    (sum.orphans ? ` · ${sum.orphans} orphan notes` : '') +
    (sum.brokenRefs ? ` · ${sum.brokenRefs} broken refs` : ''))
  const show = (label, st, max = 15) => {
    const list = result.entries.filter((e) => e.status === st)
    if (!list.length) return
    console.log(`\n${label}:`)
    for (const e of list.slice(0, max)) console.log(`  ${e.type === 'dir' ? 'D' : 'F'} ${e.path || '(root)'}${fmtDelta(e.delta)}`)
    if (list.length > max) console.log(`  … and ${list.length - max} more (use --json for the full list)`)
  }
  show('outdated', 'outdated')
  show('missing', 'missing')
  const movedList = result.entries.filter((e) => e.status === 'moved')
  if (movedList.length) {
    console.log(`\nmoved (note follows with 'repo-atlas migrate --apply'):`)
    for (const e of movedList) {
      const sim = e.similarity === 100 ? 'identical' : e.similarity !== null ? `${e.similarity}% similar` : 'children moved'
      console.log(`  ${e.type === 'dir' ? 'D' : 'F'} ${e.movedFrom} -> ${e.path} (${sim})`)
    }
  }
  for (const o of result.orphans) console.log(`\norphan note (target gone): ${o.noteFile}`)
  if (result.brokenRefs.length) {
    console.log(`\nbroken references in note prose:`)
    for (const r of result.brokenRefs.slice(0, 20)) {
      console.log(`  ${r.note || '(root)'}: \`${r.ref}\`${r.suggestion ? ` — now ${r.suggestion}?` : ''}`)
    }
    if (result.brokenRefs.length > 20) console.log(`  … and ${result.brokenRefs.length - 20} more`)
  }
}

function notepath(root, args) {
  const target = args[0]
  if (target === undefined) {
    console.error('usage: repo-atlas notepath <repo-path>   (use "." for the repo root)')
    process.exit(1)
  }
  const rel = target === '.' ? '' : target.replace(/\/+$/, '')
  const config = requireConfig(root)
  const found = hashFor(scan(root, config), rel)
  if (!found) {
    console.error(`path not in scan (excluded, gitignored, or nonexistent): ${target}`)
    process.exit(1)
  }
  console.log(noteFileFor(root, rel, found.type))
}

/** True when the stamped content of `p` is not what HEAD has for it. */
function isDirty(dirty, p, type) {
  if (type === 'file') return dirty.has(p)
  if (p === '') return dirty.size > 0
  return [...dirty].some((d) => d.startsWith(p + '/'))
}

function stamp(root, args) {
  const config = requireConfig(root)
  const scanResult = scan(root, config)
  const notes = loadNotes(root)
  const anchor = headCommitFull(root)
  const dirty = dirtyPaths(root)
  let targets
  if (args.includes('--all') || args.length === 0) {
    targets = [...notes.keys()]
  } else {
    targets = args.map((a) => (a === '.' ? '' : a.replace(/\/+$/, '')))
  }
  let stamped = 0
  for (const p of targets) {
    const note = notes.get(p)
    if (!note) {
      console.error(`no note for: ${p || '(root)'} — write ${noteFileFor(root, p, hashFor(scanResult, p)?.type ?? 'dir')} first`)
      process.exitCode = 1
      continue
    }
    const current = hashFor(scanResult, p)
    if (!current) {
      console.error(`skipping ${p}: no longer exists in scan (orphan note)`)
      continue
    }
    if (note.hash === current.hash && note.anchor) continue
    stampNote(note.file, current.hash, { anchor, dirty: isDirty(dirty, p, current.type) })
    stamped++
  }
  console.log(`stamped ${stamped} note(s), ${targets.length - stamped} already current or skipped`)
}

/**
 * Relocate the notes of moved paths (status 'moved') to their new ledger
 * slots. Dry-run prints the plan; --apply performs it:
 *   - note file moves to the new path's slot
 *   - a leading '# <old-path>' heading and inline `old-path` references in
 *     EVERY note body are rewritten to the new path
 *   - identical moves (similarity 100) are re-stamped; edited moves keep
 *     their old stamp so they still show as outdated (revise, then stamp)
 */
function migrate(root, args) {
  const apply = args.includes('--apply')
  const config = requireConfig(root)
  const scanResult = scan(root, config)
  const result = computeStatus(root, scanResult)
  const moves = result.entries.filter((e) => e.status === 'moved')
  if (!moves.length) {
    console.log('nothing to migrate — no moved paths detected')
    return
  }
  for (const e of moves) {
    const sim = e.similarity === 100 ? 'identical' : e.similarity !== null ? `${e.similarity}% similar` : 'children moved'
    console.log(`${apply ? 'migrating' : 'would migrate'}: ${e.movedFrom} -> ${e.path} (${sim})`)
  }
  if (!apply) {
    console.log(`\ndry run — pass --apply to relocate ${moves.length} note(s)`)
    return
  }

  const notes = loadNotes(root)
  const anchor = headCommitFull(root)
  const dirty = dirtyPaths(root)
  for (const e of moves) {
    const note = notes.get(e.movedFrom)
    const dest = moveNoteFile(root, note, e.path, e.type)
    // rewrite the conventional '# old-path' heading in the moved note itself
    const headed = fs.readFileSync(dest, 'utf8')
      .replace(new RegExp(`^# ${escapeRe(e.movedFrom)}$`, 'm'), `# ${e.path}`)
    fs.writeFileSync(dest, headed)
    if (e.similarity === 100) {
      stampNote(dest, hashFor(scanResult, e.path).hash, { anchor, dirty: isDirty(dirty, e.path, e.type) })
    }
  }
  // rewrite inline `old-path` references across all note bodies
  let refFixes = 0
  for (const { file } of loadNotes(root).values()) {
    const raw = fs.readFileSync(file, 'utf8')
    let next = raw
    for (const e of moves) {
      next = next.replaceAll('`' + e.movedFrom + '`', '`' + e.path + '`')
    }
    if (next !== raw) {
      fs.writeFileSync(file, next)
      refFixes++
    }
  }
  // drop note directories emptied by the moves
  pruneEmptyDirs(notesRoot(root))
  const exact = moves.filter((e) => e.similarity === 100).length
  console.log(`\nmigrated ${moves.length} note(s): ${exact} re-stamped (identical), ` +
    `${moves.length - exact} left outdated for revision` +
    (refFixes ? `; rewrote old-path references in ${refFixes} note(s)` : ''))
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function pruneEmptyDirs(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) pruneEmptyDirs(path.join(dir, entry.name))
  }
  if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir)
}

function build(root, args) {
  const config = requireConfig(root)
  const oIdx = args.indexOf('-o')
  const outFile = oIdx >= 0 ? args[oIdx + 1] : (config.output ?? '.atlas/atlas.html')
  const scanResult = scan(root, config)
  const status = computeStatus(root, scanResult)
  const html = buildHtml({
    repoName: path.basename(root),
    commit: headCommit(root),
    status,
    graph: buildImportGraph(root, scanResult),
    glossary: parseGlossary(loadGlossaryRaw(root)),
  })
  const target = writeAtlas(root, outFile, html)
  const sum = summarize(status)
  console.log(`wrote ${target}`)
  console.log(`${sum.total} paths · ${sum.fresh} fresh · ${sum.outdated} outdated · ${sum.missing} missing`)
}

main()
