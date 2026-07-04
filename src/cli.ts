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
import { computeCheck, type CheckFinding } from './check.js'
import type { AtlasConfig, PathType } from './types.js'

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
  check [--json]           validate code: anchors — links and ![embeds] (parse + marker rot)
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
    console.error(err instanceof Error ? err.message : String(err))
    process.exit(1)
  }
}

function dispatch(cmd: string | undefined, args: string[]) {
  const root = cmd && cmd !== 'help' ? repoRoot() : null
  switch (cmd) {
    case 'init': return init(root!)
    case 'status': return status(root!, args)
    case 'notepath': return notepath(root!, args)
    case 'stamp': return stamp(root!, args)
    case 'migrate': return migrate(root!, args)
    case 'build': return build(root!, args)
    case 'check': return check(root!, args)
    case 'serve': {
      const pIdx = args.indexOf('-p')
      const hIdx = args.indexOf('--host')
      const host = hIdx >= 0 ? (args[hIdx + 1]?.startsWith('-') || !args[hIdx + 1] ? '0.0.0.0' : args[hIdx + 1]) : '127.0.0.1'
      return serve(root!, requireConfig(root!), pIdx >= 0 ? Number(args[pIdx + 1]) : 4400, host)
    }
    default:
      console.log(USAGE)
      process.exitCode = cmd && cmd !== 'help' ? 1 : 0
  }
}

function requireConfig(root: string): AtlasConfig {
  const config = loadConfig(root)
  if (!config) {
    console.error(`no .atlas/config.json in ${root} — run 'repo-atlas init' first`)
    process.exit(1)
  }
  return config
}

function init(root: string) {
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

function status(root: string, args: string[]) {
  const config = requireConfig(root)
  const result = computeStatus(root, scan(root, config), { deltas: true })
  const sum = summarize(result)
  const fmtDelta = (d?: { added: number; removed: number; files: number }) =>
    d ? ` (+${d.added}/-${d.removed}${d.files > 1 ? ` in ${d.files} files` : ''})` : ''
  if (args.includes('--json')) {
    const pick = (st: string) => result.entries.filter((e) => e.status === st).map(({ path, type }) => ({ path, type }))
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
    (sum.ignored ? ` · ${sum.ignored} ignored` : '') +
    (sum.orphans ? ` · ${sum.orphans} orphan notes` : '') +
    (sum.brokenRefs ? ` · ${sum.brokenRefs} broken refs` : ''))
  const show = (label: string, st: string, max = 15) => {
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

function notepath(root: string, args: string[]) {
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

function isDirty(dirty: Set<string>, p: string, type: PathType): boolean {
  if (type === 'file') return dirty.has(p)
  if (p === '') return dirty.size > 0
  return [...dirty].some((d) => d.startsWith(p + '/'))
}

function stamp(root: string, args: string[]) {
  const config = requireConfig(root)
  const scanResult = scan(root, config)
  const notes = loadNotes(root)
  const anchor = headCommitFull(root)
  const dirty = dirtyPaths(root)
  let targets: string[]
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

function migrate(root: string, args: string[]) {
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
    const note = notes.get(e.movedFrom!)
    if (!note) continue
    const dest = moveNoteFile(root, note, e.path, e.type)
    const headed = fs.readFileSync(dest, 'utf8')
      .replace(new RegExp(`^# ${escapeRe(e.movedFrom!)}$`, 'm'), `# ${e.path}`)
    fs.writeFileSync(dest, headed)
    if (e.similarity === 100) {
      const found = hashFor(scanResult, e.path)!
      stampNote(dest, found.hash, { anchor, dirty: isDirty(dirty, e.path, e.type) })
    }
  }
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
  pruneEmptyDirs(notesRoot(root))
  const exact = moves.filter((e) => e.similarity === 100).length
  console.log(`\nmigrated ${moves.length} note(s): ${exact} re-stamped (identical), ` +
    `${moves.length - exact} left outdated for revision` +
    (refFixes ? `; rewrote old-path references in ${refFixes} note(s)` : ''))
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function pruneEmptyDirs(dir: string) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) pruneEmptyDirs(path.join(dir, entry.name))
  }
  if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir)
}

function check(root: string, args: string[]) {
  requireConfig(root)
  const result = computeCheck(root)
  const { summary } = result
  if (args.includes('--json')) {
    const pick = <K extends CheckFinding['kind']>(k: K) =>
      result.findings.filter((f): f is Extract<typeof f, { kind: K }> => f.kind === k)
    console.log(JSON.stringify({
      summary,
      parseFailures: pick('parse'),
      rotMarkers: pick('rot'),
      missingSources: pick('missing-source'),
    }, null, 2))
  } else {
    if (!summary.total) {
      console.log('check: clean — no anchor issues')
    } else {
      console.log(`check: ${summary.total} finding(s) · ${summary.parseFailures} parse · ` +
        `${summary.rotMarkers} rot · ${summary.missingSources} missing source`)
      const rel = (f: string) => path.relative(root, f) || f
      const show = (label: string, list: typeof result.findings, max = 20) => {
        if (!list.length) return
        console.log(`\n${label}:`)
        for (const f of list.slice(0, max)) {
          if (f.kind === 'parse') {
            console.log(`  ${rel(f.noteFile)}:${f.line}  ${f.anchor}`)
          } else if (f.kind === 'rot') {
            console.log(`  ${rel(f.noteFile)}:${f.line}  marker=${f.marker}  ${f.anchor}`)
          } else {
            console.log(`  ${f.note || '(root)'}  (${rel(f.noteFile)})`)
          }
        }
        if (list.length > max) console.log(`  … and ${list.length - max} more (use --json for the full list)`)
      }
      show('解析失败', result.findings.filter((f) => f.kind === 'parse'))
      show('标记失效', result.findings.filter((f) => f.kind === 'rot'))
      show('源文件缺失', result.findings.filter((f) => f.kind === 'missing-source'))
    }
  }
  if (summary.total) process.exitCode = 1
}

function build(root: string, args: string[]) {
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
    basePoints: config.basePoints ?? [],
  })
  const target = writeAtlas(root, outFile, html)
  const sum = summarize(status)
  console.log(`wrote ${target}`)
  console.log(`${sum.total} paths · ${sum.fresh} fresh · ${sum.outdated} outdated · ${sum.missing} missing`)
}

main()