#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import {
  repoRoot, headCommit, atlasDir, loadConfig, scan, hashFor, DEFAULT_EXCLUDE, DATA_FORMAT,
} from './scan.js'
import { noteFileFor, loadNotes, stampNote, notesRoot } from './notes.js'
import { computeStatus, summarize } from './status.js'
import { buildHtml, writeAtlas } from './build.js'
import { serve } from './serve.js'

const USAGE = `repo-atlas — incremental codebase atlas with staleness tracking

usage: repo-atlas <command> [args]

  init                     create .atlas/ in the current git repo
  status [--json]          compare notes ledger against the working tree
  notepath <path>          print the note file location for a repo path
  stamp [paths...|--all]   stamp note(s) with the current git hash
  build [-o <file>]        generate the self-contained HTML atlas (default .atlas/atlas.html)
  serve [-p <port>] [--host [addr]]
                           dev server with auto-reload (default 127.0.0.1:4400;
                           --host with no addr binds 0.0.0.0 for LAN access)

Notes live in .atlas/notes/ — one markdown file per described path:
  directory apps/daemon   -> .atlas/notes/apps/daemon/__dir__.md
  file      apps/x.ts     -> .atlas/notes/apps/x.ts.md
Frontmatter (hash, stamped) is managed by 'stamp'; you write the body.

Agent loop: status --json  ->  read code, write note bodies  ->  stamp  ->  build`

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
  const result = computeStatus(root, scan(root, config))
  const sum = summarize(result)
  if (args.includes('--json')) {
    const pick = (st) => result.entries.filter((e) => e.status === st).map(({ path, type }) => ({ path, type }))
    console.log(JSON.stringify({
      summary: sum,
      missing: pick('missing'),
      outdated: result.entries.filter((e) => e.status === 'outdated')
        .map(({ path, type, stamped, noteFile }) => ({ path, type, stamped, noteFile })),
      orphans: result.orphans,
    }, null, 2))
    return
  }
  console.log(`${sum.total} paths · ${sum.fresh} fresh · ${sum.outdated} outdated · ${sum.missing} missing` +
    (sum.orphans ? ` · ${sum.orphans} orphan notes` : ''))
  const show = (label, st, max = 15) => {
    const list = result.entries.filter((e) => e.status === st)
    if (!list.length) return
    console.log(`\n${label}:`)
    for (const e of list.slice(0, max)) console.log(`  ${e.type === 'dir' ? 'D' : 'F'} ${e.path || '(root)'}`)
    if (list.length > max) console.log(`  … and ${list.length - max} more (use --json for the full list)`)
  }
  show('outdated', 'outdated')
  show('missing', 'missing')
  for (const o of result.orphans) console.log(`\norphan note (target gone): ${o.noteFile}`)
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

function stamp(root, args) {
  const config = requireConfig(root)
  const scanResult = scan(root, config)
  const notes = loadNotes(root)
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
    if (note.hash === current.hash) continue
    stampNote(note.file, current.hash)
    stamped++
  }
  console.log(`stamped ${stamped} note(s), ${targets.length - stamped} already current or skipped`)
}

function build(root, args) {
  const config = requireConfig(root)
  const oIdx = args.indexOf('-o')
  const outFile = oIdx >= 0 ? args[oIdx + 1] : (config.output ?? '.atlas/atlas.html')
  const status = computeStatus(root, scan(root, config))
  const html = buildHtml({
    repoName: path.basename(root),
    commit: headCommit(root),
    status,
  })
  const target = writeAtlas(root, outFile, html)
  const sum = summarize(status)
  console.log(`wrote ${target}`)
  console.log(`${sum.total} paths · ${sum.fresh} fresh · ${sum.outdated} outdated · ${sum.missing} missing`)
}

main()
