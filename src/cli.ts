#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import {
  repoRoot, headCommit, headCommitFull, dirtyPaths, atlasDir, loadConfig, scan, hashFor,
  DEFAULT_EXCLUDE, DATA_FORMAT,
} from './scan.js'
import { noteFileFor, loadNotes, stampNote, moveNoteFile, notesRoot } from './notes.js'
import { loadConceptPages, sourcesHashFor, stampConceptPage, conceptFileFor } from './conceptPages.js'
import { loadArtifacts } from './artifacts.js'
import { importLegacyAudit, loadAuditPortfolios } from './audits.js'
import {
  buildAuditLocalizationInput,
  canonicalAuditLocalizationJson,
  loadConfiguredAuditLocalizations,
} from './audit-localizations.js'
import { loadReviewCoverage } from './review-coverage.js'
import { computeStatus, summarize, summarizeConcepts } from './status.js'
import { buildHtml, writeAtlas } from './build.js'
import { serve } from './serve.js'
import { buildImportGraph } from './deps.js'
import { loadGlossaryRaw, parseGlossary } from './glossary.js'
import { computeCheck, type CheckFinding } from './check.js'
import { concepts } from './concepts.js'
import { assertCanonicalReadabilityOutput, assertReadabilityAuditOwnership, assertReadabilityReportOutput, computeReadability, formatReadabilitySummary, isSupportedReadabilityReport, readReadabilityReport, writeCanonicalReadabilityReport, writeReadabilityArtifacts, writeReadabilityAuditLedger, writeReadabilityReport, diffReadabilityReports } from './readability.js'
import { stampAudits } from './audits.js'
import type { AtlasConfig, AtlasLocale, PathType, ReviewCoveragePortfolio } from './types.js'

const USAGE = `repo-atlas — incremental codebase atlas with staleness tracking

usage: repo-atlas <command> [args]

  init                     create .atlas/ in the current git repo
  status [--json]          compare notes ledger against the working tree
                           (reports moved paths and broken note references too)
  notepath <path>          print the note file location for a repo path
  stamp [paths...|--all]   stamp note(s) with the current git hash + HEAD anchor;
                           concept pages too: stamp .atlas/concepts/<slug>.md
                           (or concepts/<slug>) recomputes their sources_hash
  audit-stamp [names...]   (re)stamp audit ledgers in .atlas/audits/*.json with
                           per-file git hashes, so status tracks per-file drift
  audit-import <files...>  import legacy scans[] ledgers into atlas-audit-v1;
                           scan-time hashes are preserved (safe on stale audits)
  audit-localization-input --locale <en|ja|zh|ko> [--json]
                           emit digest-bound canonical audit prose for translation
  audit-localization-check [--json]
                           require every configured audit content locale to be current
  migrate [--apply]        relocate notes whose targets moved (dry-run by default);
                           also rewrites references to the old paths in note prose
  build [-o <file>]        generate the self-contained HTML atlas (default .atlas/atlas.html)
  check [--json]           validate code: anchors — links and ![embeds] (parse + marker rot)
  concepts [--min N] [--json]
                           find cross-cutting concepts (terms bolded across many
                           notes) + glossary gaps: candidates for one canonical
                           home note + a glossary essence (no-LLM, default min 4)
  readability [--json] [--out <file>] [--top N] [--exclude <glob>]... [--artifacts]
                           mechanical code-readability features per file/function
                           (line length, nesting, naming style, comments, entropy,
                           duplication, barrel) + repo-relative outliers — no LLM,
                           works without .atlas/ too (design: docs/readability-audit.md);
                           --artifacts writes per-file/dir cards to .atlas/artifacts/
  serve [-p <port>] [--host [addr]]
                           dev server with auto-reload (default 127.0.0.1:4400;
                           --host with no addr binds 0.0.0.0 for LAN access)

Notes live in .atlas/notes/ — one markdown file per described path:
  directory apps/daemon   -> .atlas/notes/apps/daemon/__dir__.md
  file      apps/x.ts     -> .atlas/notes/apps/x.ts.md
Frontmatter (hash, anchor, dirty, stamped) is managed by 'stamp'; you write the body.

Concept pages live in .atlas/concepts/<slug>.md — explainers anchored to a SET
of repo paths (frontmatter: title, audience, sources, sources_hash, anchor,
stamped). 'status' reports them fresh / outdated / broken-source.

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
    case 'concepts': return concepts(root!, args)
    case 'readability': return readability(root!, args)
    case 'audit-stamp': return auditStamp(root!, args)
    case 'audit-import': return auditImport(root!, args)
    case 'audit-localization-input': return auditLocalizationInput(root!, args)
    case 'audit-localization-check': return auditLocalizationCheck(root!, args)
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

function formatCoverageText(coverage: ReviewCoveragePortfolio): string {
  const { state, report, errors, drift } = coverage
  if (state === 'missing') {
    return 'coverage: missing — no review coverage report (coverage unknown; not zero)'
  }
  if (state === 'invalid') {
    const n = errors.length
    const head = errors[0]?.message
    return `coverage: invalid — ${n} error(s)` + (head ? ` · ${head}` : '')
  }
  if (state === 'stale') {
    const bits = [
      drift.added.length ? `${drift.added.length} added` : null,
      drift.removed.length ? `${drift.removed.length} removed` : null,
      drift.changed.length ? `${drift.changed.length} changed` : null,
    ].filter(Boolean).join(' · ')
    return `coverage: stale — inventory drifted` + (bits ? ` (${bits})` : '') +
      '; re-run coverage producer before trusting verdict'
  }
  // state === 'current'
  const summary = report?.summary
  const securityGaps = summary
    ? summary.securityMissing + summary.securityStale + summary.securityInvalid
    : 0
  const testGaps = summary
    ? summary.testMissing + summary.testStale + summary.testInvalid
    : 0
  const policyGaps = summary
    ? summary.unclassified + summary.conflicted + summary.invalidLedgers
    : 0
  const gapLine = summary
    ? `security gaps ${securityGaps}/${summary.securityRequired}` +
      ` · tests gaps ${testGaps}/${summary.testRequired}` +
      ` · policy gaps ${policyGaps}`
    : 'gap counts unavailable'
  if (report?.verdict === 'incomplete') {
    return `coverage: current incomplete — ${gapLine}`
  }
  if (report?.verdict === 'complete') {
    return `coverage: current complete — ${gapLine}` +
      (securityGaps + testGaps === 0 ? ' · no coverage gaps recorded' : '')
  }
  // invalid verdict should not appear under current, but fail closed in text
  return `coverage: current ${report?.verdict ?? 'unknown'} — ${gapLine}`
}

function status(root: string, args: string[]) {
  const config = requireConfig(root)
  const result = computeStatus(root, scan(root, config), { deltas: true })
  // Reuse already-computed audit statuses — do not re-scan ledgers for portfolios.
  const portfolios = loadAuditPortfolios(root, result.audits)
  const coverage = loadReviewCoverage(root, portfolios)
  const sum = summarize(result)
  const conceptSum = summarizeConcepts(result)
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
      concepts: {
        summary: conceptSum,
        pages: result.concepts.map(({ slug, title, audience, status, sources, brokenSources, stamped, file }) =>
          ({ slug, title, audience, status, sources, brokenSources, stamped, file })),
      },
      audits: result.audits.map(({ name, status, scannedAt, fileCount, findingCount, missingFiles, changedFiles, failedFiles, findingsWithDrift, detailAvailable, invalidReason, file }) =>
        ({ name, status, scannedAt, fileCount, findingCount, missingFiles, changedFiles, failedFiles, findingsWithDrift, detailAvailable, invalidReason, file })),
      readability: result.readability,
      coverage: {
        state: coverage.state,
        verdict: coverage.report?.verdict ?? null,
        summary: coverage.report?.summary ?? null,
        drift: coverage.drift,
        errors: coverage.errors,
      },
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
  if (conceptSum.total) {
    console.log(`\nconcepts: ${conceptSum.total} page(s) · ${conceptSum.fresh} fresh · ` +
      `${conceptSum.outdated} outdated · ${conceptSum.brokenSource} broken-source`)
    for (const c of result.concepts) {
      if (c.status === 'fresh') continue
      const detail = c.status === 'broken-source'
        ? `source(s) gone: ${c.brokenSources.join(', ')}`
        : 'a source changed since stamped'
      console.log(`  C ${c.slug} — ${c.title} (${detail})`)
    }
  }
  if (result.audits.length) {
    const st = result.audits.filter((a) => a.status === 'stale').length
    console.log(`\naudits: ${result.audits.length} ledger(s) · ${result.audits.length - st} fresh · ${st} stale`)
    for (const a of result.audits) {
      if (a.status === 'fresh' && !a.findingsWithDrift) continue
      if (a.invalidReason) {
        console.log(`  A ${a.name} — invalid ledger: ${a.invalidReason}`)
        continue
      }
      const detail = [
        a.changedFiles.length ? `${a.changedFiles.length} changed` : null,
        a.missingFiles.length ? `${a.missingFiles.length} gone` : null,
        a.failedFiles.length ? `${a.failedFiles.length} unreadable` : null,
        a.findingsWithDrift === null
          ? `${a.findingCount} findings: drift detail unavailable until audit-stamp`
          : `${a.findingsWithDrift}/${a.findingCount} findings drifted`,
      ].filter(Boolean).join(' · ')
      console.log(`  A ${a.name} — ${detail}`)
    }
  }
  console.log(`\n${formatCoverageText(coverage)}`)
  if (result.readability) {
    const readability = result.readability
    const latest = readability.latestTrend
    console.log(`\nreadability: ${readability.trackedFiles} tracked · ${readability.changedFiles.length} changed · ${readability.missingFiles.length} gone · ${readability.failedFiles.length} unreadable` +
      (latest ? ` · last run ${latest.worsenedCount} worsened / ${latest.improvedCount} improved / ${latest.addedFiles.length} added / ${latest.removedFiles.length} removed` : ''))
    for (const file of readability.changedFiles.slice(0, 10)) console.log(`  R ${file} — changed since readability scan`)
    for (const file of readability.missingFiles.slice(0, 10)) console.log(`  R ${file} — gone since readability scan`)
    for (const file of readability.failedFiles.slice(0, 10)) console.log(`  R ${file} — could not hash current bytes`)
    if (readability.changedFiles.length > 10) console.log(`  … and ${readability.changedFiles.length - 10} more changed (use --json for the full list)`)
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
  const conceptPages = new Map(loadConceptPages(root).map((p) => [p.slug, p]))
  const anchor = headCommitFull(root)
  const dirty = dirtyPaths(root)

  // A target names a concept page via its ledger file (.atlas/concepts/<slug>.md)
  // or the concepts/<slug> shorthand — the shorthand only when it can't be a
  // real repo path (a repo may well contain a concepts/ directory of its own).
  const conceptSlugFor = (a: string): string | null => {
    const file = /^\.atlas\/concepts\/(.+?)\.md$/.exec(a)
    if (file) return file[1]
    const short = /^concepts\/(.+)$/.exec(a)
    if (short && conceptPages.has(short[1]) && !notes.has(a) && !hashFor(scanResult, a)) return short[1]
    return null
  }

  const all = args.includes('--all') || args.length === 0
  const targets: string[] = []
  const conceptTargets: string[] = []
  if (all) {
    targets.push(...notes.keys())
    conceptTargets.push(...conceptPages.keys())
  } else {
    for (const a of args) {
      const slug = conceptSlugFor(a)
      if (slug !== null) conceptTargets.push(slug)
      else targets.push(a === '.' ? '' : a.replace(/\/+$/, ''))
    }
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

  let stampedConcepts = 0
  for (const slug of conceptTargets) {
    const page = conceptPages.get(slug)
    if (!page) {
      console.error(`no concept page: write ${conceptFileFor(root, slug)} first`)
      process.exitCode = 1
      continue
    }
    const { hash, broken } = sourcesHashFor(scanResult, page.sources)
    if (hash === null) {
      // like an orphan note under --all this is only a warning; an explicit
      // target that can't be stamped is an error
      console.error(`skipping concept ${slug}: source(s) not in scan: ${broken.join(', ')}`)
      if (!all) process.exitCode = 1
      continue
    }
    if (page.sourcesHash === hash && page.anchor) continue
    stampConceptPage(page, hash, anchor)
    stampedConcepts++
  }

  console.log(`stamped ${stamped} note(s), ${targets.length - stamped} already current or skipped`)
  if (conceptTargets.length) {
    console.log(`stamped ${stampedConcepts} concept page(s), ` +
      `${conceptTargets.length - stampedConcepts} already current or skipped`)
  }
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

function auditStamp(root: string, args: string[]) {
  const names = args.filter((a) => !a.startsWith('--'))
  const { stamped, skipped, notFound } = stampAudits(root, scan(root, requireConfig(root)), names.length ? names : undefined)
  for (const s of stamped) console.log(`stamped: ${s}`)
  for (const s of skipped) console.error(`refused: ${s}`)
  for (const name of notFound) console.error(`refused: ${name}: audit ledger not found`)
  if (!stamped.length) console.log('no ledgers to stamp (check .atlas/audits/*.json)')
  if (skipped.length || notFound.length) process.exitCode = 1
}

function auditImport(root: string, args: string[]) {
  const sources = args.filter((arg) => !arg.startsWith('--'))
  if (!sources.length) throw new Error('usage: repo-atlas audit-import <legacy-ledger.json>...')
  for (const source of sources) {
    const imported = importLegacyAudit(root, source)
    console.log(`imported: ${imported.name} · ${imported.fileCount} files · ${imported.findingCount} finding(s) → ${imported.file}`)
  }
}

function readability(root: string, args: string[]) {
  const config = loadConfig(root) ?? {}
  const json = args.includes('--json')
  const outIdx = args.indexOf('--out')
  if (outIdx >= 0 && (!args[outIdx + 1] || args[outIdx + 1].startsWith('--'))) throw new Error('--out requires a file path')
  const target = outIdx >= 0 ? path.resolve(args[outIdx + 1]) : null
  const canonicalTarget = target !== null && target === path.resolve(atlasDir(root), 'readability.json')
  if (canonicalTarget) {
    assertCanonicalReadabilityOutput(root)
    assertReadabilityAuditOwnership(root)
  } else if (target !== null) assertReadabilityReportOutput(root, target)
  const topIdx = args.indexOf('--top')
  const top = topIdx >= 0 ? Number(args[topIdx + 1]) : 10
  if (!Number.isSafeInteger(top) || top <= 0) throw new Error('--top requires a positive integer')
  const extraExcludes: string[] = []
  for (let i = 0; i < args.length; i++) {
    if (args[i] !== '--exclude') continue
    if (!args[i + 1] || args[i + 1].startsWith('--')) throw new Error('--exclude requires a pattern')
    extraExcludes.push(args[i + 1])
  }
  const report = computeReadability(root, { exclude: [...(config.exclude ?? []), ...extraExcludes] }, top)
  const log = json ? console.error : console.log
  if (target !== null) {
    // trend vs the previous report at the same path (per-file git hash comparison)
    if (fs.existsSync(target)) {
      let prev: unknown
      try {
        prev = readReadabilityReport(root, target)
      } catch {
        throw new Error(`refusing to overwrite unreadable readability report: ${target}`)
      }
      if (!isSupportedReadabilityReport(prev)) throw new Error(`refusing to overwrite unsupported readability report: ${target}`)
      const trend = diffReadabilityReports(prev, report, top)
      report.trend = { comparedTo: prev.generatedAt ?? null, ...trend }
      if (trend.changedFiles || trend.addedFiles.length || trend.removedFiles.length) {
        log(`trend vs ${prev.generatedAt}: ${trend.changedFiles} changed · ${trend.addedFiles.length} added · ${trend.removedFiles.length} removed · ${trend.improvedCount} improved · ${trend.worsenedCount} worsened (composite, |Δ|>=1)`)
        for (const w of trend.worsened.slice(0, 5)) log(`  ↓ ${w.path}  ${w.before.toFixed(1)} → ${w.after.toFixed(1)}`)
        for (const im of trend.improved.slice(0, 5)) log(`  ↑ ${im.path}  ${im.before.toFixed(1)} → ${im.after.toFixed(1)}`)
      }
    }
    if (canonicalTarget) writeCanonicalReadabilityReport(root, report)
    else writeReadabilityReport(root, target, report)
    if (canonicalTarget) writeReadabilityAuditLedger(root, report)
    log(`wrote ${target}`)
  }
  if (args.includes('--artifacts')) {
    const n = writeReadabilityArtifacts(root, report)
    log(n ? `wrote ${n} readability artifact(s) under .atlas/artifacts/`
      : 'no .atlas/ (or no changes) — artifacts skipped')
  }
  if (json) console.log(JSON.stringify(report, null, 2))
  else console.log(formatReadabilitySummary(report, top))
}

function build(root: string, args: string[]) {
  const config = requireConfig(root)
  const oIdx = args.indexOf('-o')
  const outFile = oIdx >= 0 ? args[oIdx + 1] : (config.output ?? '.atlas/atlas.html')
  const scanResult = scan(root, config)
  const status = computeStatus(root, scanResult, { readability: false })
  const portfolios = loadAuditPortfolios(root, status.audits)
  const reviewCoverage = loadReviewCoverage(root, portfolios)
  const localizations = loadConfiguredAuditLocalizations(
    root,
    config,
    reviewCoverage,
    portfolios,
  )
  const html = buildHtml({
    repoName: path.basename(root),
    commit: headCommit(root),
    status,
    graph: buildImportGraph(root, scanResult),
    glossary: parseGlossary(loadGlossaryRaw(root)),
    basePoints: config.basePoints ?? [],
    artifacts: loadArtifacts(root),
    audits: portfolios.security,
    testAudits: portfolios.tests,
    reviewCoverage,
    defaultLocale: config.defaultLocale ?? 'en',
    auditSourceLocale: localizations.sourceLocale,
    auditLocalizations: localizations.portfolios,
  })
  const target = writeAtlas(root, outFile, html)
  const sum = summarize(status)
  console.log(`wrote ${target}`)
  console.log(`${sum.total} paths · ${sum.fresh} fresh · ${sum.outdated} outdated · ${sum.missing} missing`)
}

const AUDIT_LOCALES = new Set<AtlasLocale>(['en', 'ja', 'zh', 'ko'])

function auditLocalizationContext(root: string, config: AtlasConfig) {
  const scanResult = scan(root, config)
  const status = computeStatus(root, scanResult, { readability: false })
  const portfolios = loadAuditPortfolios(root, status.audits)
  const reviewCoverage = loadReviewCoverage(root, portfolios)
  return { portfolios, reviewCoverage }
}

function auditLocalizationInput(root: string, args: string[]) {
  const localeIndex = args.indexOf('--locale')
  const localeValue = localeIndex >= 0 ? args[localeIndex + 1] : undefined
  const expectedLength = args.includes('--json') ? 3 : 2
  if (localeIndex < 0 || localeIndex + 1 >= args.length || args.length !== expectedLength ||
      !localeValue || !AUDIT_LOCALES.has(localeValue as AtlasLocale)) {
    throw new Error('usage: repo-atlas audit-localization-input --locale <en|ja|zh|ko> [--json]')
  }
  const locale = localeValue as AtlasLocale
  const config = requireConfig(root)
  const sourceLocale = config.auditSourceLocale ?? 'en'
  if (locale === sourceLocale) {
    throw new Error('audit localization target locale must differ from the canonical source locale')
  }
  const { portfolios, reviewCoverage } = auditLocalizationContext(root, config)
  const input = buildAuditLocalizationInput(
    sourceLocale,
    locale,
    reviewCoverage,
    portfolios,
  )
  process.stdout.write(canonicalAuditLocalizationJson(input))
}

function auditLocalizationCheck(root: string, args: string[]) {
  if (args.some((arg) => arg !== '--json') || args.filter((arg) => arg === '--json').length > 1) {
    throw new Error('usage: repo-atlas audit-localization-check [--json]')
  }
  const config = requireConfig(root)
  const { portfolios, reviewCoverage } = auditLocalizationContext(root, config)
  const loaded = loadConfiguredAuditLocalizations(
    root,
    config,
    reviewCoverage,
    portfolios,
  )
  if (args.includes('--json')) {
    process.stdout.write(canonicalAuditLocalizationJson({
      sourceLocale: loaded.sourceLocale,
      locales: loaded.portfolios,
    }))
  } else if (Object.keys(loaded.portfolios).length === 0) {
    console.log('audit localizations: no required content locales configured')
  } else {
    for (const [locale, portfolio] of Object.entries(loaded.portfolios)) {
      console.log(`audit localization ${locale}: ${portfolio?.state ?? 'missing'}`)
      for (const error of portfolio?.errors ?? []) console.log(`  ${error.code}: ${error.message}`)
    }
  }
  if (Object.values(loaded.portfolios).some((portfolio) => portfolio?.state !== 'complete')) {
    process.exitCode = 1
  }
}

main()
