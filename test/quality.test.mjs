import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { auditStatusEntries } from '../dist/audits.js'
import {
  computeQuality, failingFindings, formatQualitySummary, ingestReport, parseLayers,
  writeQualityArtifacts, writeQualityAuditLedger, writeQualityReport,
} from '../dist/quality.js'
import { scan } from '../dist/scan.js'
import { cleanup, commitAll, makeRepo, write } from './helpers.mjs'

/**
 * The mechanical half of the design axis. Every detector here must be
 * PRECISE enough to gate CI, so each test pins both the true positive and the
 * near-miss that must NOT fire.
 */

const CLI = new URL('../dist/cli.js', import.meta.url).pathname

function detectorFindings(report, detector) {
  return report.findings.filter((finding) => finding.detector === detector)
}

test('import cycles are found at module and package level', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', "import { b } from './b.js'\nexport const a = () => b\n")
    write(root, 'src/b.ts', "import { a } from './a.js'\nexport const b = () => a\n")
    write(root, 'src/lonely.ts', 'export const lonely = 1\n')
    commitAll(root)
    const report = computeQuality(root, {})
    const cycles = detectorFindings(report, 'import-cycle')
    assert.equal(cycles.length, 1)
    assert.deepEqual(cycles[0].locations, ['src/a.ts', 'src/b.ts'])
    assert.equal(cycles[0].category, 'layering-violation')
    assert.match(cycles[0].evidence, /module import cycle/)
  } finally { cleanup(root) }
})

test('a cycle that exists only in commented-out imports is not reported', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', "import { b } from './b.js'\nexport const a = () => b\n")
    write(root, 'src/b.ts', "// import { a } from './a.js'\nexport const b = 1\n")
    commitAll(root)
    const report = computeQuality(root, {})
    assert.deepEqual(detectorFindings(report, 'import-cycle'), [])
  } finally { cleanup(root) }
})

test('declared layers turn an upward import into a finding', () => {
  const root = makeRepo()
  try {
    write(root, 'app/main.ts', "import { core } from '../core/index.js'\nexport const main = core\n")
    write(root, 'core/index.ts', "import { main } from '../app/main.js'\nexport const core = main\n")
    write(root, 'core/pure.ts', 'export const pure = 1\n')
    commitAll(root)
    const layers = parseLayers([
      { name: 'app', paths: ['app/**'] },
      { name: 'core', paths: ['core/**'] },
    ])
    const report = computeQuality(root, {}, { layers })
    const violations = detectorFindings(report, 'layer-violation')
    assert.equal(violations.length, 1)
    assert.equal(violations[0].severity, 'high')
    assert.match(violations[0].title, /core imports upward into app/)
    assert.deepEqual(violations[0].locations, ['core/index.ts'])

    // downward-only imports in the same tree stay silent
    fs.writeFileSync(path.join(root, 'core/index.ts'), 'export const core = 1\n')
    const clean = computeQuality(root, {}, { layers })
    assert.deepEqual(detectorFindings(clean, 'layer-violation'), [])
    assert.equal(clean.detectors['layer-violation'].note, undefined)
  } finally { cleanup(root) }
})

test('without declared layers the layer detector says so instead of passing silently', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    const report = computeQuality(root, {})
    assert.match(report.detectors['layer-violation'].note ?? '', /no layers declared/)
  } finally { cleanup(root) }
})

test('one declaration spelling absence two ways is reported, one convention is not', () => {
  const root = makeRepo()
  try {
    write(root, 'src/mixed.ts', [
      'export interface Mixed {',
      '  id: string',
      '  stamped: string | null',
      '  anchor: string | null',
      '  snoozedUntil?: string',
      '}',
      '',
      'export interface Consistent {',
      '  a: string | null',
      '  b: number | null',
      '}',
      '',
      'export interface AllOptional {',
      '  a?: string',
      '  b?: number',
      '}',
      '',
      'export interface Nested {',
      '  a?: string',
      '  inner: { deep: string | null }',
      '}',
      '',
    ].join('\n'))
    commitAll(root)
    const report = computeQuality(root, {})
    const mixed = detectorFindings(report, 'absence-mixing')
    assert.deepEqual(mixed.map((finding) => finding.title), ['Mixed spells absence two ways'])
    assert.equal(mixed[0].category, 'absence-semantics')
    assert.match(mixed[0].evidence, /1 member\(s\) use/)
  } finally { cleanup(root) }
})

test('type escapes are counted per file above a cluster threshold', () => {
  const root = makeRepo()
  try {
    write(root, 'src/one.ts', 'export const one = JSON.parse("{}") as any\n')
    write(root, 'src/many.ts', [
      'export const a = JSON.parse("{}") as any',
      'export const b = a as unknown as string',
      'const c: any = 1',
      '// @ts-expect-error deliberate',
      'export const d: Record<string, unknown> = {}',
      '',
    ].join('\n'))
    write(root, 'src/strings.ts', 'export const text = "this mentions as any inside a string"\n')
    commitAll(root)
    const report = computeQuality(root, {})
    const escapes = detectorFindings(report, 'type-escape')
    assert.deepEqual(escapes.map((finding) => finding.locations[0].split(':')[0]), ['src/many.ts'])
    assert.match(escapes[0].evidence, /@ts-ignore \/ @ts-expect-error/)
  } finally { cleanup(root) }
})

test('a trailing positional boolean is a trap, a named object property is not', () => {
  const root = makeRepo()
  try {
    write(root, 'src/api.ts', [
      'export function render(node: string, compact?: boolean) { return [node, compact] }',
      'export function Panel({ node, compact }: { node: string; compact?: boolean }) { return [node, compact] }',
      'export function Card({ node, compact = false }) { return [node, compact] }',
      'export function only(compact?: boolean) { return compact }',
      '',
    ].join('\n'))
    commitAll(root)
    const report = computeQuality(root, {})
    const traps = detectorFindings(report, 'boolean-trap')
    assert.equal(traps.length, 1)
    assert.match(traps[0].evidence, /render\(…, compact\?: boolean\)/)
    assert.equal(traps[0].locations.length, 1)
  } finally { cleanup(root) }
})

test('marker age comes from git blame and unknown age is declared, not assumed fresh', () => {
  const root = makeRepo()
  try {
    write(root, 'src/old.ts', '// TODO: decide this some day\nexport const old = 1\n')
    execFileSync('git', ['add', '-A'], { cwd: root })
    execFileSync('git', ['commit', '-qm', 'old', '--date', '2020-01-02T03:04:05'], {
      cwd: root,
      env: { ...process.env, GIT_COMMITTER_DATE: '2020-01-02T03:04:05' },
    })
    const aged = computeQuality(root, {}, { staleMarkerDays: 365 })
    const markers = detectorFindings(aged, 'stale-marker')
    assert.equal(markers.length, 1)
    assert.equal(markers[0].severity, 'medium')
    assert.match(markers[0].evidence, /oldest is \d+\.\dy old at line 1/)

    // a marker young enough is not a finding
    const fresh = computeQuality(root, {}, { staleMarkerDays: 365 * 100 })
    assert.deepEqual(detectorFindings(fresh, 'stale-marker'), [])

    // an uncommitted file has no history: unknown, and the summary says so
    write(root, 'src/new.ts', '// FIXME: fresh and uncommitted\nexport const brandNew = 1\n')
    const unknown = computeQuality(root, {}, { staleMarkerDays: 0 })
    assert.equal(unknown.detectors['stale-marker'].scanned, 2)
    assert.match(unknown.detectors['stale-marker'].note ?? '', /1 file\(s\).*age unknown/)
  } finally { cleanup(root) }
})

test('generic ingest keeps only fully specified findings and counts the rest', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, 'tool.json', JSON.stringify({
      tool: 'mytool',
      findings: [
        { path: 'src/a.ts', line: 3, category: 'magic-constant', title: 'bare 86400', evidence: 'seconds in a day, inline', detector: 'numbers' },
        { path: 'src/a.ts', category: 'not-a-real-category', title: 'x', evidence: 'y' },
        { path: '../escape.ts', category: 'dead-code', title: 'x', evidence: 'y' },
        { path: 'src/a.ts', category: 'dead-code', title: '', evidence: 'y' },
      ],
    }))
    commitAll(root)
    const { findings, stat } = ingestReport(root, 'generic', path.join(root, 'tool.json'))
    assert.deepEqual(stat, { tool: 'mytool', source: 'tool.json', accepted: 1, dropped: 3 })
    assert.equal(findings[0].detector, 'mytool:numbers')
    assert.deepEqual(findings[0].locations, ['src/a.ts:3'])
  } finally { cleanup(root) }
})

test('eslint ingest maps design-bearing rules and drops style-only ones', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, 'eslint.json', JSON.stringify([
      {
        filePath: path.join(root, 'src/a.ts'),
        messages: [
          { ruleId: '@typescript-eslint/no-explicit-any', line: 2, message: 'Unexpected any' },
          { ruleId: 'semi', line: 1, message: 'Missing semicolon' },
          { ruleId: null, line: 1, message: 'parse error' },
        ],
      },
    ]))
    commitAll(root)
    const { findings, stat } = ingestReport(root, 'eslint', path.join(root, 'eslint.json'))
    assert.equal(stat.accepted, 1)
    assert.equal(stat.dropped, 2)
    assert.equal(findings[0].detector, 'eslint:@typescript-eslint/no-explicit-any')
    assert.equal(findings[0].category, 'type-escape')
  } finally { cleanup(root) }
})

test('knip ingest reports unused files and exports as dead code', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, 'knip.json', JSON.stringify({
      files: ['src/orphan.ts'],
      issues: [{ file: 'src/a.ts', exports: [{ symbol: 'unused', line: 1 }] }],
    }))
    commitAll(root)
    const { findings } = ingestReport(root, 'knip', path.join(root, 'knip.json'))
    assert.deepEqual(findings.map((finding) => finding.detector), ['knip:files', 'knip:exports'])
    assert.ok(findings.every((finding) => finding.category === 'dead-code'))
  } finally { cleanup(root) }
})

test('the report writes a thin ledger that status tracks for drift', () => {
  const root = makeRepo()
  try {
    write(root, 'src/mixed.ts', [
      'export interface Mixed {',
      '  stamped: string | null',
      '  snoozedUntil?: string',
      '}',
      '',
    ].join('\n'))
    commitAll(root)
    const report = computeQuality(root, {})
    writeQualityReport(root, report)
    const ledger = writeQualityAuditLedger(root, report)
    assert.ok(ledger)

    const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(status.name, 'quality')
    assert.equal(status.invalidReason, null)
    assert.equal(status.status, 'fresh')

    write(root, 'src/mixed.ts', 'export interface Mixed { stamped: string | null }\n')
    const [drifted] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(drifted.status, 'stale')
    assert.deepEqual(drifted.changedFiles, ['src/mixed.ts'])
  } finally { cleanup(root) }
})

test('a foreign ledger at the quality slug is never overwritten', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, '.atlas/audits/quality.json', JSON.stringify({
      formatVersion: 2, format: 'atlas-audit-v2', domain: 'security', slug: 'quality',
      title: 'someone else', ruleset: 'security-v1', scanned_at: '2026-07-25',
      scope_hash: 'a'.repeat(40), files: ['src/a.ts'], findings: [],
    }))
    commitAll(root)
    const report = computeQuality(root, {})
    assert.throws(() => writeQualityAuditLedger(root, report), /refusing to overwrite unrelated audit ledger/)
  } finally { cleanup(root) }
})

test('artifacts land on the pages the findings touch and stale cards are pruned', () => {
  const root = makeRepo()
  try {
    write(root, 'src/mixed.ts', [
      'export interface Mixed {',
      '  stamped: string | null',
      '  snoozedUntil?: string',
      '}',
      '',
    ].join('\n'))
    commitAll(root)
    const written = writeQualityArtifacts(root, computeQuality(root, {}))
    assert.equal(written, 1)
    const card = path.join(root, '.atlas/artifacts/src/mixed.ts/quality.md')
    assert.match(fs.readFileSync(card, 'utf8'), /absence-mixing/)

    fs.writeFileSync(path.join(root, 'src/mixed.ts'), 'export interface Mixed { stamped: string | null }\n')
    writeQualityArtifacts(root, computeQuality(root, {}))
    assert.equal(fs.existsSync(card), false)
  } finally { cleanup(root) }
})

test('--fail-on gates on detector, category, or severity and otherwise exits clean', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', "import { b } from './b.js'\nexport const a = () => b\n")
    write(root, 'src/b.ts', "import { a } from './a.js'\nexport const b = () => a\n")
    commitAll(root)
    const report = computeQuality(root, {})
    assert.equal(failingFindings(report, ['import-cycle']).length, 1)
    assert.equal(failingFindings(report, ['layering-violation']).length, 1)
    assert.equal(failingFindings(report, ['stale-marker']).length, 0)
    assert.equal(failingFindings(report, []).length, 0)

    const failed = execFileSync('node', [CLI, 'quality', '--fail-on', 'import-cycle'], {
      cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    })
    assert.fail(`expected a nonzero exit, got:\n${failed}`)
  } catch (error) {
    if (error?.status !== 1) throw error
    assert.match(String(error.stderr), /match --fail-on import-cycle/)
  } finally { cleanup(root) }
})

test('the summary never claims a detector ran when it could not', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    const summary = formatQualitySummary(computeQuality(root, {}))
    assert.match(summary, /findings: 0 \(0 high · 0 medium · 0 low\)/)
    assert.match(summary, /layer-violation\s+0 finding\(s\).*no layers declared/)
  } finally { cleanup(root) }
})

test('layer specs are validated instead of silently ignored', () => {
  assert.deepEqual(parseLayers(undefined), [])
  assert.throws(() => parseLayers([{ name: '', paths: ['a/**'] }]), /nonempty name/)
  assert.throws(() => parseLayers([{ name: 'a', paths: [] }]), /nonempty paths array/)
  assert.throws(() => parseLayers(['app']), /must be an object/)
  assert.deepEqual(parseLayers([{ name: ' app ', paths: ['app/**'] }]), [{ name: 'app', paths: ['app/**'] }])
})
