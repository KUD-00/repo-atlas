import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { computeReadability, diffReadabilityReports, writeReadabilityArtifacts } from '../dist/readability.js'
import { hashFilePaths, scan } from '../dist/scan.js'
import { cleanup, commitAll, makeRepo, write } from './helpers.mjs'

const CLI = new URL('../dist/cli.js', import.meta.url).pathname

function duplicatedLines(count) {
  return Array.from({ length: count }, (_, i) =>
    `export const descriptiveValue${i} = computeDescriptiveValue(${i});`).join('\n') + '\n'
}

test('duplication ignores statistically tiny shingle sets', () => {
  const root = makeRepo()
  try {
    const small = duplicatedLines(10) // seven 4-line shingles
    const large = duplicatedLines(12) // nine 4-line shingles
    write(root, 'src/small-a.ts', small)
    write(root, 'src/small-b.ts', small)
    write(root, 'src/large-a.ts', large)
    write(root, 'src/large-b.ts', large)
    commitAll(root)

    const report = computeReadability(root, { exclude: [] })
    assert.equal(Number.isFinite(report.files['src/small-a.ts'].dupRatio), false)
    assert.ok(report.files['src/large-a.ts'].dupRatio > 0)
  } finally {
    cleanup(root)
  }
})

test('duplication counts repeated blocks within one sufficiently large file', () => {
  const root = makeRepo()
  try {
    const block = duplicatedLines(12)
    write(root, 'src/repeated.ts', block + block)
    commitAll(root)

    const ratio = computeReadability(root, { exclude: [] }).files['src/repeated.ts'].dupRatio
    assert.ok(ratio > 0, `expected intra-file duplication, got ${ratio}`)
  } finally {
    cleanup(root)
  }
})

test('comment coherence uses nearby identifiers rather than any identifier in the file', () => {
  const root = makeRepo()
  try {
    write(root, 'src/coherence.ts', [
      'const customerSession = createCustomerSession()',
      'consume(customerSession)',
      '',
      '',
      '',
      '',
      '',
      '// customer session is renewed by the distant declaration',
      'const unrelatedValue = 1',
      '',
    ].join('\n'))
    commitAll(root)

    const score = computeReadability(root, { exclude: [] }).files['src/coherence.ts'].commentCoherence
    assert.equal(score, 0)
  } finally {
    cleanup(root)
  }
})

test('scan and readability reject tracked files reached through a symlinked parent', () => {
  const root = makeRepo()
  const outside = fs.mkdtempSync(path.join(path.dirname(root), 'repo-atlas-scan-outside-'))
  try {
    write(root, 'src/a.ts', 'export const inside = 1\n')
    commitAll(root)
    fs.rmSync(path.join(root, 'src'), { recursive: true, force: true })
    write(outside, 'a.ts', 'export const secret = "outside"\n')
    fs.symlinkSync(outside, path.join(root, 'src'))

    const scanned = scan(root, { exclude: [] })
    assert.equal(scanned.files.has('src/a.ts'), false)
    assert.equal(computeReadability(root, { exclude: [] }).files['src/a.ts'], undefined)
    assert.deepEqual(hashFilePaths(root, ['src/a.ts'], scanned).missing, ['src/a.ts'])
  } finally {
    cleanup(root)
    fs.rmSync(outside, { recursive: true, force: true })
  }
})

test('scan hashes tracked filenames containing newlines without splitting the path', () => {
  const root = makeRepo()
  try {
    const repoPath = 'src/line\nbreak.ts'
    write(root, repoPath, 'export const answer = 1\n')
    commitAll(root)

    const scanned = scan(root, { exclude: [] })
    assert.equal(scanned.files.has(repoPath), true)
    assert.match(scanned.files.get(repoPath), /^[0-9a-f]{40}$/)
  } finally {
    cleanup(root)
  }
})

test('prototype-named extensions are treated as non-code', () => {
  const root = makeRepo()
  try {
    write(root, 'src/evil.constructor', 'not actually source code\n')
    commitAll(root)

    const report = computeReadability(root, { exclude: [] })
    assert.equal(report.files['src/evil.constructor'], undefined)
    assert.equal(report.repo.skippedNonCode, 1)
  } finally {
    cleanup(root)
  }
})

test('readability handles very high line counts below the byte cap without argument overflow', () => {
  const root = makeRepo()
  try {
    write(root, 'src/many-lines.ts', `${'\n'.repeat(150_000)}export const answer = 1\n`)
    commitAll(root)

    const report = computeReadability(root, { exclude: [] })
    assert.equal(report.files['src/many-lines.ts'].lines, 150_002)
  } finally {
    cleanup(root)
  }
})

test('status reports files changed since the committed readability snapshot', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    const report = computeReadability(root, { exclude: [] })
    write(root, '.atlas/readability.json', JSON.stringify(report, null, 2) + '\n')
    write(root, 'src/a.ts', duplicatedLines(13))

    const run = spawnSync(process.execPath, [CLI, 'status', '--json'], { cwd: root, encoding: 'utf8' })
    assert.equal(run.status, 0, run.stderr)
    const status = JSON.parse(run.stdout)
    assert.deepEqual(status.readability.changedFiles, ['src/a.ts'])
  } finally {
    cleanup(root)
  }
})

test('readability --json keeps stdout machine-readable when --out is also used', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    const out = path.join(root, '.atlas', 'readability.json')
    const run = spawnSync(process.execPath, [CLI, 'readability', '--json', '--out', out], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(run.status, 0, run.stderr)
    const parsed = JSON.parse(run.stdout)
    assert.equal(parsed.format, 'repo-atlas-readability-v1')
    assert.equal(parsed.formatVersion, 1)
    assert.equal(parsed.repo.files, 1)
    assert.equal(parsed.files['src/a.ts'].commentCoherence, null)
    assert.match(run.stderr, /wrote .*readability\.json/)
    const audit = JSON.parse(fs.readFileSync(path.join(root, '.atlas', 'audits', 'readability.json'), 'utf8'))
    assert.equal(audit.format, 'atlas-audit-v1')
    assert.equal(audit.file_count, 1)
    assert.equal(audit.hashes['src/a.ts'], parsed.files['src/a.ts'].hash)
  } finally {
    cleanup(root)
  }
})

test('readability status uses the thin audit index without parsing the full feature report', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    const generated = spawnSync(process.execPath, [CLI, 'readability', '--out', '.atlas/readability.json'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(generated.status, 0, generated.stderr)
    fs.writeFileSync(path.join(root, '.atlas/readability.json'), '{ deliberately unreadable')

    const run = spawnSync(process.execPath, [CLI, 'status', '--json'], { cwd: root, encoding: 'utf8' })
    assert.equal(run.status, 0, run.stderr)
    const status = JSON.parse(run.stdout)
    assert.equal(status.readability.trackedFiles, 1)
    assert.deepEqual(status.readability.changedFiles, [])
  } finally {
    cleanup(root)
  }
})

test('readability status rejects a truncated thin index and falls back to the full report', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    write(root, 'src/b.ts', duplicatedLines(13))
    commitAll(root)
    const generated = spawnSync(process.execPath, [CLI, 'readability', '--out', '.atlas/readability.json'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(generated.status, 0, generated.stderr)
    const indexFile = path.join(root, '.atlas/audits/readability.json')
    const index = JSON.parse(fs.readFileSync(indexFile, 'utf8'))
    index.files = ['src/a.ts']
    index.file_count = 1
    index.hashes = { 'src/a.ts': index.hashes['src/a.ts'] }
    fs.writeFileSync(indexFile, JSON.stringify(index))

    const run = spawnSync(process.execPath, [CLI, 'status', '--json'], { cwd: root, encoding: 'utf8' })
    assert.equal(run.status, 0, run.stderr)
    assert.equal(JSON.parse(run.stdout).readability.trackedFiles, 2)
  } finally {
    cleanup(root)
  }
})

test('readability status does not call an excluded but existing report file gone', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    const report = computeReadability(root, { exclude: [] })
    write(root, '.atlas/readability.json', JSON.stringify(report, null, 2) + '\n')
    write(root, '.atlas/config.json', JSON.stringify({ formatVersion: 1, exclude: ['src/a.ts'] }) + '\n')

    const run = spawnSync(process.execPath, [CLI, 'status', '--json'], { cwd: root, encoding: 'utf8' })
    assert.equal(run.status, 0, run.stderr)
    const status = JSON.parse(run.stdout)
    assert.deepEqual(status.readability.missingFiles, [])
    assert.deepEqual(status.readability.changedFiles, [])
  } finally {
    cleanup(root)
  }
})

test('readability status exposes files whose current bytes cannot be hashed', () => {
  const root = makeRepo()
  const source = path.join(root, 'src/a.ts')
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    const report = computeReadability(root, { exclude: [] })
    write(root, '.atlas/readability.json', JSON.stringify(report, null, 2) + '\n')
    write(root, '.atlas/config.json', JSON.stringify({ formatVersion: 1, exclude: ['src/a.ts'] }) + '\n')
    fs.chmodSync(source, 0o000)

    const run = spawnSync(process.execPath, [CLI, 'status', '--json'], { cwd: root, encoding: 'utf8' })
    assert.equal(run.status, 0, run.stderr)
    const status = JSON.parse(run.stdout)
    assert.deepEqual(status.readability.missingFiles, [])
    assert.deepEqual(status.readability.failedFiles, ['src/a.ts'])
  } finally {
    try { fs.chmodSync(source, 0o600) } catch {}
    cleanup(root)
  }
})

test('future readability report versions are ignored instead of interpreted as current', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    write(root, '.atlas/readability.json', JSON.stringify({
      format: 'repo-atlas-readability-v1',
      formatVersion: 2,
      generatedAt: 'future',
      files: { 'src/a.ts': { hash: 'future' } },
    }))

    const run = spawnSync(process.execPath, [CLI, 'status', '--json'], { cwd: root, encoding: 'utf8' })
    assert.equal(run.status, 0, run.stderr)
    assert.equal(JSON.parse(run.stdout).readability, null)

    const overwrite = spawnSync(process.execPath, [CLI, 'readability', '--out', '.atlas/readability.json'], { cwd: root, encoding: 'utf8' })
    assert.notEqual(overwrite.status, 0)
    assert.match(overwrite.stderr, /unsupported readability report/i)
    assert.equal(JSON.parse(fs.readFileSync(path.join(root, '.atlas/readability.json'), 'utf8')).formatVersion, 2)
  } finally {
    cleanup(root)
  }
})

test('readability trend keeps exact improvement and regression counts beyond the display cap', () => {
  const norms = {
    commentRatio: { mean: 0, sd: 1 },
    halsteadPerLine: { mean: 0, sd: 1 },
    lineLenMean: { mean: 0, sd: 1 },
    tokenEntropy: { mean: 0, sd: 1 },
  }
  const files = (commentRatio, hash) => Object.fromEntries(Array.from({ length: 12 }, (_, index) => [
    `src/file-${index}.ts`,
    { commentRatio, halsteadPerLine: 0, lineLen: { mean: 0 }, tokenEntropy: 0, hash },
  ]))
  const previous = { generatedAt: 'before', norms, files: files(2, 'before') }
  const current = { generatedAt: 'after', norms, files: files(0, 'after') }
  previous.files['src/removed.ts'] = { commentRatio: 2, halsteadPerLine: 0, lineLen: { mean: 0 }, tokenEntropy: 0, hash: 'removed' }
  current.files['src/added.ts'] = { commentRatio: 0, halsteadPerLine: 0, lineLen: { mean: 0 }, tokenEntropy: 0, hash: 'added' }

  const trend = diffReadabilityReports(previous, current, 3)
  assert.equal(trend.worsened.length, 3)
  assert.equal(trend.worsenedCount, 12)
  assert.equal(trend.improvedCount, 0)
  assert.deepEqual(trend.addedFiles, ['src/added.ts'])
  assert.deepEqual(trend.removedFiles, ['src/removed.ts'])
})

test('malformed persisted trend data cannot crash human status output', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    const report = computeReadability(root, { exclude: [] })
    report.trend = {}
    write(root, '.atlas/readability.json', JSON.stringify(report, null, 2) + '\n')

    const run = spawnSync(process.execPath, [CLI, 'status'], { cwd: root, encoding: 'utf8' })
    assert.equal(run.status, 0, run.stderr)
    assert.match(run.stdout, /readability:/)
  } finally {
    cleanup(root)
  }
})

test('canonical readability output refuses to overwrite another audit producer', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    write(root, '.atlas/audits/readability.json', JSON.stringify({
      format: 'atlas-audit-v1',
      slug: 'readability',
      ruleset: 'another-readability-tool-v1',
      files: [],
      findings: [],
    }) + '\n')
    write(root, '.atlas/readability.json', '{"sentinel":true}\n')

    const run = spawnSync(process.execPath, [CLI, 'readability', '--out', '.atlas/readability.json'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /refusing to overwrite/i)
    const stored = JSON.parse(fs.readFileSync(path.join(root, '.atlas/audits/readability.json'), 'utf8'))
    assert.equal(stored.ruleset, 'another-readability-tool-v1')
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, '.atlas/readability.json'), 'utf8')), { sentinel: true })
  } finally {
    cleanup(root)
  }
})

test('canonical readability output never follows its audit ledger symlink', () => {
  const root = makeRepo()
  const outside = fs.mkdtempSync(path.join(root, '..', 'repo-atlas-readability-outside-'))
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    const canary = path.join(outside, 'readability.json')
    const original = JSON.stringify({
      formatVersion: 1,
      format: 'atlas-audit-v1',
      slug: 'readability',
      ruleset: 'repo-atlas-readability-v1',
      files: [],
      hashes: {},
      findings: [],
    }) + '\n'
    fs.writeFileSync(canary, original)
    fs.symlinkSync(canary, path.join(root, '.atlas/audits/readability.json'))
    write(root, '.atlas/readability.json', '{"sentinel":true}\n')

    const run = spawnSync(process.execPath, [CLI, 'readability', '--out', '.atlas/readability.json'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /symlink|unsafe|regular file/i)
    assert.equal(fs.readFileSync(canary, 'utf8'), original)
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, '.atlas/readability.json'), 'utf8')), { sentinel: true })
  } finally {
    cleanup(root)
    fs.rmSync(outside, { recursive: true, force: true })
  }
})

test('canonical readability output never follows the full report symlink', () => {
  const root = makeRepo()
  const outside = fs.mkdtempSync(path.join(root, '..', 'repo-atlas-report-outside-'))
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    const canary = path.join(outside, 'readability.json')
    fs.writeFileSync(canary, '{"outside":true}\n')
    fs.symlinkSync(canary, path.join(root, '.atlas/readability.json'))

    const run = spawnSync(process.execPath, [CLI, 'readability', '--out', '.atlas/readability.json'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /symlink|unsafe|regular file/i)
    assert.deepEqual(JSON.parse(fs.readFileSync(canary, 'utf8')), { outside: true })
  } finally {
    cleanup(root)
    fs.rmSync(outside, { recursive: true, force: true })
  }
})

test('readability artifacts never follow an output symlink', () => {
  const root = makeRepo()
  const outside = fs.mkdtempSync(path.join(root, '..', 'repo-atlas-artifact-outside-'))
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    const report = computeReadability(root, { exclude: [] })
    report.outliers = {
      ...report.outliers,
      forced: [{ path: 'src/a.ts', value: 1, z: 3 }],
    }
    const dir = path.join(root, '.atlas/artifacts/src/a.ts')
    fs.mkdirSync(dir, { recursive: true })
    const canary = path.join(outside, 'canary.md')
    fs.writeFileSync(canary, 'outside stays unchanged\n')
    fs.symlinkSync(canary, path.join(dir, 'readability.md'))

    assert.throws(() => writeReadabilityArtifacts(root, report), /symlink|unsafe|regular file/i)
    assert.equal(fs.readFileSync(canary, 'utf8'), 'outside stays unchanged\n')
  } finally {
    cleanup(root)
    fs.rmSync(outside, { recursive: true, force: true })
  }
})

test('readability artifacts escape Git-controlled paths before rendering Markdown', () => {
  const root = makeRepo()
  try {
    const repoPath = 'src/<img src=x onerror=alert(1)>.ts'
    write(root, repoPath, duplicatedLines(12))
    commitAll(root)
    const report = computeReadability(root, { exclude: [] })
    report.outliers = {
      ...report.outliers,
      forced: [{ path: repoPath, value: 1, z: 3 }],
    }
    report.dirs = [{ path: 'src', files: 1, meanComposite: -1, lowFiles: 1, worst: repoPath, worstComposite: -1 }]

    writeReadabilityArtifacts(root, report)
    const card = fs.readFileSync(path.join(root, '.atlas/artifacts/src/readability.md'), 'utf8')
    assert.doesNotMatch(card, /<img\b/i)
    assert.match(card, /&#60;img src=x onerror=alert&#40;1&#41;&#62;/)
  } finally {
    cleanup(root)
  }
})

test('readability CLI rejects missing or invalid option values', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', duplicatedLines(12))
    commitAll(root)
    for (const args of [
      ['readability', '--top', '0'],
      ['readability', '--top', '1.5'],
      ['readability', '--top'],
      ['readability', '--out', '--json'],
      ['readability', '--exclude'],
    ]) {
      const run = spawnSync(process.execPath, [CLI, ...args], { cwd: root, encoding: 'utf8' })
      assert.notEqual(run.status, 0, `${args.join(' ')} unexpectedly succeeded`)
      assert.match(run.stderr, /requires|positive integer|usage|value/i)
    }
  } finally {
    cleanup(root)
  }
})
