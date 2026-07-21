import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { auditStatusEntries, loadAuditPortfolios, loadAudits, stampAudits } from '../dist/audits.js'
import { scan } from '../dist/scan.js'
import { cleanup, commitAll, makeRepo, scopeHash, write } from './helpers.mjs'

const CLI = new URL('../dist/cli.js', import.meta.url).pathname

function finding(file, severity = 'medium') {
  return {
    severity,
    category: 'boundary',
    title: `${file} finding`,
    locations: [`${file}#handler`, `${file}:1`],
    dataflow: 'input to sink',
    fix: 'validate it',
  }
}

function testFinding(file, impact = 'blocking') {
  return {
    impact,
    category: 'missing-invariant',
    title: `${file} test finding`,
    invariant: 'handler rejects unauthenticated callers',
    evidence: 'suite mocks auth away',
    fix: 'assert the real gate',
    locations: [`${file}:1`],
  }
}

function ledger(root, name, files, extra = {}) {
  const value = {
    formatVersion: 1,
    format: 'atlas-audit-v1',
    slug: name,
    title: name,
    ruleset: 'test-v1',
    scanned_at: '2026-07-19',
    scope_hash: scopeHash(root, files),
    file_count: files.length,
    files,
    findings: [finding(files[0])],
    dropped: [],
    rounds: [],
    finalPass: true,
    ...extra,
  }
  write(root, `.atlas/audits/${name}.json`, JSON.stringify(value, null, 2) + '\n')
  return value
}

function v2Envelope(root, domain, slug, files, findings, extra = {}) {
  const value = {
    formatVersion: 2,
    format: 'atlas-audit-v2',
    domain,
    reviewState: 'complete',
    slug,
    title: slug,
    ruleset: `fixture-${domain}-v1`,
    scanned_at: '2026-07-21',
    scope_hash: scopeHash(root, files),
    file_count: files.length,
    files,
    findings,
    ...extra,
  }
  write(root, `.atlas/audits/${slug}.json`, JSON.stringify(value, null, 2) + '\n')
  return value
}

test('v2 security and test ledgers project into domain portfolios', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    v2Envelope(root, 'security', 'security-runtime', ['src/a.ts'], [finding('src/a.ts', 'high')], {
      conceptSlug: 'auth',
    })
    v2Envelope(root, 'test', 'test-runtime', ['src/a.ts'], [testFinding('src/a.ts', 'blocking')])

    const portfolios = loadAuditPortfolios(root)
    assert.equal(portfolios.security[0].slug, 'security-runtime')
    assert.equal(portfolios.security[0].domain, 'security')
    assert.equal(portfolios.security[0].formatVersion, 2)
    assert.equal(portfolios.security[0].conceptSlug, 'auth')
    assert.equal(portfolios.tests[0].slug, 'test-runtime')
    assert.equal(portfolios.tests[0].domain, 'test')
    assert.equal(portfolios.tests[0].findings[0].impact, 'blocking')
    assert.equal(loadAudits(root)[0].slug, 'security-runtime')
    assert.equal(loadAudits(root).length, 1)

    const statuses = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.deepEqual(statuses.map((status) => ({ name: status.name, status: status.status, invalid: status.invalidReason })), [
      { name: 'security-runtime', status: 'fresh', invalid: null },
      { name: 'test-runtime', status: 'fresh', invalid: null },
    ])
  } finally {
    cleanup(root)
  }
})

test('v2 domain validation fails closed for crossover, unknown domain, incomplete, and schema errors', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)

    const cases = [
      {
        slug: 'crossover',
        domain: 'test',
        findings: [finding('src/a.ts')],
        match: /finding|schema|impact|invariant/i,
      },
      {
        slug: 'unknown-domain',
        domain: 'ops',
        findings: [],
        match: /unsupported audit domain|domain/i,
      },
      {
        slug: 'incomplete',
        domain: 'security',
        findings: [],
        extra: { reviewState: 'in-progress' },
        match: /reviewState must be complete/i,
      },
      {
        slug: 'unknown-category',
        domain: 'test',
        findings: [{ ...testFinding('src/a.ts'), category: 'not-a-category' }],
        match: /categor/i,
      },
      {
        slug: 'empty-locations',
        domain: 'test',
        findings: [{ ...testFinding('src/a.ts'), locations: [] }],
        match: /location/i,
      },
      {
        slug: 'version-format-mismatch',
        domain: 'security',
        findings: [finding('src/a.ts')],
        extra: { format: 'atlas-audit-v1' },
        match: /version 2|atlas-audit-v2|format/i,
      },
    ]

    for (const item of cases) {
      for (const entry of fs.readdirSync(path.join(root, '.atlas/audits'))) {
        fs.unlinkSync(path.join(root, '.atlas/audits', entry))
      }
      v2Envelope(root, item.domain, item.slug, ['src/a.ts'], item.findings, item.extra ?? {})
      const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
      assert.equal(status.status, 'stale', item.slug)
      assert.match(status.invalidReason ?? '', item.match, item.slug)
      assert.deepEqual(loadAuditPortfolios(root), { security: [], tests: [] }, item.slug)
      assert.deepEqual(loadAudits(root), [], item.slug)
    }
  } finally {
    cleanup(root)
  }
})

test('v2 finding locations require normalized repository-relative paths and positive line numbers', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)

    const cases = [
      { slug: 'escape-parent', locations: ['../outside.ts:1'] },
      { slug: 'absolute-path', locations: ['/abs.ts:1'] },
      { slug: 'zero-line', locations: ['src/a.ts:0'] },
    ]

    for (const item of cases) {
      for (const entry of fs.readdirSync(path.join(root, '.atlas/audits'))) {
        fs.unlinkSync(path.join(root, '.atlas/audits', entry))
      }
      v2Envelope(root, 'security', item.slug, ['src/a.ts'], [{
        ...finding('src/a.ts'),
        locations: item.locations,
      }])
      const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
      assert.equal(status.status, 'stale', item.slug)
      assert.match(status.invalidReason ?? '', /location|path|schema/i, item.slug)
      assert.deepEqual(loadAuditPortfolios(root), { security: [], tests: [] }, item.slug)

      for (const entry of fs.readdirSync(path.join(root, '.atlas/audits'))) {
        fs.unlinkSync(path.join(root, '.atlas/audits', entry))
      }
      v2Envelope(root, 'test', `test-${item.slug}`, ['src/a.ts'], [{
        ...testFinding('src/a.ts'),
        locations: item.locations,
      }])
      const [testStatus] = auditStatusEntries(root, scan(root, { exclude: [] }))
      assert.equal(testStatus.status, 'stale', `test-${item.slug}`)
      assert.match(testStatus.invalidReason ?? '', /location|path|schema/i, `test-${item.slug}`)
      assert.deepEqual(loadAuditPortfolios(root), { security: [], tests: [] }, `test-${item.slug}`)
    }

    // Still accepts path, path:line>=1, and path#symbol forms.
    v2Envelope(root, 'security', 'location-ok', ['src/a.ts'], [{
      ...finding('src/a.ts'),
      locations: ['src/a.ts', 'src/a.ts:1', 'src/a.ts#handler'],
    }])
    assert.equal(loadAuditPortfolios(root).security[0]?.slug, 'location-ok')
  } finally {
    cleanup(root)
  }
})

test('v2 ledger slugs must be lowercase kebab for namespaced routes', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    v2Envelope(root, 'security', 'Bad Slug', ['src/a.ts'], [finding('src/a.ts')])

    const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(status.status, 'stale')
    assert.match(status.invalidReason ?? '', /slug/i)
    assert.deepEqual(loadAuditPortfolios(root), { security: [], tests: [] })
    assert.deepEqual(loadAudits(root), [])

    // Legacy v1 remains un-tightened for slug character set.
    ledger(root, 'Legacy_Name', ['src/a.ts'])
    assert.equal(loadAudits(root)[0]?.slug, 'Legacy_Name')
  } finally {
    cleanup(root)
  }
})

test('portfolio loader orders security by severity and tests by stale then impact', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    write(root, 'src/b.ts', 'export const other = 1\n')
    commitAll(root)

    v2Envelope(root, 'security', 'security-low', ['src/a.ts'], [finding('src/a.ts', 'low')])
    v2Envelope(root, 'security', 'security-high', ['src/a.ts'], [finding('src/a.ts', 'high')])
    v2Envelope(root, 'test', 'test-advisory', ['src/a.ts'], [testFinding('src/a.ts', 'advisory')])
    v2Envelope(root, 'test', 'test-blocking', ['src/a.ts'], [testFinding('src/a.ts', 'blocking')])
    v2Envelope(root, 'test', 'test-stale', ['src/b.ts'], [testFinding('src/b.ts', 'advisory')])
    write(root, 'src/b.ts', 'export const other = 2\n')

    const statuses = auditStatusEntries(root, scan(root, { exclude: [] }))
    const portfolios = loadAuditPortfolios(root, statuses)
    assert.deepEqual(portfolios.security.map((u) => u.slug), ['security-high', 'security-low'])
    assert.deepEqual(portfolios.tests.map((u) => u.slug), ['test-stale', 'test-blocking', 'test-advisory'])
    assert.equal(portfolios.tests[0].stale, true)
    assert.equal(portfolios.tests[1].stale, false)
    assert.deepEqual(loadAudits(root, statuses).map((u) => u.slug), ['security-high', 'security-low'])
  } finally {
    cleanup(root)
  }
})

test('malformed portfolio v2 ledgers stay status-invalid and never enter portfolios', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    v2Envelope(root, 'security', 'security-ok', ['src/a.ts'], [finding('src/a.ts', 'medium')])
    v2Envelope(root, 'test', 'test-incomplete', ['src/a.ts'], [], { reviewState: 'draft' })
    v2Envelope(root, 'security', 'security-bad-finding', ['src/a.ts'], [{
      ...finding('src/a.ts'),
      locations: ['../escape.ts:1'],
    }])

    const statuses = auditStatusEntries(root, scan(root, { exclude: [] }))
    const byName = Object.fromEntries(statuses.map((s) => [s.name, s]))
    assert.equal(byName['security-ok'].status, 'fresh')
    assert.equal(byName['security-ok'].invalidReason, null)
    assert.equal(byName['test-incomplete'].status, 'stale')
    assert.ok(byName['test-incomplete'].invalidReason)
    assert.equal(byName['security-bad-finding'].status, 'stale')
    assert.ok(byName['security-bad-finding'].invalidReason)

    const portfolios = loadAuditPortfolios(root, statuses)
    assert.deepEqual(portfolios.security.map((u) => u.slug), ['security-ok'])
    assert.deepEqual(portfolios.tests, [])
    assert.equal(portfolios.security[0].findings.length, 1)
  } finally {
    cleanup(root)
  }
})

test('unstamped audit still becomes stale when its scope hash drifts', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    ledger(root, 'scope', ['src/a.ts'])

    assert.equal(auditStatusEntries(root, scan(root, { exclude: [] }))[0].status, 'fresh')
    write(root, 'src/a.ts', 'export const answer = 2\n')

    const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(status.status, 'stale')
    assert.deepEqual(status.changedFiles, [], 'without per-file hashes the exact changed file stays unknown')
  } finally {
    cleanup(root)
  }
})

test('audit-stamp refuses to bind a stale verdict to current bytes', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    ledger(root, 'scope', ['src/a.ts'])
    write(root, 'src/a.ts', 'export const answer = 2\n')

    const result = stampAudits(root, scan(root, { exclude: [] }))
    assert.deepEqual(result.stamped, [])
    assert.deepEqual(result.skipped, ['scope: scope drifted; re-run the audit before stamping'])
    const stored = JSON.parse(fs.readFileSync(path.join(root, '.atlas/audits/scope.json'), 'utf8'))
    assert.equal(stored.hashes, undefined)
  } finally {
    cleanup(root)
  }
})

test('audit-stamp enables per-file and finding drift detail for a fresh ledger', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    ledger(root, 'scope', ['src/a.ts'])

    assert.deepEqual(stampAudits(root, scan(root, { exclude: [] })).stamped, ['scope'])
    write(root, 'src/a.ts', 'export const answer = 2\n')

    const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(status.status, 'stale')
    assert.deepEqual(status.changedFiles, ['src/a.ts'])
    assert.equal(status.findingsWithDrift, 1)
  } finally {
    cleanup(root)
  }
})

test('viewer loader fails closed on malformed security ledgers and preserves severity ordering', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    ledger(root, 'low', ['src/a.ts'], { findings: [finding('src/a.ts', 'low')] })
    ledger(root, 'high', ['src/a.ts'], { findings: [finding('src/a.ts', 'high')] })
    ledger(root, 'malformed-finding', ['src/a.ts'], { findings: [finding('src/a.ts'), { nope: true }] })
    ledger(root, 'count-mismatch', ['src/a.ts'], { file_count: 999 })
    ledger(root, 'unfinished', ['src/a.ts'], { finalPass: false })
    ledger(root, 'future', ['src/a.ts'], { formatVersion: 99 })
    ledger(root, 'malformed-findings', ['src/a.ts'], { findings: { clean: true } })

    const audits = loadAudits(root)
    assert.deepEqual(audits.map((audit) => audit.slug), ['high', 'low'])
    assert.equal(audits[0].fileCount, 1)
    assert.equal(audits[1].findings.length, 1)
  } finally {
    cleanup(root)
  }
})

test('audit scope paths excluded from the atlas scan are hashed directly, not reported missing', () => {
  const root = makeRepo()
  try {
    write(root, 'src/excluded.ts', 'export const answer = 1\n')
    commitAll(root)
    ledger(root, 'excluded', ['src/excluded.ts'])
    const excludedScan = scan(root, { exclude: ['src/excluded.ts'] })

    const [fresh] = auditStatusEntries(root, excludedScan)
    assert.equal(fresh.status, 'fresh')
    assert.deepEqual(fresh.missingFiles, [])
    assert.deepEqual(stampAudits(root, excludedScan).stamped, ['excluded'])

    write(root, 'src/excluded.ts', 'export const answer = 2\n')
    const [drifted] = auditStatusEntries(root, scan(root, { exclude: ['src/excluded.ts'] }))
    assert.equal(drifted.status, 'stale')
    assert.deepEqual(drifted.missingFiles, [])
    assert.deepEqual(drifted.changedFiles, ['src/excluded.ts'])
  } finally {
    cleanup(root)
  }
})

test('generic audit ledgers participate in status without entering the security viewer', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    write(root, '.atlas/audits/design.json', JSON.stringify({
      format: 'atlas-audit-v1',
      name: 'design',
      title: 'Design scan',
      ruleset: 'design-v1',
      scanned_at: '2026-07-19',
      scope_hash: scopeHash(root, ['src/a.ts']),
      files: ['src/a.ts'],
      findings: [{ path: 'src/a.ts', severity: 'medium', count: 2, summary: 'needless optionality' }],
    }, null, 2) + '\n')

    const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(status.name, 'design')
    assert.equal(status.status, 'fresh')
    assert.equal(status.findingCount, 2)
    assert.deepEqual(loadAudits(root), [], 'generic findings are not security-viewer cards')

    assert.deepEqual(stampAudits(root, scan(root, { exclude: [] })).stamped, ['design'])
    write(root, 'src/a.ts', 'export const answer = 2\n')
    const [drifted] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.deepEqual(drifted.changedFiles, ['src/a.ts'])
    assert.equal(drifted.findingsWithDrift, 2)
  } finally {
    cleanup(root)
  }
})

test('legacy per-file ledgers import into atlas-audit-v1 with scan-time hashes intact', async () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    const blob = fs.readFileSync(path.join(root, 'src/a.ts'))
    const gitBlobSha = (await import('node:crypto')).createHash('sha1')
      .update(`blob ${blob.length}\0`).update(blob).digest('hex')
    write(root, 'audits/design-scan/ledger.json', JSON.stringify({
      schema: 1,
      ruleset: 'relayos-design-v1',
      scans: [{
        path: 'src/a.ts',
        git_blob_sha1: gitBlobSha.toUpperCase(),
        scanned_at: '2026-07-19',
        status: 'findings',
        max_severity: 'medium',
        finding_count: 2,
        findings_ref: 'findings.md#src-a',
      }],
    }, null, 2) + '\n')

    const { importLegacyAudit } = await import('../dist/audits.js')
    assert.equal(typeof importLegacyAudit, 'function')
    const imported = importLegacyAudit(root, 'audits/design-scan/ledger.json')
    assert.equal(imported.name, 'design-scan')
    assert.equal(imported.findingCount, 2)
    const stored = JSON.parse(fs.readFileSync(path.join(root, '.atlas/audits/design-scan.json'), 'utf8'))
    assert.equal(stored.format, 'atlas-audit-v1')
    assert.equal(stored.hashes['src/a.ts'], gitBlobSha)
    assert.equal(stored.findings[0].count, 2)
    const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(status.status, 'fresh')
    assert.equal(status.findingCount, 2)
  } finally {
    cleanup(root)
  }
})

test('a malformed security scope is rejected instead of rendered as clean or merely stale', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    write(root, '.atlas/audits/malformed.json', JSON.stringify({
      formatVersion: 1,
      format: 'atlas-audit-v1',
      slug: 'malformed',
      title: 'Malformed scope',
      ruleset: 'test-v1',
      scanned_at: '2026-07-19',
      scope_hash: '0'.repeat(40),
      file_count: 1,
      files: ['src'],
      findings: [],
      finalPass: true,
    }, null, 2) + '\n')

    assert.deepEqual(loadAudits(root), [])
  } finally {
    cleanup(root)
  }
})

test('security viewer keeps the historical filename fallback for missing slugs', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    write(root, '.atlas/audits/filename-fallback.json', JSON.stringify({
      formatVersion: 1,
      format: 'atlas-audit-v1',
      title: 'Filename fallback',
      ruleset: 'test-v1',
      scanned_at: '2026-07-19',
      scope_hash: scopeHash(root, ['src/a.ts']),
      file_count: 1,
      files: ['src/a.ts'],
      findings: [],
      finalPass: true,
    }, null, 2) + '\n')

    assert.equal(loadAudits(root)[0].slug, 'filename-fallback')
  } finally {
    cleanup(root)
  }
})

test('legacy import refuses to overwrite an unrelated native ledger', async () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    write(root, 'audits/design-scan/ledger.json', JSON.stringify({
      ruleset: 'legacy-v1',
      scans: [{
        path: 'src/a.ts',
        git_blob_sha1: scopeHash(root, ['src/a.ts']).slice(0, 40),
        scanned_at: '2026-07-19',
        finding_count: 0,
      }],
    }))
    write(root, '.atlas/audits/design-scan.json', JSON.stringify({
      format: 'atlas-audit-v1',
      slug: 'native-design-scan',
      files: ['src/a.ts'],
      findings: [],
    }))

    const { importLegacyAudit } = await import('../dist/audits.js')
    assert.throws(() => importLegacyAudit(root, 'audits/design-scan/ledger.json'), /refusing to overwrite/i)
    const stored = JSON.parse(fs.readFileSync(path.join(root, '.atlas/audits/design-scan.json'), 'utf8'))
    assert.equal(stored.slug, 'native-design-scan')
  } finally {
    cleanup(root)
  }
})

test('legacy import rejects partial scope migration and non-integer finding counts', async () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    const sha = (await import('node:child_process')).execFileSync('git', ['hash-object', '--', 'src/a.ts'], {
      cwd: root,
      encoding: 'utf8',
    }).trim()
    write(root, 'audits/design-scan/ledger.json', JSON.stringify({
      scans: [
        { path: 'src/a.ts', git_blob_sha1: sha, finding_count: 0 },
        { path: 'src/bad.ts', git_blob_sha1: 'not-a-sha', finding_count: 0.5 },
      ],
    }))

    const { importLegacyAudit } = await import('../dist/audits.js')
    assert.throws(() => importLegacyAudit(root, 'audits/design-scan/ledger.json'), /invalid legacy scan.*2/i)
    assert.equal(fs.existsSync(path.join(root, '.atlas/audits/design-scan.json')), false)
  } finally {
    cleanup(root)
  }
})

test('generic ledgers with invalid explicit finding counts are rejected', () => {
  const root = makeRepo()
  const warnings = []
  const originalWarn = console.warn
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    write(root, '.atlas/audits/invalid-count.json', JSON.stringify({
      format: 'atlas-audit-v1',
      slug: 'invalid-count',
      scope_hash: scopeHash(root, ['src/a.ts']),
      files: ['src/a.ts'],
      findings: [{ path: 'src/a.ts', count: 0.5 }],
    }))
    console.warn = (...args) => warnings.push(args.join(' '))

    const scanResult = scan(root, { exclude: [] })
    const statuses = auditStatusEntries(root, scanResult)
    assert.equal(statuses.length, 1)
    assert.equal(statuses[0].status, 'stale')
    assert.match(statuses[0].invalidReason, /finding count.*nonnegative integer/i)
    assert.match(warnings.join('\n'), /finding count.*nonnegative integer/i)
    const stamped = stampAudits(root, scanResult)
    assert.deepEqual(stamped.stamped, [])
    assert.deepEqual(stamped.skipped, ['invalid-count: finding count must be a finite nonnegative integer'])
    const stored = JSON.parse(fs.readFileSync(path.join(root, '.atlas/audits/invalid-count.json'), 'utf8'))
    assert.equal(stored.hashes, undefined)
  } finally {
    console.warn = originalWarn
    cleanup(root)
  }
})

test('audit-stamp reports scope refusal and unknown requested ledgers as failures', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    ledger(root, 'scope', ['src/a.ts'])
    write(root, 'src/a.ts', 'export const answer = 2\n')

    const drifted = spawnSync(process.execPath, [CLI, 'audit-stamp', 'scope'], { cwd: root, encoding: 'utf8' })
    assert.notEqual(drifted.status, 0)
    assert.match(drifted.stderr, /scope drifted; re-run the audit/i)
    assert.doesNotMatch(`${drifted.stdout}${drifted.stderr}`, /all scope files missing/i)

    const absent = spawnSync(process.execPath, [CLI, 'audit-stamp', 'does-not-exist'], { cwd: root, encoding: 'utf8' })
    assert.notEqual(absent.status, 0)
    assert.match(absent.stderr, /does-not-exist.*not found/i)
  } finally {
    cleanup(root)
  }
})

test('security viewer warns when malformed and future ledgers are skipped', () => {
  const root = makeRepo()
  const warnings = []
  const originalWarn = console.warn
  try {
    write(root, '.atlas/audits/broken.json', '{not json')
    write(root, '.atlas/audits/future.json', JSON.stringify({
      formatVersion: 99,
      slug: 'future',
      files: [],
      findings: [],
      finalPass: true,
    }))
    console.warn = (...args) => warnings.push(args.join(' '))

    assert.deepEqual(loadAudits(root), [])
    assert.match(warnings.join('\n'), /broken\.json.*parse|broken\.json.*解析/i)
    assert.match(warnings.join('\n'), /future\.json.*formatVersion 99/i)
  } finally {
    console.warn = originalWarn
    cleanup(root)
  }
})

test('status exposes unreadable and unsupported audit ledgers as stale invalid entries', () => {
  const root = makeRepo()
  const warnings = []
  const originalWarn = console.warn
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    write(root, '.atlas/audits/broken.json', '{not json')
    write(root, '.atlas/audits/future.json', JSON.stringify({
      formatVersion: 99,
      format: 'atlas-audit-v1',
      slug: 'future',
      files: ['src/a.ts'],
      findings: [],
    }))
    console.warn = (...args) => warnings.push(args.join(' '))

    const statuses = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.deepEqual(statuses.map(({ name, status }) => ({ name, status })), [
      { name: 'broken', status: 'stale' },
      { name: 'future', status: 'stale' },
    ])
    assert.ok(statuses.every((status) => status.invalidReason))
    assert.match(warnings.join('\n'), /broken\.json.*parse|future\.json.*unsupported/i)
  } finally {
    console.warn = originalWarn
    cleanup(root)
  }
})

test('security viewer rejects explicit slugs that do not match their ledger filename', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    const value = ledger(root, 'expected', ['src/a.ts'])
    fs.renameSync(path.join(root, '.atlas/audits/expected.json'), path.join(root, '.atlas/audits/shadow.json'))
    assert.equal(value.slug, 'expected')

    assert.deepEqual(loadAudits(root), [])
    const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(status.status, 'stale')
    assert.match(status.invalidReason, /slug.*filename/i)
  } finally {
    cleanup(root)
  }
})

test('legacy import rejects normalized-path aliases and aggregate finding-count overflow', async () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, 'src/b.ts', 'export const b = 2\n')
    commitAll(root)
    const shaA = (await import('node:child_process')).execFileSync('git', ['hash-object', '--', 'src/a.ts'], { cwd: root, encoding: 'utf8' }).trim()
    const shaB = (await import('node:child_process')).execFileSync('git', ['hash-object', '--', 'src/b.ts'], { cwd: root, encoding: 'utf8' }).trim()
    const { importLegacyAudit } = await import('../dist/audits.js')

    write(root, 'audits/alias/ledger.json', JSON.stringify({
      scans: [{ path: 'src/./a.ts', git_blob_sha1: shaA, finding_count: 0 }],
    }))
    assert.throws(() => importLegacyAudit(root, 'audits/alias/ledger.json'), /normalized repository-relative path/i)

    write(root, 'audits/overflow/ledger.json', JSON.stringify({
      scans: [
        { path: 'src/a.ts', git_blob_sha1: shaA, finding_count: Number.MAX_SAFE_INTEGER },
        { path: 'src/b.ts', git_blob_sha1: shaB, finding_count: 1 },
      ],
    }))
    assert.throws(() => importLegacyAudit(root, 'audits/overflow/ledger.json'), /aggregate|safe integer|overflow/i)
  } finally {
    cleanup(root)
  }
})

test('audit-stamp never follows a ledger symlink outside the repository', () => {
  const root = makeRepo()
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-audit-outside-'))
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    const canary = path.join(outside, 'canary.json')
    const original = JSON.stringify({
      formatVersion: 1,
      format: 'atlas-audit-v1',
      slug: 'evil',
      title: 'evil',
      ruleset: 'test-v1',
      scanned_at: '2026-07-19',
      scope_hash: scopeHash(root, ['src/a.ts']),
      files: ['src/a.ts'],
      findings: [],
    }, null, 2) + '\n'
    fs.writeFileSync(canary, original)
    fs.symlinkSync(canary, path.join(root, '.atlas/audits/evil.json'))

    assert.deepEqual(stampAudits(root, scan(root, { exclude: [] })).stamped, [])
    assert.equal(fs.readFileSync(canary, 'utf8'), original)
  } finally {
    cleanup(root)
    fs.rmSync(outside, { recursive: true, force: true })
  }
})

test('audit import rejects symlinked sources and a symlinked audit directory', async () => {
  const root = makeRepo()
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-import-outside-'))
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    const externalSource = path.join(outside, 'ledger.json')
    fs.writeFileSync(externalSource, JSON.stringify({
      scans: [{ path: 'src/a.ts', git_blob_sha1: scopeHash(root, ['src/a.ts']), finding_count: 0 }],
    }))
    fs.mkdirSync(path.join(root, 'audits/design-scan'), { recursive: true })
    fs.symlinkSync(externalSource, path.join(root, 'audits/design-scan/ledger.json'))
    const { importLegacyAudit } = await import('../dist/audits.js')

    assert.throws(() => importLegacyAudit(root, 'audits/design-scan/ledger.json'), /symlink|outside|regular file/i)

    fs.unlinkSync(path.join(root, 'audits/design-scan/ledger.json'))
    fs.writeFileSync(path.join(root, 'audits/design-scan/ledger.json'), fs.readFileSync(externalSource))
    fs.rmdirSync(path.join(root, '.atlas/audits'))
    fs.mkdirSync(path.join(outside, 'audits'))
    fs.symlinkSync(path.join(outside, 'audits'), path.join(root, '.atlas/audits'))
    assert.throws(() => importLegacyAudit(root, 'audits/design-scan/ledger.json'), /audit.*directory|symlink|unsafe/i)
    const [invalid] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(invalid.status, 'stale')
    assert.match(invalid.invalidReason, /unsafe audit directory/i)
    assert.equal(fs.existsSync(path.join(outside, 'audits/design-scan.json')), false)
  } finally {
    cleanup(root)
    fs.rmSync(outside, { recursive: true, force: true })
  }
})
