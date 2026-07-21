import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { loadAuditPortfolios } from '../dist/audits.js'
import { buildPayload } from '../dist/build.js'
import { loadReviewCoverage } from '../dist/review-coverage.js'
import { scan } from '../dist/scan.js'
import { computeStatus } from '../dist/status.js'
import { cleanup, commitAll, gitBlob, makeRepo, scopeHash, write } from './helpers.mjs'

const CLI = new URL('../dist/cli.js', import.meta.url).pathname
const COVERAGE_REL = '.atlas/review-coverage.json'
const SELF_PATH = COVERAGE_REL
const GENERATED_PROOF = 'GENERATED-PROOF'

function securityFinding(file, severity = 'medium') {
  return {
    severity,
    category: 'boundary',
    title: `${file} finding`,
    locations: [`${file}:1`],
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

function writeV2(root, domain, slug, files, findings, extra = {}) {
  write(root, `.atlas/audits/${slug}.json`, JSON.stringify({
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
  }, null, 2) + '\n')
}

test('payload carries testAudits from the portfolio loader and defaults to []', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    writeV2(root, 'security', 'security-runtime', ['src/a.ts'], [securityFinding('src/a.ts', 'high')])
    writeV2(root, 'test', 'test-runtime', ['src/a.ts'], [testFinding('src/a.ts', 'blocking')])

    const scanResult = scan(root, { exclude: [] })
    const status = computeStatus(root, scanResult, { readability: false })
    const portfolios = loadAuditPortfolios(root, status.audits)

    const withBoth = buildPayload({
      repoName: 'fixture',
      commit: null,
      status,
      audits: portfolios.security,
      testAudits: portfolios.tests,
    })
    assert.deepEqual(withBoth.testAudits, portfolios.tests)
    assert.deepEqual(withBoth.audits.map((u) => u.slug), ['security-runtime'])
    assert.equal(withBoth.testAudits[0].domain, 'test')
    assert.equal(withBoth.testAudits[0].slug, 'test-runtime')

    const defaults = buildPayload({
      repoName: 'fixture',
      commit: null,
      status,
    })
    assert.deepEqual(defaults.testAudits, [])
    assert.deepEqual(defaults.audits, [])
  } finally {
    cleanup(root)
  }
})

function inventoryHashFor(entries) {
  const lines = entries.map((entry) => {
    const marker = entry.path === SELF_PATH ? GENERATED_PROOF : entry.blob
    return `${marker}  ${entry.path}`
  }).sort()
  return createHash('sha256').update(lines.join('\n') + '\n').digest('hex')
}

function writeCoverageReport(root, verdict = 'incomplete') {
  const securityStatus = verdict === 'incomplete' ? 'missing' : 'fresh'
  const securityLedgers = verdict === 'incomplete' ? [] : ['security-src']
  const entries = [
    {
      path: 'src/a.ts',
      blob: gitBlob(root, 'src/a.ts'),
      ruleIds: ['source'],
      classification: {
        kind: 'review',
        domains: { security: { unit: 'security-src' } },
      },
      evidence: {
        security: { status: securityStatus, ledgers: securityLedgers },
      },
    },
    {
      path: SELF_PATH,
      ruleIds: ['generated-proof'],
      classification: {
        kind: 'excluded',
        ruleId: 'generated-proof',
        category: 'generated-proof',
        reason: 'canonical report validates its own bytes',
      },
      evidence: {},
    },
    {
      path: '.atlas/config.json',
      blob: gitBlob(root, '.atlas/config.json'),
      ruleIds: ['fixture-config'],
      classification: {
        kind: 'excluded',
        ruleId: 'fixture-config',
        category: 'fixture',
        reason: 'fixture configuration is outside this parser test',
      },
      evidence: {},
    },
    {
      path: '.atlas/audits/security-src.json',
      blob: gitBlob(root, '.atlas/audits/security-src.json'),
      ruleIds: ['generated-ledger'],
      classification: {
        kind: 'excluded',
        ruleId: 'generated-ledger',
        category: 'generated',
        reason: 'strict fixture builder output',
      },
      evidence: {},
    },
  ]
  const summary = {
    tracked: 4,
    securityRequired: 1,
    securityFresh: verdict === 'complete' ? 1 : 0,
    securityMissing: verdict === 'incomplete' ? 1 : 0,
    securityStale: 0,
    securityInvalid: 0,
    testRequired: 0,
    testFresh: 0,
    testMissing: 0,
    testStale: 0,
    testInvalid: 0,
    dualRequired: 0,
    excluded: 3,
    unclassified: 0,
    conflicted: 0,
    invalidLedgers: 0,
  }
  const report = {
    formatVersion: 1,
    format: 'atlas-review-coverage-v1',
    verdict,
    policy: { format: 'fixture-policy-v1', hash: 'a'.repeat(64) },
    inventoryHash: inventoryHashFor(entries),
    units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
    summary,
    entries,
    invalidLedgerDetails: [],
    reportErrors: [],
  }
  write(root, COVERAGE_REL, JSON.stringify(report, null, 2) + '\n')
  execFileSync('git', ['add', '--', COVERAGE_REL], { cwd: root })
  return report
}

function emptyStatus(root) {
  const scanResult = scan(root, { exclude: [] })
  return computeStatus(root, scanResult, { readability: false })
}

function extractAtlasPayload(html) {
  const marker = 'window.__ATLAS__ = '
  const start = html.indexOf(marker)
  assert.ok(start >= 0, 'atlas payload marker missing from HTML')
  const jsonStart = start + marker.length
  const jsonEnd = html.indexOf(';</script>', jsonStart)
  assert.ok(jsonEnd > jsonStart, 'atlas payload terminator missing from HTML')
  return JSON.parse(html.slice(jsonStart, jsonEnd))
}

test('payload carries review coverage and defaults to missing', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writeV2(root, 'security', 'security-src', ['src/a.ts'], [securityFinding('src/a.ts')], {
      hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
    })
    commitAll(root)

    const status = emptyStatus(root)
    const defaults = buildPayload({ repoName: 'fixture', commit: null, status })
    assert.equal(defaults.reviewCoverage.state, 'missing')
    assert.equal(defaults.reviewCoverage.report, null)

    writeCoverageReport(root, 'incomplete')
    const portfolios = loadAuditPortfolios(root, status.audits)
    const coverage = loadReviewCoverage(root, portfolios)
    assert.equal(coverage.state, 'current')
    assert.equal(coverage.report?.verdict, 'incomplete')

    const withCoverage = buildPayload({
      repoName: 'fixture',
      commit: null,
      status,
      reviewCoverage: coverage,
    })
    assert.deepEqual(withCoverage.reviewCoverage, coverage)
  } finally {
    cleanup(root)
  }
})

test('coverage-only changes reach the shared build payload', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writeV2(root, 'security', 'security-src', ['src/a.ts'], [securityFinding('src/a.ts')], {
      hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
    })
    commitAll(root)
    writeCoverageReport(root, 'incomplete')

    const first = spawnSync(process.execPath, [CLI, 'build', '-o', '.atlas/atlas-a.html'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(first.status, 0, first.stderr || first.stdout)
    const htmlA = fs.readFileSync(path.join(root, '.atlas/atlas-a.html'), 'utf8')
    const dataA = extractAtlasPayload(htmlA)
    assert.equal(dataA.reviewCoverage.state, 'current')
    assert.equal(dataA.reviewCoverage.report.verdict, 'incomplete')
    assert.equal(dataA.reviewCoverage.report.summary.securityMissing, 1)

    // Only the coverage report changes — audits/status notes stay put.
    writeCoverageReport(root, 'complete')
    const second = spawnSync(process.execPath, [CLI, 'build', '-o', '.atlas/atlas-b.html'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(second.status, 0, second.stderr || second.stdout)
    const htmlB = fs.readFileSync(path.join(root, '.atlas/atlas-b.html'), 'utf8')
    const dataB = extractAtlasPayload(htmlB)
    assert.equal(dataB.reviewCoverage.report.verdict, 'complete')
    assert.equal(dataB.reviewCoverage.report.summary.securityMissing, 0)
    assert.notEqual(
      JSON.stringify(dataA.reviewCoverage),
      JSON.stringify(dataB.reviewCoverage),
    )
  } finally {
    cleanup(root)
  }
})
