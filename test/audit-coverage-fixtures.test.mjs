import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { createAuditCoverageFixtures } from '../qa/audit-coverage-fixtures.mjs'

function extractAtlasPayload(html) {
  const marker = 'window.__ATLAS__ = '
  const start = html.indexOf(marker)
  assert.ok(start >= 0, 'atlas payload marker missing from HTML')
  const jsonStart = start + marker.length
  const jsonEnd = html.indexOf(';</script>', jsonStart)
  assert.ok(jsonEnd > jsonStart, 'atlas payload terminator missing from HTML')
  return JSON.parse(html.slice(jsonStart, jsonEnd))
}

function readPayload(htmlPath) {
  assert.ok(fs.existsSync(htmlPath), `expected built HTML at ${htmlPath}`)
  return extractAtlasPayload(fs.readFileSync(htmlPath, 'utf8'))
}

test('createAuditCoverageFixtures builds three browser-acceptance repositories', () => {
  let baseDir
  try {
    const fixtures = createAuditCoverageFixtures()
    baseDir = fixtures.baseDir

    assert.equal(typeof baseDir, 'string')
    assert.ok(fs.existsSync(baseDir))

    for (const key of ['missing', 'incomplete', 'complete']) {
      assert.ok(fixtures[key], `missing fixture metadata for ${key}`)
      assert.equal(typeof fixtures[key].root, 'string')
      assert.equal(typeof fixtures[key].html, 'string')
      assert.ok(fs.existsSync(fixtures[key].html), `${key} HTML must exist`)
      assert.equal(
        fixtures[key].html,
        path.join(fixtures[key].root, '.atlas', 'atlas.html'),
      )
    }

    // 1) missing coverage report + one current completed v2 Security unit
    const missing = readPayload(fixtures.missing.html)
    assert.equal(missing.reviewCoverage.state, 'missing')
    assert.equal(missing.reviewCoverage.report, null)
    assert.equal(missing.reviewCoverage.report?.summary?.tracked, undefined)
    assert.equal(missing.audits.length, 1)
    assert.equal(missing.audits[0].domain, 'security')
    assert.equal(missing.audits[0].formatVersion, 2)
    assert.equal(missing.audits[0].stale, false)
    assert.equal(missing.audits[0].slug, 'security-main')
    assert.deepEqual(missing.testAudits, [])

    // 2) current incomplete coverage: security required=2 / fresh=1 / missing=1
    const incomplete = readPayload(fixtures.incomplete.html)
    assert.equal(incomplete.reviewCoverage.state, 'current')
    assert.equal(incomplete.reviewCoverage.report.verdict, 'incomplete')
    assert.equal(incomplete.reviewCoverage.report.summary.securityRequired, 2)
    assert.equal(incomplete.reviewCoverage.report.summary.securityFresh, 1)
    assert.equal(incomplete.reviewCoverage.report.summary.securityMissing, 1)
    const missingRow = incomplete.reviewCoverage.report.entries.find(
      (entry) => entry.classification?.kind === 'review'
        && entry.evidence?.security?.status === 'missing',
    )
    assert.ok(missingRow, 'incomplete fixture must expose an explicit missing security row')
    assert.deepEqual(missingRow.evidence.security.ledgers, [])
    assert.equal(incomplete.audits.length, 1)
    assert.equal(incomplete.audits[0].domain, 'security')
    assert.equal(incomplete.audits[0].stale, false)

    // 3) current complete coverage + Security dispositions + independent Tests unit
    const complete = readPayload(fixtures.complete.html)
    assert.equal(complete.reviewCoverage.state, 'current')
    assert.equal(complete.reviewCoverage.report.verdict, 'complete')
    assert.equal(
      complete.reviewCoverage.report.summary.securityRequired,
      complete.reviewCoverage.report.summary.securityFresh,
    )
    assert.ok(complete.reviewCoverage.report.summary.securityRequired >= 1)
    assert.equal(complete.reviewCoverage.report.summary.securityMissing, 0)

    assert.equal(complete.audits.length, 1)
    const security = complete.audits[0]
    assert.equal(security.domain, 'security')
    assert.equal(security.formatVersion, 2)
    assert.equal(security.stale, false)
    assert.deepEqual(
      security.findings.map((finding) => finding.disposition).sort(),
      ['accepted-risk', 'open', 'separate-design'],
    )
    assert.deepEqual(security.evidenceRefs, ['audits/evidence/security.json'])
    assert.equal(security.ruleset, 'fixture-security-v1')
    assert.match(security.scopeHash, /^[0-9a-f]{40}$/u)
    assert.equal(security.roundCount, 0)

    assert.equal(complete.testAudits.length, 1)
    const tests = complete.testAudits[0]
    assert.equal(tests.domain, 'test')
    assert.equal(tests.formatVersion, 2)
    assert.equal(tests.stale, false)
    assert.deepEqual(tests.evidenceRefs, ['audits/evidence/tests.json'])
    assert.equal(tests.ruleset, 'fixture-test-v1')
    assert.match(tests.scopeHash, /^[0-9a-f]{40}$/u)
    assert.equal(tests.roundCount, 0)
    for (const finding of tests.findings) {
      assert.ok(['blocking', 'warning', 'advisory'].includes(finding.impact))
      assert.equal(Object.hasOwn(finding, 'severity'), false)
      assert.equal(Object.hasOwn(finding, 'disposition'), false)
      assert.equal(typeof finding.category, 'string')
      assert.equal(typeof finding.invariant, 'string')
      assert.equal(typeof finding.evidence, 'string')
      assert.equal(typeof finding.fix, 'string')
      assert.ok(finding.invariant.length > 0)
      assert.ok(finding.evidence.length > 0)
      assert.ok(finding.fix.length > 0)
    }

    const securityEntry = complete.reviewCoverage.report.entries.find(
      (entry) => entry.path === 'src/secure.ts',
    )
    assert.ok(securityEntry)
    assert.deepEqual(securityEntry.evidence.security.ledgers, ['security-complete'])
    assert.equal(securityEntry.blob, security.hashes['src/secure.ts'])

    const testEntry = complete.reviewCoverage.report.entries.find(
      (entry) => entry.path === 'src/service.ts',
    )
    assert.ok(testEntry)
    assert.deepEqual(testEntry.evidence.test.ledgers, ['test-complete'])
    assert.equal(testEntry.blob, tests.hashes['src/service.ts'])

    // Refuse an existing caller-provided directory (never overwrite).
    assert.throws(
      () => createAuditCoverageFixtures(baseDir),
      /exist|already|refuse|overwrite/i,
    )
  } finally {
    if (baseDir && fs.existsSync(baseDir)) {
      fs.rmSync(baseDir, { recursive: true, force: true })
    }
  }
})

test('createAuditCoverageFixtures accepts an explicit nonexistent output directory', () => {
  const baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-cov-fix-base-'))
  fs.rmSync(baseDir, { recursive: true, force: true })
  let created
  try {
    created = createAuditCoverageFixtures(baseDir)
    assert.equal(created.baseDir, baseDir)
    assert.ok(fs.existsSync(created.missing.html))
    assert.ok(fs.existsSync(created.incomplete.html))
    assert.ok(fs.existsSync(created.complete.html))
  } finally {
    if (fs.existsSync(baseDir)) fs.rmSync(baseDir, { recursive: true, force: true })
  }
})
