import assert from 'node:assert/strict'
import test from 'node:test'

import {
  attentionActions,
  auditActionQueue,
  auditActionTarget,
  auditFilesForUnit,
  auditSidebarRows,
  auditUnitEvidence,
  auditUnitRows,
  coverageCountsAvailable,
  coverageStatementText,
  domainAssurance,
  domainNavSuffix,
  gapsModeProjection,
  recentAuditUnits,
  searchUnitFiles,
  strongZeroFindingPhrase,
} from '../dist/audit-assurance.js'

const ZERO_SUMMARY = {
  tracked: 0,
  securityRequired: 0,
  securityFresh: 0,
  securityMissing: 0,
  securityStale: 0,
  securityInvalid: 0,
  testRequired: 0,
  testFresh: 0,
  testMissing: 0,
  testStale: 0,
  testInvalid: 0,
  dualRequired: 0,
  excluded: 0,
  unclassified: 0,
  conflicted: 0,
  invalidLedgers: 0,
}

function missingCoverage() {
  return {
    state: 'missing',
    report: null,
    errors: [],
    drift: { added: [], removed: [], changed: [] },
  }
}

function invalidCoverage(errors = [{ code: 'bad', message: 'broken' }]) {
  return {
    state: 'invalid',
    report: null,
    errors,
    drift: { added: [], removed: [], changed: [] },
  }
}

function coverageWithReport(report, state = 'current') {
  return {
    state,
    report,
    errors: [],
    drift: { added: [], removed: [], changed: [] },
  }
}

function makeReport(overrides = {}) {
  const summary = { ...ZERO_SUMMARY, ...(overrides.summary ?? {}) }
  return {
    formatVersion: 1,
    format: 'atlas-review-coverage-v1',
    verdict: 'complete',
    policy: { format: 'fixture-policy-v1', hash: 'a'.repeat(64) },
    inventoryHash: 'b'.repeat(64),
    units: [],
    summary,
    entries: [],
    invalidLedgerDetails: [],
    reportErrors: [],
    ...overrides,
    summary,
  }
}

function securityFinding(overrides = {}) {
  return {
    severity: 'medium',
    category: 'boundary',
    title: 'finding',
    locations: ['src/a.ts:1'],
    dataflow: 'input to sink',
    fix: 'fix it',
    disposition: 'open',
    ...overrides,
  }
}

function securityUnit(overrides = {}) {
  return {
    formatVersion: 2,
    domain: 'security',
    slug: 'security-src',
    title: 'Source',
    ruleset: 'fixture-rules',
    scannedAt: '2026-03-01T00:00:00.000Z',
    scopeHash: 'c'.repeat(40),
    fileCount: 1,
    files: ['src/a.ts'],
    hashes: { 'src/a.ts': 'd'.repeat(40) },
    evidenceRefs: [],
    droppedCount: 0,
    roundCount: 1,
    stale: false,
    findings: [],
    ...overrides,
  }
}

function testUnit(overrides = {}) {
  return {
    formatVersion: 2,
    domain: 'test',
    slug: 'test-src',
    title: 'Tests',
    ruleset: 'test-rules',
    scannedAt: '2026-03-01T00:00:00.000Z',
    scopeHash: 'e'.repeat(40),
    fileCount: 1,
    files: ['src/a.ts'],
    hashes: { 'src/a.ts': 'f'.repeat(40) },
    evidenceRefs: [],
    droppedCount: 0,
    roundCount: 1,
    stale: false,
    findings: [],
    ...overrides,
  }
}

function testFinding(overrides = {}) {
  return {
    impact: 'blocking',
    category: 'missing-invariant',
    title: 'finding',
    invariant: 'holds under concurrent load',
    evidence: 'no concurrent test',
    fix: 'add race harness',
    locations: ['src/a.ts:1'],
    ...overrides,
  }
}

const SECURITY_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const TEST_IMPACTS = ['blocking', 'warning', 'advisory']

function reviewEntry(path, domains, evidence = {}) {
  return {
    path,
    blob: '1'.repeat(40),
    ruleIds: ['source'],
    classification: { kind: 'review', domains },
    evidence,
  }
}

function assertNoCleanClaim(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value)
  assert.doesNotMatch(text, /\bclean\b/i)
  assert.doesNotMatch(text, /vulnerabilit(y|ies)[\s-]*(free|absent|none)/i)
  assert.doesNotMatch(text, /\bsecure\b/i)
  assert.doesNotMatch(text, /no vulnerabilities/i)
}

test('domain assurance fails closed when a live server omits review coverage', () => {
  const model = domainAssurance('security', undefined, [])

  assert.equal(model.portfolioState, 'missing')
  assert.equal(model.verdict, null)
  assert.equal(model.required, 0)
  assert.equal(model.fresh, 0)
  assert.equal(coverageCountsAvailable(model), false)
  assert.equal(domainNavSuffix(model).kind, 'unknown')
})

test('domain suffix priority is unknown then gaps then open then covered', () => {
  const unknownMissing = domainAssurance('security', missingCoverage(), [])
  const unknownSuffix = domainNavSuffix(unknownMissing)
  assert.equal(unknownSuffix.text, 'unknown')
  assert.equal(unknownSuffix.kind, 'unknown')
  assert.match(unknownSuffix.ariaLabel, /security/i)
  assert.match(unknownSuffix.ariaLabel, /unknown|unavailable|invalid/i)

  const unknownInvalid = domainAssurance('security', invalidCoverage(), [])
  assert.equal(domainNavSuffix(unknownInvalid).kind, 'unknown')
  assert.equal(domainNavSuffix(unknownInvalid).text, 'unknown')

  const gapped = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 2,
          securityRequired: 2,
          securityFresh: 0,
          securityMissing: 2,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
          reviewEntry('src/b.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
        ],
      }),
    ),
    [],
  )
  const gapSuffix = domainNavSuffix(gapped)
  assert.equal(gapSuffix.text, '2 gaps')
  assert.equal(gapSuffix.kind, 'gap')
  assert.match(gapSuffix.ariaLabel, /security/i)
  assert.match(gapSuffix.ariaLabel, /2/)
  assert.match(gapSuffix.ariaLabel, /gap/i)

  const open = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        findings: [securityFinding({ severity: 'high', title: 'open high', disposition: 'open' })],
      }),
    ],
  )
  const openSuffix = domainNavSuffix(open)
  assert.equal(openSuffix.text, '1 open')
  assert.equal(openSuffix.kind, 'open')
  assert.match(openSuffix.ariaLabel, /security/i)
  assert.match(openSuffix.ariaLabel, /1/)
  assert.match(openSuffix.ariaLabel, /open/i)

  const covered = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [securityUnit({ findings: [] })],
  )
  const coveredSuffix = domainNavSuffix(covered)
  assert.equal(coveredSuffix.text, 'covered')
  assert.equal(coveredSuffix.kind, 'covered')
  assert.match(coveredSuffix.ariaLabel, /security/i)
  assert.match(coveredSuffix.ariaLabel, /covered|complete/i)

  for (const suffix of [unknownSuffix, gapSuffix, openSuffix, coveredSuffix]) {
    assertNoCleanClaim(suffix)
  }
})

test('coverage and risk remain orthogonal for every unit', () => {
  const model = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [
          { domain: 'security', slug: 'covered-risky', title: 'Covered Risky' },
          { domain: 'security', slug: 'gap-quiet', title: 'Gap Quiet' },
        ],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 2,
          securityRequired: 2,
          securityFresh: 1,
          securityMissing: 1,
        },
        entries: [
          reviewEntry('src/covered.ts', { security: { unit: 'covered-risky' } }, {
            security: { status: 'fresh', ledgers: ['covered-risky'] },
          }),
          reviewEntry('src/gap.ts', { security: { unit: 'gap-quiet' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'covered-risky',
        title: 'Covered Risky',
        files: ['src/covered.ts'],
        hashes: { 'src/covered.ts': 'a'.repeat(40) },
        findings: [
          securityFinding({
            severity: 'high',
            title: 'critical surface open',
            disposition: 'open',
          }),
        ],
      }),
      // gap-quiet has no completed ledger
    ],
  )

  const rows = auditUnitRows(model)
  const covered = rows.find((row) => row.slug === 'covered-risky')
  const gap = rows.find((row) => row.slug === 'gap-quiet')
  assert.ok(covered)
  assert.ok(gap)

  assert.equal(covered.coverage.state, 'fresh')
  assert.equal(covered.coverage.required, 1)
  assert.equal(covered.coverage.fresh, 1)
  assert.equal(covered.risk.openCount, 1)
  assert.equal(covered.risk.highestOpen, 'high')
  assert.notEqual(covered.coverage.state, covered.risk.kind)

  assert.equal(gap.coverage.state, 'gap')
  assert.equal(gap.coverage.required, 1)
  assert.equal(gap.coverage.fresh, 0)
  assert.equal(gap.coverage.missing, 1)
  assert.equal(gap.risk.openCount, 0)
  assert.equal(gap.risk.highestOpen, null)

  assertNoCleanClaim(covered)
  assertNoCleanClaim(gap)
  assertNoCleanClaim(domainNavSuffix(model))
})

test('accepted risk and separate design stay visible but are not actionable', () => {
  const model = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        findings: [
          securityFinding({
            id: 'SEC-AR',
            title: 'accepted',
            disposition: 'accepted-risk',
            severity: 'high',
          }),
          securityFinding({
            id: 'SEC-SD',
            title: 'designed',
            disposition: 'separate-design',
            severity: 'critical',
          }),
        ],
      }),
    ],
  )

  assert.equal(model.openCount, 0)
  assert.equal(model.acceptedRiskCount, 1)
  assert.equal(model.separateDesignCount, 1)

  const actions = auditActionQueue(model)
  assert.equal(actions.filter((a) => a.kind === 'finding').length, 0)
  assert.equal(domainNavSuffix(model).kind, 'covered')

  const row = auditUnitRows(model)[0]
  assert.equal(row.risk.openCount, 0)
  assert.equal(row.risk.acceptedRiskCount, 1)
  assert.equal(row.risk.separateDesignCount, 1)
  assert.match(row.risk.label, /accepted/i)
  assert.match(row.risk.label, /separate/i)
  assertNoCleanClaim(model)
  assertNoCleanClaim(row)
  assertNoCleanClaim(actions)
})

test('coverage actions sort before findings and findings sort by severity', () => {
  const model = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [
          { domain: 'security', slug: 'security-a', title: 'A' },
          { domain: 'security', slug: 'security-b', title: 'B' },
        ],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 2,
          securityRequired: 2,
          securityFresh: 1,
          securityMissing: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-a' } }, {
            security: { status: 'fresh', ledgers: ['security-a'] },
          }),
          reviewEntry('src/gap.ts', { security: { unit: 'security-b' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'security-a',
        title: 'A',
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': 'a'.repeat(40) },
        findings: [
          securityFinding({ id: 'F-INFO', severity: 'info', title: 'info finding' }),
          securityFinding({ id: 'F-CRIT', severity: 'critical', title: 'critical finding' }),
          securityFinding({ id: 'F-MED', severity: 'medium', title: 'medium finding' }),
          securityFinding({ id: 'F-LOW', severity: 'low', title: 'low finding' }),
          securityFinding({ id: 'F-HIGH', severity: 'high', title: 'high finding' }),
          securityFinding({
            id: 'F-KEEP',
            severity: 'critical',
            title: 'retained critical',
            disposition: 'accepted-risk',
          }),
        ],
      }),
    ],
  )

  const actions = auditActionQueue(model)
  const kinds = actions.map((a) => a.kind)
  const firstFinding = kinds.indexOf('finding')
  assert.ok(firstFinding > 0)
  assert.ok(kinds.slice(0, firstFinding).every((k) => k === 'coverage'))
  assert.ok(kinds.slice(firstFinding).every((k) => k === 'finding'))

  const findingSeverities = actions
    .filter((a) => a.kind === 'finding')
    .map((a) => a.severity)
  assert.deepEqual(findingSeverities, ['critical', 'high', 'medium', 'low', 'info'])

  // stable tie-break: same severity ordered by title then id
  const twin = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-a', title: 'A' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-a' } }, {
            security: { status: 'fresh', ledgers: ['security-a'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'security-a',
        title: 'A',
        findings: [
          securityFinding({ id: 'B', severity: 'high', title: 'beta' }),
          securityFinding({ id: 'A', severity: 'high', title: 'alpha' }),
          securityFinding({ id: 'C', severity: 'high', title: 'alpha' }),
        ],
      }),
    ],
  )
  assert.deepEqual(
    auditActionQueue(twin)
      .filter((a) => a.kind === 'finding')
      .map((a) => a.id),
    ['A', 'C', 'B'],
  )

  assertNoCleanClaim(actions)
})

test('unit rows include registered units with no completed ledger', () => {
  const model = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [
          { domain: 'security', slug: 'security-with-ledger', title: 'With Ledger' },
          { domain: 'security', slug: 'security-no-ledger', title: 'No Ledger' },
        ],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 2,
          securityRequired: 2,
          securityFresh: 1,
          securityMissing: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-with-ledger' } }, {
            security: { status: 'fresh', ledgers: ['security-with-ledger'] },
          }),
          reviewEntry('src/b.ts', { security: { unit: 'security-no-ledger' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'security-with-ledger',
        title: 'With Ledger',
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': 'a'.repeat(40) },
      }),
    ],
  )

  const rows = auditUnitRows(model)
  assert.deepEqual(
    rows.map((r) => r.slug).sort(),
    ['security-no-ledger', 'security-with-ledger'],
  )
  const bare = rows.find((r) => r.slug === 'security-no-ledger')
  assert.equal(bare.hasLedger, false)
  assert.equal(bare.coverage.required, 1)
  assert.equal(bare.coverage.fresh, 0)
  assert.equal(bare.scannedAt, null)
  assert.equal(bare.ruleset, null)
})

test('unit rows order invalid unknown gap open severity then title', () => {
  const model = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [
          { domain: 'security', slug: 'unit-title-b', title: 'Bravo' },
          { domain: 'security', slug: 'unit-title-a', title: 'Alpha' },
          { domain: 'security', slug: 'unit-open-high', title: 'Open High' },
          { domain: 'security', slug: 'unit-open-crit', title: 'Open Crit' },
          { domain: 'security', slug: 'unit-gap', title: 'Gap' },
          { domain: 'security', slug: 'unit-invalid', title: 'Invalid' },
        ],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 6,
          securityRequired: 6,
          securityFresh: 4,
          securityMissing: 1,
          securityInvalid: 1,
        },
        entries: [
          reviewEntry('src/invalid.ts', { security: { unit: 'unit-invalid' } }, {
            security: { status: 'invalid', ledgers: ['unit-invalid'] },
          }),
          reviewEntry('src/gap.ts', { security: { unit: 'unit-gap' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
          reviewEntry('src/crit.ts', { security: { unit: 'unit-open-crit' } }, {
            security: { status: 'fresh', ledgers: ['unit-open-crit'] },
          }),
          reviewEntry('src/high.ts', { security: { unit: 'unit-open-high' } }, {
            security: { status: 'fresh', ledgers: ['unit-open-high'] },
          }),
          reviewEntry('src/a.ts', { security: { unit: 'unit-title-a' } }, {
            security: { status: 'fresh', ledgers: ['unit-title-a'] },
          }),
          reviewEntry('src/b.ts', { security: { unit: 'unit-title-b' } }, {
            security: { status: 'fresh', ledgers: ['unit-title-b'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'unit-open-crit',
        title: 'Open Crit',
        files: ['src/crit.ts'],
        findings: [securityFinding({ severity: 'critical', title: 'c' })],
      }),
      securityUnit({
        slug: 'unit-open-high',
        title: 'Open High',
        files: ['src/high.ts'],
        findings: [securityFinding({ severity: 'high', title: 'h' })],
      }),
      securityUnit({
        slug: 'unit-title-b',
        title: 'Bravo',
        files: ['src/b.ts'],
      }),
      securityUnit({
        slug: 'unit-title-a',
        title: 'Alpha',
        files: ['src/a.ts'],
      }),
    ],
  )

  // unit with no coverage assignment and no report membership is not in this fixture.
  // Missing coverage portfolio yields unknown; here we inject an extra ledger-only unit.
  const withUnknown = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [
          { domain: 'security', slug: 'unit-title-b', title: 'Bravo' },
          { domain: 'security', slug: 'unit-title-a', title: 'Alpha' },
          { domain: 'security', slug: 'unit-open-high', title: 'Open High' },
          { domain: 'security', slug: 'unit-open-crit', title: 'Open Crit' },
          { domain: 'security', slug: 'unit-gap', title: 'Gap' },
          { domain: 'security', slug: 'unit-invalid', title: 'Invalid' },
        ],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 6,
          securityRequired: 6,
          securityFresh: 4,
          securityMissing: 1,
          securityInvalid: 1,
        },
        entries: [
          reviewEntry('src/invalid.ts', { security: { unit: 'unit-invalid' } }, {
            security: { status: 'invalid', ledgers: ['unit-invalid'] },
          }),
          reviewEntry('src/gap.ts', { security: { unit: 'unit-gap' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
          reviewEntry('src/crit.ts', { security: { unit: 'unit-open-crit' } }, {
            security: { status: 'fresh', ledgers: ['unit-open-crit'] },
          }),
          reviewEntry('src/high.ts', { security: { unit: 'unit-open-high' } }, {
            security: { status: 'fresh', ledgers: ['unit-open-high'] },
          }),
          reviewEntry('src/a.ts', { security: { unit: 'unit-title-a' } }, {
            security: { status: 'fresh', ledgers: ['unit-title-a'] },
          }),
          reviewEntry('src/b.ts', { security: { unit: 'unit-title-b' } }, {
            security: { status: 'fresh', ledgers: ['unit-title-b'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'unit-open-crit',
        title: 'Open Crit',
        files: ['src/crit.ts'],
        findings: [securityFinding({ severity: 'critical', title: 'c' })],
      }),
      securityUnit({
        slug: 'unit-open-high',
        title: 'Open High',
        files: ['src/high.ts'],
        findings: [securityFinding({ severity: 'high', title: 'h' })],
      }),
      securityUnit({
        slug: 'unit-title-b',
        title: 'Bravo',
        files: ['src/b.ts'],
      }),
      securityUnit({
        slug: 'unit-title-a',
        title: 'Alpha',
        files: ['src/a.ts'],
      }),
      securityUnit({
        slug: 'unit-unknown',
        title: 'Unknown Ledger',
        files: ['src/unknown.ts'],
        findings: [],
      }),
    ],
  )

  assert.deepEqual(
    auditUnitRows(withUnknown).map((r) => r.slug),
    [
      'unit-invalid',
      'unit-unknown',
      'unit-gap',
      'unit-open-crit',
      'unit-open-high',
      'unit-title-a',
      'unit-title-b',
    ],
  )

  // unknown coverage portfolio ranks every unit unknown, ordered by title
  const unknownModel = domainAssurance(
    'security',
    missingCoverage(),
    [
      securityUnit({ slug: 'zebra', title: 'Zebra' }),
      securityUnit({ slug: 'alpha', title: 'Alpha' }),
    ],
  )
  assert.deepEqual(
    auditUnitRows(unknownModel).map((r) => r.slug),
    ['alpha', 'zebra'],
  )
  assert.ok(auditUnitRows(unknownModel).every((r) => r.coverage.state === 'unknown'))
  assert.equal(domainNavSuffix(unknownModel).kind, 'unknown')
})

test('dual-domain paths contribute independently to security and tests', () => {
  const report = makeReport({
    verdict: 'incomplete',
    units: [
      { domain: 'security', slug: 'security-src', title: 'Security Src' },
      { domain: 'test', slug: 'test-src', title: 'Test Src' },
    ],
    summary: {
      ...ZERO_SUMMARY,
      tracked: 1,
      securityRequired: 1,
      securityFresh: 1,
      testRequired: 1,
      testMissing: 1,
      dualRequired: 1,
    },
    entries: [
      reviewEntry(
        'src/shared.ts',
        {
          security: { unit: 'security-src' },
          test: { unit: 'test-src' },
        },
        {
          security: { status: 'fresh', ledgers: ['security-src'] },
          test: { status: 'missing', ledgers: [] },
        },
      ),
    ],
  })
  const coverage = coverageWithReport(report)

  const security = domainAssurance('security', coverage, [
    securityUnit({
      slug: 'security-src',
      title: 'Security Src',
      files: ['src/shared.ts'],
      hashes: { 'src/shared.ts': 'a'.repeat(40) },
    }),
  ])
  const tests = domainAssurance('test', coverage, [])

  assert.equal(security.required, 1)
  assert.equal(security.fresh, 1)
  assert.equal(security.gapCount, 0)
  assert.equal(domainNavSuffix(security).kind, 'covered')

  assert.equal(tests.required, 1)
  assert.equal(tests.fresh, 0)
  assert.equal(tests.missing, 1)
  assert.equal(tests.gapCount, 1)
  assert.equal(domainNavSuffix(tests).kind, 'gap')
  assert.equal(domainNavSuffix(tests).text, '1 gaps')

  const testFiles = auditFilesForUnit(tests, 'test-src')
  assert.deepEqual(
    testFiles.map((f) => ({ path: f.path, status: f.status })),
    [{ path: 'src/shared.ts', status: 'missing' }],
  )
  const securityFiles = auditFilesForUnit(security, 'security-src')
  assert.deepEqual(
    securityFiles.map((f) => ({ path: f.path, status: f.status })),
    [{ path: 'src/shared.ts', status: 'fresh' }],
  )
})

test('recent audits sort current accepted units by scannedAt', () => {
  const model = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [
          { domain: 'security', slug: 'accepted-new', title: 'Accepted New' },
          { domain: 'security', slug: 'accepted-old', title: 'Accepted Old' },
          { domain: 'security', slug: 'stale-unit', title: 'Stale Unit' },
          { domain: 'security', slug: 'rejected-unit', title: 'Rejected Unit' },
        ],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 4,
          securityRequired: 4,
          securityFresh: 3,
          securityMissing: 1,
        },
        entries: [
          reviewEntry('src/new.ts', { security: { unit: 'accepted-new' } }, {
            security: { status: 'fresh', ledgers: ['accepted-new'] },
          }),
          reviewEntry('src/old.ts', { security: { unit: 'accepted-old' } }, {
            security: { status: 'fresh', ledgers: ['accepted-old'] },
          }),
          reviewEntry('src/stale.ts', { security: { unit: 'stale-unit' } }, {
            security: { status: 'fresh', ledgers: ['stale-unit'] },
          }),
          reviewEntry('src/rejected.ts', { security: { unit: 'rejected-unit' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'accepted-new',
        title: 'Accepted New',
        scannedAt: '2026-06-02T00:00:00.000Z',
        files: ['src/new.ts'],
        hashes: { 'src/new.ts': '1'.repeat(40) },
      }),
      securityUnit({
        slug: 'accepted-old',
        title: 'Accepted Old',
        scannedAt: '2026-06-01T00:00:00.000Z',
        files: ['src/old.ts'],
        hashes: { 'src/old.ts': '1'.repeat(40) },
      }),
      securityUnit({
        slug: 'stale-unit',
        title: 'Stale Unit',
        scannedAt: '2026-06-03T00:00:00.000Z',
        stale: true,
        files: ['src/stale.ts'],
        hashes: { 'src/stale.ts': '1'.repeat(40) },
      }),
      securityUnit({
        slug: 'rejected-unit',
        title: 'Rejected Unit',
        scannedAt: '2026-06-04T00:00:00.000Z',
        files: ['src/other.ts'],
        hashes: { 'src/other.ts': '1'.repeat(40) },
      }),
    ],
  )

  assert.deepEqual(
    recentAuditUnits(model).map((r) => r.slug),
    ['accepted-new', 'accepted-old'],
  )

  const recent = recentAuditUnits(model)
  for (const row of recent) {
    assert.equal(row.evidenceAccepted, true)
    assert.equal(row.stale, false)
    if (row.risk.openCount === 0 && row.coverage.state === 'fresh') {
      assert.equal(
        row.outcomeLabel,
        'No actionable findings in current completed review',
      )
    }
    assertNoCleanClaim(row)
  }
})

test('test findings retain impact vocabulary and never receive security disposition or severity', () => {
  const model = domainAssurance(
    'test',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'test', slug: 'test-src', title: 'Tests' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          testRequired: 1,
          testFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { test: { unit: 'test-src' } }, {
            test: { status: 'fresh', ledgers: ['test-src'] },
          }),
        ],
      }),
    ),
    [
      testUnit({
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': '1'.repeat(40) },
        findings: [
          testFinding({ impact: 'blocking', title: 'blocks release' }),
          testFinding({ impact: 'warning', title: 'warns on flake' }),
          testFinding({ impact: 'advisory', title: 'advises coverage' }),
        ],
      }),
    ],
  )

  const findingActions = auditActionQueue(model).filter((a) => a.kind === 'finding')
  assert.equal(findingActions.length, 3)
  for (const action of findingActions) {
    assert.equal(action.domain, 'test')
    assert.ok(TEST_IMPACTS.includes(action.impact), `expected test impact, got ${action.impact}`)
    assert.equal(Object.hasOwn(action, 'disposition'), false)
    assert.equal(Object.hasOwn(action, 'severity'), false)
  }
  assert.deepEqual(
    findingActions.map((a) => a.impact),
    ['blocking', 'warning', 'advisory'],
  )

  const row = auditUnitRows(model)[0]
  assert.equal(row.risk.domain, 'test')
  assert.equal(row.risk.openCount, 3)
  assert.equal(row.risk.highestOpen, 'blocking')
  assert.match(row.risk.label, /blocking/i)
  assert.doesNotMatch(row.risk.label, /\b(critical|high|medium|low|info)\b/i)
  assert.equal(Object.hasOwn(row.risk, 'acceptedRiskCount'), false)
  assert.equal(Object.hasOwn(row.risk, 'separateDesignCount'), false)

  assert.equal(model.domain, 'test')
  assert.deepEqual(model.openByImpact, {
    blocking: 1,
    warning: 1,
    advisory: 1,
  })
  assert.equal(Object.hasOwn(model, 'openBySeverity'), false)
  assert.equal(model.openCount, 3)

  // Security still exposes severity buckets, not impact.
  const security = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': '1'.repeat(40) },
        findings: [
          securityFinding({ severity: 'high', title: 'open high', disposition: 'open' }),
        ],
      }),
    ],
  )
  assert.equal(security.domain, 'security')
  assert.equal(security.openBySeverity.high, 1)
  assert.equal(Object.hasOwn(security, 'openByImpact'), false)
  const secAction = auditActionQueue(security).find((a) => a.kind === 'finding')
  assert.equal(secAction.domain, 'security')
  assert.equal(secAction.severity, 'high')
  assert.equal(secAction.disposition, 'open')
  assert.equal(Object.hasOwn(secAction, 'impact'), false)
  assert.ok(SECURITY_SEVERITIES.includes(secAction.severity))
})

test('evidenceAccepted requires a named current v2 ledger containing the exact report blob', () => {
  const blob = '1'.repeat(40)
  const wrongBlob = '2'.repeat(40)

  // Legacy v1 ledger on an otherwise current/fresh unit is not evidenceAccepted.
  const legacyV1 = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'legacy-v1', title: 'Legacy V1' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/legacy.ts', { security: { unit: 'legacy-v1' } }, {
            security: { status: 'fresh', ledgers: ['legacy-v1'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        formatVersion: 1,
        slug: 'legacy-v1',
        title: 'Legacy V1',
        files: ['src/legacy.ts'],
        hashes: { 'src/legacy.ts': blob },
        scannedAt: '2026-06-10T00:00:00.000Z',
      }),
    ],
  )
  const legacyRow = auditUnitRows(legacyV1).find((r) => r.slug === 'legacy-v1')
  assert.ok(legacyRow)
  assert.equal(legacyRow.coverage.state, 'fresh')
  assert.equal(legacyRow.hasLedger, true)
  assert.equal(legacyRow.stale, false)
  assert.equal(legacyRow.evidenceAccepted, false)
  assert.deepEqual(recentAuditUnits(legacyV1).map((r) => r.slug), [])

  // Stale v2 ledger is rejected even when named on a fresh claim.
  const staleV2 = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'stale-v2', title: 'Stale V2' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/stale.ts', { security: { unit: 'stale-v2' } }, {
            security: { status: 'fresh', ledgers: ['stale-v2'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'stale-v2',
        title: 'Stale V2',
        stale: true,
        files: ['src/stale.ts'],
        hashes: { 'src/stale.ts': blob },
        scannedAt: '2026-06-11T00:00:00.000Z',
      }),
    ],
  )
  assert.equal(auditUnitRows(staleV2)[0].evidenceAccepted, false)
  assert.deepEqual(recentAuditUnits(staleV2).map((r) => r.slug), [])

  // Matching named current v2 ledger is accepted.
  const accepted = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'owner-unit', title: 'Owner' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/owner.ts', { security: { unit: 'owner-unit' } }, {
            security: { status: 'fresh', ledgers: ['owner-unit'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'owner-unit',
        title: 'Owner',
        files: ['src/owner.ts'],
        hashes: { 'src/owner.ts': blob },
        scannedAt: '2026-06-12T00:00:00.000Z',
      }),
    ],
  )
  const acceptedRow = auditUnitRows(accepted)[0]
  assert.equal(acceptedRow.evidenceAccepted, true)
  assert.deepEqual(recentAuditUnits(accepted).map((r) => r.slug), ['owner-unit'])
  assert.equal(
    acceptedRow.outcomeLabel,
    'No actionable findings in current completed review',
  )

  // Present v2 ledger whose slug is not named is not accepted.
  const unnamed = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [
          { domain: 'security', slug: 'owner-unit', title: 'Owner' },
          { domain: 'security', slug: 'unnamed-ledger', title: 'Unnamed' },
        ],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/owner.ts', { security: { unit: 'owner-unit' } }, {
            // Fresh claim credits only the owner; unnamed ledger is present but not listed.
            security: { status: 'fresh', ledgers: ['owner-unit'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'owner-unit',
        title: 'Owner',
        files: ['src/owner.ts'],
        hashes: { 'src/owner.ts': blob },
      }),
      securityUnit({
        slug: 'unnamed-ledger',
        title: 'Unnamed',
        files: ['src/owner.ts'],
        hashes: { 'src/owner.ts': blob },
        scannedAt: '2026-06-13T00:00:00.000Z',
      }),
    ],
  )
  const unnamedRow = auditUnitRows(unnamed).find((r) => r.slug === 'unnamed-ledger')
  assert.ok(unnamedRow)
  assert.equal(unnamedRow.evidenceAccepted, false)
  assert.ok(!recentAuditUnits(unnamed).some((r) => r.slug === 'unnamed-ledger'))

  // Present v2 ledger named but with mismatched file/hash is not accepted.
  const mismatch = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'mismatch-unit', title: 'Mismatch' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/mismatch.ts', { security: { unit: 'mismatch-unit' } }, {
            security: { status: 'fresh', ledgers: ['mismatch-unit'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'mismatch-unit',
        title: 'Mismatch',
        files: ['src/mismatch.ts'],
        hashes: { 'src/mismatch.ts': wrongBlob },
        scannedAt: '2026-06-14T00:00:00.000Z',
      }),
    ],
  )
  assert.equal(auditUnitRows(mismatch)[0].evidenceAccepted, false)
  assert.deepEqual(recentAuditUnits(mismatch).map((r) => r.slug), [])

  // Named but files array omits the path — not accepted.
  const missingFile = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'missing-file', title: 'Missing File' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/path.ts', { security: { unit: 'missing-file' } }, {
            security: { status: 'fresh', ledgers: ['missing-file'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'missing-file',
        title: 'Missing File',
        files: ['src/other.ts'],
        hashes: { 'src/other.ts': blob },
        scannedAt: '2026-06-15T00:00:00.000Z',
      }),
    ],
  )
  assert.equal(auditUnitRows(missingFile)[0].evidenceAccepted, false)

  // Supplementary named v2 evidence may be recent even when not the owner unit,
  // but does not get the complete-unit no-actionable phrase without complete coverage.
  const supplementary = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'owner-unit', title: 'Owner' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/owner.ts', { security: { unit: 'owner-unit' } }, {
            security: {
              status: 'fresh',
              ledgers: ['owner-unit', 'supplementary-ledger'],
            },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'owner-unit',
        title: 'Owner',
        files: ['src/owner.ts'],
        hashes: { 'src/owner.ts': blob },
        scannedAt: '2026-06-01T00:00:00.000Z',
      }),
      securityUnit({
        slug: 'supplementary-ledger',
        title: 'Supplementary',
        files: ['src/owner.ts'],
        hashes: { 'src/owner.ts': blob },
        scannedAt: '2026-06-20T00:00:00.000Z',
      }),
    ],
  )
  const owner = auditUnitRows(supplementary).find((r) => r.slug === 'owner-unit')
  const extra = auditUnitRows(supplementary).find((r) => r.slug === 'supplementary-ledger')
  assert.ok(owner)
  assert.ok(extra)
  assert.equal(owner.evidenceAccepted, true)
  assert.equal(extra.evidenceAccepted, true)
  assert.equal(extra.coverage.state, 'unknown')
  assert.notEqual(
    extra.outcomeLabel,
    'No actionable findings in current completed review',
  )
  assert.deepEqual(
    recentAuditUnits(supplementary).map((r) => r.slug),
    ['supplementary-ledger', 'owner-unit'],
  )
  assert.equal(
    owner.outcomeLabel,
    'No actionable findings in current completed review',
  )
})

test('assurance labels never claim clean or vulnerability absence', () => {
  const fixtures = [
    domainAssurance('security', missingCoverage(), [securityUnit()]),
    domainAssurance('security', invalidCoverage(), []),
    domainAssurance(
      'security',
      coverageWithReport(
        makeReport({
          verdict: 'complete',
          units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
          summary: {
            ...ZERO_SUMMARY,
            tracked: 1,
            securityRequired: 1,
            securityFresh: 1,
          },
          entries: [
            reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
              security: { status: 'fresh', ledgers: ['security-src'] },
            }),
          ],
        }),
      ),
      [securityUnit({ findings: [] })],
    ),
    domainAssurance(
      'test',
      coverageWithReport(
        makeReport({
          verdict: 'complete',
          units: [{ domain: 'test', slug: 'test-src', title: 'Tests' }],
          summary: {
            ...ZERO_SUMMARY,
            tracked: 1,
            testRequired: 1,
            testFresh: 1,
          },
          entries: [
            reviewEntry('src/a.ts', { test: { unit: 'test-src' } }, {
              test: { status: 'fresh', ledgers: ['test-src'] },
            }),
          ],
        }),
      ),
      [testUnit({ findings: [] })],
    ),
  ]

  for (const model of fixtures) {
    assertNoCleanClaim(domainNavSuffix(model))
    assertNoCleanClaim(auditUnitRows(model))
    assertNoCleanClaim(auditActionQueue(model))
    assertNoCleanClaim(recentAuditUnits(model))
    assertNoCleanClaim(auditSidebarRows(model))
    for (const row of auditUnitRows(model)) {
      assertNoCleanClaim(auditFilesForUnit(model, row.slug))
    }
  }
})

test('strong zero-finding outcome requires a current complete accepted review', () => {
  const report = makeReport({
    verdict: 'incomplete',
    units: [
      { domain: 'security', slug: 'security-src', title: 'Source' },
      { domain: 'test', slug: 'test-src', title: 'Tests' },
    ],
    summary: {
      ...ZERO_SUMMARY,
      tracked: 2,
      securityRequired: 1,
      securityFresh: 1,
      testRequired: 1,
      testMissing: 1,
    },
    entries: [
      reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
        security: { status: 'fresh', ledgers: ['security-src'] },
      }),
      reviewEntry('test/a.test.ts', { test: { unit: 'test-src' } }, {
        test: { status: 'missing', ledgers: [] },
      }),
    ],
  })
  const model = domainAssurance('security', coverageWithReport(report), [
    securityUnit({ hashes: { 'src/a.ts': '1'.repeat(40) }, findings: [] }),
  ])
  const row = auditUnitRows(model)[0]

  assert.equal(row.evidenceAccepted, true)
  assert.equal(row.coverage.state, 'fresh')
  assert.notEqual(
    row.outcomeLabel,
    'No actionable findings in current completed review',
  )
  assert.equal(row.risk.label, 'No open findings recorded')
})

test('invalid ledger diagnostics remain domain coverage gaps', () => {
  const report = makeReport({
    verdict: 'incomplete',
    summary: { ...ZERO_SUMMARY, invalidLedgers: 1 },
    invalidLedgerDetails: [{
      code: 'malformed-ledger',
      message: 'ledger could not be accepted',
      slug: 'security-bad',
    }],
  })
  const model = domainAssurance('security', coverageWithReport(report), [])

  assert.equal(model.gapCount, 1)
  assert.deepEqual(domainNavSuffix(model), {
    text: '1 gaps',
    kind: 'gap',
    ariaLabel: 'Security 1 coverage gaps',
  })
})

test('audit sidebar rows order overview attention gaps then registered units', () => {
  const model = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [
          { domain: 'security', slug: 'security-b', title: 'Bravo' },
          { domain: 'security', slug: 'security-a', title: 'Alpha' },
        ],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 2,
          securityRequired: 2,
          securityFresh: 1,
          securityMissing: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-a' } }, {
            security: { status: 'fresh', ledgers: ['security-a'] },
          }),
          reviewEntry('src/b.ts', { security: { unit: 'security-b' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'security-a',
        title: 'Alpha',
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': '1'.repeat(40) },
        findings: [
          securityFinding({
            severity: 'high',
            title: 'open high',
            disposition: 'open',
          }),
        ],
      }),
    ],
  )

  const rows = auditSidebarRows(model)
  assert.deepEqual(rows.slice(0, 3).map((row) => row.kind), [
    'overview',
    'attention',
    'gaps',
  ])
  assert.deepEqual(
    rows.slice(0, 3).map((row) => row.mode),
    ['overview', 'attention', 'gaps'],
  )

  const unitRows = rows.slice(3)
  assert.ok(unitRows.length >= 2)
  assert.ok(unitRows.every((row) => row.kind === 'unit'))
  assert.deepEqual(
    unitRows.map((row) => row.slug),
    auditUnitRows(model).map((row) => row.slug),
  )

  for (const row of unitRows) {
    assert.equal(typeof row.title, 'string')
    assert.ok(row.title.length > 0)
    assert.equal(typeof row.coverageLabel, 'string')
    assert.equal(typeof row.riskLabel, 'string')
    assert.ok(row.coverageLabel.length > 0)
    assert.ok(row.riskLabel.length > 0)
    // Coverage and risk stay separate axes — never a single collapsed count.
    assert.notEqual(row.coverageLabel, row.riskLabel)
    assert.doesNotMatch(row.coverageLabel, /^\d+$/)
    assert.doesNotMatch(row.riskLabel, /^\d+$/)
  }

  const overview = rows[0]
  const attention = rows[1]
  const gaps = rows[2]
  assert.equal(overview.kind, 'overview')
  assert.equal(attention.kind, 'attention')
  assert.equal(gaps.kind, 'gaps')
  assert.match(attention.suffix ?? '', /\d/)
  assert.match(gaps.suffix ?? '', /\d/)
  assertNoCleanClaim(rows)
})

test('sidebar navigation suffix priority is unknown then gaps then open then covered', () => {
  const unknown = domainAssurance('security', missingCoverage(), [])
  const unknownSidebar = auditSidebarRows(unknown)
  assert.equal(unknownSidebar[1].suffix, 'unknown')
  assert.equal(unknownSidebar[2].suffix, 'unknown')
  const gapped = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 2,
          securityRequired: 2,
          securityFresh: 0,
          securityMissing: 2,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
          reviewEntry('src/b.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        findings: [
          securityFinding({ severity: 'critical', title: 'one' }),
          securityFinding({ severity: 'high', title: 'two' }),
          securityFinding({ severity: 'medium', title: 'three' }),
        ],
      }),
    ],
  )
  const open = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        findings: [
          securityFinding({ severity: 'low', title: 'open low', disposition: 'open' }),
          securityFinding({
            severity: 'high',
            title: 'accepted',
            disposition: 'accepted-risk',
          }),
        ],
      }),
    ],
  )
  const covered = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [securityUnit({ findings: [] })],
  )

  assert.equal(domainNavSuffix(unknown).text, 'unknown')
  assert.equal(domainNavSuffix(gapped).text, '2 gaps')
  assert.equal(domainNavSuffix(open).text, '1 open')
  assert.equal(domainNavSuffix(covered).text, 'covered')

  // Raw finding totals must never become the primary suffix.
  const gappedFindings = 3
  const openFindings = 2
  assert.notEqual(domainNavSuffix(gapped).text, String(gappedFindings))
  assert.notEqual(domainNavSuffix(open).text, String(openFindings))
  assert.notEqual(domainNavSuffix(covered).text, '0')
  for (const model of [unknown, gapped, open, covered]) {
    const suffix = domainNavSuffix(model)
    assert.doesNotMatch(suffix.text, /^\d+$/)
    assert.match(suffix.text, /^(unknown|\d+ gaps|\d+ open|covered)$/)
    assertNoCleanClaim(suffix)
  }

  const sidebar = auditSidebarRows(gapped)
  assert.deepEqual(sidebar.slice(0, 3).map((row) => row.kind), [
    'overview',
    'attention',
    'gaps',
  ])
})

test('attention mode contains gaps before open findings and excludes retained risk', () => {
  const model = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [
          { domain: 'security', slug: 'security-gap', title: 'Gap Unit' },
          { domain: 'security', slug: 'security-open', title: 'Open Unit' },
        ],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 2,
          securityRequired: 2,
          securityFresh: 1,
          securityMissing: 1,
        },
        entries: [
          reviewEntry('src/gap.ts', { security: { unit: 'security-gap' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
          reviewEntry('src/open.ts', { security: { unit: 'security-open' } }, {
            security: { status: 'fresh', ledgers: ['security-open'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'security-open',
        title: 'Open Unit',
        files: ['src/open.ts'],
        hashes: { 'src/open.ts': '1'.repeat(40) },
        findings: [
          securityFinding({
            id: 'F-AR',
            severity: 'critical',
            title: 'accepted retained',
            disposition: 'accepted-risk',
          }),
          securityFinding({
            id: 'F-SD',
            severity: 'high',
            title: 'separate design retained',
            disposition: 'separate-design',
          }),
          securityFinding({
            id: 'F-INFO',
            severity: 'info',
            title: 'info open',
            disposition: 'open',
          }),
          securityFinding({
            id: 'F-CRIT',
            severity: 'critical',
            title: 'critical open',
            disposition: 'open',
          }),
          securityFinding({
            id: 'F-MED',
            severity: 'medium',
            title: 'medium open',
            disposition: 'open',
          }),
        ],
      }),
    ],
  )

  const actions = attentionActions(model)
  assert.ok(actions.length >= 2)
  assert.equal(actions[0].kind, 'coverage')
  assert.equal(actions[0].path, 'src/gap.ts')
  assert.equal(actions[0].status, 'missing')

  const findings = actions.filter((a) => a.kind === 'finding')
  assert.deepEqual(
    findings.map((a) => a.severity),
    ['critical', 'medium', 'info'],
  )
  assert.deepEqual(
    findings.map((a) => a.id),
    ['F-CRIT', 'F-MED', 'F-INFO'],
  )
  for (const action of findings) {
    assert.equal(action.disposition, 'open')
  }
  assert.equal(
    actions.some((a) => a.kind === 'finding' && /accepted|separate/i.test(a.title)),
    false,
  )
  assert.equal(
    actions.some((a) => a.kind === 'finding' && a.id === 'F-AR'),
    false,
  )
  assert.equal(
    actions.some((a) => a.kind === 'finding' && a.id === 'F-SD'),
    false,
  )
  // Coverage gaps always precede open findings in attention mode.
  const firstFinding = actions.findIndex((a) => a.kind === 'finding')
  assert.ok(firstFinding > 0)
  assert.ok(actions.slice(0, firstFinding).every((a) => a.kind === 'coverage'))
  assertNoCleanClaim(actions)
})

test('gaps mode contains already fresh and missing counts without hiding either', () => {
  const model = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [
          { domain: 'security', slug: 'security-a', title: 'A' },
          { domain: 'security', slug: 'security-b', title: 'B' },
        ],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 3,
          securityRequired: 3,
          securityFresh: 1,
          securityMissing: 2,
        },
        entries: [
          reviewEntry('src/fresh.ts', { security: { unit: 'security-a' } }, {
            security: { status: 'fresh', ledgers: ['security-a'] },
          }),
          reviewEntry('src/miss-b.ts', { security: { unit: 'security-b' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
          reviewEntry('src/miss-a.ts', { security: { unit: 'security-a' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'security-a',
        title: 'A',
        files: ['src/fresh.ts'],
        hashes: { 'src/fresh.ts': '1'.repeat(40) },
      }),
    ],
  )

  const gaps = gapsModeProjection(model)
  assert.equal(gaps.required, 3)
  assert.equal(gaps.fresh, 1)
  assert.equal(gaps.missing, 2)
  // Numerator/denominator stay explicit — fresh is not hidden by gaps mode.
  assert.equal(gaps.numerator, 1)
  assert.equal(gaps.denominator, 3)
  assert.deepEqual(
    gaps.rows.map((r) => ({ path: r.path, status: r.status })),
    [
      { path: 'src/miss-a.ts', status: 'missing' },
      { path: 'src/miss-b.ts', status: 'missing' },
    ],
  )
  assert.equal(gaps.rows.some((r) => r.status === 'fresh'), false)
  assertNoCleanClaim(gaps)
})

test('unit file rows are searchable stable and domain-specific', () => {
  const report = makeReport({
    verdict: 'incomplete',
    units: [
      { domain: 'security', slug: 'security-src', title: 'Security Src' },
      { domain: 'test', slug: 'test-src', title: 'Test Src' },
    ],
    summary: {
      ...ZERO_SUMMARY,
      tracked: 3,
      securityRequired: 2,
      securityFresh: 1,
      securityMissing: 1,
      testRequired: 1,
      testMissing: 1,
      dualRequired: 1,
    },
    entries: [
      reviewEntry(
        'src/shared.ts',
        {
          security: { unit: 'security-src' },
          test: { unit: 'test-src' },
        },
        {
          security: { status: 'fresh', ledgers: ['security-src'] },
          test: { status: 'missing', ledgers: [] },
        },
      ),
      reviewEntry('src/security-only.ts', { security: { unit: 'security-src' } }, {
        security: { status: 'missing', ledgers: [] },
      }),
      reviewEntry('test/only.test.ts', { test: { unit: 'test-src' } }, {
        test: { status: 'missing', ledgers: [] },
      }),
    ],
  })
  const coverage = coverageWithReport(report)
  const security = domainAssurance('security', coverage, [
    securityUnit({
      slug: 'security-src',
      title: 'Security Src',
      files: ['src/shared.ts', 'src/security-only.ts'],
      hashes: {
        'src/shared.ts': '1'.repeat(40),
        'src/security-only.ts': '1'.repeat(40),
      },
    }),
  ])
  const tests = domainAssurance('test', coverage, [])

  const securityFiles = auditFilesForUnit(security, 'security-src')
  assert.deepEqual(
    securityFiles.map((f) => f.path),
    ['src/security-only.ts', 'src/shared.ts'],
  )
  assert.equal(securityFiles.some((f) => f.path === 'test/only.test.ts'), false)

  const filtered = searchUnitFiles(security, 'security-src', 'shared')
  assert.deepEqual(
    filtered.map((f) => f.path),
    ['src/shared.ts'],
  )
  assert.equal(searchUnitFiles(security, 'security-src', 'ONLY').length, 1)
  assert.equal(searchUnitFiles(security, 'security-src', 'only.test').length, 0)
  assert.equal(searchUnitFiles(security, 'security-src', 'missing-path-xyz').length, 0)

  const testFiles = searchUnitFiles(tests, 'test-src', '')
  assert.deepEqual(
    testFiles.map((f) => f.path),
    ['src/shared.ts', 'test/only.test.ts'],
  )
  assert.equal(testFiles.some((f) => f.path === 'src/security-only.ts'), false)
})

test('unit evidence exposes ruleset scan scope rounds refs and acceptance', () => {
  const blob = '1'.repeat(40)
  const model = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        slug: 'security-src',
        title: 'Source',
        ruleset: 'fixture-ruleset-v3',
        scannedAt: '2026-04-15T12:34:56.000Z',
        scopeHash: 'ab'.repeat(20),
        roundCount: 3,
        evidenceRefs: ['audits/evidence/src-a.json', 'audits/notes/src-a.md'],
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': blob },
        findings: [],
      }),
    ],
  )

  const evidence = auditUnitEvidence(model, 'security-src')
  assert.ok(evidence)
  assert.equal(evidence.slug, 'security-src')
  assert.equal(evidence.ruleset, 'fixture-ruleset-v3')
  assert.equal(evidence.scannedAt, '2026-04-15T12:34:56.000Z')
  assert.equal(evidence.scopeHash, 'ab'.repeat(20))
  assert.equal(evidence.roundCount, 3)
  assert.deepEqual(evidence.evidenceRefs, [
    'audits/evidence/src-a.json',
    'audits/notes/src-a.md',
  ])
  assert.equal(evidence.evidenceAccepted, true)
  assert.equal(evidence.hasLedger, true)
  assert.equal(evidence.stale, false)
  assert.match(evidence.acceptanceLabel, /accepted/i)

  const bare = auditUnitEvidence(model, 'does-not-exist')
  assert.equal(bare, null)

  // Registered unit without a ledger exposes null metadata and not-accepted.
  const noLedger = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [{ domain: 'security', slug: 'security-empty', title: 'Empty' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityMissing: 1,
        },
        entries: [
          reviewEntry('src/empty.ts', { security: { unit: 'security-empty' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
        ],
      }),
    ),
    [],
  )
  const emptyEvidence = auditUnitEvidence(noLedger, 'security-empty')
  assert.ok(emptyEvidence)
  assert.equal(emptyEvidence.hasLedger, false)
  assert.equal(emptyEvidence.ruleset, null)
  assert.equal(emptyEvidence.scannedAt, null)
  assert.equal(emptyEvidence.scopeHash, null)
  assert.equal(emptyEvidence.roundCount, null)
  assert.deepEqual(emptyEvidence.evidenceRefs, [])
  assert.equal(emptyEvidence.evidenceAccepted, false)
})

test('zero findings wording requires complete current coverage', () => {
  const STRONG = 'No actionable findings in current completed review'
  const blob = '1'.repeat(40)

  const completeCurrent = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': blob },
        findings: [],
      }),
    ],
  )
  assert.equal(strongZeroFindingPhrase(completeCurrent), STRONG)
  assert.equal(coverageStatementText(completeCurrent).kind, 'complete')
  assert.match(coverageStatementText(completeCurrent).text, /complete/i)
  assert.equal(
    auditUnitRows(completeCurrent)[0].outcomeLabel,
    STRONG,
  )

  const missing = domainAssurance(
    'security',
    missingCoverage(),
    [securityUnit({ findings: [] })],
  )
  assert.equal(strongZeroFindingPhrase(missing), null)
  assert.equal(coverageStatementText(missing).kind, 'missing')
  assert.equal(
    coverageStatementText(missing).text,
    'Coverage unknown because no review coverage report exists',
  )
  assert.notEqual(auditUnitRows(missing)[0].outcomeLabel, STRONG)

  const invalid = domainAssurance(
    'security',
    invalidCoverage([{ code: 'bad-report', message: 'broken report' }]),
    [securityUnit({ findings: [] })],
  )
  assert.equal(strongZeroFindingPhrase(invalid), null)
  assert.equal(coverageStatementText(invalid).kind, 'invalid')
  assert.match(coverageStatementText(invalid).text, /invalid|diagnostic|untrusted|broken/i)
  assert.notEqual(auditUnitRows(invalid)[0].outcomeLabel, STRONG)

  const incomplete = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'incomplete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 2,
          securityRequired: 2,
          securityFresh: 1,
          securityMissing: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
          reviewEntry('src/b.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'missing', ledgers: [] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': blob },
        findings: [],
      }),
    ],
  )
  assert.equal(strongZeroFindingPhrase(incomplete), null)
  assert.equal(coverageStatementText(incomplete).kind, 'incomplete')
  assert.match(coverageStatementText(incomplete).text, /incomplete|missing/i)
  assert.notEqual(auditUnitRows(incomplete)[0].outcomeLabel, STRONG)

  const stale = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
      'stale',
    ),
    [
      securityUnit({
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': blob },
        findings: [],
      }),
    ],
  )
  assert.equal(strongZeroFindingPhrase(stale), null)
  assert.equal(coverageStatementText(stale).kind, 'stale')
  assert.match(coverageStatementText(stale).text, /stale|not current|changed/i)
  assert.notEqual(auditUnitRows(stale)[0].outcomeLabel, STRONG)

  // Zero open with retained risk still qualifies when coverage is complete/current/accepted.
  const retainedOnly = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': blob },
        findings: [
          securityFinding({
            severity: 'high',
            title: 'accepted',
            disposition: 'accepted-risk',
          }),
        ],
      }),
    ],
  )
  assert.equal(strongZeroFindingPhrase(retainedOnly), STRONG)
  assert.equal(retainedOnly.openCount, 0)
  assert.equal(retainedOnly.acceptedRiskCount, 1)

  // Open findings block the strong phrase even with complete coverage.
  const withOpen = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [
      securityUnit({
        files: ['src/a.ts'],
        hashes: { 'src/a.ts': blob },
        findings: [securityFinding({ severity: 'low', disposition: 'open' })],
      }),
    ],
  )
  assert.equal(strongZeroFindingPhrase(withOpen), null)

  // Empty portfolio without units: no strong phrase; explicit no-units semantics.
  const noUnits = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [],
        summary: { ...ZERO_SUMMARY, tracked: 0 },
        entries: [],
      }),
    ),
    [],
  )
  assert.equal(strongZeroFindingPhrase(noUnits), null)
  assert.equal(noUnits.unitRows.length, 0)
})

test('trusted coverage counts are unavailable for missing and invalid portfolios', () => {
  // Missing/invalid portfolios must not surface synthetic 0/0 denominators.
  // Current and stale portfolios keep trusted numeric coverage facts.
  const missing = domainAssurance('security', missingCoverage(), [])
  const invalid = domainAssurance(
    'security',
    invalidCoverage([{ code: 'bad', message: 'broken report' }]),
    [],
  )
  const current = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
    ),
    [securityUnit()],
  )
  const stale = domainAssurance(
    'security',
    coverageWithReport(
      makeReport({
        verdict: 'complete',
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
        summary: {
          ...ZERO_SUMMARY,
          tracked: 1,
          securityRequired: 1,
          securityFresh: 1,
        },
        entries: [
          reviewEntry('src/a.ts', { security: { unit: 'security-src' } }, {
            security: { status: 'fresh', ledgers: ['security-src'] },
          }),
        ],
      }),
      'stale',
    ),
    [securityUnit()],
  )

  assert.equal(coverageCountsAvailable(missing), false)
  assert.equal(coverageCountsAvailable(invalid), false)
  assert.equal(coverageCountsAvailable(current), true)
  assert.equal(coverageCountsAvailable(stale), true)

  // Untrusted portfolios still expose zero counts in the model, but UI must
  // consult this gate rather than rendering those zeros as facts.
  assert.equal(missing.required, 0)
  assert.equal(missing.fresh, 0)
  assert.equal(invalid.required, 0)
  assert.equal(invalid.fresh, 0)
})

test('action targeting sends coverage paths to code jump and findings to units', () => {
  // Coverage with a nonempty path always code-jumps — even when unitSlug is set.
  assert.deepEqual(
    auditActionTarget({
      kind: 'coverage',
      id: 'coverage::security-src::src/a.ts',
      unitSlug: 'security-src',
      path: 'src/a.ts',
      status: 'missing',
      label: 'Source: src/a.ts missing evidence',
    }),
    { kind: 'code-jump', path: 'src/a.ts' },
  )

  // Orphan/unassigned coverage path also code-jumps.
  assert.deepEqual(
    auditActionTarget({
      kind: 'coverage',
      id: 'coverage::unclassified::src/orphan.ts',
      unitSlug: '',
      path: 'src/orphan.ts',
      status: 'unclassified',
      label: 'src/orphan.ts: unclassified path',
    }),
    { kind: 'code-jump', path: 'src/orphan.ts' },
  )

  // Coverage without a path falls back to gaps mode.
  assert.deepEqual(
    auditActionTarget({
      kind: 'coverage',
      id: 'coverage::security-src::',
      unitSlug: 'security-src',
      path: '',
      status: 'missing',
      label: 'Source: missing evidence',
    }),
    { kind: 'gaps' },
  )

  // Security finding actions target their unit.
  assert.deepEqual(
    auditActionTarget({
      kind: 'finding',
      domain: 'security',
      id: 'SEC-1',
      unitSlug: 'security-src',
      severity: 'high',
      title: 'open high',
      disposition: 'open',
      label: 'high: open high',
    }),
    { kind: 'unit', unitSlug: 'security-src' },
  )

  // Test finding actions target their unit (impact vocabulary, not severity).
  assert.deepEqual(
    auditActionTarget({
      kind: 'finding',
      domain: 'test',
      id: 'test-src:race:blocking',
      unitSlug: 'test-src',
      impact: 'blocking',
      title: 'race',
      label: 'blocking: race',
    }),
    { kind: 'unit', unitSlug: 'test-src' },
  )
})
