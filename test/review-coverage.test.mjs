import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { loadAuditPortfolios } from '../dist/audits.js'
import { loadReviewCoverage, reviewCoveragePath } from '../dist/review-coverage.js'
import { cleanup, commitAll, gitBlob, makeRepo, scopeHash, write } from './helpers.mjs'

const COVERAGE_REL = '.atlas/review-coverage.json'
const SELF_PATH = COVERAGE_REL
const GENERATED_PROOF = 'GENERATED-PROOF'

function writeV2(root, domain, slug, files, findings, extra = {}) {
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
    dropped: [],
    rounds: [],
    ...extra,
  }
  write(root, `.atlas/audits/${slug}.json`, JSON.stringify(value, null, 2) + '\n')
  return value
}

function securityFinding(file) {
  return {
    severity: 'low',
    category: 'boundary',
    title: `${file} finding`,
    locations: [`${file}:1`],
    dataflow: 'input to sink',
    fix: 'validate it',
  }
}

function inventoryHashFor(entries) {
  const lines = entries.map((entry) => {
    const marker = entry.path === SELF_PATH
      ? GENERATED_PROOF
      : entry.blob
    return `${marker}  ${entry.path}`
  }).sort()
  return createHash('sha256').update(lines.join('\n') + '\n').digest('hex')
}

function summaryFrom(entries, invalidLedgerDetails = []) {
  let securityRequired = 0
  let securityFresh = 0
  let securityMissing = 0
  let securityStale = 0
  let securityInvalid = 0
  let testRequired = 0
  let testFresh = 0
  let testMissing = 0
  let testStale = 0
  let testInvalid = 0
  let dualRequired = 0
  let excluded = 0
  let unclassified = 0
  let conflicted = 0

  for (const entry of entries) {
    const kind = entry.classification.kind
    if (kind === 'excluded') excluded += 1
    else if (kind === 'unclassified') unclassified += 1
    else if (kind === 'conflict') conflicted += 1
    else if (kind === 'review') {
      const domains = entry.classification.domains
      const hasSecurity = Boolean(domains.security)
      const hasTest = Boolean(domains.test)
      if (hasSecurity && hasTest) dualRequired += 1
      if (hasSecurity) {
        securityRequired += 1
        const status = entry.evidence.security?.status
        if (status === 'fresh') securityFresh += 1
        else if (status === 'missing') securityMissing += 1
        else if (status === 'stale') securityStale += 1
        else if (status === 'invalid') securityInvalid += 1
      }
      if (hasTest) {
        testRequired += 1
        const status = entry.evidence.test?.status
        if (status === 'fresh') testFresh += 1
        else if (status === 'missing') testMissing += 1
        else if (status === 'stale') testStale += 1
        else if (status === 'invalid') testInvalid += 1
      }
    }
  }

  return {
    tracked: entries.length,
    securityRequired,
    securityFresh,
    securityMissing,
    securityStale,
    securityInvalid,
    testRequired,
    testFresh,
    testMissing,
    testStale,
    testInvalid,
    dualRequired,
    excluded,
    unclassified,
    conflicted,
    invalidLedgers: invalidLedgerDetails.length,
  }
}

function canonicalEntries(root, { securityStatus = 'fresh', securityLedgers = ['security-src'] } = {}) {
  const reviewEvidence = securityStatus === 'missing'
    ? { security: { status: 'missing', ledgers: [] } }
    : { security: { status: securityStatus, ledgers: securityLedgers } }

  return [
    {
      path: 'src/a.ts',
      blob: gitBlob(root, 'src/a.ts'),
      ruleIds: ['source'],
      classification: {
        kind: 'review',
        domains: { security: { unit: 'security-src' } },
      },
      evidence: reviewEvidence,
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
}

function buildReport(root, {
  verdict = 'complete',
  entries,
  units = [{ domain: 'security', slug: 'security-src', title: 'Source' }],
  invalidLedgerDetails = [],
  reportErrors = [],
  summary,
  inventoryHash,
  extra = {},
} = {}) {
  const resolvedEntries = entries ?? canonicalEntries(root, {
    securityStatus: verdict === 'incomplete' ? 'missing' : 'fresh',
    securityLedgers: verdict === 'incomplete' ? [] : ['security-src'],
  })
  const resolvedSummary = summary ?? summaryFrom(resolvedEntries, invalidLedgerDetails)
  return {
    formatVersion: 1,
    format: 'atlas-review-coverage-v1',
    verdict,
    policy: { format: 'fixture-policy-v1', hash: 'a'.repeat(64) },
    inventoryHash: inventoryHash ?? inventoryHashFor(resolvedEntries),
    units,
    summary: resolvedSummary,
    entries: resolvedEntries,
    invalidLedgerDetails,
    reportErrors,
    ...extra,
  }
}

function prepareFixtureRepo() {
  const root = makeRepo()
  write(root, 'src/a.ts', 'export const a = 1\n')
  writeV2(root, 'security', 'security-src', ['src/a.ts'], [securityFinding('src/a.ts')], {
    hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
  })
  commitAll(root)
  return root
}

function writeCoverage(root, report) {
  write(root, COVERAGE_REL, JSON.stringify(report, null, 2) + '\n')
  execFileSync('git', ['add', '--', COVERAGE_REL], { cwd: root })
}

function load(root) {
  return loadReviewCoverage(root, loadAuditPortfolios(root))
}

test('missing coverage report is unknown rather than zero coverage', () => {
  const root = prepareFixtureRepo()
  try {
    assert.ok(!fs.existsSync(reviewCoveragePath(root)))
    const portfolio = load(root)
    assert.equal(portfolio.state, 'missing')
    assert.equal(portfolio.report, null)
    assert.deepEqual(portfolio.errors, [])
    assert.deepEqual(portfolio.drift, { added: [], removed: [], changed: [] })
    // Missing must not fabricate a zero-coverage report.
    assert.equal(portfolio.report?.summary?.tracked, undefined)
  } finally {
    cleanup(root)
  }
})

test('complete and incomplete reports preserve explicit verdicts', () => {
  const root = prepareFixtureRepo()
  try {
    const complete = buildReport(root, { verdict: 'complete' })
    writeCoverage(root, complete)
    const completePortfolio = load(root)
    assert.notEqual(completePortfolio.state, 'invalid')
    assert.notEqual(completePortfolio.state, 'missing')
    assert.equal(completePortfolio.report?.verdict, 'complete')
    assert.equal(completePortfolio.report?.summary.securityRequired, 1)
    assert.equal(completePortfolio.report?.summary.securityFresh, 1)
    assert.equal(completePortfolio.report?.summary.securityMissing, 0)
    assert.equal(completePortfolio.report?.entries.length, 4)
    assert.ok(completePortfolio.report?.entries.some((entry) => entry.path === SELF_PATH))
    assert.equal(
      completePortfolio.report?.entries.find((entry) => entry.path === SELF_PATH)?.blob,
      undefined,
    )

    const incomplete = buildReport(root, { verdict: 'incomplete' })
    writeCoverage(root, incomplete)
    const incompletePortfolio = load(root)
    assert.notEqual(incompletePortfolio.state, 'invalid')
    assert.notEqual(incompletePortfolio.state, 'missing')
    assert.equal(incompletePortfolio.report?.verdict, 'incomplete')
    assert.equal(incompletePortfolio.report?.summary.securityMissing, 1)
    assert.equal(incompletePortfolio.report?.summary.securityFresh, 0)

    // complete with an explicit gap must not preserve the declared verdict.
    const completeWithGap = buildReport(root, {
      verdict: 'complete',
      entries: canonicalEntries(root, { securityStatus: 'missing', securityLedgers: [] }),
    })
    writeCoverage(root, completeWithGap)
    const rejectedComplete = load(root)
    assert.equal(rejectedComplete.state, 'invalid')
    assert.equal(rejectedComplete.report, null)

    // incomplete with zero gaps must not preserve the declared verdict.
    const incompleteNoGap = buildReport(root, {
      verdict: 'incomplete',
      entries: canonicalEntries(root, { securityStatus: 'fresh', securityLedgers: ['security-src'] }),
    })
    writeCoverage(root, incompleteNoGap)
    const rejectedIncomplete = load(root)
    assert.equal(rejectedIncomplete.state, 'invalid')
    assert.equal(rejectedIncomplete.report, null)
  } finally {
    cleanup(root)
  }
})

test('invalid report ignores every embedded fresh claim', () => {
  const root = prepareFixtureRepo()
  try {
    const entries = canonicalEntries(root, { securityStatus: 'fresh', securityLedgers: ['security-src'] })
    // Intentionally lie: declare invalid but keep a "fresh" claim and inflated fresh count.
    const report = buildReport(root, {
      verdict: 'invalid',
      entries,
      reportErrors: [{ code: 'policy-error', message: 'fixture policy failed to join inventory' }],
      summary: {
        ...summaryFrom(entries),
        securityFresh: 99,
        securityRequired: 99,
      },
    })
    writeCoverage(root, report)
    const portfolio = load(root)
    assert.equal(portfolio.state, 'invalid')
    assert.equal(portfolio.report, null)
    assert.ok(portfolio.errors.length >= 1)
    assert.ok(portfolio.errors.some((error) =>
      /policy-error|reportErrors|invalid/i.test(`${error.code} ${error.message}`),
    ))
    // No trusted report projection — embedded fresh claims are unusable.
    assert.equal(portfolio.report?.summary?.securityFresh, undefined)
  } finally {
    cleanup(root)
  }
})

test('coverage report rejects malformed JSON and future versions', () => {
  const root = prepareFixtureRepo()
  try {
    write(root, COVERAGE_REL, '{not json\n')
    execFileSync('git', ['add', '--', COVERAGE_REL], { cwd: root })
    const malformed = load(root)
    assert.equal(malformed.state, 'invalid')
    assert.equal(malformed.report, null)
    assert.ok(malformed.errors.some((error) =>
      /malformed|json|parse/i.test(`${error.code} ${error.message}`),
    ))

    const future = buildReport(root, { verdict: 'complete' })
    future.formatVersion = 99
    writeCoverage(root, future)
    const futurePortfolio = load(root)
    assert.equal(futurePortfolio.state, 'invalid')
    assert.equal(futurePortfolio.report, null)
    assert.ok(futurePortfolio.errors.some((error) =>
      /formatVersion|unsupported|version|future/i.test(`${error.code} ${error.message}`),
    ))

    const wrongFormat = buildReport(root, { verdict: 'complete' })
    wrongFormat.format = 'relayos-review-coverage-v1'
    writeCoverage(root, wrongFormat)
    const wrongFormatPortfolio = load(root)
    assert.equal(wrongFormatPortfolio.state, 'invalid')
    assert.equal(wrongFormatPortfolio.report, null)
    assert.ok(wrongFormatPortfolio.errors.some((error) =>
      /atlas-review-coverage-v1|format/i.test(`${error.code} ${error.message}`),
    ))
  } finally {
    cleanup(root)
  }
})

test('coverage report rejects duplicate paths, units, and unsafe aliases', () => {
  const root = prepareFixtureRepo()
  try {
    // Duplicate path.
    {
      const base = buildReport(root, { verdict: 'complete' })
      const dup = structuredClone(base)
      dup.entries = [...dup.entries, structuredClone(dup.entries[0])]
      dup.summary = summaryFrom(dup.entries)
      writeCoverage(root, dup)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) => /duplicate|path/i.test(`${error.code} ${error.message}`)))
    }

    // Duplicate unit slug/domain.
    {
      const base = buildReport(root, { verdict: 'complete' })
      const dup = structuredClone(base)
      dup.units = [
        { domain: 'security', slug: 'security-src', title: 'Source' },
        { domain: 'security', slug: 'security-src', title: 'Source again' },
      ]
      writeCoverage(root, dup)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) => /duplicate|unit/i.test(`${error.code} ${error.message}`)))
    }

    // Unsafe path alias (parent traversal).
    {
      const base = buildReport(root, { verdict: 'complete' })
      const unsafe = structuredClone(base)
      unsafe.entries = unsafe.entries.map((entry, index) =>
        index === 0
          ? { ...entry, path: '../outside.ts' }
          : entry,
      )
      unsafe.summary = summaryFrom(unsafe.entries)
      unsafe.inventoryHash = inventoryHashFor(unsafe.entries)
      writeCoverage(root, unsafe)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) => /unsafe|path|normalized/i.test(`${error.code} ${error.message}`)))
    }

    // Non-normalized path alias.
    {
      const base = buildReport(root, { verdict: 'complete' })
      const alias = structuredClone(base)
      alias.entries = alias.entries.map((entry, index) =>
        index === 0
          ? { ...entry, path: './src/a.ts' }
          : entry,
      )
      alias.summary = summaryFrom(alias.entries)
      alias.inventoryHash = inventoryHashFor(alias.entries)
      writeCoverage(root, alias)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) => /unsafe|path|normalized|duplicate/i.test(`${error.code} ${error.message}`)))
    }
  } finally {
    cleanup(root)
  }
})

test('coverage report recomputes summary identities and unit ownership', () => {
  const root = prepareFixtureRepo()
  try {
    // Each summary identity independently.
    const identityCases = [
      { securityFresh: 0 }, // breaks fresh+missing+stale+invalid === required
      { tracked: 99 },
      { excluded: 0 },
      { dualRequired: 1 },
      { securityRequired: 0 },
      { invalidLedgers: 1 },
    ]
    for (const patch of identityCases) {
      const base = buildReport(root, { verdict: 'complete' })
      const broken = structuredClone(base)
      broken.summary = { ...broken.summary, ...patch }
      writeCoverage(root, broken)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid', `expected invalid for summary patch ${JSON.stringify(patch)}`)
      assert.equal(portfolio.report, null)
      assert.ok(
        portfolio.errors.some((error) => /summary|identity|mismatch|recompute/i.test(`${error.code} ${error.message}`)),
        `expected summary identity diagnostic for ${JSON.stringify(patch)}; got ${JSON.stringify(portfolio.errors)}`,
      )
    }

    // Cross-domain unit ownership: security domain points at a test unit.
    {
      writeV2(root, 'test', 'test-src', ['src/a.ts'], [{
        impact: 'blocking',
        category: 'missing-invariant',
        title: 'test finding',
        invariant: 'x',
        evidence: 'y',
        fix: 'z',
        locations: ['src/a.ts:1'],
      }], {
        hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
      })
      commitAll(root, 'add test unit')

      const entries = canonicalEntries(root)
      entries[0] = {
        ...entries[0],
        classification: {
          kind: 'review',
          domains: { security: { unit: 'test-src' } },
        },
        evidence: { security: { status: 'fresh', ledgers: ['test-src'] } },
      }
      const cross = buildReport(root, {
        verdict: 'complete',
        entries,
        units: [
          { domain: 'security', slug: 'security-src', title: 'Source' },
          { domain: 'test', slug: 'test-src', title: 'Tests' },
        ],
      })
      writeCoverage(root, cross)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /unit|domain|ownership|same-domain|registered/i.test(`${error.code} ${error.message}`),
      ))
    }

    // Unknown unit slug for the domain.
    {
      const entries = canonicalEntries(root)
      entries[0] = {
        ...entries[0],
        classification: {
          kind: 'review',
          domains: { security: { unit: 'security-unknown' } },
        },
        evidence: { security: { status: 'fresh', ledgers: ['security-unknown'] } },
      }
      const unknown = buildReport(root, { verdict: 'complete', entries })
      writeCoverage(root, unknown)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /unit|unknown|registered|ownership/i.test(`${error.code} ${error.message}`),
      ))
    }

    // Excluded entry carrying domain evidence must fail closed.
    {
      const entries = canonicalEntries(root)
      entries[1] = {
        ...entries[1],
        evidence: { security: { status: 'fresh', ledgers: ['security-src'] } },
      }
      const withEvidence = buildReport(root, { verdict: 'complete', entries })
      writeCoverage(root, withEvidence)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /evidence|excluded|unclassified|conflict/i.test(`${error.code} ${error.message}`),
      ))
    }
  } finally {
    cleanup(root)
  }
})
