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

function excludedEntry(root, repoPath, ruleId, category, reason) {
  return {
    path: repoPath,
    blob: gitBlob(root, repoPath),
    ruleIds: [ruleId],
    classification: {
      kind: 'excluded',
      ruleId,
      category,
      reason,
    },
    evidence: {},
  }
}

function rebuildCanonicalAfterMutation(root, { securityStatus = 'fresh', securityLedgers = ['security-src'] } = {}) {
  // Inventory must match after ledger/source mutations: re-read every tracked
  // blob while preserving the security claim under test.
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
    excludedEntry(root, '.atlas/config.json', 'fixture-config', 'fixture', 'fixture configuration'),
    excludedEntry(root, '.atlas/audits/security-src.json', 'generated-ledger', 'generated', 'ledger under test'),
  ]
}

test('coverage inventory detects added removed and changed tracked paths', () => {
  const root = prepareFixtureRepo()
  try {
    const initial = buildReport(root, { verdict: 'complete' })
    writeCoverage(root, initial)
    const current = load(root)
    assert.equal(current.state, 'current')
    assert.equal(current.report?.verdict, 'complete')
    assert.deepEqual(current.drift, { added: [], removed: [], changed: [] })

    write(root, 'src/added.ts', 'export const added = 1\n')
    write(root, 'src/a.ts', 'export const a = 2\n')
    fs.unlinkSync(path.join(root, '.atlas/config.json'))
    commitAll(root, 'add remove and change tracked paths')

    // Keep the coverage report itself staged so the self path remains tracked.
    writeCoverage(root, initial)
    const portfolio = load(root)
    assert.equal(portfolio.state, 'stale')
    assert.ok(portfolio.report)
    assert.deepEqual(portfolio.drift.added, ['src/added.ts'])
    assert.deepEqual(portfolio.drift.removed, ['.atlas/config.json'])
    assert.deepEqual(portfolio.drift.changed, ['src/a.ts'])
  } finally {
    cleanup(root)
  }
})

test('coverage inventory is NUL-safe for newline and option-like paths', () => {
  const root = prepareFixtureRepo()
  try {
    const newlinePath = 'src/line\nbreak.ts'
    const optionPath = '--option.ts'
    write(root, newlinePath, 'export const lineBreak = 1\n')
    write(root, optionPath, 'export const option = 1\n')
    commitAll(root, 'add NUL-hostile paths')

    const entries = [
      ...canonicalEntries(root),
      excludedEntry(root, newlinePath, 'newline-path', 'fixture', 'newline in path'),
      excludedEntry(root, optionPath, 'option-path', 'fixture', 'option-like path'),
    ]
    const report = buildReport(root, { verdict: 'complete', entries })
    writeCoverage(root, report)
    const portfolio = load(root)
    assert.equal(portfolio.state, 'current')
    const paths = portfolio.report?.entries.map((entry) => entry.path) ?? []
    assert.ok(paths.includes(newlinePath))
    assert.ok(paths.includes(optionPath))
    assert.equal(paths.filter((item) => item === newlinePath).length, 1)
    assert.equal(paths.filter((item) => item === optionPath).length, 1)
  } finally {
    cleanup(root)
  }
})

test('coverage inventory uses index blobs but rehashes unstaged bytes', () => {
  const root = prepareFixtureRepo()
  try {
    // Stage v1, then leave unstaged v2 in the worktree.
    write(root, 'src/a.ts', 'export const a = staged\n')
    execFileSync('git', ['add', '--', 'src/a.ts'], { cwd: root })
    const stagedBlob = gitBlob(root, 'src/a.ts')
    write(root, 'src/a.ts', 'export const a = unstaged\n')
    const worktreeBlob = gitBlob(root, 'src/a.ts')
    assert.notEqual(stagedBlob, worktreeBlob)

    // Report claims the staged blob while the worktree has moved on.
    writeV2(root, 'security', 'security-src', ['src/a.ts'], [securityFinding('src/a.ts')], {
      hashes: { 'src/a.ts': worktreeBlob },
      scope_hash: scopeHash(root, ['src/a.ts']),
    })
    execFileSync('git', ['add', '--', '.atlas/audits/security-src.json'], { cwd: root })

    const entries = canonicalEntries(root)
    entries[0] = {
      ...entries[0],
      blob: stagedBlob,
      evidence: { security: { status: 'fresh', ledgers: ['security-src'] } },
    }
    // Exclude entries must use current worktree blobs for clean files; only
    // src/a.ts is dirty and intentionally carries the stale staged blob.
    const report = buildReport(root, {
      verdict: 'complete',
      entries: [
        entries[0],
        entries[1],
        {
          ...entries[2],
          blob: gitBlob(root, '.atlas/config.json'),
        },
        {
          ...entries[3],
          blob: gitBlob(root, '.atlas/audits/security-src.json'),
        },
      ],
    })
    writeCoverage(root, report)
    const portfolio = load(root)
    assert.equal(portfolio.state, 'stale')
    assert.deepEqual(portfolio.drift.changed, ['src/a.ts'])
    assert.deepEqual(portfolio.drift.added, [])
    assert.deepEqual(portfolio.drift.removed, [])
  } finally {
    cleanup(root)
  }
})

test('coverage inventory rejects symlinks gitlinks and unresolved index stages', () => {
  // Symlink mode 120000.
  {
    const root = prepareFixtureRepo()
    try {
      const outside = fs.mkdtempSync(path.join(path.dirname(root), 'repo-atlas-link-'))
      fs.writeFileSync(path.join(outside, 'target.ts'), 'export {}\n')
      fs.symlinkSync(path.join(outside, 'target.ts'), path.join(root, 'src/link.ts'))
      execFileSync('git', ['add', '--', 'src/link.ts'], { cwd: root })
      const report = buildReport(root, { verdict: 'complete' })
      writeCoverage(root, report)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /symlink|120000|mode|unsafe/i.test(`${error.code} ${error.message}`),
      ))
      cleanup(outside)
    } finally {
      cleanup(root)
    }
  }

  // Gitlink mode 160000.
  {
    const root = prepareFixtureRepo()
    try {
      const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
      execFileSync('git', ['update-index', '--add', '--cacheinfo', `160000,${head},vendor/lib`], { cwd: root })
      const report = buildReport(root, { verdict: 'complete' })
      writeCoverage(root, report)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /gitlink|submodule|160000|mode|unsafe/i.test(`${error.code} ${error.message}`),
      ))
    } finally {
      cleanup(root)
    }
  }

  // Each unresolved merge stage must fail independently; one earlier stage
  // must not mask a parser that accidentally accepts another.
  for (const stage of [1, 2, 3]) {
    const root = prepareFixtureRepo()
    try {
      const blob = gitBlob(root, 'src/a.ts')
      const info = `100644 ${blob} ${stage}\tsrc/conflicted.ts\n`
      execFileSync('git', ['update-index', '--index-info'], { cwd: root, input: info })
      const report = buildReport(root, { verdict: 'complete' })
      writeCoverage(root, report)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid', `merge stage ${stage} must fail closed`)
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /unresolved|stage|conflict|index/i.test(`${error.code} ${error.message}`),
      ), `missing unresolved-index diagnostic for stage ${stage}`)
    } finally {
      cleanup(root)
    }
  }
})

test('GENERATED-PROOF marker is accepted only for the exact self entry', () => {
  const root = prepareFixtureRepo()
  try {
    // Canonical self entry omits blob and is current.
    const complete = buildReport(root, { verdict: 'complete' })
    writeCoverage(root, complete)
    const ok = load(root)
    assert.equal(ok.state, 'current')
    assert.equal(
      ok.report?.entries.find((entry) => entry.path === SELF_PATH)?.blob,
      undefined,
    )

    // Any non-self entry that omits its blob is structurally invalid.
    const missingBlob = structuredClone(complete)
    missingBlob.entries = missingBlob.entries.map((entry) => {
      if (entry.path === 'src/a.ts') {
        const { blob: _blob, ...rest } = entry
        return rest
      }
      return entry
    })
    writeCoverage(root, missingBlob)
    const rejected = load(root)
    assert.equal(rejected.state, 'invalid')
    assert.equal(rejected.report, null)
    assert.ok(rejected.errors.some((error) =>
      /blob|required|generated-proof|self/i.test(`${error.code} ${error.message}`),
    ))

    // Self entry with a concrete blob is not the reserved generated-proof form.
    const selfWithBlob = structuredClone(complete)
    selfWithBlob.entries = selfWithBlob.entries.map((entry) =>
      entry.path === SELF_PATH
        ? { ...entry, blob: 'a'.repeat(40) }
        : entry,
    )
    selfWithBlob.inventoryHash = inventoryHashFor(selfWithBlob.entries)
    writeCoverage(root, selfWithBlob)
    const selfRejected = load(root)
    assert.equal(selfRejected.state, 'invalid')
    assert.equal(selfRejected.report, null)
    assert.ok(selfRejected.errors.some((error) =>
      /generated-proof|self|blob/i.test(`${error.code} ${error.message}`),
    ))
  } finally {
    cleanup(root)
  }
})

test('fresh evidence requires a current v2 same-domain ledger containing the exact blob', () => {
  const mutations = [
    {
      name: 'domain',
      apply(root) {
        const file = path.join(root, '.atlas/audits/security-src.json')
        const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
        raw.domain = 'test'
        raw.findings = [{
          impact: 'blocking',
          category: 'missing-invariant',
          title: 'cross domain',
          invariant: 'x',
          evidence: 'y',
          fix: 'z',
          locations: ['src/a.ts:1'],
        }]
        fs.writeFileSync(file, JSON.stringify(raw, null, 2) + '\n')
      },
    },
    {
      name: 'scope',
      apply(root) {
        write(root, 'src/other.ts', 'export const other = 1\n')
        writeV2(root, 'security', 'security-src', ['src/other.ts'], [securityFinding('src/other.ts')], {
          hashes: { 'src/other.ts': gitBlob(root, 'src/other.ts') },
        })
      },
    },
    {
      name: 'hash',
      apply(root) {
        writeV2(root, 'security', 'security-src', ['src/a.ts'], [securityFinding('src/a.ts')], {
          hashes: { 'src/a.ts': 'b'.repeat(40) },
        })
      },
    },
    {
      name: 'version',
      apply(root) {
        const file = path.join(root, '.atlas/audits/security-src.json')
        const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
        delete raw.domain
        delete raw.reviewState
        raw.formatVersion = 1
        raw.format = 'atlas-audit-v1'
        raw.finalPass = true
        delete raw.hashes
        fs.writeFileSync(file, JSON.stringify(raw, null, 2) + '\n')
      },
    },
    {
      name: 'staleness',
      apply(root) {
        const file = path.join(root, '.atlas/audits/security-src.json')
        const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
        raw.scope_hash = 'c'.repeat(40)
        fs.writeFileSync(file, JSON.stringify(raw, null, 2) + '\n')
      },
    },
  ]

  for (const mutation of mutations) {
    const root = prepareFixtureRepo()
    try {
      mutation.apply(root)
      commitAll(root, `mutate ledger ${mutation.name}`)
      const entries = rebuildCanonicalAfterMutation(root)
      // Scope mutation tracks an extra file that must appear in inventory.
      if (mutation.name === 'scope') {
        entries.push(excludedEntry(root, 'src/other.ts', 'other-source', 'fixture', 'scope mutation helper'))
      }
      const report = buildReport(root, {
        verdict: 'complete',
        entries,
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
      })
      writeCoverage(root, report)
      const portfolio = load(root)
      assert.equal(
        portfolio.state,
        'invalid',
        `expected invalid fresh claim after ${mutation.name} mutation; got ${portfolio.state} ${JSON.stringify(portfolio.errors)}`,
      )
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /fresh|evidence|ledger|domain|hash|stale|version|v2|blob/i.test(`${error.code} ${error.message}`),
      ), `missing fresh-evidence diagnostic for ${mutation.name}: ${JSON.stringify(portfolio.errors)}`)
    } finally {
      cleanup(root)
    }
  }
})

test('unknown cross-domain and stale ledger references fail closed', () => {
  // Nonexistent slug.
  {
    const root = prepareFixtureRepo()
    try {
      const entries = canonicalEntries(root, {
        securityStatus: 'fresh',
        securityLedgers: ['security-missing'],
      })
      entries[0] = {
        ...entries[0],
        classification: {
          kind: 'review',
          domains: { security: { unit: 'security-src' } },
        },
        evidence: { security: { status: 'fresh', ledgers: ['security-missing'] } },
      }
      const report = buildReport(root, { verdict: 'complete', entries })
      writeCoverage(root, report)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /unknown|missing|ledger|security-missing|not found|registered/i.test(`${error.code} ${error.message}`),
      ))
    } finally {
      cleanup(root)
    }
  }

  // Cross-domain: Security evidence names a Tests ledger slug.
  {
    const root = prepareFixtureRepo()
    try {
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
      commitAll(root, 'add test ledger')
      const entries = [
        {
          path: 'src/a.ts',
          blob: gitBlob(root, 'src/a.ts'),
          ruleIds: ['source'],
          classification: {
            kind: 'review',
            domains: { security: { unit: 'security-src' } },
          },
          evidence: { security: { status: 'fresh', ledgers: ['test-src'] } },
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
        excludedEntry(root, '.atlas/config.json', 'fixture-config', 'fixture', 'fixture configuration'),
        excludedEntry(root, '.atlas/audits/security-src.json', 'generated-ledger', 'generated', 'security ledger'),
        excludedEntry(root, '.atlas/audits/test-src.json', 'generated-ledger', 'generated', 'test ledger'),
      ]
      const report = buildReport(root, {
        verdict: 'complete',
        entries,
        units: [
          { domain: 'security', slug: 'security-src', title: 'Source' },
          { domain: 'test', slug: 'test-src', title: 'Tests' },
        ],
      })
      writeCoverage(root, report)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /cross-domain|same-domain|domain|ledger|test-src/i.test(`${error.code} ${error.message}`),
      ))
    } finally {
      cleanup(root)
    }
  }

  // Missing claim with a non-empty ledger list is impossible.
  {
    const root = prepareFixtureRepo()
    try {
      const entries = canonicalEntries(root, {
        securityStatus: 'missing',
        securityLedgers: [],
      })
      entries[0] = {
        ...entries[0],
        evidence: { security: { status: 'missing', ledgers: ['security-src'] } },
      }
      const report = buildReport(root, { verdict: 'incomplete', entries })
      writeCoverage(root, report)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /missing|ledger|empty/i.test(`${error.code} ${error.message}`),
      ))
    } finally {
      cleanup(root)
    }
  }
})

test('coverage loading never follows source or ledger symlinks', () => {
  // Report path symlink.
  {
    const root = prepareFixtureRepo()
    try {
      const outside = fs.mkdtempSync(path.join(path.dirname(root), 'repo-atlas-canary-'))
      const canary = path.join(outside, 'review-coverage.json')
      const original = JSON.stringify({ outside: true }) + '\n'
      fs.writeFileSync(canary, original)
      fs.symlinkSync(canary, path.join(root, COVERAGE_REL))
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /symlink|unsafe/i.test(`${error.code} ${error.message}`),
      ))
      assert.equal(fs.readFileSync(canary, 'utf8'), original)
      cleanup(outside)
    } finally {
      cleanup(root)
    }
  }

  // Tracked source symlink.
  {
    const root = prepareFixtureRepo()
    try {
      const outside = fs.mkdtempSync(path.join(path.dirname(root), 'repo-atlas-canary-'))
      const canary = path.join(outside, 'a.ts')
      const original = 'export const outside = true\n'
      fs.writeFileSync(canary, original)
      fs.unlinkSync(path.join(root, 'src/a.ts'))
      fs.symlinkSync(canary, path.join(root, 'src/a.ts'))
      execFileSync('git', ['add', '--', 'src/a.ts'], { cwd: root })
      const report = buildReport(root, { verdict: 'complete' })
      writeCoverage(root, report)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.ok(portfolio.errors.some((error) =>
        /symlink|unsafe|120000|mode/i.test(`${error.code} ${error.message}`),
      ))
      assert.equal(fs.readFileSync(canary, 'utf8'), original)
      cleanup(outside)
    } finally {
      cleanup(root)
    }
  }

  // Evidence-ref symlink must not be followed; canary stays intact.
  {
    const root = prepareFixtureRepo()
    try {
      const outside = fs.mkdtempSync(path.join(path.dirname(root), 'repo-atlas-canary-'))
      const canary = path.join(outside, 'evidence.json')
      const original = '{"outside":true}\n'
      fs.writeFileSync(canary, original)
      fs.mkdirSync(path.join(root, 'audits/evidence'), { recursive: true })
      fs.symlinkSync(canary, path.join(root, 'audits/evidence/a.json'))
      writeV2(root, 'security', 'security-src', ['src/a.ts'], [securityFinding('src/a.ts')], {
        hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
        evidenceRefs: ['audits/evidence/a.json'],
      })
      commitAll(root, 'symlink evidence ref')
      // Unit is rejected by the portfolio loader; coverage still claims fresh.
      const entries = [
        {
          path: 'src/a.ts',
          blob: gitBlob(root, 'src/a.ts'),
          ruleIds: ['source'],
          classification: {
            kind: 'review',
            domains: { security: { unit: 'security-src' } },
          },
          evidence: { security: { status: 'fresh', ledgers: ['security-src'] } },
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
        excludedEntry(root, '.atlas/config.json', 'fixture-config', 'fixture', 'fixture configuration'),
        excludedEntry(root, '.atlas/audits/security-src.json', 'generated-ledger', 'generated', 'ledger under test'),
        excludedEntry(root, 'audits/evidence/a.json', 'evidence-ref', 'fixture', 'symlinked evidence'),
      ]
      // git may store the symlink as 120000 — either inventory mode rejection or
      // fresh-evidence failure is fail-closed; canary bytes must not change.
      const report = buildReport(root, { verdict: 'complete', entries })
      writeCoverage(root, report)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.equal(portfolio.report, null)
      assert.equal(fs.readFileSync(canary, 'utf8'), original)
      cleanup(outside)
    } finally {
      cleanup(root)
    }
  }
})
