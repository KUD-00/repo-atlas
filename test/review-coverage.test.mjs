import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { AUDIT_LIMITS } from '../dist/audit-core.js'
import { loadAuditPortfolios } from '../dist/audits.js'
import { loadAuditReviewPolicy } from '../dist/audit-policy.js'
import { updateAuditCoverage } from '../dist/audit-coverage-generator.js'
import { loadReviewCoverage, reviewCoveragePath } from '../dist/review-coverage.js'
import { reviewCoverageInventoryHash } from '../dist/review-coverage-hash.js'
import { cleanup, commitAll, gitBlob, makeRepo, scopeHash, write } from './helpers.mjs'

const CLI = new URL('../dist/cli.js', import.meta.url).pathname

const COVERAGE_REL = '.atlas/review-coverage.json'
const SELF_PATH = COVERAGE_REL
const GENERATED_PROOF = 'GENERATED-PROOF'

function decisionPolicy() {
  return {
    requireDisposition: true,
    blockingActions: ['open', 'reopened'],
    drift: {
      findingBearing: 'blocking',
      clean: 'advisory',
      unknown: 'blocking',
    },
    expiry: {
      warningDays: 14,
      requiredFor: ['accepted-risk', 'separate-design'],
      acceptedRiskMaximumDays: 90,
      separateDesignMaximumDays: 90,
      falsePositiveMustBeNull: true,
      severityOverrides: [{
        severities: ['critical', 'high'],
        maximumDays: 30,
        minimumIndependentReviews: 2,
        reviewEvidenceRequired: true,
      }],
    },
    remediation: {
      fixBlobRequired: true,
      postFixProofRequired: true,
      passingRegressionRequired: true,
      allowedRegressionKinds: ['test', 'guardrail', 'check'],
    },
    falsePositive: {
      reviewedBlobRequired: true,
      sourceEvidenceRequired: true,
    },
    superseded: {
      replacementOrDeletionProofRequired: true,
      existingPathRequiresCurrentReview: true,
    },
    retirement: {
      historyProofRequired: true,
      allowedReasons: [
        'deleted',
        'moved',
        'superseded',
        'staged-deletion',
        'uncommitted-snapshot-absent',
      ],
    },
    acceptedRulesets: ['fixture-security-v1'],
  }
}

function fixtureReviewPolicy() {
  return {
    formatVersion: 1,
    format: 'atlas-review-policy-v1',
    rules: [
      {
        id: 'source',
        include: ['src/**'],
        except: [],
        rationale: 'Fixture source requires security review.',
        domains: ['security'],
      },
      {
        id: 'generated-proof',
        include: [COVERAGE_REL],
        except: [],
        rationale: 'Canonical generated coverage proof.',
        excluded: {
          category: 'generated-proof',
          reason: 'canonical report validates its own bytes',
          owner: 'repo-atlas-tests',
        },
      },
      {
        id: 'fixture-config',
        include: ['.atlas/config.json'],
        except: [],
        rationale: 'Fixture configuration is not product source.',
        excluded: {
          category: 'fixture',
          reason: 'fixture configuration is outside this parser test',
          owner: 'repo-atlas-tests',
        },
      },
      {
        id: 'generated-ledger',
        include: ['.atlas/audits/**'],
        except: [],
        rationale: 'Fixture audit output is generated.',
        excluded: {
          category: 'generated',
          reason: 'strict fixture builder output',
        },
      },
    ],
    units: [{
      domain: 'security',
      slug: 'security-src',
      title: 'Source',
      include: ['src/**'],
      except: [],
      context: [],
    }],
    securityDecisions: decisionPolicy(),
  }
}

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
  return reviewCoverageInventoryHash(entries.map((entry) => ({
    marker: entry.path === SELF_PATH
      ? GENERATED_PROOF
      : entry.blob,
    path: entry.path,
  })))
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
        owner: 'repo-atlas-tests',
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
        owner: 'repo-atlas-tests',
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
  const policy = loadAuditReviewPolicy(root)
  assert.notEqual(policy.policyHash, null)
  return {
    formatVersion: 1,
    format: 'atlas-review-coverage-v1',
    verdict,
    policy: {
      format: 'atlas-review-policy-v1',
      hash: policy.policyHash,
    },
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
  write(
    root,
    '.atlas/review-policy.json',
    `${JSON.stringify(fixtureReviewPolicy(), null, 2)}\n`,
  )
  fs.appendFileSync(
    path.join(root, '.git/info/exclude'),
    '\n.atlas/review-policy.json\n',
  )
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
  const atlas = path.join(root, '.atlas')
  const parkedAtlas = path.join(root, '.atlas-missing-fixture')
  try {
    assert.ok(!fs.existsSync(reviewCoveragePath(root)))
    const portfolio = load(root)
    assert.equal(portfolio.state, 'missing')
    assert.equal(portfolio.report, null)
    assert.deepEqual(portfolio.errors, [])
    assert.deepEqual(portfolio.drift, { added: [], removed: [], changed: [] })
    // Missing must not fabricate a zero-coverage report.
    assert.equal(portfolio.report?.summary?.tracked, undefined)

    fs.renameSync(atlas, parkedAtlas)
    const missingDirectory = load(root)
    assert.equal(missingDirectory.state, 'missing')
    assert.equal(missingDirectory.report, null)
    assert.deepEqual(missingDirectory.errors, [])
  } finally {
    if (fs.existsSync(parkedAtlas) && !fs.existsSync(atlas)) {
      fs.renameSync(parkedAtlas, atlas)
    }
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

test('coverage reader cannot certify across a pre-retention atlas acquisition gap', () => {
  const root = prepareFixtureRepo()
  const atlas = path.join(root, '.atlas')
  const parkedAtlas = path.join(root, '.atlas-original')
  const replacementAtlas = path.join(root, '.atlas-replacement')
  const originalOpendir = fs.opendirSync
  let swapped = false
  try {
    writeCoverage(root, buildReport(root, { verdict: 'incomplete' }))
    const baseline = load(root)
    assert.equal(
      baseline.state,
      'current',
      JSON.stringify(baseline.errors),
    )
    fs.cpSync(atlas, replacementAtlas, { recursive: true })
    assert.notEqual(
      fs.statSync(atlas).ino,
      fs.statSync(replacementAtlas).ino,
    )

    fs.opendirSync = function swapAfterUnretainedAtlasListing(file, ...rest) {
      const directory = originalOpendir.call(fs, file, ...rest)
      let isAtlasRoot = false
      try {
        isAtlasRoot = fs.realpathSync(file) === atlas
      } catch {
        // Only a named listing of the live .atlas root is relevant.
      }
      if (isAtlasRoot) {
        const originalClose = directory.closeSync.bind(directory)
        directory.closeSync = function closeThenSwapAtlas() {
          const result = originalClose()
          if (!swapped) {
            fs.renameSync(atlas, parkedAtlas)
            fs.renameSync(replacementAtlas, atlas)
            swapped = true
          }
          return result
        }
      }
      return directory
    }

    const portfolio = load(root)
    assert.equal(
      swapped && portfolio.state === 'current',
      false,
      'a preliminary .atlas listing and the retained report must not come from different directory identities',
    )
  } finally {
    fs.opendirSync = originalOpendir
    cleanup(root)
  }
})

test('coverage exact-evidence validation never reopens atlas files through the retained root name', () => {
  const root = prepareFixtureRepo()
  const originalOpen = fs.openSync
  const namedAtlasOpens = []
  try {
    const configPath = '.atlas/config.json'
    const policy = fixtureReviewPolicy()
    policy.rules = policy.rules.filter((rule) =>
      rule.id !== 'fixture-config')
    policy.rules[0].include.push(configPath)
    policy.units[0].include.push(configPath)
    write(
      root,
      '.atlas/review-policy.json',
      `${JSON.stringify(policy, null, 2)}\n`,
    )
    writeV2(
      root,
      'security',
      'security-src',
      ['src/a.ts', configPath],
      [securityFinding('src/a.ts')],
      {
        hashes: {
          'src/a.ts': gitBlob(root, 'src/a.ts'),
          [configPath]: gitBlob(root, configPath),
        },
      },
    )
    commitAll(root, 'review an atlas-owned config path')

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
          security: { status: 'fresh', ledgers: ['security-src'] },
        },
      },
      {
        path: configPath,
        blob: gitBlob(root, configPath),
        ruleIds: ['source'],
        classification: {
          kind: 'review',
          domains: { security: { unit: 'security-src' } },
        },
        evidence: {
          security: { status: 'fresh', ledgers: ['security-src'] },
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
          owner: 'repo-atlas-tests',
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
    writeCoverage(root, buildReport(root, { entries }))
    const portfolios = loadAuditPortfolios(root)
    const baseline = loadReviewCoverage(root, portfolios)
    assert.equal(
      baseline.state,
      'current',
      JSON.stringify(baseline.errors),
    )

    fs.openSync = function recordNamedAtlasOpen(file, flags, ...rest) {
      const candidate = String(file)
      if (
        /^\/proc\/self\/fd\/\d+\/\.atlas\/config\.json$/u.test(candidate)
      ) {
        namedAtlasOpens.push(candidate)
      }
      return originalOpen.call(fs, file, flags, ...rest)
    }

    const portfolio = loadReviewCoverage(root, portfolios)
    assert.equal(
      portfolio.state,
      'current',
      JSON.stringify(portfolio.errors),
    )
    assert.deepEqual(
      namedAtlasOpens,
      [],
      'all .atlas file validation and hashing must descend from the retained .atlas descriptor',
    )
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
  }
})

test('coverage reader never certifies a policy modified after its validated read', () => {
  const root = prepareFixtureRepo()
  const policyPath = path.join(root, '.atlas/review-policy.json')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const policyFds = new Set()
  let modified = false
  try {
    writeCoverage(root, buildReport(root, { verdict: 'incomplete' }))
    const portfolios = loadAuditPortfolios(root)
    const baseline = loadReviewCoverage(root, portfolios)
    assert.equal(
      baseline.state,
      'current',
      JSON.stringify(baseline.errors),
    )

    fs.openSync = function trackPolicyOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        if (fs.realpathSync(`/proc/self/fd/${fd}`) === policyPath) {
          policyFds.add(fd)
        }
      } catch {
        // Only a successfully opened policy descriptor matters here.
      }
      return fd
    }
    fs.closeSync = function mutatePolicyAfterValidatedRead(fd) {
      const result = originalClose.call(fs, fd)
      if (!modified && policyFds.has(fd)) {
        fs.writeFileSync(policyPath, '{malformed policy replacement\n')
        modified = true
      }
      return result
    }

    const portfolio = loadReviewCoverage(root, portfolios)
    assert.equal(modified, true)
    assert.notEqual(
      portfolio.state,
      'current',
      'supporting policy bytes must remain sealed until coverage validation returns',
    )
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('coverage reader never certifies a source modified when final support hashing closes', () => {
  const root = prepareFixtureRepo()
  const sourcePath = path.join(root, 'src/a.ts')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const sourceFds = new Set()
  let modified = false
  try {
    writeCoverage(root, buildReport(root, { verdict: 'incomplete' }))
    const portfolios = loadAuditPortfolios(root)
    const baseline = loadReviewCoverage(root, portfolios)
    assert.equal(
      baseline.state,
      'current',
      JSON.stringify(baseline.errors),
    )

    fs.openSync = function trackSourceOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        if (fs.realpathSync(`/proc/self/fd/${fd}`) === sourcePath) {
          sourceFds.add(fd)
        }
      } catch {
        // Only successfully opened source descriptors matter here.
      }
      return fd
    }
    fs.closeSync = function mutateSourceAfterFinalSupportHash(fd) {
      const wasSource = sourceFds.delete(fd)
      const result = originalClose.call(fs, fd)
      if (
        !modified &&
        wasSource &&
        new Error().stack?.includes('verifyAuditSupportSnapshot')
      ) {
        fs.writeFileSync(sourcePath, 'export const a = 2\n')
        modified = true
      }
      return result
    }

    const portfolio = loadReviewCoverage(root, portfolios)
    assert.equal(modified, true)
    assert.notEqual(
      portfolio.state,
      'current',
      'supporting source bytes must remain sealed through the transaction linearization point',
    )
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('coverage reader seals an empty audits directory through final listing cleanup', () => {
  const root = makeRepo()
  const auditsPath = path.join(root, '.atlas/audits')
  const originalOpendir = fs.opendirSync
  let added = false
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    write(
      root,
      '.atlas/review-policy.json',
      `${JSON.stringify(fixtureReviewPolicy(), null, 2)}\n`,
    )
    fs.mkdirSync(auditsPath, { recursive: true })
    const generated = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(generated.current, true)
    const portfolios = loadAuditPortfolios(root)
    const baseline = loadReviewCoverage(root, portfolios)
    assert.equal(
      baseline.state,
      'current',
      JSON.stringify(baseline.errors),
    )

    fs.opendirSync = function mutateAfterFinalAuditsListing(file, ...rest) {
      const directory = originalOpendir.call(fs, file, ...rest)
      let isAudits = false
      try {
        isAudits = fs.realpathSync(String(file)) === auditsPath
      } catch {
        // Only the retained fixture audits directory matters here.
      }
      if (isAudits) {
        const close = directory.closeSync.bind(directory)
        directory.closeSync = function closeThenAddLedger() {
          const result = close()
          if (
            !added &&
            new Error().stack?.includes('verifyAuditSupportSnapshot')
          ) {
            fs.writeFileSync(
              path.join(auditsPath, 'late.json'),
              '{malformed late ledger\n',
            )
            added = true
          }
          return result
        }
      }
      return directory
    }

    const portfolio = loadReviewCoverage(root, portfolios)
    assert.equal(added, true)
    assert.notEqual(
      portfolio.state,
      'current',
      'directory membership must remain sealed through final listing cleanup',
    )
  } finally {
    fs.opendirSync = originalOpendir
    cleanup(root)
  }
})

test('coverage reader revalidates audits membership after final support file cleanup', () => {
  const root = makeRepo()
  const auditsPath = path.join(root, '.atlas/audits')
  const sourcePath = path.join(root, 'src/a.ts')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const sourceFds = new Set()
  let added = false
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    write(
      root,
      '.atlas/review-policy.json',
      `${JSON.stringify(fixtureReviewPolicy(), null, 2)}\n`,
    )
    fs.mkdirSync(auditsPath, { recursive: true })
    const generated = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(generated.current, true)
    const portfolios = loadAuditPortfolios(root)
    const baseline = loadReviewCoverage(root, portfolios)
    assert.equal(
      baseline.state,
      'current',
      JSON.stringify(baseline.errors),
    )

    fs.openSync = function trackSourceOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        if (fs.realpathSync(`/proc/self/fd/${fd}`) === sourcePath) {
          sourceFds.add(fd)
        }
      } catch {
        // Only successfully opened source descriptors matter here.
      }
      return fd
    }
    fs.closeSync = function addLedgerAfterFinalSupportHash(fd) {
      const wasSource = sourceFds.delete(fd)
      const result = originalClose.call(fs, fd)
      if (
        !added &&
        wasSource &&
        new Error().stack?.includes('verifyAuditSupportSnapshot')
      ) {
        fs.writeFileSync(
          path.join(auditsPath, 'late.json'),
          '{malformed late ledger\n',
        )
        added = true
      }
      return result
    }

    const portfolio = loadReviewCoverage(root, portfolios)
    assert.equal(added, true)
    assert.notEqual(
      portfolio.state,
      'current',
      'directory membership must be checked after support file cleanup',
    )
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('coverage reader never certifies bytes from an atlas directory replaced after the report snapshot closes', () => {
  const root = prepareFixtureRepo()
  const atlas = path.join(root, '.atlas')
  const parkedAtlas = path.join(root, '.atlas-original')
  const replacementAtlas = path.join(root, '.atlas-replacement')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  let reportFd = null
  let swapped = false
  try {
    writeCoverage(root, buildReport(root, { verdict: 'incomplete' }))
    const baseline = load(root)
    assert.equal(
      baseline.state,
      'current',
      JSON.stringify(baseline.errors),
    )

    fs.cpSync(atlas, replacementAtlas, { recursive: true })
    fs.writeFileSync(
      path.join(replacementAtlas, 'review-coverage.json'),
      '{malformed replacement\n',
    )

    fs.openSync = function trackCoverageOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        if (
          fs.realpathSync(`/proc/self/fd/${fd}`) ===
          path.join(atlas, 'review-coverage.json')
        ) {
          reportFd = fd
        }
      } catch {
        // Only the retained original coverage descriptor matters here.
      }
      return fd
    }
    fs.closeSync = function replaceAtlasAfterReportClose(fd) {
      const result = originalClose.call(fs, fd)
      if (!swapped && fd === reportFd) {
        fs.renameSync(atlas, parkedAtlas)
        fs.renameSync(replacementAtlas, atlas)
        swapped = true
      }
      return result
    }

    const portfolio = load(root)
    assert.equal(swapped, true)
    assert.notEqual(
      portfolio.state,
      'current',
      'a report snapshot cannot remain current after its containing .atlas identity changes',
    )
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('coverage reader never certifies through a transient atlas ABA replacement', () => {
  const root = prepareFixtureRepo()
  const atlas = path.join(root, '.atlas')
  const parkedAtlas = path.join(root, '.atlas-original')
  const replacementAtlas = path.join(root, '.atlas-replacement')
  const reportPath = path.join(atlas, 'review-coverage.json')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const originalFstat = fs.fstatSync
  const reportFds = new Set()
  let retainedReportFd = null
  let swapped = false
  let restored = false
  try {
    writeCoverage(root, buildReport(root, { verdict: 'incomplete' }))
    const baseline = load(root)
    assert.equal(
      baseline.state,
      'current',
      JSON.stringify(baseline.errors),
    )
    fs.cpSync(atlas, replacementAtlas, { recursive: true })

    fs.openSync = function trackCoverageOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        if (
          fs.realpathSync(`/proc/self/fd/${fd}`) === reportPath
        ) {
          reportFds.add(fd)
          if (retainedReportFd === null) retainedReportFd = fd
        }
      } catch {
        // Only the first retained report descriptor matters here.
      }
      return fd
    }
    fs.closeSync = function swapAtlasAfterInnerReportClose(fd) {
      const result = originalClose.call(fs, fd)
      if (
        !swapped &&
        retainedReportFd !== null &&
        reportFds.has(fd) &&
        fd !== retainedReportFd
      ) {
        let real = ''
        try {
          real = fs.realpathSync(`/proc/self/fd/${retainedReportFd}`)
        } catch {
          // The retained descriptor must stay live for the transaction.
        }
        if (real === reportPath) {
          fs.renameSync(atlas, parkedAtlas)
          fs.renameSync(replacementAtlas, atlas)
          swapped = true
        }
      }
      return result
    }
    fs.fstatSync = function restoreAtlasBeforeFinalIdentityCheck(fd) {
      if (
        swapped &&
        !restored &&
        fd === retainedReportFd
      ) {
        fs.renameSync(atlas, replacementAtlas)
        fs.renameSync(parkedAtlas, atlas)
        restored = true
      }
      return originalFstat.call(fs, fd)
    }

    const portfolio = load(root)
    assert.equal(swapped, true)
    assert.equal(restored, true)
    assert.notEqual(
      portfolio.state,
      'current',
      'all repository revalidation must remain bound to the retained .atlas capability',
    )
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    fs.fstatSync = originalFstat
    if (fs.existsSync(parkedAtlas)) {
      if (fs.existsSync(atlas) && !fs.existsSync(replacementAtlas)) {
        fs.renameSync(atlas, replacementAtlas)
      }
      if (!fs.existsSync(atlas)) fs.renameSync(parkedAtlas, atlas)
    }
    cleanup(root)
  }
})

test('coverage reader never certifies a report modified in place after its snapshot closes', () => {
  const root = prepareFixtureRepo()
  const reportPath = path.join(root, COVERAGE_REL)
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  let reportFd = null
  let modified = false
  try {
    writeCoverage(root, buildReport(root, { verdict: 'incomplete' }))
    assert.equal(load(root).state, 'current')

    fs.openSync = function trackCoverageOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        if (fs.realpathSync(`/proc/self/fd/${fd}`) === reportPath) {
          reportFd = fd
        }
      } catch {
        // Only the retained coverage descriptor matters here.
      }
      return fd
    }
    fs.closeSync = function mutateCoverageAfterRead(fd) {
      const result = originalClose.call(fs, fd)
      if (!modified && fd === reportFd) {
        modified = true
        fs.writeFileSync(reportPath, '{malformed in-place replacement\n')
      }
      return result
    }

    const portfolio = load(root)
    assert.equal(modified, true)
    assert.notEqual(
      portfolio.state,
      'current',
      'a report snapshot cannot remain current after its retained inode changes bytes',
    )
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('oversized coverage keeps the report-too-large diagnostic through identity retention', () => {
  const root = prepareFixtureRepo()
  try {
    fs.writeFileSync(
      path.join(root, COVERAGE_REL),
      Buffer.alloc(AUDIT_LIMITS.jsonBytes + 1, 0x20),
    )
    const portfolio = load(root)
    assert.equal(portfolio.state, 'invalid')
    assert.ok(portfolio.errors.some((error) =>
      error.code === 'report-too-large'))
  } finally {
    cleanup(root)
  }
})

test('current atlas policy strictly recomputes rule IDs, classification, and unit assignment', () => {
  const root = prepareFixtureRepo()
  try {
    const base = buildReport(root, { verdict: 'complete' })
    const sourceIndex = base.entries.findIndex((entry) =>
      entry.path === 'src/a.ts')
    assert.notEqual(sourceIndex, -1)

    const forgedRuleIds = structuredClone(base)
    forgedRuleIds.entries[sourceIndex].ruleIds = ['fixture-config']

    const forgedExtraRuleId = structuredClone(base)
    forgedExtraRuleId.entries[sourceIndex].ruleIds = [
      'source',
      'fixture-config',
    ]

    const forgedClassification = structuredClone(base)
    forgedClassification.entries[sourceIndex] = {
      ...forgedClassification.entries[sourceIndex],
      ruleIds: ['source'],
      classification: {
        kind: 'excluded',
        ruleId: 'source',
        category: 'forged',
        reason: 'forged policy interpretation',
      },
      evidence: {},
    }
    forgedClassification.units = []
    forgedClassification.summary = summaryFrom(
      forgedClassification.entries,
    )

    const forgedUnit = structuredClone(base)
    forgedUnit.verdict = 'incomplete'
    forgedUnit.entries[sourceIndex] = {
      ...forgedUnit.entries[sourceIndex],
      classification: {
        kind: 'review',
        domains: {
          security: { unit: 'security-other' },
        },
      },
      evidence: {
        security: { status: 'missing', ledgers: [] },
      },
    }
    forgedUnit.units = [{
      domain: 'security',
      slug: 'security-other',
      title: 'Forged owner',
    }]
    forgedUnit.summary = summaryFrom(forgedUnit.entries)

    for (const report of [
      forgedRuleIds,
      forgedExtraRuleId,
      forgedClassification,
      forgedUnit,
    ]) {
      writeCoverage(root, report)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.ok(portfolio.errors.some((error) =>
        error.code === 'policy-classification-mismatch'))
    }

    const reorderedPolicy = fixtureReviewPolicy()
    reorderedPolicy.rules.push({
      id: 'source-secondary',
      include: ['src/**'],
      except: [],
      rationale: 'A second equivalent source review rule.',
      domains: ['security'],
    })
    write(
      root,
      '.atlas/review-policy.json',
      `${JSON.stringify(reorderedPolicy, null, 2)}\n`,
    )
    const reordered = buildReport(root, { verdict: 'complete' })
    reordered.entries[sourceIndex].ruleIds = [
      'source-secondary',
      'source',
    ]
    writeCoverage(root, reordered)
    assert.equal(load(root).state, 'current')
  } finally {
    cleanup(root)
  }
})

test('arbitrary non-atlas policy formats cannot become trusted-current', () => {
  const root = prepareFixtureRepo()
  try {
    const report = buildReport(root, { verdict: 'complete' })
    const sourceIndex = report.entries.findIndex((entry) =>
      entry.path === 'src/a.ts')
    report.entries[sourceIndex] = {
      ...report.entries[sourceIndex],
      ruleIds: ['forged-exclusion'],
      classification: {
        kind: 'excluded',
        ruleId: 'forged-exclusion',
        category: 'forged',
        reason: 'unverified legacy interpretation',
      },
      evidence: {},
    }
    report.units = []
    report.summary = summaryFrom(report.entries)
    report.policy = {
      format: 'forged-policy-v1',
      hash: 'f'.repeat(64),
    }

    writeCoverage(root, report)
    const portfolio = load(root)
    assert.equal(portfolio.state, 'invalid')
    assert.ok(portfolio.errors.some((error) =>
      error.code === 'unsupported-policy-format'))
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
      /summary|mismatch/i.test(`${error.code} ${error.message}`),
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

test('coverage reader uses strict bounded JSON while accepting pretty atlas V1 reports', () => {
  const root = prepareFixtureRepo()
  try {
    const report = buildReport(root, { verdict: 'complete' })
    const pretty = `${JSON.stringify(report, null, 2)}\n`
    const invalidUtf8 = Buffer.from(pretty)
    const titleOffset = invalidUtf8.indexOf(Buffer.from('"title": "Source"'))
    assert.ok(titleOffset >= 0)
    invalidUtf8[titleOffset + '"title": "'.length] = 0xff

    const duplicateKey = pretty.replace(
      '{',
      '{"formatVersion":1,',
    )
    const excessiveDepth =
      `${'['.repeat(258)}0${']'.repeat(258)}`
    const excessiveMembers =
      `[${'0,'.repeat(AUDIT_LIMITS.collectionItems)}0]`
    const excessiveString = JSON.stringify({
      ...report,
      policy: {
        ...report.policy,
        format: 'x'.repeat(AUDIT_LIMITS.textCodeUnits + 1),
      },
    })
    const cases = [
      [invalidUtf8, /UTF-8/i],
      [duplicateKey, /duplicate.*key/i],
      [excessiveDepth, /depth|nesting/i],
      [excessiveMembers, /collection|member|item.*limit/i],
      [excessiveString, /string|code unit|text.*limit/i],
    ]
    for (const [bytes, errorPattern] of cases) {
      fs.writeFileSync(reviewCoveragePath(root), bytes)
      const portfolio = load(root)
      assert.equal(portfolio.state, 'invalid')
      assert.ok(portfolio.errors.some((error) =>
        errorPattern.test(`${error.code} ${error.message}`)))
    }

    writeCoverage(root, report)
    const current = load(root)
    assert.equal(current.state, 'current')
    assert.deepEqual(current.errors, [])
  } finally {
    cleanup(root)
  }
})

test('coverage validation uses indexed ownership, evidence-unit, and receipt joins', () => {
  const roots = []
  const originalFind = Array.prototype.find
  let joinFindCalls = 0
  const countJoinFind = function (...args) {
    const first = this[0]
    if (
      first !== null &&
      typeof first === 'object' &&
      (
        (
          Object.hasOwn(first, 'path') &&
          Object.hasOwn(first, 'reviewed') &&
          Object.hasOwn(first, 'fullRead')
        ) ||
        (
          Object.hasOwn(first, 'domain') &&
          Object.hasOwn(first, 'slug') &&
          (
            Object.hasOwn(first, 'receipts') ||
            Object.hasOwn(first, 'title')
          )
        )
      )
    ) {
      joinFindCalls += 1
    }
    return Reflect.apply(originalFind, this, args)
  }

  try {
    const root = makeRepo()
    roots.push(root)
    const sourcePaths = Array.from(
      { length: 128 },
      (_, index) => `src/file-${String(index).padStart(3, '0')}.ts`,
    )
    for (const sourcePath of sourcePaths) {
      write(root, sourcePath, `export const value${sourcePath.length} = 1\n`)
    }
    writeV2(root, 'security', 'security-src', sourcePaths, [], {
      hashes: Object.fromEntries(sourcePaths.map((sourcePath) =>
        [sourcePath, gitBlob(root, sourcePath)])),
    })
    commitAll(root)
    write(
      root,
      '.atlas/review-policy.json',
      `${JSON.stringify(fixtureReviewPolicy(), null, 2)}\n`,
    )
    const entries = [
      ...sourcePaths.map((sourcePath) => ({
        path: sourcePath,
        blob: gitBlob(root, sourcePath),
        ruleIds: ['source'],
        classification: {
          kind: 'review',
          domains: { security: { unit: 'security-src' } },
        },
        evidence: {
          security: { status: 'fresh', ledgers: ['security-src'] },
        },
      })),
      {
        path: SELF_PATH,
        ruleIds: ['generated-proof'],
        classification: {
          kind: 'excluded',
          ruleId: 'generated-proof',
          category: 'generated-proof',
          reason: 'canonical report validates its own bytes',
          owner: 'repo-atlas-tests',
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
          owner: 'repo-atlas-tests',
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
    writeCoverage(root, buildReport(root, { entries }))
    const portfolios = loadAuditPortfolios(root)

    const crossEvidenceRoot = makeRepo()
    roots.push(crossEvidenceRoot)
    write(crossEvidenceRoot, 'src/a.ts', 'export const a = 1\n')
    writeV2(
      crossEvidenceRoot,
      'test',
      'security-src',
      ['src/a.ts'],
      [],
      { hashes: { 'src/a.ts': gitBlob(crossEvidenceRoot, 'src/a.ts') } },
    )
    commitAll(crossEvidenceRoot)
    write(
      crossEvidenceRoot,
      '.atlas/review-policy.json',
      `${JSON.stringify(fixtureReviewPolicy(), null, 2)}\n`,
    )
    writeCoverage(
      crossEvidenceRoot,
      buildReport(crossEvidenceRoot, { verdict: 'complete' }),
    )
    const crossEvidencePortfolios = loadAuditPortfolios(crossEvidenceRoot)

    const ownershipRoot = prepareFixtureRepo()
    roots.push(ownershipRoot)
    const ownershipReport = buildReport(ownershipRoot, {
      verdict: 'complete',
    })
    const source = ownershipReport.entries.find((entry) =>
      entry.path === 'src/a.ts')
    source.classification.domains.security.unit = 'test-owner'
    source.evidence.security.ledgers = ['test-owner']
    ownershipReport.units = [{
      domain: 'test',
      slug: 'test-owner',
      title: 'Test owner',
    }]
    writeCoverage(ownershipRoot, ownershipReport)
    const ownershipPortfolios = loadAuditPortfolios(ownershipRoot)

    Array.prototype.find = countJoinFind
    let fresh
    let crossEvidence
    let crossOwnership
    try {
      fresh = loadReviewCoverage(root, portfolios)
      crossEvidence = loadReviewCoverage(
        crossEvidenceRoot,
        crossEvidencePortfolios,
      )
      crossOwnership = loadReviewCoverage(
        ownershipRoot,
        ownershipPortfolios,
      )
    } finally {
      Array.prototype.find = originalFind
    }

    assert.equal(fresh.state, 'current')
    assert.equal(crossEvidence.state, 'invalid')
    assert.ok(crossEvidence.errors.some((error) =>
      error.code === 'cross-domain-ledger'))
    assert.equal(crossOwnership.state, 'invalid')
    assert.ok(crossOwnership.errors.some((error) =>
      error.code === 'unit-ownership'))
    assert.equal(joinFindCalls, 0)
  } finally {
    Array.prototype.find = originalFind
    for (const root of roots) cleanup(root)
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
      unsafe.inventoryHash = '0'.repeat(64)
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
      alias.inventoryHash = '0'.repeat(64)
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

function excludedEntry(
  root,
  repoPath,
  ruleId,
  category,
  reason,
  owner,
) {
  return {
    path: repoPath,
    blob: gitBlob(root, repoPath),
    ruleIds: [ruleId],
    classification: {
      kind: 'excluded',
      ruleId,
      category,
      reason,
      ...(owner === undefined ? {} : { owner }),
    },
    evidence: {},
  }
}

function rebuildCanonicalAfterMutation(root, { securityStatus = 'fresh', securityLedgers = ['security-src'] } = {}) {
  // Re-read every tracked blob while preserving the exact policy-owned
  // classification metadata and the security claim under test.
  return canonicalEntries(root, { securityStatus, securityLedgers })
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

test('unstaged tracked deletion is stale removed drift rather than unreadable inventory', () => {
  const root = prepareFixtureRepo()
  try {
    const report = buildReport(root, { verdict: 'complete' })
    writeCoverage(root, report)
    commitAll(root, 'record complete review coverage')

    fs.unlinkSync(path.join(root, 'src/a.ts'))
    const portfolio = load(root)

    assert.equal(portfolio.state, 'stale')
    assert.deepEqual(portfolio.drift.removed, ['src/a.ts'])
    assert.equal(
      portfolio.errors.some((error) => error.code === 'unreadable-path'),
      false,
    )
  } finally {
    cleanup(root)
  }
})

test('unstaged symlink replacement remains invalid inventory', () => {
  const root = prepareFixtureRepo()
  const outside = fs.mkdtempSync(path.join(path.dirname(root), 'repo-atlas-link-'))
  try {
    const report = buildReport(root, { verdict: 'complete' })
    writeCoverage(root, report)
    commitAll(root, 'record complete review coverage')

    const canary = path.join(outside, 'a.ts')
    fs.writeFileSync(canary, 'export const outside = true\n')
    fs.unlinkSync(path.join(root, 'src/a.ts'))
    fs.symlinkSync(canary, path.join(root, 'src/a.ts'))

    const portfolio = load(root)
    assert.equal(portfolio.state, 'invalid')
    assert.equal(portfolio.report, null)
    assert.ok(portfolio.errors.some((error) => error.code === 'unreadable-path'))
    assert.equal(fs.readFileSync(canary, 'utf8'), 'export const outside = true\n')
  } finally {
    cleanup(root)
    cleanup(outside)
  }
})

test('unstaged deletion cannot hide a symlinked parent replacement', () => {
  const root = prepareFixtureRepo()
  const outside = fs.mkdtempSync(path.join(path.dirname(root), 'repo-atlas-parent-link-'))
  try {
    const report = buildReport(root, { verdict: 'complete' })
    writeCoverage(root, report)
    commitAll(root, 'record complete review coverage')

    fs.writeFileSync(path.join(outside, 'a.ts'), 'export const outside = true\n')
    fs.rmSync(path.join(root, 'src'), { recursive: true, force: true })
    fs.symlinkSync(outside, path.join(root, 'src'), 'dir')

    const portfolio = load(root)
    assert.equal(portfolio.state, 'invalid')
    assert.equal(portfolio.report, null)
    assert.ok(portfolio.errors.some((error) => error.code === 'unreadable-path'))
  } finally {
    cleanup(root)
    cleanup(outside)
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
    const policy = fixtureReviewPolicy()
    policy.rules[0].except = [newlinePath]
    policy.rules.push(
      {
        id: 'newline-path',
        include: [newlinePath],
        except: [],
        rationale: 'Exercise NUL-delimited Git inventory parsing.',
        excluded: {
          category: 'fixture',
          reason: 'newline in path',
          owner: 'repo-atlas-tests',
        },
      },
      {
        id: 'option-path',
        include: [optionPath],
        except: [],
        rationale: 'Exercise option-like Git inventory paths.',
        excluded: {
          category: 'fixture',
          reason: 'option-like path',
          owner: 'repo-atlas-tests',
        },
      },
    )
    write(
      root,
      '.atlas/review-policy.json',
      `${JSON.stringify(policy, null, 2)}\n`,
    )

    const entries = [
      ...canonicalEntries(root),
      excludedEntry(
        root,
        newlinePath,
        'newline-path',
        'fixture',
        'newline in path',
        'repo-atlas-tests',
      ),
      excludedEntry(
        root,
        optionPath,
        'option-path',
        'fixture',
        'option-like path',
        'repo-atlas-tests',
      ),
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
        entries.push({
          path: 'src/other.ts',
          blob: gitBlob(root, 'src/other.ts'),
          ruleIds: ['source'],
          classification: {
            kind: 'review',
            domains: { security: { unit: 'security-src' } },
          },
          evidence: {
            security: { status: 'fresh', ledgers: ['security-src'] },
          },
        })
      }
      const report = buildReport(root, {
        verdict: 'complete',
        entries,
        units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
      })
      writeCoverage(root, report)
      const portfolio = load(root)
      if (mutation.name === 'staleness') {
        // Coverage freshness is receipt-local. A unit-level scope hash drift
        // cannot poison a complete V2 exact hash receipt whose path/blob still
        // matches the current inventory.
        assert.equal(portfolio.state, 'current')
        assert.equal(portfolio.report?.verdict, 'complete')
        continue
      }
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

test('status json reports the same coverage verdict and failure buckets', () => {
  const root = prepareFixtureRepo()
  try {
    writeCoverage(root, buildReport(root, { verdict: 'incomplete' }))
    const run = spawnSync(process.execPath, [CLI, 'status', '--json'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(run.status, 0, run.stderr)
    const output = JSON.parse(run.stdout)
    assert.equal(output.coverage.state, 'current')
    assert.equal(output.coverage.verdict, 'incomplete')
    assert.equal(output.coverage.summary.securityMissing, 1)
    assert.deepEqual(output.coverage.drift, { added: [], removed: [], changed: [] })
    assert.ok(Array.isArray(output.coverage.errors))
  } finally {
    cleanup(root)
  }
})

test('status text distinguishes coverage states and never says clean', () => {
  const root = prepareFixtureRepo()
  try {
    const missing = spawnSync(process.execPath, [CLI, 'status'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(missing.status, 0, missing.stderr)
    assert.match(missing.stdout, /coverage:.*missing/i)
    assert.doesNotMatch(missing.stdout, /\bclean\b/i)

    writeCoverage(root, buildReport(root, { verdict: 'incomplete' }))
    const incomplete = spawnSync(process.execPath, [CLI, 'status'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(incomplete.status, 0, incomplete.stderr)
    assert.match(incomplete.stdout, /coverage:.*incomplete/i)
    assert.match(incomplete.stdout, /security/i)
    assert.match(incomplete.stdout, /policy gaps 0/i)
    assert.doesNotMatch(incomplete.stdout, /\bclean\b/i)

    writeCoverage(root, buildReport(root, { verdict: 'complete' }))
    const complete = spawnSync(process.execPath, [CLI, 'status'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(complete.status, 0, complete.stderr)
    assert.match(complete.stdout, /coverage:.*complete/i)
    assert.doesNotMatch(complete.stdout, /\bclean\b/i)

    write(root, COVERAGE_REL, '{not json\n')
    execFileSync('git', ['add', '--', COVERAGE_REL], { cwd: root })
    const invalid = spawnSync(process.execPath, [CLI, 'status'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(invalid.status, 0, invalid.stderr)
    assert.match(invalid.stdout, /coverage:.*invalid/i)
    assert.doesNotMatch(invalid.stdout, /\bclean\b/i)
  } finally {
    cleanup(root)
  }
})
