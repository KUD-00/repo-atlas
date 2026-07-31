import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { loadAuditPortfolios } from '../dist/audits.js'
import { buildAuditLocalizationInput } from '../dist/audit-localizations.js'
import { loadAuditReviewPolicy } from '../dist/audit-policy.js'
import { buildPayload, loadAuditV3Presentation } from '../dist/build.js'
import { loadReviewCoverage } from '../dist/review-coverage.js'
import { reviewCoverageInventoryHash } from '../dist/review-coverage-hash.js'
import { scan } from '../dist/scan.js'
import { computeStatus } from '../dist/status.js'
import { cleanup, commitAll, gitBlob, makeRepo, scopeHash, write } from './helpers.mjs'

const CLI = new URL('../dist/cli.js', import.meta.url).pathname
const COVERAGE_REL = '.atlas/review-coverage.json'
const SELF_PATH = COVERAGE_REL
const GENERATED_PROOF = 'GENERATED-PROOF'

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
    securityDecisions: {
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
    },
  }
}

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
    assert.equal(defaults.defaultLocale, 'en')
    assert.equal(defaults.auditSourceLocale, 'en')
    assert.deepEqual(defaults.auditLocalizations, {})

    const zhPortfolio = {
      locale: 'zh',
      state: 'complete',
      units: [],
      errors: [],
    }
    const localized = buildPayload({
      repoName: 'fixture',
      commit: null,
      status,
      defaultLocale: 'zh',
      auditSourceLocale: 'en',
      auditLocalizations: { zh: zhPortfolio },
    })
    assert.equal(localized.defaultLocale, 'zh')
    assert.equal(localized.auditSourceLocale, 'en')
    assert.deepEqual(localized.auditLocalizations, { zh: zhPortfolio })
  } finally {
    cleanup(root)
  }
})

function inventoryHashFor(entries) {
  return reviewCoverageInventoryHash(entries.map((entry) => ({
    marker: entry.path === SELF_PATH ? GENERATED_PROOF : entry.blob,
    path: entry.path,
  })))
}

function writeCoverageReport(root, verdict = 'incomplete') {
  write(
    root,
    '.atlas/review-policy.json',
    `${JSON.stringify(fixtureReviewPolicy(), null, 2)}\n`,
  )
  const policy = loadAuditReviewPolicy(root)
  assert.notEqual(policy.policyHash, null)
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
    policy: {
      format: 'atlas-review-policy-v1',
      hash: policy.policyHash,
    },
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

test('concept snapshot changes when a present source changes beside a broken source', () => {
  const root = makeRepo()
  try {
    write(root, 'src/present.ts', 'export const value = 1\n')
    write(root, '.atlas/concepts/runtime.md', `---
title: Runtime
audience: dev
sources: ["src/present.ts", "src/missing.ts"]
---
Runtime orientation.
`)
    commitAll(root)

    const first = emptyStatus(root).concepts[0]
    assert.match(first.snapshot, /^[a-f0-9]{64}$/)
    assert.equal(first.currentSourcesHash, null)
    assert.deepEqual(first.brokenSources, ['src/missing.ts'])

    write(root, 'src/present.ts', 'export const value = 2\n')
    const second = emptyStatus(root).concepts[0]
    assert.match(second.snapshot, /^[a-f0-9]{64}$/)
    assert.notEqual(second.snapshot, first.snapshot)
    assert.equal(second.currentSourcesHash, null)
    assert.deepEqual(second.brokenSources, ['src/missing.ts'])
  } finally {
    cleanup(root)
  }
})

test('build payload exposes static attention and preserves supplied live attention', () => {
  const root = makeRepo()
  try {
    write(root, 'src/runtime.ts', 'export const runtime = true\n')
    write(root, '.atlas/concepts/runtime.md', `---
title: Runtime
audience: dev
sources: ["src/runtime.ts"]
---
Runtime orientation.
`)
    commitAll(root)
    const status = emptyStatus(root)

    const staticPayload = buildPayload({ repoName: 'fixture', commit: null, status })
    assert.equal(staticPayload.attention.mode, 'static')
    assert.equal(staticPayload.attention.state, 'ready')
    assert.equal(staticPayload.attention.summary.open, 1)
    assert.equal(staticPayload.attention.summary.snoozed, 0)
    assert.equal(staticPayload.attention.summary.done, 0)
    assert.equal(staticPayload.attention.items[0].slug, 'runtime')
    assert.equal(staticPayload.attention.items[0].workflow, 'open')
    assert.deepEqual(staticPayload.attention.events, [])
    assert.equal(staticPayload.attention.health.concepts.outdated, 1)

    const supplied = {
      ...staticPayload.attention,
      mode: 'live',
      generatedAt: '2026-07-22T10:00:00.000Z',
      diagnostics: [],
    }
    const livePayload = buildPayload({
      repoName: 'fixture',
      commit: null,
      status,
      attention: supplied,
    })
    assert.deepEqual(livePayload.attention, supplied)
  } finally {
    cleanup(root)
  }
})

test('concept page renders the full body into html (no overview projection)', () => {
  const root = makeRepo()
  try {
    write(root, 'src/runtime.ts', 'export const runtime = true\n')
    write(root, '.atlas/concepts/runtime.md', `---
title: Runtime
audience: dev
sources: ["src/runtime.ts"]
---
Start here: the runtime turns accepted work into leased jobs.

## Request path

Later walkthrough detail.

### Lease boundary

Lease-specific detail.
`)
    write(root, '.atlas/concepts/no-headings.md', `---
title: No headings
audience: general
sources: ["src/runtime.ts"]
---
The complete short explanation has no section headings.
`)
    commitAll(root)

    const payload = buildPayload({ repoName: 'fixture', commit: null, status: emptyStatus(root) })
    const runtime = payload.concepts.find((entry) => entry.slug === 'runtime')
    assert.ok(runtime)
    // The whole page renders into html — the opening, the walkthrough and its
    // subsections all land in one document; no separate overview/sections projection.
    assert.match(runtime.html, /Start here/)
    assert.match(runtime.html, /Later walkthrough detail/)
    assert.match(runtime.html, /Lease boundary/)
    assert.equal(runtime.briefHtml, undefined)
    assert.equal(runtime.sections, undefined)

    const short = payload.concepts.find((entry) => entry.slug === 'no-headings')
    assert.ok(short)
    assert.match(short.html, /complete short explanation/)
  } finally {
    cleanup(root)
  }
})

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
      title: 'Source',
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

test('cli build carries configured verified audit localizations', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writeV2(root, 'security', 'security-src', ['src/a.ts'], [securityFinding('src/a.ts')], {
      hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
      title: 'Source',
    })
    write(root, '.atlas/config.json', `${JSON.stringify({
      formatVersion: 1,
      exclude: [],
      output: '.atlas/atlas.html',
      defaultLocale: 'zh',
      auditSourceLocale: 'en',
      auditContentLocales: ['zh'],
    }, null, 2)}\n`)
    commitAll(root)
    writeCoverageReport(root, 'complete')

    const status = emptyStatus(root)
    const portfolios = loadAuditPortfolios(root, status.audits)
    const coverage = loadReviewCoverage(root, portfolios)
    const input = buildAuditLocalizationInput('en', 'zh', coverage, portfolios)
    write(root, '.atlas/locales/zh/audits.json', `${JSON.stringify({
      formatVersion: 1,
      format: 'atlas-audit-localizations-v1',
      locale: 'zh',
      units: input.units,
    }, null, 2)}\n`)

    const result = spawnSync(process.execPath, [CLI, 'build', '-o', '.atlas/localized.html'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(result.status, 0, result.stderr || result.stdout)
    const data = extractAtlasPayload(
      fs.readFileSync(path.join(root, '.atlas/localized.html'), 'utf8'),
    )
    assert.equal(data.defaultLocale, 'zh')
    assert.equal(data.auditSourceLocale, 'en')
    assert.equal(data.auditLocalizations.zh.state, 'complete')
    assert.deepEqual(data.auditLocalizations.zh.units.map((unit) => unit.slug), ['security-src'])
  } finally {
    cleanup(root)
  }
})

test('audit localization cli emits deterministic input and gates required locales', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writeV2(root, 'security', 'security-src', ['src/a.ts'], [securityFinding('src/a.ts')], {
      hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
      title: 'Source',
    })
    write(root, '.atlas/config.json', `${JSON.stringify({
      formatVersion: 1,
      exclude: [],
      defaultLocale: 'zh',
      auditSourceLocale: 'en',
      auditContentLocales: ['zh'],
    }, null, 2)}\n`)
    commitAll(root)
    writeCoverageReport(root, 'complete')

    const inputResult = spawnSync(
      process.execPath,
      [CLI, 'audit-localization-input', '--locale', 'zh', '--json'],
      { cwd: root, encoding: 'utf8' },
    )
    assert.equal(inputResult.status, 0, inputResult.stderr || inputResult.stdout)
    const input = JSON.parse(inputResult.stdout)
    assert.equal(input.format, 'atlas-audit-localization-input-v1')
    assert.equal(input.sourceLocale, 'en')
    assert.equal(input.targetLocale, 'zh')
    assert.deepEqual(input.units.map((unit) => unit.slug), ['security-src'])

    const missingResult = spawnSync(
      process.execPath,
      [CLI, 'audit-localization-check', '--json'],
      { cwd: root, encoding: 'utf8' },
    )
    assert.equal(missingResult.status, 1)
    assert.equal(JSON.parse(missingResult.stdout).locales.zh.state, 'missing')

    write(root, '.atlas/locales/zh/audits.json', `${JSON.stringify({
      formatVersion: 1,
      format: 'atlas-audit-localizations-v1',
      locale: 'zh',
      units: input.units,
    }, null, 2)}\n`)
    const completeResult = spawnSync(
      process.execPath,
      [CLI, 'audit-localization-check', '--json'],
      { cwd: root, encoding: 'utf8' },
    )
    assert.equal(completeResult.status, 0, completeResult.stderr || completeResult.stdout)
    assert.equal(JSON.parse(completeResult.stdout).locales.zh.state, 'complete')
  } finally {
    cleanup(root)
  }
})

// ---------------------------------------------------------------------------
// V3 assurance payload (build + serve share the derived model)
// ---------------------------------------------------------------------------

const v3 = await import('../dist/audit-v3.js')
const v3decisions = await import('../dist/audit-decisions.js')
const {
  computeAuditInventoryDigest,
  computeAuditScopeHash,
  computeAtlasFindingId,
  computeAtlasFingerprint,
  computeAtlasObservationId,
  computeAtlasOccurrenceId,
  computeExactScopeIdentityDigest,
  prepareAuditObservationPublication,
  publishAuditObservation,
} = v3
const { appendAuditDecision } = v3decisions

const V3_NOW = '2026-07-29T00:00:00.000Z'
const V3_REPOSITORY_ID = 'repo_build_fixture'
const V3_SLUG = 'security-v3'
const V3_RULESET_ID = 'fixture-security-v1'
const V3_RULESET_DIGEST = `sha256:${'1'.repeat(64)}`
const V3_TARGET_DIGEST = `sha256:${'2'.repeat(64)}`
const V3_ACTOR = 'identity:reviewer@example.invalid'

function publishV3Observation(root, blob) {
  const scopeIdentityDigest = computeExactScopeIdentityDigest({
    mode: 'unit',
    includePaths: ['src/**'],
    excludePaths: [],
    files: [{ path: 'src/a.ts', blob }],
  })
  const finding = (instance) => {
    const fingerprint = computeAtlasFingerprint({
      repositoryId: V3_REPOSITORY_ID,
      domain: 'security',
      ruleId: 'authorization/build-fixture',
      anchor: 'audit/build-fixture',
      instance,
    })
    return { fingerprint, findingId: computeAtlasFindingId(fingerprint) }
  }
  const observationId = computeAtlasObservationId({
    slug: V3_SLUG,
    adapter: 'repo-atlas/manual-v1',
    runId: 'build-fixture-run',
    producerIdentityDigest: V3_RULESET_DIGEST,
    targetId: 'build-fixture-target',
    targetIdentityDigest: V3_TARGET_DIGEST,
    scopeIdentityDigest,
  })
  const findingA = finding('a')
  const findingB = finding('b')
  const occurrenceA = computeAtlasOccurrenceId(observationId, findingA.fingerprint)
  const occurrenceB = computeAtlasOccurrenceId(observationId, findingB.fingerprint)
  const files = [{
    path: 'src/a.ts',
    blob,
    lines: 1,
    status: 'reviewed',
    outcome: 'findings',
    reviewedAt: '2026-07-28T12:00:00.000Z',
    reviewedAtPrecision: 'timestamp',
    reviewedBy: 'fixture',
    ruleset: V3_RULESET_ID,
    findingOccurrenceIds: [occurrenceA, occurrenceB].sort(),
    receiptRefs: ['fixture:full-read'],
  }]
  const inventoryDigest = computeAuditInventoryDigest(files)
  const v3FindingFor = (ids, title) => ({
    findingId: ids.findingId,
    occurrenceId: ids.occurrenceId,
    decisionLedger: V3_SLUG,
    ruleId: 'authorization/build-fixture',
    identity: { anchor: 'audit/build-fixture', instance: ids.instance },
    fingerprints: [{ scheme: 'atlas/v1', value: ids.fingerprint, role: 'canonical' }],
    title,
    summary: 'Bounded build fixture finding.',
    severity: { level: 'medium' },
    taxonomy: { category: 'authorization' },
    locations: [{ path: 'src/a.ts', startLine: 1 }],
    remediation: 'Add the missing gate.',
    provenance: { source: 'manual' },
  })
  const observation = {
    observationId,
    observedAt: '2026-07-28T12:00:00.000Z',
    reviewState: 'complete',
    producer: {
      kind: 'manual',
      name: 'fixture',
      version: '1',
      adapter: 'repo-atlas/manual-v1',
      adapterVersion: '0.1.0',
      runId: 'build-fixture-run',
      identityDigest: V3_RULESET_DIGEST,
      identityBasis: 'ruleset',
      ruleset: { id: V3_RULESET_ID, digest: V3_RULESET_DIGEST },
    },
    target: {
      kind: 'directory-snapshot',
      repositoryId: V3_REPOSITORY_ID,
      targetId: 'build-fixture-target',
      identityDigest: V3_TARGET_DIGEST,
      identityBasis: 'snapshot',
      snapshotDigest: V3_TARGET_DIGEST,
    },
    scope: {
      mode: 'unit',
      identityDigest: scopeIdentityDigest,
      identityBasis: 'exact-inventory',
      includePaths: ['src/**'],
      excludePaths: [],
      scopeHash: computeAuditScopeHash({
        mode: 'unit',
        includePaths: ['src/**'],
        excludePaths: [],
        inventoryDigest,
      }),
      inventoryDigest,
      fileCount: 1,
      files,
      artifactsReviewed: [],
      limitations: [],
    },
    exactCoverage: {
      completeness: 'complete',
      basis: 'full-read-receipts',
      reviewedFileCount: 1,
      unreviewed: [],
    },
    semanticCoverage: {
      mode: 'unit',
      completeness: 'complete',
      inventoryStrategy: 'unit',
      surfaces: [{
        id: 'surface-1',
        label: 'authorization boundary',
        disposition: 'reported',
        receiptRefs: [],
      }],
      explicitExclusions: [],
      deferred: [],
    },
    findings: [
      v3FindingFor({ ...findingA, occurrenceId: occurrenceA, instance: 'a' }, 'build fixture finding A'),
      v3FindingFor({ ...findingB, occurrenceId: occurrenceB, instance: 'b' }, 'build fixture finding B'),
    ],
    evidenceRefs: ['evidence/v3.json'],
    sourceArtifacts: [],
    producerExtensions: [],
  }
  const prepared = prepareAuditObservationPublication(
    root,
    observation,
    { slug: V3_SLUG, title: 'Build Fixture V3' },
  )
  publishAuditObservation(root, prepared.ledger)
  return {
    slug: V3_SLUG,
    blob,
    observationId,
    findingA: { findingId: findingA.findingId, occurrenceId: occurrenceA },
    findingB: { findingId: findingB.findingId, occurrenceId: occurrenceB },
  }
}

test('payload carries the derived V3 assurance model on build and static html', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    write(root, '.atlas/config.json', `${JSON.stringify({
      formatVersion: 1,
      exclude: [],
      repositoryId: V3_REPOSITORY_ID,
    }, null, 2)}\n`)
    write(root, '.atlas/review-policy.json', `${JSON.stringify(fixtureReviewPolicy(), null, 2)}\n`)
    const rawBlob = gitBlob(root, 'src/a.ts')
    const blob = `git-sha${rawBlob.length === 40 ? '1' : '256'}:${rawBlob}`
    const fixture = publishV3Observation(root, blob)

    // Finding B is explicitly accepted (warning-window expiry); finding A stays open.
    const policyDigest = loadAuditReviewPolicy(root).policy.securityDecisions.policyDigest
    const binding = { path: 'src/a.ts', blob }
    appendAuditDecision(root, fixture.slug, {
      type: 'finding-disposition',
      findingId: fixture.findingB.findingId,
      occurrenceId: fixture.findingB.occurrenceId,
      action: 'accepted-risk',
      actor: V3_ACTOR,
      owner: 'build-fixture-owner',
      reason: 'Bounded build fixture acceptance.',
      createdAt: '2026-07-01T00:00:00.000Z',
      createdAtBasis: 'recorded',
      reviewContext: {
        observationId: fixture.observationId,
        bindings: [binding],
        ruleset: { id: V3_RULESET_ID, digest: V3_RULESET_DIGEST },
        policyDigest,
      },
      evidenceRefs: [],
      proofs: [{
        kind: 'current-review',
        observationId: fixture.observationId,
        reviewedBindings: [binding],
        outcome: 'finding-present',
        summary: 'Bounded fixture review proof.',
      }],
      reviews: [],
      expiresAt: '2026-08-05T00:00:00.000Z',
    })

    const scanResult = scan(root, { exclude: [] })
    const status = computeStatus(root, scanResult, { readability: false })
    const portfolios = loadAuditPortfolios(root, status.audits)
    const auditV3 = loadAuditV3Presentation(root, portfolios.security, V3_NOW)
    assert.notEqual(auditV3, null)
    assert.equal(auditV3.decisionStateAvailable, true)
    assert.equal(auditV3.units.length, 1)

    const unit = auditV3.units[0]
    assert.equal(unit.slug, V3_SLUG)
    assert.equal(unit.exact.state, 'complete')
    assert.equal(unit.semantic.state, 'covered')
    assert.equal(unit.staleExactBytes, false)
    assert.equal(unit.policyDrift, false)
    assert.equal(unit.producer.kind, 'manual')
    assert.equal(unit.producer.ruleset.id, V3_RULESET_ID)
    assert.equal(unit.current.observationId, fixture.observationId)
    assert.equal(unit.current.publicationState, 'current')
    assert.equal(unit.historyAhead, false)
    assert.equal(unit.history.length, 1)
    assert.equal(unit.history[0].publicationState, 'current')

    const findings = new Map(unit.findings.map((finding) => [finding.findingId, finding]))
    const findingA = findings.get(fixture.findingA.findingId)
    assert.equal(findingA.status, 'open')
    assert.equal(findingA.lifecycle, 'new')
    assert.equal(findingA.derivation, 'implicit-open')
    assert.equal(findingA.blocking, true)
    assert.equal(findingA.confidence, null)
    const findingB = findings.get(fixture.findingB.findingId)
    assert.equal(findingB.status, 'accepted')
    assert.equal(findingB.expiryState, 'warning')
    assert.equal(findingB.expiresAt, '2026-08-05T00:00:00.000Z')
    assert.equal(findingB.blocking, false)
    assert.equal(unit.openCount, 1)
    assert.equal(unit.countsByStatus.accepted, 1)

    const payload = buildPayload({
      repoName: 'fixture',
      commit: null,
      status,
      audits: portfolios.security,
      testAudits: portfolios.tests,
      auditV3,
    })
    assert.deepEqual(payload.auditV3, auditV3)
    assert.deepEqual(JSON.parse(JSON.stringify(payload.auditV3)), payload.auditV3)

    const defaults = buildPayload({ repoName: 'fixture', commit: null, status })
    assert.equal(defaults.auditV3, null)

    // The static build surface embeds the same derived V3 model.
    const result = spawnSync(process.execPath, [CLI, 'build', '-o', '.atlas/v3.html'], {
      cwd: root,
      encoding: 'utf8',
    })
    assert.equal(result.status, 0, result.stderr || result.stdout)
    const data = extractAtlasPayload(
      fs.readFileSync(path.join(root, '.atlas/v3.html'), 'utf8'),
    )
    assert.notEqual(data.auditV3, null)
    assert.equal(data.auditV3.units.length, 1)
    assert.equal(data.auditV3.units[0].slug, V3_SLUG)
    assert.equal(data.auditV3.units[0].exact.state, 'complete')
    assert.equal(data.auditV3.units[0].semantic.state, 'covered')
    assert.equal(data.auditV3.decisionStateAvailable, true)
    const htmlFindingB = data.auditV3.units[0].findings
      .find((finding) => finding.findingId === fixture.findingB.findingId)
    assert.equal(htmlFindingB.status, 'accepted')

    // Byte drift after the receipt is explicit stale exact evidence.
    write(root, 'src/a.ts', 'export const a = 2\n')
    const staleStatus = computeStatus(root, scan(root, { exclude: [] }), { readability: false })
    const stalePortfolios = loadAuditPortfolios(root, staleStatus.audits)
    const staleV3 = loadAuditV3Presentation(root, stalePortfolios.security, V3_NOW)
    assert.equal(staleV3.units[0].staleExactBytes, true)
  } finally {
    cleanup(root)
  }
})
