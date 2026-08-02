import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import {
  cleanup,
  commitAll,
  gitBlob,
  makeRepo,
  scopeHash,
  write,
} from './helpers.mjs'

async function policyApi() {
  try {
    return await import('../dist/audit-policy.js')
  } catch (error) {
    assert.fail(
      `Task 4 audit-policy public API is missing: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

async function generatorApi() {
  try {
    return await import('../dist/audit-coverage-generator.js')
  } catch (error) {
    assert.fail(
      `Task 4 audit coverage generator API is missing: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

async function auditsApi() {
  try {
    return await import('../dist/audits.js')
  } catch (error) {
    assert.fail(
      `Task 4 normalized audit evidence API is missing: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

async function coverageReaderApi() {
  try {
    return await import('../dist/review-coverage.js')
  } catch (error) {
    assert.fail(
      `Task 4 review-coverage reader API is missing: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

function emptyExactEvidence() {
  return {
    units: [],
    invalidLedgers: [],
    invalidClaimedPaths: [],
  }
}

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
    acceptedRulesets: ['atlas-security-v3'],
  }
}

function reviewPolicy(overrides = {}) {
  return {
    formatVersion: 1,
    format: 'atlas-review-policy-v1',
    rules: [
      {
        id: 'source-security',
        include: ['src/**'],
        except: [],
        rationale: 'Source code receives security review.',
        domains: ['security'],
      },
      {
        id: 'zz-atlas-config',
        include: ['.atlas/config.json'],
        except: [],
        rationale: 'Repo Atlas fixture configuration.',
        excluded: {
          category: 'configuration',
          reason: 'Test harness configuration is not product source.',
          owner: 'repo-atlas-tests',
        },
      },
    ],
    units: [{
      domain: 'security',
      slug: 'security-source',
      title: 'Source',
      include: ['src/**'],
      except: [],
      context: [],
    }],
    securityDecisions: decisionPolicy(),
    ...overrides,
  }
}

function trackedFile(repoPath, blob = 'a'.repeat(40)) {
  return {
    path: repoPath,
    indexBlob: blob,
    currentBlob: blob,
    indexMode: '100644',
    currentMode: '100644',
    deleted: false,
  }
}

function writePolicy(root, policy, pretty = true) {
  write(
    root,
    '.atlas/review-policy.json',
    pretty
      ? `${JSON.stringify(policy, null, 2)}\n`
      : `${JSON.stringify(policy)}\n`,
  )
}

function writeV2(root, {
  domain = 'security',
  slug = 'security-source',
  files = ['src/a.ts'],
  ruleset = 'atlas-security-v3',
  hashes = Object.fromEntries(files.map((file) => [file, gitBlob(root, file)])),
  ...overrides
} = {}) {
  write(root, `.atlas/audits/${slug}.json`, `${JSON.stringify({
    formatVersion: 2,
    format: 'atlas-audit-v2',
    domain,
    reviewState: 'complete',
    slug,
    title: slug,
    ruleset,
    scanned_at: '2026-07-29',
    scope_hash: scopeHash(root, files),
    file_count: files.length,
    files,
    hashes,
    findings: [],
    dropped: [],
    rounds: [],
    ...overrides,
  }, null, 2)}\n`)
}

async function publishOpenV3(root) {
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
  } = await import('../dist/audit-v3.js')
  const blob = `git-sha1:${gitBlob(root, 'src/a.ts')}`
  const rulesetDigest = `sha256:${'1'.repeat(64)}`
  const targetDigest = `sha256:${'2'.repeat(64)}`
  const scopeIdentityDigest = computeExactScopeIdentityDigest({
    mode: 'unit',
    includePaths: ['src/**'],
    excludePaths: [],
    files: [{ path: 'src/a.ts', blob }],
  })
  const producer = {
    kind: 'migration',
    name: 'fixture-security',
    version: '1',
    adapter: 'repo-atlas/test-v1',
    adapterVersion: '0.1.0',
    runId: 'open-finding-run',
    identityDigest: rulesetDigest,
    identityBasis: 'ruleset',
    ruleset: {
      id: 'atlas-security-v3',
      digest: rulesetDigest,
    },
  }
  const target = {
    kind: 'git-worktree',
    repositoryId: 'repo_fixture',
    targetId: 'fixture-target',
    identityDigest: targetDigest,
    identityBasis: 'snapshot',
    revision: execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: root,
      encoding: 'utf8',
    }).trim(),
    snapshotDigest: targetDigest,
    dirty: false,
  }
  const observationId = computeAtlasObservationId({
    slug: 'security-source',
    adapter: producer.adapter,
    runId: producer.runId,
    producerIdentityDigest: producer.identityDigest,
    targetId: target.targetId,
    targetIdentityDigest: target.identityDigest,
    scopeIdentityDigest,
  })
  const fingerprint = computeAtlasFingerprint({
    repositoryId: target.repositoryId,
    domain: 'security',
    ruleId: 'authorization/open-fixture',
    anchor: 'src/a.ts:export-a',
    instance: 'export-a',
  })
  const findingId = computeAtlasFindingId(fingerprint)
  const occurrenceId = computeAtlasOccurrenceId(observationId, fingerprint)
  const files = [{
    path: 'src/a.ts',
    blob,
    lines: 1,
    status: 'reviewed',
    outcome: 'findings',
    reviewedAt: '2026-07-29T12:34:56.000Z',
    reviewedAtPrecision: 'timestamp',
    reviewedBy: 'fixture reviewer',
    ruleset: 'atlas-security-v3',
    findingOccurrenceIds: [occurrenceId],
    receiptRefs: ['fixture:open'],
  }]
  const inventoryDigest = computeAuditInventoryDigest(files)
  const scopeHash = computeAuditScopeHash({
    mode: 'unit',
    includePaths: ['src/**'],
    excludePaths: [],
    inventoryDigest,
  })
  const observation = {
    observationId,
    observedAt: '2026-07-29T12:34:56.000Z',
    reviewState: 'complete',
    producer,
    target,
    scope: {
      mode: 'unit',
      identityDigest: scopeIdentityDigest,
      identityBasis: 'exact-inventory',
      includePaths: ['src/**'],
      excludePaths: [],
      scopeHash,
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
      completeness: 'unknown',
      inventoryStrategy: 'unit',
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      openQuestions: [],
    },
    findings: [{
      findingId,
      occurrenceId,
      decisionLedger: 'security-source',
      ruleId: 'authorization/open-fixture',
      identity: {
        anchor: 'src/a.ts:export-a',
        instance: 'export-a',
      },
      fingerprints: [{
        scheme: 'atlas/v1',
        value: fingerprint,
        role: 'canonical',
      }],
      title: 'Open fixture finding',
      summary: 'The fixture remains open.',
      severity: { level: 'high' },
      taxonomy: { category: 'authorization' },
      locations: [{ path: 'src/a.ts', startLine: 1 }],
      codeEvidence: [{
        evidenceBasis: 'exact-blob',
        id: 'export-a',
        label: 'Fixture export',
        path: 'src/a.ts',
        startLine: 1,
        code: 'export const a = 1',
        explanation: 'The exact reviewed export.',
        blob,
      }],
      rootCause: { summary: 'The fixture lacks a gate.' },
      remediation: 'Add a gate.',
      provenance: { source: 'migration' },
    }],
    evidenceRefs: [],
    sourceArtifacts: [],
    producerExtensions: [],
  }
  const prepared = prepareAuditObservationPublication(
    root,
    observation,
    { slug: 'security-source', title: 'Security source' },
  )
  publishAuditObservation(root, prepared.ledger)
  return { findingId }
}

test('strict policy parsing normalizes optional arrays and hashes canonical parsed policy', async () => {
  const { loadAuditReviewPolicy } = await policyApi()
  const root = makeRepo()
  try {
    const policy = reviewPolicy({
      rules: [{
        id: 'source-security',
        include: ['src/**'],
        rationale: 'Source code receives security review.',
        domains: ['security'],
      }],
      units: [{
        domain: 'security',
        slug: 'security-source',
        title: 'Source',
        include: ['src/**'],
      }],
    })
    writePolicy(root, policy)
    const first = loadAuditReviewPolicy(root)
    assert.deepEqual(first.diagnostics, [])
    assert.equal(first.policy.format, 'atlas-review-policy-v1')
    assert.deepEqual(first.policy.rules[0].except, [])
    assert.deepEqual(first.policy.units[0].except, [])
    assert.deepEqual(first.policy.units[0].context, [])
    assert.match(first.policyHash, /^[0-9a-f]{64}$/)

    const reordered = Object.fromEntries(
      Object.entries(policy).reverse(),
    )
    writePolicy(root, reordered, false)
    const second = loadAuditReviewPolicy(root)
    assert.deepEqual(second.diagnostics, [])
    assert.equal(second.policyHash, first.policyHash)
  } finally {
    cleanup(root)
  }
})

test('strict policy parsing rejects duplicate IDs and non-ruleset identity bases', async () => {
  const { loadAuditReviewPolicy } = await policyApi()
  const root = makeRepo()
  try {
    const duplicate = reviewPolicy()
    duplicate.rules.push(structuredClone(duplicate.rules[0]))
    writePolicy(root, duplicate)
    const duplicateResult = loadAuditReviewPolicy(root)
    assert.equal(duplicateResult.policy, null)
    assert.ok(duplicateResult.diagnostics.some((item) =>
      /duplicate.*source-security/i.test(`${item.code} ${item.message}`),
    ))

    const identityBasis = reviewPolicy()
    identityBasis.securityDecisions.acceptedRulesets = ['codex-contract']
    writePolicy(root, identityBasis)
    const identityResult = loadAuditReviewPolicy(root)
    assert.equal(identityResult.policy, null)
    assert.ok(identityResult.diagnostics.some((item) =>
      /ruleset|codex-contract|identity/i.test(`${item.code} ${item.message}`),
    ))
  } finally {
    cleanup(root)
  }
})

test('tracked inventory is sanitized, records index/current blobs, and preserves deletions', async () => {
  const { readAuditTrackedInventory } = await policyApi()
  const root = makeRepo()
  const priorIndexFile = process.env.GIT_INDEX_FILE
  try {
    write(root, 'src/a.ts', 'export const value = 1\n')
    write(root, '-option-like.ts', 'export const optionLike = true\n')
    commitAll(root)
    write(root, 'src/a.ts', 'export const value = 2\n')
    fs.unlinkSync(path.join(root, '-option-like.ts'))
    process.env.GIT_INDEX_FILE = path.join(root, 'hostile-index')

    const result = readAuditTrackedInventory(root)
    assert.ok(result.diagnostics.some((item) =>
      item.path === '-option-like.ts' && /delet/i.test(
        `${item.code} ${item.message}`,
      ),
    ))
    assert.ok(!result.diagnostics.some((item) => /git-inventory-failed/i.test(
      item.code,
    )))
    assert.equal(result.objectFormat, 'sha1')
    const dirty = result.files.find((file) => file.path === 'src/a.ts')
    assert.match(dirty.indexBlob, /^[0-9a-f]{40}$/)
    assert.match(dirty.currentBlob, /^[0-9a-f]{40}$/)
    assert.notEqual(dirty.currentBlob, dirty.indexBlob)
    const deleted = result.files.find(
      (file) => file.path === '-option-like.ts',
    )
    assert.equal(deleted.deleted, true)
    assert.equal(deleted.currentBlob, null)
  } finally {
    if (priorIndexFile === undefined) delete process.env.GIT_INDEX_FILE
    else process.env.GIT_INDEX_FILE = priorIndexFile
    cleanup(root)
  }
})

test('classification unions domains, preserves rule IDs, and never lets context own coverage', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
  } = await policyApi()
  const root = makeRepo()
  try {
    writePolicy(root, reviewPolicy({
      rules: [
        {
          id: 'security-source',
          include: ['src/**', 'context/**'],
          rationale: 'Security review.',
          domains: ['security'],
        },
        {
          id: 'test-source',
          include: ['src/**'],
          rationale: 'Test review.',
          domains: ['test'],
        },
      ],
      units: [
        {
          domain: 'security',
          slug: 'security-source',
          title: 'Security source',
          include: ['src/**'],
          context: ['context/**'],
        },
        {
          domain: 'test',
          slug: 'test-source',
          title: 'Test source',
          include: ['src/**'],
        },
      ],
    }))
    const loaded = loadAuditReviewPolicy(root)
    assert.deepEqual(loaded.diagnostics, [])
    const blob = 'a'.repeat(40)
    const classified = classifyAuditInventory([
      {
        path: 'src/a.ts',
        indexBlob: blob,
        currentBlob: blob,
        indexMode: '100644',
        currentMode: '100644',
        deleted: false,
      },
      {
        path: 'context/helper.ts',
        indexBlob: blob,
        currentBlob: blob,
        indexMode: '100644',
        currentMode: '100644',
        deleted: false,
      },
    ], loaded.policy)

    const source = classified.files.find((file) => file.path === 'src/a.ts')
    assert.deepEqual(source.ruleIds, ['security-source', 'test-source'])
    assert.deepEqual(source.classification, {
      kind: 'review',
      domains: {
        security: { unit: 'security-source' },
        test: { unit: 'test-source' },
      },
    })
    const context = classified.files.find(
      (file) => file.path === 'context/helper.ts',
    )
    assert.equal(context.classification.kind, 'conflict')
    assert.ok(classified.diagnostics.some((item) =>
      /context\/helper\.ts.*unit|unit.*context\/helper\.ts/i.test(
        `${item.message}`,
      ),
    ))
  } finally {
    cleanup(root)
  }
})

test('schema-owned evidence distinguishes V2 full reads from V1 hash claims', async () => {
  const { loadAuditExactEvidence } = await auditsApi()
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, 'src/legacy.ts', 'export const legacy = true\n')
    writeV2(root)
    write(root, '.atlas/audits/legacy.json', `${JSON.stringify({
      formatVersion: 1,
      format: 'atlas-audit-v1',
      slug: 'legacy',
      title: 'Legacy',
      ruleset: 'legacy-ruleset',
      scanned_at: '2026-07-29',
      scope_hash: scopeHash(root, ['src/legacy.ts']),
      file_count: 1,
      files: ['src/legacy.ts'],
      hashes: { 'src/legacy.ts': gitBlob(root, 'src/legacy.ts') },
      findings: [],
      finalPass: true,
    }, null, 2)}\n`)

    const evidence = loadAuditExactEvidence(root)
    assert.deepEqual(evidence.invalidLedgers, [])
    const v2 = evidence.units.find((unit) => unit.slug === 'security-source')
    assert.equal(v2.version, 2)
    assert.equal(v2.receipts[0].path, 'src/a.ts')
    assert.equal(v2.receipts[0].blob, gitBlob(root, 'src/a.ts'))
    assert.equal(v2.receipts[0].fullRead, true)
    assert.equal(v2.receipts[0].reviewed, true)

    const v1 = evidence.units.find((unit) => unit.slug === 'legacy')
    assert.equal(v1.version, 1)
    assert.equal(v1.receipts[0].fullRead, false)
    assert.equal(v1.receipts[0].blob, null)
  } finally {
    cleanup(root)
  }
})

test('generator joins exact evidence only to assigned unit and accepted ruleset', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
    readAuditTrackedInventory,
  } = await policyApi()
  const { loadAuditExactEvidence } = await auditsApi()
  const {
    buildAuditCoverageReport,
    updateAuditCoverage,
  } = await generatorApi()
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    writeV2(root)
    const loaded = loadAuditReviewPolicy(root)
    const inventory = readAuditTrackedInventory(root)
    const classification = classifyAuditInventory(
      inventory.files,
      loaded.policy,
    )
    const evidence = loadAuditExactEvidence(root)
    const fresh = buildAuditCoverageReport({
      policy: loaded.policy,
      policyHash: loaded.policyHash,
      inventory,
      classification,
      evidence,
    })
    assert.equal(fresh.verdict, 'complete')
    assert.deepEqual(
      fresh.entries.find((entry) => entry.path === 'src/a.ts').evidence.security,
      {
      status: 'fresh',
      ledgers: ['security-source'],
      },
    )

    const wrongUnit = structuredClone(evidence)
    wrongUnit.units[0].slug = 'other-unit'
    const missing = buildAuditCoverageReport({
      policy: loaded.policy,
      policyHash: loaded.policyHash,
      inventory,
      classification,
      evidence: wrongUnit,
    })
    assert.deepEqual(
      missing.entries.find((entry) => entry.path === 'src/a.ts').evidence.security,
      { status: 'missing', ledgers: [] },
    )

    const rejected = structuredClone(evidence)
    rejected.units[0].ruleset = 'not-accepted'
    const invalid = buildAuditCoverageReport({
      policy: loaded.policy,
      policyHash: loaded.policyHash,
      inventory,
      classification,
      evidence: rejected,
    })
    assert.equal(invalid.verdict, 'incomplete')
    assert.deepEqual(
      invalid.entries.find((entry) => entry.path === 'src/a.ts').evidence.security,
      { status: 'missing', ledgers: [] },
    )

    const rejectedPolicy = reviewPolicy()
    rejectedPolicy.securityDecisions.acceptedRulesets = ['other-ruleset']
    writePolicy(root, rejectedPolicy)
    const rejectedResult = updateAuditCoverage(root, {
      allowIncomplete: true,
    })
    assert.equal(rejectedResult.report.verdict, 'incomplete')
    assert.ok(rejectedResult.runtimeAssurance.rulesets.some((item) =>
      item.slug === 'security-source' &&
      item.ruleset === 'atlas-security-v3' &&
      item.accepted === false,
    ))
  } finally {
    cleanup(root)
  }
})

test('update and check use canonical exact bytes and allow only honest incompleteness', async () => {
  const {
    checkAuditCoverage,
    updateAuditCoverage,
  } = await generatorApi()
  const { loadAuditPortfolios } = await auditsApi()
  const { loadReviewCoverage } = await import('../dist/review-coverage.js')
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    writeV2(root)

    const updated = updateAuditCoverage(root)
    assert.equal(updated.ok, true)
    assert.equal(updated.current, true)
    assert.equal(updated.wrote, true)
    assert.equal(updated.report.verdict, 'complete')
    assert.equal(updated.bytes.endsWith('\n'), true)
    assert.equal(updated.bytes.endsWith('\n\n'), false)
    assert.doesNotMatch(updated.bytes, /generatedAt|scannedAt/)
    assert.equal(
      fs.readFileSync(path.join(root, '.atlas/review-coverage.json'), 'utf8'),
      updated.bytes,
    )

    const checked = checkAuditCoverage(root)
    assert.equal(checked.ok, true)
    assert.equal(checked.current, true)
    assert.equal(checked.wrote, false)
    assert.equal(checked.bytes, updated.bytes)

    write(
      root,
      '.atlas/review-coverage.json',
      `${JSON.stringify(updated.report, null, 2)}\n`,
    )
    const legacyReadable = loadReviewCoverage(root, loadAuditPortfolios(root))
    assert.equal(legacyReadable.state, 'current')
    const byteDrift = checkAuditCoverage(root, { allowIncomplete: true })
    assert.equal(byteDrift.ok, false)
    assert.equal(byteDrift.current, false)
    assert.ok(byteDrift.diagnostics.some((item) =>
      /byte|canonical|committed/i.test(`${item.code} ${item.message}`),
    ))

    fs.unlinkSync(path.join(root, '.atlas/audits/security-source.json'))
    const incomplete = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(incomplete.report.verdict, 'incomplete')
    assert.equal(incomplete.ok, true)
    assert.equal(
      incomplete.report.entries.find(
        (entry) => entry.path === 'src/a.ts',
      ).evidence.security.status,
      'missing',
    )
    assert.equal(
      checkAuditCoverage(root, { allowIncomplete: false }).ok,
      false,
    )
  } finally {
    cleanup(root)
  }
})

test('coverage update refuses to publish after a tracked source changes at its final input hash', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const root = makeRepo()
  const sourcePath = path.join(root, 'src/a.ts')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const sourceFds = new Set()
  let sourceCloses = 0
  let modified = false
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    const baseline = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(baseline.current, true)

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
    fs.closeSync = function mutateSourceAfterFinalInputHash(fd) {
      const wasSource = sourceFds.delete(fd)
      const result = originalClose.call(fs, fd)
      if (wasSource) {
        sourceCloses += 1
        if (!modified && sourceCloses === 1) {
          fs.writeFileSync(sourcePath, 'export const a = 2\n')
          modified = true
        }
      }
      return result
    }

    const result = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(modified, true)
    assert.equal(result.ok, false)
    assert.equal(result.current, false)
    assert.equal(result.wrote, false)
    assert.ok(result.diagnostics.some((item) =>
      /snapshot|transaction|changed/i.test(`${item.code} ${item.message}`),
    ))
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('coverage check never reports current after a tracked source changes at its final input hash', async () => {
  const {
    checkAuditCoverage,
    updateAuditCoverage,
  } = await generatorApi()
  const root = makeRepo()
  const sourcePath = path.join(root, 'src/a.ts')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const sourceFds = new Set()
  let sourceCloses = 0
  let modified = false
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    const baseline = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(baseline.current, true)

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
    fs.closeSync = function mutateSourceAfterFinalInputHash(fd) {
      const wasSource = sourceFds.delete(fd)
      const result = originalClose.call(fs, fd)
      if (wasSource) {
        sourceCloses += 1
        if (!modified && sourceCloses === 1) {
          fs.writeFileSync(sourcePath, 'export const a = 2\n')
          modified = true
        }
      }
      return result
    }

    const result = checkAuditCoverage(root, { allowIncomplete: true })
    assert.equal(modified, true)
    assert.equal(result.ok, false)
    assert.equal(result.current, false)
    assert.equal(result.wrote, false)
    assert.ok(result.diagnostics.some((item) =>
      /snapshot|transaction|changed/i.test(`${item.code} ${item.message}`),
    ))
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('coverage update seals the Git index query that defines tracked inventory', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const root = makeRepo()
  const sourcePath = path.join(root, 'src/a.ts')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const sourceFds = new Set()
  let staged = false
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    write(root, 'src/latent.ts', 'export const latent = true\n')
    writePolicy(root, reviewPolicy())
    const baseline = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(baseline.current, true)
    assert.equal(
      baseline.report.entries.some((entry) =>
        entry.path === 'src/latent.ts'),
      false,
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
    fs.closeSync = function stageLatentPathAfterInventoryHash(fd) {
      const wasSource = sourceFds.delete(fd)
      const result = originalClose.call(fs, fd)
      if (!staged && wasSource) {
        execFileSync('git', ['add', '--', 'src/latent.ts'], { cwd: root })
        staged = true
      }
      return result
    }

    const result = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(staged, true)
    assert.equal(result.ok, false)
    assert.equal(result.current, false)
    assert.equal(result.wrote, false)
    assert.ok(result.diagnostics.some((item) =>
      /Git|index|inventory|snapshot|transaction|changed/i.test(
        `${item.code} ${item.message}`,
      ),
    ))
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('coverage update revalidates tracked inventory after final support file cleanup', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const root = makeRepo()
  const sourcePath = path.join(root, 'src/a.ts')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const sourceFds = new Set()
  let staged = false
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    write(root, 'src/latent.ts', 'export const latent = true\n')
    writePolicy(root, reviewPolicy())
    const baseline = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(baseline.current, true)

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
    fs.closeSync = function stageAfterFinalSupportHash(fd) {
      const wasSource = sourceFds.delete(fd)
      const result = originalClose.call(fs, fd)
      if (
        !staged &&
        wasSource &&
        new Error().stack?.includes('verifyAuditSupportSnapshot')
      ) {
        execFileSync('git', ['add', '--', 'src/latent.ts'], { cwd: root })
        staged = true
      }
      return result
    }

    const result = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(staged, true)
    assert.equal(result.ok, false)
    assert.equal(result.current, false)
    assert.equal(result.wrote, false)
    assert.ok(result.diagnostics.some((item) =>
      /Git|index|inventory|snapshot|transaction|changed/i.test(
        `${item.code} ${item.message}`,
      ),
    ))
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('coverage update converges after a source changes during atomic report commit', async () => {
  const {
    checkAuditCoverage,
    updateAuditCoverage,
  } = await generatorApi()
  const root = makeRepo()
  const sourcePath = path.join(root, 'src/a.ts')
  const originalRename = fs.renameSync
  let modified = false
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    const baseline = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(baseline.current, true)
    write(root, 'src/a.ts', 'export const a = 2\n')

    fs.renameSync = function mutateSourceDuringCoverageCommit(
      source,
      destination,
    ) {
      if (
        !modified &&
        path.basename(String(destination)) === 'review-coverage.json'
      ) {
        fs.writeFileSync(sourcePath, 'export const a = 3\n')
        modified = true
      }
      return originalRename.call(fs, source, destination)
    }

    const result = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(modified, true)
    assert.equal(result.ok, true)
    assert.equal(result.current, true)
    assert.equal(result.wrote, true)
    assert.equal(
      result.report.entries.find((entry) => entry.path === 'src/a.ts').blob,
      gitBlob(root, 'src/a.ts'),
      'returned report must describe the post-commit source snapshot',
    )
    assert.equal(
      fs.readFileSync(
        path.join(root, '.atlas/review-coverage.json'),
        'utf8',
      ),
      result.bytes,
    )
    const checked = checkAuditCoverage(root, { allowIncomplete: true })
    assert.equal(checked.current, true)
    assert.equal(checked.ok, true)
  } finally {
    fs.renameSync = originalRename
    cleanup(root)
  }
})

test('coverage update fails closed after bounded atomic-write churn', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const root = makeRepo()
  const sourcePath = path.join(root, 'src/a.ts')
  const originalRename = fs.renameSync
  let coverageWrites = 0
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    const baseline = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(baseline.current, true)
    write(root, 'src/a.ts', 'export const a = 2\n')

    fs.renameSync = function churnSourceDuringCoverageCommit(
      source,
      destination,
    ) {
      if (path.basename(String(destination)) === 'review-coverage.json') {
        coverageWrites += 1
        fs.writeFileSync(
          sourcePath,
          `export const a = ${coverageWrites + 2}\n`,
        )
      }
      return originalRename.call(fs, source, destination)
    }

    const result = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(coverageWrites, 3)
    assert.equal(result.ok, false)
    assert.equal(result.current, false)
    assert.equal(result.wrote, true)
    assert.ok(result.diagnostics.some((item) =>
      item.code === 'coverage-update-did-not-converge',
    ))
  } finally {
    fs.renameSync = originalRename
    cleanup(root)
  }
})

test('hostile coverage reader rejects fresh claims from a policy-rejected ruleset', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const { loadAuditPortfolios } = await auditsApi()
  const { loadReviewCoverage } = await import('../dist/review-coverage.js')
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    const policy = reviewPolicy()
    policy.securityDecisions.acceptedRulesets = ['other-ruleset']
    writePolicy(root, policy)
    writeV2(root)

    const generated = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(generated.report.verdict, 'incomplete')
    const forged = structuredClone(generated.report)
    const source = forged.entries.find((entry) => entry.path === 'src/a.ts')
    source.evidence.security = {
      status: 'fresh',
      ledgers: ['security-source'],
    }
    forged.summary.securityMissing -= 1
    forged.summary.securityFresh += 1
    forged.verdict = 'complete'
    write(
      root,
      '.atlas/review-coverage.json',
      `${JSON.stringify(forged, null, 2)}\n`,
    )

    const loaded = loadReviewCoverage(root, loadAuditPortfolios(root))
    assert.equal(loaded.state, 'invalid')
    assert.ok(loaded.errors.some((item) =>
      /ruleset|accepted|fresh evidence/i.test(`${item.code} ${item.message}`),
    ))
  } finally {
    cleanup(root)
  }
})

test('policy rejects unsafe globs, non-route slugs, padded text, and broad code exclusions', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
  } = await policyApi()
  const root = makeRepo()
  try {
    for (const include of [
      ['!src/**'],
      ['/absolute/**'],
      ['C:/windows/**'],
      ['./src/**'],
      ['src/../secret/**'],
      ['src//**'],
    ]) {
      writePolicy(root, reviewPolicy({
        rules: [{
          id: 'unsafe',
          include,
          rationale: 'Unsafe glob.',
          domains: ['security'],
        }],
      }))
      assert.equal(loadAuditReviewPolicy(root).policy, null, include[0])
    }

    writePolicy(root, reviewPolicy({
      units: [{
        domain: 'security',
        slug: 'bad_slug',
        title: 'Bad slug',
        include: ['src/**'],
      }],
    }))
    assert.equal(loadAuditReviewPolicy(root).policy, null)

    const padded = reviewPolicy()
    padded.rules[0].rationale = ' padded rationale '
    writePolicy(root, padded)
    assert.equal(loadAuditReviewPolicy(root).policy, null)

    writePolicy(root, reviewPolicy({
      rules: [{
        id: 'broad-source-exclusion',
        include: ['src/**'],
        rationale: 'Generated source.',
        excluded: {
          category: 'generated',
          reason: 'Generated source.',
          owner: 'generator',
        },
      }],
      units: [],
    }))
    const broad = loadAuditReviewPolicy(root)
    assert.notEqual(broad.policy, null)
    const blob = 'a'.repeat(40)
    const classified = classifyAuditInventory([{
      path: 'src/a.ts',
      indexBlob: blob,
      currentBlob: blob,
      indexMode: '100644',
      currentMode: '100644',
      deleted: false,
    }], broad.policy)
    assert.equal(classified.files[0].classification.kind, 'conflict')
    assert.ok(classified.diagnostics.some((item) =>
      /exact.*owner|broad.*exclusion|source.*exclusion/i.test(
        `${item.code} ${item.message}`,
      ),
    ))

    const exactPolicy = reviewPolicy({
      rules: [{
        id: 'exact-source-exclusion',
        include: ['src/a.ts'],
        rationale: 'Generated source.',
        excluded: {
          category: 'generated',
          reason: 'Generated source.',
          owner: 'generator',
        },
      }],
      units: [],
    })
    writePolicy(root, exactPolicy)
    const exact = loadAuditReviewPolicy(root)
    const exactClassified = classifyAuditInventory([{
      path: 'src/a.ts',
      indexBlob: blob,
      currentBlob: blob,
      indexMode: '100644',
      currentMode: '100644',
      deleted: false,
    }], exact.policy)
    assert.equal(exactClassified.files[0].classification.kind, 'excluded')
    assert.deepEqual(exactClassified.diagnostics, [])
  } finally {
    cleanup(root)
  }
})

test('configuration exclusions require exact ownership across the Relay corpus', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
  } = await policyApi()
  const root = makeRepo()
  const extensions = [
    'bash', 'c', 'cc', 'cjs', 'cpp', 'cts', 'fish', 'go', 'graphql', 'h',
    'hcl', 'hpp', 'java', 'js', 'jsx', 'kt', 'kts', 'mjs', 'mts', 'key',
    'keystore', 'nix', 'p12', 'pem', 'pfx', 'proto', 'ps1', 'py', 'rb', 'rs',
    'sh', 'sql', 'swift', 'tf', 'tfvars', 'toml', 'ts', 'tsx', 'yaml', 'yml',
    'zsh',
  ]
  const locks = [
    'bun.lock',
    'bun.lockb',
    'Cargo.lock',
    'composer.lock',
    'Gemfile.lock',
    'go.sum',
    'package-lock.json',
    'Pipfile.lock',
    'pnpm-lock.yaml',
    'poetry.lock',
    'yarn.lock',
  ]
  const controls = [
    '.dockerignore',
    '.gitignore',
    '.npmrc',
    '.nvmrc',
    '.sops.yaml',
    '.sops.yml',
    'CODEOWNERS',
    'composer.json',
    'deno.json',
    'deno.jsonc',
    'Dockerfile',
    'Gemfile',
    'go.mod',
    'gradle.properties',
    'Makefile',
    'package.json',
    'Pipfile',
    'pnpm-workspace.yaml',
    'pom.xml',
    'requirements.txt',
    'review-policy.json',
    'settings.gradle',
    'settings.gradle.kts',
    'build.gradle',
    'build.gradle.kts',
    'turbo.json',
  ]
  const hazardousPaths = [
    ...extensions.map((extension) => `fixtures/example.${extension}`),
    ...controls.map((name) => `fixtures/${name}`),
    '.agents-src/reviewer.md',
    '.env.example',
    'certs/signing.keystore',
    'deps/Gemfile',
    'deps/composer.json',
    'deps/go.mod',
    'deps/requirements.txt',
    'deps/pnpm-lock.yaml',
  ]
  const inertPaths = [
    ...locks.map((name) => `fixtures/${name}`),
    'fixtures/AGENTS.md',
    'fixtures/CLAUDE.md',
    'fixtures/guide.md',
    'fixtures/guide.mdx',
    'fixtures/readme.txt',
  ]
  const blob = 'a'.repeat(40)
  const inventory = [
    ...hazardousPaths,
    ...inertPaths,
    'outside/readme.txt',
  ].map((repoPath) => ({
    path: repoPath,
    indexBlob: blob,
    currentBlob: blob,
    indexMode: repoPath === 'deps/pnpm-lock.yaml' ? '100755' : '100644',
    currentMode: repoPath === 'deps/pnpm-lock.yaml' ? '100755' : '100644',
    deleted: false,
  }))
  try {
    writePolicy(root, reviewPolicy({
      rules: [
        {
          id: 'broad-fixture-exclusion',
          include: [
            'fixtures/**',
            '.agents-src/**',
            '.env*',
            'certs/**',
            'deps/**',
          ],
          except: [],
          rationale: 'Generated fixture material.',
          excluded: {
            category: 'generated',
            reason: 'Generated fixture material.',
            owner: 'fixture-generator',
          },
        },
        {
          id: 'outside-document',
          include: ['outside/readme.txt'],
          except: [],
          rationale: 'Unrelated document.',
          excluded: {
            category: 'documentation',
            reason: 'Unrelated document.',
            owner: 'docs',
          },
        },
      ],
      units: [],
    }))
    const broad = loadAuditReviewPolicy(root)
    assert.notEqual(broad.policy, null)
    const broadClassification = classifyAuditInventory(
      inventory,
      broad.policy,
    )
    for (const repoPath of hazardousPaths) {
      assert.equal(
        broadClassification.files.find((file) => file.path === repoPath)
          .classification.kind,
        'conflict',
        repoPath,
      )
    }
    for (const repoPath of inertPaths) {
      assert.equal(
        broadClassification.files.find((file) => file.path === repoPath)
          .classification.kind,
        'excluded',
        repoPath,
      )
    }

    writePolicy(root, reviewPolicy({
      rules: hazardousPaths.map((repoPath, index) => ({
        id: `exact-config-${String(index).padStart(3, '0')}`,
        include: [repoPath],
        except: [],
        rationale: 'Exact generated configuration fixture.',
        excluded: {
          category: 'generated',
          reason: 'Exact generated configuration fixture.',
          owner: 'fixture-generator',
        },
      })),
      units: [],
    }))
    const exact = loadAuditReviewPolicy(root)
    assert.notEqual(exact.policy, null)
    const exactClassification = classifyAuditInventory(
      inventory.filter((file) => hazardousPaths.includes(file.path)),
      exact.policy,
    )
    assert.deepEqual(exactClassification.diagnostics, [])
    assert.ok(exactClassification.files.every((file) =>
      file.classification.kind === 'excluded'))
  } finally {
    cleanup(root)
  }
})

test('tracked inventory rejects hostile path encodings, aliases, modes, and collisions', async () => {
  const { readAuditTrackedInventory } = await policyApi()
  const roots = []
  try {
    const nfcRoot = makeRepo()
    roots.push(nfcRoot)
    write(nfcRoot, 'src/cafe\u0301.ts', 'export const decomposed = true\n')
    commitAll(nfcRoot)
    assert.ok(readAuditTrackedInventory(nfcRoot).diagnostics.some((item) =>
      /NFC|normalization/i.test(`${item.code} ${item.message}`),
    ))

    const collisionRoot = makeRepo()
    roots.push(collisionRoot)
    write(collisionRoot, 'src/A.ts', 'export const upper = true\n')
    write(collisionRoot, 'src/a.ts', 'export const lower = true\n')
    commitAll(collisionRoot)
    assert.ok(readAuditTrackedInventory(collisionRoot).diagnostics.some(
      (item) => /collision/i.test(`${item.code} ${item.message}`),
    ))

    const aliasRoot = makeRepo()
    roots.push(aliasRoot)
    write(aliasRoot, 'C:/evil.ts', 'export const evil = true\n')
    commitAll(aliasRoot)
    assert.ok(readAuditTrackedInventory(aliasRoot).diagnostics.some((item) =>
      /invalid-tracked-path|drive|normalized/i.test(
        `${item.code} ${item.message}`,
      ),
    ))

    const modeRoot = makeRepo()
    roots.push(modeRoot)
    write(modeRoot, 'script.sh', '#!/bin/sh\nexit 0\n')
    commitAll(modeRoot)
    fs.chmodSync(path.join(modeRoot, 'script.sh'), 0o755)
    assert.ok(readAuditTrackedInventory(modeRoot).diagnostics.some((item) =>
      /mode.*drift|executable/i.test(`${item.code} ${item.message}`),
    ))

    const symlinkRoot = makeRepo()
    roots.push(symlinkRoot)
    write(symlinkRoot, 'target.txt', 'target\n')
    fs.symlinkSync('target.txt', path.join(symlinkRoot, 'link.txt'))
    commitAll(symlinkRoot)
    assert.ok(readAuditTrackedInventory(symlinkRoot).diagnostics.some((item) =>
      /120000|symlink|mode/i.test(`${item.code} ${item.message}`),
    ))

    const gitlinkRoot = makeRepo()
    roots.push(gitlinkRoot)
    commitAll(gitlinkRoot)
    const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: gitlinkRoot,
      encoding: 'utf8',
    }).trim()
    execFileSync(
      'git',
      ['update-index', '--add', '--cacheinfo', `160000,${commit},vendor/sub`],
      { cwd: gitlinkRoot },
    )
    assert.ok(readAuditTrackedInventory(gitlinkRoot).diagnostics.some((item) =>
      /160000|gitlink|mode/i.test(`${item.code} ${item.message}`),
    ))

    const stageRoot = makeRepo()
    roots.push(stageRoot)
    write(stageRoot, 'conflict.txt', 'base\n')
    commitAll(stageRoot)
    const blob = gitBlob(stageRoot, 'conflict.txt')
    execFileSync('git', ['update-index', '--index-info'], {
      cwd: stageRoot,
      input:
        `0 ${'0'.repeat(40)}\tconflict.txt\n` +
        `100644 ${blob} 1\tconflict.txt\n` +
        `100644 ${blob} 2\tconflict.txt\n`,
    })
    assert.ok(readAuditTrackedInventory(stageRoot).diagnostics.some((item) =>
      /stage|unmerged|unresolved/i.test(`${item.code} ${item.message}`),
    ))

    const utf8Root = makeRepo()
    roots.push(utf8Root)
    const invalidPath = Buffer.concat([
      Buffer.from(`${utf8Root}/src/`),
      Buffer.from([0xff]),
      Buffer.from('.ts'),
    ])
    fs.mkdirSync(path.join(utf8Root, 'src'), { recursive: true })
    fs.writeFileSync(invalidPath, 'invalid path\n')
    commitAll(utf8Root)
    assert.ok(readAuditTrackedInventory(utf8Root).diagnostics.some((item) =>
      /UTF-8|encoding/i.test(`${item.code} ${item.message}`),
    ))
  } finally {
    for (const root of roots) cleanup(root)
  }
})

test('tracked inventory handles newline and option-like paths without delimiter confusion', async () => {
  const { readAuditTrackedInventory } = await policyApi()
  const root = makeRepo()
  try {
    write(root, 'line\nbreak.ts', 'export const newline = true\n')
    write(root, '-option.ts', 'export const option = true\n')
    commitAll(root)
    const inventory = readAuditTrackedInventory(root)
    assert.deepEqual(inventory.diagnostics, [])
    assert.ok(inventory.files.some((file) => file.path === 'line\nbreak.ts'))
    assert.ok(inventory.files.some((file) => file.path === '-option.ts'))
  } finally {
    cleanup(root)
  }
})

test('public classifier rejects forged rows, duplicate paths, and incoherent deletions without invoking getters', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
  } = await policyApi()
  const root = makeRepo()
  try {
    writePolicy(root, reviewPolicy())
    const loaded = loadAuditReviewPolicy(root)
    const blob = 'a'.repeat(40)
    const row = {
      path: 'src/a.ts',
      indexBlob: blob,
      currentBlob: blob,
      indexMode: '100644',
      currentMode: '100644',
      deleted: false,
    }
    const duplicate = classifyAuditInventory([row, { ...row }], loaded.policy)
    assert.ok(duplicate.diagnostics.some((item) =>
      /duplicate/i.test(`${item.code} ${item.message}`),
    ))
    assert.ok(duplicate.files.every(
      (file) => file.classification.kind === 'conflict',
    ))

    const deletion = classifyAuditInventory([{
      ...row,
      deleted: true,
    }], loaded.policy)
    assert.ok(deletion.diagnostics.some((item) =>
      /delet|coheren|currentBlob/i.test(`${item.code} ${item.message}`),
    ))
    assert.equal(deletion.files[0].classification.kind, 'conflict')

    let getterRan = false
    const accessor = {}
    Object.defineProperty(accessor, 'path', {
      enumerable: true,
      get() {
        getterRan = true
        throw new Error('must not execute')
      },
    })
    const accessorResult = classifyAuditInventory([accessor], loaded.policy)
    assert.equal(getterRan, false)
    assert.equal(accessorResult.files.length, 0)
    assert.ok(accessorResult.diagnostics.some((item) =>
      /accessor|plain|invalid.*inventory/i.test(
        `${item.code} ${item.message}`,
      ),
    ))
  } finally {
    cleanup(root)
  }
})

test('public classifier accepts the reader inventory ceiling instead of the policy row ceiling', async () => {
  const { classifyAuditInventory } = await policyApi()
  const inventory = Array.from(
    { length: 10_001 },
    (_, index) => trackedFile(`src/file-${index}.ts`),
  )
  const accepted = classifyAuditInventory(inventory, null)
  assert.equal(accepted.files.length, inventory.length)
  assert.ok(!accepted.diagnostics.some((item) =>
    item.code === 'invalid-inventory-input'))

  const overReaderLimit = new Array(1_000_001)
  const rejected = classifyAuditInventory(overReaderLimit, null)
  assert.deepEqual(rejected.files, [])
  assert.ok(rejected.diagnostics.some((item) =>
    item.code === 'invalid-inventory-input' &&
    /1[,_]?000[,_]?000|1000000/.test(item.message)))
})

test('public snapshots reject array and object side properties without invoking accessors', async () => {
  const { normalizeAuditReviewPolicy } = await policyApi()
  const cases = [
    ['array symbol', (policy) => {
      policy.rules[Symbol('hostile')] = true
    }],
    ['array enumerable extra', (policy) => {
      policy.rules.extra = true
    }],
    ['array hidden extra', (policy) => {
      Object.defineProperty(policy.rules, 'hidden', {
        value: true,
        enumerable: false,
      })
    }],
    ['array hidden index', (policy) => {
      Object.defineProperty(policy.rules, '0', {
        value: policy.rules[0],
        enumerable: false,
      })
    }],
    ['object hidden extra', (policy) => {
      Object.defineProperty(policy, 'hidden', {
        value: true,
        enumerable: false,
      })
    }],
  ]
  for (const [label, mutate] of cases) {
    const policy = reviewPolicy()
    mutate(policy)
    assert.throws(
      () => normalizeAuditReviewPolicy(policy),
      /plain|own propert|enumerable|symbol|array|data property/i,
      label,
    )
  }

  for (const target of ['array', 'object']) {
    let getterRan = false
    const policy = reviewPolicy()
    const owner = target === 'array' ? policy.rules : policy
    Object.defineProperty(owner, 'hiddenAccessor', {
      enumerable: false,
      get() {
        getterRan = true
        throw new Error('must not execute')
      },
    })
    assert.throws(
      () => normalizeAuditReviewPolicy(policy),
      /accessor|own propert|enumerable|plain/i,
      target,
    )
    assert.equal(getterRan, false, target)
  }
})

test('public snapshots enforce aggregate node and string budgets before cloning hostile inputs', async () => {
  const { normalizeAuditReviewPolicy } = await policyApi()

  const nodeBomb = reviewPolicy()
  nodeBomb.padding = Array.from(
    { length: 101 },
    () => new Array(10_000).fill(null),
  )
  assert.throws(
    () => normalizeAuditReviewPolicy(nodeBomb),
    /aggregate.*node|node.*limit|collection.*limit/i,
  )

  const stringBomb = reviewPolicy()
  stringBomb.padding = Array.from(
    { length: 33 },
    () => 'x'.repeat(256 * 1024),
  )
  assert.throws(
    () => normalizeAuditReviewPolicy(stringBomb),
    /aggregate.*string|aggregate.*text|string.*limit/i,
  )
})

test('public policy snapshots reject prototype keys and non-finite numbers before traversal', async () => {
  const { normalizeAuditReviewPolicy } = await policyApi()
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    const policy = reviewPolicy()
    let getterRan = false
    Object.defineProperty(policy.rules[0], key, {
      enumerable: true,
      get() {
        getterRan = true
        throw new Error('must not execute')
      },
    })
    assert.throws(
      () => normalizeAuditReviewPolicy(policy),
      /prohibited prototype key/i,
      key,
    )
    assert.equal(getterRan, false, key)
  }

  for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    const policy = reviewPolicy()
    policy.padding = value
    assert.throws(
      () => normalizeAuditReviewPolicy(policy),
      /finite safe JSON number/i,
    )
  }
})

test('public classifier rejects excessive rule and unit matching before any partial classification', async () => {
  const { classifyAuditInventory } = await policyApi()
  const inventory = Array.from(
    { length: 1_001 },
    (_, index) => trackedFile(`src/file-${index}.ts`),
  )
  const include = [
    '**',
    ...Array.from(
      { length: 4_999 },
      (_, index) => `unused/pattern-${index}/**`,
    ),
  ]
  const result = classifyAuditInventory(inventory, reviewPolicy({
    rules: [{
      id: 'large-source-rule',
      include,
      except: [],
      rationale: 'Deliberately large matcher corpus.',
      domains: ['security'],
    }],
    units: [{
      domain: 'security',
      slug: 'security-source',
      title: 'Source',
      include: ['**'],
      except: [],
      context: [],
    }],
  }))

  assert.equal(result.files.length, inventory.length)
  assert.ok(result.files.every((file) =>
    file.ruleIds.length === 0 &&
    file.classification.kind === 'conflict'))
  assert.deepEqual(
    result.diagnostics.filter((item) =>
      item.code === 'classification-resource-limit'),
    [{
      code: 'classification-resource-limit',
      message:
        'classification requires 5006001 worst-case match operations; ' +
        'limit is 5000000',
    }],
  )
})

test('generated-proof is accepted only through the exact reserved policy classification', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
  } = await policyApi()
  const { buildAuditCoverageReport } = await generatorApi()
  const root = makeRepo()
  try {
    const self = {
      path: '.atlas/review-coverage.json',
      indexBlob: 'a'.repeat(40),
      currentBlob: 'a'.repeat(40),
      indexMode: '100644',
      currentMode: '100644',
      deleted: false,
    }
    const inventory = {
      objectFormat: 'sha1',
      files: [self],
      diagnostics: [],
    }

    writePolicy(root, reviewPolicy({ rules: [], units: [] }))
    const missing = loadAuditReviewPolicy(root)
    const missingClassification = classifyAuditInventory(
      inventory.files,
      missing.policy,
    )
    const rejected = buildAuditCoverageReport({
      policy: missing.policy,
      policyHash: missing.policyHash,
      inventory,
      classification: missingClassification,
      evidence: emptyExactEvidence(),
    })
    assert.equal(rejected.verdict, 'invalid')
    assert.ok(rejected.reportErrors.some((item) =>
      /generated-proof|classification|reserved/i.test(
        `${item.code} ${item.message}`,
      ),
    ))

    writePolicy(root, reviewPolicy({
      rules: [{
        id: 'generated-proof',
        include: ['.atlas/review-coverage.json'],
        rationale: 'Canonical generated coverage proof.',
        excluded: {
          category: 'generated-proof',
          reason: 'Canonical generated coverage proof.',
          owner: 'repo-atlas',
        },
      }],
      units: [],
    }))
    const exact = loadAuditReviewPolicy(root)
    const exactClassification = classifyAuditInventory(
      inventory.files,
      exact.policy,
    )
    const accepted = buildAuditCoverageReport({
      policy: exact.policy,
      policyHash: exact.policyHash,
      inventory,
      classification: exactClassification,
      evidence: emptyExactEvidence(),
    })
    assert.equal(accepted.verdict, 'complete')
    assert.equal(accepted.entries[0].blob, undefined)
    assert.deepEqual(accepted.entries[0].ruleIds, ['generated-proof'])
    assert.equal(accepted.entries[0].classification.ruleId, 'generated-proof')
    assert.equal(
      accepted.entries[0].classification.category,
      'generated-proof',
    )
  } finally {
    cleanup(root)
  }
})

test('public builder emits structurally readable invalid placeholders for non-SHA-1 inventories', async () => {
  const {
    classifyAuditInventory,
    normalizeAuditReviewPolicy,
  } = await policyApi()
  const { buildAuditCoverageReport } = await generatorApi()
  const { loadReviewCoverage } = await coverageReaderApi()
  const normalized = normalizeAuditReviewPolicy(reviewPolicy())
  const root = makeRepo()
  try {
    for (const [objectFormat, blob, diagnosticCode] of [
      ['sha256', 'a'.repeat(64), 'unsupported-object-format'],
      [null, 'a'.repeat(40), 'invalid-object-format'],
    ]) {
      const files = [trackedFile('src/a.ts', blob)]
      const report = buildAuditCoverageReport({
        policy: normalized.policy,
        policyHash: normalized.policyHash,
        inventory: {
          objectFormat,
          files,
          diagnostics: [],
        },
        classification: classifyAuditInventory(files, normalized.policy),
        evidence: emptyExactEvidence(),
      })

      assert.equal(report.verdict, 'invalid')
      assert.deepEqual(report.entries, [])
      assert.ok(report.reportErrors.some((item) =>
        item.code === diagnosticCode))

      write(
        root,
        '.atlas/review-coverage.json',
        `${JSON.stringify(report, null, 2)}\n`,
      )
      const loaded = loadReviewCoverage(root, {})
      assert.equal(loaded.state, 'invalid')
      assert.ok(loaded.errors.some((item) => item.code === diagnosticCode))
      assert.ok(loaded.errors.every((item) => item.code !== 'malformed-report'))
    }

    const malformedAfterInventory = buildAuditCoverageReport({
      policy: normalized.policy,
      policyHash: normalized.policyHash,
      inventory: {
        objectFormat: 'sha256',
        files: [trackedFile('src/a.ts', 'b'.repeat(64))],
        diagnostics: [],
      },
      classification: {
        files: [],
        diagnostics: [{ code: 'missing-message' }],
      },
      evidence: emptyExactEvidence(),
    })
    assert.equal(malformedAfterInventory.verdict, 'invalid')
    assert.deepEqual(malformedAfterInventory.entries, [])
    write(
      root,
      '.atlas/review-coverage.json',
      `${JSON.stringify(malformedAfterInventory)}\n`,
    )
    assert.ok(loadReviewCoverage(root, {}).errors.every((item) =>
      item.code !== 'malformed-report'))
  } finally {
    cleanup(root)
  }
})

test('exact freshness is per receipt, not poisoned across a partially drifted unit', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
    readAuditTrackedInventory,
  } = await policyApi()
  const { loadAuditExactEvidence } = await auditsApi()
  const { buildAuditCoverageReport } = await generatorApi()
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, 'src/b.ts', 'export const b = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    writeV2(root, { files: ['src/a.ts', 'src/b.ts'] })
    write(root, 'src/b.ts', 'export const b = 2\n')

    const policy = loadAuditReviewPolicy(root)
    const inventory = readAuditTrackedInventory(root)
    const classification = classifyAuditInventory(
      inventory.files,
      policy.policy,
    )
    const report = buildAuditCoverageReport({
      policy: policy.policy,
      policyHash: policy.policyHash,
      inventory,
      classification,
      evidence: loadAuditExactEvidence(root),
    })
    assert.equal(
      report.entries.find((entry) => entry.path === 'src/a.ts')
        .evidence.security.status,
      'fresh',
    )
    assert.equal(
      report.entries.find((entry) => entry.path === 'src/b.ts')
        .evidence.security.status,
      'stale',
    )
  } finally {
    cleanup(root)
  }
})

test('legacy exact-evidence hash membership is indexed instead of rescanning every scope row', async () => {
  const { loadAuditExactEvidence } = await auditsApi()
  const root = makeRepo()
  const originalIncludes = Array.prototype.includes
  const files = Array.from(
    { length: 128 },
    (_, index) => `src/file-${String(index).padStart(3, '0')}.ts`,
  )
  let scopeMembershipScans = 0
  try {
    for (const [index, repoPath] of files.entries()) {
      write(root, repoPath, `export const value${index} = ${index}\n`)
    }
    commitAll(root)
    writeV2(root, { files })

    Array.prototype.includes = function trackScopeMembership(
      searchElement,
      ...rest
    ) {
      if (
        this.length === files.length &&
        this[0] === files[0] &&
        this[this.length - 1] === files[files.length - 1] &&
        typeof searchElement === 'string'
      ) {
        scopeMembershipScans += 1
      }
      return originalIncludes.call(this, searchElement, ...rest)
    }
    const evidence = loadAuditExactEvidence(root)
    assert.equal(evidence.invalidLedgers.length, 0)
    assert.equal(evidence.units.length, 1)
    assert.equal(evidence.units[0].receipts.length, files.length)
  } finally {
    Array.prototype.includes = originalIncludes
    cleanup(root)
  }

  assert.equal(
    scopeMembershipScans,
    0,
    'hash-key validation must not linearly rescan the files array per key',
  )
})

test('V1 V2 and V3 exact evidence share one bounded source snapshot cache', async () => {
  const { loadAuditExactEvidence } = await auditsApi()
  const root = makeRepo()
  const sourcePath = path.join(root, 'src/a.ts')
  const originalOpen = fs.openSync
  let sourceOpens = 0
  try {
    write(
      root,
      '.atlas/config.json',
      '{"formatVersion":1,"exclude":[],"repositoryId":"repo_fixture"}\n',
    )
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writeV2(root, { slug: 'legacy-source' })
    await publishOpenV3(root)

    fs.openSync = function countSourceSnapshots(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        if (fs.realpathSync(`/proc/self/fd/${fd}`) === sourcePath) {
          sourceOpens += 1
        }
      } catch {
        // Only successfully opened source descriptors matter here.
      }
      return fd
    }

    const evidence = loadAuditExactEvidence(root)
    assert.deepEqual(evidence.invalidLedgers, [])
    assert.equal(evidence.units.length, 2)
    assert.equal(
      evidence.units.filter((unit) =>
        unit.receipts.some((receipt) => receipt.path === 'src/a.ts')).length,
      2,
    )
    assert.equal(
      sourceOpens,
      1,
      'every evidence version must reuse the same exact-file inspector cache',
    )
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
  }
})

test('normalized evidence preserves invalid ledger claims and malformed V1 is never silent', async () => {
  const { loadAuditExactEvidence } = await auditsApi()
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, '.atlas/audits/unsafe.json', `${JSON.stringify({
      formatVersion: 2,
      format: 'atlas-audit-v2',
      domain: 'security',
      reviewState: 'complete',
      slug: 'unsafe',
      title: 'Unsafe',
      ruleset: 'atlas-security-v3',
      scanned_at: '2026-07-29',
      scope_hash: 'a'.repeat(40),
      file_count: 1,
      files: ['../outside.ts'],
      hashes: { '../outside.ts': 'b'.repeat(40) },
      findings: [],
      dropped: [],
      rounds: [],
    })}\n`)
    write(root, '.atlas/audits/silent-v1.json', `${JSON.stringify({
      formatVersion: 1,
      format: 'atlas-audit-v1',
      slug: 'silent-v1',
      title: 'Silent V1',
      ruleset: 'legacy',
      scanned_at: '2026-07-29',
      scope_hash: scopeHash(root, ['src/a.ts']),
      file_count: 1,
      files: ['src/a.ts'],
      findings: [],
    })}\n`)

    const loaded = loadAuditExactEvidence(root)
    assert.ok(loaded.invalidLedgers.some((item) =>
      /silent-v1|finalPass|legacy/i.test(`${item.slug} ${item.message}`),
    ))
    assert.ok(loaded.invalidClaimedPaths.some((item) =>
      item.path === '../outside.ts' &&
      item.slug === 'unsafe' &&
      item.domain === 'security',
    ))
  } finally {
    cleanup(root)
  }
})

test('historical assignments cannot overlap current inventory classification', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
  } = await policyApi()
  const root = makeRepo()
  try {
    writePolicy(root, reviewPolicy({
      historicalUnitAssignments: [{
        id: 'retired-source',
        sourceKind: 'relayos-security-scan/v1',
        domain: 'security',
        unit: 'security-source',
        include: ['src/**'],
      }],
    }))
    const loaded = loadAuditReviewPolicy(root)
    assert.notEqual(loaded.policy, null)
    const blob = 'a'.repeat(40)
    const classified = classifyAuditInventory([{
      path: 'src/a.ts',
      indexBlob: blob,
      currentBlob: blob,
      indexMode: '100644',
      currentMode: '100644',
      deleted: false,
    }], loaded.policy)
    assert.ok(classified.diagnostics.some((item) =>
      /historical.*current|current.*historical/i.test(
        `${item.code} ${item.message}`,
      ),
    ))
    assert.equal(classified.files[0].classification.kind, 'conflict')
  } finally {
    cleanup(root)
  }
})

test('public report builder recomputes forged classification and never invokes accessors', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
    readAuditTrackedInventory,
  } = await policyApi()
  const { buildAuditCoverageReport } = await generatorApi()
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    const policy = loadAuditReviewPolicy(root)
    const inventory = readAuditTrackedInventory(root)
    const classification = classifyAuditInventory(
      inventory.files,
      policy.policy,
    )
    const forged = structuredClone(classification)
    const source = forged.files.find((file) => file.path === 'src/a.ts')
    source.ruleIds = ['forged-exclusion']
    source.classification = {
      kind: 'excluded',
      ruleId: 'forged-exclusion',
      category: 'generated',
      reason: 'forged',
    }
    const report = buildAuditCoverageReport({
      policy: policy.policy,
      policyHash: policy.policyHash,
      inventory,
      classification: forged,
      evidence: emptyExactEvidence(),
    })
    assert.equal(report.verdict, 'invalid')
    assert.equal(
      report.entries.find((entry) => entry.path === 'src/a.ts')
        .classification.kind,
      'review',
    )
    assert.ok(report.reportErrors.some((item) =>
      /forged.*classification|recomputation/i.test(
        `${item.code} ${item.message}`,
      ),
    ))

    let getterRan = false
    const hostileInventory = {
      objectFormat: 'sha1',
      diagnostics: [],
    }
    Object.defineProperty(hostileInventory, 'files', {
      enumerable: true,
      get() {
        getterRan = true
        throw new Error('must not execute')
      },
    })
    let hostileReport
    assert.doesNotThrow(() => {
      hostileReport = buildAuditCoverageReport({
        policy: policy.policy,
        policyHash: policy.policyHash,
        inventory: hostileInventory,
        classification,
        evidence: emptyExactEvidence(),
      })
    })
    assert.equal(getterRan, false)
    assert.equal(hostileReport.verdict, 'invalid')
  } finally {
    cleanup(root)
  }
})

test('public policy and coverage snapshots reject proxies before invoking traps', async () => {
  const { normalizeAuditReviewPolicy } = await policyApi()
  const { buildAuditCoverageReport } = await generatorApi()
  let policyTrapCalls = 0
  const policyProxy = new Proxy(reviewPolicy(), {
    getPrototypeOf() {
      policyTrapCalls += 1
      throw new Error('policy proxy trap must not execute')
    },
  })
  assert.throws(
    () => normalizeAuditReviewPolicy(policyProxy),
    /proxy|plain|policy|input|data/i,
  )
  assert.equal(policyTrapCalls, 0)

  let coverageTrapCalls = 0
  const coverageProxy = new Proxy({}, {
    getPrototypeOf() {
      coverageTrapCalls += 1
      throw new Error('coverage proxy trap must not execute')
    },
  })
  const report = buildAuditCoverageReport(coverageProxy)
  assert.equal(report.verdict, 'invalid')
  assert.equal(coverageTrapCalls, 0)
  assert.ok(report.reportErrors.some((item) =>
    /proxy|plain|input|data/i.test(`${item.code} ${item.message}`),
  ))
})

test('coverage V1 refuses SHA-256 Git repositories before writing', async () => {
  const {
    checkAuditCoverage,
    updateAuditCoverage,
  } = await generatorApi()
  const os = await import('node:os')
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sha256-'))
  try {
    try {
      execFileSync('git', ['init', '-q', '--object-format=sha256'], {
        cwd: root,
      })
    } catch {
      return
    }
    execFileSync('git', ['config', 'user.email', 'test@example.invalid'], {
      cwd: root,
    })
    execFileSync('git', ['config', 'user.name', 'test'], { cwd: root })
    write(root, '.atlas/config.json', '{"formatVersion":1,"exclude":[]}\n')
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())

    const result = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(result.ok, false)
    assert.equal(result.wrote, false)
    assert.equal(result.current, false)
    assert.ok(result.diagnostics.some((item) =>
      item.code === 'unsupported-object-format',
    ))
    assert.equal(
      fs.existsSync(path.join(root, '.atlas/review-coverage.json')),
      false,
    )
    assert.deepEqual(result.report.entries, [])

    const checked = checkAuditCoverage(root, { allowIncomplete: true })
    assert.equal(checked.ok, false)
    assert.equal(checked.wrote, false)
    assert.equal(checked.current, false)
    assert.deepEqual(checked.report.entries, [])
    assert.ok(checked.diagnostics.some((item) =>
      item.code === 'unsupported-object-format'))
  } finally {
    cleanup(root)
  }
})

test('coverage transactions refuse a missing anchored Git object format without touching coverage bytes', async () => {
  const {
    checkAuditCoverage,
    updateAuditCoverage,
  } = await generatorApi()
  const root = makeRepo()
  const tooling = makeRepo()
  const originalPath = process.env.PATH
  const originalLstat = fs.lstatSync
  const originalOpen = fs.openSync
  const originalRename = fs.renameSync
  const marker = path.join(tooling, 'object-format-failures')
  let coverageTouches = 0
  let updated
  let checked
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())

    const realGit = execFileSync('which', ['git'], {
      encoding: 'utf8',
    }).trim()
    const wrapper = path.join(tooling, 'git')
    fs.writeFileSync(
      wrapper,
      `#!/usr/bin/env node
const fs = require('node:fs')
const { spawnSync } = require('node:child_process')
const args = process.argv.slice(2)
if (
  args.includes('rev-parse') &&
  args.includes('--show-object-format=storage')
) {
  fs.appendFileSync(${JSON.stringify(marker)}, 'x')
  process.exit(2)
}
const result = spawnSync(${JSON.stringify(realGit)}, args)
if (result.stdout) process.stdout.write(result.stdout)
if (result.stderr) process.stderr.write(result.stderr)
process.exit(result.status === null ? 1 : result.status)
`,
      { mode: 0o700 },
    )
    process.env.PATH = `${tooling}${path.delimiter}${originalPath ?? ''}`

    const noteCoverageTouch = (...values) => {
      for (const value of values) {
        if (String(value).includes('review-coverage.json')) {
          coverageTouches += 1
        }
      }
    }
    fs.lstatSync = function trackCoverageLstat(file, ...rest) {
      noteCoverageTouch(file)
      return originalLstat.call(fs, file, ...rest)
    }
    fs.openSync = function trackCoverageOpen(file, flags, ...rest) {
      noteCoverageTouch(file)
      return originalOpen.call(fs, file, flags, ...rest)
    }
    fs.renameSync = function trackCoverageRename(source, target) {
      noteCoverageTouch(source, target)
      return originalRename.call(fs, source, target)
    }

    updated = updateAuditCoverage(root, { allowIncomplete: true })
    checked = checkAuditCoverage(root, { allowIncomplete: true })
  } finally {
    fs.lstatSync = originalLstat
    fs.openSync = originalOpen
    fs.renameSync = originalRename
    if (originalPath === undefined) delete process.env.PATH
    else process.env.PATH = originalPath
  }

  try {
    assert.equal(updated.ok, false)
    assert.equal(updated.current, false)
    assert.equal(updated.wrote, false)
    assert.equal(updated.report.formatVersion, 1)
    assert.equal(updated.report.format, 'atlas-review-coverage-v1')
    assert.equal(updated.report.verdict, 'invalid')
    assert.deepEqual(updated.report.entries, [])
    assert.deepEqual(JSON.parse(updated.bytes), updated.report)
    assert.ok(updated.diagnostics.some((item) =>
      item.code === 'invalid-object-format'))

    assert.equal(checked.ok, false)
    assert.equal(checked.current, false)
    assert.equal(checked.wrote, false)
    assert.equal(checked.report.verdict, 'invalid')
    assert.deepEqual(checked.report.entries, [])
    assert.ok(checked.diagnostics.some((item) =>
      item.code === 'invalid-object-format'))

    assert.equal(fs.existsSync(marker), true)
    assert.equal(fs.readFileSync(marker, 'utf8'), 'xx')
    assert.equal(coverageTouches, 0)
    assert.equal(
      fs.existsSync(path.join(root, '.atlas/review-coverage.json')),
      false,
    )
  } finally {
    cleanup(root)
    cleanup(tooling)
  }
})

test('update and check acquire the shared audit lock and lifecycle failures stay runtime-only', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const { withAuditLock } = await import('../dist/audit-core.js')
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    writeV2(root)

    assert.throws(
      () => withAuditLock(root, () => updateAuditCoverage(root)),
      /lock.*held|already held/i,
    )

    write(root, '.atlas/audit-decisions/broken.json', '{"broken":')
    const result = updateAuditCoverage(root)
    assert.equal(result.report.verdict, 'complete')
    assert.equal(result.ok, false)
    assert.ok(result.runtimeAssurance.lifecycle.diagnostics.length > 0)
    assert.doesNotMatch(result.bytes, /lifecycle|rulesets|semantic/)
  } finally {
    cleanup(root)
  }
})

test('coverage update never mutates a replacement root swapped in after lock acquisition', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const root = makeRepo()
  const replacement = makeRepo()
  const parked = `${root}-parked`
  const originalLstat = fs.lstatSync
  let swapped = false
  try {
    for (const [target, value] of [
      [root, 'original'],
      [replacement, 'replacement'],
    ]) {
      write(target, 'src/a.ts', `export const source = '${value}'\n`)
      commitAll(target, `${value} source`)
      writePolicy(target, reviewPolicy())
      writeV2(target)
    }

    fs.lstatSync = function swapOnFirstLockedNestedRootOpen(
      file,
      ...rest
    ) {
      if (
        !swapped &&
        path.resolve(String(file)) === root &&
        fs.existsSync(
          path.join(root, '.git/repo-atlas/audit-state.lock'),
        ) &&
        /safeRoot/u.test(new Error().stack ?? '')
      ) {
        fs.renameSync(root, parked)
        fs.renameSync(replacement, root)
        swapped = true
      }
      return originalLstat.call(fs, file, ...rest)
    }

    let failure
    try {
      updateAuditCoverage(root, { allowIncomplete: true })
    } catch (error) {
      failure = error
    }
    assert.equal(swapped, true)
    assert.ok(failure, 'root replacement must fail the locked update')
    assert.equal(
      fs.existsSync(path.join(root, '.atlas/review-coverage.json')),
      false,
      'the replacement root must remain untouched',
    )
  } finally {
    fs.lstatSync = originalLstat
    if (fs.existsSync(parked)) {
      if (fs.existsSync(root) && !fs.existsSync(replacement)) {
        fs.renameSync(root, replacement)
      }
      if (!fs.existsSync(root)) fs.renameSync(parked, root)
    }
    cleanup(root)
    cleanup(parked)
    cleanup(replacement)
  }
})

test('coverage reader cannot report mixed-tree current after a post-report root swap', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const { loadReviewCoverage } = await coverageReaderApi()
  const { loadAuditPortfolios } = await auditsApi()
  const root = makeRepo()
  const replacement = makeRepo()
  const parked = `${root}-parked`
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  let coverageFd = null
  let swapped = false
  try {
    write(root, 'src/a.ts', "export const source = 'shared'\n")
    commitAll(root, 'shared original source')
    writePolicy(root, reviewPolicy())
    writeV2(root)
    const originalCoverage = updateAuditCoverage(
      root,
      { allowIncomplete: true },
    )
    assert.equal(originalCoverage.current, true)

    write(
      replacement,
      'src/a.ts',
      "export const source = 'shared'\n",
    )
    commitAll(replacement, 'shared replacement source')
    writePolicy(replacement, reviewPolicy())
    writeV2(replacement)
    const originalOnly = loadReviewCoverage(
      root,
      loadAuditPortfolios(root),
    )
    assert.equal(originalOnly.state, 'current')
    const portfolios = loadAuditPortfolios(root)

    fs.openSync = function trackCoverageOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        if (
          fs.realpathSync(`/proc/self/fd/${fd}`) ===
            path.join(root, '.atlas/review-coverage.json')
        ) {
          coverageFd = fd
        }
      } catch {
        // Only the retained coverage file descriptor is relevant.
      }
      return fd
    }
    fs.closeSync = function swapAfterCoverageRead(fd) {
      const result = originalClose.call(fs, fd)
      if (!swapped && fd === coverageFd) {
        fs.renameSync(root, parked)
        fs.renameSync(replacement, root)
        swapped = true
      }
      return result
    }

    const mixed = loadReviewCoverage(root, portfolios)
    assert.equal(swapped, true)
    assert.notEqual(
      mixed.state,
      'current',
      'one reader result must never combine report bytes and repository facts from different root inodes',
    )
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    if (fs.existsSync(parked)) {
      if (fs.existsSync(root) && !fs.existsSync(replacement)) {
        fs.renameSync(root, replacement)
      }
      if (!fs.existsSync(root)) fs.renameSync(parked, root)
    }
    cleanup(root)
    cleanup(parked)
    cleanup(replacement)
  }
})

test('coverage reader rejects a mixed .atlas subtree swapped after the report read', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const { loadReviewCoverage } = await coverageReaderApi()
  const { loadAuditPortfolios } = await auditsApi()
  const root = makeRepo()
  const replacement = makeRepo()
  const originalAtlas = path.join(root, '.atlas')
  const replacementAtlas = path.join(replacement, '.atlas')
  const parkedAtlas = `${root}-atlas-parked`
  const coveragePath = path.join(originalAtlas, 'review-coverage.json')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const atlasFds = new Set()
  let coverageFd = null
  let swapped = false
  try {
    write(root, 'src/a.ts', 'export const source = true\n')
    commitAll(root, 'source fixture')
    const policy = reviewPolicy()
    policy.rules.push({
      id: 'generated-proof',
      include: ['.atlas/review-coverage.json'],
      except: [],
      rationale: 'Canonical generated coverage proof.',
      excluded: {
        category: 'generated-proof',
        reason: 'Canonical generated coverage proof.',
        owner: 'repo-atlas',
      },
    })
    writePolicy(root, policy)

    const first = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(first.current, true)
    assert.equal(first.report.verdict, 'incomplete')
    execFileSync(
      'git',
      ['add', '--', '.atlas/review-coverage.json'],
      { cwd: root },
    )
    execFileSync('git', ['commit', '-qm', 'track coverage proof'], {
      cwd: root,
    })
    const generated = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(generated.current, true)
    assert.equal(generated.report.verdict, 'incomplete')
    assert.ok(generated.report.entries.some((entry) =>
      entry.path === '.atlas/review-coverage.json' &&
      entry.classification.kind === 'excluded'))

    fs.rmSync(replacementAtlas, { recursive: true, force: true })
    fs.cpSync(originalAtlas, replacementAtlas, { recursive: true })
    write(replacement, '.atlas/review-coverage.json', '{"malformed":')
    const portfolios = loadAuditPortfolios(root)

    fs.openSync = function trackAtlasDescriptors(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        const real = fs.realpathSync(`/proc/self/fd/${fd}`)
        if (real === originalAtlas) atlasFds.add(fd)
        if (real === coveragePath) coverageFd = fd
      } catch {
        // Only descriptors in the original .atlas subtree matter.
      }
      return fd
    }
    fs.closeSync = function swapAtlasAfterCoverageClose(fd) {
      const result = originalClose.call(fs, fd)
      if (!swapped && fd === coverageFd) {
        fs.renameSync(originalAtlas, parkedAtlas)
        fs.renameSync(replacementAtlas, originalAtlas)
        swapped = true
      }
      return result
    }

    const mixed = loadReviewCoverage(root, portfolios)
    assert.equal(swapped, true)
    assert.equal(
      mixed.state,
      'invalid',
      'an old report must not certify facts read from a replacement .atlas subtree',
    )
    assert.ok(mixed.errors.some((item) =>
      /atlas|identity|changed|unsafe/i.test(`${item.code} ${item.message}`)))
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    for (const fd of atlasFds) {
      assert.throws(
        () => fs.fstatSync(fd),
        (error) => error?.code === 'EBADF',
        'retained .atlas descriptor leaked',
      )
    }
    if (fs.existsSync(parkedAtlas)) {
      if (fs.existsSync(originalAtlas) && !fs.existsSync(replacementAtlas)) {
        fs.renameSync(originalAtlas, replacementAtlas)
      }
      if (!fs.existsSync(originalAtlas)) {
        fs.renameSync(parkedAtlas, originalAtlas)
      }
    }
    cleanup(root)
    cleanup(parkedAtlas)
    cleanup(replacement)
  }
})

test('a valid implicit open finding blocks overall success without changing exact coverage bytes', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const root = makeRepo()
  try {
    write(
      root,
      '.atlas/config.json',
      '{"formatVersion":1,"exclude":[],"repositoryId":"repo_fixture"}\n',
    )
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    const { findingId } = await publishOpenV3(root)

    const result = updateAuditCoverage(root, { allowIncomplete: true })
    assert.equal(result.report.verdict, 'complete')
    assert.equal(result.ok, false)
    assert.deepEqual(result.runtimeAssurance.lifecycle.diagnostics, [])
    const lifecycle = result.runtimeAssurance.lifecycle.findings.find(
      (finding) => finding.findingId === findingId,
    )
    assert.equal(lifecycle.disposition, 'open')
    assert.equal(lifecycle.blocking, true)
    assert.equal(lifecycle.lifecycle, 'new')
    assert.doesNotMatch(result.bytes, /lifecycle|blocking|disposition/)
  } finally {
    cleanup(root)
  }
})

test('hostile coverage reader ignores ambient Git directory and index injection', async () => {
  const { updateAuditCoverage } = await generatorApi()
  const { loadAuditPortfolios } = await auditsApi()
  const { loadReviewCoverage } = await import('../dist/review-coverage.js')
  const root = makeRepo()
  const priorGitDir = process.env.GIT_DIR
  const priorIndex = process.env.GIT_INDEX_FILE
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    writeV2(root)
    const generated = updateAuditCoverage(root)
    assert.equal(generated.ok, true)

    process.env.GIT_DIR = path.join(root, 'hostile-git-dir')
    process.env.GIT_INDEX_FILE = path.join(root, 'hostile-index')
    const loaded = loadReviewCoverage(root, loadAuditPortfolios(root))
    assert.equal(loaded.state, 'current')
    assert.deepEqual(loaded.errors, [])
  } finally {
    if (priorGitDir === undefined) delete process.env.GIT_DIR
    else process.env.GIT_DIR = priorGitDir
    if (priorIndex === undefined) delete process.env.GIT_INDEX_FILE
    else process.env.GIT_INDEX_FILE = priorIndex
    cleanup(root)
  }
})

test('tracked inventory cannot mix index bytes with a transient replacement root', async () => {
  const { readAuditTrackedInventory } = await policyApi()
  const root = makeRepo()
  const replacement = makeRepo()
  const tooling = makeRepo()
  const parked = `${root}-parked`
  const originalPath = process.env.PATH
  try {
    write(root, 'src/a.ts', 'export const trusted = true\n')
    commitAll(root, 'trusted inventory')
    write(replacement, 'src/a.ts', 'export const hostile = true\n')
    commitAll(replacement, 'replacement inventory')
    const trustedBlob = gitBlob(root, 'src/a.ts')
    const hostileBlob = gitBlob(replacement, 'src/a.ts')
    assert.notEqual(trustedBlob, hostileBlob)

    const realGit = execFileSync('which', ['git'], {
      encoding: 'utf8',
    }).trim()
    const wrapper = path.join(tooling, 'git')
    fs.writeFileSync(
      wrapper,
      `#!/usr/bin/env node
const fs = require('node:fs')
const { spawnSync } = require('node:child_process')
const args = process.argv.slice(2)
const result = spawnSync(${JSON.stringify(realGit)}, args)
if (
  result.status === 0 &&
  args.includes('ls-files') &&
  fs.existsSync(${JSON.stringify(root)}) &&
  fs.existsSync(${JSON.stringify(replacement)}) &&
  !fs.existsSync(${JSON.stringify(parked)})
) {
  fs.renameSync(${JSON.stringify(root)}, ${JSON.stringify(parked)})
  fs.renameSync(${JSON.stringify(replacement)}, ${JSON.stringify(root)})
}
if (result.stdout) process.stdout.write(result.stdout)
if (result.stderr) process.stderr.write(result.stderr)
process.exit(result.status === null ? 1 : result.status)
`,
      { mode: 0o700 },
    )
    process.env.PATH = `${tooling}${path.delimiter}${originalPath ?? ''}`

    const inventory = readAuditTrackedInventory(root)
    assert.equal(
      inventory.files.some((file) =>
        file.path === 'src/a.ts' &&
        file.indexBlob === trustedBlob &&
        file.currentBlob === hostileBlob),
      false,
      'one inventory must never combine the original index with replacement bytes',
    )
    assert.ok(inventory.diagnostics.some((item) =>
      /root|identity|capabil|changed|inventory/i.test(
        `${item.code} ${item.message}`,
      ),
    ))
  } finally {
    if (originalPath === undefined) delete process.env.PATH
    else process.env.PATH = originalPath
    if (fs.existsSync(parked)) {
      if (fs.existsSync(root) && !fs.existsSync(replacement)) {
        fs.renameSync(root, replacement)
      }
      if (!fs.existsSync(root)) fs.renameSync(parked, root)
    }
    cleanup(root)
    cleanup(parked)
    cleanup(replacement)
    cleanup(tooling)
  }
})

test('tracked inventory closes both retained Git capabilities when cleanup fails', async () => {
  const { readAuditTrackedInventory } = await policyApi()
  const root = makeRepo()
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const trackedFds = new Map()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    fs.openSync = function trackingCapabilityOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      let real = ''
      try {
        real = fs.realpathSync(`/proc/self/fd/${fd}`)
      } catch {
        // Only retained directory capabilities matter to this assertion.
      }
      if (real === root || real === path.join(root, '.git')) {
        trackedFds.set(fd, real)
      }
      return fd
    }
    fs.closeSync = function closeThenFail(fd) {
      const tracked = trackedFds.has(fd)
      const result = originalClose.call(fs, fd)
      if (tracked) {
        throw new Error(
          `injected ${trackedFds.get(fd) === root ? 'root' : 'git-admin'} cleanup failure`,
        )
      }
      return result
    }

    const inventory = readAuditTrackedInventory(root)
    assert.equal(trackedFds.size, 2)
    assert.ok(inventory.diagnostics.some((item) =>
      /cleanup|descriptor/i.test(`${item.code} ${item.message}`),
    ))
    for (const fd of trackedFds.keys()) {
      assert.throws(
        () => fs.fstatSync(fd),
        (error) => error?.code === 'EBADF',
      )
    }
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    for (const fd of trackedFds.keys()) {
      try {
        originalClose.call(fs, fd)
      } catch {
        // Assertions require each retained descriptor to have been closed.
      }
    }
    cleanup(root)
  }
})

test('public report builder rejects every hostile exact-evidence shape without throwing', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
    readAuditTrackedInventory,
  } = await policyApi()
  const { buildAuditCoverageReport } = await generatorApi()
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writePolicy(root, reviewPolicy())
    const loaded = loadAuditReviewPolicy(root)
    const inventory = readAuditTrackedInventory(root)
    const classification = classifyAuditInventory(
      inventory.files,
      loaded.policy,
    )
    const evidence = {
      units: [{
        version: 2,
        domain: 'security',
        slug: 'security-source',
        ruleset: 'atlas-security-v3',
        rulesetDigest: null,
        semanticStatus: 'unknown',
        stale: false,
        receipts: [{
          path: 'src/a.ts',
          blob: gitBlob(root, 'src/a.ts'),
          reviewed: true,
          fullRead: true,
        }],
        invalidClaimedPaths: [],
        sourcePath: '.atlas/audits/security-source.json',
      }],
      invalidLedgers: [],
      invalidClaimedPaths: [],
    }
    const base = {
      policy: loaded.policy,
      policyHash: loaded.policyHash,
      inventory,
      classification,
      exactEvidence: evidence,
    }
    assert.equal(buildAuditCoverageReport(base).verdict, 'complete')

    const cases = [
      ['unknown version', (value) => {
        value.exactEvidence.units[0].version = 99
      }],
      ['truthy reviewed', (value) => {
        value.exactEvidence.units[0].receipts[0].reviewed = 'true'
      }],
      ['truthy fullRead', (value) => {
        value.exactEvidence.units[0].receipts[0].fullRead = 1
      }],
      ['missing receipts', (value) => {
        delete value.exactEvidence.units[0].receipts
      }],
      ['non-array receipts', (value) => {
        value.exactEvidence.units[0].receipts = {}
      }],
      ['unknown unit field', (value) => {
        value.exactEvidence.units[0].extra = true
      }],
      ['ruleset digest without ruleset', (value) => {
        value.exactEvidence.units[0].ruleset = null
        value.exactEvidence.units[0].rulesetDigest =
          `sha256:${'1'.repeat(64)}`
      }],
      ['legacy ruleset digest', (value) => {
        value.exactEvidence.units[0].rulesetDigest =
          `sha256:${'1'.repeat(64)}`
      }],
      ['invalid stale state', (value) => {
        value.exactEvidence.units[0].stale = 'false'
      }],
      ['invalid semantic state', (value) => {
        value.exactEvidence.units[0].semanticStatus = 'complete'
      }],
      ['invalid source path', (value) => {
        value.exactEvidence.units[0].sourcePath = '../ledger.json'
      }],
      ['wrong V2 blob width', (value) => {
        value.exactEvidence.units[0].receipts[0].blob = 'a'.repeat(64)
      }],
      ['prefixed V3 blob', (value) => {
        value.exactEvidence.units[0].version = 3
        value.exactEvidence.units[0].rulesetDigest =
          `sha256:${'1'.repeat(64)}`
        value.exactEvidence.units[0].receipts[0].blob =
          `git-sha1:${'a'.repeat(40)}`
      }],
      ['V1 exact claim', (value) => {
        value.exactEvidence.units[0].version = 1
        value.exactEvidence.units[0].receipts[0].fullRead = false
      }],
      ['duplicate unit identity', (value) => {
        value.exactEvidence.units.push(
          structuredClone(value.exactEvidence.units[0]),
        )
      }],
      ['duplicate receipt path', (value) => {
        value.exactEvidence.units[0].receipts.push(
          structuredClone(value.exactEvidence.units[0].receipts[0]),
        )
      }],
      ['malformed ledger diagnostic', (value) => {
        value.exactEvidence.invalidLedgers = [{ code: 'broken' }]
      }],
      ['malformed invalid claimed path', (value) => {
        value.exactEvidence.invalidClaimedPaths = [{
          path: '../outside.ts',
          domain: 'design',
          slug: 'bad_slug',
          sourcePath: '../ledger.json',
        }]
      }],
      ['missing invalid claimed paths', (value) => {
        delete value.exactEvidence.invalidClaimedPaths
      }],
      ['non-array invalid claimed paths', (value) => {
        value.exactEvidence.invalidClaimedPaths = {}
      }],
      ['oversized text', (value) => {
        value.exactEvidence.units[0].sourcePath =
          'x'.repeat(256 * 1024 + 1)
      }],
      ['nested prototype', (value) => {
        Object.setPrototypeOf(value.exactEvidence.units[0], { hostile: true })
      }],
      ['nested symbol', (value) => {
        value.exactEvidence.units[0][Symbol('hostile')] = true
      }],
      ['nested getter', (value) => {
        Object.defineProperty(value.exactEvidence.units[0], 'receipts', {
          enumerable: true,
          get() {
            throw new Error('must not execute')
          },
        })
      }],
      ['excessive depth', (value) => {
        let current = value.exactEvidence
        for (let index = 0; index < 140; index += 1) {
          current.extra = {}
          current = current.extra
        }
      }],
    ]

    for (const [label, forge] of cases) {
      const hostile = structuredClone(base)
      forge(hostile)
      let report
      assert.doesNotThrow(() => {
        report = buildAuditCoverageReport(hostile)
      }, label)
      assert.equal(report.verdict, 'invalid', label)
      assert.ok(report.reportErrors.length > 0, label)
      assert.equal(
        report.entries.some((entry) =>
          entry.evidence.security?.status === 'fresh'),
        false,
        label,
      )
      let repeated
      assert.doesNotThrow(() => {
        repeated = buildAuditCoverageReport(hostile)
      }, `${label} repeat`)
      assert.deepEqual(repeated, report, `${label} must be deterministic`)
    }
  } finally {
    cleanup(root)
  }
})

test('invalid policy fallback never serializes unvalidated inventory rows', async () => {
  const { loadAuditReviewPolicy } = await policyApi()
  const { buildAuditCoverageReport } = await generatorApi()
  const root = makeRepo()
  try {
    writePolicy(root, reviewPolicy())
    const loaded = loadAuditReviewPolicy(root)
    const policy = structuredClone(loaded.policy)
    policy.format = 'forged-policy'
    let report
    assert.doesNotThrow(() => {
      report = buildAuditCoverageReport({
        policy,
        policyHash: loaded.policyHash,
        inventory: {
          objectFormat: 'sha1',
          files: [{ forged: true }],
          diagnostics: [],
        },
        classification: { files: [], diagnostics: [] },
        exactEvidence: emptyExactEvidence(),
      })
    })
    assert.equal(report.verdict, 'invalid')
    assert.deepEqual(report.entries, [])
    assert.equal(report.summary.tracked, 0)

    const validFile = trackedFile('src/a.ts')
    const validShape = buildAuditCoverageReport({
      policy,
      policyHash: loaded.policyHash,
      inventory: {
        objectFormat: 'sha1',
        files: [validFile],
        diagnostics: [],
      },
      classification: { files: [], diagnostics: [] },
      exactEvidence: emptyExactEvidence(),
    })
    assert.equal(validShape.verdict, 'invalid')
    assert.deepEqual(validShape.entries, [{
      path: 'src/a.ts',
      blob: validFile.currentBlob,
      ruleIds: [],
      classification: { kind: 'conflict' },
      evidence: {},
    }])
  } finally {
    cleanup(root)
  }
})

test('canonical invalid reports preserve zero rule matches and pass full reader structure validation', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
    normalizeAuditReviewPolicy,
    readAuditTrackedInventory,
  } = await policyApi()
  const { buildAuditCoverageReport } = await generatorApi()
  const { loadAuditPortfolios } = await auditsApi()
  const { loadReviewCoverage } = await coverageReaderApi()
  const roots = []
  const readReport = (root, report) => {
    write(
      root,
      '.atlas/review-coverage.json',
      `${JSON.stringify(report)}\n`,
    )
    return loadReviewCoverage(root, loadAuditPortfolios(root))
  }
  try {
    const unclassifiedRoot = makeRepo()
    roots.push(unclassifiedRoot)
    write(unclassifiedRoot, 'misc/unclassified.txt', 'unclassified\n')
    commitAll(unclassifiedRoot)
    writePolicy(unclassifiedRoot, reviewPolicy())
    const loaded = loadAuditReviewPolicy(unclassifiedRoot)
    const inventory = readAuditTrackedInventory(unclassifiedRoot)
    const classification = classifyAuditInventory(
      inventory.files,
      loaded.policy,
    )
    const unclassified = buildAuditCoverageReport({
      policy: loaded.policy,
      policyHash: loaded.policyHash,
      inventory,
      classification,
      exactEvidence: emptyExactEvidence(),
    })
    const unclassifiedEntry = unclassified.entries.find((entry) =>
      entry.path === 'misc/unclassified.txt')
    assert.equal(unclassified.verdict, 'invalid')
    assert.deepEqual(unclassifiedEntry.ruleIds, [])
    assert.equal(unclassifiedEntry.classification.kind, 'unclassified')
    const unclassifiedRead = readReport(unclassifiedRoot, unclassified)
    assert.equal(unclassifiedRead.state, 'invalid')
    assert.ok(unclassifiedRead.errors.some((item) =>
      item.code === 'invalid-classification'), JSON.stringify(
      unclassifiedRead.errors,
    ))
    assert.ok(!unclassifiedRead.errors.some((item) =>
      item.code === 'malformed-report'))

    const resourceRoot = makeRepo()
    roots.push(resourceRoot)
    const resourceFiles = Array.from(
      { length: 1_001 },
      (_, index) => trackedFile(`src/resource-${index}.ts`),
    )
    const resourcePolicyInput = reviewPolicy({
      rules: [{
        id: 'large-source-rule',
        include: [
          '**',
          ...Array.from(
            { length: 4_999 },
            (_, index) => `unused/resource-${index}/**`,
          ),
        ],
        except: [],
        rationale: 'Deliberately exceeds the classification match budget.',
        domains: ['security'],
      }],
      units: [{
        domain: 'security',
        slug: 'security-source',
        title: 'Source',
        include: ['**'],
        except: [],
        context: [],
      }],
    })
    const resourcePolicy = normalizeAuditReviewPolicy(resourcePolicyInput)
    const resourceClassification = classifyAuditInventory(
      resourceFiles,
      resourcePolicy.policy,
    )
    const resource = buildAuditCoverageReport({
      policy: resourcePolicy.policy,
      policyHash: resourcePolicy.policyHash,
      inventory: {
        objectFormat: 'sha1',
        files: resourceFiles,
        diagnostics: [],
      },
      classification: resourceClassification,
      exactEvidence: emptyExactEvidence(),
    })
    assert.equal(resource.verdict, 'invalid')
    assert.ok(resource.reportErrors.some((item) =>
      item.code === 'classification-resource-limit'))
    assert.ok(resource.entries.every((entry) =>
      entry.ruleIds.length === 0 &&
      entry.classification.kind === 'conflict'))
    const resourceRead = readReport(resourceRoot, resource)
    assert.equal(resourceRead.state, 'invalid')
    assert.ok(resourceRead.errors.some((item) =>
      item.code === 'classification-resource-limit'))
    assert.ok(!resourceRead.errors.some((item) =>
      item.code === 'malformed-report'))

    const selfRoot = makeRepo()
    roots.push(selfRoot)
    const selfPolicy = normalizeAuditReviewPolicy(reviewPolicy({
      rules: [],
      units: [],
    }))
    const selfFiles = [trackedFile('.atlas/review-coverage.json')]
    const selfClassification = classifyAuditInventory(
      selfFiles,
      selfPolicy.policy,
    )
    const invalidSelf = buildAuditCoverageReport({
      policy: selfPolicy.policy,
      policyHash: selfPolicy.policyHash,
      inventory: {
        objectFormat: 'sha1',
        files: selfFiles,
        diagnostics: [],
      },
      classification: selfClassification,
      exactEvidence: emptyExactEvidence(),
    })
    assert.equal(invalidSelf.verdict, 'invalid')
    assert.deepEqual(invalidSelf.entries[0].ruleIds, [])
    assert.equal(invalidSelf.entries[0].classification.kind, 'conflict')
    const selfRead = readReport(selfRoot, invalidSelf)
    assert.equal(selfRead.state, 'invalid')
    assert.ok(selfRead.errors.some((item) =>
      item.code === 'invalid-generated-proof'))
    assert.ok(!selfRead.errors.some((item) =>
      item.code === 'malformed-report'))

    const malformed = structuredClone(unclassified)
    const malformedEntry = malformed.entries.find((entry) =>
      entry.path === 'misc/unclassified.txt')
    malformedEntry.classification = {
      kind: 'excluded',
      ruleId: 'forged',
      category: 'forged',
      reason: 'forged',
    }
    const malformedRead = readReport(unclassifiedRoot, malformed)
    assert.equal(malformedRead.state, 'invalid')
    assert.ok(malformedRead.errors.some((item) =>
      item.code === 'malformed-report' &&
      /ruleIds/.test(item.message)))
  } finally {
    for (const root of roots) cleanup(root)
  }
})

test('generator preflights historical receipt matching and emits no partial fresh claims', async () => {
  const {
    classifyAuditInventory,
    normalizeAuditReviewPolicy,
  } = await policyApi()
  const historicalIncludes = [
    'legacy/**',
    ...Array.from(
      { length: 4_999 },
      (_, index) => `unused/historical-${index}/**`,
    ),
  ]
  const normalized = normalizeAuditReviewPolicy(reviewPolicy({
    historicalUnitAssignments: [{
      id: 'retired-security',
      sourceKind: 'relayos-security-scan/v1',
      domain: 'security',
      unit: 'security-source',
      include: historicalIncludes,
    }],
  }))
  const files = [trackedFile('src/a.ts')]
  const classification = classifyAuditInventory(files, normalized.policy)
  assert.equal(classification.files[0].classification.kind, 'review')
  const receipts = [
    {
      path: 'src/a.ts',
      blob: files[0].currentBlob,
      reviewed: true,
      fullRead: true,
    },
    ...Array.from({ length: 1_000 }, (_, index) => ({
      path: `legacy/receipt-${index}.ts`,
      blob: 'b'.repeat(40),
      reviewed: true,
      fullRead: true,
    })),
  ]
  const input = {
    policy: normalized.policy,
    policyHash: normalized.policyHash,
    inventory: {
      objectFormat: 'sha1',
      files,
      diagnostics: [],
    },
    classification,
    exactEvidence: {
      units: [{
        version: 2,
        domain: 'security',
        slug: 'security-source',
        ruleset: 'atlas-security-v3',
        rulesetDigest: null,
        semanticStatus: 'covered',
        stale: false,
        receipts,
        invalidClaimedPaths: [],
        sourcePath: '.atlas/audits/security-source.json',
      }],
      invalidLedgers: [],
      invalidClaimedPaths: [],
    },
  }
  const moduleUrl = new URL(
    '../dist/audit-coverage-generator.js',
    import.meta.url,
  ).href
  const child = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `
        import fs from 'node:fs'
        const { buildAuditCoverageReport } = await import(${JSON.stringify(moduleUrl)})
        const input = JSON.parse(fs.readFileSync(0, 'utf8'))
        const report = buildAuditCoverageReport(input)
        process.stdout.write(JSON.stringify({
          verdict: report.verdict,
          reportErrors: report.reportErrors,
          entries: report.entries,
        }))
      `,
    ],
    {
      input: JSON.stringify(input),
      encoding: 'utf8',
      timeout: 5_000,
      maxBuffer: 16 * 1024 * 1024,
    },
  )
  assert.equal(
    child.error,
    undefined,
    child.error instanceof Error ? child.error.message : String(child.error),
  )
  assert.equal(child.status, 0, child.stderr)
  const report = JSON.parse(child.stdout)
  assert.equal(report.verdict, 'invalid')
  assert.deepEqual(
    report.reportErrors.filter((item) =>
      item.code === 'historical-receipt-resource-limit'),
    [{
      code: 'historical-receipt-resource-limit',
      message:
        'historical receipt overlap requires 5005000 worst-case match ' +
        'operations; limit is 5000000',
    }],
  )
  assert.equal(
    report.entries.some((entry) =>
      entry.evidence.security?.status === 'fresh'),
    false,
  )
  assert.deepEqual(report.entries[0].evidence.security, {
    status: 'invalid',
    ledgers: [],
  })
})

test('generator indexes exact receipts once instead of scanning a unit per classified file', async () => {
  const {
    classifyAuditInventory,
    normalizeAuditReviewPolicy,
  } = await policyApi()
  const { buildAuditCoverageReport } = await generatorApi()
  const normalized = normalizeAuditReviewPolicy(reviewPolicy())
  const files = Array.from(
    { length: 64 },
    (_, index) => trackedFile(`src/file-${index}.ts`),
  )
  const classification = classifyAuditInventory(files, normalized.policy)
  const exactEvidence = {
    units: [{
      version: 2,
      domain: 'security',
      slug: 'security-source',
      ruleset: 'atlas-security-v3',
      rulesetDigest: null,
      semanticStatus: 'covered',
      stale: false,
      receipts: files.map((file) => ({
        path: file.path,
        blob: file.currentBlob,
        reviewed: true,
        fullRead: true,
      })),
      invalidClaimedPaths: [],
      sourcePath: '.atlas/audits/security-source.json',
    }],
    invalidLedgers: [],
    invalidClaimedPaths: [],
  }
  const originalFind = Array.prototype.find
  let receiptFindCalls = 0
  Array.prototype.find = function (...args) {
    const first = this[0]
    if (
      first !== null &&
      typeof first === 'object' &&
      Object.hasOwn(first, 'path') &&
      Object.hasOwn(first, 'blob') &&
      Object.hasOwn(first, 'reviewed') &&
      Object.hasOwn(first, 'fullRead')
    ) {
      receiptFindCalls += 1
    }
    return Reflect.apply(originalFind, this, args)
  }
  let report
  try {
    report = buildAuditCoverageReport({
      policy: normalized.policy,
      policyHash: normalized.policyHash,
      inventory: {
        objectFormat: 'sha1',
        files,
        diagnostics: [],
      },
      classification,
      exactEvidence,
    })
  } finally {
    Array.prototype.find = originalFind
  }
  assert.equal(receiptFindCalls, 0)
  assert.equal(report.verdict, 'complete')
  assert.equal(
    report.entries.filter((entry) =>
      entry.evidence.security?.status === 'fresh').length,
    files.length,
  )
})

test('generator validation never scans its classified array while historical matchers still short-circuit', async () => {
  const {
    classifyAuditInventory,
    normalizeAuditReviewPolicy,
  } = await policyApi()
  const { buildAuditCoverageReport } = await generatorApi()
  const normalized = normalizeAuditReviewPolicy(reviewPolicy({
    historicalUnitAssignments: [{
      id: 'retired-security',
      sourceKind: 'relayos-security-scan/v1',
      domain: 'security',
      unit: 'security-source',
      include: ['unused/**', 'legacy/**'],
    }],
  }))
  const files = Array.from(
    { length: 128 },
    (_, index) => trackedFile(`src/file-${index}.ts`),
  )
  const classification = classifyAuditInventory(files, normalized.policy)
  const exactEvidence = {
    units: [{
      version: 2,
      domain: 'security',
      slug: 'security-source',
      ruleset: 'atlas-security-v3',
      rulesetDigest: null,
      semanticStatus: 'covered',
      stale: false,
      receipts: [{
        path: 'legacy/old.ts',
        blob: 'b'.repeat(40),
        reviewed: true,
        fullRead: true,
      }],
      invalidClaimedPaths: [],
      sourcePath: '.atlas/audits/security-source.json',
    }],
    invalidLedgers: [],
    invalidClaimedPaths: [],
  }
  const originalSome = Array.prototype.some
  let classifiedArraySomeCalls = 0
  let classifiedArrayVisits = 0
  Array.prototype.some = function instrumentClassifiedArraySome(
    callback,
    thisArg,
  ) {
    const first = this[0]
    if (
      Array.isArray(this) &&
      this.length === files.length &&
      first !== null &&
      typeof first === 'object' &&
      Object.hasOwn(first, 'path') &&
      Object.hasOwn(first, 'ruleIds') &&
      Object.hasOwn(first, 'classification')
    ) {
      classifiedArraySomeCalls += 1
      return Reflect.apply(originalSome, this, [
        (...args) => {
          classifiedArrayVisits += 1
          return Reflect.apply(callback, thisArg, args)
        },
      ])
    }
    return Reflect.apply(originalSome, this, [callback, thisArg])
  }
  let report
  try {
    report = buildAuditCoverageReport({
      policy: normalized.policy,
      policyHash: normalized.policyHash,
      inventory: {
        objectFormat: 'sha1',
        files,
        diagnostics: [],
      },
      classification,
      exactEvidence,
    })
  } finally {
    Array.prototype.some = originalSome
  }

  assert.equal(classifiedArraySomeCalls, 0)
  assert.equal(classifiedArrayVisits, 0)
  assert.ok(report.reportErrors.some((item) =>
    item.code === 'historical-active-receipt-overlap' &&
    item.path === 'legacy/old.ts'))
})

test('coverage inventory hash preserves the normative V1 line digest for legacy-safe paths', async () => {
  const { reviewCoverageInventoryHash } = await import(
    '../dist/review-coverage-hash.js'
  )
  const tuples = [
    {
      marker: 'a'.repeat(40),
      path: 'src/a.ts',
    },
    {
      marker: 'GENERATED-PROOF',
      path: '.atlas/review-coverage.json',
    },
  ]
  const legacyBytes = tuples
    .map((tuple) => `${tuple.marker}  ${tuple.path}`)
    .sort()
    .join('\n') + '\n'
  const legacyDigest = createHash('sha256')
    .update(legacyBytes)
    .digest('hex')
  assert.equal(
    legacyDigest,
    '4038578d7f81a9da060746dd8e2cc1e6e12bcffcff9b81e4ee299f7eb3937fcc',
  )
  assert.equal(reviewCoverageInventoryHash(tuples), legacyDigest)
})

test('coverage inventory hash snapshots only dense bounded plain tuples without invoking accessors', async () => {
  const { reviewCoverageInventoryHash } = await import(
    '../dist/review-coverage-hash.js'
  )
  const valid = {
    marker: 'a'.repeat(40),
    path: 'src/a.ts',
  }
  let getterCalls = 0
  const accessor = {
    path: 'src/a.ts',
  }
  Object.defineProperty(accessor, 'marker', {
    enumerable: true,
    get() {
      getterCalls += 1
      return 'a'.repeat(40)
    },
  })
  const nullPrototype = Object.assign(Object.create(null), valid)
  const extraKey = { ...valid, extra: true }
  const symbolKey = { ...valid, [Symbol('extra')]: true }
  const arrayWithExtra = [{ ...valid }]
  Object.defineProperty(arrayWithExtra, 'extra', {
    value: true,
    enumerable: false,
  })

  for (const input of [
    new Array(1),
    [accessor],
    [nullPrototype],
    [extraKey],
    [symbolKey],
    arrayWithExtra,
    [{ marker: 'a'.repeat(40), path: `src/${'x'.repeat(300_000)}` }],
    [{ marker: 'a'.repeat(40), path: 'src/\ud800.ts' }],
  ]) {
    assert.throws(
      () => reviewCoverageInventoryHash(input),
      /inventory|tuple|dense|plain|accessor|property|path|limit|bound|unicode/i,
    )
  }
  assert.equal(getterCalls, 0)
})

test('coverage inventory hash rejects delimiter-shaped markers instead of admitting legacy collisions', async () => {
  const { reviewCoverageInventoryHash } = await import(
    '../dist/review-coverage-hash.js'
  )
  const left = [{ marker: 'a', path: ' b' }]
  const right = [{ marker: 'a ', path: 'b' }]

  assert.throws(
    () => reviewCoverageInventoryHash(left),
    /marker|SHA-1|generated/i,
  )
  assert.throws(
    () => reviewCoverageInventoryHash(right),
    /marker|SHA-1|generated/i,
  )
})

test('coverage inventory hash uses unambiguous tuples for newline paths', async () => {
  const {
    classifyAuditInventory,
    loadAuditReviewPolicy,
  } = await policyApi()
  const { buildAuditCoverageReport } = await generatorApi()
  const root = makeRepo()
  try {
    const firstBlob = '1'.repeat(40)
    const secondBlob = '2'.repeat(40)
    const joinedPath = `x\n${secondBlob}  y`
    writePolicy(root, reviewPolicy({
      rules: [{
        id: 'all-security',
        include: ['x', 'y', joinedPath],
        except: [],
        rationale: 'Synthetic collision inventory.',
        domains: ['security'],
      }],
      units: [{
        domain: 'security',
        slug: 'security-source',
        title: 'Source',
        include: ['x', 'y', joinedPath],
        except: [],
        context: [],
      }],
    }))
    const loaded = loadAuditReviewPolicy(root)
    assert.notEqual(loaded.policy, null)
    const row = (repoPath, blob) => ({
      path: repoPath,
      indexBlob: blob,
      currentBlob: blob,
      indexMode: '100644',
      currentMode: '100644',
      deleted: false,
    })
    const joined = [row(joinedPath, firstBlob)]
    const split = [row('x', firstBlob), row('y', secondBlob)]
    const oldPreimage = (files) => files.map((file) =>
      `${file.currentBlob}  ${file.path}`).sort().join('\n') + '\n'
    assert.equal(oldPreimage(joined), oldPreimage(split))

    const reportFor = (files) => buildAuditCoverageReport({
      policy: loaded.policy,
      policyHash: loaded.policyHash,
      inventory: {
        objectFormat: 'sha1',
        files,
        diagnostics: [],
      },
      classification: classifyAuditInventory(files, loaded.policy),
      exactEvidence: emptyExactEvidence(),
    })
    assert.notEqual(
      reportFor(joined).inventoryHash,
      reportFor(split).inventoryHash,
    )
  } finally {
    cleanup(root)
  }
})

test('tracked coverage gains only the reserved self proof on its second generation', async () => {
  const {
    checkAuditCoverage,
    updateAuditCoverage,
  } = await generatorApi()
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root, 'initial tracked inventory')
    writePolicy(root, reviewPolicy({
      rules: [
        ...reviewPolicy().rules,
        {
          id: 'generated-proof',
          include: ['.atlas/review-coverage.json'],
          except: [],
          rationale: 'Canonical generated coverage proof.',
          excluded: {
            category: 'generated-proof',
            reason: 'Canonical generated coverage proof.',
            owner: 'repo-atlas',
          },
        },
      ],
    }))
    writeV2(root)

    const first = updateAuditCoverage(root)
    assert.equal(first.report.verdict, 'complete')
    assert.equal(
      first.report.entries.some((entry) =>
        entry.path === '.atlas/review-coverage.json'),
      false,
    )
    execFileSync(
      'git',
      ['add', '--', '.atlas/review-coverage.json'],
      { cwd: root },
    )
    execFileSync(
      'git',
      ['commit', '-qm', 'track generated coverage'],
      { cwd: root },
    )

    const second = updateAuditCoverage(root)
    const selfEntries = second.report.entries.filter((entry) =>
      entry.path === '.atlas/review-coverage.json')
    assert.equal(second.report.verdict, 'complete')
    assert.equal(selfEntries.length, 1)
    assert.deepEqual(selfEntries[0], {
      path: '.atlas/review-coverage.json',
      ruleIds: ['generated-proof'],
      classification: {
        kind: 'excluded',
        ruleId: 'generated-proof',
        category: 'generated-proof',
        reason: 'Canonical generated coverage proof.',
        owner: 'repo-atlas',
      },
      evidence: {},
    })
    assert.equal(
      second.report.entries.filter((entry) =>
        entry.classification.kind === 'excluded' &&
        entry.classification.category === 'generated-proof').length,
      1,
    )
    assert.equal(
      fs.readFileSync(
        path.join(root, '.atlas/review-coverage.json'),
        'utf8',
      ),
      second.bytes,
    )
    const checked = checkAuditCoverage(root)
    assert.equal(checked.current, true)
    assert.equal(checked.ok, true)
    assert.equal(checked.bytes, second.bytes)
  } finally {
    cleanup(root)
  }
})

test('literal Relay retired paths expand 3/30/25 with zero unmapped', async () => {
  const {
    expandAuditHistoricalUnitAssignments,
    loadAuditReviewPolicy,
  } = await policyApi()
  const runtime = [
    'apps/cloud-daemon-host/src/cloudflare-env.d.ts',
    'apps/cloud-daemon-host/src/index.ts',
    'apps/cloud-daemon-host/src/routing.ts',
  ]
  const edge = [
    'apps/cloudflare-marketplace-worker/migrations/0001_marketplace_foundation.sql',
    'apps/cloudflare-marketplace-worker/migrations/0003_revision_signature.sql',
    'apps/cloudflare-marketplace-worker/package.json',
    'apps/cloudflare-marketplace-worker/scripts/apply-migrations.ts',
    'apps/cloudflare-marketplace-worker/src/admin-auth.ts',
    'apps/cloudflare-marketplace-worker/src/cloudflare-env.d.ts',
    'apps/cloudflare-marketplace-worker/src/index.ts',
    'apps/cloudflare-marketplace-worker/src/postgres-store.ts',
    'apps/cloudflare-marketplace-worker/src/r2-storage.ts',
    'apps/cloudflare-marketplace-worker/src/routing.ts',
    'apps/cloudflare-marketplace-worker/tsconfig.json',
    'apps/cloudflare-marketplace-worker/vitest.config.ts',
    'apps/cloudflare-marketplace-worker/wrangler.marketplace.jsonc',
    'apps/cloudflare-sandbox-worker/src/index.ts',
    'apps/cloudflare-sandbox-worker/src/routing.ts',
    'apps/daemon-edge/src/index.ts',
    'apps/daemon-edge/src/router.ts',
    'apps/daemon-edge/wrangler.daemon-edge.jsonc',
    'apps/telemetry-gateway-worker/package.json',
    'apps/telemetry-gateway-worker/src/cloudflare-env.d.ts',
    'apps/telemetry-gateway-worker/src/index.ts',
    'apps/telemetry-gateway-worker/src/router.ts',
    'apps/telemetry-gateway-worker/tsconfig.json',
    'apps/telemetry-gateway-worker/wrangler.gateway.jsonc',
    'apps/telemetry-tail-worker/package.json',
    'apps/telemetry-tail-worker/src/cloudflare-env.d.ts',
    'apps/telemetry-tail-worker/src/index.ts',
    'apps/telemetry-tail-worker/src/transform.ts',
    'apps/telemetry-tail-worker/tsconfig.json',
    'apps/telemetry-tail-worker/wrangler.tail.jsonc',
  ]
  const product = [
    'apps/web/src/api.ts',
    'apps/web/src/auth/AuthLayout.tsx',
    'apps/web/src/auth/AuthRouter.tsx',
    'apps/web/src/auth/BootstrapScreen.tsx',
    'apps/web/src/auth/CliApproveScreen.tsx',
    'apps/web/src/auth/CreateWorkspaceScreen.tsx',
    'apps/web/src/auth/LoginScreen.tsx',
    'apps/web/src/auth/MagicLinkRequestScreen.tsx',
    'apps/web/src/auth/MagicLinkSentScreen.tsx',
    'apps/web/src/auth/SignupScreen.tsx',
    'apps/web/src/auth/api.ts',
    'apps/web/src/auth/useAuthStatus.ts',
    'apps/web/src/auth/useFirstLaunchGuard.ts',
    'apps/web/src/credentialsSurface.ts',
    'apps/web/src/env.ts',
    'apps/web/src/organizationCredentialsScreen.tsx',
    'apps/web/src/organizationMachineInvites.tsx',
    'apps/web/src/routes.tsx',
    'apps/web/src/settings/BillingSetting.tsx',
    'apps/web/src/settings/CredentialsSetting.tsx',
    'apps/web/src/settings/credentialProviders.tsx',
    'apps/web/src/telemetry.ts',
    'apps/web/src/walletSurface.ts',
    'apps/web/src/workflowsMarketplaceDetailScreen.tsx',
    'apps/web/src/workflowsMarketplaceScreen.tsx',
  ]
  assert.deepEqual(
    [runtime.length, edge.length, product.length],
    [3, 30, 25],
  )
  const root = makeRepo()
  try {
    writePolicy(root, reviewPolicy({
      rules: [],
      units: [
        {
          domain: 'security',
          slug: 'security-apps-runtime',
          title: 'Runtime',
          include: ['runtime/**'],
          except: [],
          context: [],
        },
        {
          domain: 'security',
          slug: 'security-apps-edge',
          title: 'Edge',
          include: ['edge/**'],
          except: [],
          context: [],
        },
        {
          domain: 'security',
          slug: 'security-apps-product',
          title: 'Product',
          include: ['product/**'],
          except: [],
          context: [],
        },
      ],
      historicalUnitAssignments: [
        {
          id: 'relayos-retired-daemon-host',
          sourceKind: 'relayos-security-scan/v1',
          domain: 'security',
          unit: 'security-apps-runtime',
          include: ['apps/cloud-daemon-host/**'],
        },
        {
          id: 'relayos-retired-edge-apps',
          sourceKind: 'relayos-security-scan/v1',
          domain: 'security',
          unit: 'security-apps-edge',
          include: [
            'apps/cloudflare-marketplace-worker/**',
            'apps/cloudflare-sandbox-worker/**',
            'apps/daemon-edge/**',
            'apps/telemetry-gateway-worker/**',
            'apps/telemetry-tail-worker/**',
          ],
        },
        {
          id: 'relayos-retired-web',
          sourceKind: 'relayos-security-scan/v1',
          domain: 'security',
          unit: 'security-apps-product',
          include: ['apps/web/**'],
        },
      ],
    }))
    const loaded = loadAuditReviewPolicy(root)
    assert.notEqual(loaded.policy, null)
    const expanded = expandAuditHistoricalUnitAssignments({
      policy: loaded.policy,
      sourceKind: 'relayos-security-scan/v1',
      historicalPaths: [...runtime, ...edge, ...product],
      currentPaths: [],
      activeReceiptPaths: [],
    })
    assert.deepEqual(expanded.diagnostics, [])
    assert.deepEqual(expanded.unmapped, [])
    assert.match(expanded.expansionDigest, /^sha256:[0-9a-f]{64}$/)
    assert.deepEqual(
      Object.fromEntries(expanded.assignments.map((assignment) => [
        assignment.unit,
        assignment.paths.length,
      ])),
      {
        'security-apps-edge': 30,
        'security-apps-product': 25,
        'security-apps-runtime': 3,
      },
    )
    assert.equal(
      expanded.assignments.reduce(
        (count, assignment) => count + assignment.paths.length,
        0,
      ),
      58,
    )

    const blocked = expandAuditHistoricalUnitAssignments({
      policy: loaded.policy,
      sourceKind: 'relayos-security-scan/v1',
      historicalPaths: [...runtime, ...edge, ...product],
      currentPaths: [runtime[0]],
      activeReceiptPaths: [edge[0]],
    })
    assert.ok(blocked.diagnostics.some((item) =>
      item.code === 'historical-current-overlap'))
    assert.ok(blocked.diagnostics.some((item) =>
      item.code === 'historical-active-receipt-overlap'))
  } finally {
    cleanup(root)
  }
})

test('historical expansion rejects the assignment/path cross-product before matching', async () => {
  const { expandAuditHistoricalUnitAssignments } = await policyApi()
  const historicalUnitAssignments = Array.from(
    { length: 1_001 },
    (_, index) => ({
      id: `retired-${index}`,
      sourceKind: 'relayos-security-scan/v1',
      domain: 'security',
      unit: 'security-source',
      include: [`retired/${index}/**`],
    }),
  )
  const historicalPaths = Array.from(
    { length: 2_000 },
    (_, index) => `archive/historical-${index}.ts`,
  )
  const currentPaths = Array.from(
    { length: 1_500 },
    (_, index) => `current/file-${index}.ts`,
  )
  const activeReceiptPaths = Array.from(
    { length: 1_500 },
    (_, index) => `receipt/file-${index}.ts`,
  )
  const result = expandAuditHistoricalUnitAssignments({
    policy: reviewPolicy({ historicalUnitAssignments }),
    sourceKind: 'relayos-security-scan/v1',
    historicalPaths,
    currentPaths,
    activeReceiptPaths,
  })

  assert.deepEqual(result.assignments, [])
  assert.deepEqual(result.unmapped, [...historicalPaths].sort())
  assert.deepEqual(result.diagnostics, [{
    code: 'historical-resource-limit',
    message:
      'historical expansion requires 5005000 worst-case match operations; ' +
      'limit is 5000000',
  }])
  assert.match(result.expansionDigest, /^sha256:[0-9a-f]{64}$/)
})

test('historical expansion digest binds normalized assignment globs as well as extensional paths', async () => {
  const {
    expandAuditHistoricalUnitAssignments,
    normalizeAuditReviewPolicy,
  } = await policyApi()
  const expansionFor = (include) => {
    const normalized = normalizeAuditReviewPolicy(reviewPolicy({
      historicalUnitAssignments: [{
        id: 'retired-source',
        sourceKind: 'relayos-security-scan/v1',
        domain: 'security',
        unit: 'security-source',
        include,
      }],
    }))
    return expandAuditHistoricalUnitAssignments({
      policy: normalized.policy,
      sourceKind: 'relayos-security-scan/v1',
      historicalPaths: ['legacy/a.ts'],
      currentPaths: [],
      activeReceiptPaths: [],
    })
  }
  const recursive = expansionFor(['legacy/**'])
  const shallow = expansionFor(['legacy/*.ts'])

  assert.deepEqual(recursive.diagnostics, [])
  assert.deepEqual(shallow.diagnostics, [])
  assert.deepEqual(recursive.assignments, shallow.assignments)
  assert.deepEqual(recursive.unmapped, shallow.unmapped)
  assert.notEqual(recursive.expansionDigest, shallow.expansionDigest)
})
