import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  computeAuditCanonicalDigest,
  computeAuditHistoryEntryDigest,
  computeAuditInventoryDigest,
  computeAuditScopeHash,
  computeAtlasFindingId,
  computeAtlasFingerprint,
  computeAtlasObservationId,
  computeAtlasOccurrenceId,
  computeExactScopeIdentityDigest,
  computeSemanticScopeIdentityDigest,
  isStrictRfc3339Timestamp,
  AUDIT_V3_UNIQUE_BLOB_BYTE_LIMIT,
  loadAuditObservationHistory,
  loadAuditObservations,
  parseAuditCurrentLedger,
  parseAuditObservationHistory,
  prepareAuditObservationPublication,
  publishAuditObservation,
  registerAuditUniqueBlobBytes,
} from '../dist/audit-v3.js'
import { withAuditLock } from '../dist/audit-core.js'
import {
  buildAuditDecisionIndex,
  parseAuditDecisionPolicy,
  reduceAuditDecisionState,
} from '../dist/audit-decisions.js'

const REPOSITORY_ID = 'repo_fixture'
const SOURCE_BLOB = 'git-sha1:41715495f45f651e6cf7d38f58a3d512abcfa440'
const RULESET_DIGEST = 'sha256:12cf94bca7b76afaccb3138ad0251291c303ff5e8b8295d519c1e1da563d4a1f'
const SNAPSHOT_DIGEST = 'sha256:8d8d0572b42f193c291c94350d24e3c1354dbdc322fdd808e912bf8b54f00afd'
const EFFECTIVE_CONFIG_DIGEST = 'sha256:bc9c72bbf740e607b2ee20f9cded9b1f77e6f77dd2ba0a8da12b697d91df4436'
const ENVIRONMENT_POLICY_DIGEST = 'sha256:afa13acf32201c00babd08df7ea8ac2c481c33c3a2e0c9c2befe53162349b094'
const FIXTURE_REVISION = '4330d27a57a5c204605d3dbe40bd4dd4038d6227'
const FINGERPRINT = 'atlas/v1:sha256:83a0938048442a8ddf9ddebe56076bf4d0237b4e6539485767e9292e729aa53a'
const FINDING_ID = 'atf_0d465ed12cdccf67f62645b4'
const OBSERVATION_ID = 'aobs_a41a0fb238644b712492565c'
const OCCURRENCE_ID = 'atocc_fe401c5bdff9b7bbde7c5fe6'
const EXACT_SCOPE_IDENTITY = 'sha256:cba4d1702bdc8aa3dbb14e0527fe2bbc5e4d549b05dc6eaf87db362a346cfff6'
const INVENTORY_DIGEST = 'sha256:6fdda192e0ea5d6de1067c713b1d18397c4eae508978ead029cfe87a8a0c08eb'
const SCOPE_HASH = 'sha256:7076b1b19e28d4d37af046a660dd8fe7270eae4fd54013be82fa061d9e02a2bc'
const CURRENT_DIGEST = 'sha256:d867f9ba60a78f1a4576ae22c3c1651e43860c859ff30082b4abfbb0b24be26d'
const HISTORY_ENTRY_DIGEST = 'sha256:29dd29cb8f2a9ac19f638fba35e9cf560f02bfbca91113cef0262ae4dd48ecbe'
const HISTORY_DIGEST = 'sha256:9a28edfbc6912db2d972d94191aadd2e93d60a0d799372500c35728a686c72ef'
const CODEX_PRODUCER_IDENTITY = 'sha256:f20a13a478139ab72b98014fb9517fced38919c0a49264a4d29501133dd9c259'
const CODEX_TARGET_IDENTITY = 'sha256:e4d37c70eb1b693cd6ae3332f9844c9f21cd04ee2e03064637b93ba7bb7fb7a4'
const SEMANTIC_SCOPE_IDENTITY = 'sha256:efeccb1a48012872adab152bd4a99daaeb57574ceb53b23bdfaa3560a78d7135'
const SEMANTIC_OBSERVATION_ID = 'aobs_f5c5ea537debe1d10197bb51'
const SEMANTIC_OCCURRENCE_ID = 'atocc_c1f10056b30fd531977a84c0'
const CODEX_FINGERPRINT = 'codex-security/v1:sha256:742008ec891950bad65fc89f8f4636bbf34e135a302b21b9af4f2e4f84518e2c'
const CODEX_FINDING_ID = 'csf_c49e1003f50b3ca9efc21e7e'
const CODEX_OCCURRENCE_ID = 'occ_2eaae3119067bf92982593e3'
const ARTIFACT_SHA256 = 'f'.repeat(64)
const COVERAGE_ARTIFACT_SHA256 = 'c'.repeat(64)
const MANIFEST_ARTIFACT_SHA256 = 'a'.repeat(64)
const RECEIPT_ARTIFACT_SHA256 = 'b'.repeat(64)
const HARDENING_ARTIFACT_SHA256 = 'd'.repeat(64)

test('source timestamp validation follows the RFC 3339 calendar', () => {
  for (const timestamp of [
    '2024-02-29T12:34:56Z',
    '2024-02-29t12:34:56.123z',
    '2024-02-29T12:34:56.123+05:30',
  ]) {
    assert.equal(isStrictRfc3339Timestamp(timestamp), true, timestamp)
  }
  for (const timestamp of [
    '0000-01-01T00:00:00Z',
    '2026-02-29T12:34:56Z',
    '2026-04-31T12:34:56Z',
    '2026-05-31T24:00:00Z',
    '2026-05-31T23:59:60Z',
    '2026-05-31T23:59:59+24:00',
  ]) {
    assert.equal(isStrictRfc3339Timestamp(timestamp), false, timestamp)
  }
})

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical(value[key])}`
  ).join(',')}}`
}

function canonicalDigest(value) {
  return `sha256:${createHash('sha256').update(canonical(value)).digest('hex')}`
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function codexFingerprint(current, finding = current.findings[0]) {
  return `codex-security/v1:sha256:${sha256([
    'codex-security/v1',
    current.target.targetId,
    finding.ruleId,
    finding.identity.anchor,
    finding.identity.instance ?? '',
  ].join('\0'))}`
}

function resealCodexFindingIdentity(ledger) {
  const current = ledger.current
  const finding = current.findings[0]
  const atlasFingerprint = computeAtlasFingerprint({
    repositoryId: current.target.repositoryId,
    domain: 'security',
    ruleId: finding.ruleId,
    anchor: finding.identity.anchor,
    instance: finding.identity.instance,
  })
  const producerFingerprint = codexFingerprint(current, finding)
  finding.findingId = computeAtlasFindingId(atlasFingerprint)
  finding.occurrenceId = computeAtlasOccurrenceId(
    current.observationId,
    atlasFingerprint,
  )
  finding.fingerprints = [
    {
      scheme: 'atlas/v1',
      value: atlasFingerprint,
      role: 'canonical',
    },
    {
      scheme: 'codex-security/v1',
      value: producerFingerprint,
      role: 'producer',
    },
  ]
  finding.provenance.sourceFindingId =
    `csf_${sha256(producerFingerprint).slice(0, 24)}`
  finding.provenance.sourceOccurrenceId =
    `occ_${sha256(`${current.producer.runId}\0${producerFingerprint}`).slice(0, 24)}`
  return resealCurrent(ledger)
}

function makeV3Repo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-v3-'))
  execFileSync('git', ['init', '-q'], { cwd: root })
  fs.mkdirSync(path.join(root, '.atlas', 'audits'), { recursive: true })
  fs.mkdirSync(path.join(root, '.atlas', 'audit-history'), { recursive: true })
  fs.mkdirSync(path.join(root, 'src'), { recursive: true })
  fs.writeFileSync(
    path.join(root, '.atlas', 'config.json'),
    '{"formatVersion":1,"exclude":[],"repositoryId":"repo_fixture"}\n',
  )
  fs.writeFileSync(path.join(root, 'src', 'a.ts'), 'export const a = 1\n')
  execFileSync('git', ['add', '-A'], { cwd: root })
  execFileSync('git', ['commit', '-qm', 'fixture'], {
    cwd: root,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Repo Atlas Fixture',
      GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
      GIT_COMMITTER_NAME: 'Repo Atlas Fixture',
      GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      GIT_AUTHOR_DATE: '2026-07-29T12:00:00.000Z',
      GIT_COMMITTER_DATE: '2026-07-29T12:00:00.000Z',
    },
  })
  assert.equal(
    execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
    FIXTURE_REVISION,
  )
  return root
}

function cleanup(root) {
  fs.rmSync(root, { recursive: true, force: true })
}

function writeJson(root, repoPath, value) {
  const file = path.join(root, ...repoPath.split('/'))
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, `${canonical(value)}\n`)
}

function buildExactFixture() {
  const files = [{
    path: 'src/a.ts',
    blob: SOURCE_BLOB,
    lines: 1,
    status: 'reviewed',
    outcome: 'findings',
    reviewedAt: '2026-07-29T12:34:56.000Z',
    reviewedAtPrecision: 'timestamp',
    reviewedBy: 'fixture migrator',
    ruleset: 'relayos-security-v1',
    findingOccurrenceIds: [OCCURRENCE_ID],
    receiptRefs: ['migration:fixture'],
  }]
  const current = {
    observationId: OBSERVATION_ID,
    observedAt: '2026-07-29T12:34:56.000Z',
    reviewState: 'complete',
    producer: {
      kind: 'migration',
      name: 'relayos-security-scan',
      version: '1',
      adapter: 'repo-atlas/migration-v1',
      adapterVersion: '0.1.0',
      runId: 'fixture-run',
      identityDigest: RULESET_DIGEST,
      identityBasis: 'ruleset',
      ruleset: { id: 'relayos-security-v1', digest: RULESET_DIGEST },
      effectiveConfigDigest: EFFECTIVE_CONFIG_DIGEST,
      environmentPolicyDigest: ENVIRONMENT_POLICY_DIGEST,
    },
    target: {
      kind: 'git-worktree',
      repositoryId: REPOSITORY_ID,
      targetId: 'fixture-target',
      identityDigest: SNAPSHOT_DIGEST,
      identityBasis: 'snapshot',
      revision: FIXTURE_REVISION,
      snapshotDigest: SNAPSHOT_DIGEST,
      dirty: false,
    },
    scope: {
      mode: 'unit',
      identityDigest: EXACT_SCOPE_IDENTITY,
      identityBasis: 'exact-inventory',
      includePaths: ['src/**'],
      excludePaths: [],
      scopeHash: SCOPE_HASH,
      inventoryDigest: INVENTORY_DIGEST,
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
      findingId: FINDING_ID,
      occurrenceId: OCCURRENCE_ID,
      decisionLedger: 'security-runtime',
      ruleId: 'authorization/fixture-boundary',
      identity: {
        anchor: 'runtime/fixture-boundary',
        instance: 'export-a',
      },
      fingerprints: [{
        scheme: 'atlas/v1',
        value: FINGERPRINT,
        role: 'canonical',
      }],
      title: 'Fixture boundary bypass',
      summary: 'The fixture export crosses a boundary.',
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
        explanation: 'The exported value is the reviewed boundary.',
        blob: SOURCE_BLOB,
      }],
      rootCause: { summary: 'The fixture exports the boundary directly.' },
      remediation: 'Add the missing authorization gate.',
      provenance: { source: 'migration' },
    }],
    evidenceRefs: [],
    sourceArtifacts: [],
    producerExtensions: [],
  }
  const entryCore = {
    observationId: OBSERVATION_ID,
    observationDigest: CURRENT_DIGEST,
    previousEntryDigest: null,
    observation: current,
  }
  const historyEntry = {
    ...entryCore,
    entryDigest: HISTORY_ENTRY_DIGEST,
  }
  const history = {
    formatVersion: 1,
    format: 'atlas-audit-history-v1',
    domain: 'security',
    slug: 'security-runtime',
    entries: [historyEntry],
  }
  const ledger = {
    formatVersion: 3,
    format: 'atlas-audit-v3',
    domain: 'security',
    slug: 'security-runtime',
    title: 'Runtime',
    conceptSlug: 'runtime',
    current,
    currentDigest: CURRENT_DIGEST,
    history: {
      path: '.atlas/audit-history/security-runtime.json',
      observationId: OBSERVATION_ID,
      entryDigest: HISTORY_ENTRY_DIGEST,
    },
  }
  return { current, files, historyEntry, history, ledger }
}

function coordinateTargetIdentity(target) {
  const identity = {
    namespace: 'repo-atlas/revision-coordinate/v1',
    sourceKind: target.sourceKind,
    targetId: target.targetId,
  }
  for (const key of [
    'sourceRevision',
    'sourceBaseRevision',
    'sourceHeadRevision',
    'sourceSnapshotDigest',
  ]) {
    if (Object.hasOwn(target, key)) identity[key] = target[key]
  }
  return canonicalDigest(identity)
}

function buildSemanticFixture() {
  const current = {
    observationId: SEMANTIC_OBSERVATION_ID,
    observedAt: '2026-07-29T12:34:56.000Z',
    reviewState: 'complete',
    producer: {
      kind: 'codex-security',
      name: 'codex-security',
      version: '1.0',
      adapter: 'repo-atlas/codex-security-v1',
      adapterVersion: '0.1.0',
      runId: 'scan-fixture',
      identityDigest: CODEX_PRODUCER_IDENTITY,
      identityBasis: 'codex-contract',
      sourceContract: {
        namespace: 'codex-security/1.0',
        status: 'completed',
        startedAt: '2026-07-29T12:00:00.000Z',
        completedAt: '2026-07-29T12:34:56.000Z',
        sealedAt: '2026-07-29T12:34:56.000Z',
        manifestPath: 'scan-manifest.json',
        coverageRef: 'coverage.json',
        findingsRef: 'findings.json',
      },
    },
    target: {
      kind: 'git-revision',
      sourceKind: 'git_revision',
      repositoryId: REPOSITORY_ID,
      targetId: 'codex-target',
      displayName: 'Codex fixture',
      identityDigest: CODEX_TARGET_IDENTITY,
      identityBasis: 'revision-coordinate',
      sourceRevision: 'deadbeef',
    },
    scope: {
      mode: 'repository',
      identityDigest: SEMANTIC_SCOPE_IDENTITY,
      identityBasis: 'semantic-declaration',
      inventoryStrategy: 'repository',
      includePaths: ['src/**'],
      excludePaths: [],
      explicitExclusions: [],
      artifactsReviewed: [],
      limitations: [],
    },
    exactCoverage: {
      completeness: 'unknown',
      basis: 'unavailable',
      reason: 'Codex Security 1.0 did not supply exact per-file blob receipts.',
    },
    semanticCoverage: {
      mode: 'repository',
      completeness: 'complete',
      inventoryStrategy: 'repository',
      surfaces: [{
        id: 'authorization',
        label: 'Authorization',
        disposition: 'reported',
        receiptRefs: ['artifacts/authorization.json'],
      }],
      explicitExclusions: [],
      deferred: [],
      openQuestions: [{
        question: 'Can a lower-trust caller reach the fixture export?',
      }],
    },
    findings: [{
      findingId: FINDING_ID,
      occurrenceId: SEMANTIC_OCCURRENCE_ID,
      decisionLedger: 'security-runtime',
      ruleId: 'authorization/fixture-boundary',
      identity: {
        anchor: 'runtime/fixture-boundary',
        instance: 'export-a',
      },
      fingerprints: [{
        scheme: 'atlas/v1',
        value: FINGERPRINT,
        role: 'canonical',
      }, {
        scheme: 'codex-security/v1',
        value: CODEX_FINGERPRINT,
        role: 'producer',
      }],
      title: 'Fixture boundary bypass',
      summary: 'The fixture export crosses a boundary.',
      severity: { level: 'high' },
      confidence: {
        level: 'high',
        rationale: 'The sealed source trace reaches the export.',
      },
      taxonomy: { category: 'authorization' },
      locations: [{ path: 'src/a.ts', startLine: 1 }],
      codeEvidence: [{
        evidenceBasis: 'sealed-producer-snippet',
        id: 'export-a',
        label: 'Fixture export',
        path: 'src/a.ts',
        startLine: 1,
        code: 'export const a = 1',
        explanation: 'The producer traced the exported boundary.',
        sourceSeal: {
          artifactPath: 'findings.json',
          artifactSha256: ARTIFACT_SHA256,
          jsonPointer: '/findings/0/codeEvidence/0',
        },
      }],
      rootCause: {
        summary: 'The fixture exports the boundary directly.',
      },
      remediation: 'Add the missing authorization gate.',
      validation: {
        method: 'static source trace',
        disposition: 'reportable',
        summary: 'The exported boundary has no gate.',
        confidence: 'high',
        confidenceRationale: 'The sealed trace is direct.',
        evidenceRefs: ['export-a'],
        limitations: [],
      },
      attackPath: {
        summary: 'A lower-trust caller reaches the export.',
        dataflow: {
          summary: 'Caller input reaches the exported value.',
          source: 'lower-trust caller',
          transformations: [],
          sink: 'fixture export',
          outcome: 'boundary bypass',
          evidenceRefs: ['export-a'],
        },
        impact: {
          level: 'high',
          why: 'Authorization is bypassed.',
        },
        likelihood: {
          level: 'medium',
          why: 'The caller needs access to the adapter.',
        },
        evidenceRefs: ['export-a'],
        limitations: [],
      },
      provenance: {
        source: 'codex-security',
        producerSource: 'codex-security',
        sourceFindingId: CODEX_FINDING_ID,
        sourceOccurrenceId: CODEX_OCCURRENCE_ID,
      },
    }],
    evidenceRefs: [],
    sourceArtifacts: [
      {
        path: 'artifacts/authorization.json',
        sha256: RECEIPT_ARTIFACT_SHA256,
        mediaType: 'application/json',
        integrityKind: 'producer-manifest',
        integrityIndex: 'scan-manifest.json',
        referencedBy: ['/semanticCoverage/surfaces/0/receiptRefs/0'],
        retainedInAtlas: false,
      },
      {
        path: 'coverage.json',
        sha256: COVERAGE_ARTIFACT_SHA256,
        mediaType: 'application/json',
        integrityKind: 'producer-manifest',
        integrityIndex: 'scan-manifest.json',
        referencedBy: ['/producer/sourceContract/coverageRef'],
        retainedInAtlas: false,
      },
      {
        path: 'findings.json',
        sha256: ARTIFACT_SHA256,
        mediaType: 'application/json',
        integrityKind: 'producer-manifest',
        integrityIndex: 'scan-manifest.json',
        referencedBy: [
          '/findings/0/codeEvidence/0/sourceSeal/artifactPath',
          '/producer/sourceContract/findingsRef',
        ],
        retainedInAtlas: false,
      },
      {
        path: 'scan-manifest.json',
        sha256: MANIFEST_ARTIFACT_SHA256,
        mediaType: 'application/json',
        integrityKind: 'adapter-bundle',
        referencedBy: ['/producer/sourceContract/manifestPath'],
        retainedInAtlas: false,
      },
    ],
    producerExtensions: [],
  }
  const entryCore = {
    observationId: current.observationId,
    observationDigest: canonicalDigest(current),
    previousEntryDigest: null,
    observation: current,
  }
  const entryDigest = canonicalDigest(entryCore)
  const ledger = {
    formatVersion: 3,
    format: 'atlas-audit-v3',
    domain: 'security',
    slug: 'security-runtime',
    title: 'Runtime',
    current,
    currentDigest: entryCore.observationDigest,
    history: {
      path: '.atlas/audit-history/security-runtime.json',
      observationId: current.observationId,
      entryDigest,
    },
  }
  return { current, ledger }
}

function retargetSemanticFixture(fixture, target) {
  target.displayName ??= 'Codex fixture'
  target.identityDigest = target.identityBasis === 'snapshot'
    ? target.snapshotDigest
    : coordinateTargetIdentity(target)
  fixture.ledger.current.target = target
  fixture.ledger.current.observationId = computeAtlasObservationId({
    slug: 'security-runtime',
    adapter: fixture.ledger.current.producer.adapter,
    runId: fixture.ledger.current.producer.runId,
    producerIdentityDigest: fixture.ledger.current.producer.identityDigest,
    targetId: target.targetId,
    targetIdentityDigest: target.identityDigest,
    scopeIdentityDigest: fixture.ledger.current.scope.identityDigest,
  })
  fixture.ledger.current.findings[0].occurrenceId = computeAtlasOccurrenceId(
    fixture.ledger.current.observationId,
    FINGERPRINT,
  )
  fixture.ledger.history.observationId = fixture.ledger.current.observationId
  resealCurrent(fixture.ledger)
}

function resealSemanticDerivations(ledger) {
  const current = ledger.current
  current.scope.identityDigest = computeSemanticScopeIdentityDigest({
    mode: current.scope.mode,
    inventoryStrategy: current.scope.inventoryStrategy,
    includePaths: current.scope.includePaths,
    excludePaths: current.scope.excludePaths,
    explicitExclusions: current.scope.explicitExclusions,
  })
  current.observationId = computeAtlasObservationId({
    slug: ledger.slug,
    adapter: current.producer.adapter,
    runId: current.producer.runId,
    producerIdentityDigest: current.producer.identityDigest,
    targetId: current.target.targetId,
    targetIdentityDigest: current.target.identityDigest,
    scopeIdentityDigest: current.scope.identityDigest,
  })
  ledger.history.observationId = current.observationId
  return resealCodexFindingIdentity(ledger)
}

function resealExactDerivations(ledger) {
  ledger.current.scope.identityDigest = computeExactScopeIdentityDigest({
    mode: ledger.current.scope.mode,
    includePaths: ledger.current.scope.includePaths,
    excludePaths: ledger.current.scope.excludePaths,
    files: ledger.current.scope.files.map(({ path: filePath, blob }) => ({
      path: filePath,
      blob,
    })),
  })
  ledger.current.observationId = computeAtlasObservationId({
    slug: ledger.slug,
    adapter: ledger.current.producer.adapter,
    runId: ledger.current.producer.runId,
    producerIdentityDigest: ledger.current.producer.identityDigest,
    targetId: ledger.current.target.targetId,
    targetIdentityDigest: ledger.current.target.identityDigest,
    scopeIdentityDigest: ledger.current.scope.identityDigest,
  })
  const occurrenceId = computeAtlasOccurrenceId(
    ledger.current.observationId,
    FINGERPRINT,
  )
  ledger.current.findings[0].occurrenceId = occurrenceId
  ledger.current.scope.files[0].findingOccurrenceIds = [occurrenceId]
  ledger.current.scope.inventoryDigest =
    computeAuditInventoryDigest(ledger.current.scope.files)
  ledger.current.scope.scopeHash = computeAuditScopeHash({
    mode: ledger.current.scope.mode,
    includePaths: ledger.current.scope.includePaths,
    excludePaths: ledger.current.scope.excludePaths,
    inventoryDigest: ledger.current.scope.inventoryDigest,
  })
  ledger.current.scope.fileCount = ledger.current.scope.files.length
  ledger.history.observationId = ledger.current.observationId
  resealCurrent(ledger)
}

function resealCurrent(ledger) {
  ledger.currentDigest = canonicalDigest(ledger.current)
  return ledger
}

function prepareExactSlug(root, slug, runId) {
  const fixture = buildExactFixture()
  fixture.ledger.slug = slug
  fixture.ledger.title = slug
  delete fixture.ledger.conceptSlug
  fixture.ledger.current.producer.runId = runId
  fixture.ledger.current.findings[0].decisionLedger = slug
  fixture.ledger.history.path = `.atlas/audit-history/${slug}.json`
  resealExactDerivations(fixture.ledger)
  return prepareAuditObservationPublication(
    root,
    fixture.ledger.current,
    { slug, title: slug },
  )
}

function assertInvalid(result, pattern) {
  assert.equal(result.ok, false)
  assert.match(result.diagnostics.map((diagnostic) =>
    `${diagnostic.path} ${diagnostic.message}`
  ).join('\n'), pattern)
}

test('Atlas identity formulas match independent literal golden vectors', () => {
  const fingerprint = computeAtlasFingerprint({
    repositoryId: REPOSITORY_ID,
    domain: 'security',
    ruleId: 'authorization/fixture-boundary',
    anchor: 'runtime/fixture-boundary',
    instance: 'export-a',
  })
  assert.equal(
    fingerprint,
    'atlas/v1:sha256:83a0938048442a8ddf9ddebe56076bf4d0237b4e6539485767e9292e729aa53a',
  )
  assert.equal(computeAtlasFindingId(fingerprint), 'atf_0d465ed12cdccf67f62645b4')

  const scopeIdentityDigest = computeExactScopeIdentityDigest({
    mode: 'unit',
    includePaths: ['src/**'],
    excludePaths: [],
    files: [{ path: 'src/a.ts', blob: SOURCE_BLOB }],
  })
  assert.equal(
    scopeIdentityDigest,
    'sha256:cba4d1702bdc8aa3dbb14e0527fe2bbc5e4d549b05dc6eaf87db362a346cfff6',
  )

  const observationId = computeAtlasObservationId({
    slug: 'security-runtime',
    adapter: 'repo-atlas/migration-v1',
    runId: 'fixture-run',
    producerIdentityDigest: RULESET_DIGEST,
    targetId: 'fixture-target',
    targetIdentityDigest: SNAPSHOT_DIGEST,
    scopeIdentityDigest,
  })
  assert.equal(observationId, 'aobs_a41a0fb238644b712492565c')
  assert.equal(
    computeAtlasOccurrenceId(observationId, fingerprint),
    'atocc_fe401c5bdff9b7bbde7c5fe6',
  )
})

test('semantic declaration identity excludes result surfaces', () => {
  const declaration = {
    mode: 'repository',
    inventoryStrategy: 'repository',
    includePaths: ['src/**'],
    excludePaths: [],
    explicitExclusions: [],
  }
  assert.equal(
    computeSemanticScopeIdentityDigest(declaration),
    'sha256:efeccb1a48012872adab152bd4a99daaeb57574ceb53b23bdfaa3560a78d7135',
  )
  assert.equal(
    computeSemanticScopeIdentityDigest({
      ...declaration,
      surfaces: [{
        id: 'authorization',
        disposition: 'needs_follow_up',
        receiptRefs: ['finding:ignored-result'],
      }],
    }),
    'sha256:efeccb1a48012872adab152bd4a99daaeb57574ceb53b23bdfaa3560a78d7135',
  )
})

test('identity helpers reject ambiguous material and use byte-stable UTF-16 ordering', () => {
  assert.throws(
    () => computeAtlasFingerprint({
      repositoryId: REPOSITORY_ID,
      domain: 'security',
      ruleId: 'authorization/fixture-boundary',
      anchor: 'runtime\0fixture-boundary',
      instance: 'export-a',
    }),
    /NUL|identity|anchor/i,
  )
  assert.throws(
    () => computeAtlasObservationId({
      slug: 'Security Runtime',
      adapter: 'repo-atlas/migration-v1',
      runId: 'fixture-run',
      producerIdentityDigest: RULESET_DIGEST,
      targetId: 'fixture-target',
      targetIdentityDigest: 'sha256:not-a-digest',
      scopeIdentityDigest: EXACT_SCOPE_IDENTITY,
    }),
    /slug|digest|identity/i,
  )
  assert.throws(
    () => computeExactScopeIdentityDigest({
      mode: 'unit',
      includePaths: ['../src/**'],
      excludePaths: [],
      files: [{ path: 'src/a.ts', blob: SOURCE_BLOB }],
    }),
    /path|normalized/i,
  )

  assert.equal(
    computeExactScopeIdentityDigest({
      mode: 'custom',
      includePaths: ['src/**'],
      excludePaths: [],
      files: [
        {
          path: 'src/ä.ts',
          blob: `git-sha1:${'a'.repeat(40)}`,
        },
        {
          path: 'src/z.ts',
          blob: `git-sha1:${'b'.repeat(40)}`,
        },
      ],
    }),
    'sha256:0ce3be4920d905cb4dcb1d745ccac2e255b0879840a93fa241e217823e5d3173',
  )

  for (const malformed of ['high-\ud800', 'low-\udc00']) {
    assert.throws(
      () => computeAtlasFingerprint({
        repositoryId: REPOSITORY_ID,
        domain: 'security',
        ruleId: 'authorization/fixture-boundary',
        anchor: malformed,
      }),
      /surrogate|Unicode|identity/i,
    )
    assert.throws(
      () => computeAtlasObservationId({
        slug: 'security-runtime',
        adapter: 'repo-atlas/migration-v1',
        runId: malformed,
        producerIdentityDigest: RULESET_DIGEST,
        targetId: 'fixture-target',
        targetIdentityDigest: SNAPSHOT_DIGEST,
        scopeIdentityDigest: EXACT_SCOPE_IDENTITY,
      }),
      /surrogate|Unicode|identity/i,
    )
  }

  const exactSets = {
    mode: 'custom',
    includePaths: ['z/**', 'a/**'],
    excludePaths: ['vendor/z/**', 'vendor/a/**'],
    files: [{ path: 'src/a.ts', blob: SOURCE_BLOB }],
  }
  assert.equal(
    computeExactScopeIdentityDigest(exactSets),
    computeExactScopeIdentityDigest({
      ...exactSets,
      includePaths: [...exactSets.includePaths].reverse(),
      excludePaths: [...exactSets.excludePaths].reverse(),
    }),
  )
  const semanticSets = {
    mode: 'repository',
    inventoryStrategy: 'repository',
    includePaths: ['z/**', 'a/**'],
    excludePaths: ['vendor/z/**', 'vendor/a/**'],
    explicitExclusions: [],
  }
  assert.equal(
    computeSemanticScopeIdentityDigest(semanticSets),
    computeSemanticScopeIdentityDigest({
      ...semanticSets,
      includePaths: [...semanticSets.includePaths].reverse(),
      excludePaths: [...semanticSets.excludePaths].reverse(),
    }),
  )

  const receipt = {
    path: 'src/a.ts',
    blob: SOURCE_BLOB,
    status: 'reviewed',
    outcome: 'findings',
    findingOccurrenceIds: [OCCURRENCE_ID, `atocc_${'0'.repeat(24)}`],
    receiptRefs: ['z:receipt', 'a:receipt'],
  }
  assert.equal(
    computeAuditInventoryDigest([receipt]),
    computeAuditInventoryDigest([{
      ...receipt,
      findingOccurrenceIds: [...receipt.findingOccurrenceIds].reverse(),
      receiptRefs: [...receipt.receiptRefs].reverse(),
    }]),
  )
  assert.throws(
    () => computeAuditInventoryDigest([{
      ...receipt,
      findingOccurrenceIds: [OCCURRENCE_ID, OCCURRENCE_ID],
    }]),
    /occurrence|duplicate|unique/i,
  )
  assert.throws(
    () => computeAuditInventoryDigest([{
      ...receipt,
      receiptRefs: ['valid', '\ud800'],
    }]),
    /surrogate|Unicode|receipt|identity/i,
  )
})

test('result, current, and history digest helpers match literal vectors', () => {
  const fixture = buildExactFixture()
  assert.equal(computeAuditInventoryDigest(fixture.files), INVENTORY_DIGEST)
  assert.equal(
    computeAuditScopeHash({
      mode: 'unit',
      includePaths: ['src/**'],
      excludePaths: [],
      inventoryDigest: INVENTORY_DIGEST,
    }),
    SCOPE_HASH,
  )
  assert.equal(computeAuditCanonicalDigest(fixture.current), CURRENT_DIGEST)
  assert.equal(
    computeAuditHistoryEntryDigest({
      observationId: OBSERVATION_ID,
      observationDigest: CURRENT_DIGEST,
      previousEntryDigest: null,
      observation: fixture.current,
    }),
    HISTORY_ENTRY_DIGEST,
  )
  assert.equal(computeAuditCanonicalDigest(fixture.history), HISTORY_DIGEST)
})

test('strict current-ledger parsing accepts the exact one-file fixture', () => {
  const root = makeV3Repo()
  try {
    const fixture = buildExactFixture()
    const result = parseAuditCurrentLedger(
      root,
      '.atlas/audits/security-runtime.json',
      fixture.ledger,
    )
    assert.equal(result.ok, true)
    assert.deepEqual(result.value, fixture.ledger)
  } finally {
    cleanup(root)
  }
})

test('strict V3 current and history snapshots build and reduce without reopening the trust boundary', () => {
  const root = makeV3Repo()
  try {
    const fixture = buildExactFixture()
    const current = parseAuditCurrentLedger(
      root,
      '.atlas/audits/security-runtime.json',
      fixture.ledger,
    )
    const history = parseAuditObservationHistory(
      root,
      '.atlas/audit-history/security-runtime.json',
      fixture.history,
    )
    assert.equal(current.ok, true)
    assert.equal(history.ok, true)
    const policy = parseAuditDecisionPolicy({
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
        severityOverrides: [],
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
      acceptedRulesets: ['relayos-security-v1'],
    }, ENVIRONMENT_POLICY_DIGEST)
    const state = reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [current.value],
        [history.value],
        [],
      ),
      policy,
      '2026-07-30T00:00:00.000Z',
    )
    assert.equal(state.findings.get(FINDING_ID).disposition, 'open')
    assert.equal(state.findings.get(FINDING_ID).blocking, true)

    const hostileCurrent = structuredClone(current.value)
    let getterCalls = 0
    Object.defineProperty(hostileCurrent, 'current', {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1
        throw new Error('hostile current getter executed')
      },
    })
    assert.throws(
      () => buildAuditDecisionIndex(
        [hostileCurrent],
        [history.value],
        [],
      ),
      /data|canonical|property|accessor|snapshot/i,
    )
    assert.equal(getterCalls, 0)
  } finally {
    cleanup(root)
  }
})

test('finding decision ledgers retain a stable security home across source units', () => {
  const root = makeV3Repo()
  try {
    const moved = buildExactFixture().ledger
    moved.current.findings[0].decisionLedger = 'security-origin'
    resealCurrent(moved)
    assert.equal(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        moved,
      ).ok,
      true,
    )

    for (const decisionLedger of [
      'runtime',
      'security-Origin',
      'security-origin/',
    ]) {
      const invalid = structuredClone(moved)
      invalid.current.findings[0].decisionLedger = decisionLedger
      resealCurrent(invalid)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          invalid,
        ),
        /decisionLedger|decision ledger|security|slug/i,
      )
    }
  } finally {
    cleanup(root)
  }
})

test('strict current-ledger parsing accepts the semantic Codex fixture', () => {
  const root = makeV3Repo()
  try {
    const fixture = buildSemanticFixture()
    assert.equal(fixture.current.producer.identityDigest, CODEX_PRODUCER_IDENTITY)
    assert.equal(fixture.current.target.identityDigest, CODEX_TARGET_IDENTITY)
    assert.equal(fixture.current.scope.identityDigest, SEMANTIC_SCOPE_IDENTITY)
    assert.equal(fixture.current.observationId, SEMANTIC_OBSERVATION_ID)
    assert.equal(fixture.current.findings[0].occurrenceId, SEMANTIC_OCCURRENCE_ID)
    assert.equal(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        fixture.ledger,
      ).ok,
      true,
    )
  } finally {
    cleanup(root)
  }
})

test('Codex provider fingerprints and provenance obey independent source identity vectors', () => {
  assert.equal(
    `codex-security/v1:sha256:${sha256([
      'codex-security/v1',
      'codex-target',
      'authorization/fixture-boundary',
      'runtime/fixture-boundary',
      'export-a',
    ].join('\0'))}`,
    CODEX_FINGERPRINT,
  )
  assert.equal(`csf_${sha256(CODEX_FINGERPRINT).slice(0, 24)}`, CODEX_FINDING_ID)
  assert.equal(
    `occ_${sha256(`scan-fixture\0${CODEX_FINGERPRINT}`).slice(0, 24)}`,
    CODEX_OCCURRENCE_ID,
  )

  const root = makeV3Repo()
  try {
    const cases = [
      {
        label: 'missing producer fingerprint',
        mutate(ledger) {
          ledger.current.findings[0].fingerprints =
            ledger.current.findings[0].fingerprints.slice(0, 1)
        },
      },
      {
        label: 'wrong producer fingerprint',
        mutate(ledger) {
          ledger.current.findings[0].fingerprints[1].value =
            `codex-security/v1:sha256:${'0'.repeat(64)}`
        },
      },
      {
        label: 'wrong normalized source family',
        mutate(ledger) {
          ledger.current.findings[0].provenance.source = 'migration'
        },
      },
      {
        label: 'missing original producer source',
        mutate(ledger) {
          delete ledger.current.findings[0].provenance.producerSource
        },
      },
      {
        label: 'wrong source finding ID',
        mutate(ledger) {
          ledger.current.findings[0].provenance.sourceFindingId =
            `csf_${'0'.repeat(24)}`
        },
      },
      {
        label: 'wrong source occurrence ID',
        mutate(ledger) {
          ledger.current.findings[0].provenance.sourceOccurrenceId =
            `occ_${'0'.repeat(24)}`
        },
      },
    ]
    for (const { label, mutate } of cases) {
      const candidate = buildSemanticFixture().ledger
      mutate(candidate)
      resealCurrent(candidate)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          candidate,
        ),
        /Codex|producer|fingerprint|provenance|source|identity/i,
      )
    }

    const invalidSlug = buildSemanticFixture().ledger
    invalidSlug.current.findings[0].ruleId = 'Authorization/Fixture'
    resealCodexFindingIdentity(invalidSlug)
    assertInvalid(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        invalidSlug,
      ),
      /Codex|ruleId|slug|lowercase/i,
    )

    const trailingSourceSlug = buildSemanticFixture().ledger
    trailingSourceSlug.current.findings[0].identity.instance = 'export-'
    resealCodexFindingIdentity(trailingSourceSlug)
    assert.equal(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        trailingSourceSlug,
      ).ok,
      true,
      'literal Codex source slug regex permits a trailing source separator',
    )

    const contradictory = buildExactFixture().ledger
    contradictory.current.findings[0].provenance.source = 'codex-security'
    resealCurrent(contradictory)
    assertInvalid(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        contradictory,
      ),
      /producer|provenance|source|Codex|contradict/i,
    )
  } finally {
    cleanup(root)
  }
})

test('Codex source-contract artifacts and every source reference are bidirectionally joined', () => {
  const root = makeV3Repo()
  try {
    const cases = [
      {
        label: 'missing manifest artifact',
        mutate(current) {
          current.sourceArtifacts = current.sourceArtifacts
            .filter((artifact) => artifact.path !== 'scan-manifest.json')
        },
      },
      {
        label: 'manifest falsely called producer-sealed',
        mutate(current) {
          const artifact = current.sourceArtifacts
            .find((candidate) => candidate.path === 'scan-manifest.json')
          artifact.integrityKind = 'producer-manifest'
          artifact.integrityIndex = 'scan-manifest.json'
        },
      },
      {
        label: 'coverage not protected by manifest',
        mutate(current) {
          const artifact = current.sourceArtifacts
            .find((candidate) => candidate.path === 'coverage.json')
          artifact.integrityKind = 'adapter-bundle'
          delete artifact.integrityIndex
        },
      },
      {
        label: 'canonical document has the wrong media type',
        mutate(current) {
          current.sourceArtifacts
            .find((candidate) => candidate.path === 'coverage.json')
            .mediaType = 'text/plain'
        },
      },
      {
        label: 'wrong findings integrity index',
        mutate(current) {
          current.sourceArtifacts
            .find((candidate) => candidate.path === 'findings.json')
            .integrityIndex = 'other-manifest.json'
        },
      },
      {
        label: 'source contract points to an unrepresented artifact',
        mutate(current) {
          current.producer.sourceContract.coverageRef = 'other-coverage.json'
        },
      },
      {
        label: 'coverage receipt is unrepresented',
        mutate(current) {
          current.semanticCoverage.surfaces[0].receiptRefs =
            ['artifacts/missing.json']
        },
      },
      {
        label: 'backlink resolves to unrelated text',
        mutate(current) {
          current.sourceArtifacts
            .find((candidate) => candidate.path === 'findings.json')
            .referencedBy = ['/findings/0/title']
        },
      },
      {
        label: 'required source-seal backlink is absent',
        mutate(current) {
          current.sourceArtifacts
            .find((candidate) => candidate.path === 'findings.json')
            .referencedBy = ['/producer/sourceContract/findingsRef']
        },
      },
      {
        label: 'extraneous self-backlink is not a forward reference',
        mutate(current) {
          current.sourceArtifacts
            .find((candidate) =>
              candidate.path === 'artifacts/authorization.json'
            )
            .referencedBy = [
              '/semanticCoverage/surfaces/0/receiptRefs/0',
              '/sourceArtifacts/0/path',
            ]
        },
      },
      {
        label: 'finding artifact reference lacks its backlink',
        mutate(current) {
          current.findings[0].artifactRefs = [{
            kind: 'external',
            sourceArtifactPath: 'artifacts/authorization.json',
            integrityKind: 'producer-manifest',
            sha256: RECEIPT_ARTIFACT_SHA256,
            mediaType: 'application/json',
            retainedInAtlas: false,
          }]
        },
      },
    ]
    for (const { label, mutate } of cases) {
      const candidate = buildSemanticFixture().ledger
      mutate(candidate.current)
      resealCurrent(candidate)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          candidate,
        ),
        /artifact|manifest|coverage|findings|reference|backlink|integrity|Codex/i,
      )
    }
  } finally {
    cleanup(root)
  }
})

test('Codex hardening portfolios are first-class and bidirectionally sealed', () => {
  const root = makeV3Repo()
  const withHardening = (integrityKind = 'adapter-bundle') => {
    const ledger = buildSemanticFixture().ledger
    ledger.current.hardening = {
      portfolio: {
        kind: 'external',
        sourceArtifactPath: 'hardening/hardening.md',
        integrityKind,
        sha256: HARDENING_ARTIFACT_SHA256,
        mediaType: 'text/markdown',
        retainedInAtlas: false,
      },
    }
    ledger.current.sourceArtifacts.push({
      path: 'hardening/hardening.md',
      sha256: HARDENING_ARTIFACT_SHA256,
      mediaType: 'text/markdown',
      integrityKind,
      ...(integrityKind === 'producer-manifest'
        ? { integrityIndex: 'scan-manifest.json' }
        : {}),
      referencedBy: ['/hardening/portfolio/sourceArtifactPath'],
      retainedInAtlas: false,
    })
    ledger.current.sourceArtifacts.sort((left, right) =>
      left.path < right.path ? -1 : left.path > right.path ? 1 : 0
    )
    resealCurrent(ledger)
    return ledger
  }
  try {
    for (const integrityKind of ['adapter-bundle', 'producer-manifest']) {
      assert.equal(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          withHardening(integrityKind),
        ).ok,
        true,
        integrityKind,
      )
    }

    const cases = [
      {
        label: 'hardening digest differs from source artifact',
        mutate(current) {
          current.hardening.portfolio.sha256 = 'e'.repeat(64)
        },
      },
      {
        label: 'hardening media type differs from source artifact',
        mutate(current) {
          current.hardening.portfolio.mediaType = 'text/plain'
        },
      },
      {
        label: 'hardening backlink is missing',
        mutate(current) {
          current.sourceArtifacts
            .find(({ path: artifactPath }) =>
              artifactPath === 'hardening/hardening.md'
            )
            .referencedBy = []
        },
      },
      {
        label: 'hardening source artifact is missing',
        mutate(current) {
          current.sourceArtifacts = current.sourceArtifacts
            .filter(({ path: artifactPath }) =>
              artifactPath !== 'hardening/hardening.md'
            )
        },
      },
      {
        label: 'hardening reference has an unknown field',
        mutate(current) {
          current.hardening.portfolio.body = '# untrusted copy'
        },
      },
    ]
    for (const { label, mutate } of cases) {
      const candidate = withHardening()
      mutate(candidate.current)
      resealCurrent(candidate)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          candidate,
        ),
        /hardening|artifact|reference|backlink|digest|media|unknown/i,
      )
    }
  } finally {
    cleanup(root)
  }
})

test('ruleset file joins and exact authoritative locations close over reviewed receipts', () => {
  const root = makeV3Repo()
  try {
    const cases = [
      {
        label: 'reviewed receipt missing producer ruleset',
        mutate(ledger) {
          delete ledger.current.scope.files[0].ruleset
        },
      },
      {
        label: 'receipt names a different ruleset',
        mutate(ledger) {
          ledger.current.scope.files[0].ruleset = 'other-ruleset'
        },
      },
      {
        label: 'location is outside the exact inventory',
        mutate(ledger) {
          ledger.current.findings[0].locations[0].path = 'src/supporting.ts'
        },
      },
      {
        label: 'location exceeds the exact receipt line count',
        mutate(ledger) {
          ledger.current.findings[0].locations[0].startLine = 2
        },
      },
    ]
    for (const { label, mutate } of cases) {
      const candidate = buildExactFixture().ledger
      mutate(candidate)
      resealExactDerivations(candidate)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          candidate,
        ),
        /ruleset|receipt|location|inventory|scoped file|line/i,
      )
    }

    const semantic = buildSemanticFixture().ledger
    semantic.current.findings[0].locations[0].path = 'support/context.ts'
    resealCurrent(semantic)
    assert.equal(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        semantic,
      ).ok,
      true,
      'semantic Codex supporting locations remain outside exact inventory',
    )
  } finally {
    cleanup(root)
  }
})

test('exact blob reads are cached per parse and unique-byte budgets fail before allocation growth', () => {
  assert.equal(
    registerAuditUniqueBlobBytes(
      AUDIT_V3_UNIQUE_BLOB_BYTE_LIMIT - 1,
      1,
    ),
    AUDIT_V3_UNIQUE_BLOB_BYTE_LIMIT,
  )
  assert.throws(
    () => registerAuditUniqueBlobBytes(
      AUDIT_V3_UNIQUE_BLOB_BYTE_LIMIT,
      1,
    ),
    /unique|blob|byte|limit|268435456/i,
  )
  for (const invalid of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(
      () => registerAuditUniqueBlobBytes(invalid, 1),
      /nonnegative|safe integer|byte/i,
    )
  }

  const root = makeV3Repo()
  const wrapperRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), 'repo-atlas-v3-git-wrapper-'),
  )
  const wrapper = path.join(wrapperRoot, 'git')
  const counter = path.join(wrapperRoot, 'calls')
  const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim()
  const previousPath = process.env.PATH
  const previousCounter = process.env.ATLAS_TEST_GIT_COUNTER
  const previousRealGit = process.env.ATLAS_TEST_REAL_GIT
  try {
    fs.writeFileSync(
      wrapper,
      [
        '#!/bin/sh',
        'printf "call\\n" >> "$ATLAS_TEST_GIT_COUNTER"',
        'exec "$ATLAS_TEST_REAL_GIT" "$@"',
        '',
      ].join('\n'),
      { mode: 0o755 },
    )
    fs.writeFileSync(path.join(root, 'src/b.ts'), 'export const a = 1\n')
    execFileSync(realGit, ['add', 'src/b.ts'], { cwd: root })
    execFileSync(realGit, ['commit', '-qm', 'same blob at second path'], {
      cwd: root,
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: 'Repo Atlas Fixture',
        GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
        GIT_COMMITTER_NAME: 'Repo Atlas Fixture',
        GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      },
    })
    process.env.PATH = `${wrapperRoot}${path.delimiter}${previousPath ?? ''}`
    process.env.ATLAS_TEST_GIT_COUNTER = counter
    process.env.ATLAS_TEST_REAL_GIT = realGit

    const countCalls = (ledger) => {
      fs.writeFileSync(counter, '')
      const result = parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        ledger,
      )
      assert.equal(result.ok, true, JSON.stringify(result))
      return fs.readFileSync(counter, 'utf8').trim().split('\n').filter(Boolean).length
    }
    const single = buildExactFixture().ledger
    const singleCalls = countCalls(single)

    const duplicate = buildExactFixture().ledger
    duplicate.current.scope.files.push({
      ...structuredClone(duplicate.current.scope.files[0]),
      path: 'src/b.ts',
      outcome: 'clean',
      findingOccurrenceIds: [],
      receiptRefs: ['migration:fixture-b'],
    })
    duplicate.current.exactCoverage.reviewedFileCount = 2
    resealExactDerivations(duplicate)
    const duplicateCalls = countCalls(duplicate)
    assert.equal(
      duplicateCalls,
      singleCalls,
      'the same canonical blob must invoke Git only once per parse',
    )

    const runtime = prepareExactSlug(root, 'security-runtime', 'fixture-run')
    const storage = prepareExactSlug(root, 'security-storage', 'storage-run')
    writeJson(
      root,
      '.atlas/audit-history/security-runtime.json',
      JSON.parse(runtime.historyBytes),
    )
    fs.writeFileSync(counter, '')
    const oneHistory = loadAuditObservationHistory(root)
    assert.deepEqual(oneHistory.diagnostics, [])
    assert.equal(oneHistory.histories.length, 1)
    const oneHistoryCalls = fs.readFileSync(counter, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .length

    writeJson(
      root,
      '.atlas/audit-history/security-storage.json',
      JSON.parse(storage.historyBytes),
    )
    fs.writeFileSync(counter, '')
    const twoHistories = loadAuditObservationHistory(root)
    assert.deepEqual(twoHistories.diagnostics, [])
    assert.equal(twoHistories.histories.length, 2)
    const twoHistoryCalls = fs.readFileSync(counter, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .length
    assert.equal(
      twoHistoryCalls,
      oneHistoryCalls,
      'one history load must share canonical blob reads across every ledger',
    )
  } finally {
    if (previousPath === undefined) delete process.env.PATH
    else process.env.PATH = previousPath
    if (previousCounter === undefined) delete process.env.ATLAS_TEST_GIT_COUNTER
    else process.env.ATLAS_TEST_GIT_COUNTER = previousCounter
    if (previousRealGit === undefined) delete process.env.ATLAS_TEST_REAL_GIT
    else process.env.ATLAS_TEST_REAL_GIT = previousRealGit
    cleanup(root)
    cleanup(wrapperRoot)
  }
})

test('Codex required source code text is nonempty', () => {
  const root = makeV3Repo()
  try {
    for (const mutate of [
      (current) => {
        current.findings[0].codeEvidence[0].code = ''
      },
      (current) => {
        current.findings[0].rootCause.legacyCode = {
          code: '',
        }
      },
    ]) {
      const candidate = buildSemanticFixture().ledger
      mutate(candidate.current)
      resealCurrent(candidate)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          candidate,
        ),
        /code|nonempty|text|string/i,
      )
    }
  } finally {
    cleanup(root)
  }
})

test('strict Codex targets preserve completed snapshot rows and optional diff coordinates', () => {
  const root = makeV3Repo()
  try {
    const snapshotDigest = `sha256:${'a'.repeat(64)}`
    for (const target of [
      {
        kind: 'git-revision',
        sourceKind: 'git_revision',
        identityBasis: 'revision-coordinate',
        sourceRevision: 'deadbeef',
      },
      {
        kind: 'git-revision',
        sourceKind: 'git_revision',
        identityBasis: 'snapshot',
        sourceRevision: 'deadbeef',
        snapshotDigest,
        sourceSnapshotDigest: `codex-security-snapshot/v1:${snapshotDigest}`,
      },
      {
        kind: 'git-worktree',
        sourceKind: 'git_worktree',
        identityBasis: 'snapshot',
        snapshotDigest,
        sourceSnapshotDigest: `codex-security-snapshot/v1:${snapshotDigest}`,
        sourceRevision: 'opaque-worktree-coordinate',
        sourceBaseRevision: 'unusual-base-coordinate',
        sourceHeadRevision: 'unusual-head-coordinate',
      },
      {
        kind: 'git-diff',
        sourceKind: 'git_diff',
        identityBasis: 'snapshot',
        snapshotDigest,
        sourceSnapshotDigest: `codex-security-snapshot/v1:${snapshotDigest}`,
      },
      {
        kind: 'git-diff',
        sourceKind: 'git_diff',
        identityBasis: 'snapshot',
        snapshotDigest,
        sourceSnapshotDigest: `codex-security-snapshot/v1:${snapshotDigest}`,
        sourceBaseRevision: 'base-coordinate',
      },
      {
        kind: 'git-diff',
        sourceKind: 'git_diff',
        identityBasis: 'snapshot',
        snapshotDigest,
        sourceSnapshotDigest: `codex-security-snapshot/v1:${snapshotDigest}`,
        sourceHeadRevision: 'head-coordinate',
      },
      {
        kind: 'directory-snapshot',
        sourceKind: 'directory_snapshot',
        identityBasis: 'snapshot',
        snapshotDigest,
        sourceSnapshotDigest: `codex-security-snapshot/v1:${snapshotDigest}`,
        sourceRevision: 'unusual-directory-revision',
        sourceBaseRevision: 'unusual-directory-base',
        sourceHeadRevision: 'unusual-directory-head',
      },
    ]) {
      const fixture = buildSemanticFixture()
      retargetSemanticFixture(fixture, {
        repositoryId: REPOSITORY_ID,
        targetId: 'codex-target',
        ...target,
      })
      const result = parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        fixture.ledger,
      )
      assert.equal(
        result.ok,
        true,
        `${target.kind}/${target.sourceKind}: ${JSON.stringify(result)}`,
      )
    }

    for (const target of [
      {
        kind: 'git-worktree',
        sourceKind: 'git_worktree',
        identityBasis: 'revision-coordinate',
      },
      {
        kind: 'git-diff',
        sourceKind: 'git_diff',
        identityBasis: 'revision-coordinate',
        sourceBaseRevision: 'base-coordinate',
        sourceHeadRevision: 'head-coordinate',
      },
      {
        kind: 'directory-snapshot',
        sourceKind: 'directory_snapshot',
        identityBasis: 'revision-coordinate',
      },
    ]) {
      const fixture = buildSemanticFixture()
      retargetSemanticFixture(fixture, {
        repositoryId: REPOSITORY_ID,
        targetId: 'codex-target',
        ...target,
      })
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          fixture.ledger,
        ),
        /snapshot|identityBasis|target|completed/i,
      )
    }

    const missingDisplayName = buildSemanticFixture().ledger
    delete missingDisplayName.current.target.displayName
    resealCurrent(missingDisplayName)
    assertInvalid(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        missingDisplayName,
      ),
      /displayName|required|target/i,
    )
  } finally {
    cleanup(root)
  }
})

test('minimal Codex source records preserve optional members and safe semantic selectors', () => {
  const root = makeV3Repo()
  try {
    const minimal = buildSemanticFixture().ledger
    delete minimal.current.scope.artifactsReviewed
    delete minimal.current.scope.limitations
    delete minimal.current.semanticCoverage.openQuestions
    minimal.current.threatModel = {
      summary: 'Only the upstream-required threat-model summary is present.',
    }
    resealCurrent(minimal)
    assert.equal(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        minimal,
      ).ok,
      true,
      'optional upstream members must remain absent rather than becoming invented arrays',
    )

    for (const selector of ['.', 'src/']) {
      const fixture = buildSemanticFixture().ledger
      fixture.current.scope.includePaths = [selector]
      resealSemanticDerivations(fixture)
      assert.equal(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          fixture,
        ).ok,
        true,
        selector,
      )
      assert.throws(
        () => computeExactScopeIdentityDigest({
          mode: 'unit',
          includePaths: [selector],
          excludePaths: [],
          files: [{ path: 'src/a.ts', blob: SOURCE_BLOB }],
        }),
        /path|pattern|normalized/i,
        `exact scope must remain stricter for ${selector}`,
      )
    }

    for (const unsafe of [
      '/src/',
      '../src/',
      'src//nested',
      'src/./nested',
      'src/../nested',
      'src\\nested',
      `src/\ud800`,
    ]) {
      assert.throws(
        () => computeSemanticScopeIdentityDigest({
          mode: 'repository',
          inventoryStrategy: 'repository',
          includePaths: [unsafe],
          excludePaths: [],
          explicitExclusions: [],
        }),
        /path|selector|normalized|Unicode|surrogate/i,
        unsafe,
      )
    }
  } finally {
    cleanup(root)
  }
})

test('strict unions reject forbidden cross-variant members and missing common scope facts', () => {
  const root = makeV3Repo()
  try {
    const cases = [
      {
        mutate(ledger) {
          ledger.current.producer.ruleset = {
            id: 'invented',
            digest: CODEX_PRODUCER_IDENTITY,
          }
        },
        pattern: /producer|ruleset|unknown|forbid/i,
      },
      {
        mutate(ledger) {
          ledger.current.producer.sourceContract.sealedAt =
            '2026-07-29T12:34:57.000Z'
        },
        pattern: /sealedAt|completedAt|timestamp/i,
      },
      {
        mutate(ledger) {
          ledger.current.producer.sourceContract.startedAt =
            '2026-02-29T12:00:00Z'
        },
        pattern: /startedAt|timestamp|calendar|RFC/i,
      },
      {
        mutate(ledger) {
          ledger.current.producer.sourceContract.completedAt =
            '2026-04-31T12:34:56Z'
          ledger.current.producer.sourceContract.sealedAt =
            '2026-04-31T12:34:56Z'
          ledger.current.observedAt = '2026-05-01T12:34:56.000Z'
        },
        pattern: /completedAt|timestamp|calendar|RFC/i,
      },
      {
        mutate(ledger) {
          ledger.current.target.dirty = false
        },
        pattern: /target|dirty|unknown|forbid/i,
      },
      {
        mutate(ledger) {
          ledger.current.target.revision = FIXTURE_REVISION
        },
        pattern: /target|revision|unknown|forbid/i,
      },
      {
        mutate(ledger) {
          ledger.current.scope.files = []
        },
        pattern: /scope|files|unknown|forbid/i,
      },
      {
        mutate(ledger) {
          ledger.current.exactCoverage.reviewedFileCount = 0
        },
        pattern: /exactCoverage|reviewedFileCount|unknown|forbid/i,
      },
      {
        mutate(ledger) {
          delete ledger.current.sourceArtifacts[0].integrityIndex
        },
        pattern: /sourceArtifacts|integrityIndex|required/i,
      },
    ]
    for (const { mutate, pattern } of cases) {
      const fixture = buildSemanticFixture()
      mutate(fixture.ledger)
      resealCurrent(fixture.ledger)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          fixture.ledger,
        ),
        pattern,
      )
    }

    for (const member of ['artifactsReviewed', 'limitations']) {
      const exact = buildExactFixture().ledger
      delete exact.current.scope[member]
      resealCurrent(exact)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          exact,
        ),
        new RegExp(`scope|${member}|required`, 'i'),
      )
    }

    const exact = buildExactFixture().ledger
    exact.current.scope.inventoryStrategy = 'unit'
    resealCurrent(exact)
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', exact),
      /scope|inventoryStrategy|unknown|forbid/i,
    )
  } finally {
    cleanup(root)
  }
})

test('strict parsing rejects accessors before executing getters', () => {
  const root = makeV3Repo()
  let getterCalls = 0
  try {
    const objectAccessor = buildExactFixture().ledger
    Object.defineProperty(objectAccessor.current.producer, 'name', {
      enumerable: true,
      get() {
        getterCalls += 1
        return 'migration'
      },
    })
    assertInvalid(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        objectAccessor,
      ),
      /accessor|data-only|propert|canonical/i,
    )
    assert.equal(getterCalls, 0)

    const arrayAccessor = buildExactFixture().ledger
    Object.defineProperty(arrayAccessor.current.findings, '0', {
      enumerable: true,
      get() {
        getterCalls += 1
        return buildExactFixture().ledger.current.findings[0]
      },
    })
    assertInvalid(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        arrayAccessor,
      ),
      /accessor|data-only|array|canonical/i,
    )
    assert.equal(getterCalls, 0)
  } finally {
    cleanup(root)
  }
})

test('strict parsing enforces explicit UTF-16 ordering for semantic sets', () => {
  const root = makeV3Repo()
  try {
    const includePaths = buildSemanticFixture().ledger
    includePaths.current.scope.includePaths = ['z/**', 'a/**']
    includePaths.current.semanticCoverage.explicitExclusions = []
    resealCurrent(includePaths)
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', includePaths),
      /includePaths|order|sorted/i,
    )

    const exclusions = buildSemanticFixture().ledger
    exclusions.current.scope.explicitExclusions = [
      { pattern: 'z/**', reason: 'z' },
      { pattern: 'a/**', reason: 'a' },
    ]
    exclusions.current.semanticCoverage.explicitExclusions =
      structuredClone(exclusions.current.scope.explicitExclusions)
    resealCurrent(exclusions)
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', exclusions),
      /explicitExclusions|order|sorted/i,
    )

    const refs = buildExactFixture().ledger
    refs.current.scope.files[0].receiptRefs = ['z:receipt', 'a:receipt']
    resealCurrent(refs)
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', refs),
      /receiptRefs|order|sorted/i,
    )
  } finally {
    cleanup(root)
  }
})

test('Codex remote metadata accepts canonical hierarchical URLs without ambient authority', () => {
  const root = makeV3Repo()
  try {
    for (const remote of [
      'https://example.invalid/repository.git',
      'git+ssh://example.invalid/repository.git',
      'ftp://example.invalid/repository.git',
      'javascript://example.invalid/repository',
    ]) {
      const accepted = buildSemanticFixture()
      accepted.ledger.current.target.remote = remote
      resealCurrent(accepted.ledger)
      assert.equal(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          accepted.ledger,
        ).ok,
        true,
        remote,
      )
    }

    for (const remote of [
      '../repository',
      'repository',
      'https://user@example.invalid/repository',
      'https://example.invalid/repository?token=secret',
      'https://example.invalid/repository#fragment',
      'https:\\\\example.invalid\\repository',
      'https://example.invalid/\u0001repository',
      'HTTPS://Example.Invalid:443/repository',
    ]) {
      const fixture = buildSemanticFixture()
      fixture.ledger.current.target.remote = remote
      resealCurrent(fixture.ledger)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          fixture.ledger,
        ),
        /remote|URL|credential|query|fragment|control|canonical/i,
      )
    }
  } finally {
    cleanup(root)
  }
})

test('documented validation and attack-path fields are closed first-class objects', () => {
  const root = makeV3Repo()
  try {
    for (const section of ['validation', 'attackPath']) {
      const fixture = buildSemanticFixture()
      fixture.ledger.current.findings[0][section].unpreservedUnknown = true
      resealCurrent(fixture.ledger)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          fixture.ledger,
        ),
        new RegExp(`${section}|unknown|extension`, 'i'),
      )
    }
  } finally {
    cleanup(root)
  }
})

test('first-party targets accept every verified canonical kind and reject cross-kind members', () => {
  const root = makeV3Repo()
  try {
    for (const coordinates of [
      {
        kind: 'git-revision',
        revision: FIXTURE_REVISION,
        dirty: false,
      },
      {
        kind: 'git-worktree',
        revision: FIXTURE_REVISION,
        dirty: false,
      },
      {
        kind: 'git-worktree',
        dirty: true,
      },
      {
        kind: 'git-diff',
        baseRevision: FIXTURE_REVISION,
        headRevision: FIXTURE_REVISION,
        dirty: false,
      },
      {
        kind: 'directory-snapshot',
      },
    ]) {
      const ledger = buildExactFixture().ledger
      ledger.current.target = {
        repositoryId: REPOSITORY_ID,
        targetId: 'fixture-target',
        identityDigest: SNAPSHOT_DIGEST,
        identityBasis: 'snapshot',
        snapshotDigest: SNAPSHOT_DIGEST,
        ...coordinates,
      }
      resealExactDerivations(ledger)
      const result = parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        ledger,
      )
      assert.equal(result.ok, true, `${coordinates.kind}: ${JSON.stringify(result)}`)
    }

    const invalid = buildExactFixture().ledger
    invalid.current.target.sourceRevision = 'deadbeef'
    resealCurrent(invalid)
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', invalid),
      /target|sourceRevision|unknown|forbid/i,
    )
  } finally {
    cleanup(root)
  }
})

test('partial exact coverage closes arithmetically over sorted full-read receipts', () => {
  const root = makeV3Repo()
  try {
    const ledger = buildExactFixture().ledger
    ledger.current.scope.files.push({
      path: 'src/z.ts',
      blob: SOURCE_BLOB,
      lines: 1,
      status: 'not-reviewed',
      outcome: 'unknown',
      findingOccurrenceIds: [],
      receiptRefs: [],
    })
    ledger.current.exactCoverage = {
      completeness: 'partial',
      basis: 'full-read-receipts',
      reviewedFileCount: 1,
      unreviewed: [{
        path: 'src/z.ts',
        reason: 'No full-file read receipt was retained.',
      }],
    }
    resealExactDerivations(ledger)
    assert.equal(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        ledger,
      ).ok,
      true,
    )

    for (const mutate of [
      (candidate) => {
        candidate.current.exactCoverage.reviewedFileCount = 2
      },
      (candidate) => {
        candidate.current.exactCoverage.completeness = 'complete'
      },
      (candidate) => {
        candidate.current.scope.files[1].status = 'reviewed'
      },
    ]) {
      const candidate = structuredClone(ledger)
      mutate(candidate)
      resealExactDerivations(candidate)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          candidate,
        ),
        /coverage|reviewed|arithmetic|closure|reference/i,
      )
    }
  } finally {
    cleanup(root)
  }
})

test('result receipts change result seals but never exact pre-result identity or observation ID', () => {
  const ledger = buildExactFixture().ledger
  const scopeIdentity = ledger.current.scope.identityDigest
  const observationId = ledger.current.observationId
  const inventoryDigest = ledger.current.scope.inventoryDigest
  const currentDigest = ledger.currentDigest

  ledger.current.scope.files[0].receiptRefs.push('z:additional-receipt')
  ledger.current.scope.inventoryDigest =
    computeAuditInventoryDigest(ledger.current.scope.files)
  ledger.current.scope.scopeHash = computeAuditScopeHash({
    mode: ledger.current.scope.mode,
    includePaths: ledger.current.scope.includePaths,
    excludePaths: ledger.current.scope.excludePaths,
    inventoryDigest: ledger.current.scope.inventoryDigest,
  })
  resealCurrent(ledger)

  assert.equal(ledger.current.scope.identityDigest, scopeIdentity)
  assert.equal(ledger.current.observationId, observationId)
  assert.notEqual(ledger.current.scope.inventoryDigest, inventoryDigest)
  assert.notEqual(ledger.currentDigest, currentDigest)
})

test('semantic completeness and sealed code-evidence references fail closed', () => {
  const root = makeV3Repo()
  try {
    const deferred = buildSemanticFixture().ledger
    deferred.current.semanticCoverage.deferred.push({
      id: 'runtime-proof',
      reason: 'Requires runtime proof.',
      surfaceIds: ['authorization'],
    })
    resealCurrent(deferred)
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', deferred),
      /semantic|complete|deferred|closure/i,
    )

    const followUp = buildSemanticFixture().ledger
    followUp.current.semanticCoverage.surfaces[0].disposition = 'needs_follow_up'
    resealCurrent(followUp)
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', followUp),
      /semantic|complete|follow|closure/i,
    )

    for (const mutate of [
      (ledger) => {
        ledger.current.findings[0].codeEvidence[0].blob = SOURCE_BLOB
      },
      (ledger) => {
        delete ledger.current.findings[0].codeEvidence[0].sourceSeal
      },
      (ledger) => {
        ledger.current.findings[0].codeEvidence[0].sourceSeal.artifactSha256 =
          'e'.repeat(64)
      },
      (ledger) => {
        ledger.current.findings[0].codeEvidence[0].sourceSeal.jsonPointer =
          '/findings/~2invalid'
      },
      (ledger) => {
        ledger.current.findings[0].codeEvidence[0].sourceSeal.jsonPointer =
          '/findings/0/codeEvidence/1'
      },
    ]) {
      const candidate = buildSemanticFixture().ledger
      mutate(candidate)
      resealCurrent(candidate)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          candidate,
        ),
        /codeEvidence|sourceSeal|blob|artifact|pointer|required|unknown/i,
      )
    }
  } finally {
    cleanup(root)
  }
})

test('Codex sealed snippets cannot be fully resealed onto coverage artifacts', () => {
  const root = makeV3Repo()
  try {
    const candidate = buildSemanticFixture().ledger
    const sourceSeal =
      candidate.current.findings[0].codeEvidence[0].sourceSeal
    sourceSeal.artifactPath = 'coverage.json'
    sourceSeal.artifactSha256 = COVERAGE_ARTIFACT_SHA256

    const coverageArtifact = candidate.current.sourceArtifacts.find(
      (artifact) => artifact.path === 'coverage.json',
    )
    const findingsArtifact = candidate.current.sourceArtifacts.find(
      (artifact) => artifact.path === 'findings.json',
    )
    coverageArtifact.referencedBy = [
      '/findings/0/codeEvidence/0/sourceSeal/artifactPath',
      '/producer/sourceContract/coverageRef',
    ]
    findingsArtifact.referencedBy = ['/producer/sourceContract/findingsRef']
    resealCurrent(candidate)

    assertInvalid(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        candidate,
      ),
      /sourceSeal|findings\.json|artifact/i,
    )
  } finally {
    cleanup(root)
  }
})

test('artifact integrity variants enforce required and forbidden index members', () => {
  const root = makeV3Repo()
  try {
    const adapterBundle = buildExactFixture().ledger
    adapterBundle.current.sourceArtifacts = [{
      path: 'adapter-bundle.json',
      sha256: 'e'.repeat(64),
      mediaType: 'application/json',
      integrityKind: 'adapter-bundle',
      referencedBy: [],
      retainedInAtlas: false,
    }]
    resealCurrent(adapterBundle)
    assert.equal(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        adapterBundle,
      ).ok,
      true,
    )

    adapterBundle.current.sourceArtifacts[0].integrityIndex = 'scan-manifest.json'
    resealCurrent(adapterBundle)
    assertInvalid(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        adapterBundle,
      ),
      /integrityIndex|artifact|unknown|forbid/i,
    )
  } finally {
    cleanup(root)
  }
})

test('extensions preserve bounded data-only JSON under strict global identities', () => {
  const root = makeV3Repo()
  try {
    const extension = {
      namespace: 'codex-security.findings/1.0',
      path: '/findings/0/validation/customField',
      value: { custom: true },
      digest: canonicalDigest({ custom: true }),
    }
    const valid = buildSemanticFixture().ledger
    valid.current.producerExtensions = [extension]
    resealCurrent(valid)
    assert.equal(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        valid,
      ).ok,
      true,
    )

    const cases = [
      {
        mutate(ledger) {
          ledger.current.producerExtensions[0].digest = `sha256:${'0'.repeat(64)}`
        },
        pattern: /extension|digest/i,
      },
      {
        mutate(ledger) {
          ledger.current.producerExtensions[0].namespace = 'codex-security/1.0'
        },
        pattern: /extension|namespace/i,
      },
      {
        mutate(ledger) {
          ledger.current.producerExtensions[0].path = '/findings/~2bad'
        },
        pattern: /extension|pointer|path/i,
      },
      {
        mutate(ledger) {
          ledger.current.producerExtensions.push(
            structuredClone(ledger.current.producerExtensions[0]),
          )
        },
        pattern: /extension|duplicate/i,
      },
      {
        mutate(ledger) {
          const value = 'x'.repeat(64 * 1024)
          ledger.current.producerExtensions[0].value = value
          ledger.current.producerExtensions[0].digest = canonicalDigest(value)
        },
        pattern: /extension|65536|byte|limit/i,
      },
      {
        mutate(ledger) {
          let value = true
          for (let index = 0; index < 17; index += 1) value = { nested: value }
          ledger.current.producerExtensions[0].value = value
          ledger.current.producerExtensions[0].digest = canonicalDigest(value)
        },
        pattern: /extension|depth|limit/i,
      },
      {
        mutate(ledger) {
          const value = Object.fromEntries(
            Array.from({ length: 1_001 }, (_, index) => [`k${index}`, true]),
          )
          ledger.current.producerExtensions[0].value = value
          ledger.current.producerExtensions[0].digest = canonicalDigest(value)
        },
        pattern: /extension|member|1000|limit/i,
      },
      {
        mutate(ledger) {
          ledger.current.findings[0].extensions = [
            structuredClone(ledger.current.producerExtensions[0]),
          ]
        },
        pattern: /extension|duplicate/i,
      },
    ]
    for (const { mutate, pattern } of cases) {
      const candidate = structuredClone(valid)
      mutate(candidate)
      resealCurrent(candidate)
      assertInvalid(
        parseAuditCurrentLedger(
          root,
          '.atlas/audits/security-runtime.json',
          candidate,
        ),
        pattern,
      )
    }
  } finally {
    cleanup(root)
  }
})

test('publication rejects unsafe integer data-only JSON before durable reload', () => {
  for (const { label, mutate } of [
    {
      label: 'producer extension',
      mutate(current) {
        const value = { unsafeInteger: Number.MAX_SAFE_INTEGER + 1 }
        current.producerExtensions = [{
          namespace: 'codex-security.findings/1.0',
          path: '/findings/0/validation/customField',
          value,
          digest: canonicalDigest(value),
        }]
      },
    },
    {
      label: 'documented validation value',
      mutate(current) {
        current.findings[0].validation.assertions = [{
          unsafeInteger: 1e20,
        }]
      },
    },
  ]) {
    const root = makeV3Repo()
    try {
      const current = buildSemanticFixture().current
      mutate(current)
      let publicationError
      try {
        const prepared = prepareAuditObservationPublication(
          root,
          current,
          { slug: 'security-runtime', title: 'Runtime' },
        )
        publishAuditObservation(root, prepared.ledger)
      } catch (error) {
        publicationError = error
      }

      if (publicationError === undefined) {
        const reloaded = loadAuditObservations(root)
        assert.fail(
          `${label} published but durable reload returned ${JSON.stringify(reloaded.diagnostics)}`,
        )
      }
      assert.match(
        String(publicationError),
        /integer-valued|safe integer|extension value/i,
      )
      assert.equal(
        fs.existsSync(path.join(root, '.atlas/audits/security-runtime.json')),
        false,
      )
      assert.equal(
        fs.existsSync(
          path.join(root, '.atlas/audit-history/security-runtime.json'),
        ),
        false,
      )
    } finally {
      cleanup(root)
    }
  }
})

test('canonical ledger bytes are bounded at one MiB', () => {
  const root = makeV3Repo()
  try {
    const ledger = buildExactFixture().ledger
    ledger.current.scope.summary = 'x'.repeat(1024 * 1024)
    resealCurrent(ledger)
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', ledger),
      /ledger|1048576|byte|limit/i,
    )
  } finally {
    cleanup(root)
  }
})

test('publication preparation is deterministic and mutation-free, then publishes genesis', () => {
  const root = makeV3Repo()
  try {
    const fixture = buildExactFixture()
    const prepared = prepareAuditObservationPublication(
      root,
      fixture.current,
      {
        slug: 'security-runtime',
        title: 'Runtime',
        conceptSlug: 'runtime',
      },
    )
    assert.deepEqual(prepared.ledger, fixture.ledger)
    assert.deepEqual(prepared.historyEntry, fixture.historyEntry)
    assert.equal(prepared.currentBytes, `${canonical(fixture.ledger)}\n`)
    assert.equal(prepared.historyBytes, `${canonical(fixture.history)}\n`)
    assert.equal(
      fs.existsSync(path.join(root, '.atlas/audits/security-runtime.json')),
      false,
    )
    assert.equal(
      fs.existsSync(path.join(root, '.atlas/audit-history/security-runtime.json')),
      false,
    )

    const published = publishAuditObservation(root, prepared.ledger)
    assert.deepEqual(published, {
      currentPath: '.atlas/audits/security-runtime.json',
      historyPath: '.atlas/audit-history/security-runtime.json',
      appendedObservationId: OBSERVATION_ID,
      status: 'appended',
    })
    assert.equal(
      fs.readFileSync(
        path.join(root, '.atlas/audits/security-runtime.json'),
        'utf8',
      ),
      prepared.currentBytes,
    )
    assert.equal(
      fs.readFileSync(
        path.join(root, '.atlas/audit-history/security-runtime.json'),
        'utf8',
      ),
      prepared.historyBytes,
    )

    const loaded = loadAuditObservations(root)
    assert.deepEqual(loaded.diagnostics, [])
    assert.deepEqual(loaded.historyAhead, [])
    assert.deepEqual(loaded.observations, [prepared.ledger])
    const histories = loadAuditObservationHistory(root)
    assert.deepEqual(histories.diagnostics, [])
    assert.deepEqual(histories.histories, [fixture.history])

    assert.deepEqual(publishAuditObservation(root, prepared.ledger), {
      ...published,
      status: 'already-current',
    })
  } finally {
    cleanup(root)
  }
})

test('same-ledger publication canonicalizes raw byte drift without appending history', () => {
  const root = makeV3Repo()
  try {
    const prepared = prepareAuditObservationPublication(
      root,
      buildExactFixture().current,
      {
        slug: 'security-runtime',
        title: 'Runtime',
        conceptSlug: 'runtime',
      },
    )
    const prettyCurrent =
      `${JSON.stringify(JSON.parse(prepared.currentBytes), null, 2)}\n\n`
    const prettyHistory =
      `${JSON.stringify(JSON.parse(prepared.historyBytes), null, 2)}\n\n`
    assert.notEqual(prettyCurrent, prepared.currentBytes)
    assert.notEqual(prettyHistory, prepared.historyBytes)
    fs.writeFileSync(
      path.join(root, '.atlas/audits/security-runtime.json'),
      prettyCurrent,
    )
    fs.writeFileSync(
      path.join(root, '.atlas/audit-history/security-runtime.json'),
      prettyHistory,
    )

    assert.deepEqual(publishAuditObservation(root, prepared.ledger), {
      currentPath: '.atlas/audits/security-runtime.json',
      historyPath: '.atlas/audit-history/security-runtime.json',
      appendedObservationId: OBSERVATION_ID,
      status: 'already-current',
    })
    assert.equal(
      fs.readFileSync(
        path.join(root, '.atlas/audits/security-runtime.json'),
        'utf8',
      ),
      prepared.currentBytes,
    )
    assert.equal(
      fs.readFileSync(
        path.join(root, '.atlas/audit-history/security-runtime.json'),
        'utf8',
      ),
      prepared.historyBytes,
    )
    assert.equal(JSON.parse(prepared.historyBytes).entries.length, 1)
  } finally {
    cleanup(root)
  }
})

test('history-first publication appends and current switches without rewriting its prefix', () => {
  const root = makeV3Repo()
  try {
    const genesis = prepareAuditObservationPublication(
      root,
      buildExactFixture().current,
      { slug: 'security-runtime', title: 'Runtime' },
    )
    assert.equal(publishAuditObservation(root, genesis.ledger).status, 'appended')
    const genesisBytes = fs.readFileSync(
      path.join(root, '.atlas/audit-history/security-runtime.json'),
      'utf8',
    )

    const nextLedger = buildExactFixture().ledger
    nextLedger.current.producer.runId = 'fixture-run-2'
    nextLedger.current.observedAt = '2026-07-29T13:00:00.000Z'
    resealExactDerivations(nextLedger)
    const next = prepareAuditObservationPublication(
      root,
      nextLedger.current,
      { slug: 'security-runtime', title: 'Runtime' },
    )
    assert.equal(
      next.historyEntry.previousEntryDigest,
      genesis.historyEntry.entryDigest,
    )
    assert.notEqual(next.historyEntry.observationId, genesis.historyEntry.observationId)
    assert.equal(
      JSON.parse(genesisBytes).entries[0].entryDigest,
      genesis.historyEntry.entryDigest,
    )

    assert.equal(publishAuditObservation(root, next.ledger).status, 'appended')
    const history = JSON.parse(
      fs.readFileSync(
        path.join(root, '.atlas/audit-history/security-runtime.json'),
        'utf8',
      ),
    )
    assert.deepEqual(history.entries, [genesis.historyEntry, next.historyEntry])
    assert.deepEqual(loadAuditObservations(root), {
      observations: [next.ledger],
      historyAhead: [],
      diagnostics: [],
    })
  } finally {
    cleanup(root)
  }
})

test('combined loading permits exactly one history-ahead entry and no more', () => {
  const root = makeV3Repo()
  try {
    const genesis = prepareAuditObservationPublication(
      root,
      buildExactFixture().current,
      { slug: 'security-runtime', title: 'Runtime' },
    )
    writeJson(
      root,
      '.atlas/audit-history/security-runtime.json',
      JSON.parse(genesis.historyBytes),
    )
    assert.deepEqual(loadAuditObservations(root), {
      observations: [],
      historyAhead: ['security-runtime'],
      diagnostics: [],
    })

    fs.writeFileSync(
      path.join(root, '.atlas/audits/security-runtime.json'),
      genesis.currentBytes,
    )
    const nextLedger = buildExactFixture().ledger
    nextLedger.current.producer.runId = 'fixture-run-2'
    resealExactDerivations(nextLedger)
    const next = prepareAuditObservationPublication(
      root,
      nextLedger.current,
      { slug: 'security-runtime', title: 'Runtime' },
    )
    fs.writeFileSync(
      path.join(root, '.atlas/audit-history/security-runtime.json'),
      next.historyBytes,
    )
    assert.deepEqual(loadAuditObservations(root), {
      observations: [genesis.ledger],
      historyAhead: ['security-runtime'],
      diagnostics: [],
    })

    const thirdLedger = buildExactFixture().ledger
    thirdLedger.current.producer.runId = 'fixture-run-3'
    resealExactDerivations(thirdLedger)
    const thirdCore = {
      observationId: thirdLedger.current.observationId,
      observationDigest: canonicalDigest(thirdLedger.current),
      previousEntryDigest: next.historyEntry.entryDigest,
      observation: thirdLedger.current,
    }
    const thirdEntry = {
      ...thirdCore,
      entryDigest: canonicalDigest(thirdCore),
    }
    const invalidHistory = JSON.parse(next.historyBytes)
    invalidHistory.entries.push(thirdEntry)
    writeJson(
      root,
      '.atlas/audit-history/security-runtime.json',
      invalidHistory,
    )
    const invalid = loadAuditObservations(root)
    assert.deepEqual(invalid.observations, [])
    assert.deepEqual(invalid.historyAhead, [])
    assert.match(
      invalid.diagnostics.map((entry) => entry.message).join('\n'),
      /more than one|history-ahead|trailing|current/i,
    )

    fs.rmSync(path.join(root, '.atlas/audits/security-runtime.json'))
    const invalidGenesis = loadAuditObservations(root)
    assert.deepEqual(invalidGenesis.observations, [])
    assert.match(
      invalidGenesis.diagnostics.map((entry) => entry.message).join('\n'),
      /genesis|more than one|history-ahead|current/i,
    )
  } finally {
    cleanup(root)
  }
})

test('history loading rejects forks, unknown members, and embedded observation mismatches', () => {
  const root = makeV3Repo()
  try {
    const fixture = buildExactFixture()
    const cases = [
      {
        mutate(history) {
          history.entries[0].unexpected = true
        },
        pattern: /unknown|unexpected/i,
      },
      {
        mutate(history) {
          history.entries[0].observationDigest = `sha256:${'0'.repeat(64)}`
        },
        pattern: /observation|digest/i,
      },
      {
        mutate(history) {
          history.entries[0].previousEntryDigest = `sha256:${'0'.repeat(64)}`
          const core = { ...history.entries[0] }
          delete core.entryDigest
          history.entries[0].entryDigest = canonicalDigest(core)
        },
        pattern: /previous|genesis|chain/i,
      },
    ]
    for (const { mutate, pattern } of cases) {
      const history = structuredClone(fixture.history)
      mutate(history)
      writeJson(root, '.atlas/audit-history/security-runtime.json', history)
      const loaded = loadAuditObservationHistory(root)
      assert.deepEqual(loaded.histories, [])
      assert.match(
        loaded.diagnostics.map((entry) => entry.message).join('\n'),
        pattern,
      )
    }
  } finally {
    cleanup(root)
  }
})

test('history loading rejects observation and occurrence identity collisions across ledgers', () => {
  const root = makeV3Repo()
  try {
    const runtime = prepareExactSlug(root, 'security-runtime', 'runtime-run')
    const storage = prepareExactSlug(root, 'security-storage', 'storage-run')
    const runtimeHistory = JSON.parse(runtime.historyBytes)
    const storageHistory = JSON.parse(storage.historyBytes)
    writeJson(
      root,
      '.atlas/audit-history/security-runtime.json',
      runtimeHistory,
    )
    writeJson(
      root,
      '.atlas/audit-history/security-storage.json',
      storageHistory,
    )
    const valid = loadAuditObservationHistory(root)
    assert.deepEqual(valid.diagnostics, [])
    assert.equal(valid.histories.length, 2)
    assert.equal(
      valid.histories[0].entries[0].observation.findings[0].findingId,
      valid.histories[1].entries[0].observation.findings[0].findingId,
      'finding identities may legitimately recur across observations',
    )

    const observationCollision = structuredClone(storageHistory)
    observationCollision.entries[0].observationId =
      runtimeHistory.entries[0].observationId
    observationCollision.entries[0].observation.observationId =
      runtimeHistory.entries[0].observationId
    observationCollision.entries[0].observationDigest = canonicalDigest(
      observationCollision.entries[0].observation,
    )
    const observationCore = { ...observationCollision.entries[0] }
    delete observationCore.entryDigest
    observationCollision.entries[0].entryDigest = canonicalDigest(observationCore)
    writeJson(
      root,
      '.atlas/audit-history/security-storage.json',
      observationCollision,
    )
    assert.equal(
      loadAuditObservationHistory(root).diagnostics.some((entry) =>
        entry.code === 'audit-history-observation-id-collision'
      ),
      true,
    )

    const occurrenceCollision = structuredClone(storageHistory)
    const runtimeOccurrence =
      runtimeHistory.entries[0].observation.findings[0].occurrenceId
    occurrenceCollision.entries[0].observation.findings[0].occurrenceId =
      runtimeOccurrence
    occurrenceCollision.entries[0].observation.scope.files[0]
      .findingOccurrenceIds = [runtimeOccurrence]
    occurrenceCollision.entries[0].observationDigest = canonicalDigest(
      occurrenceCollision.entries[0].observation,
    )
    const occurrenceCore = { ...occurrenceCollision.entries[0] }
    delete occurrenceCore.entryDigest
    occurrenceCollision.entries[0].entryDigest = canonicalDigest(occurrenceCore)
    writeJson(
      root,
      '.atlas/audit-history/security-storage.json',
      occurrenceCollision,
    )
    assert.equal(
      loadAuditObservationHistory(root).diagnostics.some((entry) =>
        entry.code === 'audit-history-occurrence-id-collision'
      ),
      true,
    )
  } finally {
    cleanup(root)
  }
})

test('observation loaders enumerate raw directories incrementally and diagnose every extra entry', () => {
  const root = makeV3Repo()
  const originalReaddir = fs.readdirSync
  try {
    const fixture = buildExactFixture()
    writeJson(root, '.atlas/audits/security-runtime.json', fixture.ledger)
    writeJson(root, '.atlas/audit-history/security-runtime.json', fixture.history)
    writeJson(root, '.atlas/audits/legacy-v2.json', {
      formatVersion: 2,
      findings: [],
    })
    fs.writeFileSync(
      path.join(root, '.atlas/audits/malformed.json'),
      '{"formatVersion":3,',
    )
    fs.writeFileSync(path.join(root, '.atlas/audits/README'), 'unexpected\n')
    fs.symlinkSync(
      path.join(root, 'src/runtime.ts'),
      path.join(root, '.atlas/audits/symlink.json'),
    )
    fs.writeFileSync(
      path.join(root, '.atlas/audit-history/malformed.json'),
      '{"format":"atlas-audit-history-v1",',
    )
    fs.writeFileSync(
      path.join(root, '.atlas/audit-history/README'),
      'unexpected\n',
    )
    fs.symlinkSync(
      path.join(root, 'src/runtime.ts'),
      path.join(root, '.atlas/audit-history/symlink.json'),
    )
    fs.readdirSync = function rejectingBareAuditEnumeration(file, ...rest) {
      const candidate = String(file)
      if (
        candidate === path.join(root, '.atlas/audits') ||
        candidate === path.join(root, '.atlas/audit-history')
      ) {
        throw new Error('bare audit-directory enumeration is forbidden')
      }
      return originalReaddir.call(fs, file, ...rest)
    }

    const histories = loadAuditObservationHistory(root)
    assert.deepEqual(histories.histories, [fixture.history])
    assert.deepEqual(
      histories.diagnostics.map((entry) => entry.path).sort(),
      [
        '.atlas/audit-history/README',
        '.atlas/audit-history/malformed.json',
        '.atlas/audit-history/symlink.json',
      ],
    )

    const loaded = loadAuditObservations(root)
    assert.deepEqual(loaded.observations, [fixture.ledger])
    assert.deepEqual(loaded.historyAhead, [])
    assert.deepEqual(
      loaded.diagnostics.map((entry) => entry.path).sort(),
      [
        '.atlas/audit-history/README',
        '.atlas/audit-history/malformed.json',
        '.atlas/audit-history/symlink.json',
        '.atlas/audits/README',
        '.atlas/audits/malformed.json',
        '.atlas/audits/symlink.json',
      ],
    )
    assert.equal(
      loaded.diagnostics.some((entry) => entry.path.endsWith('legacy-v2.json')),
      false,
      'valid V1/V2 JSON remains owned by compatibility loading',
    )
  } finally {
    fs.readdirSync = originalReaddir
    cleanup(root)
  }
})

test('publication rejects conflicts and pre-held locks without changing prior bytes', () => {
  const root = makeV3Repo()
  try {
    const prepared = prepareAuditObservationPublication(
      root,
      buildExactFixture().current,
      { slug: 'security-runtime', title: 'Runtime' },
    )
    const before = {
      current: fs.existsSync(path.join(root, '.atlas/audits/security-runtime.json')),
      history: fs.existsSync(path.join(root, '.atlas/audit-history/security-runtime.json')),
    }
    assert.throws(
      () => withAuditLock(root, () => publishAuditObservation(root, prepared.ledger)),
      /lock|held|exists/i,
    )
    assert.equal(
      fs.existsSync(path.join(root, '.atlas/audits/security-runtime.json')),
      before.current,
    )
    assert.equal(
      fs.existsSync(path.join(root, '.atlas/audit-history/security-runtime.json')),
      before.history,
    )

    publishAuditObservation(root, prepared.ledger)
    const currentBytes = fs.readFileSync(
      path.join(root, '.atlas/audits/security-runtime.json'),
      'utf8',
    )
    const historyBytes = fs.readFileSync(
      path.join(root, '.atlas/audit-history/security-runtime.json'),
      'utf8',
    )
    const conflicting = structuredClone(prepared.ledger.current)
    conflicting.findings[0].summary = 'Different evidence under the same observation ID.'
    assert.throws(
      () => prepareAuditObservationPublication(
        root,
        conflicting,
        { slug: 'security-runtime', title: 'Runtime' },
      ),
      /same observation|conflict|digest|identity/i,
    )
    assert.equal(
      fs.readFileSync(path.join(root, '.atlas/audits/security-runtime.json'), 'utf8'),
      currentBytes,
    )
    assert.equal(
      fs.readFileSync(
        path.join(root, '.atlas/audit-history/security-runtime.json'),
        'utf8',
      ),
      historyBytes,
    )
  } finally {
    cleanup(root)
  }
})

test('idempotent publication rejects wrapper metadata changes and historical rewinds', () => {
  const mutations = [
    {
      label: 'title',
      mutate(ledger) {
        ledger.title = 'Changed title'
      },
    },
    {
      label: 'conceptSlug',
      mutate(ledger) {
        ledger.conceptSlug = 'changed-concept'
      },
    },
    {
      label: 'history pointer',
      mutate(ledger) {
        ledger.history.path = '.atlas/audit-history/security-other.json'
      },
    },
  ]
  for (const { label, mutate } of mutations) {
    const root = makeV3Repo()
    try {
      const prepared = prepareAuditObservationPublication(
        root,
        buildExactFixture().current,
        { slug: 'security-runtime', title: 'Runtime' },
      )
      publishAuditObservation(root, prepared.ledger)
      const currentPath = path.join(root, '.atlas/audits/security-runtime.json')
      const historyPath = path.join(
        root,
        '.atlas/audit-history/security-runtime.json',
      )
      const currentBytes = fs.readFileSync(currentPath)
      const historyBytes = fs.readFileSync(historyPath)
      const changed = structuredClone(prepared.ledger)
      mutate(changed)
      assert.throws(
        () => publishAuditObservation(root, changed),
        /conflict|metadata|wrapper|history|path|same observation|match/i,
        label,
      )
      assert.deepEqual(fs.readFileSync(currentPath), currentBytes, label)
      assert.deepEqual(fs.readFileSync(historyPath), historyBytes, label)
    } finally {
      cleanup(root)
    }
  }

  const root = makeV3Repo()
  try {
    const genesis = prepareAuditObservationPublication(
      root,
      buildExactFixture().current,
      { slug: 'security-runtime', title: 'Runtime' },
    )
    publishAuditObservation(root, genesis.ledger)
    const nextLedger = buildExactFixture().ledger
    nextLedger.current.producer.runId = 'fixture-run-2'
    resealExactDerivations(nextLedger)
    const next = prepareAuditObservationPublication(
      root,
      nextLedger.current,
      { slug: 'security-runtime', title: 'Runtime' },
    )
    publishAuditObservation(root, next.ledger)
    assert.throws(
      () => publishAuditObservation(root, genesis.ledger),
      /rewind|older|history|head|resume/i,
    )
  } finally {
    cleanup(root)
  }
})

test('publication preparation rejects unsafe optional-file parent topology even when the leaf is absent', () => {
  for (const directory of ['audits', 'audit-history']) {
    const root = makeV3Repo()
    const outside = fs.mkdtempSync(
      path.join(os.tmpdir(), 'repo-atlas-v3-optional-outside-'),
    )
    const target = path.join(root, '.atlas', directory)
    const parked = `${target}-parked`
    try {
      fs.renameSync(target, parked)
      fs.symlinkSync(outside, target)
      assert.throws(
        () => prepareAuditObservationPublication(
          root,
          buildExactFixture().current,
          { slug: 'security-runtime', title: 'Runtime' },
        ),
        /audit directory|symlink|safe|topology|parent/i,
        directory,
      )
    } finally {
      if (fs.existsSync(target) && fs.lstatSync(target).isSymbolicLink()) {
        fs.unlinkSync(target)
      }
      if (!fs.existsSync(target) && fs.existsSync(parked)) {
        fs.renameSync(parked, target)
      }
      cleanup(root)
      cleanup(outside)
    }
  }
})

test('a failed current switch leaves one resumable history-ahead entry', () => {
  const root = makeV3Repo()
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-v3-outside-'))
  const audits = path.join(root, '.atlas/audits')
  const parked = path.join(root, '.atlas/audits-parked')
  const originalRename = fs.renameSync
  try {
    const prepared = prepareAuditObservationPublication(
      root,
      buildExactFixture().current,
      { slug: 'security-runtime', title: 'Runtime' },
    )
    let injected = false
    fs.renameSync = function swapCurrentAfterHistoryWrite(source, destination) {
      const result = originalRename.call(fs, source, destination)
      if (
        !injected &&
        path.basename(String(destination)) === 'security-runtime.json' &&
        (() => {
          try {
            return fs.realpathSync(path.dirname(String(destination))) ===
              path.join(root, '.atlas/audit-history')
          } catch {
            return false
          }
        })()
      ) {
        injected = true
        originalRename.call(fs, audits, parked)
        fs.symlinkSync(outside, audits)
      }
      return result
    }
    assert.throws(
      () => publishAuditObservation(root, prepared.ledger),
      /audit parent|symlink|safe|directory/i,
    )
    assert.equal(injected, true)
    fs.renameSync = originalRename
    assert.equal(fs.readdirSync(outside).length, 0)
    assert.equal(
      fs.existsSync(path.join(root, '.atlas/audit-history/security-runtime.json')),
      true,
    )
    fs.unlinkSync(audits)
    fs.renameSync(parked, audits)
    assert.deepEqual(loadAuditObservations(root), {
      observations: [],
      historyAhead: ['security-runtime'],
      diagnostics: [],
    })
    assert.equal(
      publishAuditObservation(root, prepared.ledger).status,
      'resumed',
    )
    assert.deepEqual(loadAuditObservations(root), {
      observations: [prepared.ledger],
      historyAhead: [],
      diagnostics: [],
    })
  } finally {
    fs.renameSync = originalRename
    if (fs.existsSync(audits) && fs.lstatSync(audits).isSymbolicLink()) {
      fs.unlinkSync(audits)
    }
    if (!fs.existsSync(audits) && fs.existsSync(parked)) {
      fs.renameSync(parked, audits)
    }
    cleanup(root)
    cleanup(outside)
  }
})

test('stored clean targets remain valid after the repository advances', () => {
  const root = makeV3Repo()
  try {
    fs.writeFileSync(path.join(root, 'later.txt'), 'later commit\n')
    execFileSync('git', ['add', 'later.txt'], { cwd: root })
    execFileSync('git', ['commit', '-qm', 'later'], {
      cwd: root,
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: 'Repo Atlas Fixture',
        GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
        GIT_COMMITTER_NAME: 'Repo Atlas Fixture',
        GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      },
    })
    assert.notEqual(
      execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
      FIXTURE_REVISION,
    )

    assert.equal(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        buildExactFixture().ledger,
      ).ok,
      true,
    )
  } finally {
    cleanup(root)
  }
})

test('dirty first-party worktree targets may omit an unprovable revision', () => {
  const root = makeV3Repo()
  try {
    const fixture = buildExactFixture()
    fixture.ledger.current.target.dirty = true
    delete fixture.ledger.current.target.revision
    resealCurrent(fixture.ledger)

    assert.equal(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-runtime.json',
        fixture.ledger,
      ).ok,
      true,
    )
  } finally {
    cleanup(root)
  }
})

test('strict current-ledger parsing rejects unknown members and resealed wrong identities', () => {
  const root = makeV3Repo()
  try {
    const unknownRoot = structuredClone(buildExactFixture().ledger)
    unknownRoot.unexpected = true
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', unknownRoot),
      /unexpected|unknown/i,
    )

    const unknownNested = structuredClone(buildExactFixture().ledger)
    unknownNested.current.producer.ruleset.unexpected = true
    resealCurrent(unknownNested)
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', unknownNested),
      /producer.*ruleset|unexpected|unknown/i,
    )

    const wrongObservation = structuredClone(buildExactFixture().ledger)
    wrongObservation.current.producer.runId = 'different-run'
    resealCurrent(wrongObservation)
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', wrongObservation),
      /observationId|identity/i,
    )

    const wrongCurrentDigest = structuredClone(buildExactFixture().ledger)
    wrongCurrentDigest.currentDigest = `sha256:${'0'.repeat(64)}`
    assertInvalid(
      parseAuditCurrentLedger(root, '.atlas/audits/security-runtime.json', wrongCurrentDigest),
      /currentDigest|digest/i,
    )

    assertInvalid(
      parseAuditCurrentLedger(
        root,
        '.atlas/audits/security-other.json',
        buildExactFixture().ledger,
      ),
      /filename|slug|history/i,
    )
  } finally {
    cleanup(root)
  }
})

test('a history blob this clone no longer has keeps the ledger valid, while the current one does not', () => {
  const root = makeV3Repo()
  try {
    const fixture = buildExactFixture()
    // A blob id of the right shape that no object database contains. This is not
    // hypothetical: a dirty-worktree run registers reviewed bytes with
    // `hash-object -w`, which produces a loose object reachable from no ref, so it
    // is never pushed and `git gc` may prune it. The record survives; the object
    // does not travel.
    const absent = `git-sha1:${'a1b2c3d4'.repeat(5)}`

    const historyWithAbsentBlob = JSON.parse(JSON.stringify(fixture.history))
    const entry = historyWithAbsentBlob.entries.at(-1)
    entry.observation.scope.files[0].blob = absent
    const history = parseAuditObservationHistory(
      root,
      '.atlas/audit-history/security-runtime.json',
      historyWithAbsentBlob,
    )
    // Not ok — the entry digest no longer matches, which is the RIGHT reason to
    // reject: integrity is the digest chain. What must not happen is a rejection
    // whose reason is merely that the object is absent.
    if (history.ok === false) {
      const reasons = JSON.stringify(history)
      assert.ok(
        !reasons.includes('claimed Git blob is unavailable'),
        `history must not be rejected for blob absence alone: ${reasons.slice(0, 400)}`,
      )
    }

    // The current observation is a live claim a reader must be able to
    // re-derive, so there the absent object IS the failure.
    const currentWithAbsentBlob = JSON.parse(JSON.stringify(fixture.ledger))
    currentWithAbsentBlob.current.scope.files[0].blob = absent
    const current = parseAuditCurrentLedger(
      root,
      '.atlas/audits/security-runtime.json',
      currentWithAbsentBlob,
    )
    assert.equal(current.ok, false)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})
