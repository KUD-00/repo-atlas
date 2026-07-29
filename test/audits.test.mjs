import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  auditStatusEntries,
  loadAuditPortfolios,
  loadAudits,
  projectAuditV3SecurityUnit,
  stampAudits,
} from '../dist/audits.js'
import {
  computeAuditInventoryDigest,
  computeAuditScopeHash,
  computeAtlasFindingId,
  computeAtlasFingerprint,
  computeAtlasObservationId,
  computeAtlasOccurrenceId,
  computeExactScopeIdentityDigest,
  loadAuditObservations,
  prepareAuditObservationPublication,
  publishAuditObservation,
} from '../dist/audit-v3.js'
import { scan } from '../dist/scan.js'
import { cleanup, commitAll, gitBlob, makeRepo, scopeHash, write } from './helpers.mjs'

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

/** Alias used by coverage-aware Task 1 fixtures. */
const writeV2 = v2Envelope

function makeSha256Repo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sha256-'))
  execFileSync('git', ['init', '-q', '--object-format=sha256'], { cwd: root })
  execFileSync('git', ['config', 'user.email', 'repo-atlas-test@example.invalid'], {
    cwd: root,
  })
  execFileSync('git', ['config', 'user.name', 'repo-atlas test'], { cwd: root })
  fs.mkdirSync(path.join(root, '.atlas', 'audits'), { recursive: true })
  write(
    root,
    '.atlas/config.json',
    JSON.stringify({ formatVersion: 1, exclude: [] }) + '\n',
  )
  return root
}

function publishExactV3(root, slug = 'security-v3-runtime') {
  const repositoryId = 'repo_audits_fixture'
  write(
    root,
    '.atlas/config.json',
    JSON.stringify({ formatVersion: 1, exclude: [], repositoryId }) + '\n',
  )
  const rawBlob = gitBlob(root, 'src/a.ts')
  const blob = `git-sha${rawBlob.length === 40 ? '1' : '256'}:${rawBlob}`
  const rulesetDigest = `sha256:${'1'.repeat(64)}`
  const targetDigest = `sha256:${'2'.repeat(64)}`
  const scopeIdentityDigest = computeExactScopeIdentityDigest({
    mode: 'unit',
    includePaths: ['src/**'],
    excludePaths: [],
    files: [{ path: 'src/a.ts', blob }],
  })
  const fingerprint = computeAtlasFingerprint({
    repositoryId,
    domain: 'security',
    ruleId: 'authorization/audits-fixture',
    anchor: 'audits/fixture',
    instance: 'a',
  })
  const findingId = computeAtlasFindingId(fingerprint)
  const observationId = computeAtlasObservationId({
    slug,
    adapter: 'repo-atlas/manual-v1',
    runId: 'audits-fixture-run',
    producerIdentityDigest: rulesetDigest,
    targetId: 'audits-fixture-target',
    targetIdentityDigest: targetDigest,
    scopeIdentityDigest,
  })
  const occurrenceId = computeAtlasOccurrenceId(observationId, fingerprint)
  const files = [{
    path: 'src/a.ts',
    blob,
    lines: 1,
    status: 'reviewed',
    outcome: 'findings',
    reviewedAt: '2026-07-29T12:34:56.000Z',
    reviewedAtPrecision: 'timestamp',
    reviewedBy: 'fixture',
    ruleset: 'fixture-security-v3',
    findingOccurrenceIds: [occurrenceId],
    receiptRefs: ['fixture:full-read'],
  }]
  const inventoryDigest = computeAuditInventoryDigest(files)
  const observation = {
    observationId,
    observedAt: '2026-07-29T12:34:56.000Z',
    reviewState: 'complete',
    producer: {
      kind: 'manual',
      name: 'fixture',
      version: '1',
      adapter: 'repo-atlas/manual-v1',
      adapterVersion: '0.1.0',
      runId: 'audits-fixture-run',
      identityDigest: rulesetDigest,
      identityBasis: 'ruleset',
      ruleset: {
        id: 'fixture-security-v3',
        digest: rulesetDigest,
      },
    },
    target: {
      kind: 'directory-snapshot',
      repositoryId,
      targetId: 'audits-fixture-target',
      identityDigest: targetDigest,
      identityBasis: 'snapshot',
      snapshotDigest: targetDigest,
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
      decisionLedger: slug,
      ruleId: 'authorization/audits-fixture',
      identity: {
        anchor: 'audits/fixture',
        instance: 'a',
      },
      fingerprints: [{
        scheme: 'atlas/v1',
        value: fingerprint,
        role: 'canonical',
      }],
      title: 'V3 fixture finding',
      summary: 'The fixture has a boundary issue.',
      severity: { level: 'medium' },
      confidence: {
        level: 'high',
        rationale: 'The source receipt is exact.',
      },
      taxonomy: { category: 'authorization' },
      locations: [{ path: 'src/a.ts', startLine: 1 }],
      remediation: 'Add the missing gate.',
      provenance: { source: 'manual' },
    }],
    evidenceRefs: ['evidence/v3.json'],
    sourceArtifacts: [],
    producerExtensions: [],
  }
  const prepared = prepareAuditObservationPublication(
    root,
    observation,
    { slug, title: 'V3 Runtime', conceptSlug: 'runtime' },
  )
  publishAuditObservation(root, prepared.ledger)
  return { prepared, rawBlob, blob, findingId }
}

test('verified exact V3 observations project raw Git hashes and descriptor-checked freshness', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    const fixture = publishExactV3(root)

    const unit = loadAuditPortfolios(root).security[0]
    assert.equal(unit.formatVersion, 3)
    assert.equal(unit.ruleset, 'fixture-security-v3')
    assert.deepEqual(unit.files, ['src/a.ts'])
    assert.deepEqual(unit.hashes, { 'src/a.ts': fixture.rawBlob })
    assert.equal(unit.scopeHash, fixture.prepared.ledger.current.scope.scopeHash)
    assert.equal(unit.stale, false)
    assert.deepEqual(unit.evidenceRefs, ['evidence/v3.json'])
    assert.equal(unit.findings[0].id, fixture.findingId)
    assert.equal(unit.findings[0].confidence, 'high')
    assert.equal(unit.findings[0].disposition, 'open')
    assert.equal(unit.findings[0].dataflow, '')
    assert.equal(Object.hasOwn(unit, 'fullRead'), false)

    const direct = loadAuditObservations(root)
    assert.deepEqual(direct.diagnostics, [])
    assert.equal(
      direct.observations[0].current.scope.files[0].blob,
      fixture.blob,
      'the rich V3 ledger retains its canonical prefixed Git identity',
    )
    let status = auditStatusEntries(root, scan(root, { exclude: [] }))[0]
    assert.equal(status.status, 'fresh')
    assert.deepEqual(status.changedFiles, [])

    write(root, 'src/a.ts', 'export const a = 2\n')
    const drifted = loadAuditPortfolios(root).security[0]
    assert.equal(drifted.stale, true)
    status = auditStatusEntries(root, scan(root, { exclude: [] }))[0]
    assert.equal(status.status, 'stale')
    assert.deepEqual(status.changedFiles, ['src/a.ts'])
    assert.deepEqual(status.missingFiles, [])

    fs.unlinkSync(path.join(root, 'src/a.ts'))
    status = auditStatusEntries(root, scan(root, { exclude: [] }))[0]
    assert.equal(status.status, 'stale')
    assert.deepEqual(status.missingFiles, ['src/a.ts'])
  } finally {
    cleanup(root)
  }
})

test('exact V3 freshness hashes current bytes with the receipt Git object algorithm', () => {
  const root = makeSha256Repo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    const fixture = publishExactV3(root, 'security-v3-sha256')
    assert.equal(fixture.rawBlob.length, 64)
    assert.match(fixture.blob, /^git-sha256:/)
    assert.equal(loadAuditPortfolios(root).security[0].stale, false)

    write(root, 'src/a.ts', 'export const a = 2\n')
    assert.equal(loadAuditPortfolios(root).security[0].stale, true)
    assert.deepEqual(
      auditStatusEntries(root, scan(root, { exclude: [] }))[0].changedFiles,
      ['src/a.ts'],
    )
  } finally {
    cleanup(root)
  }
})

test('semantic Codex compatibility projection preserves absence without a freshness claim', () => {
  const root = makeRepo()
  try {
    const unit = projectAuditV3SecurityUnit(
      root,
      {
        formatVersion: 3,
        format: 'atlas-audit-v3',
        domain: 'security',
        slug: 'security-codex',
        title: 'Codex',
        current: {
          observedAt: '2026-07-29T12:34:56.000Z',
          producer: { kind: 'codex-security' },
          scope: {
            identityBasis: 'semantic-declaration',
          },
          findings: [{
            findingId: 'atf_000000000000000000000000',
            severity: { level: 'informational' },
            confidence: { level: 'medium' },
            taxonomy: { category: 'authorization' },
            title: 'Semantic finding',
            locations: [{ path: 'src/a.ts', startLine: 4 }],
            remediation: 'Review the gate.',
          }],
          evidenceRefs: [],
        },
      },
      { status: 'fresh' },
    )
    assert.equal(unit.formatVersion, 3)
    assert.equal(unit.ruleset, null)
    assert.equal(unit.scannedAt, '2026-07-29T12:34:56.000Z')
    assert.deepEqual(unit.files, [])
    assert.equal(unit.fileCount, 0)
    assert.equal(unit.hashes, null)
    assert.equal(unit.scopeHash, '')
    assert.equal(unit.stale, true)
    assert.equal(unit.findings[0].severity, 'info')
    assert.equal(unit.findings[0].dataflow, '')
    assert.equal(Object.hasOwn(unit, 'fullRead'), false)
  } finally {
    cleanup(root)
  }
})

test('portfolio discovery is bounded and V3-looking polyglots never downgrade to V1', () => {
  const root = makeRepo()
  const originalReaddir = fs.readdirSync
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    v2Envelope(
      root,
      'security',
      'security-v2',
      ['src/a.ts'],
      [finding('src/a.ts')],
    )
    write(root, '.atlas/audits/security-polyglot.json', JSON.stringify({
      formatVersion: 3,
      format: 'atlas-audit-v3',
      domain: 'security',
      slug: 'security-polyglot',
      title: 'Polyglot',
      ruleset: 'must-not-downgrade',
      scanned_at: '2026-07-29',
      scope_hash: scopeHash(root, ['src/a.ts']),
      files: ['src/a.ts'],
      findings: [finding('src/a.ts')],
      finalPass: true,
    }) + '\n')
    fs.readdirSync = function rejectBareAuditEnumeration(file, ...args) {
      if (String(file) === path.join(root, '.atlas/audits')) {
        throw new Error('bare audit enumeration is forbidden')
      }
      return originalReaddir.call(fs, file, ...args)
    }

    assert.deepEqual(
      loadAuditPortfolios(root).security.map((unit) => unit.slug),
      ['security-v2'],
    )
    const statuses = auditStatusEntries(root, scan(root, { exclude: [] }))
    const byName = Object.fromEntries(statuses.map((entry) => [entry.name, entry]))
    assert.equal(byName['security-v2'].status, 'fresh')
    assert.equal(byName['security-polyglot'].status, 'stale')
    assert.match(
      byName['security-polyglot'].invalidReason,
      /V3|current|history|missing|member|strict/i,
    )
  } finally {
    fs.readdirSync = originalReaddir
    cleanup(root)
  }
})

test('v2 security units expose exact scope, evidence refs, and normalized dispositions', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, 'audits/evidence/a.json', '{}\n')
    commitAll(root)
    writeV2(root, 'security', 'security-runtime', ['src/a.ts'], [{
      id: 'SEC-1',
      severity: 'medium',
      category: 'boundary',
      title: 'boundary is open',
      locations: ['src/a.ts:1'],
      dataflow: 'input to sink',
      fix: 'validate it',
      disposition: 'accepted-risk',
    }], {
      hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
      evidenceRefs: ['audits/evidence/a.json'],
    })
    const unit = loadAuditPortfolios(root).security[0]
    assert.deepEqual(unit.files, ['src/a.ts'])
    assert.equal(unit.scopeHash, scopeHash(root, ['src/a.ts']))
    assert.deepEqual(unit.hashes, { 'src/a.ts': gitBlob(root, 'src/a.ts') })
    assert.deepEqual(unit.evidenceRefs, ['audits/evidence/a.json'])
    assert.equal(unit.findings[0].id, 'SEC-1')
    assert.equal(unit.findings[0].disposition, 'accepted-risk')
  } finally { cleanup(root) }
})

test('v2 security finding without disposition normalizes to open', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writeV2(root, 'security', 'security-runtime', ['src/a.ts'], [{
      severity: 'low', category: 'boundary', title: 'open by default',
      locations: ['src/a.ts:1'], dataflow: 'input to sink', fix: 'validate it',
    }], { hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') } })
    assert.equal(loadAuditPortfolios(root).security[0].findings[0].disposition, 'open')
  } finally { cleanup(root) }
})

test('v2 units reject invalid dispositions and unsafe or duplicate evidence refs', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writeV2(root, 'security', 'security-bad', ['src/a.ts'], [{
      severity: 'low', category: 'boundary', title: 'bad disposition',
      locations: ['src/a.ts:1'], dataflow: 'input to sink', fix: 'validate it',
      disposition: 'ignored',
    }], { evidenceRefs: ['../outside', '../outside'] })
    assert.equal(loadAuditPortfolios(root).security.length, 0)
    const invalid = auditStatusEntries(root, scan(root, { exclude: [] }))
      .find((entry) => entry.name === 'security-bad')
    assert.match(invalid.invalidReason, /disposition|evidence ref|normalized/i)
  } finally { cleanup(root) }
})

test('v2 security findings reject empty or overlong finding ids', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)

    writeV2(root, 'security', 'empty-id', ['src/a.ts'], [{
      ...finding('src/a.ts'),
      id: '',
    }], { hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') } })
    assert.equal(loadAuditPortfolios(root).security.length, 0)
    const empty = auditStatusEntries(root, scan(root, { exclude: [] }))
      .find((entry) => entry.name === 'empty-id')
    assert.match(empty.invalidReason, /id|finding/i)

    for (const entry of fs.readdirSync(path.join(root, '.atlas/audits'))) {
      fs.unlinkSync(path.join(root, '.atlas/audits', entry))
    }
    writeV2(root, 'security', 'long-id', ['src/a.ts'], [{
      ...finding('src/a.ts'),
      id: 'x'.repeat(257),
    }], { hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') } })
    assert.equal(loadAuditPortfolios(root).security.length, 0)
    const long = auditStatusEntries(root, scan(root, { exclude: [] }))
      .find((entry) => entry.name === 'long-id')
    assert.match(long.invalidReason, /id|finding|256/i)
  } finally { cleanup(root) }
})

test('v2 units reject duplicate evidence refs', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, 'audits/evidence/a.json', '{}\n')
    commitAll(root)
    writeV2(root, 'security', 'dup-evidence', ['src/a.ts'], [finding('src/a.ts')], {
      hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
      evidenceRefs: ['audits/evidence/a.json', 'audits/evidence/a.json'],
    })
    assert.equal(loadAuditPortfolios(root).security.length, 0)
    const invalid = auditStatusEntries(root, scan(root, { exclude: [] }))
      .find((entry) => entry.name === 'dup-evidence')
    assert.match(invalid.invalidReason, /evidence ref|duplicate|normalized/i)
  } finally { cleanup(root) }
})

test('v2 units reject missing evidence refs', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writeV2(root, 'security', 'missing-evidence', ['src/a.ts'], [finding('src/a.ts')], {
      hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
      evidenceRefs: ['audits/evidence/missing.json'],
    })
    assert.equal(loadAuditPortfolios(root).security.length, 0)
    const invalid = auditStatusEntries(root, scan(root, { exclude: [] }))
      .find((entry) => entry.name === 'missing-evidence')
    assert.match(invalid.invalidReason, /evidence ref|missing|safe|regular/i)
  } finally { cleanup(root) }
})

test('v2 units reject symlinked evidence refs', () => {
  const root = makeRepo()
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-evidence-outside-'))
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    const canary = path.join(outside, 'canary.json')
    fs.writeFileSync(canary, '{}\n')
    fs.mkdirSync(path.join(root, 'audits/evidence'), { recursive: true })
    fs.symlinkSync(canary, path.join(root, 'audits/evidence/a.json'))
    commitAll(root)
    writeV2(root, 'security', 'symlink-evidence', ['src/a.ts'], [finding('src/a.ts')], {
      hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
      evidenceRefs: ['audits/evidence/a.json'],
    })
    assert.equal(loadAuditPortfolios(root).security.length, 0)
    const invalid = auditStatusEntries(root, scan(root, { exclude: [] }))
      .find((entry) => entry.name === 'symlink-evidence')
    assert.match(invalid.invalidReason, /evidence ref|symlink|safe|regular/i)
    assert.equal(fs.readFileSync(canary, 'utf8'), '{}\n')
  } finally {
    cleanup(root)
    fs.rmSync(outside, { recursive: true, force: true })
  }
})

test('legacy security units expose scope metadata and normalize disposition to open', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    ledger(root, 'legacy-scope', ['src/a.ts'])
    const unit = loadAuditPortfolios(root).security[0]
    assert.deepEqual(unit.files, ['src/a.ts'])
    assert.equal(unit.scopeHash, scopeHash(root, ['src/a.ts']))
    assert.equal(unit.hashes, null)
    assert.deepEqual(unit.evidenceRefs, [])
    assert.equal(unit.findings[0].disposition, 'open')
  } finally { cleanup(root) }
})

test('v2 test findings omit disposition while still projecting scope and evidence refs', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, 'audits/evidence/t.json', '{}\n')
    commitAll(root)
    writeV2(root, 'test', 'test-runtime', ['src/a.ts'], [testFinding('src/a.ts')], {
      hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
      evidenceRefs: ['audits/evidence/t.json'],
    })
    const unit = loadAuditPortfolios(root).tests[0]
    assert.deepEqual(unit.files, ['src/a.ts'])
    assert.equal(unit.scopeHash, scopeHash(root, ['src/a.ts']))
    assert.deepEqual(unit.hashes, { 'src/a.ts': gitBlob(root, 'src/a.ts') })
    assert.deepEqual(unit.evidenceRefs, ['audits/evidence/t.json'])
    assert.equal(Object.hasOwn(unit.findings[0], 'disposition'), false)
  } finally { cleanup(root) }
})

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

test('v2 security and test ledgers omit slug fail closed despite name/filename fallback', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const answer = 1\n')
    commitAll(root)
    const files = ['src/a.ts']
    const scope = scopeHash(root, files)

    // Security v2: no slug, but `name` matches filename stem — must NOT fill in.
    write(root, '.atlas/audits/security-noslug.json', JSON.stringify({
      formatVersion: 2,
      format: 'atlas-audit-v2',
      domain: 'security',
      reviewState: 'complete',
      name: 'security-noslug',
      title: 'Security without slug',
      ruleset: 'fixture-security-v1',
      scanned_at: '2026-07-21',
      scope_hash: scope,
      file_count: 1,
      files,
      findings: [finding('src/a.ts', 'high')],
    }, null, 2) + '\n')

    // Test v2: no slug and no name — filename stem would be the only fallback.
    write(root, '.atlas/audits/test-noslug.json', JSON.stringify({
      formatVersion: 2,
      format: 'atlas-audit-v2',
      domain: 'test',
      reviewState: 'complete',
      title: 'Test without slug',
      ruleset: 'fixture-test-v1',
      scanned_at: '2026-07-21',
      scope_hash: scope,
      file_count: 1,
      files,
      findings: [testFinding('src/a.ts', 'blocking')],
    }, null, 2) + '\n')

    // Also treat format-only atlas-audit-v2 (no formatVersion) as a v2 candidate.
    write(root, '.atlas/audits/format-only-noslug.json', JSON.stringify({
      format: 'atlas-audit-v2',
      domain: 'security',
      reviewState: 'complete',
      name: 'format-only-noslug',
      title: 'Format-only without slug',
      ruleset: 'fixture-security-v1',
      scanned_at: '2026-07-21',
      scope_hash: scope,
      file_count: 1,
      files,
      findings: [finding('src/a.ts')],
    }, null, 2) + '\n')

    const statuses = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(statuses.length, 3)
    for (const status of statuses) {
      assert.equal(status.status, 'stale', status.name)
      assert.ok(status.invalidReason, status.name)
    }
    assert.deepEqual(loadAuditPortfolios(root), { security: [], tests: [] })
    assert.deepEqual(loadAudits(root), [])
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
