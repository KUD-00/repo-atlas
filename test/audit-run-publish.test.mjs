import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url))
const PACKAGE_ROOT = path.dirname(TEST_DIR)
const FAKE_GROK_SOURCE = path.join(TEST_DIR, 'fixtures', 'fake-grok', 'grok.mjs')

const providers = await import('../dist/audit-providers.js')
const grok = await import('../dist/audit-provider-grok.js')
const publish = await import('../dist/audit-run-publish.js')
const v3 = await import('../dist/audit-v3.js')
const core = await import('../dist/audit-core.js')

const { runAuditProviderInvocation, resolveAuditProviderPolicy } = providers
const { createGrokAuditProvider } = grok
const { publishAuditProviderRunObservations } = publish
const {
  computeAtlasFingerprint,
  computeAtlasFindingId,
  computeAtlasObservationId,
  computeAtlasOccurrenceId,
  computeAuditCanonicalDigest,
  computeAuditHistoryEntryDigest,
  computeAuditInventoryDigest,
  computeAuditScopeHash,
  computeExactScopeIdentityDigest,
  parseAuditCurrentLedger,
  parseAuditObservationHistory,
} = v3
const { canonicalJson } = core

function sha256Tagged(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`
}

function makeSource(lines, label) {
  const body = []
  for (let index = 1; index <= lines; index += 1) {
    body.push(`export const ${label}_${index} = ${index}`)
  }
  return body.join('\n') + '\n'
}

function write(root, rel, contents) {
  const target = path.join(root, ...rel.split('/'))
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, contents)
}

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: 'Repo Atlas Fixture',
  GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
  GIT_COMMITTER_NAME: 'Repo Atlas Fixture',
  GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
  GIT_AUTHOR_DATE: '2026-07-29T12:00:00.000Z',
  GIT_COMMITTER_DATE: '2026-07-29T12:00:00.000Z',
}

const SECURITY_DECISIONS = {
  requireDisposition: true,
  blockingActions: ['open', 'reopened'],
  drift: { findingBearing: 'blocking', clean: 'advisory', unknown: 'blocking' },
  expiry: {
    warningDays: 14,
    requiredFor: ['accepted-risk', 'separate-design'],
    acceptedRiskMaximumDays: 90,
    separateDesignMaximumDays: 90,
    falsePositiveMustBeNull: true,
    severityOverrides: [
      {
        severities: ['critical', 'high'],
        maximumDays: 30,
        minimumIndependentReviews: 2,
        reviewEvidenceRequired: true,
      },
    ],
  },
  remediation: {
    fixBlobRequired: true,
    postFixProofRequired: true,
    passingRegressionRequired: true,
    allowedRegressionKinds: ['test', 'guardrail', 'check'],
  },
  falsePositive: { reviewedBlobRequired: true, sourceEvidenceRequired: true },
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

const UNIT = {
  domain: 'security',
  slug: 'security-fixture',
  title: 'Fixture security',
  include: ['src/**'],
}

const POLICY_RULES = [
  {
    id: 'source',
    include: ['src/**'],
    rationale: 'fixture source files are security-reviewed',
    domains: ['security'],
  },
  {
    id: 'atlas-config',
    include: ['.atlas/config.json', '.atlas/review-policy.json', '.atlas/audit-providers.json'],
    rationale: 'atlas configuration is an audit control, not reviewed source',
    excluded: {
      category: 'audit-control',
      reason: 'audit check revalidates atlas configuration',
      owner: 'repo-atlas',
    },
  },
  {
    id: 'atlas-generated',
    include: [
      '.atlas/audits/**',
      '.atlas/audit-history/**',
      '.atlas/audit-decisions/**',
      '.atlas/migrations/**',
      '.atlas/review-coverage.json',
      '.atlas/.runtime/**',
    ],
    rationale: 'atlas state is generated and revalidated, not re-audited',
    excluded: {
      category: 'generated-state',
      reason: 'audit check revalidates every generated atlas artifact',
    },
  },
]

function makeUnitRepo(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-publish-repo-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  execFileSync('git', ['init', '-q'], { cwd: root })
  write(
    root,
    '.atlas/config.json',
    '{"formatVersion":1,"exclude":[],"repositoryId":"repo_fixture"}\n',
  )
  write(
    root,
    '.atlas/review-policy.json',
    JSON.stringify({
      formatVersion: 1,
      format: 'atlas-review-policy-v1',
      rules: POLICY_RULES,
      units: [UNIT],
      securityDecisions: SECURITY_DECISIONS,
    }) + '\n',
  )
  for (const [rel, contents] of Object.entries(files)) write(root, rel, contents)
  execFileSync('git', ['add', '-A'], { cwd: root })
  execFileSync('git', ['commit', '-qm', 'fixture'], { cwd: root, env: GIT_ENV })
  const revision = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: root,
    encoding: 'utf8',
  }).trim()
  return { root, revision }
}

function makeFakeGrok(t, control) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-fake-grok-'))
  const binPath = path.join(dir, 'grok.mjs')
  fs.copyFileSync(FAKE_GROK_SOURCE, binPath)
  fs.chmodSync(binPath, 0o755)
  fs.writeFileSync(path.join(dir, 'control.json'), JSON.stringify(control))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  return { binPath, dir }
}

function writeProviderPolicy(root, fake) {
  write(
    root,
    '.atlas/audit-providers.json',
    JSON.stringify({
      formatVersion: 1,
      format: 'atlas-audit-providers/v1',
      provider: 'grok',
      command: fake.binPath,
      model: 'grok-4.5',
      concurrency: 2,
      maxBatchFiles: 2,
      approvedConfigDigests: [],
    }) + '\n',
  )
}

function makePolicy(fake, overrides = {}) {
  return resolveAuditProviderPolicy({
    command: fake.binPath,
    model: 'grok-4.5',
    concurrency: 2,
    maxBatchFiles: 2,
    timeoutMs: 10_000,
    ...overrides,
  })
}

async function runAndPublish(root, fake, paths, overrides = {}) {
  const policy = makePolicy(fake, overrides)
  const targets = paths.map((repoPath) => ({ path: repoPath, role: 'review' }))
  const result = await runAuditProviderInvocation(
    {
      command: 'audit run security',
      provider: 'grok',
      repoRoot: root,
      policy,
      targets,
    },
    createGrokAuditProvider(),
  )
  const publication = publishAuditProviderRunObservations(root, {
    result,
    targets,
    providerPolicy: policy,
  })
  return { result, publication, policy, targets }
}

function readJson(root, rel) {
  return JSON.parse(fs.readFileSync(path.join(root, ...rel.split('/')), 'utf8'))
}

function listTracked(root) {
  return execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' })
    .split('\n')
    .filter((line) => line.length > 0)
}

const FINDING = {
  ruleId: 'injection-sql-cmd-path-ssrf/command-exec',
  title: 'unsanitized exec',
  severity: 'high',
  confidence: 'high',
  summary: 'user input reaches exec',
  startLine: 2,
  endLine: 3,
  detail: 'abuse path detail',
  fix: 'spawn with an argv array',
}

test('a completed run publishes a validated per-unit observation and coverage accepts it', async (t) => {
  const files = {
    'src/a.ts': makeSource(6, 'a'),
    'src/b.ts': makeSource(9, 'b'),
    'src/c.ts': makeSource(12, 'c'),
  }
  const { root, revision } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)
  const paths = Object.keys(files)
  const { result, publication } = await runAndPublish(root, fake, paths)

  assert.equal(publication.units.length, 1)
  const unitPublication = publication.units[0]
  assert.equal(unitPublication.slug, 'security-fixture')
  assert.equal(unitPublication.status, 'appended')
  assert.equal(unitPublication.findings, 0)

  const ledgerPath = '.atlas/audits/security-fixture.json'
  const historyPath = '.atlas/audit-history/security-fixture.json'
  assert.ok(fs.existsSync(path.join(root, ledgerPath)), 'current ledger published')
  assert.ok(fs.existsSync(path.join(root, historyPath)), 'history published')

  const parsedLedger = parseAuditCurrentLedger(root, ledgerPath, readJson(root, ledgerPath))
  assert.ok(parsedLedger.ok, `published ledger must validate: ${JSON.stringify(parsedLedger)}`)
  const ledger = parsedLedger.value
  assert.equal(ledger.format, 'atlas-audit-v3')
  assert.equal(ledger.formatVersion, 3)
  assert.equal(ledger.domain, 'security')
  assert.equal(ledger.slug, 'security-fixture')
  assert.equal(ledger.title, 'Fixture security')
  assert.equal(ledger.conceptSlug, 'security')
  assert.equal(ledger.currentDigest, computeAuditCanonicalDigest(ledger.current))
  assert.equal(ledger.history.path, historyPath)

  const observation = ledger.current
  assert.equal(observation.observationId, unitPublication.observationId)
  assert.equal(observation.reviewState, 'complete')
  assert.match(observation.observedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)

  const producer = observation.producer
  assert.equal(producer.kind, 'grok-cli')
  assert.equal(producer.name, 'grok')
  assert.equal(producer.version, '0.2.111')
  assert.equal(producer.adapter, 'repo-atlas/grok-v1')
  assert.equal(producer.adapterVersion, '0.1.0')
  assert.equal(producer.runId, result.invocationId)
  assert.equal(producer.identityBasis, 'ruleset')
  assert.equal(producer.identityDigest, result.receipt.ruleset.digest)
  assert.deepEqual(producer.ruleset, result.receipt.ruleset)
  assert.deepEqual(producer.prompt, result.receipt.prompt)
  assert.equal(producer.effectiveConfigDigest, result.receipt.effectiveConfigDigest)
  assert.equal(producer.environmentPolicyDigest, result.receipt.environmentPolicyDigest)
  assert.equal(producer.transcriptDigest, result.receipt.transcriptDigest)

  const target = observation.target
  assert.equal(target.kind, 'git-worktree')
  assert.equal(target.repositoryId, 'repo_fixture')
  assert.equal(target.revision, revision)
  assert.equal(target.dirty, false)
  assert.equal(target.identityBasis, 'snapshot')
  assert.equal(target.snapshotDigest, result.receipt.snapshotManifestDigest)
  assert.equal(target.identityDigest, result.receipt.snapshotManifestDigest)

  const scope = observation.scope
  assert.equal(scope.mode, 'unit')
  assert.equal(scope.identityBasis, 'exact-inventory')
  assert.deepEqual(scope.includePaths, ['src/**'])
  assert.deepEqual(scope.excludePaths, [])
  assert.equal(scope.fileCount, 3)
  assert.deepEqual(
    scope.files.map((file) => file.path),
    paths,
  )
  for (const file of scope.files) {
    assert.equal(file.status, 'reviewed')
    assert.equal(file.outcome, 'clean')
    assert.equal(file.reviewedBy, 'grok-4.5 via grok-cli')
    assert.equal(file.reviewedAtPrecision, 'timestamp')
    assert.equal(file.ruleset, 'atlas-security-v3')
    assert.deepEqual(file.findingOccurrenceIds, [])
    assert.match(file.reviewedAt, /^\d{4}-\d{2}-\d{2}T/)
  }
  const batchOf = (repoPath) => `phase:review:review:${Math.floor(paths.indexOf(repoPath) / 2)}`
  for (const file of scope.files) {
    assert.deepEqual(file.receiptRefs, [batchOf(file.path)])
  }
  assert.equal(
    scope.inventoryDigest,
    computeAuditInventoryDigest(scope.files),
    'scope inventory digest seals the file receipts',
  )
  assert.equal(
    scope.scopeHash,
    computeAuditScopeHash({
      mode: 'unit',
      includePaths: ['src/**'],
      excludePaths: [],
      inventoryDigest: scope.inventoryDigest,
    }),
  )
  assert.equal(
    scope.identityDigest,
    computeExactScopeIdentityDigest({
      mode: 'unit',
      includePaths: ['src/**'],
      excludePaths: [],
      files: scope.files.map((file) => ({ path: file.path, blob: file.blob })),
    }),
  )
  assert.equal(
    observation.observationId,
    computeAtlasObservationId({
      slug: 'security-fixture',
      adapter: 'repo-atlas/grok-v1',
      runId: result.invocationId,
      producerIdentityDigest: result.receipt.ruleset.digest,
      targetId: 'grok-worktree/security-fixture',
      targetIdentityDigest: result.receipt.snapshotManifestDigest,
      scopeIdentityDigest: scope.identityDigest,
    }),
    'observation identity binds slug, run, producer, target, and scope digests',
  )

  assert.deepEqual(observation.exactCoverage, {
    completeness: 'complete',
    basis: 'full-read-receipts',
    reviewedFileCount: 3,
    unreviewed: [],
  })
  assert.equal(observation.semanticCoverage.completeness, 'unknown')
  assert.deepEqual(observation.findings, [])
  assert.deepEqual(observation.sourceArtifacts, [])

  const parsedHistory = parseAuditObservationHistory(root, historyPath, readJson(root, historyPath))
  assert.ok(parsedHistory.ok, 'published history must validate')
  const history = parsedHistory.value
  assert.equal(history.entries.length, 1)
  const entry = history.entries[0]
  assert.equal(entry.observationId, observation.observationId)
  assert.equal(entry.previousEntryDigest, null)
  assert.equal(entry.observationDigest, ledger.currentDigest)
  assert.equal(entry.entryDigest, ledger.history.entryDigest)
  assert.equal(entry.entryDigest, computeAuditHistoryEntryDigest({
    observationId: entry.observationId,
    observationDigest: entry.observationDigest,
    previousEntryDigest: entry.previousEntryDigest,
    observation: entry.observation,
  }))

  // Raw transcripts and run receipts stay clone-local; only digests publish.
  assert.ok(fs.existsSync(path.join(root, '.atlas', 'review-coverage.json')), 'coverage is regenerated')
  const atlasFiles = []
  const walk = (dir, rel) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const childRel = rel ? `${rel}/${entry.name}` : entry.name
      if (entry.isDirectory()) walk(path.join(dir, entry.name), childRel)
      else atlasFiles.push(childRel)
    }
  }
  walk(path.join(root, '.atlas'), '')
  const publishedBytes = atlasFiles
    .filter((rel) => !rel.startsWith('.runtime/'))
    .map((rel) => fs.readFileSync(path.join(root, '.atlas', ...rel.split('/')), 'utf8'))
    .join('\n')
  for (const marker of ['fake grok system prompt', 'Reading the listed files.']) {
    assert.ok(!publishedBytes.includes(marker), `tracked state must not contain transcript bytes: ${marker}`)
  }
  for (const chunk of result.receipt.chunks) {
    for (const sessionId of chunk.sessionIds) {
      assert.ok(!publishedBytes.includes(sessionId), 'session ids never publish')
    }
  }

  const check = execFileSync(
    process.execPath,
    [path.join(PACKAGE_ROOT, 'dist', 'cli.js'), 'audit', 'check'],
    { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  )
  assert.match(check, /audit check/i)
})

test('re-publishing an unchanged run is a byte-identical no-op', async (t) => {
  const files = { 'src/a.ts': makeSource(6, 'a'), 'src/b.ts': makeSource(9, 'b') }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)
  const paths = Object.keys(files)

  const first = await runAndPublish(root, fake, paths)
  assert.equal(first.publication.units[0].status, 'appended')
  const ledgerPath = path.join(root, '.atlas', 'audits', 'security-fixture.json')
  const historyPath = path.join(root, '.atlas', 'audit-history', 'security-fixture.json')
  const coveragePath = path.join(root, '.atlas', 'review-coverage.json')
  const before = {
    ledger: fs.readFileSync(ledgerPath, 'utf8'),
    history: fs.readFileSync(historyPath, 'utf8'),
    coverage: fs.readFileSync(coveragePath, 'utf8'),
  }

  const second = await runAndPublish(root, fake, paths)
  assert.equal(second.result.invocationId, first.result.invocationId, 'unchanged inputs derive the same run id')
  assert.equal(second.publication.units[0].status, 'already-current')
  assert.equal(fs.readFileSync(ledgerPath, 'utf8'), before.ledger)
  assert.equal(fs.readFileSync(historyPath, 'utf8'), before.history)
  assert.equal(fs.readFileSync(coveragePath, 'utf8'), before.coverage)
  const history = readJson(root, '.atlas/audit-history/security-fixture.json')
  assert.equal(history.entries.length, 1, 'no duplicate history entry')
})

test('a divergent pre-existing observation with the same identity is rejected before any mutation', async (t) => {
  const files = { 'src/a.ts': makeSource(6, 'a'), 'src/b.ts': makeSource(9, 'b') }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)
  const paths = Object.keys(files)
  const first = await runAndPublish(root, fake, paths)

  const ledgerPath = path.join(root, '.atlas', 'audits', 'security-fixture.json')
  const tampered = readJson(root, '.atlas/audits/security-fixture.json')
  tampered.current.semanticCoverage.completeness = 'partial'
  fs.writeFileSync(ledgerPath, JSON.stringify(tampered, null, 2) + '\n')
  const beforeHistory = fs.readFileSync(
    path.join(root, '.atlas', 'audit-history', 'security-fixture.json'),
    'utf8',
  )

  assert.throws(
    () =>
      publishAuditProviderRunObservations(root, {
        result: first.result,
        targets: first.targets,
        providerPolicy: first.policy,
      }),
    /digest|identity|no longer matches/i,
    'same observationId with a different digest must fail closed',
  )
  assert.equal(
    fs.readFileSync(path.join(root, '.atlas', 'audit-history', 'security-fixture.json'), 'utf8'),
    beforeHistory,
    'a rejected publication never mutates history',
  )
})

test('reportable findings publish with deterministic identities and full provenance', async (t) => {
  const files = { 'src/a.ts': makeSource(8, 'a'), 'src/b.ts': makeSource(8, 'b') }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok', reviewFindings: { 'src/a.ts': [FINDING] } })
  writeProviderPolicy(root, fake)
  const paths = Object.keys(files)
  const { result, publication } = await runAndPublish(root, fake, paths)
  assert.equal(publication.units[0].findings, 1)

  const ledger = readJson(root, '.atlas/audits/security-fixture.json')
  const observation = ledger.current
  assert.equal(observation.findings.length, 1)
  const finding = observation.findings[0]
  const candidate = result.findings[0]
  assert.equal(candidate.disposition, 'reportable')

  const atlas = computeAtlasFingerprint({
    repositoryId: 'repo_fixture',
    domain: 'security',
    ruleId: candidate.ruleId,
    anchor: candidate.fingerprint,
  })
  assert.equal(finding.findingId, computeAtlasFindingId(atlas))
  assert.equal(finding.occurrenceId, computeAtlasOccurrenceId(observation.observationId, atlas))
  assert.equal(finding.decisionLedger, 'security-fixture')
  assert.equal(finding.ruleId, candidate.ruleId)
  assert.deepEqual(finding.identity, { anchor: candidate.fingerprint })
  assert.deepEqual(finding.fingerprints, [
    { scheme: 'atlas/v1', value: atlas, role: 'canonical' },
    { scheme: 'grok-cli/v1', value: candidate.fingerprint, role: 'producer' },
  ])
  assert.equal(finding.title, candidate.title)
  assert.equal(finding.severity.level, 'high')
  assert.equal(finding.confidence.level, 'high')
  assert.deepEqual(finding.taxonomy, { category: 'injection-sql-cmd-path-ssrf' })
  assert.deepEqual(finding.locations, [{ path: 'src/a.ts', startLine: 2, endLine: 3 }])
  assert.equal(finding.remediation, candidate.fix)
  assert.equal(finding.validation.disposition, 'reportable')
  assert.equal(finding.validation.summary, candidate.dispositionRationale)
  assert.equal(finding.attackPath.summary, candidate.detail)
  assert.deepEqual(finding.provenance, {
    source: 'repo-atlas/grok-v1',
    candidateId: candidate.fingerprint,
  })

  const receiptA = observation.scope.files.find((file) => file.path === 'src/a.ts')
  assert.equal(receiptA.outcome, 'findings')
  assert.deepEqual(receiptA.findingOccurrenceIds, [finding.occurrenceId])
  assert.deepEqual(receiptA.receiptRefs, [
    'phase:review:review:0',
    'phase:verification:verification:0',
  ])
  const receiptB = observation.scope.files.find((file) => file.path === 'src/b.ts')
  assert.equal(receiptB.outcome, 'clean')
  assert.deepEqual(receiptB.findingOccurrenceIds, [])

  const parsedLedger = parseAuditCurrentLedger(
    root,
    '.atlas/audits/security-fixture.json',
    ledger,
  )
  assert.ok(parsedLedger.ok, 'a finding-bearing ledger must validate')
})

test('non-reportable dispositions never publish as occurrences', async (t) => {
  const files = { 'src/a.ts': makeSource(8, 'a') }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, {
    mode: 'ok',
    reviewFindings: { 'src/a.ts': [FINDING] },
    disposition: 'suppressed',
  })
  writeProviderPolicy(root, fake)
  const { publication } = await runAndPublish(root, fake, ['src/a.ts'])
  assert.equal(publication.units[0].findings, 0)
  const ledger = readJson(root, '.atlas/audits/security-fixture.json')
  assert.deepEqual(ledger.current.findings, [])
  assert.equal(ledger.current.scope.files[0].outcome, 'clean')
  assert.deepEqual(ledger.current.scope.files[0].findingOccurrenceIds, [])
})

test('a dirty worktree run publishes after registering audited bytes as git objects', async (t) => {
  const { root } = makeUnitRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  write(root, 'src/a.ts', makeSource(7, 'a2'))
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)
  const { result, publication } = await runAndPublish(root, fake, ['src/a.ts'])
  assert.equal(publication.units[0].status, 'appended')

  const ledger = readJson(root, '.atlas/audits/security-fixture.json')
  assert.equal(ledger.current.target.dirty, true)
  const receipt = ledger.current.scope.files[0]
  const parsedLedger = parseAuditCurrentLedger(
    root,
    '.atlas/audits/security-fixture.json',
    ledger,
  )
  assert.ok(parsedLedger.ok, 'a dirty-run ledger must validate once audited bytes are registered')
  const objectId = receipt.blob.split(':')[1]
  const stored = execFileSync('git', ['cat-file', 'blob', objectId], {
    cwd: root,
    encoding: 'utf8',
  })
  assert.equal(stored, makeSource(7, 'a2'), 'the registered object holds exactly the audited bytes')
  assert.equal(result.files[0].blob, receipt.blob)
})

test('the CLI publishes through audit run security and re-runs are already-current', async (t) => {
  const files = { 'src/a.ts': makeSource(6, 'a'), 'src/b.ts': makeSource(9, 'b') }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)
  const cliPath = path.join(PACKAGE_ROOT, 'dist', 'cli.js')

  const first = execFileSync(
    process.execPath,
    [cliPath, 'audit', 'run', 'security', '--provider', 'grok', '--unit', 'security-fixture'],
    { cwd: root, encoding: 'utf8' },
  )
  assert.match(first, /audit run security: completed/)
  assert.match(first, /published security-fixture: appended/)
  assert.match(first, /coverage:/)
  assert.ok(fs.existsSync(path.join(root, '.atlas', 'audits', 'security-fixture.json')))

  const second = execFileSync(
    process.execPath,
    [cliPath, 'audit', 'run', 'security', '--provider', 'grok', '--unit', 'security-fixture'],
    { cwd: root, encoding: 'utf8' },
  )
  assert.match(second, /published security-fixture: already-current/)

  execFileSync(process.execPath, [cliPath, 'audit', 'check'], {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
})

test('publishing a subset of a unit is refused, because it would delete the rest of its evidence', async (t) => {
  // Both files belong to security-fixture, but only one is reviewed. A unit
  // ledger's `current` is rebuilt from the reviewed set and freshness reads
  // `current` alone, so publishing this would leave src/b.ts with no evidence
  // at all — reported later as a plain coverage gap, with nothing pointing at
  // the run that caused it.
  const files = {
    'src/a.ts': makeSource(6, 'a'),
    'src/b.ts': makeSource(9, 'b'),
  }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)

  await assert.rejects(
    runAndPublish(root, fake, ['src/a.ts']),
    (error) =>
      error instanceof Error &&
      /cannot publish a partial scope for security-fixture/u.test(error.message) &&
      /src\/b\.ts/u.test(error.message) &&
      /--unit security-fixture/u.test(error.message),
  )

  assert.equal(
    fs.existsSync(path.join(root, '.atlas', 'audits', 'security-fixture.json')),
    false,
    'the refusal happens before any ledger is written',
  )
})
