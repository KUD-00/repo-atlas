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
  const invocationsDir = path.join(dir, 'invocations')
  return {
    binPath,
    dir,
    invocations() {
      if (!fs.existsSync(invocationsDir)) return []
      return fs
        .readdirSync(invocationsDir)
        .filter((name) => name.endsWith('.json'))
        .sort()
        .map((name) => JSON.parse(fs.readFileSync(path.join(invocationsDir, name), 'utf8')))
    },
  }
}

/** Analysis runs only: the version/help/inspect probes are not review work. */
function reviewCalls(fake) {
  return fake.invocations().filter((invocation) => invocation.phase === 'review')
}

/**
 * Commits exactly one path. `git add -A` would also track the generated
 * `.atlas/review-coverage.json` the run just wrote, which the fixture policy
 * classifies as generated state — `audit check` then fails on the fixture
 * rather than on anything under test.
 */
function commitPath(root, rel, message) {
  execFileSync('git', ['add', '--', rel], { cwd: root })
  execFileSync('git', ['commit', '-qm', message], { cwd: root, env: GIT_ENV })
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

async function runInvocation(root, fake, paths, overrides = {}, requestOverrides = {}) {
  const policy = makePolicy(fake, overrides)
  const targets = paths.map((repoPath) => ({ path: repoPath, role: 'review' }))
  const result = await runAuditProviderInvocation(
    {
      command: 'audit run security',
      provider: 'grok',
      repoRoot: root,
      policy,
      targets,
      ...requestOverrides,
    },
    createGrokAuditProvider(),
  )
  return { result, policy, targets }
}

async function runAndPublish(root, fake, paths, overrides = {}, requestOverrides = {}) {
  const { result, policy, targets } = await runInvocation(
    root,
    fake,
    paths,
    overrides,
    requestOverrides,
  )
  const publication = publishAuditProviderRunObservations(root, {
    result,
    targets,
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
  // The ref names the chunk that actually reviewed the file. It is NOT the
  // file's position in the inventory divided by the batch size: placement
  // spreads look-alike siblings across batches, so `src/b.ts` here really is
  // reviewed by review:1 while `src/c.ts` shares review:0 with `src/a.ts`. This
  // assertion used to encode the positional formula and therefore asserted refs
  // that named the wrong batch.
  assert.deepEqual(
    Object.keys(result.reviewUnitByPath).sort(),
    paths,
    'every reviewed path reports the chunk that reviewed it',
  )
  for (const file of scope.files) {
    assert.deepEqual(file.receiptRefs, [`phase:review:${result.reviewUnitByPath[file.path]}`])
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

// ---------------------------------------------------------------------------
// Cross-run receipt reuse
//
// An observation is whole-unit, so before reuse a one-line fix cost a
// unit-sized re-audit: every file in the unit needed a receipt from THIS run,
// at one provider process per file. These tests hold the line on both halves of
// the bargain — unchanged files must not be re-reviewed, and anything the reuse
// key cannot prove must be.
// ---------------------------------------------------------------------------

const REUSE = { reuseUnchangedReceipts: true }
const ONE_FILE_PER_CALL = { maxBatchFiles: 1 }

test('a rescan with --reuse-unchanged reviews the changed file and carries the rest', async (t) => {
  const files = {
    'src/a.ts': makeSource(6, 'a'),
    'src/b.ts': makeSource(9, 'b'),
    'src/c.ts': makeSource(12, 'c'),
  }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)
  const paths = Object.keys(files)

  const first = await runAndPublish(root, fake, paths, ONE_FILE_PER_CALL)
  assert.equal(reviewCalls(fake).length, 3, 'the first run reviews every file')
  assert.deepEqual(first.result.carriedReceipts, [], 'nothing exists to carry yet')
  const firstObservationId = first.publication.units[0].observationId
  const firstLedger = readJson(root, '.atlas/audits/security-fixture.json')
  const firstReviewedAt = new Map(
    firstLedger.current.scope.files.map((file) => [file.path, file.reviewedAt]),
  )

  // One file changes, keeping its line count so the blob is the only thing
  // that moved — the shape of a real one-line fix. The other two do not change.
  write(root, 'src/b.ts', makeSource(9, 'b2'))
  commitPath(root, 'src/b.ts', 'edit b')

  const before = reviewCalls(fake).length
  const second = await runAndPublish(root, fake, paths, ONE_FILE_PER_CALL, REUSE)
  const rescanCalls = reviewCalls(fake).slice(before)
  assert.equal(rescanCalls.length, 1, 'a rescan costs one provider call per changed file')
  assert.deepEqual(
    rescanCalls[0].unit.kind === 'review' ? rescanCalls[0].snapshotFiles.map((f) => f.path) : [],
    ['src/b.ts'],
    'the only provider call is about the file that changed',
  )
  assert.deepEqual(
    second.result.carriedReceipts.map((carried) => carried.path),
    ['src/a.ts', 'src/c.ts'],
  )
  assert.deepEqual(Object.keys(second.result.reviewUnitByPath), ['src/b.ts'])
  for (const carried of second.result.carriedReceipts) {
    assert.equal(carried.observationId, firstObservationId)
    assert.equal(carried.slug, 'security-fixture')
  }

  // The published unit still covers every file exactly once, and says which
  // receipts it did not earn itself.
  const ledger = readJson(root, '.atlas/audits/security-fixture.json')
  const observation = ledger.current
  assert.notEqual(observation.observationId, firstObservationId, 'a changed scope is a new observation')
  assert.deepEqual(observation.scope.files.map((file) => file.path), paths)
  assert.deepEqual(observation.exactCoverage.unreviewed, [])
  const receiptOf = (repoPath) =>
    observation.scope.files.find((file) => file.path === repoPath)
  for (const repoPath of ['src/a.ts', 'src/c.ts']) {
    const receipt = receiptOf(repoPath)
    assert.deepEqual(
      receipt.receiptRefs,
      [`carried-from:${firstObservationId}`],
      'a carried receipt names the observation that proved it, and no chunk of this run',
    )
    assert.equal(
      receipt.reviewedAt,
      firstReviewedAt.get(repoPath),
      'a carried receipt keeps the timestamp of the review that actually happened',
    )
  }
  const fresh = receiptOf('src/b.ts')
  assert.deepEqual(fresh.receiptRefs, [`phase:review:${second.result.reviewUnitByPath['src/b.ts']}`])
  assert.notEqual(fresh.reviewedAt, firstReviewedAt.get('src/b.ts'))

  const parsed = parseAuditCurrentLedger(
    root,
    '.atlas/audits/security-fixture.json',
    ledger,
  )
  assert.ok(parsed.ok, `a carried-receipt ledger must validate: ${JSON.stringify(parsed)}`)

  // Downstream freshness is per-file and blob-bound, and the carried receipts
  // carry the current blob — so `audit check` stays meaningful rather than
  // being satisfied by something stale.
  execFileSync(process.execPath, [path.join(PACKAGE_ROOT, 'dist', 'cli.js'), 'audit', 'check'], {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
})

test('reuse on an untouched tree spends nothing and republishes byte-identically', async (t) => {
  const files = { 'src/a.ts': makeSource(6, 'a'), 'src/b.ts': makeSource(9, 'b') }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)
  const paths = Object.keys(files)

  await runAndPublish(root, fake, paths, ONE_FILE_PER_CALL)
  const ledgerPath = path.join(root, '.atlas', 'audits', 'security-fixture.json')
  const historyPath = path.join(root, '.atlas', 'audit-history', 'security-fixture.json')
  const before = {
    ledger: fs.readFileSync(ledgerPath, 'utf8'),
    history: fs.readFileSync(historyPath, 'utf8'),
    calls: reviewCalls(fake).length,
  }

  const second = await runAndPublish(root, fake, paths, ONE_FILE_PER_CALL, REUSE)
  assert.equal(reviewCalls(fake).length, before.calls, 'no file changed, so no review call')
  assert.equal(second.result.carriedReceipts.length, 2)
  assert.equal(second.publication.units[0].status, 'already-current')
  assert.equal(fs.readFileSync(ledgerPath, 'utf8'), before.ledger)
  assert.equal(fs.readFileSync(historyPath, 'utf8'), before.history)
})

test('a moved ruleset digest re-reviews identical bytes instead of carrying them', async (t) => {
  const files = { 'src/a.ts': makeSource(6, 'a'), 'src/b.ts': makeSource(9, 'b') }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)
  const paths = Object.keys(files)

  const first = await runAndPublish(root, fake, paths, ONE_FILE_PER_CALL)
  const rulesetDigest = first.result.receipt.ruleset.digest

  // Not one byte of source changed. The extra prompt enters the prompt digest,
  // which enters the ruleset digest — a different question about the same
  // bytes, so the old answer proves nothing.
  const before = reviewCalls(fake).length
  const second = await runInvocation(root, fake, paths, ONE_FILE_PER_CALL, {
    ...REUSE,
    extraPrompt: 'Also weigh deserialization sinks.',
  })
  assert.notEqual(second.result.receipt.ruleset.digest, rulesetDigest)
  assert.deepEqual(second.result.carriedReceipts, [], 'a moved ruleset digest carries nothing')
  assert.equal(
    reviewCalls(fake).length - before,
    2,
    'every file is reviewed again under the new ruleset',
  )
})

test('findings on a carried file keep their finding ids and their dispositions', async (t) => {
  const files = { 'src/a.ts': makeSource(8, 'a'), 'src/b.ts': makeSource(8, 'b') }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok', reviewFindings: { 'src/a.ts': [FINDING] } })
  writeProviderPolicy(root, fake)
  const paths = Object.keys(files)

  const first = await runAndPublish(root, fake, paths, ONE_FILE_PER_CALL)
  const firstObservation = readJson(root, '.atlas/audits/security-fixture.json').current
  assert.equal(firstObservation.findings.length, 1)
  const firstFinding = firstObservation.findings[0]

  // src/b.ts changes, same line count; src/a.ts and the code its finding
  // points at do not change at all.
  write(root, 'src/b.ts', makeSource(8, 'b2'))
  commitPath(root, 'src/b.ts', 'edit b')

  const before = reviewCalls(fake).length
  const second = await runAndPublish(root, fake, paths, ONE_FILE_PER_CALL, REUSE)
  assert.equal(reviewCalls(fake).length - before, 1, 'only the changed file is reviewed')
  assert.equal(
    fake.invocations().filter((invocation) => invocation.phase === 'verification').length,
    1,
    'the carried finding is not re-verified: its terminal disposition carried with it',
  )

  const observation = readJson(root, '.atlas/audits/security-fixture.json').current
  assert.equal(observation.findings.length, 1)
  const finding = observation.findings[0]
  assert.equal(
    finding.findingId,
    firstFinding.findingId,
    'content-anchored identity means an unchanged file keeps the same finding id',
  )
  assert.deepEqual(finding.identity, firstFinding.identity)
  assert.deepEqual(finding.fingerprints, firstFinding.fingerprints)
  assert.equal(finding.validation.disposition, 'reportable')
  assert.equal(finding.validation.summary, firstFinding.validation.summary)
  assert.equal(finding.title, firstFinding.title)

  // The occurrence is per-observation by construction, so it is the one id that
  // MUST move: this is a different observation of the same finding.
  const atlas = computeAtlasFingerprint({
    repositoryId: 'repo_fixture',
    domain: 'security',
    ruleId: finding.ruleId,
    anchor: finding.identity.anchor,
  })
  assert.equal(finding.occurrenceId, computeAtlasOccurrenceId(observation.observationId, atlas))
  assert.notEqual(finding.occurrenceId, firstFinding.occurrenceId)
  const receipt = observation.scope.files.find((file) => file.path === 'src/a.ts')
  assert.equal(receipt.outcome, 'findings', 'a carried file is not reported clean')
  assert.deepEqual(receipt.findingOccurrenceIds, [finding.occurrenceId])
  assert.deepEqual(receipt.receiptRefs, [`carried-from:${firstObservation.observationId}`])
  assert.equal(second.result.carriedReceipts.length, 1)
})

test('a missing or malformed prior observation is reviewed again, never assumed', async (t) => {
  const files = { 'src/a.ts': makeSource(6, 'a'), 'src/b.ts': makeSource(9, 'b') }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)
  const paths = Object.keys(files)
  const ledgerPath = path.join(root, '.atlas', 'audits', 'security-fixture.json')

  await runAndPublish(root, fake, paths, ONE_FILE_PER_CALL)
  const intact = fs.readFileSync(ledgerPath, 'utf8')

  // Control: with the ledger intact and nothing changed, both files carry. Each
  // case below differs from this one only in the ledger bytes.
  const control = await runInvocation(root, fake, paths, ONE_FILE_PER_CALL, REUSE)
  assert.equal(control.result.carriedReceipts.length, 2)

  const cases = {
    'not JSON at all': () => fs.writeFileSync(ledgerPath, '{not a ledger\n'),
    'gone': () => fs.rmSync(ledgerPath),
    'no reuse key': () => {
      const ledger = JSON.parse(intact)
      delete ledger.current.producer.effectiveConfigDigest
      fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2) + '\n')
    },
    'a receipt with no blob': () => {
      const ledger = JSON.parse(intact)
      delete ledger.current.scope.files[0].blob
      fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2) + '\n')
    },
    'a receipt that never completed': () => {
      const ledger = JSON.parse(intact)
      ledger.current.scope.files[0].status = 'not-reviewed'
      fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2) + '\n')
    },
  }
  for (const [label, damage] of Object.entries(cases)) {
    damage()
    const before = reviewCalls(fake).length
    const { result } = await runInvocation(root, fake, paths, ONE_FILE_PER_CALL, REUSE)
    assert.deepEqual(result.carriedReceipts, [], `${label}: nothing may carry`)
    assert.equal(
      reviewCalls(fake).length - before,
      2,
      `${label}: every file is reviewed again`,
    )
    fs.writeFileSync(ledgerPath, intact)
  }
})

test('reuse is off unless asked for, and the CLI flag is how it is asked for', async (t) => {
  const files = { 'src/a.ts': makeSource(6, 'a'), 'src/b.ts': makeSource(9, 'b') }
  const { root } = makeUnitRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  writeProviderPolicy(root, fake)
  const cliPath = path.join(PACKAGE_ROOT, 'dist', 'cli.js')
  const runCli = (args) =>
    execFileSync(process.execPath, [cliPath, 'audit', 'run', 'security', '--provider', 'grok',
      '--unit', 'security-fixture', ...args], { cwd: root, encoding: 'utf8' })

  runCli([])
  const afterFirst = reviewCalls(fake).length
  // .atlas/audit-providers.json batches two files per call, so a full review of
  // this two-file unit is one call and a fully carried one is none.
  assert.equal(afterFirst, 1)

  // A bare re-run re-reviews: asking for a review must never quietly return
  // receipts an earlier run earned.
  const plain = runCli([])
  assert.equal(reviewCalls(fake).length - afterFirst, 1, 'the default run reviews every file')
  assert.doesNotMatch(plain, /carried receipts/u)

  const before = reviewCalls(fake).length
  const reused = runCli(['--reuse-unchanged'])
  assert.equal(reviewCalls(fake).length - before, 0, '--reuse-unchanged carries both receipts')
  assert.match(reused, /carried receipts: 2 file\(s\) not re-reviewed \(from aobs_[0-9a-f]{24}\)/u)
})
