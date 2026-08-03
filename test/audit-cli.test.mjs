import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { scopeHash } from './helpers.mjs'

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url))
const CLI = path.join(TEST_DIR, '..', 'dist', 'cli.js')
const FAKE_GROK_SOURCE = path.join(TEST_DIR, 'fixtures', 'fake-grok', 'grok.mjs')
const CODEX_FIXTURE_ROOT = path.join(TEST_DIR, 'fixtures', 'codex-security')
const RELAYOS_SECURITY_FIXTURES = path.join(TEST_DIR, 'fixtures', 'relayos-security')
const RELAYOS_ROOT_FIXTURES = path.join(TEST_DIR, 'fixtures', 'relayos-root-audits')

const v3 = await import('../dist/audit-v3.js')
const core = await import('../dist/audit-core.js')
const decisions = await import('../dist/audit-decisions.js')

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
const { canonicalJson } = core
const { computeAuditFindingComparisonId } = decisions

const REPOSITORY_ID = 'repo_audit_cli_fixture'
const UNIT_SLUG = 'security-cli-fixture'
const RULESET_ID = 'fixture-security-v3'
const RULESET_DIGEST = `sha256:${'1'.repeat(64)}`
const TARGET_DIGEST = `sha256:${'2'.repeat(64)}`
const POLICY_DIGEST = `sha256:${'3'.repeat(64)}`
const ACTOR = 'identity:reviewer@example.invalid'
const STAMP = '2026-07-29T00:00:00.000Z'

// ---------------------------------------------------------------------------
// repo + CLI helpers
// ---------------------------------------------------------------------------

function write(root, rel, contents) {
  const target = path.join(root, ...rel.split('/'))
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, contents)
}

function writeJson(root, rel, value) {
  write(root, rel, `${JSON.stringify(value, null, 2)}\n`)
}

function commit(root, message = 'fixture') {
  execFileSync('git', ['add', '-A'], { cwd: root })
  execFileSync('git', ['commit', '-qm', message], {
    cwd: root,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Repo Atlas Fixture',
      GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
      GIT_COMMITTER_NAME: 'Repo Atlas Fixture',
      GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      GIT_AUTHOR_DATE: '2026-07-30T03:56:24.000Z',
      GIT_COMMITTER_DATE: '2026-07-30T03:56:24.000Z',
    },
  })
}

function head(root) {
  return execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: root,
    encoding: 'utf8',
  }).trim()
}

function gitBlob(root, file) {
  return execFileSync('git', ['hash-object', '--', file], {
    cwd: root,
    encoding: 'utf8',
  }).trim()
}

function makeRepo(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-audit-cli-'))
  execFileSync('git', ['init', '-q'], { cwd: root })
  execFileSync('git', ['config', 'user.email', 'repo-atlas-test@example.invalid'], { cwd: root })
  execFileSync('git', ['config', 'user.name', 'repo-atlas test'], { cwd: root })
  fs.mkdirSync(path.join(root, '.atlas', 'audits'), { recursive: true })
  writeJson(root, '.atlas/config.json', {
    formatVersion: 1,
    exclude: [],
    repositoryId: REPOSITORY_ID,
  })
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return root
}

function runCli(root, args, env = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: root,
    encoding: 'utf8',
    timeout: 120_000,
    env: { ...process.env, ...env },
  })
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
    acceptedRulesets: [RULESET_ID],
  }
}

function reviewPolicy() {
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
        include: ['.atlas/review-coverage.json'],
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
          reason: 'fixture configuration is outside this fixture',
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

function writeReviewPolicy(root) {
  writeJson(root, '.atlas/review-policy.json', reviewPolicy())
}

/** A committed src/a.ts + review policy; coverage state starts unwritten. */
function makeCoverageRepo(t) {
  const root = makeRepo(t)
  write(root, 'src/a.ts', 'export const a = 1\n')
  commit(root)
  writeReviewPolicy(root)
  return root
}

// ---------------------------------------------------------------------------
// V3 publication fixture (mirrors test/audits.test.mjs publishExactV3)
// ---------------------------------------------------------------------------

function publishV3(root, { slug = UNIT_SLUG, instance = 'a', runId = 'audit-cli-fixture-run' } = {}) {
  const rawBlob = gitBlob(root, 'src/a.ts')
  const blob = `git-sha${rawBlob.length === 40 ? '1' : '256'}:${rawBlob}`
  const scopeIdentityDigest = computeExactScopeIdentityDigest({
    mode: 'unit',
    includePaths: ['src/**'],
    excludePaths: [],
    files: [{ path: 'src/a.ts', blob }],
  })
  const fingerprint = computeAtlasFingerprint({
    repositoryId: REPOSITORY_ID,
    domain: 'security',
    ruleId: 'authorization/audit-cli-fixture',
    anchor: 'audit/cli-fixture',
    instance,
  })
  const findingId = computeAtlasFindingId(fingerprint)
  const observationId = computeAtlasObservationId({
    slug,
    adapter: 'repo-atlas/manual-v1',
    runId,
    producerIdentityDigest: RULESET_DIGEST,
    targetId: 'audit-cli-fixture-target',
    targetIdentityDigest: TARGET_DIGEST,
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
    ruleset: RULESET_ID,
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
      runId,
      identityDigest: RULESET_DIGEST,
      identityBasis: 'ruleset',
      ruleset: { id: RULESET_ID, digest: RULESET_DIGEST },
    },
    target: {
      kind: 'directory-snapshot',
      repositoryId: REPOSITORY_ID,
      targetId: 'audit-cli-fixture-target',
      identityDigest: TARGET_DIGEST,
      identityBasis: 'snapshot',
      snapshotDigest: TARGET_DIGEST,
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
      ruleId: 'authorization/audit-cli-fixture',
      identity: { anchor: 'audit/cli-fixture', instance },
      fingerprints: [{ scheme: 'atlas/v1', value: fingerprint, role: 'canonical' }],
      title: 'CLI fixture finding',
      summary: 'The fixture has a boundary issue.',
      severity: { level: 'medium' },
      confidence: { level: 'high', rationale: 'The source receipt is exact.' },
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
    { slug, title: 'CLI Fixture', conceptSlug: 'runtime' },
  )
  publishAuditObservation(root, prepared.ledger)
  return { slug, blob, findingId, occurrenceId, observationId }
}

// ---------------------------------------------------------------------------
// decision event fixtures
// ---------------------------------------------------------------------------

function openEvent(fixture, overrides = {}) {
  return {
    type: 'finding-disposition',
    findingId: fixture.findingId,
    occurrenceId: fixture.occurrenceId,
    action: 'open',
    actor: ACTOR,
    owner: 'cli-fixture',
    reason: 'A bounded CLI fixture decision reason.',
    createdAt: STAMP,
    createdAtBasis: 'recorded',
    reviewContext: {
      observationId: fixture.observationId,
      bindings: [{ path: 'src/a.ts', blob: fixture.blob }],
      ruleset: { id: RULESET_ID, digest: RULESET_DIGEST },
      policyDigest: POLICY_DIGEST,
    },
    evidenceRefs: [],
    proofs: [],
    reviews: [],
    ...overrides,
  }
}

function retirementBase(fixture, overrides = {}) {
  return {
    type: 'scope-retirement',
    decisionLedger: fixture.slug,
    path: 'src/a.ts',
    blob: fixture.blob,
    reason: 'staged-deletion',
    retiredAt: STAMP,
    retiredAtPrecision: 'timestamp',
    actor: ACTOR,
    createdAt: STAMP,
    createdAtBasis: 'recorded',
    historyProof: {
      slug: fixture.slug,
      observationId: fixture.observationId,
      path: 'src/a.ts',
      blob: fixture.blob,
    },
    evidenceRefs: [],
    ...overrides,
  }
}

function stagedRetirementEvent(fixture, headRevision) {
  return retirementBase(fixture, {
    absenceProof: {
      kind: 'worktree-index-absence',
      headRevision,
      headBinding: { path: 'src/a.ts', blob: fixture.blob },
      indexState: 'absent',
      worktreeState: 'absent',
    },
  })
}

function finalizeRetirementEvent(fixture, headRevision, supersedesEventId) {
  return retirementBase(fixture, {
    reason: 'deleted',
    deletionCommit: headRevision,
    deletionProof: {
      kind: 'git-deletion',
      parentRevision: 'a'.repeat(40),
      parentBindings: [{ path: 'src/a.ts', blob: fixture.blob }],
      absentPaths: ['src/a.ts'],
    },
    supersedesEventId,
  })
}

function reconcileEvent(ledgerSlug, before, after, overrides = {}) {
  return {
    type: 'finding-reconciliation',
    comparisonId: computeAuditFindingComparisonId({
      beforeObservationIds: [before.observationId],
      afterObservationIds: [after.observationId],
    }),
    decisionLedger: ledgerSlug,
    beforeOccurrenceIds: [before.occurrenceId],
    afterOccurrenceIds: [after.occurrenceId],
    outcome: 'equivalent',
    confidence: 'high',
    reason: 'The CLI fixture occurrences track the same root cause.',
    source: { kind: 'manual', name: 'cli-fixture' },
    createdAt: STAMP,
    createdAtBasis: 'recorded',
    evidenceRefs: [],
    ...overrides,
  }
}

function writeEvent(root, name, event) {
  const file = path.join(root, name)
  fs.writeFileSync(file, `${JSON.stringify(event, null, 2)}\n`)
  return file
}

function decisionLedger(root, slug) {
  const file = path.join(root, '.atlas', 'audit-decisions', `${slug}.json`)
  if (!fs.existsSync(file)) return null
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

// ---------------------------------------------------------------------------
// fake grok (records every invocation; never touches the network)
// ---------------------------------------------------------------------------

function makeFakeGrok(t, control = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-cli-fake-grok-'))
  for (const name of ['grok', 'grok.mjs']) {
    fs.copyFileSync(FAKE_GROK_SOURCE, path.join(dir, name))
    fs.chmodSync(path.join(dir, name), 0o755)
  }
  fs.writeFileSync(path.join(dir, 'control.json'), JSON.stringify(control))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const invocationsDir = path.join(dir, 'invocations')
  return {
    dir,
    binPath: path.join(dir, 'grok.mjs'),
    env: { PATH: `${dir}${path.delimiter}${process.env.PATH}` },
    invocations() {
      if (!fs.existsSync(invocationsDir)) return []
      return fs.readdirSync(invocationsDir).filter((name) => name.endsWith('.json'))
    },
  }
}

function writeProviderPolicy(root, fake) {
  writeJson(root, '.atlas/audit-providers.json', {
    formatVersion: 1,
    format: 'atlas-audit-providers/v1',
    provider: 'grok',
    command: fake.binPath,
    model: 'grok-4.5',
    concurrency: 1,
    maxBatchFiles: 4,
    timeoutMs: 30_000,
  })
}

// ---------------------------------------------------------------------------
// Codex Security bundle fixture
// ---------------------------------------------------------------------------

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function materializeCodexBundle(t, name = 'clean-bundle.json') {
  const recipe = JSON.parse(
    fs.readFileSync(path.join(CODEX_FIXTURE_ROOT, name), 'utf8'),
  )
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-cli-codex-bundle-'))
  for (const [repoPath, contents] of Object.entries(recipe.files ?? {})) {
    write(root, repoPath, contents)
  }
  writeJson(root, 'findings.json', recipe.findings)
  writeJson(root, 'coverage.json', recipe.coverage)
  const manifest = structuredClone(recipe.manifest)
  for (const artifact of manifest.scan.artifacts) {
    const artifactPath = path.join(root, ...artifact.path.split('/'))
    artifact.sha256 = sha256(fs.readFileSync(artifactPath))
  }
  writeJson(root, 'scan-manifest.json', manifest)
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return root
}

// ---------------------------------------------------------------------------
// RelayOS migration fixtures (mirror the Task 6 seam tests)
// ---------------------------------------------------------------------------

const RELAYOS_SOURCE_ROOT = 'audits/security-scan'
const RELAYOS_SOURCE_FILES = [
  'ledger.json',
  'candidates.v1.json',
  'dispositions.v1.json',
  'phase-zero-provenance.v1.json',
]
const RELAYOS_SUCCESSOR =
  'apps/daemon/src/inference-relay/secure-outbound-transport.ts'

function makeRelayOSSecurityRepo(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-cli-relayos-security-'))
  execFileSync('git', ['init', '-q'], { cwd: root })
  writeJson(root, '.atlas/config.json', {
    formatVersion: 1,
    exclude: [],
    repositoryId: 'repo_relayos_migration_fixture',
  })
  writeJson(root, '.atlas/review-policy.json', {
    formatVersion: 1,
    format: 'relayos-review-policy-v1',
    rules: [],
    units: [
      {
        domain: 'security',
        slug: 'security-fixture-github',
        title: 'Fixture GitHub',
        include: ['.github/**'],
      },
      {
        domain: 'security',
        slug: 'security-fixture-apps',
        title: 'Fixture applications',
        include: ['apps/**'],
      },
      {
        domain: 'security',
        slug: 'security-fixture-packages',
        title: 'Fixture packages',
        include: ['packages/**'],
      },
    ],
  })
  for (const name of RELAYOS_SOURCE_FILES) {
    write(
      root,
      `${RELAYOS_SOURCE_ROOT}/${name}`,
      fs.readFileSync(path.join(RELAYOS_SECURITY_FIXTURES, name)),
    )
  }
  write(root, RELAYOS_SUCCESSOR, 'export const secureOutboundTransport = true\n')
  commit(root)
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return { root, revision: head(root) }
}

const ROOT_AUDIT_DESIGN_FILES = [
  'README.md',
  'findings.md',
  'ledger.json',
  'check.mjs',
  'to-atlas-ledger.mjs',
]
const ROOT_AUDIT_REPORT_FIXTURES = new Map([
  [
    'audits/atlas-suspicion-audit/2026-07-05-report.md',
    'historical/atlas-suspicion-audit/2026-07-05-report.md',
  ],
  [
    'audits/atlas-suspicion-audit/2026-07-05-solutions.md',
    'historical/atlas-suspicion-audit/2026-07-05-solutions.md',
  ],
  [
    'audits/mobile-responsive-audit/findings.md',
    'historical/mobile-responsive-audit/findings.md',
  ],
])

function makeRelayOSRootAuditsRepo(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-cli-relayos-roots-'))
  execFileSync('git', ['init', '-q'], { cwd: root })
  writeJson(root, '.atlas/config.json', {
    formatVersion: 1,
    exclude: [],
    repositoryId: 'repo_relayos_root_audits_fixture',
  })
  for (const name of ROOT_AUDIT_DESIGN_FILES) {
    write(
      root,
      `audits/design-scan/${name}`,
      fs.readFileSync(path.join(RELAYOS_ROOT_FIXTURES, 'design-scan', name)),
    )
  }
  for (const [report, fixture] of ROOT_AUDIT_REPORT_FIXTURES) {
    write(root, report, fs.readFileSync(path.join(RELAYOS_ROOT_FIXTURES, fixture)))
  }
  write(
    root,
    'audits/security-egress-boundaries.json',
    fs.readFileSync(path.join(RELAYOS_ROOT_FIXTURES, 'security-egress-boundaries.json')),
  )
  write(
    root,
    '.atlas/audits/design-fixture-layer.json',
    fs.readFileSync(path.join(RELAYOS_ROOT_FIXTURES, 'design-v2/design-fixture-layer.json')),
  )
  write(
    root,
    '.atlas/audits/design-fixture-other.json',
    fs.readFileSync(path.join(RELAYOS_ROOT_FIXTURES, 'design-v2/design-fixture-other.json')),
  )
  write(
    root,
    '.atlas/policies/security-egress-boundaries.json',
    fs.readFileSync(path.join(RELAYOS_ROOT_FIXTURES, 'security-egress-boundaries.json')),
  )
  commit(root)
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return { root, revision: head(root) }
}

// ---------------------------------------------------------------------------
// dispatch, help, and usage policy
// ---------------------------------------------------------------------------

test('audit with no verb or help prints the hierarchical usage and exits 0', (t) => {
  const root = makeRepo(t)
  for (const args of [['audit'], ['audit', 'help'], ['audit', '--help']]) {
    const result = runCli(root, args)
    assert.equal(result.status, 0, `args ${args.join(' ')}: ${result.stderr}`)
    assert.match(result.stdout, /usage: repo-atlas audit /u)
    assert.match(result.stdout, /audit check/u)
    assert.match(result.stdout, /audit run security/u)
  }
})

test('unknown audit verbs and flags exit nonzero with usage on stderr', (t) => {
  const root = makeRepo(t)
  const cases = [
    ['audit', 'bogus'],
    ['audit', 'check', '--bogus'],
    ['audit', 'check', 'extra-positional'],
    ['audit', 'status', '--allow-incomplete'],
    ['audit', 'coverage'],
    ['audit', 'coverage', 'bogus'],
    ['audit', 'coverage', 'check', '--apply'],
    ['audit', 'run'],
    ['audit', 'run', 'bogus'],
    ['audit', 'run', 'security'],
    ['audit', 'run', 'security', '--provider', 'bogus'],
    ['audit', 'import'],
    ['audit', 'import', 'bogus'],
    ['audit', 'migrate'],
    ['audit', 'migrate', 'bogus'],
    ['audit', 'decision'],
    ['audit', 'decision', 'set', 'atf_only'],
    ['audit', 'retire'],
    ['audit', 'localization'],
    ['audit', 'localization', 'bogus'],
  ]
  for (const args of cases) {
    const result = runCli(root, args)
    assert.notEqual(result.status, 0, `args ${args.join(' ')} must fail`)
    assert.match(
      result.stderr,
      /usage: repo-atlas audit/u,
      `args ${args.join(' ')} must print usage on stderr`,
    )
    assert.equal(result.stdout, '', `args ${args.join(' ')} must not write stdout`)
  }
})

test('top-level help lists the hierarchical audit surface', (t) => {
  const root = makeRepo(t)
  const result = runCli(root, [])
  assert.equal(result.status, 0)
  assert.match(result.stdout, /audit <verb>/u)
  assert.match(result.stdout, /audit-stamp/u)
})

// ---------------------------------------------------------------------------
// audit coverage check / update
// ---------------------------------------------------------------------------

test('audit coverage update writes canonical bytes and coverage check byte-compares', (t) => {
  const root = makeCoverageRepo(t)
  const fake = makeFakeGrok(t)

  const missing = runCli(root, ['audit', 'coverage', 'check', '--allow-incomplete'], fake.env)
  assert.notEqual(missing.status, 0, 'no committed coverage report must fail check')

  const updated = runCli(root, ['audit', 'coverage', 'update', '--allow-incomplete'], fake.env)
  assert.equal(updated.status, 0, updated.stderr)
  assert.match(updated.stdout, /review-coverage\.json/u)
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'review-coverage.json')), true)

  const checked = runCli(root, ['audit', 'coverage', 'check', '--allow-incomplete'], fake.env)
  assert.equal(checked.status, 0, checked.stderr)
  assert.match(checked.stdout, /current/u)

  const strict = runCli(root, ['audit', 'coverage', 'check'], fake.env)
  assert.notEqual(strict.status, 0, 'honest incomplete verdict fails without --allow-incomplete')

  fs.appendFileSync(path.join(root, '.atlas', 'review-coverage.json'), ' \n')
  const drifted = runCli(root, ['audit', 'coverage', 'check', '--allow-incomplete'], fake.env)
  assert.notEqual(drifted.status, 0, 'byte drift must fail coverage check')

  assert.deepEqual(fake.invocations(), [], 'coverage commands must never launch a provider')
})

// ---------------------------------------------------------------------------
// audit check
// ---------------------------------------------------------------------------

test('audit check exits 0 only for complete or honestly incomplete state', (t) => {
  const root = makeCoverageRepo(t)
  const fake = makeFakeGrok(t)
  assert.equal(
    runCli(root, ['audit', 'coverage', 'update', '--allow-incomplete']).status,
    0,
  )

  const strict = runCli(root, ['audit', 'check'], fake.env)
  assert.notEqual(strict.status, 0, 'incomplete evidence fails without --allow-incomplete')

  const allowed = runCli(root, ['audit', 'check', '--allow-incomplete'], fake.env)
  assert.equal(allowed.status, 0, allowed.stderr)
  assert.match(allowed.stdout, /--allow-incomplete/u)

  write(root, '.atlas/audits/broken.json', '{malformed ledger\n')
  const invalid = runCli(root, ['audit', 'check', '--allow-incomplete'], fake.env)
  assert.notEqual(invalid.status, 0, 'structural invalidity always fails')
  assert.match(invalid.stdout + invalid.stderr, /broken\.json/u)

  assert.deepEqual(fake.invocations(), [], 'audit check must never launch a provider')
})

test('audit check fails on an invalid review policy even with --allow-incomplete', (t) => {
  const root = makeRepo(t)
  write(root, 'src/a.ts', 'export const a = 1\n')
  commit(root)
  write(root, '.atlas/review-policy.json', '{not a policy\n')
  const result = runCli(root, ['audit', 'check', '--allow-incomplete'])
  assert.notEqual(result.status, 0)
  assert.match(result.stdout + result.stderr, /policy/u)
})

// ---------------------------------------------------------------------------
// audit status
// ---------------------------------------------------------------------------

test('audit status reports the V3 portfolio as bounded canonical JSON', (t) => {
  const root = makeCoverageRepo(t)
  const fixture = publishV3(root)
  const fake = makeFakeGrok(t)

  const text = runCli(root, ['audit', 'status'], fake.env)
  assert.equal(text.status, 0, text.stderr)
  assert.match(text.stdout, new RegExp(fixture.slug, 'u'))

  const json = runCli(root, ['audit', 'status', '--json'], fake.env)
  assert.equal(json.status, 0, json.stderr)
  assert.equal(
    json.stdout,
    `${canonicalJson(JSON.parse(json.stdout))}\n`,
    'audit status --json must emit canonical JSON on stdout',
  )
  const payload = JSON.parse(json.stdout)
  assert.ok(Array.isArray(payload.observations.slugs))
  assert.ok(payload.observations.slugs.includes(fixture.slug))
  assert.ok('decisions' in payload)
  assert.ok('coverage' in payload)
  assert.ok('migrations' in payload)

  assert.deepEqual(fake.invocations(), [], 'audit status must never launch a provider')
})

// ---------------------------------------------------------------------------
// audit run security
// ---------------------------------------------------------------------------

test('audit run security --provider grok launches only the explicit provider path', (t) => {
  const root = makeCoverageRepo(t)
  const fake = makeFakeGrok(t)
  writeProviderPolicy(root, fake)

  const result = runCli(
    root,
    ['audit', 'run', 'security', '--provider', 'grok', '--unit', 'security-src'],
    fake.env,
  )
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /arun_[0-9a-f]{24}/u)
  assert.ok(fake.invocations().length > 0, 'the run must record provider invocations')
})

test('audit run security validates selection flags and provider policy', (t) => {
  const root = makeCoverageRepo(t)
  const fake = makeFakeGrok(t)
  writeProviderPolicy(root, fake)

  const conflict = runCli(
    root,
    ['audit', 'run', 'security', '--provider', 'grok', '--unit', 'security-src', '--all'],
    fake.env,
  )
  assert.notEqual(conflict.status, 0, 'selection flags are mutually exclusive')
  assert.match(conflict.stderr, /usage: repo-atlas audit run/u)

  const unknownUnit = runCli(
    root,
    ['audit', 'run', 'security', '--provider', 'grok', '--unit', 'security-nope'],
    fake.env,
  )
  assert.notEqual(unknownUnit.status, 0, 'unknown units must fail')

  const stale = runCli(
    root,
    ['audit', 'run', 'security', '--provider', 'grok', '--stale'],
    fake.env,
  )
  assert.equal(stale.status, 0, stale.stderr)

  const resumed = runCli(
    root,
    ['audit', 'run', 'security', '--provider', 'grok', '--unit', 'security-src',
      '--resume', `arun_${'0'.repeat(24)}`],
    fake.env,
  )
  assert.notEqual(resumed.status, 0, 'resuming an unknown invocation must fail')

  fs.rmSync(path.join(root, '.atlas', 'audit-providers.json'))
  const noPolicy = runCli(
    root,
    ['audit', 'run', 'security', '--provider', 'grok', '--unit', 'security-src'],
    fake.env,
  )
  assert.notEqual(noPolicy.status, 0, 'a run without provider policy must fail')
  assert.match(noPolicy.stderr, /audit-providers\.json|model/u)
})

// ---------------------------------------------------------------------------
// audit import codex-security
// ---------------------------------------------------------------------------

test('audit import codex-security separates dry-run from apply', (t) => {
  const root = makeRepo(t)
  write(root, 'src/extract.py', 'destination.write_bytes(entry.read())\n')
  commit(root)
  const bundle = materializeCodexBundle(t)
  const fake = makeFakeGrok(t)
  const slug = 'security-codex-import'

  const dry = runCli(
    root,
    ['audit', 'import', 'codex-security', bundle, '--slug', slug],
    fake.env,
  )
  assert.equal(dry.status, 0, dry.stderr)
  assert.match(dry.stdout, /dry run/u)
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'audits', `${slug}.json`)), false)
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'audit-history')), false)

  const applied = runCli(
    root,
    ['audit', 'import', 'codex-security', bundle, '--slug', slug, '--apply'],
    fake.env,
  )
  assert.equal(applied.status, 0, applied.stderr)
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'audits', `${slug}.json`)), true)
  assert.equal(
    fs.existsSync(path.join(root, '.atlas', 'audit-history', `${slug}.json`)),
    true,
  )

  const missingSlug = runCli(root, ['audit', 'import', 'codex-security', bundle], fake.env)
  assert.notEqual(missingSlug.status, 0)
  assert.match(missingSlug.stderr, /usage: repo-atlas audit import/u)

  assert.deepEqual(fake.invocations(), [], 'import must never launch a provider')
})

// ---------------------------------------------------------------------------
// audit migrate
// ---------------------------------------------------------------------------

test('audit migrate relayos-security-v1 separates dry-run from apply and plumbs revisions', (t) => {
  const { root, revision } = makeRelayOSSecurityRepo(t)
  const fake = makeFakeGrok(t)
  const base = [
    'audit', 'migrate', 'relayos-security-v1',
    '--scan-root', RELAYOS_SOURCE_ROOT,
    '--policy', '.atlas/review-policy.json',
    '--source-revision', revision,
    '--validation-revision', revision,
  ]

  const dry = runCli(root, base, fake.env)
  assert.equal(dry.status, 0, dry.stderr)
  assert.match(dry.stdout, /amig_[0-9a-f]{24}/u)
  assert.match(dry.stdout, /dry run/u)
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'migrations')), false)

  const applied = runCli(root, [...base, '--apply'], fake.env)
  assert.equal(applied.status, 0, applied.stderr)
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'migrations')), true)
  const receipts = fs.readdirSync(path.join(root, '.atlas', 'migrations'))
  assert.equal(receipts.length, 1)
  assert.match(receipts[0], /^amig_[0-9a-f]{24}\.json$/u)
  assert.equal(
    fs.existsSync(path.join(root, '.atlas', 'audits', 'security-fixture-apps.json')),
    true,
  )
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'audit-history')), true)

  const missing = runCli(root, [
    'audit', 'migrate', 'relayos-security-v1',
    '--scan-root', RELAYOS_SOURCE_ROOT,
    '--policy', '.atlas/review-policy.json',
    '--validation-revision', revision,
  ], fake.env)
  assert.notEqual(missing.status, 0, 'missing --source-revision must fail')
  assert.match(missing.stderr, /--source-revision/u)

  assert.deepEqual(fake.invocations(), [], 'migrate must never launch a provider')
})

test('audit migrate relayos-security-v1 --no-include-history skips history writes', (t) => {
  const { root, revision } = makeRelayOSSecurityRepo(t)
  const applied = runCli(root, [
    'audit', 'migrate', 'relayos-security-v1',
    '--scan-root', RELAYOS_SOURCE_ROOT,
    '--policy', '.atlas/review-policy.json',
    '--source-revision', revision,
    '--validation-revision', revision,
    '--no-include-history',
    '--apply',
  ])
  assert.equal(applied.status, 0, applied.stderr)
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'migrations')), true)
  assert.equal(
    fs.existsSync(path.join(root, '.atlas', 'audit-history')),
    false,
    '--no-include-history must suppress observation history writes',
  )
})

test('audit migrate relayos-root-audits-v1 separates dry-run from apply', (t) => {
  const { root, revision } = makeRelayOSRootAuditsRepo(t)
  const fake = makeFakeGrok(t)
  const base = [
    'audit', 'migrate', 'relayos-root-audits-v1',
    '--audits-root', 'audits',
    '--source-revision', revision,
    '--validation-revision', revision,
  ]

  const dry = runCli(root, base, fake.env)
  assert.equal(dry.status, 0, dry.stderr)
  assert.match(dry.stdout, /amig_[0-9a-f]{24}/u)
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'migrations')), false)

  const applied = runCli(root, [...base, '--apply'], fake.env)
  assert.equal(applied.status, 0, applied.stderr)
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'migrations')), true)
  assert.equal(
    fs.existsSync(path.join(root, '.atlas', 'artifacts', 'historical-audits')),
    true,
  )

  assert.deepEqual(fake.invocations(), [], 'root-audits migrate must never launch a provider')
})

// ---------------------------------------------------------------------------
// audit decision set / reconcile / retire
// ---------------------------------------------------------------------------

test('audit decision set appends a validated finding-disposition event', (t) => {
  const root = makeCoverageRepo(t)
  const fixture = publishV3(root)
  const fake = makeFakeGrok(t)
  const eventFile = writeEvent(root, 'open-event.json', openEvent(fixture))

  const byFinding = runCli(
    root,
    ['audit', 'decision', 'set', fixture.findingId, 'open', '--event', eventFile],
    fake.env,
  )
  assert.equal(byFinding.status, 0, byFinding.stderr)
  assert.match(byFinding.stdout, /adev_[0-9a-f]{24}/u)
  const ledger = decisionLedger(root, fixture.slug)
  assert.equal(ledger.entries.length, 1)
  assert.equal(ledger.entries[0].event.action, 'open')

  const again = runCli(
    root,
    ['audit', 'decision', 'set', fixture.occurrenceId, 'open', '--event', eventFile],
    fake.env,
  )
  assert.equal(again.status, 0, again.stderr)
  assert.match(again.stdout, /already-present/u)
  assert.equal(decisionLedger(root, fixture.slug).entries.length, 1)

  const mismatch = runCli(
    root,
    ['audit', 'decision', 'set', fixture.findingId, 'remediated', '--event', eventFile],
    fake.env,
  )
  assert.notEqual(mismatch.status, 0, 'positional action must match the event payload')

  const unknown = runCli(
    root,
    ['audit', 'decision', 'set', `atf_${'9'.repeat(24)}`, 'open', '--event',
      writeEvent(root, 'unknown-finding.json', openEvent(fixture, {
        findingId: `atf_${'9'.repeat(24)}`,
      }))],
    fake.env,
  )
  assert.notEqual(unknown.status, 0, 'unknown findings must fail closed')

  const noEvent = runCli(
    root,
    ['audit', 'decision', 'set', fixture.findingId, 'open'],
    fake.env,
  )
  assert.notEqual(noEvent.status, 0)
  assert.match(noEvent.stderr, /--event/u)

  assert.deepEqual(fake.invocations(), [], 'decision set must never launch a provider')
})

test('audit reconcile appends a finding-reconciliation event', (t) => {
  const root = makeCoverageRepo(t)
  const before = publishV3(root)
  const after = publishV3(root, { instance: 'b', runId: 'audit-cli-fixture-run-2' })
  const fake = makeFakeGrok(t)
  const eventFile = writeEvent(
    root,
    'reconcile-event.json',
    reconcileEvent(before.slug, before, after),
  )

  const result = runCli(
    root,
    ['audit', 'reconcile', before.occurrenceId, after.occurrenceId, '--event', eventFile],
    fake.env,
  )
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /adev_[0-9a-f]{24}/u)
  const ledger = decisionLedger(root, before.slug)
  assert.equal(ledger.entries.length, 1)
  assert.equal(ledger.entries[0].event.type, 'finding-reconciliation')

  const mismatch = runCli(
    root,
    ['audit', 'reconcile', after.occurrenceId, before.occurrenceId, '--event', eventFile],
    fake.env,
  )
  assert.notEqual(mismatch.status, 0, 'positionals must match the event occurrence sets')

  assert.deepEqual(fake.invocations(), [], 'reconcile must never launch a provider')
})

test('audit retire stages and finalizes scope retirement', (t) => {
  const root = makeCoverageRepo(t)
  const fixture = publishV3(root)
  const revision = head(root)
  const fake = makeFakeGrok(t)

  const stagedFile = writeEvent(
    root,
    'retire-staged.json',
    stagedRetirementEvent(fixture, revision),
  )
  const staged = runCli(
    root,
    ['audit', 'retire', 'src/a.ts', '--event', stagedFile],
    fake.env,
  )
  assert.equal(staged.status, 0, staged.stderr)
  const stagedLedger = decisionLedger(root, fixture.slug)
  assert.equal(stagedLedger.entries.length, 1)
  const stagedEventId = stagedLedger.entries[0].eventId

  const wrongPath = runCli(
    root,
    ['audit', 'retire', 'src/other.ts', '--event', stagedFile],
    fake.env,
  )
  assert.notEqual(wrongPath.status, 0, 'the positional path must match the event')

  const finalizedFile = writeEvent(
    root,
    'retire-final.json',
    finalizeRetirementEvent(fixture, revision, stagedEventId),
  )
  const finalized = runCli(
    root,
    ['audit', 'retire', '--finalize-staged', '--event', finalizedFile],
    fake.env,
  )
  assert.equal(finalized.status, 0, finalized.stderr)
  assert.equal(decisionLedger(root, fixture.slug).entries.length, 2)

  const orphanFile = writeEvent(
    root,
    'retire-orphan.json',
    finalizeRetirementEvent(fixture, revision, `adev_${'7'.repeat(24)}`),
  )
  const orphan = runCli(
    root,
    ['audit', 'retire', '--finalize-staged', '--event', orphanFile],
    fake.env,
  )
  assert.notEqual(orphan.status, 0, 'finalize requires an existing staged-deletion event')

  const both = runCli(
    root,
    ['audit', 'retire', 'src/a.ts', '--finalize-staged', '--event', stagedFile],
    fake.env,
  )
  assert.notEqual(both.status, 0, 'path and --finalize-staged are mutually exclusive')

  assert.deepEqual(fake.invocations(), [], 'retire must never launch a provider')
})

// ---------------------------------------------------------------------------
// legacy flat aliases
// ---------------------------------------------------------------------------

test('legacy audit-localization-check prints deprecation guidance and still works', (t) => {
  const root = makeRepo(t)

  const legacy = runCli(root, ['audit-localization-check'])
  assert.equal(legacy.status, 0, legacy.stderr)
  assert.match(legacy.stderr, /deprecated/u)
  assert.match(legacy.stderr, /audit localization check/u)
  assert.match(legacy.stdout, /no required content locales/u)

  const hierarchical = runCli(root, ['audit', 'localization', 'check'])
  assert.equal(hierarchical.status, 0, hierarchical.stderr)
  assert.match(hierarchical.stdout, /no required content locales/u)
  assert.doesNotMatch(hierarchical.stderr, /deprecated/u)
})

test('legacy audit-import prints deprecation guidance and imports the same ledger', (t) => {
  const root = makeRepo(t)
  write(root, 'src/a.ts', 'export const a = 1\n')
  commit(root)
  const blob = gitBlob(root, 'src/a.ts')
  writeJson(root, 'audits/design-scan/ledger.json', {
    ruleset: 'legacy-v1',
    scans: [{
      path: 'src/a.ts',
      git_blob_sha1: blob,
      scanned_at: '2026-07-19',
      finding_count: 0,
    }],
  })

  const legacy = runCli(root, ['audit-import', 'audits/design-scan/ledger.json'])
  assert.equal(legacy.status, 0, legacy.stderr)
  assert.match(legacy.stderr, /deprecated/u)
  assert.match(legacy.stderr, /audit import legacy-v1/u)
  const stored = path.join(root, '.atlas', 'audits', 'design-scan.json')
  assert.equal(fs.existsSync(stored), true)
  fs.rmSync(stored)

  const hierarchical = runCli(
    root,
    ['audit', 'import', 'legacy-v1', 'audits/design-scan/ledger.json'],
  )
  assert.equal(hierarchical.status, 0, hierarchical.stderr)
  assert.doesNotMatch(hierarchical.stderr, /deprecated/u)
  assert.equal(fs.existsSync(stored), true)
})

test('legacy audit-stamp prints deprecation guidance and stamps the same ledgers', (t) => {
  const root = makeRepo(t)
  write(root, 'src/a.ts', 'export const a = 1\n')
  commit(root)
  const legacyLedger = (slug) => ({
    formatVersion: 1,
    format: 'atlas-audit-v1',
    slug,
    title: slug,
    ruleset: 'test-v1',
    scanned_at: '2026-07-19',
    scope_hash: scopeHash(root, ['src/a.ts']),
    file_count: 1,
    files: ['src/a.ts'],
    findings: [],
    dropped: [],
    rounds: [],
    finalPass: true,
  })
  writeJson(root, '.atlas/audits/security-legacy.json', legacyLedger('security-legacy'))

  const legacy = runCli(root, ['audit-stamp'])
  assert.equal(legacy.status, 0, legacy.stderr)
  assert.match(legacy.stderr, /deprecated/u)
  assert.match(legacy.stderr, /audit stamp/u)
  assert.match(legacy.stdout, /stamped: security-legacy/u)

  writeJson(root, '.atlas/audits/security-legacy-2.json', legacyLedger('security-legacy-2'))
  const hierarchical = runCli(root, ['audit', 'stamp'])
  assert.equal(hierarchical.status, 0, hierarchical.stderr)
  assert.doesNotMatch(hierarchical.stderr, /deprecated/u)
  assert.match(hierarchical.stdout, /stamped: security-legacy-2/u)
})


// ---------------------------------------------------------------------------
// provider-launch and deprecation completeness gates
// ---------------------------------------------------------------------------

test('audit run security without --provider grok fails without launching anything', (t) => {
  const root = makeCoverageRepo(t)
  const fake = makeFakeGrok(t)
  writeProviderPolicy(root, fake)

  for (const args of [
    ['audit', 'run', 'security'],
    ['audit', 'run', 'security', '--provider', 'bogus'],
  ]) {
    const result = runCli(root, args, fake.env)
    assert.notEqual(result.status, 0, `args ${args.join(' ')} must fail`)
    assert.match(result.stderr, /usage: repo-atlas audit run/u)
  }
  assert.deepEqual(fake.invocations(), [], 'a refused run must not launch a provider')
})

test('audit stamp and localization commands never launch a provider', (t) => {
  const root = makeCoverageRepo(t)
  const fake = makeFakeGrok(t)
  // localization input requires an available review coverage registry.
  assert.equal(
    runCli(root, ['audit', 'coverage', 'update', '--allow-incomplete'], fake.env).status,
    0,
  )

  const stamp = runCli(root, ['audit', 'stamp'], fake.env)
  assert.equal(stamp.status, 0, stamp.stderr)

  const input = runCli(root, ['audit', 'localization', 'input', '--locale', 'ja'], fake.env)
  assert.equal(input.status, 0, input.stderr)

  const check = runCli(root, ['audit', 'localization', 'check'], fake.env)
  assert.equal(check.status, 0, check.stderr)

  assert.deepEqual(
    fake.invocations(),
    [],
    'stamp/localization commands must never launch a provider',
  )
})

test('every deprecated flat audit alias prints guidance naming its V3 replacement', (t) => {
  // The alias set is derived from the dispatch source so a newly added flat
  // alias fails this gate until its success arguments are registered here.
  const cliSource = fs.readFileSync(path.join(TEST_DIR, '..', 'src', 'cli.ts'), 'utf8')
  const declared = new Map(
    [...cliSource.matchAll(/deprecatedAuditAlias\('([^']+)', '([^']+)'\)/gu)]
      .map((match) => [match[1], match[2]]),
  )
  const successArgs = new Map([
    ['audit-stamp', []],
    ['audit-import', ['audits/design-scan/ledger.json']],
    ['audit-localization-input', ['--locale', 'ja']],
    ['audit-localization-check', []],
  ])
  assert.deepEqual(
    [...declared.keys()].sort(),
    [...successArgs.keys()].sort(),
    'every deprecated alias in src/cli.ts must be exercised here',
  )

  const root = makeCoverageRepo(t)
  const fake = makeFakeGrok(t)
  // localization input requires an available review coverage registry.
  assert.equal(
    runCli(root, ['audit', 'coverage', 'update', '--allow-incomplete'], fake.env).status,
    0,
  )
  const blob = gitBlob(root, 'src/a.ts')
  writeJson(root, 'audits/design-scan/ledger.json', {
    ruleset: 'legacy-v1',
    scans: [{
      path: 'src/a.ts',
      git_blob_sha1: blob,
      scanned_at: '2026-07-19',
      finding_count: 0,
    }],
  })

  // audit-import adds a legacy ledger, which invalidates the coverage
  // registry the localization commands read — run it last.
  const ordered = [...declared.entries()]
    .sort(([left], [right]) => Number(left === 'audit-import') - Number(right === 'audit-import'))
  for (const [flat, hierarchical] of ordered) {
    const result = runCli(root, [flat, ...successArgs.get(flat)], fake.env)
    assert.equal(result.status, 0, `${flat}: ${result.stderr}`)
    assert.match(
      result.stderr,
      new RegExp(
        `repo-atlas ${flat} is deprecated — use 'repo-atlas ${hierarchical}' instead`,
        'u',
      ),
      `${flat} must name its hierarchical replacement`,
    )
  }
  assert.deepEqual(fake.invocations(), [], 'deprecated aliases must never launch a provider')
})

test('--stale refreshes whole units, so a partial rescan cannot drop standing receipts', (t) => {
  const root = makeRepo(t)
  write(root, 'src/a.ts', 'export const a = 1\n')
  write(root, 'src/b.ts', 'export const b = 2\n')
  commit(root)
  writeReviewPolicy(root)
  const fake = makeFakeGrok(t)
  writeProviderPolicy(root, fake)

  const first = runCli(
    root,
    ['audit', 'run', 'security', '--provider', 'grok', '--unit', 'security-src'],
    fake.env,
  )
  assert.equal(first.status, 0, first.stderr)
  const ledgerPath = path.join(root, '.atlas', 'audits', 'security-src.json')
  const before = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'))
  assert.deepEqual(
    before.current.scope.files.map((file) => file.path).sort(),
    ['src/a.ts', 'src/b.ts'],
  )

  // Only b.ts changes, so a.ts keeps a valid receipt while b.ts goes stale.
  // Selecting b.ts alone would republish a scope covering b.ts only, silently
  // turning a.ts back into missing evidence. The edit is committed on its own so
  // the worktree stays clean: a dirty tree makes every file in the unit stale
  // and would hide the partial-selection defect this test is about.
  write(root, 'src/b.ts', 'export const b = 3\n')
  execFileSync('git', ['add', '--', 'src/b.ts'], { cwd: root })
  execFileSync('git', ['commit', '-qm', 'edit b'], {
    cwd: root,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Repo Atlas Fixture',
      GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
      GIT_COMMITTER_NAME: 'Repo Atlas Fixture',
      GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      GIT_AUTHOR_DATE: '2026-07-30T03:56:24.000Z',
      GIT_COMMITTER_DATE: '2026-07-30T03:56:24.000Z',
    },
  })

  const stale = runCli(
    root,
    ['audit', 'run', 'security', '--provider', 'grok', '--stale'],
    fake.env,
  )
  assert.equal(stale.status, 0, stale.stderr)
  const after = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'))
  assert.deepEqual(
    after.current.scope.files.map((file) => file.path).sort(),
    ['src/a.ts', 'src/b.ts'],
    'the refreshed observation still covers the file that was already fresh',
  )
  assert.deepEqual(
    after.current.scope.files
      .map((file) => [file.path, file.status])
      .sort((left, right) => left[0].localeCompare(right[0])),
    [['src/a.ts', 'reviewed'], ['src/b.ts', 'reviewed']],
    'both files carry a reviewed receipt, not a placeholder',
  )
  assert.deepEqual(after.current.exactCoverage.unreviewed, [])
})
