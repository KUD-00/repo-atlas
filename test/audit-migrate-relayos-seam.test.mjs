import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const FIXTURE_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  'fixtures',
  'relayos-security',
)
const SOURCE_ROOT = 'audits/security-scan'
const SOURCE_FILES = [
  'ledger.json',
  'candidates.v1.json',
  'dispositions.v1.json',
  'phase-zero-provenance.v1.json',
]
const REPOSITORY_ID = 'repo_relayos_migration_fixture'
const LEGACY_SUCCESSOR_PATH =
  'apps/daemon/src/inference-relay/secure-outbound-transport.ts'
const ZERO_REVISION = '0'.repeat(40)

async function migrationApi() {
  try {
    return await import('../dist/audit-migrate-relayos.js')
  } catch (error) {
    assert.fail(
      `Task 6 RelayOS migration API is missing: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

function write(root, repoPath, contents) {
  const target = path.join(root, ...repoPath.split('/'))
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, contents)
}

function writeJson(root, repoPath, value) {
  write(root, repoPath, `${JSON.stringify(value, null, 2)}\n`)
}

function readJson(root, repoPath) {
  return JSON.parse(
    fs.readFileSync(path.join(root, ...repoPath.split('/')), 'utf8'),
  )
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function gitBlob(bytes) {
  const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, 'utf8')
  return createHash('sha1')
    .update(`blob ${value.byteLength}\0`, 'utf8')
    .update(value)
    .digest('hex')
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

function makeRepo() {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'repo-atlas-relayos-migration-seam-'),
  )
  execFileSync('git', ['init', '-q'], { cwd: root })
  writeJson(root, '.atlas/config.json', {
    formatVersion: 1,
    exclude: [],
    repositoryId: REPOSITORY_ID,
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
  for (const name of SOURCE_FILES) {
    write(
      root,
      `${SOURCE_ROOT}/${name}`,
      fs.readFileSync(path.join(FIXTURE_ROOT, name)),
    )
  }
  write(
    root,
    LEGACY_SUCCESSOR_PATH,
    'export const secureOutboundTransport = true\n',
  )
  commit(root)
  return { root, revision: head(root) }
}

function cleanup(...roots) {
  for (const root of roots) {
    if (root) fs.rmSync(root, { recursive: true, force: true })
  }
}

function migrationOptions(sourceRevision, validationRevision, overrides = {}) {
  return {
    scanRoot: SOURCE_ROOT,
    sourceRevision,
    validationRevision,
    ...overrides,
  }
}

function snapshotTree(root) {
  const entries = []
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name)
      const relative = path.relative(root, full)
      if (relative === '.git' || relative.startsWith(`.git${path.sep}`)) {
        continue
      }
      if (entry.isDirectory()) {
        walk(full)
      } else {
        entries.push([
          relative.split(path.sep).join('/'),
          sha256(fs.readFileSync(full)),
        ])
      }
    }
  }
  walk(root)
  return entries.sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0)
}

function migrationError(name) {
  return (error) => {
    assert.equal(error.name, 'RelayOSMigrationError', name)
    return true
  }
}

function currentFinding(result, candidateId) {
  return result.observations
    .filter(({ producer }) => producer.runId.endsWith('/current'))
    .flatMap(({ findings }) => findings)
    .find(({ fingerprints }) => fingerprints.some(({ value }) =>
      value === candidateId))
}

test('buildRelayOSAuditMigration is pure and byte-identical to the dry mutating seam', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  try {
    const before = snapshotTree(repo)
    const options = migrationOptions(revision, revision)
    const built = api.buildRelayOSAuditMigration(repo, options)
    const builtWithApplyFlag = api.buildRelayOSAuditMigration(
      repo,
      migrationOptions(revision, revision, { apply: true }),
    )
    const dry = api.migrateRelayOSAudit(
      repo,
      migrationOptions(revision, revision, { apply: false }),
    )

    assert.deepEqual(dry, built)
    assert.deepEqual(builtWithApplyFlag, built)
    assert.equal(dry.receipt.receiptDigest, built.receipt.receiptDigest)
    assert.equal(
      JSON.stringify(dry.receipt),
      JSON.stringify(built.receipt),
    )
    assert.equal(fs.existsSync(path.join(repo, '.atlas', 'migrations')), false)
    assert.equal(
      fs.existsSync(path.join(repo, '.atlas', 'audit-history')),
      false,
    )
    assert.equal(
      fs.existsSync(path.join(repo, '.atlas', 'audit-decisions')),
      false,
    )
    assert.equal(fs.existsSync(path.join(repo, '.atlas', 'audits')), false)
    assert.deepEqual(snapshotTree(repo), before)
  } finally {
    cleanup(repo)
  }
})

test('rejects missing, malformed, or unknown revisions before any write', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  const outputDirectories = [
    '.atlas/migrations',
    '.atlas/audit-history',
    '.atlas/audit-decisions',
    '.atlas/audits',
  ]
  const cases = [
    ['options omitted', undefined],
    ['sourceRevision missing', { validationRevision: revision }],
    ['validationRevision missing', { sourceRevision: revision }],
    [
      'sourceRevision is a symbolic ref',
      migrationOptions('HEAD', revision),
    ],
    [
      'sourceRevision is abbreviated',
      migrationOptions(revision.slice(0, 12), revision),
    ],
    [
      'sourceRevision is uppercase',
      migrationOptions(revision.toUpperCase(), revision),
    ],
    [
      'sourceRevision is unknown',
      migrationOptions(ZERO_REVISION, revision),
    ],
    [
      'validationRevision is unknown',
      migrationOptions(revision, ZERO_REVISION),
    ],
    [
      'validationRevision is not a 40-hex commit',
      migrationOptions(revision, 'a'.repeat(64)),
    ],
    [
      'legacy sourceRoot option is rejected',
      { ...migrationOptions(revision, revision), sourceRoot: SOURCE_ROOT },
    ],
  ]
  try {
    for (const [name, options] of cases) {
      assert.throws(
        () => api.buildRelayOSAuditMigration(repo, options),
        migrationError(name),
        `build: ${name}`,
      )
      assert.throws(
        () => api.migrateRelayOSAudit(repo, options),
        migrationError(name),
        `migrate: ${name}`,
      )
    }
    for (const directory of outputDirectories) {
      assert.equal(
        fs.existsSync(path.join(repo, ...directory.split('/'))),
        false,
        directory,
      )
    }
  } finally {
    cleanup(repo)
  }
})

test('reads every source and validation byte from the pinned revisions, not the worktree', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  try {
    const options = migrationOptions(revision, revision)
    const clean = api.buildRelayOSAuditMigration(repo, options)

    write(repo, `${SOURCE_ROOT}/ledger.json`, 'not json at all\n')
    fs.rmSync(path.join(repo, ...`${SOURCE_ROOT}/candidates.v1.json`.split('/')))
    write(repo, LEGACY_SUCCESSOR_PATH, 'export const drifted = true\n')
    write(repo, 'untracked-junk.txt', 'junk\n')

    const dirty = api.buildRelayOSAuditMigration(repo, options)
    const dirtyDry = api.migrateRelayOSAudit(repo, options)
    assert.deepEqual(dirty, clean)
    assert.deepEqual(dirtyDry, clean)
    assert.equal(
      fs.readFileSync(
        path.join(repo, ...`${SOURCE_ROOT}/ledger.json`.split('/')),
        'utf8',
      ),
      'not json at all\n',
    )
  } finally {
    cleanup(repo)
  }
})

test('validates current blobs against the validation revision tree', async () => {
  const api = await migrationApi()
  const { root: repo } = makeRepo()
  const candidateId = 'SEC-48AABC8B1EB6'
  const sourcePath =
    'packages/kernel/governance-relay/src/runtime/transition.ts'
  const validatedBytes = Buffer.from(
    Array.from({ length: 20 }, (_, index) =>
      `export const line${index + 1} = ${index + 1}\n`).join(''),
    'utf8',
  )
  const validatedBlob = gitBlob(validatedBytes)
  try {
    const ledger = readJson(repo, `${SOURCE_ROOT}/ledger.json`)
    const scan = ledger.scans.find(({ path: candidatePath }) =>
      candidatePath === sourcePath)
    scan.git_blob_sha1 = validatedBlob
    scan.lines = 20
    writeJson(repo, `${SOURCE_ROOT}/ledger.json`, ledger)

    const candidates = readJson(repo, `${SOURCE_ROOT}/candidates.v1.json`)
    candidates.entries.find(({ id }) => id === candidateId).sourceBlob =
      validatedBlob
    writeJson(repo, `${SOURCE_ROOT}/candidates.v1.json`, candidates)

    const dispositions =
      readJson(repo, `${SOURCE_ROOT}/dispositions.v1.json`)
    const disposition =
      dispositions.dispositions.find(({ id }) => id === candidateId)
    disposition.sourceBlob = validatedBlob
    disposition.reviewedBlob = validatedBlob
    disposition.currentScan.reviewedBlob = validatedBlob
    writeJson(repo, `${SOURCE_ROOT}/dispositions.v1.json`, dispositions)

    const provenance =
      readJson(repo, `${SOURCE_ROOT}/phase-zero-provenance.v1.json`)
    provenance.legacyRecords.find(({ path: candidatePath }) =>
      candidatePath === sourcePath).sourceBlob = validatedBlob
    writeJson(
      repo,
      `${SOURCE_ROOT}/phase-zero-provenance.v1.json`,
      provenance,
    )

    write(repo, sourcePath, '// superseded content\n')
    commit(repo, 'source revision with stale product bytes')
    const sourceRevision = head(repo)
    write(repo, sourcePath, validatedBytes)
    commit(repo, 'validation revision with exact product bytes')
    const validationRevision = head(repo)
    assert.notEqual(sourceRevision, validationRevision)

    const atValidation = api.buildRelayOSAuditMigration(
      repo,
      migrationOptions(sourceRevision, validationRevision),
    )
    const atSource = api.buildRelayOSAuditMigration(
      repo,
      migrationOptions(sourceRevision, sourceRevision),
    )

    assert.equal(
      atValidation.receipt.source.repositoryRevision,
      sourceRevision,
    )
    assert.equal(
      atValidation.receipt.validation.repositoryRevision,
      validationRevision,
    )
    assert.equal(atSource.receipt.validation.repositoryRevision, sourceRevision)
    assert.deepEqual(atValidation.receipt.source, atSource.receipt.source)
    assert.notEqual(
      atValidation.receipt.validation.digest,
      atSource.receipt.validation.digest,
    )
    assert.notEqual(atValidation.migrationId, atSource.migrationId)

    const matched = currentFinding(atValidation, candidateId)
    assert.equal(
      matched.codeEvidence?.[0]?.blob,
      `git-sha1:${validatedBlob}`,
    )
    const unmatched = currentFinding(atSource, candidateId)
    assert.ok(unmatched !== undefined)
    assert.equal(unmatched.codeEvidence, undefined)
    assert.equal(
      atValidation.receipt.validation.exactWorktreeMatches,
      atSource.receipt.validation.exactWorktreeMatches + 1,
    )
    assert.equal(
      atValidation.receipt.validation.staleOrMissingPaths + 1,
      atSource.receipt.validation.staleOrMissingPaths,
    )
  } finally {
    cleanup(repo)
  }
})

test('apply fails before any mutation when the repository drifts after planning', async () => {
  const api = await migrationApi()
  const divergent = makeRepo()
  try {
    const options = migrationOptions(divergent.revision, divergent.revision)
    const planned = api.buildRelayOSAuditMigration(divergent.root, options)
    const sabotaged = planned.writes.find(({ path: repoPath }) =>
      repoPath.startsWith('.atlas/audit-history/'))
    assert.ok(sabotaged !== undefined)
    write(divergent.root, sabotaged.path, '{"divergent":true}\n')

    assert.throws(
      () => api.migrateRelayOSAudit(
        divergent.root,
        migrationOptions(divergent.revision, divergent.revision, {
          apply: true,
        }),
      ),
      (error) => {
        assert.equal(error.name, 'RelayOSMigrationError')
        assert.match(error.message, /diverges/)
        return true
      },
    )
    for (const { path: repoPath } of planned.writes) {
      const absolute = path.join(divergent.root, ...repoPath.split('/'))
      if (repoPath === sabotaged.path) {
        assert.equal(fs.readFileSync(absolute, 'utf8'), '{"divergent":true}\n')
      } else {
        assert.equal(fs.existsSync(absolute), false, repoPath)
      }
    }
  } finally {
    cleanup(divergent.root)
  }

  const drifted = makeRepo()
  try {
    const options = migrationOptions(drifted.revision, drifted.revision)
    api.buildRelayOSAuditMigration(drifted.root, options)
    write(drifted.root, '.atlas/config.json', 'not json at all\n')
    assert.throws(
      () => api.migrateRelayOSAudit(
        drifted.root,
        migrationOptions(drifted.revision, drifted.revision, { apply: true }),
      ),
      /config|JSON|audit/i,
    )
    assert.equal(
      fs.existsSync(path.join(drifted.root, '.atlas', 'migrations')),
      false,
    )
    assert.equal(
      fs.existsSync(path.join(drifted.root, '.atlas', 'audit-history')),
      false,
    )
    assert.equal(
      fs.existsSync(path.join(drifted.root, '.atlas', 'audit-decisions')),
      false,
    )
    assert.equal(
      fs.existsSync(path.join(drifted.root, '.atlas', 'audits')),
      false,
    )
  } finally {
    cleanup(drifted.root)
  }
})

test('includeHistory:false omits history documents but keeps projections, decisions, and the receipt', async () => {
  const api = await migrationApi()
  const { loadAuditDecisionLedgers } =
    await import('../dist/audit-decisions.js')
  const { root: repo, revision } = makeRepo()
  try {
    const full = api.buildRelayOSAuditMigration(
      repo,
      migrationOptions(revision, revision),
    )
    const lite = api.buildRelayOSAuditMigration(
      repo,
      migrationOptions(revision, revision, { includeHistory: false }),
    )

    const historyWrites = full.writes.filter(({ path: repoPath }) =>
      repoPath.startsWith('.atlas/audit-history/'))
    assert.ok(historyWrites.length > 0)
    assert.equal(
      lite.writes.some(({ path: repoPath }) =>
        repoPath.startsWith('.atlas/audit-history/')),
      false,
    )
    assert.deepEqual(
      lite.writes.filter(({ path: repoPath }) =>
        !repoPath.startsWith('.atlas/migrations/')),
      full.writes.filter(({ path: repoPath }) =>
        !repoPath.startsWith('.atlas/audit-history/') &&
        !repoPath.startsWith('.atlas/migrations/')),
    )
    const liteReceiptWrite = lite.writes.find(({ path: repoPath }) =>
      repoPath.startsWith('.atlas/migrations/'))
    const fullReceiptWrite = full.writes.find(({ path: repoPath }) =>
      repoPath.startsWith('.atlas/migrations/'))
    assert.equal(liteReceiptWrite.path, fullReceiptWrite.path)
    assert.notEqual(liteReceiptWrite.sha256, fullReceiptWrite.sha256)
    assert.equal(lite.migrationId, full.migrationId)
    assert.deepEqual(lite.observations, full.observations)
    assert.deepEqual(lite.decisionEvents, full.decisionEvents)
    assert.deepEqual(lite.retirementEvents, full.retirementEvents)
    assert.deepEqual(lite.reconciliationEvents, full.reconciliationEvents)
    assert.equal(
      lite.receipt.outputs.some(({ path: repoPath }) =>
        repoPath.startsWith('.atlas/audit-history/')),
      false,
    )
    assert.deepEqual(
      lite.receipt.outputs,
      full.receipt.outputs.filter(({ path: repoPath }) =>
        !repoPath.startsWith('.atlas/audit-history/')),
    )
    assert.notEqual(lite.receipt.receiptDigest, full.receipt.receiptDigest)

    const applied = api.migrateRelayOSAudit(
      repo,
      migrationOptions(revision, revision, {
        apply: true,
        includeHistory: false,
      }),
    )
    assert.deepEqual(applied, lite)
    assert.equal(
      fs.existsSync(path.join(repo, '.atlas', 'audit-history')),
      false,
    )
    assert.equal(fs.existsSync(path.join(repo, '.atlas', 'audits')), true)
    assert.equal(
      fs.existsSync(path.join(repo, '.atlas', 'audit-decisions')),
      true,
    )
    assert.equal(
      fs.existsSync(
        path.join(repo, '.atlas', 'migrations', `${lite.migrationId}.json`),
      ),
      true,
    )
    for (const output of lite.writes) {
      const bytes = fs.readFileSync(path.join(repo, ...output.path.split('/')))
      assert.equal(sha256(bytes), output.sha256)
    }
    assert.deepEqual(loadAuditDecisionLedgers(repo).diagnostics, [])
  } finally {
    cleanup(repo)
  }
})

test('honors custom scanRoot and policyPath locations', async () => {  const api = await migrationApi()
  const { root: repo } = makeRepo()
  try {
    fs.rmSync(path.join(repo, ...'.atlas/review-policy.json'.split('/')))
    const scanRoot = 'legacy/security-evidence'
    const policyPath = 'policies/review.json'
    for (const name of SOURCE_FILES) {
      const destination = path.join(repo, ...`${scanRoot}/${name}`.split('/'))
      fs.mkdirSync(path.dirname(destination), { recursive: true })
      fs.renameSync(
        path.join(repo, ...`${SOURCE_ROOT}/${name}`.split('/')),
        destination,
      )
    }
    writeJson(repo, policyPath, {
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
    fs.rmSync(path.join(repo, ...SOURCE_ROOT.split('/')), {
      recursive: true,
      force: true,
    })
    commit(repo, 'relocated corpus and policy')
    const revision = head(repo)

    const result = api.buildRelayOSAuditMigration(repo, {
      scanRoot,
      policyPath,
      sourceRevision: revision,
      validationRevision: revision,
    })
    assert.equal(result.receipt.counts.scanRecords, 457)
    assert.equal(result.receipt.counts.canonicalFindings, 82)
    assert.equal(result.receipt.validation.policy.path, policyPath)
    assert.equal(
      result.receipt.source.files.every(({ path: repoPath }) =>
        repoPath.startsWith(`${scanRoot}/`)),
      true,
    )
    assert.equal(result.receipt.unmapped.length, 0)
  } finally {
    cleanup(repo)
  }
})

test('applied fixture migration reduces through the audit lifecycle reduction path', async () => {
  const api = await migrationApi()
  const {
    buildAuditDecisionIndex,
    loadAuditDecisionLedgers,
    reduceAuditDecisionState,
  } = await import('../dist/audit-decisions.js')
  const { loadAuditReviewPolicy } = await import('../dist/audit-policy.js')
  const { root: repo } = makeRepo()
  try {
    // Replace the legacy-format policy with the atlas-format policy whose
    // digest the migration seals into every review context; the coverage
    // generator loads the same document when it reduces the lifecycle.
    writeJson(repo, '.atlas/review-policy.json', {
      formatVersion: 1,
      format: 'atlas-review-policy-v1',
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
      },
    })
    commit(repo, 'atlas review policy')
    const revision = head(repo)
    const applied = api.migrateRelayOSAudit(
      repo,
      migrationOptions(revision, revision, { apply: true }),
    )
    assert.equal(applied.receipt.counts.canonicalFindings, 82)

    // Feed the applied state into the same lifecycle-reduction path the
    // coverage generator uses (lifecycleAssurance in
    // src/audit-coverage-generator.ts): the same three loaded inputs, the
    // same index builder, and the same reducer. The observation loaders
    // additionally verify legacy blob bytes against the Git object store;
    // those objects exist in the consumer repository but not in this
    // synthetic fixture repository, so the test reads the applied documents
    // directly. A failure here surfaces to consumers as the non-tolerated
    // audit-lifecycle-invalid diagnostic.
    const readDir = (name) =>
      fs.readdirSync(path.join(repo, '.atlas', name))
        .filter((entry) => entry.endsWith('.json'))
        .sort()
        .map((entry) =>
          JSON.parse(fs.readFileSync(
            path.join(repo, '.atlas', name, entry),
            'utf8',
          )))
    const currents = readDir('audits')
    const histories = readDir('audit-history')
    const decisions = loadAuditDecisionLedgers(repo)
    assert.deepEqual(decisions.diagnostics, [])
    const policyLoad = loadAuditReviewPolicy(repo)
    assert.deepEqual(policyLoad.diagnostics, [])
    assert.ok(policyLoad.policy !== null)

    const index = buildAuditDecisionIndex(
      currents,
      histories,
      decisions.ledgers,
    )
    const state = reduceAuditDecisionState(
      index,
      policyLoad.policy.securityDecisions,
      '2026-08-01T00:00:00.000Z',
    )

    const dispositionCounts = new Map()
    const blocking = []
    let implicitOpen = 0
    let governedNonBlocking = 0
    for (const finding of state.findings.values()) {
      if (finding.blocking) blocking.push(finding)
      if (finding.derivation === 'implicit-open') implicitOpen += 1
      if (
        finding.derivation !== 'implicit-open' &&
        finding.disposition !== 'open' &&
        !finding.blocking
      ) {
        governedNonBlocking += 1
      }
      dispositionCounts.set(
        finding.disposition,
        (dispositionCounts.get(finding.disposition) ?? 0) + 1,
      )
    }
    // Every migrated disposition governs its semantic-only occurrence
    // through the deterministic migration validation context: the accepted
    // risks carry to the current exact occurrences, and all 82 governed
    // findings hold their honest non-blocking closure.
    assert.equal(dispositionCounts.get('accepted-risk'), 3)
    assert.equal(dispositionCounts.get('separate-design'), 16)
    assert.equal(dispositionCounts.get('false-positive'), 3)
    assert.equal(dispositionCounts.get('superseded'), 5)
    assert.equal(dispositionCounts.get('remediated'), 55)
    assert.equal(governedNonBlocking, 82)
    // The opaque legacy scan-receipt findings received no decision events:
    // they stay honestly open (blocking under this disposition-requiring
    // policy) instead of being closed by fabricated migration coverage.
    assert.equal(dispositionCounts.get('open'), state.findings.size - 82)
    assert.equal(implicitOpen, state.findings.size - 82)
    assert.equal(blocking.length, state.findings.size - 82)
    assert.equal(
      [...state.findings.values()].filter((finding) =>
        finding.lifecycle === 'resolved').length,
      55,
    )
  } finally {
    cleanup(repo)
  }
})
