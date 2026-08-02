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
const LEGACY_MOVED_PATH =
  'packages/runners/providers/anthropic-managed-agent/src/client.ts'
const LEGACY_SUCCESSOR_PATH =
  'apps/daemon/src/inference-relay/secure-outbound-transport.ts'

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
    path.join(os.tmpdir(), 'repo-atlas-relayos-migration-'),
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

function baselineFileReceipts(result) {
  return result.observations
    .filter(({ producer }) => producer.runId.endsWith('/baseline'))
    .flatMap(({ scope }) =>
      scope.identityBasis === 'exact-inventory' ? scope.files : [])
}

function candidateFindings(result) {
  return result.observations
    .filter(({ producer }) => producer.runId.endsWith('/candidates'))
    .flatMap(({ findings }) => findings)
}

function semanticIds(result) {
  return {
    observations: result.observations.map(({ observationId }) => observationId),
    findings: result.observations
      .flatMap(({ findings }) => findings)
      .map(({ findingId }) => findingId),
    occurrences: result.observations
      .flatMap(({ findings }) => findings)
      .map(({ occurrenceId }) => occurrenceId),
  }
}

test('maps the real-shape RelayOS corpus losslessly without inventing semantic closure', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  try {
    const first = api.migrateRelayOSAudit(
      repo,
      migrationOptions(revision, revision),
    )
    const second = api.migrateRelayOSAudit(
      repo,
      migrationOptions(revision, revision),
    )

    assert.deepEqual(second, first)
    assert.equal(first.receipt.format, 'atlas-audit-migration-v1')
    assert.match(first.migrationId, /^amig_[0-9a-f]{24}$/)
    assert.equal(first.receipt.migrationId, first.migrationId)
    assert.equal(first.receipt.repositoryId, REPOSITORY_ID)
    assert.equal(first.receipt.source.repositoryRevision, revision)
    assert.equal(first.receipt.validation.repositoryRevision, revision)
    assert.equal(
      first.receipt.validation.policy.path,
      '.atlas/review-policy.json',
    )
    assert.match(first.receipt.validation.policy.gitBlob, /^[0-9a-f]{40}$/)
    assert.match(first.receipt.validation.policy.sha256, /^[0-9a-f]{64}$/)
    assert.match(
      first.receipt.validation.historicalAssignmentsDigest,
      /^sha256:[0-9a-f]{64}$/,
    )
    assert.equal('executedAt' in first.receipt, false)
    assert.equal('generatedAt' in first.receipt, false)
    assert.equal('wallClock' in first.receipt, false)
    assert.deepEqual(first.receipt.unmapped, [])
    assert.deepEqual(first.receipt.counts, {
      scanRecords: 457,
      activeScanRecords: 241,
      retiredScanRecords: 216,
      activeClean: 224,
      activeFindings: 17,
      activeFindingOccurrences: 19,
      candidateSourceRecords: 84,
      canonicalFindings: 82,
      duplicateCandidates: 2,
      dispositions: {
        remediated: 55,
        separateDesign: 16,
        acceptedRisk: 3,
        falsePositive: 3,
        superseded: 5,
      },
    })

    const receipts = baselineFileReceipts(first)
    assert.equal(receipts.length, 457)
    assert.equal(new Set(receipts.map(({ path }) => path)).size, 457)
    assert.equal(receipts.filter(({ outcome }) => outcome === 'clean').length, 410)
    assert.equal(receipts.every(({ status }) => status === 'reviewed'), true)
    assert.equal(
      receipts.every(({ reviewedAtPrecision }) =>
        reviewedAtPrecision === 'date'),
      true,
    )
    assert.equal(
      receipts.every(({ ruleset }) => ruleset === 'relayos-security-v1'),
      true,
    )

    const findings = candidateFindings(first)
    assert.equal(findings.length, 82)
    assert.equal(new Set(findings.map(({ findingId }) => findingId)).size, 82)
    assert.equal(findings.every((finding) => !('confidence' in finding)), true)
    assert.equal(
      findings.every(({ provenance }) =>
        provenance.source === 'relayos-security-scan/v1'),
      true,
    )
    assert.equal(
      first.observations.every(({ semanticCoverage }) =>
        semanticCoverage.completeness === 'unknown'),
      true,
    )

    const actions = Object.groupBy(
      first.decisionEvents,
      ({ action }) => action,
    )
    assert.equal(actions.remediated?.length, 55)
    assert.equal(actions['separate-design']?.length, 16)
    assert.equal(actions['accepted-risk']?.length, 3)
    assert.equal(actions['false-positive']?.length, 3)
    assert.equal(actions.superseded?.length, 5)
    assert.equal(first.retirementEvents.length, 216)
    assert.equal(
      first.retirementEvents.filter(({ reason }) =>
        reason === 'uncommitted-snapshot-absent').length,
      4,
    )
    const successorRetirement = first.retirementEvents.find(
      ({ path: retiredPath }) => retiredPath === LEGACY_MOVED_PATH,
    )
    assert.equal(successorRetirement.reason, 'superseded')
    assert.equal(successorRetirement.successor.path, LEGACY_SUCCESSOR_PATH)
    assert.equal(first.reconciliationEvents.length, 84)
    assert.equal(
      first.reconciliationEvents.filter(({ relationship }) =>
        relationship === 'duplicate-of').length,
      2,
    )
    assert.equal(first.writes.some(({ path: repoPath }) =>
      repoPath === `.atlas/migrations/${first.migrationId}.json`), true)
    assert.deepEqual(
      first.writes
        .map(({ path: repoPath }) => repoPath)
        .filter((repoPath) => repoPath.startsWith('.atlas/audits/')),
      [
        '.atlas/audits/security-fixture-apps.json',
        '.atlas/audits/security-fixture-github.json',
        '.atlas/audits/security-fixture-packages.json',
      ],
    )
  } finally {
    cleanup(repo)
  }
})

test('retains exact finding evidence only for matching repository bytes', async () => {
  const api = await migrationApi()
  const { root: repo } = makeRepo()
  const candidateId = 'SEC-48AABC8B1EB6'
  const sourcePath =
    'packages/kernel/governance-relay/src/runtime/transition.ts'
  const sourceBytes = Buffer.from(
    Array.from({ length: 20 }, (_, index) =>
      `export const line${index + 1} = ${index + 1}\n`).join(''),
    'utf8',
  )
  const blob = gitBlob(sourceBytes)
  try {
    write(repo, sourcePath, sourceBytes)
    const ledger = readJson(repo, `${SOURCE_ROOT}/ledger.json`)
    const scan = ledger.scans.find(({ path: candidatePath }) =>
      candidatePath === sourcePath)
    scan.git_blob_sha1 = blob
    scan.lines = 21
    writeJson(repo, `${SOURCE_ROOT}/ledger.json`, ledger)

    const candidates = readJson(repo, `${SOURCE_ROOT}/candidates.v1.json`)
    const candidate = candidates.entries.find(({ id }) => id === candidateId)
    candidate.sourceBlob = blob
    writeJson(repo, `${SOURCE_ROOT}/candidates.v1.json`, candidates)

    const dispositions =
      readJson(repo, `${SOURCE_ROOT}/dispositions.v1.json`)
    const disposition =
      dispositions.dispositions.find(({ id }) => id === candidateId)
    disposition.sourceBlob = blob
    disposition.reviewedBlob = blob
    disposition.currentScan.reviewedBlob = blob
    writeJson(repo, `${SOURCE_ROOT}/dispositions.v1.json`, dispositions)

    const provenance =
      readJson(repo, `${SOURCE_ROOT}/phase-zero-provenance.v1.json`)
    const legacy = provenance.legacyRecords.find(({ path: candidatePath }) =>
      candidatePath === sourcePath)
    legacy.sourceBlob = blob
    writeJson(
      repo,
      `${SOURCE_ROOT}/phase-zero-provenance.v1.json`,
      provenance,
    )
    commit(repo, 'matching candidate bytes')
    const matchingRevision = head(repo)

    const matching = api.migrateRelayOSAudit(
      repo,
      migrationOptions(matchingRevision, matchingRevision),
    )
    const exactFinding = matching.observations
      .filter(({ producer }) => producer.runId.endsWith('/current'))
      .flatMap(({ findings }) => findings)
      .find(({ fingerprints }) => fingerprints.some(({ value }) =>
        value === candidateId))
    assert.equal(exactFinding.codeEvidence?.[0]?.blob, `git-sha1:${blob}`)
    const exactReceipt = baselineFileReceipts(matching)
      .find(({ path: receiptPath }) => receiptPath === sourcePath)
    assert.equal(exactReceipt.lines, 20)
    const declaredLine = matching.observations
      .filter(({ producer }) => producer.runId.endsWith('/baseline'))
      .flatMap(({ producerExtensions }) => producerExtensions)
      .flatMap(({ value }) => value)
      .find(({ path: declaredPath }) => declaredPath === sourcePath)
    assert.equal(declaredLine.lines, 21)

    write(repo, sourcePath, `${sourceBytes.toString('utf8')}// drift\n`)
    commit(repo, 'drift candidate bytes')
    const driftedRevision = head(repo)
    const drifted = api.migrateRelayOSAudit(
      repo,
      migrationOptions(matchingRevision, driftedRevision),
    )
    const driftedFinding = drifted.observations
      .filter(({ producer }) => producer.runId.endsWith('/current'))
      .flatMap(({ findings }) => findings)
      .find(({ fingerprints }) => fingerprints.some(({ value }) =>
        value === candidateId))
    assert.equal(driftedFinding.codeEvidence, undefined)
    assert.equal(
      drifted.receipt.source.repositoryRevision,
      matchingRevision,
    )
    assert.equal(
      drifted.receipt.validation.repositoryRevision,
      driftedRevision,
    )
    assert.notEqual(drifted.migrationId, matching.migrationId)
  } finally {
    cleanup(repo)
  }
})

test('keeps semantic identities stable while preserving reordered raw-byte seals', async () => {
  const api = await migrationApi()
  const { root: repo, revision: originalRevision } = makeRepo()
  try {
    const original = api.migrateRelayOSAudit(
      repo,
      migrationOptions(originalRevision, originalRevision),
    )
    for (const [name, member] of [
      ['ledger.json', 'scans'],
      ['candidates.v1.json', 'entries'],
      ['dispositions.v1.json', 'dispositions'],
      ['phase-zero-provenance.v1.json', 'legacyRecords'],
    ]) {
      const value = readJson(repo, `${SOURCE_ROOT}/${name}`)
      value[member].reverse()
      writeJson(repo, `${SOURCE_ROOT}/${name}`, value)
    }
    commit(repo, 'reordered legacy corpus')
    const reorderedRevision = head(repo)
    const reordered = api.migrateRelayOSAudit(
      repo,
      migrationOptions(reorderedRevision, originalRevision),
    )

    assert.deepEqual(semanticIds(reordered), semanticIds(original))
    assert.deepEqual(reordered.observations, original.observations)
    assert.equal(
      reordered.receipt.source.repositoryRevision,
      reorderedRevision,
    )
    assert.equal(
      reordered.receipt.validation.repositoryRevision,
      originalRevision,
    )
    assert.notEqual(reordered.migrationId, original.migrationId)
    assert.notDeepEqual(reordered.receipt.source.files, original.receipt.source.files)
    assert.deepEqual(
      reordered.writes.filter(({ path: repoPath }) =>
        repoPath.startsWith('.atlas/audit-history/') ||
        repoPath.startsWith('.atlas/audits/')),
      original.writes.filter(({ path: repoPath }) =>
        repoPath.startsWith('.atlas/audit-history/') ||
        repoPath.startsWith('.atlas/audits/')),
    )
  } finally {
    cleanup(repo)
  }
})

test('apply publishes the dry-run bytes once and exact reruns are idempotent', async () => {
  const api = await migrationApi()
  const { loadAuditDecisionLedgers } =
    await import('../dist/audit-decisions.js')
  const { root: repo, revision } = makeRepo()
  try {
    const dry = api.migrateRelayOSAudit(
      repo,
      migrationOptions(revision, revision),
    )
    const applied = api.migrateRelayOSAudit(
      repo,
      migrationOptions(revision, revision, { apply: true }),
    )
    assert.deepEqual(applied, dry)
    for (const output of dry.writes) {
      const bytes = fs.readFileSync(
        path.join(repo, ...output.path.split('/')),
      )
      assert.equal(sha256(bytes), output.sha256)
      assert.equal(bytes.at(-1), 0x0a)
    }
    assert.deepEqual(loadAuditDecisionLedgers(repo).diagnostics, [])
    const before = new Map(dry.writes.map(({ path: repoPath }) => [
      repoPath,
      fs.readFileSync(path.join(repo, ...repoPath.split('/'))),
    ]))
    const rerun = api.migrateRelayOSAudit(
      repo,
      migrationOptions(revision, revision, { apply: true }),
    )
    assert.deepEqual(rerun, dry)
    for (const [repoPath, bytes] of before) {
      assert.deepEqual(
        fs.readFileSync(path.join(repo, ...repoPath.split('/'))),
        bytes,
      )
    }

    const ledger = readJson(repo, `${SOURCE_ROOT}/ledger.json`)
    ledger.scanner.run = `${ledger.scanner.run} changed`
    writeJson(repo, `${SOURCE_ROOT}/ledger.json`, ledger)
    commit(repo, 'scanner identity drift')
    const changedRevision = head(repo)
    const changed = api.migrateRelayOSAudit(
      repo,
      migrationOptions(changedRevision, revision),
    )
    assert.notEqual(changed.migrationId, dry.migrationId)
  } finally {
    cleanup(repo)
  }
})

test('rejects malformed or inconsistent sources before any migration write', async () => {
  const api = await migrationApi()
  const cases = [
    {
      name: 'unknown ledger field',
      mutate(root) {
        const ledger = readJson(root, `${SOURCE_ROOT}/ledger.json`)
        ledger.unmappedFact = true
        writeJson(root, `${SOURCE_ROOT}/ledger.json`, ledger)
      },
    },
    {
      name: 'duplicate candidate ID',
      mutate(root) {
        const candidates =
          readJson(root, `${SOURCE_ROOT}/candidates.v1.json`)
        candidates.entries[1].id = candidates.entries[0].id
        writeJson(root, `${SOURCE_ROOT}/candidates.v1.json`, candidates)
      },
    },
    {
      name: 'missing disposition',
      mutate(root) {
        const dispositions =
          readJson(root, `${SOURCE_ROOT}/dispositions.v1.json`)
        dispositions.dispositions.pop()
        writeJson(root, `${SOURCE_ROOT}/dispositions.v1.json`, dispositions)
      },
    },
    {
      name: 'bad provenance blob',
      mutate(root) {
        const provenance =
          readJson(root, `${SOURCE_ROOT}/phase-zero-provenance.v1.json`)
        const [candidate] = provenance.round9SourceBlobs
          ? Object.keys(provenance.round9SourceBlobs)
          : []
        provenance.round9SourceBlobs[candidate] = '0'.repeat(40)
        writeJson(
          root,
          `${SOURCE_ROOT}/phase-zero-provenance.v1.json`,
          provenance,
        )
      },
    },
    {
      name: 'overlapping policy units',
      mutate(root) {
        const policy = readJson(root, '.atlas/review-policy.json')
        policy.units.push({
          domain: 'security',
          slug: 'security-fixture-apps-conflict',
          title: 'Conflicting fixture applications',
          include: ['apps/**'],
        })
        writeJson(root, '.atlas/review-policy.json', policy)
      },
    },
  ]

  for (const fixtureCase of cases) {
    const { root: repo } = makeRepo()
    try {
      fixtureCase.mutate(repo)
      commit(repo, `malformed input: ${fixtureCase.name}`)
      const revision = head(repo)
      assert.throws(
        () => api.migrateRelayOSAudit(
          repo,
          migrationOptions(revision, revision, { apply: true }),
        ),
        (error) => {
          assert.equal(error.name, 'RelayOSMigrationError', fixtureCase.name)
          assert.match(
            error.message,
            /RelayOS|legacy|candidate|disposition|provenance|unknown|duplicate|missing|inconsistent/i,
          )
          return true
        },
        fixtureCase.name,
      )
      assert.equal(fs.existsSync(path.join(repo, '.atlas/migrations')), false)
      assert.equal(fs.existsSync(path.join(repo, '.atlas/audit-history')), false)
      assert.equal(fs.existsSync(path.join(repo, '.atlas/audit-decisions')), false)
      assert.equal(fs.existsSync(path.join(repo, '.atlas/audits')), false)
    } finally {
      cleanup(repo)
    }
  }
})
