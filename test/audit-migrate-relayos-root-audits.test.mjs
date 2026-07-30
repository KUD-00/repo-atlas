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
  'relayos-root-audits',
)
const REPOSITORY_ID = 'repo_relayos_root_audits_fixture'
const ZERO_REVISION = '0'.repeat(40)
const DESIGN_SCAN_FILES = [
  'README.md',
  'findings.md',
  'ledger.json',
  'check.mjs',
  'to-atlas-ledger.mjs',
]
const HISTORICAL_REPORTS = [
  [
    'audits/atlas-suspicion-audit/2026-07-05-report.md',
    'historical/atlas-suspicion-audit/2026-07-05-report.md',
    '.atlas/artifacts/historical-audits/atlas-suspicion-report.md',
  ],
  [
    'audits/atlas-suspicion-audit/2026-07-05-solutions.md',
    'historical/atlas-suspicion-audit/2026-07-05-solutions.md',
    '.atlas/artifacts/historical-audits/atlas-suspicion-solutions.md',
  ],
  [
    'audits/mobile-responsive-audit/findings.md',
    'historical/mobile-responsive-audit/findings.md',
    '.atlas/artifacts/historical-audits/mobile-responsive-findings.md',
  ],
]
const EGRESS_BEFORE = 'audits/security-egress-boundaries.json'
const EGRESS_AFTER = '.atlas/policies/security-egress-boundaries.json'
const DESIGN_V2_LEDGER = '.atlas/audits/design-fixture-layer.json'
const DESIGN_V2_OTHER = '.atlas/audits/design-fixture-other.json'
const SOURCE_PATHS = [
  'audits/atlas-suspicion-audit/2026-07-05-report.md',
  'audits/atlas-suspicion-audit/2026-07-05-solutions.md',
  'audits/design-scan/README.md',
  'audits/design-scan/check.mjs',
  'audits/design-scan/findings.md',
  'audits/design-scan/ledger.json',
  'audits/design-scan/to-atlas-ledger.mjs',
  'audits/mobile-responsive-audit/findings.md',
  'audits/security-egress-boundaries.json',
]

async function migrationApi() {
  try {
    return await import('../dist/audit-migrate-relayos-root-audits.js')
  } catch (error) {
    assert.fail(
      `Task 6C RelayOS root-audits migration API is missing: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

function fixtureBytes(repoRelativeFixturePath) {
  return fs.readFileSync(path.join(FIXTURE_ROOT, repoRelativeFixturePath))
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

function writeSourceCorpus(root) {
  for (const name of DESIGN_SCAN_FILES) {
    write(root, `audits/design-scan/${name}`, fixtureBytes(`design-scan/${name}`))
  }
  for (const [sourcePath, fixturePath] of HISTORICAL_REPORTS) {
    write(root, sourcePath, fixtureBytes(fixturePath))
  }
  write(root, EGRESS_BEFORE, fixtureBytes('security-egress-boundaries.json'))
}

function writeValidationCorpus(root) {
  write(root, DESIGN_V2_LEDGER, fixtureBytes('design-v2/design-fixture-layer.json'))
  write(root, DESIGN_V2_OTHER, fixtureBytes('design-v2/design-fixture-other.json'))
  write(root, EGRESS_AFTER, fixtureBytes('security-egress-boundaries.json'))
}

function makeRepo(writeOrder = 'canonical') {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'repo-atlas-relayos-root-audits-'),
  )
  execFileSync('git', ['init', '-q'], { cwd: root })
  const steps = [
    () =>
      writeJson(root, '.atlas/config.json', {
        formatVersion: 1,
        exclude: [],
        repositoryId: REPOSITORY_ID,
      }),
    () => writeSourceCorpus(root),
    () => writeValidationCorpus(root),
  ]
  for (const step of writeOrder === 'reversed' ? [...steps].reverse() : steps) {
    step()
  }
  commit(root)
  return { root, revision: head(root) }
}

function makeSplitRepo() {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'repo-atlas-relayos-root-audits-split-'),
  )
  execFileSync('git', ['init', '-q'], { cwd: root })
  writeJson(root, '.atlas/config.json', {
    formatVersion: 1,
    exclude: [],
    repositoryId: REPOSITORY_ID,
  })
  writeSourceCorpus(root)
  commit(root, 'phase zero root audit corpus')
  const sourceRevision = head(root)
  fs.rmSync(path.join(root, 'audits'), { recursive: true, force: true })
  writeValidationCorpus(root)
  commit(root, 'reviewed relocation commit')
  const validationRevision = head(root)
  assert.notEqual(sourceRevision, validationRevision)
  return { root, sourceRevision, validationRevision }
}

function cleanup(...roots) {
  for (const root of roots) {
    if (root) fs.rmSync(root, { recursive: true, force: true })
  }
}

function migrationOptions(sourceRevision, validationRevision, overrides = {}) {
  return {
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

function rootAuditsError(name) {
  return (error) => {
    assert.equal(error.name, 'RelayOSRootAuditsMigrationError', name)
    return true
  }
}

function assertZeroWrites(root) {
  assert.equal(fs.existsSync(path.join(root, '.atlas', 'migrations')), false)
  assert.equal(
    fs.existsSync(path.join(root, '.atlas', 'artifacts', 'historical-audits')),
    false,
  )
}

test('seals every root-audit input losslessly and reports zero unmapped durable facts', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  try {
    const before = snapshotTree(repo)
    const first = api.migrateRelayOSRootAudits(
      repo,
      migrationOptions(revision, revision),
    )
    const second = api.migrateRelayOSRootAudits(
      repo,
      migrationOptions(revision, revision),
    )

    assert.deepEqual(second, first)
    assert.equal(first.receipt.formatVersion, 1)
    assert.equal(first.receipt.format, 'atlas-audit-migration-v1')
    assert.match(first.migrationId, /^amig_[0-9a-f]{24}$/)
    assert.equal(first.receipt.migrationId, first.migrationId)
    assert.equal(first.receipt.repositoryId, REPOSITORY_ID)
    assert.equal(first.receipt.source.kind, 'relayos-root-audits/v1')
    assert.equal(first.receipt.source.repositoryRevision, revision)
    assert.equal(first.receipt.validation.repositoryRevision, revision)
    assert.equal(first.receipt.recordedAt, '2026-07-30T03:56:24.000Z')
    assert.equal(first.receipt.recordedAtBasis, 'source-revision')
    assert.equal('executedAt' in first.receipt, false)
    assert.equal('generatedAt' in first.receipt, false)
    assert.equal('wallClock' in first.receipt, false)
    assert.deepEqual(first.receipt.unmapped, [])
    assert.deepEqual(first.receipt.safeToDelete, [])
    assert.match(first.receipt.receiptDigest, /^sha256:[0-9a-f]{64}$/)

    const expectedSeals = new Map([
      ...DESIGN_SCAN_FILES.map((name) => [
        `audits/design-scan/${name}`,
        fixtureBytes(`design-scan/${name}`),
      ]),
      ...HISTORICAL_REPORTS.map(([sourcePath, fixturePath]) => [
        sourcePath,
        fixtureBytes(fixturePath),
      ]),
      [EGRESS_BEFORE, fixtureBytes('security-egress-boundaries.json')],
    ])
    assert.deepEqual(
      first.receipt.source.files.map(({ path: repoPath }) => repoPath),
      SOURCE_PATHS,
    )
    for (const seal of first.receipt.source.files) {
      const bytes = expectedSeals.get(seal.path)
      assert.ok(bytes !== undefined, seal.path)
      assert.equal(seal.gitBlob, gitBlob(bytes), seal.path)
      assert.equal(seal.sha256, sha256(bytes), seal.path)
    }

    assert.deepEqual(first.receipt.counts, {
      sourceFiles: 9,
      designScanRecords: 3,
      designFindings: 2,
      designDropped: 1,
      historicalReports: 3,
      proseRecords: 2,
    })
    assert.equal(first.receipt.validation.policy.path, EGRESS_AFTER)
    assert.match(first.receipt.validation.policy.gitBlob, /^[0-9a-f]{40}$/)
    assert.match(first.receipt.validation.policy.sha256, /^[0-9a-f]{64}$/)
    assert.match(
      first.receipt.validation.historicalAssignmentsDigest,
      /^sha256:[0-9a-f]{64}$/,
    )
    assert.deepEqual(
      first.receipt.validation.designLedgers.map(({ path: repoPath }) => repoPath),
      [DESIGN_V2_LEDGER, DESIGN_V2_OTHER],
    )
    assert.deepEqual(
      first.receipt.parityChecks.map(({ name }) => name),
      [
        'design scan corpus sealed',
        'design V2 ledger parity exact',
        'historical reports projected byte-for-byte',
        'egress policy relocation recorded',
      ],
    )
    for (const check of first.receipt.parityChecks) {
      assert.equal(check.status, 'passed', check.name)
    }
    assert.deepEqual(snapshotTree(repo), before)
    assertZeroWrites(repo)
  } finally {
    cleanup(repo)
  }
})

test('maps every old design-ledger unit and finding to the exact design V2 output', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  try {
    const result = api.buildRelayOSRootAuditsMigration(
      repo,
      migrationOptions(revision, revision),
    )
    const parity = result.receipt.designParity
    assert.equal(parity.ledger.path, DESIGN_V2_LEDGER)
    assert.equal(
      parity.ledger.gitBlob,
      gitBlob(fixtureBytes('design-v2/design-fixture-layer.json')),
    )
    assert.equal(parity.slug, 'design-fixture-layer')
    assert.equal(
      parity.scopeHash,
      '0493deab223d0a6c79adda6e0a503057a90d7eda',
    )
    assert.equal(parity.filesMatched, 3)
    assert.equal(parity.hashesMatched, 3)
    assert.equal(parity.findingsMatched, 2)
    assert.equal(parity.droppedMatched, 1)
    assert.deepEqual(
      parity.proseArtifacts.map(({ path: repoPath }) => repoPath),
      ['audits/design-scan/README.md', 'audits/design-scan/findings.md'],
    )
    for (const prose of parity.proseArtifacts) {
      const bytes = fixtureBytes(`design-scan/${path.basename(prose.path)}`)
      assert.equal(prose.gitBlob, gitBlob(bytes))
      assert.equal(prose.sha256, sha256(bytes))
      assert.equal(prose.bytes, bytes.byteLength)
    }

    const scopeMappings = result.receipt.mappings.filter(
      ({ destinationKind }) => destinationKind === 'design-v2-scope',
    )
    assert.equal(scopeMappings.length, 3)
    assert.equal(
      scopeMappings.every(
        ({ sourcePath, destinationIds }) =>
          sourcePath === 'audits/design-scan/ledger.json' &&
          destinationIds.length === 1 &&
          destinationIds[0] === DESIGN_V2_LEDGER,
      ),
      true,
    )
    assert.deepEqual(
      scopeMappings.map(({ sourceId }) => sourceId).sort(),
      [
        'packages/example/app/src/format.ts@1b6ab0c5f7e24d9a83f0c6d1e5a94b720f3c8d61',
        'packages/example/core/src/types.ts@2c7bc1d6a8f35e0b94a1d7e2f6b05c831a4d9e72',
        'packages/example/core/src/util.ts@3d8cd2e7b9a46f1ca5b2e8f3a7c16d942b5eaf83',
      ],
    )
    const findingMappings = result.receipt.mappings.filter(
      ({ destinationKind }) => destinationKind === 'design-v2-finding',
    )
    assert.deepEqual(
      findingMappings.map(({ sourceId }) => sourceId).sort(),
      [
        'dead-forward-compat@packages/example/app/src/format.ts:3',
        'optionality@packages/example/core/src/types.ts:12',
      ],
    )
    const droppedMappings = result.receipt.mappings.filter(
      ({ destinationKind }) => destinationKind === 'design-v2-dropped',
    )
    assert.equal(droppedMappings.length, 1)
    assert.equal(
      droppedMappings[0].sourceId,
      '**`z.unknown()` fixture outputs** (types/format)',
    )

    // Design V2 ledgers are validated, never rewritten by this migrator.
    assert.equal(
      result.writes.some(({ path: repoPath }) =>
        repoPath.startsWith('.atlas/audits/')),
      false,
    )
    assert.equal(
      result.receipt.outputs.some(({ path: repoPath }) =>
        repoPath.startsWith('.atlas/audits/')),
      false,
    )
    assert.deepEqual(
      result.writes.map(({ path: repoPath }) => repoPath),
      [
        '.atlas/artifacts/historical-audits/atlas-suspicion-report.md',
        '.atlas/artifacts/historical-audits/atlas-suspicion-solutions.md',
        '.atlas/artifacts/historical-audits/mobile-responsive-findings.md',
        `.atlas/migrations/${result.migrationId}.json`,
      ],
    )
  } finally {
    cleanup(repo)
  }
})

test('fails closed when a durable design fact is unmapped in the V2 ledger', async () => {
  const api = await migrationApi()
  const cases = [
    {
      name: 'V2 finding evidence altered',
      mutate(root) {
        const ledger = readJson(root, DESIGN_V2_LEDGER)
        ledger.findings[0].evidence = 'paraphrased evidence'
        writeJson(root, DESIGN_V2_LEDGER, ledger)
      },
    },
    {
      name: 'V2 finding dropped',
      mutate(root) {
        const ledger = readJson(root, DESIGN_V2_LEDGER)
        ledger.findings.pop()
        writeJson(root, DESIGN_V2_LEDGER, ledger)
      },
    },
    {
      name: 'findings.md gains an unmapped finding',
      mutate(root) {
        fs.appendFileSync(
          path.join(root, 'audits', 'design-scan', 'findings.md'),
          '\n### packages/example/core/src/util.ts\n\n' +
            '- **[LOW][over-complication][high]** `util.ts:2` — ' +
            '`clampFixture` re-derives state already stored in `FixtureState`. ' +
            '**Fix:** derive it.\n',
        )
      },
    },
    {
      name: 'V2 scope hash drifted',
      mutate(root) {
        const ledger = readJson(root, DESIGN_V2_LEDGER)
        ledger.scope_hash = '0'.repeat(40)
        writeJson(root, DESIGN_V2_LEDGER, ledger)
      },
    },
    {
      name: 'V2 file hash drifted',
      mutate(root) {
        const ledger = readJson(root, DESIGN_V2_LEDGER)
        ledger.hashes['packages/example/core/src/util.ts'] = '0'.repeat(40)
        writeJson(root, DESIGN_V2_LEDGER, ledger)
      },
    },
    {
      name: 'V2 scope drops a scanned file',
      mutate(root) {
        const ledger = readJson(root, DESIGN_V2_LEDGER)
        ledger.files = ledger.files.filter(
          (repoPath) => repoPath !== 'packages/example/core/src/util.ts',
        )
        writeJson(root, DESIGN_V2_LEDGER, ledger)
      },
    },
    {
      name: 'no V2 ledger claims the design scan',
      mutate(root) {
        const ledger = readJson(root, DESIGN_V2_LEDGER)
        ledger.evidenceRefs = ['audits/elsewhere/ledger.json']
        writeJson(root, DESIGN_V2_LEDGER, ledger)
      },
    },
    {
      name: 'two V2 ledgers claim the design scan',
      mutate(root) {
        const ledger = readJson(root, DESIGN_V2_LEDGER)
        ledger.slug = 'design-fixture-copy'
        writeJson(root, '.atlas/audits/design-fixture-copy.json', ledger)
      },
    },
    {
      name: 'old ledger carries an unknown field',
      mutate(root) {
        const ledger = readJson(root, 'audits/design-scan/ledger.json')
        ledger.unmappedFact = true
        writeJson(root, 'audits/design-scan/ledger.json', ledger)
      },
    },
  ]

  for (const fixtureCase of cases) {
    const { root: repo } = makeRepo()
    try {
      fixtureCase.mutate(repo)
      commit(repo, `unmapped: ${fixtureCase.name}`)
      const revision = head(repo)
      assert.throws(
        () =>
          api.buildRelayOSRootAuditsMigration(
            repo,
            migrationOptions(revision, revision),
          ),
        rootAuditsError(fixtureCase.name),
        fixtureCase.name,
      )
      assert.throws(
        () =>
          api.migrateRelayOSRootAudits(
            repo,
            migrationOptions(revision, revision, { apply: true }),
          ),
        rootAuditsError(fixtureCase.name),
        fixtureCase.name,
      )
      assertZeroWrites(repo)
    } finally {
      cleanup(repo)
    }
  }
})

test('moves the three historical reports byte-for-byte and never deletes sources', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  try {
    const applied = api.migrateRelayOSRootAudits(
      repo,
      migrationOptions(revision, revision, { apply: true }),
    )
    const artifactMappings = applied.receipt.mappings.filter(
      ({ destinationKind }) => destinationKind === 'historical-artifact',
    )
    assert.equal(artifactMappings.length, 3)
    for (const [sourcePath, fixturePath, destinationPath] of HISTORICAL_REPORTS) {
      const sourceBytes = fixtureBytes(fixturePath)
      const written = fs.readFileSync(path.join(repo, ...destinationPath.split('/')))
      assert.deepEqual(written, sourceBytes, destinationPath)
      const mapping = artifactMappings.find(
        ({ sourcePath: mapped }) => mapped === sourcePath,
      )
      assert.ok(mapping !== undefined, sourcePath)
      assert.equal(mapping.sourcePointer, '/')
      assert.equal(mapping.sourceId, gitBlob(sourceBytes))
      assert.deepEqual(mapping.destinationIds, [destinationPath])
      assert.equal(
        fs.existsSync(path.join(repo, ...sourcePath.split('/'))),
        true,
        `source deleted: ${sourcePath}`,
      )
    }
    assert.deepEqual(
      applied.historicalArtifacts.map(({ sourcePath, path: repoPath }) => [
        sourcePath,
        repoPath,
      ]),
      HISTORICAL_REPORTS.map(([sourcePath, , destinationPath]) => [
        sourcePath,
        destinationPath,
      ]),
    )
    for (const artifact of applied.historicalArtifacts) {
      const [sourcePath] = HISTORICAL_REPORTS.find(
        ([candidate]) => candidate === artifact.sourcePath,
      )
      const bytes = fs.readFileSync(path.join(repo, ...sourcePath.split('/')))
      assert.equal(artifact.gitBlob, gitBlob(bytes))
      assert.equal(artifact.sha256, sha256(bytes))
    }
    for (const sourcePath of SOURCE_PATHS) {
      assert.equal(
        fs.existsSync(path.join(repo, ...sourcePath.split('/'))),
        true,
        `source deleted: ${sourcePath}`,
      )
    }
  } finally {
    cleanup(repo)
  }
})

test('records the egress relocation without performing the product-policy move', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  try {
    const before = fs.readFileSync(path.join(repo, ...EGRESS_AFTER.split('/')))
    const applied = api.migrateRelayOSRootAudits(
      repo,
      migrationOptions(revision, revision, { apply: true }),
    )
    const egress = applied.receipt.egressPolicy
    const egressBytes = fixtureBytes('security-egress-boundaries.json')
    assert.equal(egress.before.path, EGRESS_BEFORE)
    assert.equal(egress.before.gitBlob, gitBlob(egressBytes))
    assert.equal(egress.before.sha256, sha256(egressBytes))
    assert.equal(egress.after.path, EGRESS_AFTER)
    assert.equal(egress.after.gitBlob, egress.before.gitBlob)
    assert.equal(egress.after.sha256, egress.before.sha256)
    assert.equal(egress.byteIdentical, true)
    assert.equal(egress.relocatedByThisMigrator, false)
    assert.equal(
      applied.writes.some(({ path: repoPath }) => repoPath === EGRESS_AFTER),
      false,
    )
    assert.equal(
      applied.writes.some(({ path: repoPath }) => repoPath === EGRESS_BEFORE),
      false,
    )
    assert.deepEqual(
      fs.readFileSync(path.join(repo, ...EGRESS_AFTER.split('/'))),
      before,
    )
    const relocation = applied.receipt.mappings.find(
      ({ destinationKind }) => destinationKind === 'policy-relocation',
    )
    assert.equal(relocation.sourcePath, EGRESS_BEFORE)
    assert.deepEqual(relocation.destinationIds, [EGRESS_AFTER])
  } finally {
    cleanup(repo)
  }

  const diverged = makeRepo()
  try {
    write(diverged.root, EGRESS_AFTER, '{"version":2,"boundaries":[]}\n')
    commit(diverged.root, 'diverged egress destination')
    const revision = head(diverged.root)
    assert.throws(
      () =>
        api.migrateRelayOSRootAudits(
          diverged.root,
          migrationOptions(revision, revision, { apply: true }),
        ),
      rootAuditsError('diverged egress destination'),
    )
    assertZeroWrites(diverged.root)
  } finally {
    cleanup(diverged.root)
  }

  const missing = makeRepo()
  try {
    fs.rmSync(path.join(missing.root, ...EGRESS_AFTER.split('/')))
    commit(missing.root, 'missing egress destination')
    const revision = head(missing.root)
    assert.throws(
      () =>
        api.migrateRelayOSRootAudits(
          missing.root,
          migrationOptions(revision, revision, { apply: true }),
        ),
      rootAuditsError('missing egress destination'),
    )
    assertZeroWrites(missing.root)
  } finally {
    cleanup(missing.root)
  }
})

test('dry-run and apply return identical canonical bytes and exact reruns are idempotent', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  try {
    const options = migrationOptions(revision, revision)
    const built = api.buildRelayOSRootAuditsMigration(repo, options)
    const builtWithApplyFlag = api.buildRelayOSRootAuditsMigration(
      repo,
      migrationOptions(revision, revision, { apply: true }),
    )
    const dry = api.migrateRelayOSRootAudits(repo, options)
    assert.deepEqual(dry, built)
    assert.deepEqual(builtWithApplyFlag, built)
    assertZeroWrites(repo)

    const applied = api.migrateRelayOSRootAudits(
      repo,
      migrationOptions(revision, revision, { apply: true }),
    )
    assert.deepEqual(applied, dry)
    for (const output of dry.writes) {
      const bytes = fs.readFileSync(path.join(repo, ...output.path.split('/')))
      assert.equal(sha256(bytes), output.sha256)
    }
    const receiptOnDisk = readJson(
      repo,
      `.atlas/migrations/${dry.migrationId}.json`,
    )
    assert.equal(receiptOnDisk.migrationId, dry.migrationId)
    assert.equal(receiptOnDisk.receiptDigest, dry.receipt.receiptDigest)

    const afterApply = snapshotTree(repo)
    const rerun = api.migrateRelayOSRootAudits(
      repo,
      migrationOptions(revision, revision, { apply: true }),
    )
    assert.deepEqual(rerun, dry)
    assert.deepEqual(snapshotTree(repo), afterApply)
  } finally {
    cleanup(repo)
  }
})

test('derives an identical migration identity regardless of input write order', async () => {
  const api = await migrationApi()
  const first = makeRepo('canonical')
  const second = makeRepo('reversed')
  try {
    assert.equal(first.revision, second.revision)
    const options = migrationOptions(first.revision, first.revision)
    const firstResult = api.buildRelayOSRootAuditsMigration(first.root, options)
    const secondResult = api.buildRelayOSRootAuditsMigration(
      second.root,
      migrationOptions(second.revision, second.revision),
    )
    assert.equal(secondResult.migrationId, firstResult.migrationId)
    assert.deepEqual(secondResult.receipt, firstResult.receipt)

    // Reordering raw source JSON members changes the exact seal and therefore
    // the identity; the migrator never canonicalizes away that provenance.
    const ledger = readJson(first.root, 'audits/design-scan/ledger.json')
    ledger.scans.reverse()
    writeJson(first.root, 'audits/design-scan/ledger.json', ledger)
    commit(first.root, 'reordered scan records')
    const reorderedRevision = head(first.root)
    const reordered = api.buildRelayOSRootAuditsMigration(
      first.root,
      migrationOptions(reorderedRevision, first.revision),
    )
    assert.notEqual(reordered.migrationId, firstResult.migrationId)
    assert.equal(reordered.receipt.counts.designScanRecords, 3)
    assert.deepEqual(reordered.receipt.unmapped, [])
  } finally {
    cleanup(first.root, second.root)
  }
})

test('reads every source and validation byte from the pinned revisions, not the worktree', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  try {
    const options = migrationOptions(revision, revision)
    const clean = api.buildRelayOSRootAuditsMigration(repo, options)

    write(repo, 'audits/design-scan/ledger.json', 'not json at all\n')
    fs.rmSync(
      path.join(
        repo,
        ...'audits/atlas-suspicion-audit/2026-07-05-report.md'.split('/'),
      ),
    )
    write(repo, DESIGN_V2_LEDGER, '{"drifted":true}\n')
    write(repo, 'untracked-junk.txt', 'junk\n')

    const dirty = api.buildRelayOSRootAuditsMigration(repo, options)
    const dirtyDry = api.migrateRelayOSRootAudits(repo, options)
    assert.deepEqual(dirty, clean)
    assert.deepEqual(dirtyDry, clean)
    assert.equal(
      fs.readFileSync(
        path.join(repo, ...'audits/design-scan/ledger.json'.split('/')),
        'utf8',
      ),
      'not json at all\n',
    )
  } finally {
    cleanup(repo)
  }
})

test('supplies pre-move bytes from the source revision when old paths are gone', async () => {
  const api = await migrationApi()
  const { root: repo, sourceRevision, validationRevision } = makeSplitRepo()
  try {
    for (const sourcePath of SOURCE_PATHS) {
      assert.equal(
        fs.existsSync(path.join(repo, ...sourcePath.split('/'))),
        false,
        sourcePath,
      )
    }
    const result = api.migrateRelayOSRootAudits(
      repo,
      migrationOptions(sourceRevision, validationRevision, { apply: true }),
    )
    assert.equal(result.receipt.source.repositoryRevision, sourceRevision)
    assert.equal(result.receipt.validation.repositoryRevision, validationRevision)
    assert.deepEqual(
      result.receipt.source.files.map(({ path: repoPath }) => repoPath),
      SOURCE_PATHS,
    )
    assert.deepEqual(result.receipt.unmapped, [])
    for (const [, fixturePath, destinationPath] of HISTORICAL_REPORTS) {
      assert.deepEqual(
        fs.readFileSync(path.join(repo, ...destinationPath.split('/'))),
        fixtureBytes(fixturePath),
        destinationPath,
      )
    }
    assert.equal(
      fs.existsSync(
        path.join(repo, '.atlas', 'migrations', `${result.migrationId}.json`),
      ),
      true,
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
    const planned = api.buildRelayOSRootAuditsMigration(divergent.root, options)
    const sabotaged = planned.writes.find(({ path: repoPath }) =>
      repoPath.startsWith('.atlas/artifacts/'))
    assert.ok(sabotaged !== undefined)
    write(divergent.root, sabotaged.path, '{"divergent":true}\n')

    assert.throws(
      () =>
        api.migrateRelayOSRootAudits(
          divergent.root,
          migrationOptions(divergent.revision, divergent.revision, {
            apply: true,
          }),
        ),
      (error) => {
        assert.equal(error.name, 'RelayOSRootAuditsMigrationError')
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
    api.buildRelayOSRootAuditsMigration(drifted.root, options)
    write(drifted.root, '.atlas/config.json', 'not json at all\n')
    assert.throws(
      () =>
        api.migrateRelayOSRootAudits(
          drifted.root,
          migrationOptions(drifted.revision, drifted.revision, { apply: true }),
        ),
      /config|JSON|audit/i,
    )
    assertZeroWrites(drifted.root)
  } finally {
    cleanup(drifted.root)
  }
})

test('rejects malformed or inconsistent inputs with typed errors and zero writes', async () => {
  const api = await migrationApi()
  const { root: repo, revision } = makeRepo()
  const optionCases = [
    ['options omitted', undefined],
    ['sourceRevision missing', { validationRevision: revision }],
    ['validationRevision missing', { sourceRevision: revision }],
    ['sourceRevision is a symbolic ref', migrationOptions('HEAD', revision)],
    [
      'sourceRevision is abbreviated',
      migrationOptions(revision.slice(0, 12), revision),
    ],
    [
      'sourceRevision is uppercase',
      migrationOptions(revision.toUpperCase(), revision),
    ],
    ['sourceRevision is unknown', migrationOptions(ZERO_REVISION, revision)],
    ['validationRevision is unknown', migrationOptions(revision, ZERO_REVISION)],
    [
      'validationRevision is not a 40-hex commit',
      migrationOptions(revision, 'a'.repeat(64)),
    ],
    [
      'unknown option key',
      { ...migrationOptions(revision, revision), scanRoot: 'audits' },
    ],
  ]
  try {
    for (const [name, options] of optionCases) {
      assert.throws(
        () => api.buildRelayOSRootAuditsMigration(repo, options),
        rootAuditsError(name),
        `build: ${name}`,
      )
      assert.throws(
        () => api.migrateRelayOSRootAudits(repo, options),
        rootAuditsError(name),
        `migrate: ${name}`,
      )
    }
    assertZeroWrites(repo)
  } finally {
    cleanup(repo)
  }

  const corpusCases = [
    {
      name: 'ledger.json is not JSON',
      mutate(root) {
        write(root, 'audits/design-scan/ledger.json', 'not json at all\n')
      },
    },
    {
      name: 'ledger.json is a symlink',
      mutate(root) {
        const target = path.join(root, 'audits', 'design-scan', 'ledger.json')
        fs.rmSync(target)
        fs.symlinkSync('findings.md', target)
      },
    },
    {
      name: 'a historical report is missing at the source revision',
      mutate(root) {
        fs.rmSync(
          path.join(
            root,
            ...'audits/mobile-responsive-audit/findings.md'.split('/'),
          ),
        )
      },
    },
    {
      name: 'the egress policy is missing at the source revision',
      mutate(root) {
        fs.rmSync(path.join(root, ...EGRESS_BEFORE.split('/')))
      },
    },
    {
      name: 'a design-scan tool is missing at the source revision',
      mutate(root) {
        fs.rmSync(path.join(root, 'audits', 'design-scan', 'check.mjs'))
      },
    },
  ]
  for (const fixtureCase of corpusCases) {
    const { root: mutated } = makeRepo()
    try {
      fixtureCase.mutate(mutated)
      commit(mutated, `malformed input: ${fixtureCase.name}`)
      const mutatedRevision = head(mutated)
      assert.throws(
        () =>
          api.buildRelayOSRootAuditsMigration(
            mutated,
            migrationOptions(mutatedRevision, mutatedRevision),
          ),
        rootAuditsError(fixtureCase.name),
        fixtureCase.name,
      )
      assert.throws(
        () =>
          api.migrateRelayOSRootAudits(
            mutated,
            migrationOptions(mutatedRevision, mutatedRevision, { apply: true }),
          ),
        rootAuditsError(fixtureCase.name),
        fixtureCase.name,
      )
      assertZeroWrites(mutated)
    } finally {
      cleanup(mutated)
    }
  }
})

test('honors custom auditsRoot, designLedgersPath, and historicalArtifactsPath', async () => {
  const api = await migrationApi()
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), 'repo-atlas-relayos-root-audits-custom-'),
  )
  try {
    execFileSync('git', ['init', '-q'], { cwd: root })
    writeJson(root, '.atlas/config.json', {
      formatVersion: 1,
      exclude: [],
      repositoryId: REPOSITORY_ID,
    })
    const auditsRoot = 'legacy/audits'
    for (const name of DESIGN_SCAN_FILES) {
      write(
        root,
        `${auditsRoot}/design-scan/${name}`,
        fixtureBytes(`design-scan/${name}`),
      )
    }
    for (const [sourcePath, fixturePath] of HISTORICAL_REPORTS) {
      write(
        root,
        sourcePath.replace(/^audits\//u, `${auditsRoot}/`),
        fixtureBytes(fixturePath),
      )
    }
    write(
      root,
      `${auditsRoot}/security-egress-boundaries.json`,
      fixtureBytes('security-egress-boundaries.json'),
    )
    const designLedgersPath = 'atlas-mirror/design'
    const claiming = JSON.parse(
      fixtureBytes('design-v2/design-fixture-layer.json').toString('utf8'),
    )
    claiming.evidenceRefs = [
      `${auditsRoot}/design-scan/ledger.json`,
      `${auditsRoot}/design-scan/findings.md`,
    ]
    writeJson(root, `${designLedgersPath}/design-fixture-layer.json`, claiming)
    write(
      root,
      EGRESS_AFTER,
      fixtureBytes('security-egress-boundaries.json'),
    )
    commit(root)
    const revision = head(root)

    const result = api.migrateRelayOSRootAudits(root, {
      auditsRoot,
      designLedgersPath,
      historicalArtifactsPath: 'atlas-mirror/historical',
      sourceRevision: revision,
      validationRevision: revision,
      apply: true,
    })
    assert.equal(
      result.receipt.source.files.every(({ path: repoPath }) =>
        repoPath.startsWith(`${auditsRoot}/`)),
      true,
    )
    assert.equal(result.receipt.designParity.ledger.path,
      `${designLedgersPath}/design-fixture-layer.json`)
    assert.deepEqual(
      result.historicalArtifacts.map(({ path: repoPath }) => repoPath),
      [
        'atlas-mirror/historical/atlas-suspicion-report.md',
        'atlas-mirror/historical/atlas-suspicion-solutions.md',
        'atlas-mirror/historical/mobile-responsive-findings.md',
      ],
    )
    for (const [, fixturePath, destinationPath] of HISTORICAL_REPORTS) {
      const custom = destinationPath.replace(
        /^\.atlas\/artifacts\/historical-audits\//u,
        'atlas-mirror/historical/',
      )
      assert.deepEqual(
        fs.readFileSync(path.join(root, ...custom.split('/'))),
        fixtureBytes(fixturePath),
        custom,
      )
    }
    assert.deepEqual(result.receipt.unmapped, [])
  } finally {
    cleanup(root)
  }
})
