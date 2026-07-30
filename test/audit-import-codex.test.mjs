import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  computeAuditCanonicalDigest,
  computeAtlasFindingId,
  computeAtlasFingerprint,
  computeAtlasObservationId,
  computeAtlasOccurrenceId,
  computeSemanticScopeIdentityDigest,
  parseAuditCurrentLedger,
} from '../dist/audit-v3.js'
import { AUDIT_LIMITS } from '../dist/audit-core.js'

const FIXTURE_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  'fixtures',
  'codex-security',
)
const REPOSITORY_ID = 'repo_codex_import_fixture'
const UNIT_SLUG = 'security-codex-import'
const UNIT_TITLE = 'Codex Security import'
const ADAPTER_NAME = 'repo-atlas/codex-security-v1'
const ADAPTER_VERSION = '0.1.0'
const UNAVAILABLE_REASON =
  'Codex Security 1.0 did not supply exact per-file blob receipts.'
const OFFICIAL_FINGERPRINT =
  'codex-security/v1:sha256:990a4a6a2ec18440dd47eac4d7256c0ee2c02db1b43104720cab3cbe9db706ca'
const OFFICIAL_FINDING_ID = 'csf_852f90d6e1177502ff113d4a'
const OFFICIAL_OCCURRENCE_ID = 'occ_e79cb19591e696572a1c22be'
const SOURCE_SNAPSHOT_DIGEST =
  `codex-security-snapshot/v1:sha256:${'7'.repeat(64)}`

async function importerApi() {
  try {
    return await import('../dist/audit-import-codex.js')
  } catch (error) {
    assert.fail(
      `Task 5 Codex Security importer API is missing: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8')
}

function readRecipe(name) {
  return JSON.parse(
    fs.readFileSync(path.join(FIXTURE_ROOT, name), 'utf8'),
  )
}

function clone(value) {
  return structuredClone(value)
}

function writeFile(root, repoPath, contents) {
  const target = path.join(root, ...repoPath.split('/'))
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, contents)
}

function writeJson(root, repoPath, value) {
  writeFile(root, repoPath, jsonBytes(value))
}

function materializeBundle(name = 'clean-bundle.json') {
  const recipe = clone(readRecipe(name))
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-codex-bundle-'))
  for (const [repoPath, contents] of Object.entries(recipe.files ?? {})) {
    writeFile(root, repoPath, contents)
  }
  writeJson(root, 'findings.json', recipe.findings)
  writeJson(root, 'coverage.json', recipe.coverage)
  resealBundle(root, recipe.manifest)
  return { root, recipe }
}

function resealBundle(root, manifest = readJson(root, 'scan-manifest.json')) {
  const next = clone(manifest)
  for (const artifact of next.scan.artifacts) {
    const artifactPath = path.join(root, ...artifact.path.split('/'))
    artifact.sha256 = sha256(fs.readFileSync(artifactPath))
  }
  writeJson(root, 'scan-manifest.json', next)
  return next
}

function readJson(root, repoPath) {
  return JSON.parse(
    fs.readFileSync(path.join(root, ...repoPath.split('/')), 'utf8'),
  )
}

function rewriteJson(root, repoPath, mutate, reseal = true) {
  const value = readJson(root, repoPath)
  mutate(value)
  writeJson(root, repoPath, value)
  if (reseal && repoPath !== 'scan-manifest.json') resealBundle(root)
  return value
}

function makeRepo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-codex-repo-'))
  execFileSync('git', ['init', '-q'], { cwd: root })
  writeJson(root, '.atlas/config.json', {
    formatVersion: 1,
    exclude: [],
    repositoryId: REPOSITORY_ID,
  })
  writeFile(root, 'src/extract.py', 'destination.write_bytes(entry.read())\n')
  execFileSync('git', ['add', '-A'], { cwd: root })
  execFileSync('git', ['commit', '-qm', 'fixture'], {
    cwd: root,
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Repo Atlas Fixture',
      GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
      GIT_COMMITTER_NAME: 'Repo Atlas Fixture',
      GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
      GIT_AUTHOR_DATE: '2026-05-31T18:09:00.000Z',
      GIT_COMMITTER_DATE: '2026-05-31T18:09:00.000Z',
    },
  })
  return root
}

function cleanup(...roots) {
  for (const root of roots) {
    if (root) fs.rmSync(root, { recursive: true, force: true })
  }
}

function importOptions(bundlePath, overrides = {}) {
  return {
    bundlePath,
    unitSlug: UNIT_SLUG,
    unitTitle: UNIT_TITLE,
    conceptSlug: 'security',
    ...overrides,
  }
}

function findArtifact(observation, artifactPath) {
  return observation.sourceArtifacts.find(({ path: candidate }) =>
    candidate === artifactPath
  )
}

function extensionMap(rows) {
  return new Map(rows.map((row) => [`${row.namespace}:${row.path}`, row]))
}

test('imports an official-contract clean bundle as semantic evidence without exact receipts', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle()
  try {
    const first = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    )
    const second = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    )

    assert.equal(first.applied, false)
    assert.equal(first.publication, undefined)
    assert.equal(first.currentBytes, second.currentBytes)
    assert.equal(first.observation.reviewState, 'complete')
    assert.equal(first.observation.observedAt, '2026-05-31T18:09:00.000Z')
    assert.deepEqual(first.observation.exactCoverage, {
      completeness: 'unknown',
      basis: 'unavailable',
      reason: UNAVAILABLE_REASON,
    })
    assert.equal(first.observation.scope.identityBasis, 'semantic-declaration')
    assert.equal(first.observation.scope.mode, 'repository')
    assert.deepEqual(first.observation.scope.includePaths, ['.'])
    assert.equal(first.observation.target.kind, 'git-revision')
    assert.equal(first.observation.target.sourceKind, 'git_revision')
    assert.equal(first.observation.target.sourceRevision, 'deadbeef')
    assert.equal(first.observation.target.revision, undefined)
    assert.equal(first.observation.target.dirty, undefined)
    assert.equal(first.observation.producer.identityBasis, 'codex-contract')
    assert.equal(first.observation.producer.ruleset, undefined)
    assert.equal(first.observation.producer.prompt, undefined)
    assert.equal(first.observation.scope.artifactsReviewed, undefined)
    assert.equal(first.observation.scope.limitations, undefined)
    assert.equal(first.observation.semanticCoverage.openQuestions, undefined)
    assert.equal(first.observation.threatModel, undefined)
    assert.equal(first.observation.hardening, undefined)
    assert.deepEqual(first.observation.findings, [])
    assert.equal(
      fs.existsSync(path.join(repo, '.atlas', 'audits', `${UNIT_SLUG}.json`)),
      false,
    )

    const expectedProducerIdentity = computeAuditCanonicalDigest({
      namespace: 'repo-atlas/codex-contract-identity/v1',
      documents: [
        'codex-security.scan-manifest/1.0',
        'codex-security.findings/1.0',
        'codex-security.coverage/1.0',
      ],
      producer: {
        name: 'codex-security-plugin',
        version: '0.1.0',
      },
      adapter: {
        name: ADAPTER_NAME,
        version: ADAPTER_VERSION,
      },
    })
    assert.equal(
      first.observation.producer.identityDigest,
      expectedProducerIdentity,
    )
    const expectedScopeIdentity = computeSemanticScopeIdentityDigest({
      mode: 'repository',
      inventoryStrategy: 'repository',
      includePaths: ['.'],
      excludePaths: [],
      explicitExclusions: [],
    })
    assert.equal(
      first.observation.scope.identityDigest,
      expectedScopeIdentity,
    )
    assert.equal(
      first.observation.observationId,
      computeAtlasObservationId({
        slug: UNIT_SLUG,
        adapter: ADAPTER_NAME,
        runId: 'scan_clean_001',
        producerIdentityDigest: expectedProducerIdentity,
        targetId: 'target_clean_example',
        targetIdentityDigest: first.observation.target.identityDigest,
        scopeIdentityDigest: expectedScopeIdentity,
      }),
    )

    for (const [artifactPath, integrityKind] of [
      ['scan-manifest.json', 'adapter-bundle'],
      ['findings.json', 'producer-manifest'],
      ['coverage.json', 'producer-manifest'],
    ]) {
      const artifact = findArtifact(first.observation, artifactPath)
      assert.equal(artifact.integrityKind, integrityKind)
      assert.equal(
        artifact.sha256,
        sha256(fs.readFileSync(path.join(bundle.root, artifactPath))),
      )
      assert.equal(artifact.retainedInAtlas, false)
    }
    assert.deepEqual(
      parseAuditCurrentLedger(
        repo,
        `.atlas/audits/${UNIT_SLUG}.json`,
        first.ledger,
      ),
      { ok: true, value: first.ledger },
    )
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('losslessly maps rich findings, sealed snippets, external writeups, and scan hardening', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle('finding-bundle.json')
  try {
    const result = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    )
    const observation = result.observation
    const finding = observation.findings[0]
    const atlasFingerprint = computeAtlasFingerprint({
      repositoryId: REPOSITORY_ID,
      domain: 'security',
      ruleId: 'path-traversal.archive-extraction',
      anchor: 'archive-entry-write-without-containment',
    })

    assert.equal(finding.findingId, computeAtlasFindingId(atlasFingerprint))
    assert.equal(
      finding.occurrenceId,
      computeAtlasOccurrenceId(observation.observationId, atlasFingerprint),
    )
    assert.deepEqual(finding.fingerprints, [
      {
        scheme: 'atlas/v1',
        value: atlasFingerprint,
        role: 'canonical',
      },
      {
        scheme: 'codex-security/v1',
        value: OFFICIAL_FINGERPRINT,
        role: 'producer',
      },
    ])
    assert.deepEqual(
      [finding.provenance.sourceFindingId, finding.provenance.sourceOccurrenceId],
      [OFFICIAL_FINDING_ID, OFFICIAL_OCCURRENCE_ID],
    )
    assert.equal(finding.provenance.source, 'codex-security')
    assert.equal(finding.provenance.producerSource, 'local_plugin')
    assert.equal(finding.provenance.candidateId, 'candidate-17')
    assert.equal(finding.provenance.ledgerRowId, 'ledger-22')
    assert.equal(finding.provenance.reportId, 'report-4')

    assert.deepEqual(
      finding.locations.map(({ path: locationPath }) => locationPath),
      ['src/extract.py', 'support/archive.py'],
      'the importer must not invent a location-to-scope join',
    )
    assert.equal(finding.codeEvidence[0].evidenceBasis, 'sealed-producer-snippet')
    assert.equal(finding.codeEvidence[0].blob, undefined)
    assert.deepEqual(finding.codeEvidence[0].sourceSeal, {
      artifactPath: 'findings.json',
      artifactSha256: sha256(
        fs.readFileSync(path.join(bundle.root, 'findings.json')),
      ),
      jsonPointer: '/findings/0/codeEvidence/0',
    })
    assert.deepEqual(finding.rootCause.legacyCode, {
      code: 'destination.write_bytes(entry.read())',
      language: 'python',
    })
    assert.deepEqual(
      finding.validation.counterevidenceOrProofGap,
      ['No global extraction wrapper was found.'],
    )
    assert.deepEqual(
      finding.validation.artifactRefs,
      ['artifacts/archive-receipt.json'],
    )
    assert.equal(finding.attackPath.dataflow.source, 'archive entry name')
    assert.equal(finding.attackPath.impact.level, 'high')

    const writeupPath =
      `findings/${OFFICIAL_FINDING_ID}/${OFFICIAL_FINDING_ID}.md`
    assert.deepEqual(finding.artifactRefs, [
      {
        kind: 'external',
        sourceArtifactPath: writeupPath,
        integrityKind: 'adapter-bundle',
        sha256: sha256(fs.readFileSync(path.join(bundle.root, writeupPath))),
        mediaType: 'text/markdown',
        retainedInAtlas: false,
      },
      {
        kind: 'external',
        sourceArtifactPath: 'artifacts/archive-receipt.json',
        integrityKind: 'producer-manifest',
        sha256: sha256(
          fs.readFileSync(
            path.join(bundle.root, 'artifacts/archive-receipt.json'),
          ),
        ),
        mediaType: 'application/json',
        retainedInAtlas: false,
      },
    ])
    assert.ok(
      findArtifact(
        observation,
        'artifacts/archive-receipt.json',
      ).referencedBy.includes(
        '/findings/0/artifactRefs/1/sourceArtifactPath',
      ),
    )
    assert.deepEqual(observation.hardening, {
      portfolio: {
        kind: 'external',
        sourceArtifactPath: 'hardening/hardening.md',
        integrityKind: 'adapter-bundle',
        sha256: sha256(
          fs.readFileSync(path.join(bundle.root, 'hardening/hardening.md')),
        ),
        mediaType: 'text/markdown',
        retainedInAtlas: false,
      },
    })
    assert.equal(
      findArtifact(observation, 'hardening/hardening.md').referencedBy[0],
      '/hardening/portfolio/sourceArtifactPath',
    )

    const producerExtensions = extensionMap(observation.producerExtensions)
    for (const key of [
      'codex-security.scan-manifest/1.0:/bundleNote',
      'codex-security.scan-manifest/1.0:/scan/producer/channel',
      'codex-security.scan-manifest/1.0:/scan/target/reviewedWorkspace',
      'codex-security.scan-manifest/1.0:/scan/scope/selectionReason',
      'codex-security.scan-manifest/1.0:/scan/threatModel/sourceMethod',
      'codex-security.scan-manifest/1.0:/scan/hardening/category',
      'codex-security.scan-manifest/1.0:/scan/artifacts/2/receiptKind',
      'codex-security.scan-manifest/1.0:/scan/contractNote',
      'codex-security.findings/1.0:/findingsNote',
      'codex-security.coverage/1.0:/surfaces/0/sourceDispositionRationale',
      'codex-security.coverage/1.0:/explicitExclusions/0/sourceOwner',
      'codex-security.coverage/1.0:/openQuestions/0/owner',
      'codex-security.coverage/1.0:/coverageNote',
    ]) {
      assert.ok(producerExtensions.has(key), `missing ${key}`)
    }
    const findingExtensions = extensionMap(finding.extensions)
    for (const key of [
      'codex-security.findings/1.0:/findings/0/codeEvidence/0/sourcePhase',
      'codex-security.findings/1.0:/findings/0/rootCause/code',
      'codex-security.findings/1.0:/findings/0/rootCause/language',
      'codex-security.findings/1.0:/findings/0/rootCause/sourceInvariant',
      'codex-security.findings/1.0:/findings/0/validation/counterEvidence',
      'codex-security.findings/1.0:/findings/0/validation/customValidation',
      'codex-security.findings/1.0:/findings/0/attackPath/dataflow/traceKind',
      'codex-security.findings/1.0:/findings/0/attackPath/customAttack',
      'codex-security.findings/1.0:/findings/0/provenance/engineRun',
      'codex-security.findings/1.0:/findings/0/extensions/sourceFlavor',
      'codex-security.findings/1.0:/findings/0/sourceRisk',
    ]) {
      assert.ok(findingExtensions.has(key), `missing ${key}`)
    }
    for (const extension of [
      ...observation.producerExtensions,
      ...finding.extensions,
    ]) {
      assert.equal(
        extension.digest,
        computeAuditCanonicalDigest(extension.value),
      )
    }
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('uses producer-manifest integrity only when external paths are actually listed and sealed', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle('finding-bundle.json')
  try {
    const manifest = readJson(bundle.root, 'scan-manifest.json')
    manifest.scan.artifacts.push(
      {
        path:
          `findings/${OFFICIAL_FINDING_ID}/${OFFICIAL_FINDING_ID}.md`,
        mediaType: 'text/markdown; charset=utf-8',
      },
      {
        path: 'hardening/hardening.md',
        mediaType: 'application/vnd.example.hardening+markdown',
      },
    )
    resealBundle(bundle.root, manifest)
    const result = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    )
    assert.equal(
      result.observation.findings[0].artifactRefs[0].integrityKind,
      'producer-manifest',
    )
    assert.equal(
      result.observation.findings[0].artifactRefs[0].mediaType,
      'text/markdown; charset=utf-8',
    )
    assert.equal(
      result.observation.hardening.portfolio.integrityKind,
      'producer-manifest',
    )
    assert.equal(
      result.observation.hardening.portfolio.mediaType,
      'application/vnd.example.hardening+markdown',
    )
    assert.equal(
      findArtifact(
        result.observation,
        'hardening/hardening.md',
      ).integrityIndex,
      'scan-manifest.json',
    )
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('maps every Codex target kind and semantic coverage mode without inventing exact proof', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const targetCases = [
    {
      source: {
        kind: 'git_revision',
        targetId: 'target-revision',
        displayName: 'revision',
        revision: 'revision-coordinate',
      },
      expected: {
        kind: 'git-revision',
        identityBasis: 'revision-coordinate',
        sourceRevision: 'revision-coordinate',
      },
    },
    {
      source: {
        kind: 'git_worktree',
        targetId: 'target-worktree',
        displayName: 'worktree',
        revision: 'worktree-revision',
        snapshotDigest: SOURCE_SNAPSHOT_DIGEST,
      },
      expected: {
        kind: 'git-worktree',
        identityBasis: 'snapshot',
        sourceRevision: 'worktree-revision',
      },
    },
    {
      source: {
        kind: 'git_diff',
        targetId: 'target-diff',
        displayName: 'diff',
        baseRevision: 'base-coordinate',
        headRevision: 'head-coordinate',
        snapshotDigest: SOURCE_SNAPSHOT_DIGEST,
      },
      expected: {
        kind: 'git-diff',
        identityBasis: 'snapshot',
        sourceBaseRevision: 'base-coordinate',
        sourceHeadRevision: 'head-coordinate',
      },
    },
    {
      source: {
        kind: 'directory_snapshot',
        targetId: 'target-directory',
        displayName: 'directory',
        snapshotDigest: SOURCE_SNAPSHOT_DIGEST,
      },
      expected: {
        kind: 'directory-snapshot',
        identityBasis: 'snapshot',
      },
    },
  ]
  const coverageModes = [
    ['repository', 'repository'],
    ['scoped_path', 'scoped_path'],
    ['diff', 'diff'],
    ['commit', 'repository'],
    ['branch_diff', 'diff'],
    ['working_tree', 'directory'],
    ['deep_repository', 'custom'],
  ]
  try {
    for (const [index, [mode, inventoryStrategy]] of coverageModes.entries()) {
      const bundle = materializeBundle()
      try {
        const targetCase = targetCases[index % targetCases.length]
        const manifest = readJson(bundle.root, 'scan-manifest.json')
        manifest.scan.target = clone(targetCase.source)
        const coverage = readJson(bundle.root, 'coverage.json')
        coverage.mode = mode
        coverage.inventoryStrategy = inventoryStrategy
        writeJson(bundle.root, 'coverage.json', coverage)
        resealBundle(bundle.root, manifest)

        const observation = api.importCodexSecurityBundle(
          repo,
          importOptions(bundle.root),
        ).observation
        assert.equal(observation.scope.mode, mode)
        assert.equal(
          observation.semanticCoverage.inventoryStrategy,
          inventoryStrategy,
        )
        assert.equal(observation.target.kind, targetCase.expected.kind)
        assert.equal(
          observation.target.identityBasis,
          targetCase.expected.identityBasis,
        )
        for (const [key, value] of Object.entries(targetCase.expected)) {
          assert.equal(observation.target[key], value, `${mode}:${key}`)
        }
        assert.deepEqual(observation.exactCoverage, {
          completeness: 'unknown',
          basis: 'unavailable',
          reason: UNAVAILABLE_REASON,
        })
      } finally {
        cleanup(bundle.root)
      }
    }
  } finally {
    cleanup(repo)
  }
})

test('preserves independently optional Codex severity members', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const cases = [
    {
      label: 'score without scoring system',
      mutate(severity) {
        delete severity.scoringSystem
      },
      expected: {
        score: 8.1,
        scoringSystem: undefined,
      },
    },
    {
      label: 'scoring system without score',
      mutate(severity) {
        delete severity.score
      },
      expected: {
        score: undefined,
        scoringSystem: 'CVSS:3.1',
      },
    },
  ]
  try {
    for (const { label, mutate, expected } of cases) {
      const bundle = materializeBundle('finding-bundle.json')
      try {
        rewriteJson(bundle.root, 'findings.json', (findings) => {
          mutate(findings.findings[0].severity)
        })
        const severity = api.importCodexSecurityBundle(
          repo,
          importOptions(bundle.root),
        ).observation.findings[0].severity
        assert.equal(severity.score, expected.score, label)
        assert.equal(severity.scoringSystem, expected.scoringSystem, label)
      } finally {
        cleanup(bundle.root)
      }
    }
  } finally {
    cleanup(repo)
  }
})

test('preserves schema-valid remediation and preventive-control list ordering', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle('finding-bundle.json')
  try {
    rewriteJson(bundle.root, 'findings.json', (findings) => {
      findings.findings[0].remediationTests = [
        'Run the focused regression.',
        'Run the focused regression.',
      ]
      findings.findings[0].preventiveControls = [
        'Require containment.',
        'Require centralized extraction.',
      ]
    })
    const finding = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    ).observation.findings[0]
    assert.deepEqual(finding.remediationTests, [
      'Run the focused regression.',
      'Run the focused regression.',
    ])
    assert.deepEqual(finding.preventiveControls, [
      'Require containment.',
      'Require centralized extraction.',
    ])
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('keeps schema-open strings as extensions when they cannot enter V3 text fields', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle('finding-bundle.json')
  try {
    rewriteJson(bundle.root, 'findings.json', (findings) => {
      const finding = findings.findings[0]
      finding.validation.method = ' '
      finding.validation.confidenceRationale = '\0'
      finding.attackPath.dataflow.source = '\0'
    })
    const finding = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    ).observation.findings[0]
    assert.equal(finding.validation.method, undefined)
    assert.equal(finding.validation.confidenceRationale, undefined)
    assert.equal(finding.attackPath.dataflow.source, undefined)

    const extensions = extensionMap(finding.extensions)
    assert.equal(
      extensions.get(
        'codex-security.findings/1.0:/findings/0/validation/method',
      ).value,
      ' ',
    )
    assert.equal(
      extensions.get(
        'codex-security.findings/1.0:/findings/0/validation/confidenceRationale',
      ).value,
      '\0',
    )
    assert.equal(
      extensions.get(
        'codex-security.findings/1.0:/findings/0/attackPath/dataflow/source',
      ).value,
      '\0',
    )
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('keeps incompatible or unknown open-section evidence refs as extensions', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle('finding-bundle.json')
  try {
    rewriteJson(bundle.root, 'findings.json', (findings) => {
      const finding = findings.findings[0]
      finding.validation.evidenceRefs = 7
      finding.validation.artifactRefs = ['../proof']
      finding.attackPath.evidenceRefs = ['unknown-evidence']
      finding.attackPath.dataflow.evidenceRefs = ['archive-write', 7]
    })
    const finding = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    ).observation.findings[0]
    assert.equal(finding.validation.evidenceRefs, undefined)
    assert.equal(finding.validation.artifactRefs, undefined)
    assert.equal(finding.attackPath.evidenceRefs, undefined)
    assert.equal(finding.attackPath.dataflow.evidenceRefs, undefined)

    const extensions = extensionMap(finding.extensions)
    for (const [pointer, value] of [
      ['/findings/0/validation/evidenceRefs', 7],
      ['/findings/0/validation/artifactRefs', ['../proof']],
      ['/findings/0/attackPath/evidenceRefs', ['unknown-evidence']],
      [
        '/findings/0/attackPath/dataflow/evidenceRefs',
        ['archive-write', 7],
      ],
    ]) {
      assert.deepEqual(
        extensions.get(
          `codex-security.findings/1.0:${pointer}`,
        ).value,
        value,
        pointer,
      )
    }
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('preserves ordered locations that share a source range', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle('finding-bundle.json')
  try {
    rewriteJson(bundle.root, 'findings.json', (findings) => {
      const primary = findings.findings[0].locations[0]
      findings.findings[0].locations.push(
        { ...primary, role: 'trace' },
        clone(primary),
      )
    })
    const locations = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    ).observation.findings[0].locations
    assert.deepEqual(
      locations.map(({ path: locationPath, startLine, endLine, role }) => ({
        path: locationPath,
        startLine,
        endLine,
        role,
      })),
      [
        {
          path: 'src/extract.py',
          startLine: 41,
          endLine: 44,
          role: 'root_control',
        },
        {
          path: 'support/archive.py',
          startLine: 8,
          endLine: undefined,
          role: undefined,
        },
        {
          path: 'src/extract.py',
          startLine: 41,
          endLine: 44,
          role: 'trace',
        },
        {
          path: 'src/extract.py',
          startLine: 41,
          endLine: 44,
          role: 'root_control',
        },
      ],
    )
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('normalizes every Codex set projection while preserving exact source arrays', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle('finding-bundle.json')
  try {
    const sourceStrings = ['z', 'a', 'z']
    const normalizedStrings = ['a', 'z']
    const includePaths = ['src/z/**', 'src/a/**', 'src/z/**']
    const normalizedIncludePaths = ['src/a/**', 'src/z/**']
    const excludePaths = ['vendor/z/**', 'vendor/a/**', 'vendor/z/**']
    const normalizedExcludePaths = ['vendor/a/**', 'vendor/z/**']
    const sourceExclusions = [
      { pattern: 'z/**', reason: 'Zed source exclusion.' },
      { pattern: 'a/**', reason: 'Alpha source exclusion.' },
      { pattern: 'z/**', reason: 'Zed source exclusion.' },
    ]
    const manifest = readJson(bundle.root, 'scan-manifest.json')
    manifest.scan.scope.includePaths = clone(includePaths)
    manifest.scan.scope.excludePaths = clone(excludePaths)
    manifest.scan.scope.artifactsReviewed = clone(sourceStrings)
    manifest.scan.scope.limitations = clone(sourceStrings)
    for (const key of [
      'assets',
      'trustBoundaries',
      'attackerCapabilities',
      'securityObjectives',
      'assumptions',
    ]) {
      manifest.scan.threatModel[key] = clone(sourceStrings)
    }
    writeJson(bundle.root, 'scan-manifest.json', manifest)

    rewriteJson(bundle.root, 'findings.json', (findings) => {
      const finding = findings.findings[0]
      finding.taxonomy.cwe = ['CWE-999', 'CWE-22', 'CWE-999']
      finding.rootCause.evidenceRefs = ['archive-write', 'archive-write']
      finding.validation.evidenceRefs = ['archive-write', 'archive-write']
      finding.validation.artifactRefs = [
        'coverage.json',
        'artifacts/archive-receipt.json',
        'coverage.json',
      ]
      finding.validation.artifact_paths = [
        'artifacts/archive-receipt.json',
        'coverage.json',
      ]
      finding.attackPath.evidenceRefs = ['archive-write', 'archive-write']
      finding.attackPath.dataflow.evidenceRefs = [
        'archive-write',
        'archive-write',
      ]
    }, false)
    rewriteJson(bundle.root, 'coverage.json', (coverage) => {
      coverage.completeness = 'partial'
      coverage.includePaths = clone(includePaths)
      coverage.excludePaths = clone(excludePaths)
      coverage.surfaces[0].receiptRefs = [
        'artifacts/archive-receipt.json',
        'artifacts/archive-receipt.json',
      ]
      coverage.explicitExclusions = clone(sourceExclusions)
      coverage.deferred = [
        {
          id: 'later',
          reason: 'Follow up paths later.',
          paths: clone(sourceStrings),
          surfaceIds: [
            'surface_archive_extraction',
            'surface_archive_extraction',
          ],
        },
      ]
    })
    const observation = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    ).observation
    assert.deepEqual(observation.scope.includePaths, normalizedIncludePaths)
    assert.deepEqual(observation.scope.excludePaths, normalizedExcludePaths)
    assert.deepEqual(
      observation.scope.artifactsReviewed,
      normalizedStrings,
    )
    assert.deepEqual(observation.scope.limitations, normalizedStrings)
    for (const key of [
      'assets',
      'trustBoundaries',
      'attackerCapabilities',
      'securityObjectives',
      'assumptions',
    ]) {
      assert.deepEqual(observation.threatModel[key], normalizedStrings, key)
    }
    assert.deepEqual(observation.scope.explicitExclusions, [
      sourceExclusions[1],
      sourceExclusions[0],
    ])
    assert.deepEqual(
      observation.semanticCoverage.explicitExclusions,
      observation.scope.explicitExclusions,
    )
    assert.deepEqual(
      observation.semanticCoverage.surfaces[0].receiptRefs,
      ['artifacts/archive-receipt.json'],
    )
    assert.deepEqual(
      observation.semanticCoverage.deferred[0].paths,
      normalizedStrings,
    )
    assert.deepEqual(
      observation.semanticCoverage.deferred[0].surfaceIds,
      ['surface_archive_extraction'],
    )

    const finding = observation.findings[0]
    assert.deepEqual(finding.taxonomy.cwe, ['CWE-22', 'CWE-999'])
    assert.deepEqual(finding.rootCause.evidenceRefs, ['archive-write'])
    assert.deepEqual(finding.validation.evidenceRefs, ['archive-write'])
    assert.deepEqual(
      finding.validation.artifactRefs,
      ['artifacts/archive-receipt.json', 'coverage.json'],
    )
    assert.deepEqual(finding.attackPath.evidenceRefs, ['archive-write'])
    assert.deepEqual(
      finding.attackPath.dataflow.evidenceRefs,
      ['archive-write'],
    )

    const producerExtensions = extensionMap(observation.producerExtensions)
    const producerSources = new Map([
      ['codex-security.scan-manifest/1.0:/scan/scope/includePaths', includePaths],
      ['codex-security.scan-manifest/1.0:/scan/scope/excludePaths', excludePaths],
      ['codex-security.scan-manifest/1.0:/scan/scope/artifactsReviewed', sourceStrings],
      ['codex-security.scan-manifest/1.0:/scan/scope/limitations', sourceStrings],
      ['codex-security.coverage/1.0:/includePaths', includePaths],
      ['codex-security.coverage/1.0:/excludePaths', excludePaths],
      [
        'codex-security.coverage/1.0:/surfaces/0/receiptRefs',
        ['artifacts/archive-receipt.json', 'artifacts/archive-receipt.json'],
      ],
      ['codex-security.coverage/1.0:/explicitExclusions', sourceExclusions],
      ['codex-security.coverage/1.0:/deferred/0/paths', sourceStrings],
      [
        'codex-security.coverage/1.0:/deferred/0/surfaceIds',
        ['surface_archive_extraction', 'surface_archive_extraction'],
      ],
    ])
    for (const key of [
      'assets',
      'trustBoundaries',
      'attackerCapabilities',
      'securityObjectives',
      'assumptions',
    ]) {
      producerSources.set(
        `codex-security.scan-manifest/1.0:/scan/threatModel/${key}`,
        sourceStrings,
      )
    }
    for (const [key, source] of producerSources) {
      assert.deepEqual(producerExtensions.get(key).value, source, key)
    }

    const findingExtensions = extensionMap(finding.extensions)
    for (const [pointer, source] of [
      ['/findings/0/taxonomy/cwe', ['CWE-999', 'CWE-22', 'CWE-999']],
      ['/findings/0/rootCause/evidenceRefs', ['archive-write', 'archive-write']],
      ['/findings/0/validation/evidenceRefs', ['archive-write', 'archive-write']],
      [
        '/findings/0/validation/artifactRefs',
        [
          'coverage.json',
          'artifacts/archive-receipt.json',
          'coverage.json',
        ],
      ],
      [
        '/findings/0/validation/artifact_paths',
        ['artifacts/archive-receipt.json', 'coverage.json'],
      ],
      ['/findings/0/attackPath/evidenceRefs', ['archive-write', 'archive-write']],
      [
        '/findings/0/attackPath/dataflow/evidenceRefs',
        ['archive-write', 'archive-write'],
      ],
    ]) {
      assert.deepEqual(
        findingExtensions.get(
          `codex-security.findings/1.0:${pointer}`,
        ).value,
        source,
        pointer,
      )
    }
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('apply publishes through the shared history-first seam and is idempotent', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle()
  try {
    const dryRun = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    )
    const applied = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root, { apply: true }),
    )
    const repeated = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root, { apply: true }),
    )

    assert.equal(applied.applied, true)
    assert.deepEqual(applied.publication, {
      currentPath: `.atlas/audits/${UNIT_SLUG}.json`,
      historyPath: `.atlas/audit-history/${UNIT_SLUG}.json`,
      appendedObservationId: applied.observation.observationId,
    })
    assert.equal(applied.currentBytes, dryRun.currentBytes)
    assert.equal(repeated.currentBytes, dryRun.currentBytes)
    assert.equal(
      fs.readFileSync(
        path.join(repo, '.atlas', 'audits', `${UNIT_SLUG}.json`),
        'utf8',
      ),
      dryRun.currentBytes,
    )
    const history = readJson(
      repo,
      `.atlas/audit-history/${UNIT_SLUG}.json`,
    )
    assert.equal(history.entries.length, 1)
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('rejects non-local bundle inputs and hostile public options before import', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle()
  try {
    for (const bundlePath of [
      'https://example.invalid/scan',
      'file:///tmp/scan',
      'ssh://host/scan',
    ]) {
      assert.throws(
        () => api.importCodexSecurityBundle(
          repo,
          importOptions(bundlePath),
        ),
        /local|URL|bundle|path/i,
      )
    }
    assert.throws(
      () => api.importCodexSecurityBundle(repo, {
        ...importOptions(bundle.root),
        unknown: true,
      }),
      /unknown|option/i,
    )
    assert.throws(
      () => api.importCodexSecurityBundle(
        repo,
        new Proxy(importOptions(bundle.root), {
          ownKeys() {
            throw new Error('proxy trap ran')
          },
        }),
      ),
      /proxy/i,
    )
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('rejects malformed canonical documents, mismatched scans, and invalid seals', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const cases = [
    {
      name: 'missing canonical document',
      mutate(root) {
        fs.unlinkSync(path.join(root, 'coverage.json'))
      },
      error: /coverage|missing|regular file/i,
    },
    {
      name: 'wrong document type',
      mutate(root) {
        rewriteJson(root, 'coverage.json', (coverage) => {
          coverage.documentType = 'codex-security.other'
        })
      },
      error: /documentType|coverage/i,
    },
    {
      name: 'future schema version',
      mutate(root) {
        rewriteJson(root, 'findings.json', (findings) => {
          findings.schemaVersion = '2.0'
        })
      },
      error: /schemaVersion|1\\.0/i,
    },
    {
      name: 'mismatched scan ids',
      mutate(root) {
        rewriteJson(root, 'coverage.json', (coverage) => {
          coverage.scanId = 'scan_different'
        })
      },
      error: /scan IDs|scanId|match/i,
    },
    {
      name: 'seal mismatch',
      mutate(root) {
        fs.appendFileSync(path.join(root, 'findings.json'), ' ')
      },
      error: /seal|digest|changed|artifact/i,
    },
    {
      name: 'duplicate artifact paths',
      mutate(root) {
        const manifest = readJson(root, 'scan-manifest.json')
        manifest.scan.artifacts.push(clone(manifest.scan.artifacts[0]))
        writeJson(root, 'scan-manifest.json', manifest)
      },
      error: /duplicate.*artifact|artifact.*duplicate/i,
    },
    {
      name: 'invalid sealed timestamp',
      mutate(root) {
        const manifest = readJson(root, 'scan-manifest.json')
        manifest.scan.sealedAt = '2026-05-31T18:10:00Z'
        writeJson(root, 'scan-manifest.json', manifest)
      },
      error: /sealedAt|completedAt|timestamp/i,
    },
    {
      name: 'nonexistent calendar date',
      mutate(root) {
        const manifest = readJson(root, 'scan-manifest.json')
        manifest.scan.startedAt = '2026-02-29T18:00:00Z'
        writeJson(root, 'scan-manifest.json', manifest)
      },
      error: /startedAt|date|time|RFC/i,
    },
    {
      name: 'forbidden 24-hour timestamp',
      mutate(root) {
        const manifest = readJson(root, 'scan-manifest.json')
        manifest.scan.completedAt = '2026-05-31T24:00:00Z'
        manifest.scan.sealedAt = manifest.scan.completedAt
        writeJson(root, 'scan-manifest.json', manifest)
      },
      error: /completedAt|date|time|RFC/i,
    },
  ]

  try {
    for (const fixture of cases) {
      const bundle = materializeBundle()
      try {
        fixture.mutate(bundle.root)
        assert.throws(
          () => api.importCodexSecurityBundle(
            repo,
            importOptions(bundle.root),
          ),
          fixture.error,
          fixture.name,
        )
      } finally {
        cleanup(bundle.root)
      }
    }

    const malformed = readRecipe('malformed-bundle.json')
    const bundle = materializeBundle(malformed.base)
    try {
      rewriteJson(
        bundle.root,
        `${malformed.mutation.document}.json`,
        (document) => {
          let parent = document
          for (const key of malformed.mutation.path.slice(0, -1)) {
            parent = parent[key]
          }
          parent[malformed.mutation.path.at(-1)] =
            malformed.mutation.value
        },
      )
      assert.throws(
        () => api.importCodexSecurityBundle(
          repo,
          importOptions(bundle.root),
        ),
        new RegExp(malformed.expectedError, 'i'),
      )
    } finally {
      cleanup(bundle.root)
    }
  } finally {
    cleanup(repo)
  }
})

test('accepts canonical hierarchical target remotes from the source contract', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle()
  try {
    const manifest = readJson(bundle.root, 'scan-manifest.json')
    manifest.scan.target.remote = 'git+ssh://example.invalid/repository'
    writeJson(bundle.root, 'scan-manifest.json', manifest)

    const result = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    )
    assert.equal(
      result.observation.target.remote,
      'git+ssh://example.invalid/repository',
    )
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('preserves bounded opaque source coordinates without weakening required revisions', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle()
  try {
    const manifest = readJson(bundle.root, 'scan-manifest.json')
    Object.assign(manifest.scan.target, {
      kind: 'git_diff',
      revision: '',
      baseRevision: '',
      headRevision: '',
      snapshotDigest: SOURCE_SNAPSHOT_DIGEST,
    })
    writeJson(bundle.root, 'scan-manifest.json', manifest)

    const observation = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    ).observation
    assert.equal(observation.target.sourceRevision, '')
    assert.equal(observation.target.sourceBaseRevision, '')
    assert.equal(observation.target.sourceHeadRevision, '')

    manifest.scan.target.kind = 'git_revision'
    manifest.scan.target.revision = '\0\u0001'
    manifest.scan.target.baseRevision = '\0\u0001'
    manifest.scan.target.headRevision = ' \t'
    delete manifest.scan.target.snapshotDigest
    writeJson(bundle.root, 'scan-manifest.json', manifest)
    const revisionTarget = api.importCodexSecurityBundle(
      repo,
      importOptions(bundle.root),
    ).observation.target
    assert.equal(revisionTarget.sourceRevision, '\0\u0001')
    assert.equal(revisionTarget.sourceBaseRevision, '\0\u0001')
    assert.equal(revisionTarget.sourceHeadRevision, ' \t')
    assert.equal(
      revisionTarget.identityDigest,
      computeAuditCanonicalDigest({
        namespace: 'repo-atlas/revision-coordinate/v1',
        sourceKind: 'git_revision',
        targetId: 'target_clean_example',
        sourceRevision: '\0\u0001',
        sourceBaseRevision: '\0\u0001',
        sourceHeadRevision: ' \t',
      }),
    )

    for (const revision of ['', ' \t', '\u0085']) {
      manifest.scan.target.revision = revision
      writeJson(bundle.root, 'scan-manifest.json', manifest)
      assert.throws(
        () => api.importCodexSecurityBundle(
          repo,
          importOptions(bundle.root),
        ),
        /revision|nonempty|valid bounded string/i,
      )
    }
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('rejects unsafe target remotes and scope selectors without exposing credentials', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const cases = [
    {
      label: 'credential-bearing remote',
      remote: 'https://user:secret@example.invalid/repository',
    },
    {
      label: 'query-bearing remote',
      remote: 'https://example.invalid/repository?token=secret',
    },
    {
      label: 'fragment-bearing remote',
      remote: 'https://example.invalid/repository#secret',
    },
    {
      label: 'relative remote',
      remote: 'example.invalid/repository',
    },
    {
      label: 'backslash remote',
      remote: 'https:\\\\example.invalid\\repository',
    },
    {
      label: 'noncanonical remote',
      remote: 'HTTPS://Example.Invalid:443/repository',
    },
  ]
  try {
    for (const { label, remote } of cases) {
      const bundle = materializeBundle()
      try {
        const manifest = readJson(bundle.root, 'scan-manifest.json')
        manifest.scan.target.remote = remote
        writeJson(bundle.root, 'scan-manifest.json', manifest)
        const error = assert.throws(
          () => api.importCodexSecurityBundle(
            repo,
            importOptions(bundle.root),
          ),
          /remote|URL|credential|query|fragment/i,
          label,
        )
        assert.doesNotMatch(String(error), /secret/i, label)
      } finally {
        cleanup(bundle.root)
      }
    }

    for (const selector of ['../outside', '/absolute', 'src\\escape']) {
      const bundle = materializeBundle()
      try {
        const manifest = readJson(bundle.root, 'scan-manifest.json')
        manifest.scan.scope.includePaths = [selector]
        const coverage = readJson(bundle.root, 'coverage.json')
        coverage.includePaths = [selector]
        writeJson(bundle.root, 'coverage.json', coverage)
        resealBundle(bundle.root, manifest)
        assert.throws(
          () => api.importCodexSecurityBundle(
            repo,
            importOptions(bundle.root),
          ),
          /scope|path|safe|relative|POSIX/i,
          selector,
        )
      } finally {
        cleanup(bundle.root)
      }
    }
  } finally {
    cleanup(repo)
  }
})

test('rejects duplicate-key JSON and source extensions outside V3 bounds', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  try {
    const duplicate = materializeBundle()
    try {
      const coverage = JSON.stringify(readJson(duplicate.root, 'coverage.json'))
        .replace(
          '"scanId":"scan_clean_001"',
          '"scanId":"scan_clean_001","scanId":"scan_clean_001"',
        )
      writeFile(duplicate.root, 'coverage.json', `${coverage}\n`)
      resealBundle(duplicate.root)
      assert.throws(
        () => api.importCodexSecurityBundle(
          repo,
          importOptions(duplicate.root),
        ),
        /duplicate|JSON|scanId/i,
      )
    } finally {
      cleanup(duplicate.root)
    }

    const oversized = materializeBundle()
    try {
      const manifest = readJson(oversized.root, 'scan-manifest.json')
      manifest.sourceExtension = 'x'.repeat(70 * 1024)
      writeJson(oversized.root, 'scan-manifest.json', manifest)
      assert.throws(
        () => api.importCodexSecurityBundle(
          repo,
          importOptions(oversized.root),
        ),
        /extension|65536|bound|byte/i,
      )
    } finally {
      cleanup(oversized.root)
    }
  } finally {
    cleanup(repo)
  }
})

test('enforces one aggregate byte budget across distinct hardlinked bundle members', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle()
  const memberBytes = 1024 * 1024
  const memberCount = AUDIT_LIMITS.jsonBytes / memberBytes
  try {
    const payload = Buffer.alloc(memberBytes, 0x61)
    const primary = 'artifacts/aggregate-00.bin'
    writeFile(bundle.root, primary, payload)
    const manifest = readJson(bundle.root, 'scan-manifest.json')
    const digest = sha256(payload)
    for (let index = 0; index < memberCount; index += 1) {
      const artifactPath =
        `artifacts/aggregate-${String(index).padStart(2, '0')}.bin`
      if (index > 0) {
        fs.linkSync(
          path.join(bundle.root, primary),
          path.join(bundle.root, artifactPath),
        )
      }
      manifest.scan.artifacts.push({
        path: artifactPath,
        sha256: digest,
        mediaType: 'application/octet-stream',
      })
    }
    writeJson(bundle.root, 'scan-manifest.json', manifest)

    assert.throws(
      () => api.importCodexSecurityBundle(
        repo,
        importOptions(bundle.root),
      ),
      /aggregate|bundle.*byte|byte.*budget|limit/i,
    )
  } finally {
    cleanup(repo, bundle.root)
  }
})

test('rejects unsafe paths, symlinked members, and missing external references', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-codex-outside-'))
  writeFile(outside, 'canary', 'outside\n')
  const cases = [
    {
      name: 'symlinked canonical document',
      bundleName: 'clean-bundle.json',
      mutate(root) {
        fs.unlinkSync(path.join(root, 'coverage.json'))
        fs.symlinkSync(path.join(outside, 'canary'), path.join(root, 'coverage.json'))
      },
      error: /symlink|safe|regular file/i,
    },
    {
      name: 'unsafe artifact path',
      bundleName: 'clean-bundle.json',
      mutate(root) {
        const manifest = readJson(root, 'scan-manifest.json')
        manifest.scan.artifacts.push({
          path: '../outside',
          sha256: '0'.repeat(64),
          mediaType: 'text/plain',
        })
        writeJson(root, 'scan-manifest.json', manifest)
      },
      error: /artifact|path|safe|normalized/i,
    },
    {
      name: 'missing writeup',
      bundleName: 'finding-bundle.json',
      mutate(root) {
        fs.unlinkSync(path.join(
          root,
          'findings',
          OFFICIAL_FINDING_ID,
          `${OFFICIAL_FINDING_ID}.md`,
        ))
      },
      error: /writeup|reportPath|missing|regular file/i,
    },
    {
      name: 'symlinked hardening portfolio',
      bundleName: 'finding-bundle.json',
      mutate(root) {
        const target = path.join(root, 'hardening', 'hardening.md')
        fs.unlinkSync(target)
        fs.symlinkSync(path.join(outside, 'canary'), target)
      },
      error: /hardening|symlink|safe|regular file/i,
    },
    {
      name: 'unlisted coverage receipt',
      bundleName: 'finding-bundle.json',
      mutate(root) {
        const manifest = readJson(root, 'scan-manifest.json')
        manifest.scan.artifacts = manifest.scan.artifacts.filter(
          ({ path: artifactPath }) =>
            artifactPath !== 'artifacts/archive-receipt.json',
        )
        resealBundle(root, manifest)
      },
      error: /coverage|receipt|manifest|artifact/i,
    },
  ]
  try {
    for (const fixture of cases) {
      const bundle = materializeBundle(fixture.bundleName)
      try {
        fixture.mutate(bundle.root)
        assert.throws(
          () => api.importCodexSecurityBundle(
            repo,
            importOptions(bundle.root),
          ),
          fixture.error,
          fixture.name,
        )
      } finally {
        cleanup(bundle.root)
      }
    }

    const bundle = materializeBundle()
    const linked = `${bundle.root}-link`
    fs.symlinkSync(bundle.root, linked, 'dir')
    try {
      assert.throws(
        () => api.importCodexSecurityBundle(repo, importOptions(linked)),
        /bundle|directory|symlink|safe/i,
      )
    } finally {
      fs.unlinkSync(linked)
      cleanup(bundle.root)
    }
    assert.equal(fs.readFileSync(path.join(outside, 'canary'), 'utf8'), 'outside\n')
  } finally {
    cleanup(repo, outside)
  }
})

test('recomputes Codex identities and rejects duplicate or colliding findings', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const cases = [
    {
      name: 'wrong fingerprint',
      mutate(findings) {
        findings.findings[0].fingerprints.primary =
          `codex-security/v1:sha256:${'0'.repeat(64)}`
      },
      error: /fingerprint|identity/i,
    },
    {
      name: 'wrong finding id',
      mutate(findings) {
        findings.findings[0].findingId = `csf_${'0'.repeat(24)}`
      },
      error: /findingId|identity/i,
    },
    {
      name: 'wrong occurrence id',
      mutate(findings) {
        findings.findings[0].occurrenceId = `occ_${'0'.repeat(24)}`
      },
      error: /occurrenceId|identity/i,
    },
    {
      name: 'duplicate logical finding',
      mutate(findings) {
        findings.findings.push(clone(findings.findings[0]))
      },
      error: /duplicate|collision|logical finding/i,
    },
  ]
  try {
    for (const fixture of cases) {
      const bundle = materializeBundle('finding-bundle.json')
      try {
        rewriteJson(bundle.root, 'findings.json', fixture.mutate)
        assert.throws(
          () => api.importCodexSecurityBundle(
            repo,
            importOptions(bundle.root),
          ),
          fixture.error,
          fixture.name,
        )
      } finally {
        cleanup(bundle.root)
      }
    }
  } finally {
    cleanup(repo)
  }
})

test('fails closed when an external bundle member changes after its validated read', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle('finding-bundle.json')
  const writeup = path.join(
    bundle.root,
    'findings',
    OFFICIAL_FINDING_ID,
    `${OFFICIAL_FINDING_ID}.md`,
  )
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const openedPaths = new Map()
  let changed = false
  try {
    fs.openSync = function trackBundleFiles(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        openedPaths.set(fd, fs.realpathSync(`/proc/self/fd/${fd}`))
      } catch {
        // Only regular bundle members matter.
      }
      return fd
    }
    fs.closeSync = function mutateWriteupAfterValidatedRead(fd) {
      const openedPath = openedPaths.get(fd)
      openedPaths.delete(fd)
      const result = originalClose.call(fs, fd)
      if (!changed && openedPath === writeup) {
        changed = true
        fs.appendFileSync(writeup, '\nchanged\n')
      }
      return result
    }
    assert.throws(
      () => api.importCodexSecurityBundle(
        repo,
        importOptions(bundle.root),
      ),
      /changed|seal|snapshot|bundle|digest/i,
    )
    assert.equal(changed, true)
    assert.equal(
      fs.existsSync(path.join(repo, '.atlas', 'audits', `${UNIT_SLUG}.json`)),
      false,
    )
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(repo, bundle.root)
  }
})

test('fails closed when canonical or hardening members change after their validated read', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const cases = [
    {
      bundleName: 'clean-bundle.json',
      repoPath: 'findings.json',
    },
    {
      bundleName: 'finding-bundle.json',
      repoPath: 'hardening/hardening.md',
    },
  ]
  try {
    for (const { bundleName, repoPath } of cases) {
      const bundle = materializeBundle(bundleName)
      const target = path.join(bundle.root, ...repoPath.split('/'))
      const originalOpen = fs.openSync
      const originalClose = fs.closeSync
      const openedPaths = new Map()
      let changed = false
      try {
        fs.openSync = function trackBundleFiles(file, flags, ...rest) {
          const fd = originalOpen.call(fs, file, flags, ...rest)
          try {
            openedPaths.set(fd, fs.realpathSync(`/proc/self/fd/${fd}`))
          } catch {
            // Only regular bundle members matter.
          }
          return fd
        }
        fs.closeSync = function mutateMemberAfterValidatedRead(fd) {
          const openedPath = openedPaths.get(fd)
          openedPaths.delete(fd)
          const result = originalClose.call(fs, fd)
          if (!changed && openedPath === target) {
            changed = true
            fs.appendFileSync(target, '\nchanged\n')
          }
          return result
        }
        assert.throws(
          () => api.importCodexSecurityBundle(
            repo,
            importOptions(bundle.root),
          ),
          /changed|seal|snapshot|bundle|digest/i,
          repoPath,
        )
        assert.equal(changed, true, repoPath)
      } finally {
        fs.openSync = originalOpen
        fs.closeSync = originalClose
        cleanup(bundle.root)
      }
    }
    assert.equal(
      fs.existsSync(path.join(repo, '.atlas', 'audits', `${UNIT_SLUG}.json`)),
      false,
    )
  } finally {
    cleanup(repo)
  }
})

test('fails closed when the manifest changes after its final manual re-read', async () => {
  const api = await importerApi()
  const repo = makeRepo()
  const bundle = materializeBundle()
  const target = path.join(bundle.root, 'scan-manifest.json')
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const openedPaths = new Map()
  let targetCloses = 0
  let changed = false
  try {
    fs.openSync = function trackBundleFiles(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      try {
        openedPaths.set(fd, fs.realpathSync(`/proc/self/fd/${fd}`))
      } catch {
        // Only the canonical manifest descriptor matters.
      }
      return fd
    }
    fs.closeSync = function mutateManifestAfterSecondClose(fd) {
      const openedPath = openedPaths.get(fd)
      openedPaths.delete(fd)
      const result = originalClose.call(fs, fd)
      if (openedPath === target) {
        targetCloses += 1
        if (!changed && targetCloses === 2) {
          changed = true
          fs.appendFileSync(target, '\nchanged after final re-read\n')
        }
      }
      return result
    }
    assert.throws(
      () => api.importCodexSecurityBundle(
        repo,
        importOptions(bundle.root),
      ),
      /changed|seal|snapshot|bundle|digest|support|exceeds|limit/i,
    )
    assert.equal(targetCloses >= 2, true)
    assert.equal(changed, true)
    assert.equal(
      fs.existsSync(path.join(repo, '.atlas', 'audits', `${UNIT_SLUG}.json`)),
      false,
    )
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    cleanup(repo, bundle.root)
  }
})
