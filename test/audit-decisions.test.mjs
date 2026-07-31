import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  appendAuditDecision,
  buildAuditDecisionIndex,
  computeAuditDecisionEntryDigest,
  computeAuditDecisionEventId,
  computeAuditFindingComparisonId,
  loadAuditDecisionLedgers,
  parseAuditDecisionPolicy,
  prepareAuditDecisionAppend,
  reduceAuditDecisionState,
  validateAuditDecisionLedgerCanonicalByteBudget,
  validateAuditDecisionReconciliationEdgeBudget,
  validateUniqueAuditIdentityRecords,
} from '../dist/audit-decisions.js'

const FINDING_ID = 'atf_0d465ed12cdccf67f62645b4'
const OCCURRENCE_ID = 'atocc_fe401c5bdff9b7bbde7c5fe6'
const OBSERVATION_ID = 'aobs_a41a0fb238644b712492565c'
const REVISION = '4330d27a57a5c204605d3dbe40bd4dd4038d6227'
const BLOB = 'git-sha1:41715495f45f651e6cf7d38f58a3d512abcfa440'
const RULESET_DIGEST =
  'sha256:12cf94bca7b76afaccb3138ad0251291c303ff5e8b8295d519c1e1da563d4a1f'
const POLICY_DIGEST =
  'sha256:baeb39ee62a9fe68b36e8f193f76ad6c5dcba4ee2e45d328205f6ad88c776120'
const AFTER_OBSERVATION_ID = 'aobs_bbbbbbbbbbbbbbbbbbbbbbbb'
const REPLACEMENT_FINDING_ID = 'atf_cccccccccccccccccccccccc'
const REPLACEMENT_OCCURRENCE_ID = 'atocc_dddddddddddddddddddddddd'
const SPLIT_OCCURRENCE_ID = 'atocc_eeeeeeeeeeeeeeeeeeeeeeee'
const SOURCE_ARTIFACT = {
  path: 'legacy/decisions.json',
  repositoryRevision: REVISION,
  gitBlob: BLOB,
  sha256: `sha256:${'e'.repeat(64)}`,
}

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical(value[key])}`
  ).join(',')}}`
}

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function digest(value) {
  return `sha256:${sha256(canonical(value))}`
}

function makeRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-decisions-'))
  execFileSync('git', ['init', '-q'], { cwd: root })
  fs.mkdirSync(path.join(root, '.atlas', 'audit-decisions'), { recursive: true })
  return root
}

function cleanup(root) {
  fs.rmSync(root, { recursive: true, force: true })
}

function aliasInput(overrides = {}) {
  return {
    type: 'identity-alias-reconciliation',
    decisionLedger: 'security-identity-access',
    aliases: [{
      scheme: 'relayos-security-scan/v1',
      value: 'SEC-ABC123',
    }],
    findingId: FINDING_ID,
    occurrenceIds: [OCCURRENCE_ID],
    relationship: 'canonical',
    source: {
      kind: 'migration',
      name: 'relayos-security-scan',
      version: '1',
    },
    createdAt: '2026-07-29T12:34:56.000Z',
    createdAtBasis: 'source-revision-upper-bound',
    evidenceRefs: [],
    ...overrides,
  }
}

function writeDecisionLedger(root, ledger, pretty = false) {
  fs.writeFileSync(
    path.join(
      root,
      '.atlas',
      'audit-decisions',
      `${ledger.slug}.json`,
    ),
    pretty
      ? `${JSON.stringify(ledger, null, 2)}\n\n`
      : `${canonical(ledger)}\n`,
  )
}

function binding(pathname = 'src/a.ts', blob = BLOB) {
  return { path: pathname, blob }
}

function reviewContext(overrides = {}) {
  return {
    observationId: OBSERVATION_ID,
    bindings: [binding()],
    ruleset: {
      id: 'atlas-security-v3',
      digest: RULESET_DIGEST,
    },
    policyDigest: POLICY_DIGEST,
    ...overrides,
  }
}

function currentReviewProof(overrides = {}) {
  return {
    kind: 'current-review',
    observationId: OBSERVATION_ID,
    reviewedBindings: [binding()],
    outcome: 'finding-present',
    summary: 'The exact reviewed source still contains the finding.',
    ...overrides,
  }
}

function postFixProof(overrides = {}) {
  return {
    kind: 'post-fix',
    beforeObservationId: OBSERVATION_ID,
    afterObservationId: AFTER_OBSERVATION_ID,
    beforeBindings: [binding()],
    afterBindings: [binding('src/a.ts', `git-sha1:${'a'.repeat(40)}`)],
    fixRevision: REVISION,
    outcome: 'finding-absent-after-fix',
    summary: 'The exact post-fix review no longer contains the finding.',
    ...overrides,
  }
}

function sourceEvidenceProof(overrides = {}) {
  return {
    kind: 'source-evidence',
    observationId: OBSERVATION_ID,
    reviewedBindings: [binding()],
    outcome: 'not-reportable',
    summary: 'The exact source establishes the boundary is not reportable.',
    ...overrides,
  }
}

function replacementProof(overrides = {}) {
  return {
    kind: 'replacement',
    observationId: AFTER_OBSERVATION_ID,
    replacementFindingId: REPLACEMENT_FINDING_ID,
    replacementOccurrenceId: REPLACEMENT_OCCURRENCE_ID,
    replacementBindings: [binding()],
    outcome: 'replacement-tracks-root-cause',
    summary: 'The replacement finding tracks the same root cause.',
    ...overrides,
  }
}

function deletionProof(overrides = {}) {
  return {
    kind: 'deletion',
    deletionCommit: REVISION,
    parentRevision: 'a'.repeat(40),
    deletedBindings: [binding()],
    outcome: 'exact-source-deleted',
    summary: 'The exact source was deleted.',
    ...overrides,
  }
}

function noReplacementProof(overrides = {}) {
  return {
    kind: 'no-replacement',
    observationId: AFTER_OBSERVATION_ID,
    searchRevision: REVISION,
    reviewedBindings: [binding()],
    outcome: 'no-reportable-replacement',
    summary: 'No reportable replacement remains.',
    ...overrides,
  }
}

function dispositionBase(overrides = {}) {
  return {
    type: 'finding-disposition',
    findingId: FINDING_ID,
    occurrenceId: OCCURRENCE_ID,
    action: 'open',
    actor: 'identity:reviewer@example.invalid',
    owner: 'identity-access',
    reason: 'A bounded lifecycle decision reason.',
    createdAt: '2026-07-29T00:00:00.000Z',
    createdAtBasis: 'recorded',
    reviewContext: reviewContext(),
    evidenceRefs: [],
    proofs: [],
    reviews: [],
    ...overrides,
  }
}

function validDispositionEvents() {
  const currentProof = currentReviewProof()
  const afterBinding = binding('src/a.ts', `git-sha1:${'a'.repeat(40)}`)
  return [
    dispositionBase({ action: 'open' }),
    dispositionBase({
      action: 'reopened',
      proofs: [currentProof],
      supersedesEventId: 'adev_111111111111111111111111',
    }),
    dispositionBase({
      action: 'accepted-risk',
      expiresAt: '2026-08-28T00:00:00.000Z',
      proofs: [currentProof],
    }),
    dispositionBase({
      action: 'separate-design',
      expiresAt: '2026-08-28T00:00:00.000Z',
      proofs: [currentProof],
    }),
    dispositionBase({
      action: 'false-positive',
      expiresAt: null,
      proofs: [sourceEvidenceProof()],
      actionEvidence: {
        kind: 'source-evidence',
        reviewedBindings: [binding()],
        conclusion: 'not-reportable',
        rationale: 'The exact source disproves the report.',
      },
    }),
    dispositionBase({
      action: 'remediated',
      proofs: [postFixProof()],
      regression: {
        kind: 'test',
        name: 'authorization regression',
        command: 'pnpm test',
        result: 'passed',
        binding: {
          repositoryRevision: REVISION,
          observationId: AFTER_OBSERVATION_ID,
          files: [afterBinding],
        },
      },
      actionEvidence: {
        kind: 'remediation',
        beforeBindings: [binding()],
        afterBindings: [afterBinding],
        fixRevision: REVISION,
      },
    }),
    dispositionBase({
      action: 'superseded',
      proofs: [replacementProof()],
      actionEvidence: {
        kind: 'replacement',
        replacementFindingId: REPLACEMENT_FINDING_ID,
        replacementOccurrenceId: REPLACEMENT_OCCURRENCE_ID,
      },
    }),
    dispositionBase({
      action: 'superseded',
      proofs: [deletionProof(), noReplacementProof()],
      actionEvidence: {
        kind: 'deletion',
        deletionCommit: REVISION,
        deletedBindings: [binding()],
        noReplacementEvidence: {
          observationId: AFTER_OBSERVATION_ID,
          searchRevision: REVISION,
          reviewedBindings: [binding()],
          summary: 'No replacement remains after deletion.',
        },
      },
    }),
  ]
}

function retirementBase(overrides = {}) {
  return {
    type: 'scope-retirement',
    decisionLedger: 'security-runtime',
    path: 'src/a.ts',
    blob: BLOB,
    reason: 'staged-deletion',
    retiredAt: '2026-07-29T00:00:00.000Z',
    retiredAtPrecision: 'timestamp',
    actor: 'identity:reviewer@example.invalid',
    createdAt: '2026-07-29T00:00:00.000Z',
    createdAtBasis: 'recorded',
    historyProof: {
      slug: 'security-runtime',
      observationId: OBSERVATION_ID,
      path: 'src/a.ts',
      blob: BLOB,
    },
    evidenceRefs: [],
    ...overrides,
  }
}

function treeState() {
  return {
    kind: 'git-tree-state',
    repositoryRevision: REVISION,
    presentBindings: [binding('src/new-a.ts')],
    absentPaths: ['src/a.ts'],
  }
}

function validRetirementEvents() {
  return [
    retirementBase({
      reason: 'staged-deletion',
      absenceProof: {
        kind: 'worktree-index-absence',
        headRevision: REVISION,
        headBinding: binding(),
        indexState: 'absent',
        worktreeState: 'absent',
      },
    }),
    retirementBase({
      reason: 'deleted',
      deletionCommit: REVISION,
      deletionProof: {
        kind: 'git-deletion',
        parentRevision: 'a'.repeat(40),
        parentBindings: [binding()],
        absentPaths: ['src/a.ts'],
      },
    }),
    retirementBase({
      reason: 'moved',
      successor: binding('src/new-a.ts'),
      revisionProof: treeState(),
    }),
    retirementBase({
      reason: 'superseded',
      successor: binding('src/new-a.ts'),
      revisionProof: treeState(),
    }),
    retirementBase({
      reason: 'superseded',
      noReplacementProof: noReplacementProof(),
      revisionProof: {
        ...treeState(),
        presentBindings: [],
      },
    }),
    retirementBase({
      reason: 'uncommitted-snapshot-absent',
      retiredAt: '2026-07-29T00:00:00.000Z',
      retiredAtPrecision: 'date',
      originalRetiredDate: '2026-07-29',
      createdAtBasis: 'source',
      migrationSourceProof: {
        kind: 'sealed-migration-source',
        sourceArtifact: SOURCE_ARTIFACT,
        jsonPointer: '/retirements/0',
        sourceReason: 'uncommitted_snapshot_absent',
        summary: 'The sealed migration source recorded worktree absence.',
      },
    }),
  ]
}

function observationFixture({
  observationId = OBSERVATION_ID,
  findingId = FINDING_ID,
  occurrenceId = OCCURRENCE_ID,
  decisionLedger = 'security-runtime',
  blob = BLOB,
  path: sourcePath = 'src/a.ts',
  severity = 'high',
  reviewed = true,
  exact = true,
} = {}) {
  return {
    observationId,
    observedAt: '2026-07-29T00:00:00.000Z',
    producer: exact
      ? {
          identityBasis: 'ruleset',
          ruleset: {
            id: 'atlas-security-v3',
            digest: RULESET_DIGEST,
          },
        }
      : {
          identityBasis: 'codex-contract',
        },
    target: {
      revision: REVISION,
    },
    scope: exact
      ? {
          identityBasis: 'exact-inventory',
          files: [{
            path: sourcePath,
            blob,
            status: reviewed ? 'reviewed' : 'not-reviewed',
          }],
        }
      : {
          identityBasis: 'semantic-declaration',
        },
    findings: [{
      findingId,
      occurrenceId,
      decisionLedger,
      severity: { level: severity },
      locations: [{ path: sourcePath, startLine: 1 }],
    }],
    evidenceRefs: [],
    sourceArtifacts: [],
  }
}

const MIGRATION_RULESET = {
  id: 'relayos-security-v1',
  digest: `sha256:${'7'.repeat(64)}`,
}
const MIGRATION_CURRENT_BLOB = `git-sha1:${'c'.repeat(40)}`
const MIGRATION_FIX_BLOB = `git-sha1:${'d'.repeat(40)}`
const MIGRATION_UNATTESTED_BLOB = `git-sha1:${'0'.repeat(40)}`

function migrationProducerFixture(kind = 'migration') {
  return {
    kind,
    identityBasis: 'ruleset',
    ruleset: MIGRATION_RULESET,
  }
}

function migrationCandidateObservation({
  observationId = OBSERVATION_ID,
  findingId = FINDING_ID,
  occurrenceId = OCCURRENCE_ID,
  decisionLedger = 'security-runtime',
  path: sourcePath = 'src/a.ts',
  severity = 'high',
  producer = migrationProducerFixture(),
  extraFindings = [],
} = {}) {
  return {
    observationId,
    observedAt: '2026-07-29T00:00:00.000Z',
    producer,
    target: { revision: REVISION },
    scope: { identityBasis: 'semantic-declaration' },
    findings: [
      {
        findingId,
        occurrenceId,
        decisionLedger,
        severity: { level: severity },
        locations: [{ path: sourcePath, startLine: 1 }],
      },
      ...extraFindings,
    ],
    evidenceRefs: [],
    sourceArtifacts: [],
  }
}

function migrationCurrentObservation({
  observationId = AFTER_OBSERVATION_ID,
  decisionLedger = 'security-runtime',
  producer = migrationProducerFixture(),
  files = [{
    path: 'src/a.ts',
    blob: MIGRATION_CURRENT_BLOB,
    status: 'reviewed',
  }],
  findings = [],
} = {}) {
  return {
    observationId,
    observedAt: '2026-07-30T00:00:00.000Z',
    producer,
    target: { revision: REVISION },
    scope: { identityBasis: 'exact-inventory', files },
    findings,
    evidenceRefs: [],
    sourceArtifacts: [],
  }
}

function migrationReviewContext(overrides = {}) {
  return reviewContext({ ruleset: MIGRATION_RULESET, ...overrides })
}

function migrationPolicy() {
  const base = policyInput()
  return parseAuditDecisionPolicy(
    policyInput({
      acceptedRulesets: ['atlas-security-v3', 'relayos-security-v1'],
      expiry: { ...base.expiry, severityOverrides: [] },
    }),
    POLICY_DIGEST,
  )
}

function exactObservation({
  observationId,
  rows,
  revision = REVISION,
}) {  const filesByKey = new Map()
  for (const row of rows) {
    for (const file of row.bindings) {
      filesByKey.set(`${file.path}\0${file.blob}`, {
        ...file,
        status: 'reviewed',
      })
    }
  }
  const files = [...filesByKey.values()].sort((left, right) =>
    left.path.localeCompare(right.path) || left.blob.localeCompare(right.blob)
  )
  return {
    observationId,
    observedAt: '2026-07-29T00:00:00.000Z',
    producer: {
      identityBasis: 'ruleset',
      ruleset: {
        id: 'atlas-security-v3',
        digest: RULESET_DIGEST,
      },
    },
    target: { revision },
    scope: {
      identityBasis: 'exact-inventory',
      files,
    },
    findings: rows.map((row) => ({
      findingId: row.findingId,
      occurrenceId: row.occurrenceId,
      decisionLedger: row.decisionLedger ?? 'security-runtime',
      severity: { level: row.severity ?? 'medium' },
      locations: row.bindings.map((file) => ({
        path: file.path,
        startLine: 1,
      })),
    })),
    evidenceRefs: [],
    sourceArtifacts: [],
  }
}

function reconciliationInput({
  beforeObservationIds,
  afterObservationIds,
  beforeOccurrenceIds,
  afterOccurrenceIds,
  ...overrides
}) {
  return {
    type: 'finding-reconciliation',
    comparisonId: computeAuditFindingComparisonId({
      beforeObservationIds: [...beforeObservationIds].sort(),
      afterObservationIds: [...afterObservationIds].sort(),
    }),
    decisionLedger: 'security-runtime',
    beforeOccurrenceIds: [...beforeOccurrenceIds].sort(),
    afterOccurrenceIds: [...afterOccurrenceIds].sort(),
    outcome: 'equivalent',
    confidence: 'high',
    reason: 'The exact binding algebra preserves the same root cause.',
    source: {
      kind: 'manual',
      name: 'identity:reviewer@example.invalid',
    },
    createdAt: '2026-07-29T02:00:00.000Z',
    createdAtBasis: 'recorded',
    evidenceRefs: [],
    ...overrides,
  }
}

function historyFixture(slug, observations) {
  let previousEntryDigest = null
  const entries = observations.map((observation) => {
    const observationDigest = digest(observation)
    const core = {
      observationId: observation.observationId,
      observationDigest,
      previousEntryDigest,
      observation,
    }
    const entry = {
      ...core,
      entryDigest: digest(core),
    }
    previousEntryDigest = entry.entryDigest
    return entry
  })
  return {
    formatVersion: 1,
    format: 'atlas-audit-history-v1',
    domain: 'security',
    slug,
    entries,
  }
}

function currentFixture(history, index = history.entries.length - 1) {
  const entry = history.entries[index]
  return {
    formatVersion: 3,
    format: 'atlas-audit-v3',
    domain: 'security',
    slug: history.slug,
    title: history.slug,
    current: entry.observation,
    currentDigest: entry.observationDigest,
    history: {
      path: `.atlas/audit-history/${history.slug}.json`,
      observationId: entry.observationId,
      entryDigest: entry.entryDigest,
    },
  }
}

function prepareEventLedger(slug, events) {
  let ledger = null
  for (const event of events) {
    ledger = prepareAuditDecisionAppend(
      ledger,
      'security',
      slug,
      event,
    ).ledger
  }
  return ledger
}

function policyInput(overrides = {}) {
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
    ...overrides,
  }
}

function reducerTrustFixture() {
  const observation = observationFixture({ severity: 'medium' })
  const history = historyFixture('security-runtime', [observation])
  const ledger = prepareEventLedger(
    'security-runtime',
    [validDispositionEvents()[2]],
  )
  return {
    index: buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [ledger],
    ),
    policy: parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
  }
}

function replaceDecisionViews(index, ledgers) {
  index.decisionLedgers = new Map()
  index.events = new Map()
  index.retirementEvents = []
  index.reconciliationEvents = []
  index.aliasEvents = []
  for (const ledger of [...ledgers].sort((left, right) =>
    left.slug.localeCompare(right.slug)
  )) {
    index.decisionLedgers.set(ledger.slug, ledger)
    for (const [chainIndex, entry] of ledger.entries.entries()) {
      index.events.set(entry.eventId, {
        decisionLedger: ledger.slug,
        chainIndex,
        eventDigest: digest(entry.event),
        event: entry.event,
      })
      if (entry.event.type === 'scope-retirement') {
        index.retirementEvents.push(entry.event)
      } else if (entry.event.type === 'finding-reconciliation') {
        index.reconciliationEvents.push(entry.event)
      } else if (entry.event.type === 'identity-alias-reconciliation') {
        index.aliasEvents.push(entry.event)
      }
    }
  }
  return index
}

function independentReview(reviewer, overrides = {}) {
  return {
    reviewer,
    verdict: 'approve',
    reason: 'Independent review approved this bounded decision.',
    evidence: 'Reviewed the exact source and decision proof.',
    evidenceRefs: [],
    createdAt: '2026-07-29T01:00:00.000Z',
    ...overrides,
  }
}

test('comparison identity matches the literal normative boundary vector', () => {
  const boundary = {
    beforeObservationIds: ['aobs_111111111111111111111111'],
    afterObservationIds: ['aobs_222222222222222222222222'],
  }
  const canonicalBoundary =
    '{"afterObservationIds":["aobs_222222222222222222222222"],"beforeObservationIds":["aobs_111111111111111111111111"]}'
  assert.equal(canonical(boundary), canonicalBoundary)
  assert.equal(
    sha256(`atlas-finding-comparison/v1\0${canonicalBoundary}`),
    '49e952b6b12da976599461aa0be7eb52ce0c9495e89b02bf5671f7d33425c0d4',
  )
  assert.equal(
    computeAuditFindingComparisonId(boundary),
    'acmp_49e952b6b12da976599461aa',
  )
  assert.notEqual(
    computeAuditFindingComparisonId({
      beforeObservationIds: boundary.afterObservationIds,
      afterObservationIds: boundary.beforeObservationIds,
    }),
    'acmp_49e952b6b12da976599461aa',
  )
  for (const invalid of [
    { beforeObservationIds: [], afterObservationIds: boundary.afterObservationIds },
    { beforeObservationIds: boundary.beforeObservationIds, afterObservationIds: [] },
    {
      beforeObservationIds: boundary.beforeObservationIds,
      afterObservationIds: boundary.beforeObservationIds,
    },
  ]) {
    assert.throws(
      () => computeAuditFindingComparisonId(invalid),
      /comparison|observation|nonempty|disjoint/i,
    )
  }
})

test('decision preparation uses independent event and entry formulas in chain order', () => {
  const input = aliasInput()
  const canonicalInput =
    '{"aliases":[{"scheme":"relayos-security-scan/v1","value":"SEC-ABC123"}],"createdAt":"2026-07-29T12:34:56.000Z","createdAtBasis":"source-revision-upper-bound","decisionLedger":"security-identity-access","evidenceRefs":[],"findingId":"atf_0d465ed12cdccf67f62645b4","occurrenceIds":["atocc_fe401c5bdff9b7bbde7c5fe6"],"relationship":"canonical","source":{"kind":"migration","name":"relayos-security-scan","version":"1"},"type":"identity-alias-reconciliation"}'
  assert.equal(canonical(input), canonicalInput)
  const first = prepareAuditDecisionAppend(
    null,
    'security',
    'security-identity-access',
    input,
  )
  assert.equal(first.event.eventId, 'adev_070b9b350a2dde2bae75a794')
  assert.equal(
    computeAuditDecisionEventId(input),
    'adev_070b9b350a2dde2bae75a794',
  )
  assert.equal(
    first.entry.entryDigest,
    'sha256:cf599f11d6339bf9460e2222c5159fde9a903fb675be1d14c5f8d8dcf2d4e1cf',
  )
  assert.equal(
    computeAuditDecisionEntryDigest({
      eventId: first.event.eventId,
      previousEntryDigest: null,
      event: first.event,
    }),
    'sha256:cf599f11d6339bf9460e2222c5159fde9a903fb675be1d14c5f8d8dcf2d4e1cf',
  )
  assert.equal(first.bytes, `${canonical(first.ledger)}\n`)
  assert.equal(first.status, 'append')

  const secondInput = aliasInput({
    aliases: [{
      scheme: 'relayos-security-scan/v1',
      value: 'SEC-OLDER-TIMESTAMP',
    }],
    createdAt: '2026-07-01T00:00:00.000Z',
  })
  const canonicalSecondInput =
    '{"aliases":[{"scheme":"relayos-security-scan/v1","value":"SEC-OLDER-TIMESTAMP"}],"createdAt":"2026-07-01T00:00:00.000Z","createdAtBasis":"source-revision-upper-bound","decisionLedger":"security-identity-access","evidenceRefs":[],"findingId":"atf_0d465ed12cdccf67f62645b4","occurrenceIds":["atocc_fe401c5bdff9b7bbde7c5fe6"],"relationship":"canonical","source":{"kind":"migration","name":"relayos-security-scan","version":"1"},"type":"identity-alias-reconciliation"}'
  assert.equal(canonical(secondInput), canonicalSecondInput)
  const second = prepareAuditDecisionAppend(
    first.ledger,
    'security',
    'security-identity-access',
    secondInput,
  )
  assert.equal(second.entry.previousEntryDigest, first.entry.entryDigest)
  assert.equal(second.event.eventId, 'adev_2ad52a2807387d80876f3807')
  assert.equal(
    second.entry.entryDigest,
    'sha256:38594e57db9ef22ff1fdab17f9a31a67d4f84f14ae9ec25c089ba13df2368d14',
  )
  assert.equal(second.ledger.entries.length, 2)
  assert.equal(second.status, 'append')
  assert.equal(
    prepareAuditDecisionAppend(
      second.ledger,
      'security',
      'security-identity-access',
      secondInput,
    ).status,
    'already-present',
  )
})

test('the pure identity registry distinguishes duplicates, collisions, and aliases', () => {
  const base = {
    namespace: 'decision-event',
    id: 'adev_111111111111111111111111',
    digest: `sha256:${'a'.repeat(64)}`,
    location: 'one',
  }
  assert.deepEqual(validateUniqueAuditIdentityRecords([base]), [])
  assert.match(
    validateUniqueAuditIdentityRecords([
      base,
      { ...base, location: 'two' },
    ]).map((row) => row.code).join('\n'),
    /duplicate/i,
  )
  assert.match(
    validateUniqueAuditIdentityRecords([
      base,
      { ...base, digest: `sha256:${'b'.repeat(64)}`, location: 'two' },
    ]).map((row) => row.code).join('\n'),
    /collision/i,
  )
  assert.match(
    validateUniqueAuditIdentityRecords([
      base,
      {
        ...base,
        id: 'adev_222222222222222222222222',
        location: 'two',
      },
    ]).map((row) => row.code).join('\n'),
    /alias/i,
  )
})

test('the identity registry rejects inherited and accessor-backed records without executing getters', () => {
  const inherited = Object.create({
    namespace: 'decision-event',
    id: 'adev_111111111111111111111111',
    digest: `sha256:${'a'.repeat(64)}`,
    location: 'inherited',
  })
  assert.match(
    validateUniqueAuditIdentityRecords([inherited])
      .map((row) => `${row.code} ${row.message}`)
      .join('\n'),
    /invalid|malformed|data|own|record/i,
  )

  let getterCalls = 0
  const accessor = {
    namespace: 'decision-event',
    id: 'adev_111111111111111111111111',
    digest: `sha256:${'a'.repeat(64)}`,
  }
  Object.defineProperty(accessor, 'location', {
    enumerable: true,
    get() {
      getterCalls += 1
      throw new Error('identity getter executed')
    },
  })
  assert.match(
    validateUniqueAuditIdentityRecords([accessor])
      .map((row) => `${row.code} ${row.message}`)
      .join('\n'),
    /invalid|malformed|data|accessor|record/i,
  )
  assert.equal(getterCalls, 0)
})

test('the decision-ledger entry limit is consistently enforced at 10,000', () => {
  const envelope = (entries) => ({
    formatVersion: 1,
    format: 'atlas-audit-decisions-v1',
    domain: 'security',
    slug: 'security-runtime',
    entries,
  })
  const parseLedger = (entries) => prepareAuditDecisionAppend(
    envelope(entries),
    'security',
    'security-runtime',
    aliasInput({ decisionLedger: 'security-runtime' }),
  )

  assert.throws(
    () => parseLedger(Array(10_000).fill(null)),
    (error) =>
      /entries\/0|object|record/i.test(error.message) &&
      !/over-limit|10000 entries/i.test(error.message),
  )
  assert.throws(
    () => parseLedger(Array(10_001).fill(null)),
    /10000/,
  )
})

test('append is locked, idempotent, canonical-byte exact, and reloadable', () => {
  const root = makeRoot()
  try {
    const input = aliasInput()
    const prepared = prepareAuditDecisionAppend(
      null,
      'security',
      'security-identity-access',
      input,
    )
    assert.deepEqual(
      appendAuditDecision(root, 'security-identity-access', input),
      {
        path: '.atlas/audit-decisions/security-identity-access.json',
        eventId: prepared.event.eventId,
        entryDigest: prepared.entry.entryDigest,
        status: 'appended',
      },
    )
    const ledgerPath = path.join(
      root,
      '.atlas',
      'audit-decisions',
      'security-identity-access.json',
    )
    assert.equal(fs.readFileSync(ledgerPath, 'utf8'), prepared.bytes)
    assert.deepEqual(loadAuditDecisionLedgers(root), {
      ledgers: [prepared.ledger],
      diagnostics: [],
    })

    writeDecisionLedger(root, prepared.ledger, true)
    assert.equal(
      appendAuditDecision(
        root,
        'security-identity-access',
        input,
      ).status,
      'already-present',
    )
    assert.equal(fs.readFileSync(ledgerPath, 'utf8'), prepared.bytes)

    const secondInput = aliasInput({
      aliases: [{
        scheme: 'relayos-security-scan/v1',
        value: 'SEC-OLDER-TIMESTAMP',
      }],
      createdAt: '2026-07-01T00:00:00.000Z',
    })
    assert.equal(
      appendAuditDecision(
        root,
        'security-identity-access',
        secondInput,
      ).status,
      'appended',
    )
    const loaded = loadAuditDecisionLedgers(root)
    assert.deepEqual(loaded.diagnostics, [])
    assert.equal(loaded.ledgers[0].entries.length, 2)
    assert.equal(
      loaded.ledgers[0].entries[1].event.createdAt,
      '2026-07-01T00:00:00.000Z',
    )
  } finally {
    cleanup(root)
  }
})

test('append rejects a proposed cross-ledger event identity duplicate', () => {
  const root = makeRoot()
  try {
    const event = validDispositionEvents()[0]
    assert.equal(
      appendAuditDecision(root, 'security-alpha', event).status,
      'appended',
    )
    assert.throws(
      () => appendAuditDecision(root, 'security-beta', event),
      /portfolio|global|identity|duplicate|collision/i,
    )
    assert.deepEqual(
      fs.readdirSync(
        path.join(root, '.atlas', 'audit-decisions'),
      ),
      ['security-alpha.json'],
    )
    assert.deepEqual(loadAuditDecisionLedgers(root).diagnostics, [])
  } finally {
    cleanup(root)
  }
})

test('append allows the exact ledger-count boundary and rejects the next file', () => {
  const root = makeRoot()
  try {
    for (let index = 0; index < 9_999; index += 1) {
      const slug = `security-count-${String(index).padStart(4, '0')}`
      writeDecisionLedger(
        root,
        prepareAuditDecisionAppend(
          null,
          'security',
          slug,
          aliasInput({ decisionLedger: slug }),
        ).ledger,
      )
    }
    const boundarySlug = 'security-count-boundary'
    assert.equal(
      appendAuditDecision(
        root,
        boundarySlug,
        aliasInput({ decisionLedger: boundarySlug }),
      ).status,
      'appended',
    )
    assert.equal(
      fs.readdirSync(
        path.join(root, '.atlas', 'audit-decisions'),
      ).length,
      10_000,
    )

    const overflowSlug = 'security-count-overflow'
    assert.throws(
      () => appendAuditDecision(
        root,
        overflowSlug,
        aliasInput({ decisionLedger: overflowSlug }),
      ),
      /portfolio|ledger.*count|10000|limit/i,
    )
    assert.equal(
      fs.existsSync(path.join(
        root,
        '.atlas',
        'audit-decisions',
        `${overflowSlug}.json`,
      )),
      false,
    )
  } finally {
    cleanup(root)
  }
})

test('append accounts for canonical replacement at the cumulative byte boundary', () => {
  const root = makeRoot()
  try {
    const portfolioLimit = 64 * 1024 * 1024
    const perLedgerLimit = 32 * 1024 * 1024
    const targetSlug = 'security-byte-target'
    const firstInput = aliasInput({ decisionLedger: targetSlug })
    const first = prepareAuditDecisionAppend(
      null,
      'security',
      targetSlug,
      firstInput,
    )
    const secondInput = aliasInput({
      decisionLedger: targetSlug,
      aliases: [{
        scheme: 'relayos-security-scan/v1',
        value: 'SEC-BYTE-SECOND',
      }],
      createdAt: '2026-07-29T13:00:00.000Z',
    })
    const second = prepareAuditDecisionAppend(
      first.ledger,
      'security',
      targetSlug,
      secondInput,
    )
    const appendGrowth =
      Buffer.byteLength(second.bytes) - Buffer.byteLength(first.bytes)
    const currentTotal = portfolioLimit - appendGrowth
    const fillerABytes = perLedgerLimit
    const fillerBBytes =
      currentTotal - fillerABytes - Buffer.byteLength(first.bytes)

    for (const [slug, size] of [
      ['security-byte-a', fillerABytes],
      ['security-byte-b', fillerBBytes],
    ]) {
      const prepared = prepareAuditDecisionAppend(
        null,
        'security',
        slug,
        aliasInput({ decisionLedger: slug }),
      )
      const paddingBytes = size - Buffer.byteLength(prepared.bytes)
      fs.writeFileSync(
        path.join(
          root,
          '.atlas',
          'audit-decisions',
          `${slug}.json`,
        ),
        `${' '.repeat(paddingBytes)}${prepared.bytes}`,
      )
    }
    writeDecisionLedger(root, first.ledger)

    assert.equal(
      appendAuditDecision(root, targetSlug, secondInput).status,
      'appended',
    )
    const bytesAtBoundary = fs.readFileSync(
      path.join(
        root,
        '.atlas',
        'audit-decisions',
        `${targetSlug}.json`,
      ),
    )
    assert.equal(bytesAtBoundary.toString('utf8'), second.bytes)
    assert.deepEqual(loadAuditDecisionLedgers(root).diagnostics, [])

    const thirdInput = aliasInput({
      decisionLedger: targetSlug,
      aliases: [{
        scheme: 'relayos-security-scan/v1',
        value: 'SEC-BYTE-THIRD',
      }],
      createdAt: '2026-07-29T14:00:00.000Z',
    })
    assert.throws(
      () => appendAuditDecision(root, targetSlug, thirdInput),
      /portfolio|cumulative|byte|67108864|limit/i,
    )
    assert.deepEqual(
      fs.readFileSync(path.join(
        root,
        '.atlas',
        'audit-decisions',
        `${targetSlug}.json`,
      )),
      bytesAtBoundary,
    )
  } finally {
    cleanup(root)
  }
})

test('decision loading fails closed on unknown, tampered, forked, reordered, and duplicate chains', () => {
  const first = prepareAuditDecisionAppend(
    null,
    'security',
    'security-identity-access',
    aliasInput(),
  )
  const second = prepareAuditDecisionAppend(
    first.ledger,
    'security',
    'security-identity-access',
    aliasInput({
      aliases: [{
        scheme: 'relayos-security-scan/v1',
        value: 'SEC-OLDER-TIMESTAMP',
      }],
      createdAt: '2026-07-01T00:00:00.000Z',
    }),
  )
  const cases = [
    {
      label: 'unknown',
      mutate(ledger) {
        ledger.entries[0].event.unknown = true
      },
    },
    {
      label: 'tampered',
      mutate(ledger) {
        ledger.entries[0].event.aliases[0].value = 'SEC-TAMPERED'
      },
    },
    {
      label: 'forked',
      mutate(ledger) {
        ledger.entries[1].previousEntryDigest = null
      },
    },
    {
      label: 'reordered',
      mutate(ledger) {
        ledger.entries.reverse()
      },
    },
    {
      label: 'duplicate',
      mutate(ledger) {
        const duplicated = structuredClone(ledger.entries[0])
        duplicated.previousEntryDigest = ledger.entries.at(-1).entryDigest
        duplicated.entryDigest = digest({
          eventId: duplicated.eventId,
          previousEntryDigest: duplicated.previousEntryDigest,
          event: duplicated.event,
        })
        ledger.entries.push(duplicated)
      },
    },
  ]
  for (const { label, mutate } of cases) {
    const root = makeRoot()
    try {
      const candidate = structuredClone(second.ledger)
      mutate(candidate)
      writeDecisionLedger(root, candidate)
      const loaded = loadAuditDecisionLedgers(root)
      assert.equal(loaded.ledgers.length, 0, label)
      assert.match(
        loaded.diagnostics.map((row) =>
          `${row.code} ${row.path} ${row.message}`
        ).join('\n'),
        /unknown|mismatch|chain|duplicate|identity|digest/i,
        label,
      )
    } finally {
      cleanup(root)
    }
  }
})

test('decision portfolio loading has ledger-count and cumulative raw-byte budgets', () => {
  const countRoot = makeRoot()
  try {
    for (let index = 0; index < 10_002; index += 1) {
      fs.writeFileSync(
        path.join(
          countRoot,
          '.atlas',
          'audit-decisions',
          `security-budget-${String(index).padStart(5, '0')}.json`,
        ),
        '',
      )
    }
    const loaded = loadAuditDecisionLedgers(countRoot)
    assert.equal(loaded.ledgers.length, 0)
    assert.equal(loaded.diagnostics.length, 1)
    assert.equal(
      loaded.diagnostics[0].code,
      'audit-decision-portfolio-ledger-limit',
    )
    assert.match(
      `${loaded.diagnostics[0].code} ${loaded.diagnostics[0].message}`,
      /portfolio|ledger.*count|10000|limit/i,
    )
  } finally {
    cleanup(countRoot)
  }

  const bytesRoot = makeRoot()
  try {
    const padding = ' '.repeat(22 * 1024 * 1024)
    for (const suffix of ['alpha', 'beta', 'gamma']) {
      const slug = `security-budget-${suffix}`
      const input = aliasInput({ decisionLedger: slug })
      const prepared = prepareAuditDecisionAppend(
        null,
        'security',
        slug,
        input,
      )
      fs.writeFileSync(
        path.join(
          bytesRoot,
          '.atlas',
          'audit-decisions',
          `${slug}.json`,
        ),
        `${padding}${prepared.bytes}`,
      )
    }
    const loaded = loadAuditDecisionLedgers(bytesRoot)
    assert.equal(loaded.ledgers.length, 0)
    assert.equal(loaded.diagnostics.length, 1)
    assert.match(
      `${loaded.diagnostics[0].code} ${loaded.diagnostics[0].message}`,
      /portfolio|cumulative|byte|67108864|limit/i,
    )
  } finally {
    cleanup(bytesRoot)
  }

  const boundaryRoot = makeRoot()
  try {
    const perFileBytes = 32 * 1024 * 1024
    for (const suffix of ['alpha', 'beta']) {
      const slug = `security-boundary-${suffix}`
      const prepared = prepareAuditDecisionAppend(
        null,
        'security',
        slug,
        aliasInput({ decisionLedger: slug }),
      )
      const paddingBytes =
        perFileBytes - Buffer.byteLength(prepared.bytes, 'utf8')
      fs.writeFileSync(
        path.join(
          boundaryRoot,
          '.atlas',
          'audit-decisions',
          `${slug}.json`,
        ),
        `${' '.repeat(paddingBytes)}${prepared.bytes}`,
      )
    }
    const exactBoundary = loadAuditDecisionLedgers(boundaryRoot)
    assert.equal(exactBoundary.ledgers.length, 2)
    assert.deepEqual(exactBoundary.diagnostics, [])

    const extraSlug = 'security-boundary-gamma'
    const extra = prepareAuditDecisionAppend(
      null,
      'security',
      extraSlug,
      aliasInput({ decisionLedger: extraSlug }),
    )
    fs.writeFileSync(
      path.join(
        boundaryRoot,
        '.atlas',
        'audit-decisions',
        `${extraSlug}.json`,
      ),
      extra.bytes,
    )
    const overflow = loadAuditDecisionLedgers(boundaryRoot)
    assert.equal(overflow.ledgers.length, 0)
    assert.equal(overflow.diagnostics.length, 1)
    assert.match(
      `${overflow.diagnostics[0].code} ${overflow.diagnostics[0].message}`,
      /portfolio|cumulative|byte|67108864|limit/i,
    )
  } finally {
    cleanup(boundaryRoot)
  }
})

test('malformed decision ledgers still consume the cumulative raw-byte budget', () => {
  const root = makeRoot()
  const originalRead = fs.readSync
  let finalLedgerBytesRead = 0
  try {
    const malformed = Buffer.alloc(22 * 1024 * 1024, 0x20)
    malformed[0] = 0x21
    for (const suffix of ['alpha', 'beta', 'gamma']) {
      fs.writeFileSync(
        path.join(
          root,
          '.atlas',
          'audit-decisions',
          `security-malformed-${suffix}.json`,
        ),
        malformed,
      )
    }
    const finalLedgerPath = path.join(
      root,
      '.atlas',
      'audit-decisions',
      'security-malformed-gamma.json',
    )
    fs.readSync = function boundedPortfolioRead(fd, ...args) {
      let openedPath = ''
      try {
        openedPath = fs.readlinkSync(`/proc/self/fd/${fd}`)
      } catch {
        // Non-file descriptors are outside this assertion.
      }
      const bytesRead = originalRead.call(fs, fd, ...args)
      if (openedPath === finalLedgerPath) {
        finalLedgerBytesRead += bytesRead
      }
      return bytesRead
    }
    const loaded = loadAuditDecisionLedgers(root)
    assert.equal(loaded.ledgers.length, 0)
    assert.equal(loaded.diagnostics.length, 1)
    assert.match(
      `${loaded.diagnostics[0].code} ${loaded.diagnostics[0].message}`,
      /portfolio|cumulative|raw-byte|67108864|limit/i,
    )
    assert.equal(
      finalLedgerBytesRead,
      0,
      'the descriptor size check must stop before reading past the portfolio budget',
    )
  } finally {
    fs.readSync = originalRead
    cleanup(root)
  }
})

test('all seven finding actions and their proof/evidence unions are closed', () => {
  const events = validDispositionEvents()
  for (const [index, event] of events.entries()) {
    const prepared = prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      event,
    )
    assert.equal(prepared.event.action, event.action, String(index))
    assert.match(prepared.event.eventId, /^adev_[0-9a-f]{24}$/u)
  }

  const invalidCases = [
    {
      label: 'open forbids expiry',
      index: 0,
      mutate(event) {
        event.expiresAt = null
      },
    },
    {
      label: 'reopened requires supersession',
      index: 1,
      mutate(event) {
        delete event.supersedesEventId
      },
    },
    {
      label: 'accepted risk requires non-null expiry',
      index: 2,
      mutate(event) {
        event.expiresAt = null
      },
    },
    {
      label: 'separate design forbids action evidence',
      index: 3,
      mutate(event) {
        event.actionEvidence = {
          kind: 'source-evidence',
          reviewedBindings: [binding()],
          conclusion: 'not-reportable',
          rationale: 'foreign branch',
        }
      },
    },
    {
      label: 'false positive requires source proof',
      index: 4,
      mutate(event) {
        event.proofs = [currentReviewProof()]
      },
    },
    {
      label: 'remediation requires passing regression',
      index: 5,
      mutate(event) {
        event.regression.result = 'failed'
      },
    },
    {
      label: 'replacement supersession forbids regression',
      index: 6,
      mutate(event) {
        event.regression = {
          kind: 'manual',
          name: 'foreign branch',
          result: 'passed',
          binding: {
            repositoryRevision: REVISION,
            files: [binding()],
          },
        }
      },
    },
    {
      label: 'deletion supersession requires both proof kinds',
      index: 7,
      mutate(event) {
        event.proofs = [deletionProof()]
      },
    },
  ]
  for (const { label, index, mutate } of invalidCases) {
    const event = structuredClone(events[index])
    mutate(event)
    assert.throws(
      () => prepareAuditDecisionAppend(
        null,
        'security',
        'security-runtime',
        event,
      ),
      /action|evidence|expiry|expiresAt|proof|regression|supersed|required|forbid|unknown|timestamp|nonempty|string/i,
      label,
    )
  }
})

test('review, regression, context, source, proof, and action-evidence members fail closed', () => {
  const cases = [
    {
      label: 'context unknown',
      event: validDispositionEvents()[2],
      mutate(event) {
        event.reviewContext.ambientRuleset = true
      },
    },
    {
      label: 'review unknown',
      event: validDispositionEvents()[2],
      mutate(event) {
        event.reviews = [{
          reviewer: 'identity:second@example.invalid',
          verdict: 'approve',
          reason: 'Independent approval.',
          evidence: 'Reviewed exact bindings.',
          evidenceRefs: [],
          createdAt: '2026-07-29T01:00:00.000Z',
          ambientAuthority: true,
        }]
      },
    },
    {
      label: 'regression cross variant',
      event: validDispositionEvents()[5],
      mutate(event) {
        event.regression.kind = 'manual'
        delete event.regression.command
      },
    },
    {
      label: 'source manual version',
      event: aliasInput({
        source: {
          kind: 'manual',
          name: 'identity:reviewer@example.invalid',
          version: 'forbidden',
        },
      }),
      mutate() {},
    },
    {
      label: 'proof unknown',
      event: validDispositionEvents()[4],
      mutate(event) {
        event.proofs[0].foreignConclusion = true
      },
    },
    {
      label: 'action evidence unknown',
      event: validDispositionEvents()[4],
      mutate(event) {
        event.actionEvidence.foreignConclusion = true
      },
    },
  ]
  for (const { label, event: sourceEvent, mutate } of cases) {
    const event = structuredClone(sourceEvent)
    mutate(event)
    assert.throws(
      () => prepareAuditDecisionAppend(
        null,
        'security',
        event.decisionLedger ?? 'security-runtime',
        event,
      ),
      /unknown|member|variant|manual|command|version|regression|test|guardrail|check/i,
      label,
    )
  }

  const migrated = validDispositionEvents()[2]
  migrated.createdAtBasis = 'source'
  assert.throws(
    () => prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      migrated,
    ),
    /sourceArtifact|migrated|source proof/i,
  )
  migrated.proofs[0].sourceArtifact = SOURCE_ARTIFACT
  assert.equal(
    prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      migrated,
    ).status,
    'append',
  )

  const migratedRetirement = validRetirementEvents()[4]
  migratedRetirement.createdAtBasis = 'source'
  assert.throws(
    () => prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      migratedRetirement,
    ),
    /sourceArtifact|migrated|source proof/i,
  )
  migratedRetirement.noReplacementProof.sourceArtifact = SOURCE_ARTIFACT
  assert.equal(
    prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      migratedRetirement,
    ).status,
    'append',
  )
})

test('all retirement reason branches enforce exact required and forbidden members', () => {
  const events = validRetirementEvents()
  for (const [index, event] of events.entries()) {
    const prepared = prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      event,
    )
    assert.equal(prepared.event.reason, event.reason, String(index))
  }

  const invalidCases = [
    {
      label: 'staged forbids deletion commit',
      index: 0,
      mutate(event) {
        event.deletionCommit = REVISION
      },
    },
    {
      label: 'deleted requires proof',
      index: 1,
      mutate(event) {
        delete event.deletionProof
      },
    },
    {
      label: 'moved requires successor equality',
      index: 2,
      mutate(event) {
        event.successor.blob = `git-sha1:${'f'.repeat(40)}`
      },
    },
    {
      label: 'successor supersession forbids no replacement',
      index: 3,
      mutate(event) {
        event.noReplacementProof = noReplacementProof()
      },
    },
    {
      label: 'no replacement supersession forbids successor',
      index: 4,
      mutate(event) {
        event.successor = binding('src/new-a.ts')
      },
    },
    {
      label: 'migration absence forbids revision proof',
      index: 5,
      mutate(event) {
        event.revisionProof = treeState()
      },
    },
    {
      label: 'date precision requires original date',
      index: 5,
      mutate(event) {
        delete event.originalRetiredDate
      },
    },
  ]
  for (const { label, index, mutate } of invalidCases) {
    const event = structuredClone(events[index])
    mutate(event)
    assert.throws(
      () => prepareAuditDecisionAppend(
        null,
        'security',
        'security-runtime',
        event,
      ),
      /retire|reason|proof|successor|date|member|required|forbid|unknown|blob/i,
      label,
    )
  }
})

test('temporal and identity reconciliation unions enforce direction and group shape', () => {
  const comparisonId = 'acmp_49e952b6b12da976599461aa'
  const base = {
    type: 'finding-reconciliation',
    comparisonId,
    decisionLedger: 'security-runtime',
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [
      REPLACEMENT_OCCURRENCE_ID,
      SPLIT_OCCURRENCE_ID,
    ].sort(),
    outcome: 'equivalent',
    confidence: 'high',
    reason: 'The exact binding partition preserves one root cause.',
    source: {
      kind: 'manual',
      name: 'identity:reviewer@example.invalid',
    },
    createdAt: '2026-07-29T00:00:00.000Z',
    createdAtBasis: 'recorded',
    evidenceRefs: [],
  }
  assert.equal(
    prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      base,
    ).status,
    'append',
  )
  assert.equal(
    prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      {
        ...base,
        beforeOccurrenceIds: base.afterOccurrenceIds,
        afterOccurrenceIds: base.beforeOccurrenceIds,
      },
    ).status,
    'append',
  )
  const correction = {
    ...base,
    outcome: 'distinct',
    confidence: 'medium',
    supersedesEventId: 'adev_111111111111111111111111',
  }
  assert.equal(
    prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      correction,
    ).status,
    'append',
  )

  for (const { label, event } of [
    {
      label: 'many-to-many',
      event: {
        ...base,
        beforeOccurrenceIds: [
          OCCURRENCE_ID,
          'atocc_ffffffffffffffffffffffff',
        ],
      },
    },
    {
      label: 'overlap',
      event: {
        ...base,
        afterOccurrenceIds: [OCCURRENCE_ID],
      },
    },
    {
      label: 'unknown',
      event: {
        ...base,
        comparisonTranscript: 'ambient',
      },
    },
  ]) {
    assert.throws(
      () => prepareAuditDecisionAppend(
        null,
        'security',
        'security-runtime',
        event,
      ),
      /reconciliation|many-to-many|overlap|disjoint|unknown|member/i,
      label,
    )
  }

  const alias = aliasInput()
  const withUnknownAlias = structuredClone(alias)
  withUnknownAlias.aliases[0].ambientMapping = true
  assert.throws(
    () => prepareAuditDecisionAppend(
      null,
      'security',
      'security-identity-access',
      withUnknownAlias,
    ),
    /alias|unknown|member/i,
  )
})

test('global index keeps every history occurrence but only the current pointer authoritative', () => {
  const historical = observationFixture()
  const ahead = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    occurrenceId: SPLIT_OCCURRENCE_ID,
    blob: `git-sha1:${'a'.repeat(40)}`,
  })
  const history = historyFixture(
    'security-runtime',
    [historical, ahead],
  )
  const currentBeforeSwitch = currentFixture(history, 0)
  const aheadContext = reviewContext({
    observationId: AFTER_OBSERVATION_ID,
    bindings: [binding('src/a.ts', `git-sha1:${'a'.repeat(40)}`)],
  })
  const aheadOpen = dispositionBase({
    occurrenceId: SPLIT_OCCURRENCE_ID,
    action: 'open',
    reviewContext: aheadContext,
    proofs: [currentReviewProof({
      observationId: AFTER_OBSERVATION_ID,
      reviewedBindings: aheadContext.bindings,
    })],
  })
  const decisions = prepareEventLedger('security-runtime', [aheadOpen])

  const before = buildAuditDecisionIndex(
    [currentBeforeSwitch],
    [history],
    [decisions],
  )
  assert.deepEqual(
    before.findings.get(FINDING_ID).occurrenceIds,
    [OCCURRENCE_ID, SPLIT_OCCURRENCE_ID].sort(),
  )
  assert.deepEqual(
    before.findings.get(FINDING_ID).currentOccurrenceIds,
    [OCCURRENCE_ID],
  )
  assert.equal(before.occurrences.get(OCCURRENCE_ID).authoritative, true)
  assert.equal(
    before.occurrences.get(SPLIT_OCCURRENCE_ID).authoritative,
    false,
  )
  assert.equal(before.events.size, 1)

  const after = buildAuditDecisionIndex(
    [currentFixture(history, 1)],
    [history],
    [decisions],
  )
  assert.deepEqual(
    after.findings.get(FINDING_ID).currentOccurrenceIds,
    [SPLIT_OCCURRENCE_ID],
  )
  assert.equal(after.occurrences.get(OCCURRENCE_ID).authoritative, false)
  assert.equal(after.occurrences.get(SPLIT_OCCURRENCE_ID).authoritative, true)
})

test('global index proves a stable decision home before allowing a finding to move units', () => {
  const origin = observationFixture({
    decisionLedger: 'security-runtime',
  })
  const moved = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    occurrenceId: SPLIT_OCCURRENCE_ID,
    decisionLedger: 'security-runtime',
  })
  const originHistory = historyFixture('security-runtime', [origin])
  const movedHistory = historyFixture('security-new-unit', [moved])
  assert.equal(
    buildAuditDecisionIndex(
      [
        currentFixture(originHistory),
        currentFixture(movedHistory),
      ],
      [originHistory, movedHistory],
      [],
    ).findings.get(FINDING_ID).decisionLedger,
    'security-runtime',
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(movedHistory)],
      [originHistory, movedHistory],
      [],
    ),
    /finding|decision.*home|published|history-ahead|accepted/i,
  )

  const nonexistentHome = structuredClone(moved)
  nonexistentHome.findings[0].decisionLedger = 'security-missing-home'
  const invalidHistory = historyFixture(
    'security-new-unit',
    [nonexistentHome],
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(invalidHistory)],
      [invalidHistory],
      [],
    ),
    /finding|decision.*home|ledger|history|missing/i,
  )
})

test('global index rejects invalid pointers, ownership, and decision context references', () => {
  const observation = observationFixture()
  const history = historyFixture('security-runtime', [observation])
  const current = currentFixture(history)
  const accepted = validDispositionEvents()[2]
  const validDecisions = prepareEventLedger('security-runtime', [accepted])
  assert.equal(
    buildAuditDecisionIndex(
      [current],
      [history],
      [validDecisions],
    ).events.size,
    1,
  )

  const cases = [
    {
      label: 'unknown occurrence',
      event() {
        const candidate = structuredClone(accepted)
        candidate.occurrenceId = 'atocc_999999999999999999999999'
        return candidate
      },
    },
    {
      label: 'mismatched path',
      event() {
        const candidate = structuredClone(accepted)
        candidate.reviewContext.bindings = [binding('src/other.ts')]
        candidate.proofs[0].reviewedBindings =
          candidate.reviewContext.bindings
        return candidate
      },
    },
    {
      label: 'mismatched blob',
      event() {
        const candidate = structuredClone(accepted)
        candidate.reviewContext.bindings = [
          binding('src/a.ts', `git-sha1:${'f'.repeat(40)}`),
        ]
        candidate.proofs[0].reviewedBindings =
          candidate.reviewContext.bindings
        return candidate
      },
    },
    {
      label: 'mismatched ruleset',
      event() {
        const candidate = structuredClone(accepted)
        candidate.reviewContext.ruleset.digest = `sha256:${'f'.repeat(64)}`
        return candidate
      },
    },
  ]
  for (const { label, event } of cases) {
    const decisions = prepareEventLedger('security-runtime', [event()])
    assert.throws(
      () => buildAuditDecisionIndex(
        [current],
        [history],
        [decisions],
      ),
      /unknown|occurrence|binding|path|blob|ruleset|context|reference/i,
      label,
    )
  }

  const conflictingObservation = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    decisionLedger: 'security-other',
  })
  const conflictingHistory = historyFixture(
    'security-other',
    [conflictingObservation],
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [current, currentFixture(conflictingHistory)],
      [history, conflictingHistory],
      [],
    ),
    /finding|ownership|ledger|collision/i,
  )

  const semantic = observationFixture({ exact: false })
  const semanticHistory = historyFixture('security-runtime', [semantic])
  const semanticIndex = buildAuditDecisionIndex(
    [currentFixture(semanticHistory)],
    [semanticHistory],
    [],
  )
  assert.equal(semanticIndex.occurrences.get(OCCURRENCE_ID).closureEligible, false)
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(semanticHistory)],
      [semanticHistory],
      [validDecisions],
    ),
    /semantic|exact|ruleset|binding|context|close|decision/i,
  )

  const contextOnly = observationFixture({ reviewed: false })
  const contextHistory = historyFixture('security-runtime', [contextOnly])
  const contextIndex = buildAuditDecisionIndex(
    [currentFixture(contextHistory)],
    [contextHistory],
    [],
  )
  assert.deepEqual(
    contextIndex.occurrences.get(OCCURRENCE_ID).bindings,
    [binding()],
  )
  assert.deepEqual(
    contextIndex.occurrences.get(OCCURRENCE_ID).reviewedBindings,
    [],
  )
  assert.equal(
    contextIndex.occurrences.get(OCCURRENCE_ID).closureEligible,
    false,
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(contextHistory)],
      [contextHistory],
      [validDecisions],
    ),
    /reviewed|closure|eligible|context|decision/i,
  )
})

test('migration validation context governs migrated semantic-only occurrences', () => {
  // The RelayOS migrator deliberately does not fabricate exact scope for the
  // candidates layer: the governed occurrence is semantic-only, yet its
  // migration-produced observation carries a real ruleset and the event
  // review context deterministically references the migration validation
  // observation. Such dispositions must reduce.
  const candidates = migrationCandidateObservation()
  const currentOccurrence = {
    findingId: FINDING_ID,
    occurrenceId: SPLIT_OCCURRENCE_ID,
    decisionLedger: 'security-runtime',
    severity: { level: 'high' },
    locations: [{ path: 'src/a.ts', startLine: 1 }],
  }
  const current = migrationCurrentObservation({ findings: [currentOccurrence] })
  const history = historyFixture('security-runtime', [candidates, current])
  const currentWrapper = currentFixture(history)
  const acceptedRisk = dispositionBase({
    action: 'accepted-risk',
    occurrenceId: OCCURRENCE_ID,
    expiresAt: '2026-08-28T00:00:00.000Z',
    reviewContext: migrationReviewContext({
      observationId: AFTER_OBSERVATION_ID,
      bindings: [binding('src/a.ts', MIGRATION_CURRENT_BLOB)],
    }),
    proofs: [currentReviewProof({
      observationId: AFTER_OBSERVATION_ID,
      reviewedBindings: [binding('src/a.ts', MIGRATION_CURRENT_BLOB)],
    })],
  })
  const decisions = prepareEventLedger('security-runtime', [acceptedRisk])
  const index = buildAuditDecisionIndex(
    [currentWrapper],
    [history],
    [decisions],
  )
  const occurrence = index.occurrences.get(OCCURRENCE_ID)
  assert.equal(occurrence.closureEligible, false)
  assert.equal(occurrence.ruleset.id, 'relayos-security-v1')
  const carried = reduceAuditDecisionState(
    index,
    migrationPolicy(),
    '2026-08-01T00:00:00.000Z',
  ).findings.get(FINDING_ID)
  assert.equal(carried.disposition, 'accepted-risk')
  assert.equal(carried.blocking, false)
  assert.equal(carried.derivation, 'carried')

  // A migrated remediation references the candidates observation in its
  // review context and quotes the sealed legacy fix blob, which is not an
  // attested receipt in the later exact observation.
  const remediationCandidates = migrationCandidateObservation()
  const remediationCurrent = migrationCurrentObservation()
  const remediationHistory = historyFixture(
    'security-runtime',
    [remediationCandidates, remediationCurrent],
  )
  const remediated = dispositionBase({
    action: 'remediated',
    occurrenceId: OCCURRENCE_ID,
    reviewContext: migrationReviewContext({
      observationId: OBSERVATION_ID,
      bindings: [binding()],
    }),
    proofs: [postFixProof({
      beforeObservationId: OBSERVATION_ID,
      afterObservationId: AFTER_OBSERVATION_ID,
      beforeBindings: [binding()],
      afterBindings: [binding('src/a.ts', MIGRATION_FIX_BLOB)],
      fixRevision: REVISION,
    })],
    regression: {
      kind: 'test',
      name: 'authorization regression',
      command: 'pnpm test',
      result: 'passed',
      binding: {
        repositoryRevision: REVISION,
        observationId: AFTER_OBSERVATION_ID,
        files: [binding('src/a.ts', MIGRATION_FIX_BLOB)],
      },
    },
    actionEvidence: {
      kind: 'remediation',
      beforeBindings: [binding()],
      afterBindings: [binding('src/a.ts', MIGRATION_FIX_BLOB)],
      fixRevision: REVISION,
    },
  })
  const remediationDecisions = prepareEventLedger(
    'security-runtime',
    [remediated],
  )
  const remediationIndex = buildAuditDecisionIndex(
    [currentFixture(remediationHistory)],
    [remediationHistory],
    [remediationDecisions],
  )
  const resolved = reduceAuditDecisionState(
    remediationIndex,
    migrationPolicy(),
    '2026-08-01T00:00:00.000Z',
  ).findings.get(FINDING_ID)
  assert.equal(resolved.disposition, 'remediated')
  assert.equal(resolved.blocking, false)
  assert.equal(resolved.lifecycle, 'resolved')

  // A migrated false positive quotes a reviewed blob that predates the
  // current scan blob; the source-evidence binding is sealed legacy evidence,
  // not a receipt in the exact current observation.
  const falsePositiveHistory = historyFixture(
    'security-runtime',
    [migrationCandidateObservation(), migrationCurrentObservation()],
  )
  const falsePositive = dispositionBase({
    action: 'false-positive',
    occurrenceId: OCCURRENCE_ID,
    expiresAt: null,
    reviewContext: migrationReviewContext({
      observationId: AFTER_OBSERVATION_ID,
      bindings: [binding('src/a.ts', MIGRATION_UNATTESTED_BLOB)],
    }),
    proofs: [sourceEvidenceProof({
      observationId: AFTER_OBSERVATION_ID,
      reviewedBindings: [binding('src/a.ts', MIGRATION_UNATTESTED_BLOB)],
    })],
    actionEvidence: {
      kind: 'source-evidence',
      reviewedBindings: [binding('src/a.ts', MIGRATION_UNATTESTED_BLOB)],
      conclusion: 'not-reportable',
      rationale: 'The sealed legacy review disproves the report.',
    },
  })
  const falsePositiveDecisions = prepareEventLedger(
    'security-runtime',
    [falsePositive],
  )
  const falsePositiveIndex = buildAuditDecisionIndex(
    [currentFixture(falsePositiveHistory)],
    [falsePositiveHistory],
    [falsePositiveDecisions],
  )
  const disproved = reduceAuditDecisionState(
    falsePositiveIndex,
    migrationPolicy(),
    '2026-08-01T00:00:00.000Z',
  ).findings.get(FINDING_ID)
  assert.equal(disproved.disposition, 'false-positive')
  assert.equal(disproved.blocking, false)

  // A migrated supersession through deletion quotes deleted bindings that no
  // observation ever attested; the no-replacement search stays bound to the
  // exact migration observation and its revision.
  const deletionCandidates = migrationCandidateObservation({
    path: 'src/deleted.ts',
  })
  const deletionCurrent = migrationCurrentObservation()
  const deletionHistory = historyFixture(
    'security-runtime',
    [deletionCandidates, deletionCurrent],
  )
  const superseded = dispositionBase({
    action: 'superseded',
    occurrenceId: OCCURRENCE_ID,
    reviewContext: migrationReviewContext({
      observationId: OBSERVATION_ID,
      bindings: [binding('src/deleted.ts')],
    }),
    proofs: [
      deletionProof({
        deletedBindings: [binding('src/deleted.ts', MIGRATION_UNATTESTED_BLOB)],
      }),
      noReplacementProof({
        observationId: AFTER_OBSERVATION_ID,
        searchRevision: REVISION,
        reviewedBindings: [binding('src/deleted.ts')],
      }),
    ],
    actionEvidence: {
      kind: 'deletion',
      deletionCommit: REVISION,
      deletedBindings: [binding('src/deleted.ts', MIGRATION_UNATTESTED_BLOB)],
      noReplacementEvidence: {
        observationId: AFTER_OBSERVATION_ID,
        searchRevision: REVISION,
        reviewedBindings: [binding('src/deleted.ts')],
        summary: 'No replacement remains after deletion.',
      },
    },
  })
  const deletionDecisions = prepareEventLedger('security-runtime', [superseded])
  const deletionIndex = buildAuditDecisionIndex(
    [currentFixture(deletionHistory)],
    [deletionHistory],
    [deletionDecisions],
  )
  const replaced = reduceAuditDecisionState(
    deletionIndex,
    migrationPolicy(),
    '2026-08-01T00:00:00.000Z',
  ).findings.get(FINDING_ID)
  assert.equal(replaced.disposition, 'superseded')
  assert.equal(replaced.blocking, false)

  // A migrated supersession through replacement tracks a semantic-only
  // replacement occurrence from the same migration corpus.
  const replacementFinding = {
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    decisionLedger: 'security-runtime',
    severity: { level: 'medium' },
    locations: [{ path: 'src/b.ts', startLine: 1 }],
  }
  const replacementCandidates = migrationCandidateObservation({
    path: 'src/superseded.ts',
    extraFindings: [replacementFinding],
  })
  const replacementCurrent = migrationCurrentObservation()
  const replacementHistory = historyFixture(
    'security-runtime',
    [replacementCandidates, replacementCurrent],
  )
  const replacement = dispositionBase({
    action: 'superseded',
    occurrenceId: OCCURRENCE_ID,
    reviewContext: migrationReviewContext({
      observationId: OBSERVATION_ID,
      bindings: [binding('src/superseded.ts')],
    }),
    proofs: [replacementProof({
      observationId: AFTER_OBSERVATION_ID,
      replacementBindings: [binding('src/superseded.ts')],
    })],
    actionEvidence: {
      kind: 'replacement',
      replacementFindingId: REPLACEMENT_FINDING_ID,
      replacementOccurrenceId: REPLACEMENT_OCCURRENCE_ID,
    },
  })
  const replacementDecisions = prepareEventLedger(
    'security-runtime',
    [replacement],
  )
  const replacementIndex = buildAuditDecisionIndex(
    [currentFixture(replacementHistory)],
    [replacementHistory],
    [replacementDecisions],
  )
  const tracked = reduceAuditDecisionState(
    replacementIndex,
    migrationPolicy(),
    '2026-08-01T00:00:00.000Z',
  ).findings.get(FINDING_ID)
  assert.equal(tracked.disposition, 'superseded')
  assert.equal(tracked.blocking, false)
})

test('migration validation context rejects tampered or non-migration contexts', () => {
  const candidates = migrationCandidateObservation()
  const current = migrationCurrentObservation()
  const history = historyFixture('security-runtime', [candidates, current])
  const currentWrapper = currentFixture(history)
  const acceptedRisk = (overrides = {}) => dispositionBase({
    action: 'accepted-risk',
    occurrenceId: OCCURRENCE_ID,
    expiresAt: '2026-08-28T00:00:00.000Z',
    reviewContext: migrationReviewContext({
      observationId: AFTER_OBSERVATION_ID,
      bindings: [binding('src/a.ts', MIGRATION_CURRENT_BLOB)],
    }),
    proofs: [currentReviewProof({
      observationId: AFTER_OBSERVATION_ID,
      reviewedBindings: [binding('src/a.ts', MIGRATION_CURRENT_BLOB)],
    })],
    ...overrides,
  })
  const reject = (label, event, pattern = /semantic|migration|context|ruleset|binding|location|exact/i) => {
    const decisions = prepareEventLedger('security-runtime', [event])
    assert.throws(
      () => buildAuditDecisionIndex([currentWrapper], [history], [decisions]),
      pattern,
      label,
    )
  }

  reject(
    'tampered review-context ruleset digest',
    acceptedRisk({
      reviewContext: migrationReviewContext({
        observationId: AFTER_OBSERVATION_ID,
        bindings: [binding('src/a.ts', MIGRATION_CURRENT_BLOB)],
        ruleset: {
          id: 'relayos-security-v1',
          digest: `sha256:${'f'.repeat(64)}`,
        },
      }),
    }),
  )
  // A review context naming a non-migration observation — even one carrying
  // the same ruleset receipt — is not a migration validation context.
  {
    const nativeCurrent = migrationCurrentObservation({
      producer: {
        kind: 'grok-cli',
        identityBasis: 'ruleset',
        ruleset: MIGRATION_RULESET,
      },
    })
    const nativeHistory = historyFixture('security-runtime', [
      migrationCandidateObservation(),
      nativeCurrent,
    ])
    const decisions = prepareEventLedger('security-runtime', [acceptedRisk()])
    assert.throws(
      () => buildAuditDecisionIndex(
        [currentFixture(nativeHistory)],
        [nativeHistory],
        [decisions],
      ),
      /semantic|migration|context|observation/i,
      'review-context observation outside the migration corpus',
    )
  }
  reject(
    'review-context bindings outside the occurrence locations',
    acceptedRisk({
      reviewContext: migrationReviewContext({
        observationId: AFTER_OBSERVATION_ID,
        bindings: [binding('src/other.ts', MIGRATION_CURRENT_BLOB)],
      }),
      proofs: [currentReviewProof({
        observationId: AFTER_OBSERVATION_ID,
        reviewedBindings: [binding('src/other.ts', MIGRATION_CURRENT_BLOB)],
      })],
    }),
    /semantic|migration|context|binding|location/i,
  )

  // A semantic-only occurrence produced by anything other than a migration
  // never accepts a disposition, even when a real ruleset receipt exists.
  for (const [label, producer] of [
    ['native semantic observation', migrationProducerFixture('grok-cli')],
    [
      'codex semantic-only occurrence',
      { kind: 'codex-security', identityBasis: 'codex-contract' },
    ],
  ]) {
    const nativeObservation = migrationCandidateObservation({ producer })
    const nativeHistory = historyFixture('security-runtime', [
      nativeObservation,
      migrationCurrentObservation(),
    ])
    const decisions = prepareEventLedger('security-runtime', [acceptedRisk()])
    assert.throws(
      () => buildAuditDecisionIndex(
        [currentFixture(nativeHistory)],
        [nativeHistory],
        [decisions],
      ),
      /semantic|migration|context|ruleset|exact/i,
      label,
    )
  }

  // The snapshot revalidation inside reduction applies the same predicate:
  // flipping the indexed producer kind after a valid build must fail closed.
  const decisions = prepareEventLedger('security-runtime', [acceptedRisk()])
  const index = buildAuditDecisionIndex([currentWrapper], [history], [decisions])
  index.observations.get(OBSERVATION_ID).producerKind = null
  assert.throws(
    () => reduceAuditDecisionState(
      index,
      migrationPolicy(),
      '2026-08-01T00:00:00.000Z',
    ),
    /semantic|migration|context|producer/i,
    'snapshot path revalidates the migration provenance',
  )
})

test('finding closure supersession is current-active and single-use', () => {
  const observation = observationFixture({ severity: 'medium' })
  const history = historyFixture('security-runtime', [observation])
  for (const action of ['open', 'reopened']) {
    const closure = validDispositionEvents()[2]
    const closurePlan = prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      closure,
    )
    const first = action === 'reopened'
      ? validDispositionEvents()[1]
      : validDispositionEvents()[0]
    first.supersedesEventId = closurePlan.event.eventId
    first.createdAt = '2026-07-30T00:00:00.000Z'
    const stale = structuredClone(first)
    stale.createdAt = '2026-07-31T00:00:00.000Z'
    stale.reason = 'A stale acknowledgment cannot reuse the old closure.'
    assert.throws(
      () => buildAuditDecisionIndex(
        [currentFixture(history)],
        [history],
        [prepareEventLedger(
          'security-runtime',
          [closure, first, stale],
        )],
      ),
      /decision|closure|active|supersede|single|stale/i,
      action,
    )
  }
})

test('global index permits one history-ahead entry only and validates retirement ownership', () => {
  const first = observationFixture()
  const second = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
  })
  const third = observationFixture({
    observationId: 'aobs_cccccccccccccccccccccccc',
    occurrenceId: SPLIT_OCCURRENCE_ID,
  })
  const overAhead = historyFixture(
    'security-runtime',
    [first, second, third],
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(overAhead, 0)],
      [overAhead],
      [],
    ),
    /history-ahead|trailing|current pointer|one/i,
  )

  const retirement = validRetirementEvents()[0]
  const retirementLedger = prepareEventLedger(
    'security-runtime',
    [retirement],
  )
  const history = historyFixture('security-runtime', [first])
  assert.equal(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [retirementLedger],
    ).retirementEvents.length,
    1,
  )

  const duplicateOwnerObservation = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    decisionLedger: 'security-other',
  })
  const duplicateOwnerHistory = historyFixture(
    'security-other',
    [duplicateOwnerObservation],
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [
        currentFixture(history),
        currentFixture(duplicateOwnerHistory),
      ],
      [history, duplicateOwnerHistory],
      [retirementLedger],
    ),
    /retirement|ownership|multiple|history|receipt/i,
  )
})

test('decision policy parsing keeps the full-policy digest runtime-only and fails closed', () => {
  const input = policyInput()
  const before = structuredClone(input)
  const parsed = parseAuditDecisionPolicy(input, POLICY_DIGEST)
  assert.deepEqual(parsed, {
    ...input,
    policyDigest: POLICY_DIGEST,
  })
  assert.deepEqual(input, before)
  assert.equal(canonical(input).includes('policyDigest'), false)

  const permuted = structuredClone(input)
  permuted.blockingActions.reverse()
  permuted.expiry.requiredFor.reverse()
  permuted.remediation.allowedRegressionKinds.reverse()
  permuted.retirement.allowedReasons.reverse()
  assert.deepEqual(
    parseAuditDecisionPolicy(permuted, POLICY_DIGEST),
    parsed,
  )

  assert.throws(
    () => parseAuditDecisionPolicy(input, `sha256:${'z'.repeat(64)}`),
    /policy|digest|sha-256/i,
  )
  for (const mutate of [
    (candidate) => {
      candidate.ambientPolicy = true
    },
    (candidate) => {
      candidate.expiry.ambientMaximum = 1
    },
    (candidate) => {
      candidate.blockingActions.push('open')
    },
    (candidate) => {
      candidate.expiry.warningDays = -1
    },
  ]) {
    const candidate = structuredClone(input)
    mutate(candidate)
    assert.throws(
      () => parseAuditDecisionPolicy(candidate, POLICY_DIGEST),
      /policy|unknown|duplicate|unique|integer|order|member|limit/i,
    )
  }
})

test('post-fix proofs bind the after revision and prove the finding absent', () => {
  const before = observationFixture()
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: `git-sha1:${'a'.repeat(40)}`,
  })
  after.findings = []
  const history = historyFixture('security-runtime', [before, after])
  const remediation = validDispositionEvents()[5]
  const decisions = prepareEventLedger('security-runtime', [remediation])
  assert.equal(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [decisions],
    ).events.size,
    1,
  )

  const stillPresent = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    occurrenceId: SPLIT_OCCURRENCE_ID,
    blob: `git-sha1:${'a'.repeat(40)}`,
  })
  const stillPresentHistory = historyFixture(
    'security-runtime',
    [before, stillPresent],
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(stillPresentHistory)],
      [stillPresentHistory],
      [decisions],
    ),
    /post-fix|finding.*absent|still.*present|remediation/i,
  )

  const wrongRevision = structuredClone(after)
  wrongRevision.target.revision = 'b'.repeat(40)
  const wrongRevisionHistory = historyFixture(
    'security-runtime',
    [before, wrongRevision],
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(wrongRevisionHistory)],
      [wrongRevisionHistory],
      [decisions],
    ),
    /fixRevision|regression|revision|target|post-fix/i,
  )
})

test('high-equivalent reconciliation enforces exact split partitions and merge unions', () => {
  const secondBlob = `git-sha1:${'b'.repeat(40)}`
  const thirdFindingId = 'atf_111111111111111111111111'
  const before = exactObservation({
    observationId: OBSERVATION_ID,
    rows: [{
      findingId: FINDING_ID,
      occurrenceId: OCCURRENCE_ID,
      bindings: [
        binding('src/a.ts', BLOB),
        binding('src/b.ts', secondBlob),
      ],
    }],
  })
  const after = exactObservation({
    observationId: AFTER_OBSERVATION_ID,
    rows: [
      {
        findingId: REPLACEMENT_FINDING_ID,
        occurrenceId: REPLACEMENT_OCCURRENCE_ID,
        bindings: [binding('src/a.ts', BLOB)],
      },
      {
        findingId: thirdFindingId,
        occurrenceId: SPLIT_OCCURRENCE_ID,
        bindings: [binding('src/b.ts', secondBlob)],
      },
    ],
  })
  const split = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [
      REPLACEMENT_OCCURRENCE_ID,
      SPLIT_OCCURRENCE_ID,
    ],
  })
  const splitHistory = historyFixture('security-runtime', [before, after])
  assert.equal(
    buildAuditDecisionIndex(
      [currentFixture(splitHistory)],
      [splitHistory],
      [prepareEventLedger('security-runtime', [split])],
    ).reconciliationEvents.length,
    1,
  )

  const gap = {
    ...split,
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  }
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(splitHistory)],
      [splitHistory],
      [prepareEventLedger('security-runtime', [gap])],
    ),
    /reconciliation|binding|partition|union|gap|equivalent/i,
  )

  const overlappingAfter = structuredClone(after)
  overlappingAfter.findings[1].locations = [{
    path: 'src/a.ts',
    startLine: 1,
  }]
  const overlapHistory = historyFixture(
    'security-runtime',
    [before, overlappingAfter],
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(overlapHistory)],
      [overlapHistory],
      [prepareEventLedger('security-runtime', [split])],
    ),
    /reconciliation|binding|partition|overlap|disjoint/i,
  )

  const changedAfter = structuredClone(after)
  changedAfter.scope.files[1].blob = `git-sha1:${'c'.repeat(40)}`
  const changedHistory = historyFixture(
    'security-runtime',
    [before, changedAfter],
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(changedHistory)],
      [changedHistory],
      [prepareEventLedger('security-runtime', [split])],
    ),
    /reconciliation|binding|partition|union|blob|equivalent/i,
  )

  const mergeBefore = exactObservation({
    observationId: OBSERVATION_ID,
    rows: [
      {
        findingId: FINDING_ID,
        occurrenceId: OCCURRENCE_ID,
        bindings: [binding('src/a.ts', BLOB)],
      },
      {
        findingId: thirdFindingId,
        occurrenceId: SPLIT_OCCURRENCE_ID,
        bindings: [binding('src/b.ts', secondBlob)],
      },
    ],
  })
  const mergeAfter = exactObservation({
    observationId: AFTER_OBSERVATION_ID,
    rows: [{
      findingId: REPLACEMENT_FINDING_ID,
      occurrenceId: REPLACEMENT_OCCURRENCE_ID,
      bindings: [
        binding('src/a.ts', BLOB),
        binding('src/b.ts', secondBlob),
      ],
    }],
  })
  const merge = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID, SPLIT_OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const mergeHistory = historyFixture(
    'security-runtime',
    [mergeBefore, mergeAfter],
  )
  assert.equal(
    buildAuditDecisionIndex(
      [currentFixture(mergeHistory)],
      [mergeHistory],
      [prepareEventLedger('security-runtime', [merge])],
    ).reconciliationEvents.length,
    1,
  )
})

for (const {
  label,
  outcome,
  confidence,
} of [
  {
    label: 'distinct',
    outcome: 'distinct',
    confidence: 'high',
  },
  {
    label: 'uncertain',
    outcome: 'uncertain',
    confidence: 'high',
  },
  {
    label: 'medium-confidence equivalent',
    outcome: 'equivalent',
    confidence: 'medium',
  },
  {
    label: 'low-confidence equivalent',
    outcome: 'equivalent',
    confidence: 'low',
  },
]) {
  test(`same-finding reconciliation rejects ${label}`, () => {
    const before = observationFixture({ severity: 'medium' })
    const after = observationFixture({
      observationId: AFTER_OBSERVATION_ID,
      occurrenceId: REPLACEMENT_OCCURRENCE_ID,
      severity: 'medium',
    })
    const history = historyFixture('security-runtime', [before, after])
    const reconciliation = reconciliationInput({
      beforeObservationIds: [OBSERVATION_ID],
      afterObservationIds: [AFTER_OBSERVATION_ID],
      beforeOccurrenceIds: [OCCURRENCE_ID],
      afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
      outcome,
      confidence,
    })

    assert.throws(
      () => buildAuditDecisionIndex(
        [currentFixture(history)],
        [history],
        [prepareEventLedger('security-runtime', [reconciliation])],
      ),
      /same finding|high-confidence equivalent|stable identity|reconciliation/i,
    )
  })
}

test('same-finding high-equivalent reconciliation preserves recurrence semantics', () => {
  const recurrenceObservationId = 'aobs_777777777777777777777777'
  const recurrenceOccurrenceId = 'atocc_777777777777777777777777'
  const absentObservationId = 'aobs_888888888888888888888888'
  const fixedBlob = `git-sha1:${'a'.repeat(40)}`
  const first = observationFixture({ severity: 'medium' })
  const afterFix = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: fixedBlob,
    severity: 'medium',
  })
  afterFix.findings = []
  const recurrence = observationFixture({
    observationId: recurrenceObservationId,
    occurrenceId: recurrenceOccurrenceId,
    severity: 'medium',
  })
  const absentCurrent = observationFixture({
    observationId: absentObservationId,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: `git-sha1:${'c'.repeat(40)}`,
    severity: 'medium',
  })
  absentCurrent.findings = []
  const history = historyFixture(
    'security-runtime',
    [first, afterFix, recurrence, absentCurrent],
  )
  const reconciliation = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [recurrenceObservationId],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [recurrenceOccurrenceId],
  })
  const decisions = prepareEventLedger(
    'security-runtime',
    [validDispositionEvents()[5], reconciliation],
  )
  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [decisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-08-01T00:00:00.000Z',
  ).findings.get(FINDING_ID)

  assert.equal(state.disposition, 'reopened')
  assert.equal(state.blocking, true)
  assert.equal(state.derivation, 'automatic-reopen')
  assert.equal(state.lifecycle, 'reopened')
  assert.deepEqual(state.currentOccurrenceIds, [])
  assert.deepEqual(
    state.basisEventIds,
    [decisions.entries[0].eventId],
  )
})

test('reducer rejects an invariant-violating same-finding reconciliation', () => {
  const before = observationFixture({ severity: 'medium' })
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const history = historyFixture('security-runtime', [before, after])
  const index = buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [],
  )
  const illegal = prepareAuditDecisionAppend(
    null,
    'security',
    'security-runtime',
    reconciliationInput({
      beforeObservationIds: [OBSERVATION_ID],
      afterObservationIds: [AFTER_OBSERVATION_ID],
      beforeOccurrenceIds: [OCCURRENCE_ID],
      afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
      outcome: 'uncertain',
      confidence: 'high',
    }),
  ).event
  index.reconciliationEvents.push(illegal)

  assert.throws(
    () => reduceAuditDecisionState(
      index,
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-08-01T00:00:00.000Z',
    ),
    /same finding|high-confidence equivalent|stable identity|reconciliation/i,
  )
})

test('reconciliation index maintains active corrections and rejects conflicts and cycles', () => {
  const before = observationFixture({ severity: 'medium' })
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const history = historyFixture('security-runtime', [before, after])
  const first = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const firstPlan = prepareAuditDecisionAppend(
    null,
    'security',
    'security-runtime',
    first,
  )
  const duplicateActive = {
    ...first,
    reason: 'A second active group conflicts with the first group.',
    createdAt: '2026-07-29T03:00:00.000Z',
  }
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [prepareEventLedger(
        'security-runtime',
        [first, duplicateActive],
      )],
    ),
    /reconciliation|active|conflict|occurrence|group/i,
  )

  const correction = {
    ...first,
    outcome: 'distinct',
    confidence: 'medium',
    reason: 'Correction establishes the findings are distinct.',
    createdAt: '2026-07-29T03:00:00.000Z',
    supersedesEventId: firstPlan.event.eventId,
  }
  const correctedLedger = prepareEventLedger(
    'security-runtime',
    [first, correction],
  )
  assert.equal(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [correctedLedger],
    ).reconciliationEvents.length,
    2,
  )

  const staleCorrection = {
    ...first,
    outcome: 'uncertain',
    confidence: 'low',
    reason: 'A stale correction must not bypass the active correction.',
    createdAt: '2026-07-29T04:00:00.000Z',
    supersedesEventId: firstPlan.event.eventId,
  }
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [prepareEventLedger(
        'security-runtime',
        [first, correction, staleCorrection],
      )],
    ),
    /reconciliation|active|correction|supersede/i,
  )

  const reverse = reconciliationInput({
    beforeObservationIds: [AFTER_OBSERVATION_ID],
    afterObservationIds: [OBSERVATION_ID],
    beforeOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
    afterOccurrenceIds: [OCCURRENCE_ID],
    createdAt: '2026-07-29T03:00:00.000Z',
  })
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [prepareEventLedger('security-runtime', [first, reverse])],
    ),
    /reconciliation|cycle|conflict|active/i,
  )

  const sameObservation = exactObservation({
    observationId: OBSERVATION_ID,
    rows: [
      {
        findingId: FINDING_ID,
        occurrenceId: OCCURRENCE_ID,
        bindings: [binding()],
      },
      {
        findingId: REPLACEMENT_FINDING_ID,
        occurrenceId: REPLACEMENT_OCCURRENCE_ID,
        bindings: [binding()],
      },
    ],
  })
  const sameObservationHistory = historyFixture(
    'security-runtime',
    [sameObservation],
  )
  const invalidBoundary = {
    ...first,
    comparisonId: `acmp_${'1'.repeat(24)}`,
  }
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(sameObservationHistory)],
      [sameObservationHistory],
      [prepareEventLedger('security-runtime', [invalidBoundary])],
    ),
    /comparison|observation|disjoint|boundary/i,
  )
})

test('global index rejects unbound no-replacement revisions and duplicate active identities', () => {
  const before = observationFixture()
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
  })
  after.findings = []
  delete after.target.revision
  const history = historyFixture('security-runtime', [before, after])
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [prepareEventLedger(
        'security-runtime',
        [validDispositionEvents()[7]],
      )],
    ),
    /no-replacement|revision|target|unknown/i,
  )

  const aliasHistory = historyFixture('security-runtime', [before])
  const alias = aliasInput({
    decisionLedger: 'security-runtime',
    findingId: FINDING_ID,
    occurrenceIds: [OCCURRENCE_ID],
  })
  const duplicateAlias = {
    ...alias,
    reason: undefined,
    createdAt: '2026-07-30T00:00:00.000Z',
  }
  delete duplicateAlias.reason
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(aliasHistory)],
      [aliasHistory],
      [prepareEventLedger(
        'security-runtime',
        [alias, duplicateAlias],
      )],
    ),
    /alias|duplicate|unique|pair/i,
  )

  const staged = validRetirementEvents()[0]
  const duplicateStaged = {
    ...staged,
    createdAt: '2026-07-30T00:00:00.000Z',
  }
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(aliasHistory)],
      [aliasHistory],
      [prepareEventLedger(
        'security-runtime',
        [staged, duplicateStaged],
      )],
    ),
    /retirement|staged|active|duplicate/i,
  )
})

test('retirement index permits only one terminal or exact staged-to-deleted supersession', () => {
  const observation = observationFixture()
  const history = historyFixture('security-runtime', [observation])
  const staged = validRetirementEvents()[0]
  const stagedPlan = prepareAuditDecisionAppend(
    null,
    'security',
    'security-runtime',
    staged,
  )
  const deleted = validRetirementEvents()[1]
  deleted.supersedesEventId = stagedPlan.event.eventId
  assert.equal(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [prepareEventLedger(
        'security-runtime',
        [staged, deleted],
      )],
    ).retirementEvents.length,
    2,
  )

  const terminalPairs = [
    [validRetirementEvents()[2], validRetirementEvents()[2]],
    [validRetirementEvents()[2], validRetirementEvents()[3]],
    [validRetirementEvents()[3], validRetirementEvents()[1]],
    [validRetirementEvents()[5], validRetirementEvents()[4]],
    [validRetirementEvents()[0], validRetirementEvents()[2]],
    [validRetirementEvents()[2], validRetirementEvents()[0]],
    [staged, {
      ...staged,
      createdAt: '2026-07-30T00:00:00.000Z',
    }],
  ]
  for (const [index, [first, secondInput]] of terminalPairs.entries()) {
    const second = structuredClone(secondInput)
    second.createdAt =
      `2026-07-30T${String(index).padStart(2, '0')}:00:00.000Z`
    assert.throws(
      () => buildAuditDecisionIndex(
        [currentFixture(history)],
        [history],
        [prepareEventLedger(
          'security-runtime',
          [first, second],
        )],
      ),
      /retirement|terminal|staged|duplicate|supersession/i,
      String(index),
    )
  }
})

test('superseded retirement no-replacement proof closes over observation and revision facts', () => {
  const before = observationFixture({ severity: 'medium' })
  const searched = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const history = historyFixture('security-runtime', [before, searched])
  const retirement = validRetirementEvents()[4]
  const validLedger = prepareEventLedger(
    'security-runtime',
    [retirement],
  )
  assert.equal(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [validLedger],
    ).retirementEvents.length,
    1,
  )

  const invalidCases = [
    {
      name: 'unknown observation',
      mutate(event) {
        event.noReplacementProof.observationId =
          'aobs_999999999999999999999999'
      },
    },
    {
      name: 'unknown reviewed binding',
      mutate(event) {
        event.noReplacementProof.reviewedBindings = [
          binding('src/unknown.ts'),
        ]
      },
    },
    {
      name: 'observation revision mismatch',
      mutate(event) {
        const alternateRevision = 'a'.repeat(40)
        event.noReplacementProof.searchRevision = alternateRevision
        event.revisionProof.repositoryRevision = alternateRevision
      },
    },
    {
      name: 'tree revision mismatch',
      mutate(event) {
        event.revisionProof.repositoryRevision = 'a'.repeat(40)
      },
    },
  ]
  for (const invalidCase of invalidCases) {
    const candidate = structuredClone(retirement)
    invalidCase.mutate(candidate)
    assert.throws(
      () => buildAuditDecisionIndex(
        [currentFixture(history)],
        [history],
        [prepareEventLedger(
          'security-runtime',
          [candidate],
        )],
      ),
      /retirement|no-replacement|observation|binding|revision|search|unknown|mismatch/i,
      invalidCase.name,
    )
  }
})

test('reducer rejects forged public index and policy views before business logic', () => {
  const reduce = (index, policy) => reduceAuditDecisionState(
    index,
    policy,
    '2026-07-30T00:00:00.000Z',
  )
  const mutateOnlyEventView = (mutate) => {
    const fixture = reducerTrustFixture()
    const row = [...fixture.index.events.values()][0]
    row.event = structuredClone(row.event)
    mutate(row.event)
    return fixture
  }

  for (const invalidCase of [
    {
      name: 'unknown action',
      fixture: () => mutateOnlyEventView((event) => {
        event.action = 'waived'
      }),
    },
    {
      name: 'unknown event type',
      fixture: () => mutateOnlyEventView((event) => {
        event.type = 'finding-waiver'
      }),
    },
    {
      name: 'malformed proof',
      fixture: () => mutateOnlyEventView((event) => {
        event.proofs[0].kind = 'trust-me'
      }),
    },
    {
      name: 'foreign event view mismatch',
      fixture: () => mutateOnlyEventView((event) => {
        event.reason = 'This unsealed event view is foreign to its ledger.'
      }),
    },
    {
      name: 'map key/value identity mismatch',
      fixture: () => {
        const fixture = reducerTrustFixture()
        fixture.index.occurrences.set(
          'atocc_999999999999999999999999',
          fixture.index.occurrences.get(OCCURRENCE_ID),
        )
        return fixture
      },
    },
  ]) {
    const { index, policy } = invalidCase.fixture()
    assert.throws(
      () => reduce(index, policy),
      /index|decision|event|action|proof|map|identity|mismatch|invalid|unknown|data|must be one of/i,
      invalidCase.name,
    )
  }

  const forgedPolicy = reducerTrustFixture()
  forgedPolicy.policy.blockingActions.push('waived')
  assert.throws(
    () => reduce(forgedPolicy.index, forgedPolicy.policy),
    /policy|blocking|action|invalid|enum|must be one of/i,
  )
})

test('reducer rejects duplicate event and entry identities across decision ledgers', () => {
  const { index, policy } = reducerTrustFixture()
  const canonicalLedger = index.decisionLedgers.get('security-runtime')
  const duplicateLedger = structuredClone(canonicalLedger)
  duplicateLedger.slug = 'security-a'
  index.decisionLedgers = new Map([
    [duplicateLedger.slug, duplicateLedger],
    [canonicalLedger.slug, canonicalLedger],
  ])

  assert.equal(
    [...index.events.values()][0].decisionLedger,
    canonicalLedger.slug,
  )
  assert.throws(
    () => reduceAuditDecisionState(
      index,
      policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /duplicate.*(?:event|entry|identity)|identity.*duplicate/i,
  )
})

test('reducer caps aggregate decision entries before parsing ledger bodies', () => {
  const { index, policy } = reducerTrustFixture()
  const fullLedgerEntries = new Array(10_000).fill(null)
  const decisionLedgers = new Map()
  for (let ledgerIndex = 0; ledgerIndex < 10; ledgerIndex += 1) {
    const slug = `security-${ledgerIndex.toString().padStart(2, '0')}`
    decisionLedgers.set(slug, {
      formatVersion: 1,
      format: 'atlas-audit-decisions-v1',
      domain: 'security',
      slug,
      entries: fullLedgerEntries,
    })
  }
  decisionLedgers.set('security-overflow', {
    formatVersion: 1,
    format: 'atlas-audit-decisions-v1',
    domain: 'security',
    slug: 'security-overflow',
    entries: [null],
  })
  index.decisionLedgers = decisionLedgers

  assert.throws(
    () => reduceAuditDecisionState(
      index,
      policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /aggregate decision ledger entries exceed the 100000-item limit/i,
  )
})

test('reducer rejects a forged second current before applying accepted risk', () => {
  const { index, policy } = reducerTrustFixture()
  const current = [...index.observations.values()][0]
  index.observations.set(AFTER_OBSERVATION_ID, {
    ...structuredClone(current),
    observationId: AFTER_OBSERVATION_ID,
    historyIndex: 1,
    occurrenceIds: [],
  })

  assert.throws(
    () => reduceAuditDecisionState(
      index,
      policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /observation|topology|current|history|slug/i,
  )
})

test('reducer enforces contiguous per-slug publication topology', () => {
  const clean = observationFixture()
  clean.findings = []
  const history = historyFixture('security-runtime', [clean])
  const baseIndex = () => buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [],
  )
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  const addObservation = (index, {
    observationId,
    historyIndex,
    publicationState,
  }) => {
    const current = [...index.observations.values()][0]
    index.observations.set(observationId, {
      ...structuredClone(current),
      observationId,
      historyIndex,
      authoritative: publicationState === 'current',
      publicationState,
    })
  }
  const cases = [
    {
      name: 'gap',
      mutate(index) {
        const current = [...index.observations.values()][0]
        current.historyIndex = 1
      },
    },
    {
      name: 'duplicate index',
      mutate(index) {
        addObservation(index, {
          observationId: AFTER_OBSERVATION_ID,
          historyIndex: 0,
          publicationState: 'historical',
        })
      },
    },
    {
      name: 'multiple ahead',
      mutate(index) {
        addObservation(index, {
          observationId: AFTER_OBSERVATION_ID,
          historyIndex: 1,
          publicationState: 'history-ahead',
        })
        addObservation(index, {
          observationId: 'aobs_cccccccccccccccccccccccc',
          historyIndex: 2,
          publicationState: 'history-ahead',
        })
      },
    },
    {
      name: 'historical after current',
      mutate(index) {
        addObservation(index, {
          observationId: AFTER_OBSERVATION_ID,
          historyIndex: 1,
          publicationState: 'historical',
        })
      },
    },
    {
      name: 'historical only',
      mutate(index) {
        const current = [...index.observations.values()][0]
        current.authoritative = false
        current.publicationState = 'historical'
      },
    },
  ]
  for (const topologyCase of cases) {
    const index = baseIndex()
    topologyCase.mutate(index)
    assert.throws(
      () => reduceAuditDecisionState(
        index,
        policy,
        '2026-07-30T00:00:00.000Z',
      ),
      /observation|topology|current|history|index|contiguous|ahead/i,
      topologyCase.name,
    )
  }

  const genesisAhead = baseIndex()
  const only = [...genesisAhead.observations.values()][0]
  only.authoritative = false
  only.publicationState = 'history-ahead'
  assert.doesNotThrow(() => reduceAuditDecisionState(
    genesisAhead,
    policy,
    '2026-07-30T00:00:00.000Z',
  ))
  assert.doesNotThrow(() => reduceAuditDecisionState(
    buildAuditDecisionIndex([], [], []),
    policy,
    '2026-07-30T00:00:00.000Z',
  ))
})

test('reducer rejects empty findings and mismatched occurrence binding subsets', () => {
  const observation = observationFixture({ severity: 'medium' })
  const history = historyFixture('security-runtime', [observation])
  const makeIndex = () => buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [],
  )
  const policy = parseAuditDecisionPolicy(
    policyInput({
      requireDisposition: false,
      blockingActions: [],
    }),
    POLICY_DIGEST,
  )

  const emptyFinding = makeIndex()
  emptyFinding.occurrences.clear()
  emptyFinding.observations.get(OBSERVATION_ID).occurrenceIds = []
  const finding = emptyFinding.findings.get(FINDING_ID)
  finding.occurrenceIds = []
  finding.currentOccurrenceIds = []
  assert.throws(
    () => reduceAuditDecisionState(
      emptyFinding,
      policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /finding|occurrence|nonempty|empty/i,
  )

  const mismatchedSubset = makeIndex()
  const secondBinding = binding(
    'src/b.ts',
    `git-sha1:${'b'.repeat(40)}`,
  )
  const indexedObservation = mismatchedSubset.observations.get(OBSERVATION_ID)
  indexedObservation.inventoryBindings = [binding(), secondBinding]
  indexedObservation.reviewedBindings = [binding(), secondBinding]
  const occurrence = mismatchedSubset.occurrences.get(OCCURRENCE_ID)
  occurrence.bindings = [binding()]
  occurrence.reviewedBindings = [secondBinding]
  occurrence.closureEligible = false
  assert.throws(
    () => reduceAuditDecisionState(
      mismatchedSubset,
      policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /occurrence|reviewed|binding|subset/i,
  )
})

test('reducer validates observation binding inventories and decision homes', () => {
  const clean = observationFixture()
  clean.findings = []
  const cleanHistory = historyFixture('security-runtime', [clean])
  const cleanIndex = () => buildAuditDecisionIndex(
    [currentFixture(cleanHistory)],
    [cleanHistory],
    [],
  )
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  const secondBinding = binding(
    'src/b.ts',
    `git-sha1:${'b'.repeat(40)}`,
  )
  const alternateBlob = binding(
    'src/a.ts',
    `git-sha1:${'f'.repeat(40)}`,
  )
  for (const invalidCase of [
    {
      name: 'reviewed binding outside inventory',
      mutate(observation) {
        observation.inventoryBindings = [binding()]
        observation.reviewedBindings = [secondBinding]
      },
    },
    {
      name: 'duplicate inventory path',
      mutate(observation) {
        observation.inventoryBindings = [binding(), alternateBlob]
        observation.reviewedBindings = []
      },
    },
    {
      name: 'duplicate reviewed path',
      mutate(observation) {
        observation.inventoryBindings = [binding(), alternateBlob]
        observation.reviewedBindings = [binding(), alternateBlob]
      },
    },
  ]) {
    const index = cleanIndex()
    invalidCase.mutate(index.observations.get(OBSERVATION_ID))
    assert.throws(
      () => reduceAuditDecisionState(
        index,
        policy,
        '2026-07-30T00:00:00.000Z',
      ),
      /observation|inventory|reviewed|binding|path|subset|unique/i,
      invalidCase.name,
    )
  }

  const observation = observationFixture({ severity: 'medium' })
  const history = historyFixture('security-runtime', [observation])
  const missingHome = buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [],
  )
  missingHome.findings.get(FINDING_ID).decisionLedger =
    'security-missing-home'
  missingHome.occurrences.get(OCCURRENCE_ID).decisionLedger =
    'security-missing-home'
  assert.throws(
    () => reduceAuditDecisionState(
      missingHome,
      policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /finding|decision|home|slug|occurrence/i,
  )

  const homeObservation = observationFixture({
    decisionLedger: 'security-origin',
  })
  const movedObservation = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    decisionLedger: 'security-origin',
  })
  const homeHistory = historyFixture('security-origin', [homeObservation])
  const movedHistory = historyFixture('security-runtime', [movedObservation])
  const unpublishedHome = buildAuditDecisionIndex(
    [currentFixture(homeHistory), currentFixture(movedHistory)],
    [homeHistory, movedHistory],
    [],
  )
  const home = unpublishedHome.observations.get(OBSERVATION_ID)
  home.authoritative = false
  home.publicationState = 'history-ahead'
  unpublishedHome.occurrences.get(OCCURRENCE_ID).authoritative = false
  unpublishedHome.findings.get(FINDING_ID).currentOccurrenceIds = [
    REPLACEMENT_OCCURRENCE_ID,
  ]
  assert.throws(
    () => reduceAuditDecisionState(
      unpublishedHome,
      policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /finding|decision|home|published|history-ahead/i,
  )
})

test('builder snapshots outer-array rows independently of aggregate text', () => {
  const largeText = 'x'.repeat(220_000)
  const row = Object.fromEntries(
    Array.from({ length: 20 }, (_unused, index) => [
      `padding${index.toString().padStart(2, '0')}`,
      largeText,
    ]),
  )
  const rows = [row, row]
  const calls = [
    {
      name: 'current',
      run: () => buildAuditDecisionIndex(rows, [], []),
    },
    {
      name: 'history',
      run: () => buildAuditDecisionIndex([], rows, []),
    },
    {
      name: 'decision',
      run: () => buildAuditDecisionIndex([], [], rows),
    },
  ]
  for (const call of calls) {
    assert.throws(
      call.run,
      (error) => {
        assert.doesNotMatch(
          error.message,
          /bounded data-only canonical JSON|text-code-unit/i,
          call.name,
        )
        return true
      },
      call.name,
    )
  }
})

test('builder admits 10,000 memberships and rejects the next occurrence', () => {
  const makeObservation = (count) => exactObservation({
    observationId: OBSERVATION_ID,
    rows: Array.from({ length: count }, (_unused, index) => ({
      findingId: FINDING_ID,
      occurrenceId:
        `atocc_${(index + 1).toString(16).padStart(24, '0')}`,
      bindings: [binding()],
      severity: 'medium',
    })),
  })
  const atBoundary = historyFixture(
    'security-runtime',
    [makeObservation(10_000)],
  )
  assert.equal(
    buildAuditDecisionIndex(
      [currentFixture(atBoundary)],
      [atBoundary],
      [],
    ).findings.get(FINDING_ID).occurrenceIds.length,
    10_000,
  )

  const overflow = historyFixture(
    'security-runtime',
    [makeObservation(10_001)],
  )
  assert.throws(
    () => buildAuditDecisionIndex(
      [currentFixture(overflow)],
      [overflow],
      [],
    ),
    /observation|finding|occurrence|membership|10000|limit/i,
  )
})

test('builder and reducer cap reconciliation records before ledger replay', () => {
  const rawEntry = {
    event: {
      type: 'finding-reconciliation',
    },
  }
  const rawLedger = (slug, count) => ({
    formatVersion: 1,
    format: 'atlas-audit-decisions-v1',
    domain: 'security',
    slug,
    entries: new Array(count).fill(rawEntry),
  })
  const atBoundary = Array.from({ length: 10 }, (_unused, index) =>
    rawLedger(`security-resource-${index.toString().padStart(2, '0')}`, 1_000)
  )
  const overflow = [
    ...atBoundary,
    rawLedger('security-resource-overflow', 1),
  ]
  assert.throws(
    () => buildAuditDecisionIndex([], [], atBoundary),
    (error) => {
      assert.doesNotMatch(
        error.message,
        /reconciliation.*10000.*limit/i,
      )
      return true
    },
  )
  assert.throws(
    () => buildAuditDecisionIndex([], [], overflow),
    /reconciliation.*10000.*limit/i,
  )

  const clean = observationFixture()
  clean.findings = []
  const history = historyFixture('security-runtime', [clean])
  const makeIndex = () => buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [],
  )
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  const reduce = (ledgers) => {
    const index = makeIndex()
    index.decisionLedgers = new Map(
      ledgers.map((ledger) => [ledger.slug, ledger]),
    )
    return reduceAuditDecisionState(
      index,
      policy,
      '2026-07-30T00:00:00.000Z',
    )
  }
  assert.throws(
    () => reduce(atBoundary),
    (error) => {
      assert.doesNotMatch(
        error.message,
        /reconciliation.*10000.*limit/i,
      )
      return true
    },
  )
  assert.throws(
    () => reduce(overflow),
    /reconciliation.*10000.*limit/i,
  )

  const redundant = makeIndex()
  redundant.reconciliationEvents =
    new Array(10_001).fill(null)
  assert.throws(
    () => reduceAuditDecisionState(
      redundant,
      policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /reconciliation.*10000.*limit/i,
  )
})

test('decision ledger canonical byte budget admits exact boundaries and rejects the next byte', () => {
  const ledgerByteLimit = 32 * 1024 * 1024
  const portfolioByteLimit = 64 * 1024 * 1024
  assert.equal(
    validateAuditDecisionLedgerCanonicalByteBudget(0, ledgerByteLimit),
    ledgerByteLimit,
  )
  assert.equal(
    validateAuditDecisionLedgerCanonicalByteBudget(
      ledgerByteLimit,
      ledgerByteLimit,
    ),
    portfolioByteLimit,
  )
  assert.throws(
    () => validateAuditDecisionLedgerCanonicalByteBudget(
      0,
      ledgerByteLimit + 1,
    ),
    /decision ledger canonical bytes.*33554432-byte per-ledger limit/,
  )
  assert.throws(
    () => validateAuditDecisionLedgerCanonicalByteBudget(
      portfolioByteLimit,
      1,
    ),
    /decision ledger portfolio canonical bytes.*67108864-byte cumulative limit/,
  )
})

test('reducer canonical preflight rejects accessors without executing them', () => {
  const clean = observationFixture()
  clean.findings = []
  const history = historyFixture('security-runtime', [clean])
  const index = buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [],
  )
  let getterCalls = 0
  const accessorLedger = {
    formatVersion: 1,
    format: 'atlas-audit-decisions-v1',
    domain: 'security',
    slug: 'security-accessor',
  }
  Object.defineProperty(accessorLedger, 'entries', {
    enumerable: true,
    get() {
      getterCalls += 1
      throw new Error('decision ledger getter executed')
    },
  })
  index.decisionLedgers = new Map([
    ['security-accessor', accessorLedger],
  ])

  assert.throws(
    () => reduceAuditDecisionState(
      index,
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-07-30T00:00:00.000Z',
    ),
    (error) => {
      assert.equal(error.code, 'decision-index-resource-limit')
      assert.match(
        error.message,
        /decision ledger.*bounded data-only canonical JSON/i,
      )
      return true
    },
  )
  assert.equal(getterCalls, 0)
})

test('confirmed reconciliation edge budget admits 10,000 and rejects the next', () => {
  assert.equal(
    validateAuditDecisionReconciliationEdgeBudget(0, 1, 10_000),
    10_000,
  )
  assert.equal(
    validateAuditDecisionReconciliationEdgeBudget(9_999, 1, 1),
    10_000,
  )
  assert.throws(
    () => validateAuditDecisionReconciliationEdgeBudget(10_000, 1, 1),
    /active confirmed reconciliation edges exceed the 10000-edge limit/,
  )

  const before = observationFixture({ severity: 'medium' })
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const history = historyFixture('security-runtime', [before, after])
  const reconciliation = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const index = buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [prepareEventLedger('security-runtime', [reconciliation])],
  )
  assert.equal(
    reduceAuditDecisionState(
      index,
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-07-30T00:00:00.000Z',
    ).findings.size,
    2,
  )
})

test('reducer admits 10,000 active confirmed edges and rejects the next', {
  timeout: 30_000,
}, () => {
  const syntheticId = (prefix, index) =>
    `${prefix}_${index.toString(16).padStart(24, '0')}`
  const splitBindings = Array.from({ length: 10_000 }, (_unused, index) =>
    binding(`src/reconciliation/${index.toString().padStart(5, '0')}.ts`)
  )
  const beforeOccurrenceIds = [
    syntheticId('atocc', 1),
    syntheticId('atocc', 2),
  ]
  const afterOccurrenceIds = splitBindings.map((_unused, index) =>
    syntheticId('atocc', index + 3)
  )
  const before = exactObservation({
    observationId: 'aobs_100000000000000000000000',
    rows: beforeOccurrenceIds.map((occurrenceId, index) => ({
      findingId: syntheticId('atf', index + 1),
      occurrenceId,
      bindings: splitBindings.slice(index * 5_000, (index + 1) * 5_000),
    })),
  })
  const after = exactObservation({
    observationId: 'aobs_200000000000000000000000',
    rows: splitBindings.map((file, index) => ({
      findingId: syntheticId('atf', index + 3),
      occurrenceId: afterOccurrenceIds[index],
      bindings: [file],
    })),
  })
  const overflowBeforeOccurrenceId = syntheticId('atocc', 10_003)
  const overflowAfterOccurrenceId = syntheticId('atocc', 10_004)
  const overflowBinding = binding('src/reconciliation/overflow.ts')
  const overflowBefore = exactObservation({
    observationId: 'aobs_300000000000000000000000',
    rows: [{
      findingId: syntheticId('atf', 10_003),
      occurrenceId: overflowBeforeOccurrenceId,
      bindings: [overflowBinding],
    }],
  })
  const overflowAfter = exactObservation({
    observationId: 'aobs_400000000000000000000000',
    rows: [{
      findingId: syntheticId('atf', 10_004),
      occurrenceId: overflowAfterOccurrenceId,
      bindings: [overflowBinding],
    }],
  })
  const history = historyFixture(
    'security-runtime',
    [before, after, overflowBefore, overflowAfter],
  )
  const index = buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [],
  )
  // One 1→10,000 event cannot be sealed because its canonical identity part
  // exceeds the core 262,144-code-unit limit, so two disjoint splits prove
  // the same aggregate active-edge boundary through the public reducer.
  const atBoundary = beforeOccurrenceIds.map((beforeOccurrenceId, index) =>
    reconciliationInput({
      beforeObservationIds: [before.observationId],
      afterObservationIds: [after.observationId],
      beforeOccurrenceIds: [beforeOccurrenceId],
      afterOccurrenceIds: afterOccurrenceIds.slice(
        index * 5_000,
        (index + 1) * 5_000,
      ),
      createdAt:
        `2026-07-29T0${index + 2}:00:00.000Z`,
    })
  )
  const overflow = reconciliationInput({
    beforeObservationIds: [overflowBefore.observationId],
    afterObservationIds: [overflowAfter.observationId],
    beforeOccurrenceIds: [overflowBeforeOccurrenceId],
    afterOccurrenceIds: [overflowAfterOccurrenceId],
    createdAt: '2026-07-29T04:00:00.000Z',
  })
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)

  replaceDecisionViews(
    index,
    [prepareEventLedger('security-runtime', atBoundary)],
  )
  assert.equal(
    reduceAuditDecisionState(
      index,
      policy,
      '2026-07-30T00:00:00.000Z',
    ).findings.size,
    10_004,
  )

  replaceDecisionViews(
    index,
    [prepareEventLedger('security-runtime', [...atBoundary, overflow])],
  )
  assert.throws(
    () => reduceAuditDecisionState(
      index,
      policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /active confirmed reconciliation edges exceed the 10000-edge limit/,
  )
})

test('reducer caps the public decision-ledger Map at 10,000 rows', () => {
  const clean = observationFixture()
  clean.findings = []
  const history = historyFixture('security-runtime', [clean])
  const index = buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [],
  )
  index.decisionLedgers = new Map(
    Array.from({ length: 10_001 }, (_unused, rowIndex) => [
      `security-map-${rowIndex.toString().padStart(5, '0')}`,
      null,
    ]),
  )

  assert.throws(
    () => reduceAuditDecisionState(
      index,
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-07-30T00:00:00.000Z',
    ),
    /decisionLedgers|Map exceeds the 10000-item limit/i,
  )
})

test('reducer rejects accessors without executing them', () => {
  const topLevel = reducerTrustFixture()
  let topLevelGetterCalls = 0
  Object.defineProperty(topLevel.index, 'events', {
    configurable: true,
    enumerable: true,
    get() {
      topLevelGetterCalls += 1
      throw new Error('index getter executed')
    },
  })
  assert.throws(
    () => reduceAuditDecisionState(
      topLevel.index,
      topLevel.policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /index|data|accessor|property|invalid/i,
  )
  assert.equal(topLevelGetterCalls, 0)

  const mapProperty = reducerTrustFixture()
  let mapGetterCalls = 0
  Object.defineProperty(mapProperty.index.events, 'poison', {
    configurable: true,
    enumerable: true,
    get() {
      mapGetterCalls += 1
      throw new Error('map getter executed')
    },
  })
  assert.throws(
    () => reduceAuditDecisionState(
      mapProperty.index,
      mapProperty.policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /index|map|data|accessor|property|invalid/i,
  )
  assert.equal(mapGetterCalls, 0)
})

test('reducer independently rejects forged active reconciliation invariants', () => {
  const thirdObservationId = 'aobs_333333333333333333333333'
  const thirdOccurrenceId = 'atocc_333333333333333333333333'
  const thirdFindingId = 'atf_333333333333333333333333'
  const observations = [
    observationFixture({ severity: 'medium' }),
    observationFixture({
      observationId: AFTER_OBSERVATION_ID,
      findingId: REPLACEMENT_FINDING_ID,
      occurrenceId: REPLACEMENT_OCCURRENCE_ID,
      severity: 'medium',
    }),
    observationFixture({
      observationId: thirdObservationId,
      findingId: thirdFindingId,
      occurrenceId: thirdOccurrenceId,
      severity: 'medium',
    }),
  ]
  const history = historyFixture('security-runtime', observations)
  const baseIndex = () => buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [],
  )
  const first = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const conflictingOwner = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [thirdObservationId],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [thirdOccurrenceId],
    createdAt: '2026-07-29T03:00:00.000Z',
  })
  const cycleClosing = reconciliationInput({
    beforeObservationIds: [AFTER_OBSERVATION_ID],
    afterObservationIds: [OBSERVATION_ID],
    beforeOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
    afterOccurrenceIds: [OCCURRENCE_ID],
    createdAt: '2026-07-29T03:00:00.000Z',
  })
  const firstEventId = computeAuditDecisionEventId(first)
  const correction = {
    ...first,
    outcome: 'distinct',
    confidence: 'medium',
    reason: 'The active correction replaces the first comparison.',
    createdAt: '2026-07-29T03:00:00.000Z',
    supersedesEventId: firstEventId,
  }
  const staleCorrection = {
    ...first,
    outcome: 'uncertain',
    confidence: 'low',
    reason: 'This stale correction illegally targets an inactive event.',
    createdAt: '2026-07-29T04:00:00.000Z',
    supersedesEventId: firstEventId,
  }
  const forgedCases = [
    {
      name: 'confirmed owner conflict',
      events: [first, conflictingOwner],
      expected: /conflict|owner|active|reconciliation/i,
    },
    {
      name: 'cycle closing',
      events: [first, cycleClosing],
      expected: /cycle|cyclic|reconciliation/i,
    },
    {
      name: 'stale correction',
      events: [first, correction, staleCorrection],
      expected: /correction|supersed|active|reconciliation/i,
    },
  ]
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  for (const forgedCase of forgedCases) {
    const ledger = prepareEventLedger(
      'security-runtime',
      forgedCase.events,
    )
    const index = replaceDecisionViews(baseIndex(), [ledger])
    assert.throws(
      () => reduceAuditDecisionState(
        index,
        policy,
        '2026-07-30T00:00:00.000Z',
      ),
      forgedCase.expected,
      forgedCase.name,
    )
  }
})

test('reducer derives implicit open and every explicit finding action in chain order', () => {
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  const observation = observationFixture({ severity: 'medium' })
  const history = historyFixture('security-runtime', [observation])
  const current = currentFixture(history)
  const implicit = reduceAuditDecisionState(
    buildAuditDecisionIndex([current], [history], []),
    policy,
    '2026-07-30T00:00:00.000Z',
  )
  assert.deepEqual(implicit.findings.get(FINDING_ID), {
    disposition: 'open',
    blocking: true,
    derivation: 'implicit-open',
    lifecycle: 'new',
    currentOccurrenceIds: [OCCURRENCE_ID],
    eventId: null,
    basisEventIds: [],
    expiresAt: null,
    expiryState: 'not-applicable',
    reopenAcknowledged: false,
  })

  const directCases = [
    {
      event: validDispositionEvents()[0],
      disposition: 'open',
      lifecycle: 'persisting',
    },
    {
      event: validDispositionEvents()[2],
      disposition: 'accepted-risk',
      lifecycle: 'persisting',
    },
    {
      event: validDispositionEvents()[3],
      disposition: 'separate-design',
      lifecycle: 'persisting',
    },
    {
      event: validDispositionEvents()[4],
      disposition: 'false-positive',
      lifecycle: 'unknown',
    },
  ]
  for (const { event, disposition, lifecycle } of directCases) {
    const decisions = prepareEventLedger('security-runtime', [event])
    const state = reduceAuditDecisionState(
      buildAuditDecisionIndex([current], [history], [decisions]),
      policy,
      '2026-07-30T00:00:00.000Z',
    ).findings.get(FINDING_ID)
    assert.equal(state.disposition, disposition)
    assert.equal(state.derivation, 'explicit-event')
    assert.equal(state.lifecycle, lifecycle)
    assert.equal(state.eventId, decisions.entries[0].eventId)
  }

  const replacementObservation = observationFixture({ severity: 'medium' })
  replacementObservation.findings.push({
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    decisionLedger: 'security-runtime',
    severity: { level: 'medium' },
    locations: [{ path: 'src/a.ts', startLine: 1 }],
  })
  const replacementHistory = historyFixture(
    'security-runtime',
    [replacementObservation],
  )
  const superseded = validDispositionEvents()[6]
  superseded.proofs[0].observationId = OBSERVATION_ID
  const supersededDecisions = prepareEventLedger(
    'security-runtime',
    [superseded],
  )
  assert.equal(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(replacementHistory)],
        [replacementHistory],
        [supersededDecisions],
      ),
      policy,
      '2026-07-30T00:00:00.000Z',
    ).findings.get(FINDING_ID).disposition,
    'superseded',
  )

  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: `git-sha1:${'a'.repeat(40)}`,
    severity: 'medium',
  })
  after.findings = []
  const remediatedHistory = historyFixture(
    'security-runtime',
    [observation, after],
  )
  const remediation = validDispositionEvents()[5]
  const remediationDecisions = prepareEventLedger(
    'security-runtime',
    [remediation],
  )
  assert.deepEqual(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(remediatedHistory)],
        [remediatedHistory],
        [remediationDecisions],
      ),
      policy,
      '2026-07-30T00:00:00.000Z',
    ).findings.get(FINDING_ID),
    {
      disposition: 'remediated',
      blocking: false,
      derivation: 'explicit-event',
      lifecycle: 'resolved',
      currentOccurrenceIds: [],
      eventId: remediationDecisions.entries[0].eventId,
      basisEventIds: [],
      expiresAt: null,
      expiryState: 'not-applicable',
      reopenAcknowledged: false,
    },
  )

  const accepted = validDispositionEvents()[2]
  const firstPlan = prepareAuditDecisionAppend(
    null,
    'security',
    'security-runtime',
    accepted,
  )
  const reopened = validDispositionEvents()[1]
  reopened.supersedesEventId = firstPlan.event.eventId
  reopened.createdAt = '2026-07-01T00:00:00.000Z'
  const reopenedDecisions = prepareEventLedger(
    'security-runtime',
    [accepted, reopened],
  )
  const reopenedState = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [current],
      [history],
      [reopenedDecisions],
    ),
    policy,
    '2026-07-30T00:00:00.000Z',
  ).findings.get(FINDING_ID)
  assert.equal(reopenedState.disposition, 'reopened')
  assert.equal(reopenedState.eventId, reopenedDecisions.entries[1].eventId)
  assert.deepEqual(
    reopenedState.basisEventIds,
    [reopenedDecisions.entries[0].eventId],
  )
  assert.equal(reopenedState.reopenAcknowledged, true)
})

test('requireDisposition makes an explicit open blocking without a blockingActions entry', () => {
  const observation = observationFixture({ severity: 'medium' })
  const history = historyFixture('security-runtime', [observation])
  const decisions = prepareEventLedger(
    'security-runtime',
    [validDispositionEvents()[0]],
  )
  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [decisions],
    ),
    parseAuditDecisionPolicy(
      policyInput({
        requireDisposition: true,
        blockingActions: [],
      }),
      POLICY_DIGEST,
    ),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(FINDING_ID)
  assert.equal(state.disposition, 'open')
  assert.equal(state.derivation, 'explicit-event')
  assert.equal(state.blocking, true)
})

test('expiry policy uses event-relative maxima, exact warning boundaries, and independent approvals', () => {
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  const observation = observationFixture({ severity: 'high' })
  const history = historyFixture('security-runtime', [observation])
  const current = currentFixture(history)
  const accepted = validDispositionEvents()[2]
  accepted.expiresAt = '2026-08-28T00:00:00.000Z'
  accepted.reviews = [
    independentReview('identity:independent-a@example.invalid'),
    independentReview('identity:independent-b@example.invalid'),
    independentReview('identity:independent-b@example.invalid'),
    independentReview('identity:rejected@example.invalid', {
      verdict: 'reject',
    }),
    independentReview(accepted.actor),
    independentReview(accepted.owner),
  ]
  const decisions = prepareEventLedger('security-runtime', [accepted])
  const index = buildAuditDecisionIndex([current], [history], [decisions])
  const stateAt = (now) =>
    reduceAuditDecisionState(index, policy, now).findings.get(FINDING_ID)
  assert.equal(
    stateAt('2026-08-13T23:59:59.999Z').expiryState,
    'active',
  )
  assert.equal(
    stateAt('2026-08-14T00:00:00.000Z').expiryState,
    'warning',
  )
  assert.equal(
    stateAt('2026-08-28T00:00:00.000Z').expiryState,
    'expired',
  )
  assert.equal(
    stateAt('2026-08-28T00:00:00.000Z').blocking,
    true,
  )

  const overlong = structuredClone(accepted)
  overlong.expiresAt = '2026-08-28T00:00:00.001Z'
  const overlongDecisions = prepareEventLedger(
    'security-runtime',
    [overlong],
  )
  assert.throws(
    () => reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [current],
        [history],
        [overlongDecisions],
      ),
      policy,
      '2026-08-27T00:00:00.000Z',
    ),
    /maximum|30|expiry|duration|event/i,
  )

  const underReviewed = structuredClone(accepted)
  underReviewed.reviews = [
    independentReview('identity:independent-a@example.invalid'),
    independentReview('identity:rejected@example.invalid', {
      verdict: 'reject',
    }),
    independentReview(underReviewed.actor),
    independentReview(underReviewed.owner),
  ]
  const underReviewedDecisions = prepareEventLedger(
    'security-runtime',
    [underReviewed],
  )
  assert.throws(
    () => reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [current],
        [history],
        [underReviewedDecisions],
      ),
      policy,
      '2026-07-30T00:00:00.000Z',
    ),
    /independent|review|approval|evidence|minimum/i,
  )
})

test('policy digest drift fails safe before applying newer review thresholds', () => {
  const observation = observationFixture({ severity: 'high' })
  const history = historyFixture('security-runtime', [observation])
  const accepted = validDispositionEvents()[2]
  accepted.reviewContext.policyDigest = `sha256:${'d'.repeat(64)}`
  accepted.reviews = []
  const decisions = prepareEventLedger('security-runtime', [accepted])

  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [decisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(FINDING_ID)

  assert.equal(state.disposition, 'open')
  assert.equal(state.blocking, true)
  assert.equal(state.derivation, 'carry-invalidated')
  assert.equal(state.lifecycle, 'persisting')
  assert.deepEqual(state.basisEventIds, [decisions.entries[0].eventId])
})

test('review evidence may be empty unless the active severity policy requires it', () => {
  const observation = observationFixture({ severity: 'high' })
  const history = historyFixture('security-runtime', [observation])
  const accepted = validDispositionEvents()[2]
  accepted.reviews = [
    independentReview('identity:independent-a@example.invalid', {
      evidence: '',
    }),
    independentReview('identity:independent-b@example.invalid', {
      evidence: '',
    }),
  ]
  const decisions = prepareEventLedger(
    'security-runtime',
    [accepted],
  )
  const index = buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [decisions],
  )
  const relaxedPolicyInput = policyInput()
  relaxedPolicyInput.expiry.severityOverrides[0]
    .reviewEvidenceRequired = false
  assert.equal(
    reduceAuditDecisionState(
      index,
      parseAuditDecisionPolicy(relaxedPolicyInput, POLICY_DIGEST),
      '2026-07-30T00:00:00.000Z',
    ).findings.get(FINDING_ID).disposition,
    'accepted-risk',
  )
  assert.throws(
    () => reduceAuditDecisionState(
      index,
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-07-30T00:00:00.000Z',
    ),
    /independent|review|approval|evidence|minimum/i,
  )

  for (const [name, evidence] of [
    ['NUL', 'invalid\0evidence'],
    ['over-limit', 'x'.repeat(256 * 1024 + 1)],
  ]) {
    const candidate = validDispositionEvents()[2]
    candidate.reviews = [
      independentReview('identity:independent-a@example.invalid', {
        evidence,
      }),
    ]
    assert.throws(
      () => prepareAuditDecisionAppend(
        null,
        'security',
        'security-runtime',
        candidate,
      ),
      /evidence|string|bounded|NUL|limit/i,
      name,
    )
  }

  let getterExecuted = false
  const accessorReview = independentReview(
    'identity:independent-a@example.invalid',
  )
  Object.defineProperty(accessorReview, 'evidence', {
    enumerable: true,
    get() {
      getterExecuted = true
      return ''
    },
  })
  const accessorCandidate = validDispositionEvents()[2]
  accessorCandidate.reviews = [accessorReview]
  assert.throws(
    () => prepareAuditDecisionAppend(
      null,
      'security',
      'security-runtime',
      accessorCandidate,
    ),
    /accessor|data-only|member|object/i,
  )
  assert.equal(getterExecuted, false)
})

test('history-ahead decisions remain indexed but become effective only after publication', () => {
  const before = observationFixture({ severity: 'medium' })
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: `git-sha1:${'a'.repeat(40)}`,
    severity: 'medium',
  })
  after.findings = []
  const history = historyFixture('security-runtime', [before, after])
  const remediation = validDispositionEvents()[5]
  const decisions = prepareEventLedger(
    'security-runtime',
    [remediation],
  )
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)

  const historyAheadIndex = buildAuditDecisionIndex(
    [currentFixture(history, 0)],
    [history],
    [decisions],
  )
  assert.equal(historyAheadIndex.events.size, 1)
  assert.deepEqual(
    reduceAuditDecisionState(
      historyAheadIndex,
      policy,
      '2026-07-30T00:00:00.000Z',
    ).findings.get(FINDING_ID),
    {
      disposition: 'open',
      blocking: true,
      derivation: 'implicit-open',
      lifecycle: 'new',
      currentOccurrenceIds: [OCCURRENCE_ID],
      eventId: null,
      basisEventIds: [],
      expiresAt: null,
      expiryState: 'not-applicable',
      reopenAcknowledged: false,
    },
  )

  assert.equal(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(history, 1)],
        [history],
        [decisions],
      ),
      policy,
      '2026-07-30T00:00:00.000Z',
    ).findings.get(FINDING_ID).lifecycle,
    'resolved',
  )
})

test('history-ahead retirements remain non-effective until publication', () => {
  const retiredBlob = `git-sha1:${'b'.repeat(40)}`
  const before = observationFixture({ severity: 'medium' })
  const ahead = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    path: 'src/retired.ts',
    blob: retiredBlob,
    severity: 'medium',
  })
  const history = historyFixture('security-runtime', [before, ahead])
  const retirement = validRetirementEvents()[0]
  retirement.path = 'src/retired.ts'
  retirement.blob = retiredBlob
  retirement.historyProof = {
    slug: 'security-runtime',
    observationId: AFTER_OBSERVATION_ID,
    path: 'src/retired.ts',
    blob: retiredBlob,
  }
  retirement.absenceProof.headBinding = binding(
    'src/retired.ts',
    retiredBlob,
  )
  const decisions = prepareEventLedger(
    'security-runtime',
    [retirement],
  )
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  const retirementKey = `src/retired.ts\0${retiredBlob}`

  const beforePublication = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history, 0)],
      [history],
      [decisions],
    ),
    policy,
    '2026-07-30T00:00:00.000Z',
  )
  assert.equal(beforePublication.retirements.has(retirementKey), false)

  const afterPublication = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history, 1)],
      [history],
      [decisions],
    ),
    policy,
    '2026-07-30T00:00:00.000Z',
  )
  assert.equal(afterPublication.retirements.has(retirementKey), true)
})

test('retirement no-replacement search must also be published before effect', () => {
  const before = observationFixture({ severity: 'medium' })
  const searchedAhead = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const history = historyFixture(
    'security-runtime',
    [before, searchedAhead],
  )
  const retirement = validRetirementEvents()[4]
  const decisions = prepareEventLedger(
    'security-runtime',
    [retirement],
  )
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  const retirementKey = `src/a.ts\0${BLOB}`

  assert.equal(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(history, 0)],
        [history],
        [decisions],
      ),
      policy,
      '2026-07-30T00:00:00.000Z',
    ).retirements.has(retirementKey),
    false,
  )
  assert.equal(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(history, 1)],
        [history],
        [decisions],
      ),
      policy,
      '2026-07-30T00:00:00.000Z',
    ).retirements.has(retirementKey),
    true,
  )
})

test('later same-finding reappearance stays reopened through mere current absence', () => {
  const successorObservationId = 'aobs_888888888888888888888888'
  const successorOccurrenceId = 'atocc_888888888888888888888888'
  const absentObservationId = 'aobs_999999999999999999999999'
  const fixedBlob = `git-sha1:${'a'.repeat(40)}`
  const absentBlob = `git-sha1:${'c'.repeat(40)}`
  const first = observationFixture({ severity: 'medium' })
  const afterFix = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: fixedBlob,
    severity: 'medium',
  })
  afterFix.findings = []
  const successor = observationFixture({
    observationId: successorObservationId,
    occurrenceId: successorOccurrenceId,
    severity: 'medium',
  })
  const absentCurrent = observationFixture({
    observationId: absentObservationId,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: absentBlob,
    severity: 'medium',
  })
  absentCurrent.findings = []
  const history = historyFixture(
    'security-runtime',
    [first, afterFix, successor, absentCurrent],
  )
  const remediation = validDispositionEvents()[5]
  const decisions = prepareEventLedger(
    'security-runtime',
    [remediation],
  )
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)

  assert.deepEqual(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(history)],
        [history],
        [decisions],
      ),
      policy,
      '2026-08-01T00:00:00.000Z',
    ).findings.get(FINDING_ID),
    {
      disposition: 'reopened',
      blocking: true,
      derivation: 'automatic-reopen',
      lifecycle: 'reopened',
      currentOccurrenceIds: [],
      eventId: null,
      basisEventIds: [decisions.entries[0].eventId],
      expiresAt: null,
      expiryState: 'not-applicable',
      reopenAcknowledged: false,
    },
  )

  const laterRemediation = structuredClone(remediation)
  laterRemediation.occurrenceId = successorOccurrenceId
  laterRemediation.createdAt = '2026-07-31T00:00:00.000Z'
  laterRemediation.reviewContext = reviewContext({
    observationId: successorObservationId,
  })
  laterRemediation.proofs[0] = postFixProof({
    beforeObservationId: successorObservationId,
    afterObservationId: absentObservationId,
    beforeBindings: [binding()],
    afterBindings: [binding('src/a.ts', absentBlob)],
  })
  laterRemediation.regression.binding = {
    repositoryRevision: REVISION,
    observationId: absentObservationId,
    files: [binding('src/a.ts', absentBlob)],
  }
  laterRemediation.actionEvidence = {
    kind: 'remediation',
    beforeBindings: [binding()],
    afterBindings: [binding('src/a.ts', absentBlob)],
    fixRevision: REVISION,
  }
  const closedDecisions = prepareEventLedger(
    'security-runtime',
    [remediation, laterRemediation],
  )
  const closed = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [closedDecisions],
    ),
    policy,
    '2026-08-01T00:00:00.000Z',
  ).findings.get(FINDING_ID)
  assert.equal(closed.disposition, 'remediated')
  assert.equal(closed.blocking, false)
  assert.equal(closed.lifecycle, 'resolved')
})

test('cross-history recurrence cannot fall back to resolved after later absence', () => {
  const recurrenceObservationId = 'aobs_777777777777777777777777'
  const recurrenceOccurrenceId = 'atocc_777777777777777777777777'
  const absentObservationId = 'aobs_888888888888888888888888'
  const fixedBlob = `git-sha1:${'a'.repeat(40)}`
  const absentBlob = `git-sha1:${'c'.repeat(40)}`
  const first = observationFixture({
    decisionLedger: 'security-origin',
    severity: 'medium',
  })
  const afterFix = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    decisionLedger: 'security-origin',
    blob: fixedBlob,
    severity: 'medium',
  })
  afterFix.findings = []
  const recurrence = observationFixture({
    observationId: recurrenceObservationId,
    occurrenceId: recurrenceOccurrenceId,
    decisionLedger: 'security-origin',
    severity: 'medium',
  })
  const absentCurrent = observationFixture({
    observationId: absentObservationId,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: absentBlob,
    severity: 'medium',
  })
  absentCurrent.findings = []
  const originHistory = historyFixture(
    'security-origin',
    [first, afterFix],
  )
  const recurrenceHistory = historyFixture(
    'security-runtime',
    [recurrence, absentCurrent],
  )
  const decisions = prepareEventLedger(
    'security-origin',
    [validDispositionEvents()[5]],
  )

  assert.deepEqual(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [
          currentFixture(originHistory),
          currentFixture(recurrenceHistory),
        ],
        [originHistory, recurrenceHistory],
        [decisions],
      ),
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-08-01T00:00:00.000Z',
    ).findings.get(FINDING_ID),
    {
      disposition: 'open',
      blocking: true,
      derivation: 'reconciliation-conflict',
      lifecycle: 'unknown',
      currentOccurrenceIds: [],
      eventId: null,
      basisEventIds: [decisions.entries[0].eventId],
      expiresAt: null,
      expiryState: 'not-applicable',
      reopenAcknowledged: false,
    },
  )
})

test('unconnected cross-history explicit frontiers fail closed', () => {
  const recurrenceObservationId = 'aobs_777777777777777777777777'
  const recurrenceOccurrenceId = 'atocc_777777777777777777777777'
  const absentObservationId = 'aobs_888888888888888888888888'
  const fixedBlob = `git-sha1:${'a'.repeat(40)}`
  const absentBlob = `git-sha1:${'c'.repeat(40)}`
  const first = observationFixture({
    decisionLedger: 'security-origin',
    severity: 'medium',
  })
  const afterFix = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    decisionLedger: 'security-origin',
    blob: fixedBlob,
    severity: 'medium',
  })
  afterFix.findings = []
  const recurrence = observationFixture({
    observationId: recurrenceObservationId,
    occurrenceId: recurrenceOccurrenceId,
    decisionLedger: 'security-origin',
    severity: 'medium',
  })
  const absentCurrent = observationFixture({
    observationId: absentObservationId,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: absentBlob,
    severity: 'medium',
  })
  absentCurrent.findings = []
  const originHistory = historyFixture(
    'security-origin',
    [first, afterFix],
  )
  const recurrenceHistory = historyFixture(
    'security-runtime',
    [recurrence, absentCurrent],
  )
  const remediation = validDispositionEvents()[5]
  const laterRemediation = structuredClone(remediation)
  laterRemediation.occurrenceId = recurrenceOccurrenceId
  laterRemediation.createdAt = '2026-07-31T00:00:00.000Z'
  laterRemediation.reviewContext = reviewContext({
    observationId: recurrenceObservationId,
  })
  laterRemediation.proofs[0] = postFixProof({
    beforeObservationId: recurrenceObservationId,
    afterObservationId: absentObservationId,
    beforeBindings: [binding()],
    afterBindings: [binding('src/a.ts', absentBlob)],
  })
  laterRemediation.regression.binding = {
    repositoryRevision: REVISION,
    observationId: absentObservationId,
    files: [binding('src/a.ts', absentBlob)],
  }
  laterRemediation.actionEvidence = {
    kind: 'remediation',
    beforeBindings: [binding()],
    afterBindings: [binding('src/a.ts', absentBlob)],
    fixRevision: REVISION,
  }
  const decisions = prepareEventLedger(
    'security-origin',
    [remediation, laterRemediation],
  )

  assert.deepEqual(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [
          currentFixture(originHistory),
          currentFixture(recurrenceHistory),
        ],
        [originHistory, recurrenceHistory],
        [decisions],
      ),
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-08-01T00:00:00.000Z',
    ).findings.get(FINDING_ID),
    {
      disposition: 'open',
      blocking: true,
      derivation: 'reconciliation-conflict',
      lifecycle: 'unknown',
      currentOccurrenceIds: [],
      eventId: null,
      basisEventIds: decisions.entries.map((entry) => entry.eventId).sort(),
      expiresAt: null,
      expiryState: 'not-applicable',
      reopenAcknowledged: false,
    },
  )
})

test('current recurrence conflicts with a disconnected historical acceptance regardless of discovery order', () => {
  const recurrenceObservationId = 'aobs_777777777777777777777777'
  const recurrenceOccurrenceId = 'atocc_777777777777777777777777'
  const clean = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    decisionLedger: 'security-origin',
    severity: 'medium',
  })
  clean.findings = []
  const originHistory = historyFixture(
    'security-origin',
    [
      observationFixture({
        decisionLedger: 'security-origin',
        severity: 'medium',
      }),
      clean,
    ],
  )
  const recurrenceHistory = historyFixture(
    'security-runtime',
    [observationFixture({
      observationId: recurrenceObservationId,
      occurrenceId: recurrenceOccurrenceId,
      decisionLedger: 'security-origin',
      severity: 'medium',
    })],
  )
  const accepted = validDispositionEvents()[2]
  const decisions = prepareEventLedger('security-origin', [accepted])
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  const reduceInOrder = (reversed) => {
    const currentRows = [
      currentFixture(originHistory),
      currentFixture(recurrenceHistory),
    ]
    const historyRows = [originHistory, recurrenceHistory]
    return reduceAuditDecisionState(
      buildAuditDecisionIndex(
        reversed ? currentRows.reverse() : currentRows,
        reversed ? historyRows.reverse() : historyRows,
        [decisions],
      ),
      policy,
      '2026-08-01T00:00:00.000Z',
    ).findings.get(FINDING_ID)
  }
  const expected = {
    disposition: 'open',
    blocking: true,
    derivation: 'reconciliation-conflict',
    lifecycle: 'unknown',
    currentOccurrenceIds: [recurrenceOccurrenceId],
    eventId: null,
    basisEventIds: [decisions.entries[0].eventId],
    expiresAt: null,
    expiryState: 'not-applicable',
    reopenAcknowledged: false,
  }

  assert.deepEqual(reduceInOrder(false), expected)
  assert.deepEqual(reduceInOrder(true), expected)
})

for (const canonicalAction of ['remediated', 'accepted-risk']) {
  test(`explicit incoming cannot hide the canonical ${canonicalAction} frontier`, () => {
    const recurrenceObservationId = 'aobs_777777777777777777777777'
    const recurrenceOccurrenceId = 'atocc_777777777777777777777777'
    const otherObservationId = 'aobs_888888888888888888888888'
    const otherFindingId = 'atf_888888888888888888888888'
    const otherOccurrenceId = 'atocc_888888888888888888888888'
    const fixedBlob = `git-sha1:${'a'.repeat(40)}`
    const first = observationFixture({ severity: 'medium' })
    const afterFix = observationFixture({
      observationId: AFTER_OBSERVATION_ID,
      findingId: REPLACEMENT_FINDING_ID,
      occurrenceId: REPLACEMENT_OCCURRENCE_ID,
      blob: fixedBlob,
      severity: 'medium',
    })
    afterFix.findings = []
    const recurrence = observationFixture({
      observationId: recurrenceObservationId,
      occurrenceId: recurrenceOccurrenceId,
      severity: 'medium',
    })
    const other = observationFixture({
      observationId: otherObservationId,
      findingId: otherFindingId,
      occurrenceId: otherOccurrenceId,
      decisionLedger: 'security-other',
      severity: 'medium',
    })
    const findingHistory = historyFixture(
      'security-runtime',
      [first, afterFix, recurrence],
    )
    const otherHistory = historyFixture('security-other', [other])
    const canonicalDecision = canonicalAction === 'remediated'
      ? validDispositionEvents()[5]
      : validDispositionEvents()[2]
    const otherAcceptance = structuredClone(validDispositionEvents()[2])
    otherAcceptance.findingId = otherFindingId
    otherAcceptance.occurrenceId = otherOccurrenceId
    otherAcceptance.createdAt = '2026-07-29T03:00:00.000Z'
    otherAcceptance.reviewContext = reviewContext({
      observationId: otherObservationId,
    })
    otherAcceptance.proofs = [currentReviewProof({
      observationId: otherObservationId,
    })]
    const reconciliation = reconciliationInput({
      beforeObservationIds: [otherObservationId],
      afterObservationIds: [recurrenceObservationId],
      beforeOccurrenceIds: [otherOccurrenceId],
      afterOccurrenceIds: [recurrenceOccurrenceId],
      decisionLedger: 'security-other',
      createdAt: '2026-07-29T04:00:00.000Z',
    })
    const findingDecisions = prepareEventLedger(
      'security-runtime',
      [canonicalDecision],
    )
    const otherDecisions = prepareEventLedger(
      'security-other',
      [otherAcceptance, reconciliation],
    )

    assert.deepEqual(
      reduceAuditDecisionState(
        buildAuditDecisionIndex(
          [
            currentFixture(findingHistory),
            currentFixture(otherHistory),
          ],
          [findingHistory, otherHistory],
          [findingDecisions, otherDecisions],
        ),
        parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
        '2026-08-01T00:00:00.000Z',
      ).findings.get(FINDING_ID),
      {
        disposition: 'open',
        blocking: true,
        derivation: 'reconciliation-conflict',
        lifecycle: 'unknown',
        currentOccurrenceIds: [recurrenceOccurrenceId],
        eventId: null,
        basisEventIds: [
          findingDecisions.entries[0].eventId,
          otherDecisions.entries[0].eventId,
        ].sort(),
        expiresAt: null,
        expiryState: 'not-applicable',
        reopenAcknowledged: false,
      },
    )
  })
}

test('compatible unconnected current explicit frontiers retain every basis event', () => {
  const secondObservationId = 'aobs_777777777777777777777777'
  const secondOccurrenceId = 'atocc_777777777777777777777777'
  const first = observationFixture({ severity: 'medium' })
  const second = observationFixture({
    observationId: secondObservationId,
    occurrenceId: secondOccurrenceId,
    decisionLedger: 'security-runtime',
    severity: 'medium',
  })
  const firstHistory = historyFixture('security-runtime', [first])
  const secondHistory = historyFixture('security-other', [second])
  const firstAcceptance = validDispositionEvents()[2]
  const secondAcceptance = structuredClone(firstAcceptance)
  secondAcceptance.occurrenceId = secondOccurrenceId
  secondAcceptance.createdAt = '2026-07-29T03:00:00.000Z'
  secondAcceptance.reviewContext = reviewContext({
    observationId: secondObservationId,
  })
  secondAcceptance.proofs = [currentReviewProof({
    observationId: secondObservationId,
  })]
  const decisions = prepareEventLedger(
    'security-runtime',
    [firstAcceptance, secondAcceptance],
  )

  assert.deepEqual(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [
          currentFixture(firstHistory),
          currentFixture(secondHistory),
        ],
        [firstHistory, secondHistory],
        [decisions],
      ),
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-08-01T00:00:00.000Z',
    ).findings.get(FINDING_ID),
    {
      disposition: 'open',
      blocking: true,
      derivation: 'reconciliation-conflict',
      lifecycle: 'unknown',
      currentOccurrenceIds: [OCCURRENCE_ID, secondOccurrenceId].sort(),
      eventId: null,
      basisEventIds: decisions.entries.map((entry) => entry.eventId).sort(),
      expiresAt: null,
      expiryState: 'not-applicable',
      reopenAcknowledged: false,
    },
  )
})

test('unconnected current implicit frontiers block even under advisory open policy', () => {
  const secondObservationId = 'aobs_777777777777777777777777'
  const secondOccurrenceId = 'atocc_777777777777777777777777'
  const firstHistory = historyFixture(
    'security-runtime',
    [observationFixture({ severity: 'medium' })],
  )
  const secondHistory = historyFixture(
    'security-other',
    [observationFixture({
      observationId: secondObservationId,
      occurrenceId: secondOccurrenceId,
      decisionLedger: 'security-runtime',
      severity: 'medium',
    })],
  )
  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [
        currentFixture(firstHistory),
        currentFixture(secondHistory),
      ],
      [firstHistory, secondHistory],
      [],
    ),
    parseAuditDecisionPolicy(
      policyInput({
        requireDisposition: false,
        blockingActions: [],
      }),
      POLICY_DIGEST,
    ),
    '2026-08-01T00:00:00.000Z',
  ).findings.get(FINDING_ID)

  assert.equal(state.disposition, 'open')
  assert.equal(state.blocking, true)
  assert.equal(state.derivation, 'reconciliation-conflict')
  assert.equal(state.lifecycle, 'unknown')
  assert.deepEqual(
    state.currentOccurrenceIds,
    [OCCURRENCE_ID, secondOccurrenceId].sort(),
  )
  assert.deepEqual(state.basisEventIds, [])
})

test('history-ahead occurrence does not create a global frontier component', () => {
  const aheadObservationId = 'aobs_777777777777777777777777'
  const aheadOccurrenceId = 'atocc_777777777777777777777777'
  const clean = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  clean.findings = []
  const publishedHistory = historyFixture(
    'security-runtime',
    [observationFixture({ severity: 'medium' }), clean],
  )
  const aheadHistory = historyFixture(
    'security-other',
    [observationFixture({
      observationId: aheadObservationId,
      occurrenceId: aheadOccurrenceId,
      decisionLedger: 'security-runtime',
      severity: 'medium',
    })],
  )
  const decisions = prepareEventLedger(
    'security-runtime',
    [validDispositionEvents()[2]],
  )

  assert.deepEqual(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(publishedHistory)],
        [publishedHistory, aheadHistory],
        [decisions],
      ),
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-08-01T00:00:00.000Z',
    ).findings.get(FINDING_ID),
    {
      disposition: 'accepted-risk',
      blocking: false,
      derivation: 'explicit-event',
      lifecycle: 'unknown',
      currentOccurrenceIds: [],
      eventId: decisions.entries[0].eventId,
      basisEventIds: [],
      expiresAt: validDispositionEvents()[2].expiresAt,
      expiryState: 'active',
      reopenAcknowledged: false,
    },
  )
})

test('historical unclosed finding remains blocking after current absence', () => {
  const absent = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  absent.findings = []
  const history = historyFixture(
    'security-runtime',
    [observationFixture({ severity: 'medium' }), absent],
  )
  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-08-01T00:00:00.000Z',
  ).findings.get(FINDING_ID)

  assert.equal(state.disposition, 'open')
  assert.equal(state.blocking, true)
  assert.equal(state.derivation, 'implicit-open')
  assert.equal(state.lifecycle, 'unknown')
  assert.deepEqual(state.currentOccurrenceIds, [])
})

test('explicit equivalent reappearance stays reopened through later absence', () => {
  const successorObservationId = 'aobs_888888888888888888888888'
  const absentObservationId = 'aobs_999999999999999999999999'
  const fixedBlob = `git-sha1:${'a'.repeat(40)}`
  const first = observationFixture({ severity: 'medium' })
  const afterFix = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: fixedBlob,
    severity: 'medium',
  })
  afterFix.findings = []
  const successor = observationFixture({
    observationId: successorObservationId,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const absentCurrent = observationFixture({
    observationId: absentObservationId,
    findingId: 'atf_777777777777777777777777',
    occurrenceId: 'atocc_777777777777777777777777',
    severity: 'medium',
  })
  absentCurrent.findings = []
  const history = historyFixture(
    'security-runtime',
    [first, afterFix, successor, absentCurrent],
  )
  const reconciliation = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [successorObservationId],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const decisions = prepareEventLedger(
    'security-runtime',
    [validDispositionEvents()[5], reconciliation],
  )
  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [decisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-08-01T00:00:00.000Z',
  ).findings.get(REPLACEMENT_FINDING_ID)
  assert.equal(state.disposition, 'reopened')
  assert.equal(state.blocking, true)
  assert.equal(state.derivation, 'automatic-reopen')
  assert.equal(state.lifecycle, 'reopened')
  assert.deepEqual(state.currentOccurrenceIds, [])
  assert.deepEqual(
    state.basisEventIds,
    [decisions.entries[0].eventId],
  )

})

test('one explicit closure cannot govern sibling authoritative occurrences', () => {
  const first = observationFixture({ severity: 'medium' })
  const second = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    occurrenceId: SPLIT_OCCURRENCE_ID,
    decisionLedger: 'security-runtime',
    severity: 'medium',
  })
  const firstHistory = historyFixture('security-runtime', [first])
  const secondHistory = historyFixture('security-other', [second])
  const accepted = validDispositionEvents()[2]
  const decisions = prepareEventLedger('security-runtime', [accepted])
  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [
        currentFixture(firstHistory),
        currentFixture(secondHistory),
      ],
      [firstHistory, secondHistory],
      [decisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(FINDING_ID)
  assert.deepEqual(state, {
    disposition: 'open',
    blocking: true,
    derivation: 'reconciliation-conflict',
    lifecycle: 'unknown',
    currentOccurrenceIds: [
      OCCURRENCE_ID,
      SPLIT_OCCURRENCE_ID,
    ].sort(),
    eventId: null,
    basisEventIds: [decisions.entries[0].eventId],
    expiresAt: null,
    expiryState: 'not-applicable',
    reopenAcknowledged: false,
  })
})

test('reconciliation carries retained decisions, invalidates drift, and reopens terminal closures', () => {
  const before = observationFixture({ severity: 'medium' })
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const history = historyFixture('security-runtime', [before, after])
  const reconciliation = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const accepted = validDispositionEvents()[2]
  const acceptedLedger = prepareEventLedger(
    'security-runtime',
    [accepted, reconciliation],
  )
  const acceptedState = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [acceptedLedger],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(REPLACEMENT_FINDING_ID)
  assert.deepEqual(acceptedState, {
    disposition: 'accepted-risk',
    blocking: false,
    derivation: 'carried',
    lifecycle: 'persisting',
    currentOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
    eventId: null,
    basisEventIds: [acceptedLedger.entries[0].eventId],
    expiresAt: accepted.expiresAt,
    expiryState: 'active',
    reopenAcknowledged: false,
  })

  const driftPolicyDigest = `sha256:${'d'.repeat(64)}`
  const drifted = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [acceptedLedger],
    ),
    parseAuditDecisionPolicy(policyInput(), driftPolicyDigest),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(REPLACEMENT_FINDING_ID)
  assert.equal(drifted.disposition, 'open')
  assert.equal(drifted.blocking, true)
  assert.equal(drifted.derivation, 'carry-invalidated')
  assert.deepEqual(
    drifted.basisEventIds,
    [acceptedLedger.entries[0].eventId],
  )

  const falsePositive = validDispositionEvents()[4]
  const terminalLedger = prepareEventLedger(
    'security-runtime',
    [falsePositive, reconciliation],
  )
  assert.deepEqual(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(history)],
        [history],
        [terminalLedger],
      ),
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-07-30T00:00:00.000Z',
    ).findings.get(REPLACEMENT_FINDING_ID),
    {
      disposition: 'reopened',
      blocking: true,
      derivation: 'automatic-reopen',
      lifecycle: 'reopened',
      currentOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
      eventId: null,
      basisEventIds: [terminalLedger.entries[0].eventId],
      expiresAt: null,
      expiryState: 'not-applicable',
      reopenAcknowledged: false,
    },
  )
})

test('reconciliation applies split carry and merge compatibility fail-closed', () => {
  const secondBlob = `git-sha1:${'b'.repeat(40)}`
  const thirdFindingId = 'atf_111111111111111111111111'
  const before = exactObservation({
    observationId: OBSERVATION_ID,
    rows: [{
      findingId: FINDING_ID,
      occurrenceId: OCCURRENCE_ID,
      bindings: [
        binding('src/a.ts', BLOB),
        binding('src/b.ts', secondBlob),
      ],
    }],
  })
  const after = exactObservation({
    observationId: AFTER_OBSERVATION_ID,
    rows: [
      {
        findingId: REPLACEMENT_FINDING_ID,
        occurrenceId: REPLACEMENT_OCCURRENCE_ID,
        bindings: [binding('src/a.ts', BLOB)],
      },
      {
        findingId: thirdFindingId,
        occurrenceId: SPLIT_OCCURRENCE_ID,
        bindings: [binding('src/b.ts', secondBlob)],
      },
    ],
  })
  const split = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [
      REPLACEMENT_OCCURRENCE_ID,
      SPLIT_OCCURRENCE_ID,
    ],
  })
  const accepted = validDispositionEvents()[2]
  accepted.reviewContext.bindings = [
    binding('src/a.ts', BLOB),
    binding('src/b.ts', secondBlob),
  ]
  accepted.proofs[0].reviewedBindings = structuredClone(
    accepted.reviewContext.bindings,
  )
  const splitHistory = historyFixture('security-runtime', [before, after])
  const splitLedger = prepareEventLedger(
    'security-runtime',
    [accepted, split],
  )
  const splitState = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(splitHistory)],
      [splitHistory],
      [splitLedger],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  )
  for (const findingId of [REPLACEMENT_FINDING_ID, thirdFindingId]) {
    assert.equal(splitState.findings.get(findingId).disposition, 'accepted-risk')
    assert.equal(splitState.findings.get(findingId).derivation, 'carried')
    assert.deepEqual(
      splitState.findings.get(findingId).basisEventIds,
      [splitLedger.entries[0].eventId],
    )
  }

  const mergeBefore = exactObservation({
    observationId: OBSERVATION_ID,
    rows: [
      {
        findingId: FINDING_ID,
        occurrenceId: OCCURRENCE_ID,
        bindings: [binding('src/a.ts', BLOB)],
      },
      {
        findingId: thirdFindingId,
        occurrenceId: SPLIT_OCCURRENCE_ID,
        bindings: [binding('src/b.ts', secondBlob)],
      },
    ],
  })
  const mergeAfter = exactObservation({
    observationId: AFTER_OBSERVATION_ID,
    rows: [{
      findingId: REPLACEMENT_FINDING_ID,
      occurrenceId: REPLACEMENT_OCCURRENCE_ID,
      bindings: [
        binding('src/a.ts', BLOB),
        binding('src/b.ts', secondBlob),
      ],
    }],
  })
  const merge = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID, SPLIT_OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const firstAccepted = validDispositionEvents()[2]
  const secondAccepted = structuredClone(firstAccepted)
  secondAccepted.findingId = thirdFindingId
  secondAccepted.occurrenceId = SPLIT_OCCURRENCE_ID
  secondAccepted.expiresAt = '2026-08-20T00:00:00.000Z'
  secondAccepted.reviewContext.bindings = [
    binding('src/b.ts', secondBlob),
  ]
  secondAccepted.proofs[0].reviewedBindings = [
    binding('src/b.ts', secondBlob),
  ]
  const mergeHistory = historyFixture(
    'security-runtime',
    [mergeBefore, mergeAfter],
  )
  const mergeLedger = prepareEventLedger(
    'security-runtime',
    [firstAccepted, secondAccepted, merge],
  )
  const merged = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(mergeHistory)],
      [mergeHistory],
      [mergeLedger],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(REPLACEMENT_FINDING_ID)
  assert.equal(merged.disposition, 'accepted-risk')
  assert.equal(merged.derivation, 'carried')
  assert.equal(merged.expiresAt, secondAccepted.expiresAt)
  assert.deepEqual(
    merged.basisEventIds,
    mergeLedger.entries.slice(0, 2).map((entry) => entry.eventId).sort(),
  )

  const conflicting = structuredClone(secondAccepted)
  conflicting.action = 'false-positive'
  conflicting.expiresAt = null
  conflicting.proofs = [sourceEvidenceProof({
    reviewedBindings: [binding('src/b.ts', secondBlob)],
  })]
  conflicting.actionEvidence = {
    kind: 'source-evidence',
    reviewedBindings: [binding('src/b.ts', secondBlob)],
    conclusion: 'not-reportable',
    rationale: 'The second branch is not reportable.',
  }
  const conflictLedger = prepareEventLedger(
    'security-runtime',
    [firstAccepted, conflicting, merge],
  )
  const conflict = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(mergeHistory)],
      [mergeHistory],
      [conflictLedger],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(REPLACEMENT_FINDING_ID)
  assert.equal(conflict.disposition, 'open')
  assert.equal(conflict.blocking, true)
  assert.equal(conflict.derivation, 'reconciliation-conflict')
  assert.equal(conflict.lifecycle, 'unknown')
})

test('many-to-one retained decisions conflict on owner, context, action, or validity', () => {
  const secondBlob = `git-sha1:${'b'.repeat(40)}`
  const secondFindingId = 'atf_111111111111111111111111'
  const before = exactObservation({
    observationId: OBSERVATION_ID,
    rows: [
      {
        findingId: FINDING_ID,
        occurrenceId: OCCURRENCE_ID,
        bindings: [binding('src/a.ts', BLOB)],
      },
      {
        findingId: secondFindingId,
        occurrenceId: SPLIT_OCCURRENCE_ID,
        bindings: [binding('src/b.ts', secondBlob)],
      },
    ],
  })
  const after = exactObservation({
    observationId: AFTER_OBSERVATION_ID,
    rows: [{
      findingId: REPLACEMENT_FINDING_ID,
      occurrenceId: REPLACEMENT_OCCURRENCE_ID,
      bindings: [
        binding('src/a.ts', BLOB),
        binding('src/b.ts', secondBlob),
      ],
    }],
  })
  const history = historyFixture('security-runtime', [before, after])
  const merge = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID, SPLIT_OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const firstAccepted = validDispositionEvents()[2]
  const secondAccepted = structuredClone(firstAccepted)
  secondAccepted.findingId = secondFindingId
  secondAccepted.occurrenceId = SPLIT_OCCURRENCE_ID
  secondAccepted.reviewContext.bindings = [
    binding('src/b.ts', secondBlob),
  ]
  secondAccepted.proofs[0].reviewedBindings = [
    binding('src/b.ts', secondBlob),
  ]

  const incompatibleCases = [
    {
      name: 'owner',
      mutate(event) {
        event.owner = 'runtime-security'
      },
    },
    {
      name: 'policy context',
      mutate(event) {
        event.reviewContext.policyDigest = `sha256:${'d'.repeat(64)}`
      },
    },
    {
      name: 'retained action',
      mutate(event) {
        event.action = 'separate-design'
      },
    },
    {
      name: 'expired member',
      mutate(event) {
        event.expiresAt = '2026-07-29T12:00:00.000Z'
      },
    },
  ]
  for (const incompatible of incompatibleCases) {
    const second = structuredClone(secondAccepted)
    incompatible.mutate(second)
    const decisions = prepareEventLedger(
      'security-runtime',
      [firstAccepted, second, merge],
    )
    const state = reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(history)],
        [history],
        [decisions],
      ),
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-07-30T00:00:00.000Z',
    ).findings.get(REPLACEMENT_FINDING_ID)
    assert.equal(
      state.disposition,
      'open',
      incompatible.name,
    )
    assert.equal(state.blocking, true, incompatible.name)
    assert.equal(
      state.derivation,
      'reconciliation-conflict',
      incompatible.name,
    )
    assert.equal(state.lifecycle, 'unknown', incompatible.name)
    assert.deepEqual(
      state.basisEventIds,
      decisions.entries.slice(0, 2)
        .map((entry) => entry.eventId)
        .sort(),
      incompatible.name,
    )
  }

  const alternateObservationId = 'aobs_777777777777777777777777'
  const alternateRulesetDigest = `sha256:${'7'.repeat(64)}`
  const firstBefore = exactObservation({
    observationId: OBSERVATION_ID,
    rows: [{
      findingId: FINDING_ID,
      occurrenceId: OCCURRENCE_ID,
      bindings: [binding('src/a.ts', BLOB)],
    }],
  })
  const secondBefore = exactObservation({
    observationId: alternateObservationId,
    rows: [{
      findingId: secondFindingId,
      occurrenceId: SPLIT_OCCURRENCE_ID,
      bindings: [binding('src/b.ts', secondBlob)],
    }],
  })
  secondBefore.producer.ruleset.digest = alternateRulesetDigest
  const rulesetHistory = historyFixture(
    'security-runtime',
    [firstBefore, secondBefore, after],
  )
  const rulesetMerge = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID, alternateObservationId],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID, SPLIT_OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const alternateAccepted = structuredClone(secondAccepted)
  alternateAccepted.reviewContext.observationId = alternateObservationId
  alternateAccepted.reviewContext.ruleset.digest = alternateRulesetDigest
  alternateAccepted.proofs[0].observationId = alternateObservationId
  const rulesetDecisions = prepareEventLedger(
    'security-runtime',
    [firstAccepted, alternateAccepted, rulesetMerge],
  )
  const rulesetConflict = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(rulesetHistory)],
      [rulesetHistory],
      [rulesetDecisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(REPLACEMENT_FINDING_ID)
  assert.equal(rulesetConflict.disposition, 'open')
  assert.equal(rulesetConflict.derivation, 'reconciliation-conflict')
  assert.equal(rulesetConflict.lifecycle, 'unknown')
})

test('explicit current dispositions take precedence over reconciliation-derived state', () => {
  const before = observationFixture({ severity: 'medium' })
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const history = historyFixture('security-runtime', [before, after])
  const reconciliation = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const priorAcceptance = validDispositionEvents()[2]
  const afterContext = reviewContext({
    observationId: AFTER_OBSERVATION_ID,
  })
  const explicitOpen = dispositionBase({
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    action: 'open',
    reviewContext: afterContext,
    proofs: [currentReviewProof({
      observationId: AFTER_OBSERVATION_ID,
    })],
    createdAt: '2026-07-30T00:00:00.000Z',
  })
  const openLedger = prepareEventLedger(
    'security-runtime',
    [priorAcceptance, reconciliation, explicitOpen],
  )
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  const index = buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [openLedger],
  )
  const openState = reduceAuditDecisionState(
    index,
    policy,
    '2026-07-30T01:00:00.000Z',
  ).findings.get(REPLACEMENT_FINDING_ID)
  assert.equal(openState.disposition, 'open')
  assert.equal(openState.derivation, 'explicit-event')
  assert.equal(
    openState.eventId,
    openLedger.entries.at(-1).eventId,
  )

  const currentClosure = structuredClone(explicitOpen)
  currentClosure.action = 'accepted-risk'
  currentClosure.expiresAt = '2026-08-28T00:00:00.000Z'
  delete currentClosure.supersedesEventId
  const closureId = computeAuditDecisionEventId(currentClosure)
  const acknowledged = dispositionBase({
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    action: 'reopened',
    reviewContext: afterContext,
    proofs: [currentReviewProof({
      observationId: AFTER_OBSERVATION_ID,
    })],
    supersedesEventId: closureId,
    createdAt: '2026-07-30T01:00:00.000Z',
  })
  const acknowledgedLedger = prepareEventLedger(
    'security-runtime',
    [priorAcceptance, reconciliation, currentClosure, acknowledged],
  )
  const acknowledgedState = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [acknowledgedLedger],
    ),
    policy,
    '2026-07-30T02:00:00.000Z',
  ).findings.get(REPLACEMENT_FINDING_ID)
  assert.equal(acknowledgedState.disposition, 'reopened')
  assert.equal(acknowledgedState.derivation, 'explicit-event')
  assert.equal(acknowledgedState.reopenAcknowledged, true)
  assert.equal(
    acknowledgedState.eventId,
    acknowledgedLedger.entries.at(-1).eventId,
  )
  assert.deepEqual(acknowledgedState.basisEventIds, [closureId])
})

test('uncertain reconciliation makes the related current lifecycle unknown', () => {
  const before = observationFixture({ severity: 'medium' })
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    blob: `git-sha1:${'a'.repeat(40)}`,
    severity: 'medium',
  })
  const history = historyFixture('security-runtime', [before, after])
  const uncertain = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
    outcome: 'uncertain',
    confidence: 'low',
    reason: 'Available evidence cannot confirm or reject equivalence.',
  })
  const remediation = validDispositionEvents()[5]
  const decisions = prepareEventLedger(
    'security-runtime',
    [remediation, uncertain],
  )
  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [decisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(REPLACEMENT_FINDING_ID)
  assert.equal(state.disposition, 'open')
  assert.equal(state.blocking, true)
  assert.equal(state.derivation, 'reconciliation-conflict')
  assert.equal(state.lifecycle, 'unknown')
  assert.deepEqual(
    state.basisEventIds,
    [decisions.entries[0].eventId],
  )
})

test('distinct reconciliation leaves an unrelated current occurrence new', () => {
  const before = observationFixture({ severity: 'medium' })
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const history = historyFixture('security-runtime', [before, after])
  const distinct = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
    outcome: 'distinct',
    confidence: 'high',
    reason: 'The current occurrence has a distinct root cause.',
  })
  const decisions = prepareEventLedger(
    'security-runtime',
    [validDispositionEvents()[2], distinct],
  )
  assert.deepEqual(
    reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(history)],
        [history],
        [decisions],
      ),
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-07-30T00:00:00.000Z',
    ).findings.get(REPLACEMENT_FINDING_ID),
    {
      disposition: 'open',
      blocking: true,
      derivation: 'implicit-open',
      lifecycle: 'new',
      currentOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
      eventId: null,
      basisEventIds: [],
      expiresAt: null,
      expiryState: 'not-applicable',
      reopenAcknowledged: false,
    },
  )
})

test('published reconciliation chains propagate decisions transitively by occurrence', () => {
  const middleFindingId = REPLACEMENT_FINDING_ID
  const finalFindingId = 'atf_333333333333333333333333'
  const finalOccurrenceId = 'atocc_444444444444444444444444'
  const finalObservationId = 'aobs_cccccccccccccccccccccccc'
  const first = observationFixture({ severity: 'medium' })
  const middle = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: middleFindingId,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const final = observationFixture({
    observationId: finalObservationId,
    findingId: finalFindingId,
    occurrenceId: finalOccurrenceId,
    severity: 'medium',
  })
  const history = historyFixture(
    'security-runtime',
    [first, middle, final],
  )
  const firstComparison = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const secondComparison = reconciliationInput({
    beforeObservationIds: [AFTER_OBSERVATION_ID],
    afterObservationIds: [finalObservationId],
    beforeOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
    afterOccurrenceIds: [finalOccurrenceId],
    createdAt: '2026-07-29T03:00:00.000Z',
  })
  const accepted = validDispositionEvents()[2]
  const decisions = prepareEventLedger(
    'security-runtime',
    [accepted, firstComparison, secondComparison],
  )
  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [decisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(finalFindingId)
  assert.equal(state.disposition, 'accepted-risk')
  assert.equal(state.derivation, 'carried')
  assert.equal(state.lifecycle, 'persisting')
  assert.deepEqual(
    state.basisEventIds,
    [decisions.entries[0].eventId],
  )

  const reverseDecisions = prepareEventLedger(
    'security-runtime',
    [accepted, secondComparison, firstComparison],
  )
  const reverseState = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [reverseDecisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(finalFindingId)
  assert.deepEqual(reverseState, state)
})

test('lifecycle scheduling always selects the lowest original ready edge index', () => {
  const ids = {
    rootFinding: 'atf_100000000000000000000000',
    middleFinding: 'atf_200000000000000000000000',
    sideFinding: 'atf_300000000000000000000000',
    targetFinding: 'atf_400000000000000000000000',
    rootOccurrence: 'atocc_100000000000000000000000',
    middleOccurrence: 'atocc_200000000000000000000000',
    sideOccurrence: 'atocc_300000000000000000000000',
    targetOccurrence: 'atocc_400000000000000000000000',
    rootObservation: 'aobs_100000000000000000000000',
    middleObservation: 'aobs_200000000000000000000000',
    sideObservation: 'aobs_300000000000000000000000',
    targetObservation: 'aobs_400000000000000000000000',
  }
  const observations = [
    observationFixture({
      observationId: ids.rootObservation,
      findingId: ids.rootFinding,
      occurrenceId: ids.rootOccurrence,
      severity: 'medium',
    }),
    observationFixture({
      observationId: ids.middleObservation,
      findingId: ids.middleFinding,
      occurrenceId: ids.middleOccurrence,
      severity: 'medium',
    }),
    observationFixture({
      observationId: ids.sideObservation,
      findingId: ids.sideFinding,
      occurrenceId: ids.sideOccurrence,
      severity: 'medium',
    }),
    observationFixture({
      observationId: ids.targetObservation,
      findingId: ids.targetFinding,
      occurrenceId: ids.targetOccurrence,
      severity: 'medium',
    }),
  ]
  const history = historyFixture('security-runtime', observations)
  const blockedFirst = reconciliationInput({
    beforeObservationIds: [ids.middleObservation],
    afterObservationIds: [ids.targetObservation],
    beforeOccurrenceIds: [ids.middleOccurrence],
    afterOccurrenceIds: [ids.targetOccurrence],
  })
  const unlocker = reconciliationInput({
    beforeObservationIds: [ids.rootObservation],
    afterObservationIds: [ids.middleObservation],
    beforeOccurrenceIds: [ids.rootOccurrence],
    afterOccurrenceIds: [ids.middleOccurrence],
    createdAt: '2026-07-29T03:00:00.000Z',
  })
  const alreadyReadyLater = reconciliationInput({
    beforeObservationIds: [ids.sideObservation],
    afterObservationIds: [ids.targetObservation],
    beforeOccurrenceIds: [ids.sideOccurrence],
    afterOccurrenceIds: [ids.targetOccurrence],
    outcome: 'uncertain',
    confidence: 'low',
    createdAt: '2026-07-29T04:00:00.000Z',
  })
  const accepted = dispositionBase({
    findingId: ids.rootFinding,
    occurrenceId: ids.rootOccurrence,
    action: 'accepted-risk',
    expiresAt: '2026-08-28T00:00:00.000Z',
    reviewContext: reviewContext({
      observationId: ids.rootObservation,
    }),
    proofs: [currentReviewProof({
      observationId: ids.rootObservation,
    })],
  })
  const index = buildAuditDecisionIndex(
    [currentFixture(history)],
    [history],
    [prepareEventLedger(
      'security-runtime',
      [accepted, blockedFirst, unlocker, alreadyReadyLater],
    )],
  )

  const target = reduceAuditDecisionState(
    index,
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(ids.targetFinding)
  assert.equal(target.derivation, 'reconciliation-conflict')
  assert.equal(target.lifecycle, 'unknown')
})

test('near-bound lifecycle component chains reduce without recursive stack overflow', {
  timeout: 30_000,
}, () => {
  const count = 9_000
  const splitBindings = [
    binding(),
    binding('src/b.ts', `git-sha1:${'b'.repeat(40)}`),
  ]
  const occurrenceIdAt = (index) =>
    `atocc_${(count - index).toString(16).padStart(24, '0')}`
  const observationIdAt = (index) =>
    `aobs_${(index + 1).toString(16).padStart(24, '0')}`
  const chainObservations = Array.from({ length: count }, (_unused, index) =>
    index === 0
      ? exactObservation({
          observationId: observationIdAt(index),
          rows: [{
            findingId: FINDING_ID,
            occurrenceId: occurrenceIdAt(index),
            bindings: splitBindings,
            severity: 'medium',
          }],
        })
      : observationFixture({
          observationId: observationIdAt(index),
          occurrenceId: occurrenceIdAt(index),
          severity: 'medium',
        })
  )
  const branchObservationIds = [
    `aobs_${'e'.repeat(24)}`,
    `aobs_${'f'.repeat(24)}`,
  ]
  const branchOccurrenceIds = [
    `atocc_${'e'.repeat(24)}`,
    `atocc_${'f'.repeat(24)}`,
  ]
  const branchObservations = branchObservationIds.map(
    (observationId, index) => exactObservation({
      observationId,
      rows: [{
        findingId: FINDING_ID,
        occurrenceId: branchOccurrenceIds[index],
        bindings: [splitBindings[index]],
        severity: 'medium',
      }],
    }),
  )
  const chainHistory = historyFixture('security-runtime', chainObservations)
  const branchHistories = branchObservations.map((observation, index) =>
    historyFixture(`security-branch-${index}`, [observation])
  )
  const splitSuccessor = reconciliationInput({
    beforeObservationIds: [observationIdAt(0)],
    afterObservationIds: branchObservationIds,
    beforeOccurrenceIds: [occurrenceIdAt(0)],
    afterOccurrenceIds: branchOccurrenceIds,
  })
  const index = buildAuditDecisionIndex(
    [
      currentFixture(chainHistory),
      ...branchHistories.map((history) => currentFixture(history)),
    ],
    [chainHistory, ...branchHistories],
    [prepareEventLedger('security-runtime', [splitSuccessor])],
  )

  assert.doesNotThrow(() => reduceAuditDecisionState(
    index,
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ))
})

test('stable finding identity carries before later explicit reconciliation', () => {
  const finalFindingId = 'atf_333333333333333333333333'
  const finalOccurrenceId = 'atocc_444444444444444444444444'
  const finalObservationId = 'aobs_cccccccccccccccccccccccc'
  const first = observationFixture({ severity: 'medium' })
  const sameFindingLater = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const final = observationFixture({
    observationId: finalObservationId,
    findingId: finalFindingId,
    occurrenceId: finalOccurrenceId,
    severity: 'medium',
  })
  const history = historyFixture(
    'security-runtime',
    [first, sameFindingLater, final],
  )
  const comparison = reconciliationInput({
    beforeObservationIds: [AFTER_OBSERVATION_ID],
    afterObservationIds: [finalObservationId],
    beforeOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
    afterOccurrenceIds: [finalOccurrenceId],
    createdAt: '2026-07-29T03:00:00.000Z',
  })
  const decisions = prepareEventLedger(
    'security-runtime',
    [validDispositionEvents()[2], comparison],
  )

  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(history)],
      [history],
      [decisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(finalFindingId)
  assert.equal(state.disposition, 'accepted-risk')
  assert.equal(state.derivation, 'carried')
  assert.equal(state.lifecycle, 'persisting')
  assert.deepEqual(
    state.basisEventIds,
    [decisions.entries[0].eventId],
  )
})

test('stable finding identity carries across source histories before reconciliation', () => {
  const finalFindingId = 'atf_333333333333333333333333'
  const finalOccurrenceId = 'atocc_444444444444444444444444'
  const finalObservationId = 'aobs_cccccccccccccccccccccccc'
  const sameHistoryObservationId = 'aobs_555555555555555555555555'
  const sameHistoryOccurrenceId = 'atocc_666666666666666666666666'
  const origin = observationFixture({
    decisionLedger: 'security-origin',
    severity: 'medium',
  })
  const moved = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    decisionLedger: 'security-origin',
    severity: 'medium',
  })
  const final = observationFixture({
    observationId: finalObservationId,
    findingId: finalFindingId,
    occurrenceId: finalOccurrenceId,
    decisionLedger: 'security-runtime',
    severity: 'medium',
  })
  const sameHistoryLater = observationFixture({
    observationId: sameHistoryObservationId,
    occurrenceId: sameHistoryOccurrenceId,
    decisionLedger: 'security-origin',
    severity: 'medium',
  })
  const originHistory = historyFixture('security-origin', [origin])
  const runtimeHistory = historyFixture(
    'security-runtime',
    [moved, sameHistoryLater, final],
  )
  const comparison = reconciliationInput({
    beforeObservationIds: [sameHistoryObservationId],
    afterObservationIds: [finalObservationId],
    beforeOccurrenceIds: [sameHistoryOccurrenceId],
    afterOccurrenceIds: [finalOccurrenceId],
    decisionLedger: 'security-origin',
    createdAt: '2026-07-29T03:00:00.000Z',
  })
  const decisions = prepareEventLedger(
    'security-origin',
    [validDispositionEvents()[2], comparison],
  )

  const state = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [
        currentFixture(originHistory),
        currentFixture(runtimeHistory),
      ],
      [originHistory, runtimeHistory],
      [decisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(finalFindingId)
  assert.equal(state.disposition, 'accepted-risk')
  assert.equal(state.derivation, 'carried')
  assert.equal(state.lifecycle, 'persisting')
  assert.deepEqual(
    state.basisEventIds,
    [decisions.entries[0].eventId],
  )
})

test('reconciliation with a history-ahead endpoint is non-effective until publication', () => {
  const finalFindingId = 'atf_333333333333333333333333'
  const finalOccurrenceId = 'atocc_444444444444444444444444'
  const finalObservationId = 'aobs_cccccccccccccccccccccccc'
  const first = observationFixture({ severity: 'medium' })
  const ahead = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const currentOther = observationFixture({
    observationId: finalObservationId,
    findingId: finalFindingId,
    occurrenceId: finalOccurrenceId,
    decisionLedger: 'security-other',
    severity: 'medium',
  })
  const runtimeHistory = historyFixture(
    'security-runtime',
    [first, ahead],
  )
  const otherHistory = historyFixture(
    'security-other',
    [currentOther],
  )
  const firstComparison = reconciliationInput({
    beforeObservationIds: [OBSERVATION_ID],
    afterObservationIds: [AFTER_OBSERVATION_ID],
    beforeOccurrenceIds: [OCCURRENCE_ID],
    afterOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
  })
  const secondComparison = reconciliationInput({
    beforeObservationIds: [AFTER_OBSERVATION_ID],
    afterObservationIds: [finalObservationId],
    beforeOccurrenceIds: [REPLACEMENT_OCCURRENCE_ID],
    afterOccurrenceIds: [finalOccurrenceId],
    decisionLedger: 'security-other',
    createdAt: '2026-07-29T03:00:00.000Z',
  })
  const runtimeDecisions = prepareEventLedger(
    'security-runtime',
    [validDispositionEvents()[2], firstComparison],
  )
  const otherDecisions = prepareEventLedger(
    'security-other',
    [secondComparison],
  )
  const policy = parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST)
  const beforePublication = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [
        currentFixture(runtimeHistory, 0),
        currentFixture(otherHistory),
      ],
      [runtimeHistory, otherHistory],
      [runtimeDecisions, otherDecisions],
    ),
    policy,
    '2026-07-30T00:00:00.000Z',
  ).findings.get(finalFindingId)
  assert.equal(beforePublication.disposition, 'open')
  assert.equal(beforePublication.derivation, 'implicit-open')
  assert.equal(beforePublication.lifecycle, 'new')

  const afterPublication = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [
        currentFixture(runtimeHistory, 1),
        currentFixture(otherHistory),
      ],
      [runtimeHistory, otherHistory],
      [runtimeDecisions, otherDecisions],
    ),
    policy,
    '2026-07-30T00:00:00.000Z',
  ).findings.get(finalFindingId)
  assert.equal(afterPublication.disposition, 'accepted-risk')
  assert.equal(afterPublication.derivation, 'carried')
  assert.deepEqual(
    afterPublication.basisEventIds,
    [runtimeDecisions.entries[0].eventId],
  )
})

test('superseded existing paths require a current exact review under policy', () => {
  const before = observationFixture({ severity: 'medium' })
  const after = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    severity: 'medium',
  })
  const history = historyFixture('security-runtime', [before, after])
  const superseded = validDispositionEvents()[6]
  const decisions = prepareEventLedger(
    'security-runtime',
    [superseded],
  )
  assert.throws(
    () => reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(history)],
        [history],
        [decisions],
      ),
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-07-30T00:00:00.000Z',
    ),
    /superseded|existing path|current review|policy/i,
  )

  const replacementBlob = `git-sha1:${'b'.repeat(40)}`
  const contextOnlyAfter = observationFixture({
    observationId: AFTER_OBSERVATION_ID,
    findingId: REPLACEMENT_FINDING_ID,
    occurrenceId: REPLACEMENT_OCCURRENCE_ID,
    path: 'src/replacement.ts',
    blob: replacementBlob,
    severity: 'medium',
  })
  contextOnlyAfter.scope.files.push({
    path: 'src/a.ts',
    blob: BLOB,
    status: 'not-reviewed',
  })
  contextOnlyAfter.scope.files.sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0
  )
  const contextOnlyHistory = historyFixture(
    'security-runtime',
    [before, contextOnlyAfter],
  )
  const contextOnlyIndex = buildAuditDecisionIndex(
    [currentFixture(contextOnlyHistory)],
    [contextOnlyHistory],
    [],
  )
  assert.deepEqual(
    contextOnlyIndex.observations.get(AFTER_OBSERVATION_ID)
      .inventoryBindings,
    [
      binding('src/a.ts', BLOB),
      binding('src/replacement.ts', replacementBlob),
    ],
  )

  const contextOnlySuperseded = structuredClone(superseded)
  contextOnlySuperseded.proofs[0].replacementBindings = [
    binding('src/replacement.ts', replacementBlob),
  ]
  const contextOnlyDecisions = prepareEventLedger(
    'security-runtime',
    [contextOnlySuperseded],
  )
  assert.throws(
    () => reduceAuditDecisionState(
      buildAuditDecisionIndex(
        [currentFixture(contextOnlyHistory)],
        [contextOnlyHistory],
        [contextOnlyDecisions],
      ),
      parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
      '2026-07-30T00:00:00.000Z',
    ),
    /superseded|existing path|current review|policy/i,
  )

  const absentHistory = historyFixture(
    'security-runtime',
    [before, {
      ...contextOnlyAfter,
      scope: {
        ...contextOnlyAfter.scope,
        files: contextOnlyAfter.scope.files.filter(
          (file) => file.path !== 'src/a.ts',
        ),
      },
    }],
  )
  const absent = reduceAuditDecisionState(
    buildAuditDecisionIndex(
      [currentFixture(absentHistory)],
      [absentHistory],
      [contextOnlyDecisions],
    ),
    parseAuditDecisionPolicy(policyInput(), POLICY_DIGEST),
    '2026-07-30T00:00:00.000Z',
  ).findings.get(FINDING_ID)
  assert.equal(absent.disposition, 'superseded')
  assert.equal(absent.blocking, false)
})
