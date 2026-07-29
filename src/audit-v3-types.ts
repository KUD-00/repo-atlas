export type AuditSha256 = `sha256:${string}`
export type AuditGitBlob = `git-sha1:${string}` | `git-sha256:${string}`
export type AtlasFingerprintV1 = `atlas/v1:sha256:${string}`
export type AtlasFindingId = `atf_${string}`
export type AtlasOccurrenceId = `atocc_${string}`
export type AtlasObservationId = `aobs_${string}`
export type AuditJsonPrimitive = null | boolean | number | string
export type AuditJsonValue =
  | AuditJsonPrimitive
  | AuditJsonValue[]
  | { [key: string]: AuditJsonValue }

export type AuditExactScopeMode = 'repository' | 'scoped_path' | 'unit' | 'diff' | 'custom'
export type AuditSemanticMode =
  | 'repository'
  | 'scoped_path'
  | 'diff'
  | 'commit'
  | 'branch_diff'
  | 'working_tree'
  | 'deep_repository'
  | 'unit'
  | 'custom'
export type AuditInventoryStrategy =
  | 'repository'
  | 'scoped_path'
  | 'diff'
  | 'directory'
  | 'custom'
  | 'unit'

export interface AtlasFingerprintInput {
  repositoryId: string
  domain: 'security'
  ruleId: string
  anchor: string
  instance?: string
}

export interface AtlasObservationIdentityInput {
  slug: string
  adapter: string
  runId: string
  producerIdentityDigest: AuditSha256
  targetId: string
  targetIdentityDigest: AuditSha256
  scopeIdentityDigest: AuditSha256
}

export interface AuditExactScopeIdentityInput {
  mode: AuditExactScopeMode
  includePaths: readonly string[]
  excludePaths: readonly string[]
  files: ReadonlyArray<{ path: string; blob: AuditGitBlob }>
}

export interface AuditExplicitExclusionV3 {
  pattern: string
  reason: string
}

export interface AuditSemanticScopeIdentityInput {
  mode: AuditSemanticMode
  inventoryStrategy: AuditInventoryStrategy
  includePaths: readonly string[]
  excludePaths: readonly string[]
  explicitExclusions: readonly AuditExplicitExclusionV3[]
}

export type AuditReviewStatus = 'reviewed' | 'not-reviewed'
export type AuditReviewOutcome = 'clean' | 'findings' | 'unknown'
export type AuditProducerKind = 'grok-cli' | 'codex-security' | 'migration' | 'manual'
export type AuditConfidence = 'low' | 'medium' | 'high'
export type AuditSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational'

export interface AuditRulesetReceiptV3 {
  id: string
  digest: AuditSha256
}

export type AuditPromptReceiptV3 =
  | {
      builtinVersion: string
      digest: AuditSha256
      extraPath?: never
      extraDigest?: never
    }
  | {
      builtinVersion: string
      digest: AuditSha256
      extraPath: string
      extraDigest: AuditSha256
    }

interface AuditProducerReceiptBaseV3 {
  kind: AuditProducerKind
  name: string
  version: string
  adapter: string
  adapterVersion: string
  runId: string
  identityDigest: AuditSha256
}

export interface AuditCodexSourceContractV3 {
  namespace: 'codex-security/1.0'
  status: 'completed'
  startedAt: string
  completedAt: string
  sealedAt: string
  manifestPath: 'scan-manifest.json'
  coverageRef: 'coverage.json'
  findingsRef: 'findings.json'
}

export interface AuditRulesetProducerReceiptV3 extends AuditProducerReceiptBaseV3 {
  kind: 'grok-cli' | 'migration' | 'manual'
  identityBasis: 'ruleset'
  ruleset: AuditRulesetReceiptV3
  prompt?: AuditPromptReceiptV3
  effectiveConfigDigest?: AuditSha256
  environmentPolicyDigest?: AuditSha256
  transcriptDigest?: AuditSha256
  sourceContract?: never
}

export interface AuditCodexProducerReceiptV3 extends AuditProducerReceiptBaseV3 {
  kind: 'codex-security'
  identityBasis: 'codex-contract'
  sourceContract: AuditCodexSourceContractV3
  ruleset?: never
  prompt?: never
  effectiveConfigDigest?: never
  environmentPolicyDigest?: never
  transcriptDigest?: never
}

export type AuditProducerReceiptV3 =
  | AuditRulesetProducerReceiptV3
  | AuditCodexProducerReceiptV3

interface AuditTargetReceiptBaseV3 {
  kind: 'git-revision' | 'git-worktree' | 'git-diff' | 'directory-snapshot'
  repositoryId: string
  targetId: string
  identityDigest: AuditSha256
  displayName?: string
  remote?: string
}

interface AuditFirstPartyTargetBaseV3 extends AuditTargetReceiptBaseV3 {
  identityBasis: 'snapshot'
  snapshotDigest: AuditSha256
  sourceKind?: never
  sourceRevision?: never
  sourceBaseRevision?: never
  sourceHeadRevision?: never
  sourceSnapshotDigest?: never
}

export type AuditFirstPartyTargetReceiptV3 =
  | (AuditFirstPartyTargetBaseV3 & {
      kind: 'git-revision'
      revision: string
      dirty: false
      baseRevision?: never
      headRevision?: never
    })
  | (AuditFirstPartyTargetBaseV3 & {
      kind: 'git-worktree'
      revision: string
      dirty: false
      baseRevision?: never
      headRevision?: never
    })
  | (AuditFirstPartyTargetBaseV3 & {
      kind: 'git-worktree'
      revision?: string
      dirty: true
      baseRevision?: never
      headRevision?: never
    })
  | (AuditFirstPartyTargetBaseV3 & {
      kind: 'git-diff'
      baseRevision: string
      headRevision: string
      dirty: false
      revision?: never
    })
  | (AuditFirstPartyTargetBaseV3 & {
      kind: 'directory-snapshot'
      revision?: never
      baseRevision?: never
      headRevision?: never
      dirty?: never
    })

interface AuditCodexTargetBaseV3 extends AuditTargetReceiptBaseV3 {
  displayName: string
  sourceKind: 'git_revision' | 'git_worktree' | 'git_diff' | 'directory_snapshot'
  dirty?: never
  revision?: never
  baseRevision?: never
  headRevision?: never
}

interface AuditCodexCoordinateTargetBaseV3 extends AuditCodexTargetBaseV3 {
  identityBasis: 'revision-coordinate'
  snapshotDigest?: never
  sourceSnapshotDigest?: never
}

interface AuditCodexSnapshotTargetBaseV3 extends AuditCodexTargetBaseV3 {
  identityBasis: 'snapshot'
  snapshotDigest: AuditSha256
  sourceSnapshotDigest: `codex-security-snapshot/v1:sha256:${string}`
}

type AuditCodexTargetCoordinatesV3 =
  | {
      kind: 'git-revision'
      sourceKind: 'git_revision'
      sourceRevision: string
      sourceBaseRevision?: string
      sourceHeadRevision?: string
    }
  | {
      kind: 'git-worktree'
      sourceKind: 'git_worktree'
      sourceRevision?: string
      sourceBaseRevision?: string
      sourceHeadRevision?: string
    }
  | {
      kind: 'git-diff'
      sourceKind: 'git_diff'
      sourceRevision?: string
      sourceBaseRevision?: string
      sourceHeadRevision?: string
    }
  | {
      kind: 'directory-snapshot'
      sourceKind: 'directory_snapshot'
      sourceRevision?: string
      sourceBaseRevision?: string
      sourceHeadRevision?: string
    }

export type AuditCodexTargetReceiptV3 =
  | (
      AuditCodexCoordinateTargetBaseV3 &
      Extract<AuditCodexTargetCoordinatesV3, { kind: 'git-revision' }>
    )
  | (AuditCodexSnapshotTargetBaseV3 & AuditCodexTargetCoordinatesV3)

type AssertType<T extends true> = T
type _CodexSourceContractPinsArtifactNames = AssertType<
  AuditCodexSourceContractV3 extends {
    manifestPath: 'scan-manifest.json'
    coverageRef: 'coverage.json'
    findingsRef: 'findings.json'
  } ? true : false
>
type _CodexDiffPreservesEveryOptionalCoordinate = AssertType<
  {
    kind: 'git-diff'
    sourceKind: 'git_diff'
    repositoryId: string
    targetId: string
    displayName: string
    identityDigest: AuditSha256
    identityBasis: 'snapshot'
    snapshotDigest: AuditSha256
    sourceSnapshotDigest: `codex-security-snapshot/v1:sha256:${string}`
    sourceRevision: string
    sourceBaseRevision: string
    sourceHeadRevision: string
  } extends AuditCodexTargetReceiptV3 ? true : false
>

export type AuditTargetReceiptV3 =
  | AuditFirstPartyTargetReceiptV3
  | AuditCodexTargetReceiptV3

export interface AuditFileReceiptV3 {
  path: string
  blob: AuditGitBlob
  lines: number
  status: AuditReviewStatus
  outcome: AuditReviewOutcome
  reviewedAt?: string
  reviewedAtPrecision?: 'timestamp' | 'date'
  reviewedBy?: string
  ruleset?: string
  findingOccurrenceIds: string[]
  receiptRefs: string[]
}

interface AuditScopeCommonV3 {
  identityDigest: AuditSha256
  includePaths: string[]
  excludePaths: string[]
  artifactsReviewed?: string[]
  limitations?: string[]
  summary?: string
  runtimeStatus?: string
  validationMode?: string
  context?: string
}

export interface AuditExactInventoryScopeV3 extends AuditScopeCommonV3 {
  mode: AuditExactScopeMode
  identityBasis: 'exact-inventory'
  scopeHash: AuditSha256
  inventoryDigest: AuditSha256
  fileCount: number
  files: AuditFileReceiptV3[]
  inventoryStrategy?: never
  explicitExclusions?: never
}

export interface AuditSemanticDeclarationScopeV3 extends AuditScopeCommonV3 {
  mode: AuditSemanticMode
  identityBasis: 'semantic-declaration'
  inventoryStrategy: AuditInventoryStrategy
  explicitExclusions: AuditExplicitExclusionV3[]
  scopeHash?: never
  inventoryDigest?: never
  fileCount?: never
  files?: never
}

export type AuditScopeV3 =
  | AuditExactInventoryScopeV3
  | AuditSemanticDeclarationScopeV3

export interface AuditUnreviewedFileV3 {
  path: string
  reason: string
}

export interface AuditFullReadExactCoverageV3 {
  completeness: 'complete' | 'partial'
  basis: 'full-read-receipts'
  reviewedFileCount: number
  unreviewed: AuditUnreviewedFileV3[]
  reason?: never
}

export interface AuditUnavailableExactCoverageV3 {
  completeness: 'unknown'
  basis: 'unavailable'
  reason: string
  reviewedFileCount?: never
  unreviewed?: never
}

export type AuditExactCoverageV3 =
  | AuditFullReadExactCoverageV3
  | AuditUnavailableExactCoverageV3

export interface AuditSemanticSurfaceV3 {
  id: string
  label: string
  disposition:
    | 'reported'
    | 'no_issue_found'
    | 'rejected'
    | 'not_applicable'
    | 'needs_follow_up'
  receiptRefs: string[]
  riskArea?: string
  notes?: string
}

export interface AuditDeferredWorkV3 {
  id: string
  reason: string
  paths?: string[]
  surfaceIds?: string[]
}

export interface AuditOpenQuestionV3 {
  question: string
  followUpPrompt?: string
}

export interface AuditSemanticCoverageV3 {
  mode: AuditSemanticMode
  completeness: 'complete' | 'partial' | 'unknown'
  inventoryStrategy: AuditInventoryStrategy
  surfaces: AuditSemanticSurfaceV3[]
  explicitExclusions: AuditExplicitExclusionV3[]
  deferred: AuditDeferredWorkV3[]
  openQuestions?: AuditOpenQuestionV3[]
}

export interface AuditThreatModelV3 {
  summary: string
  assets?: string[]
  trustBoundaries?: string[]
  attackerCapabilities?: string[]
  securityObjectives?: string[]
  assumptions?: string[]
}

interface AuditSourceArtifactBaseV3 {
  path: string
  sha256: string
  mediaType: string
  referencedBy: string[]
  retainedInAtlas: boolean
}

export type AuditSourceArtifactV3 =
  | (AuditSourceArtifactBaseV3 & {
      integrityKind: 'producer-manifest'
      integrityIndex: string
    })
  | (AuditSourceArtifactBaseV3 & {
      integrityKind: 'adapter-bundle'
      integrityIndex?: never
    })

export interface AuditExtensionV3 {
  namespace: string
  path: string
  value: AuditJsonValue
  digest: AuditSha256
}

export interface AuditFindingFingerprintV3 {
  scheme: string
  value: string
  role: 'canonical' | 'producer'
}

export interface AuditFindingLocationV3 {
  path: string
  startLine: number
  endLine?: number
  role?: string
}

interface AuditCodeEvidenceCommonV3 {
  id: string
  label: string
  path: string
  startLine: number
  endLine?: number
  language?: string
  role?: string
  code: string
  explanation: string
}

export type AuditCodeEvidenceV3 =
  | (AuditCodeEvidenceCommonV3 & {
      evidenceBasis: 'exact-blob'
      blob: AuditGitBlob
      sourceSeal?: never
    })
  | (AuditCodeEvidenceCommonV3 & {
      evidenceBasis: 'sealed-producer-snippet'
      sourceSeal: {
        artifactPath: string
        artifactSha256: string
        jsonPointer: string
      }
      blob?: never
    })

export interface AuditFindingSeverityV3 {
  level: AuditSeverity
  score?: number
  scoringSystem?: string
  vector?: string
  rationale?: string
  changeConditions?: string
}

export interface AuditFindingConfidenceV3 {
  level: AuditConfidence
  rationale?: string
}

export interface AuditFindingTaxonomyV3 {
  category: string
  cwe?: string[]
}

export interface AuditFindingIdentityV3 {
  anchor: string
  instance?: string
}

export interface AuditFindingRootCauseV3 {
  summary: string
  evidenceRefs?: string[]
  legacyCode?: {
    code: string
    language?: string
  }
}

export interface AuditFindingProvenanceV3 {
  source: string
  producerSource?: string
  sourceFindingId?: string
  sourceOccurrenceId?: string
  candidateId?: string
  ledgerRowId?: string
  reportId?: string
}

export interface AuditFindingValidationV3 {
  method?: string
  disposition?: 'reportable' | 'suppressed' | 'not_applicable' | 'deferred'
  summary?: string
  confidence?: AuditConfidence
  confidenceRationale?: string
  evidenceRefs?: string[]
  assertions?: AuditJsonValue[]
  evidence?: AuditJsonValue[]
  counterevidenceOrProofGap?: AuditJsonValue[]
  remainingUncertainty?: AuditJsonValue[]
  limitations?: AuditJsonValue[]
  artifactRefs?: string[]
}

export interface AuditAttackPathDataflowV3 {
  summary?: string
  source?: string
  transformations?: AuditJsonValue[]
  sink?: string
  outcome?: string
  evidenceRefs?: string[]
}

export interface AuditAttackPathReachabilityV3 {
  summary?: string
  attacker?: string
  entrypoint?: string
  accessRequirements?: AuditJsonValue[]
  preconditions?: AuditJsonValue[]
  outcome?: string
}

export interface AuditAttackPathImpactV3 {
  level: AuditSeverity
  why?: string
}

export interface AuditAttackPathLikelihoodV3 {
  level: AuditConfidence
  why?: string
}

export interface AuditFindingAttackPathV3 {
  summary?: string
  dataflow?: AuditAttackPathDataflowV3
  reachability?: AuditAttackPathReachabilityV3
  impact?: AuditAttackPathImpactV3
  likelihood?: AuditAttackPathLikelihoodV3
  evidenceRefs?: string[]
  limitations?: AuditJsonValue[]
}

export interface AuditExternalArtifactRefV3 {
  kind: 'external'
  sourceArtifactPath: string
  integrityKind: 'producer-manifest' | 'adapter-bundle'
  sha256: string
  mediaType: string
  retainedInAtlas: boolean
}

export interface AtlasSecurityFindingV3 {
  findingId: AtlasFindingId
  occurrenceId: AtlasOccurrenceId
  decisionLedger: string
  ruleId: string
  identity: AuditFindingIdentityV3
  fingerprints: AuditFindingFingerprintV3[]
  title: string
  summary: string
  severity: AuditFindingSeverityV3
  confidence?: AuditFindingConfidenceV3
  taxonomy: AuditFindingTaxonomyV3
  locations: AuditFindingLocationV3[]
  codeEvidence?: AuditCodeEvidenceV3[]
  rootCause?: string | AuditFindingRootCauseV3
  remediation: string
  validation?: AuditFindingValidationV3 | null
  attackPath?: AuditFindingAttackPathV3 | null
  remediationTests?: AuditJsonValue[]
  preventiveControls?: AuditJsonValue[]
  provenance: AuditFindingProvenanceV3
  artifactRefs?: AuditExternalArtifactRefV3[]
  extensions?: AuditExtensionV3[]
}

export interface AtlasSecurityObservationV3 {
  observationId: AtlasObservationId
  observedAt: string
  reviewState: 'complete'
  producer: AuditProducerReceiptV3
  target: AuditTargetReceiptV3
  scope: AuditScopeV3
  exactCoverage: AuditExactCoverageV3
  semanticCoverage: AuditSemanticCoverageV3
  threatModel?: AuditThreatModelV3
  findings: AtlasSecurityFindingV3[]
  evidenceRefs: string[]
  sourceArtifacts: AuditSourceArtifactV3[]
  producerExtensions: AuditExtensionV3[]
}

export interface AuditObservationHistoryReferenceV3 {
  path: string
  observationId: AtlasObservationId
  entryDigest: AuditSha256
}

export interface AtlasSecurityCurrentLedgerV3 {
  formatVersion: 3
  format: 'atlas-audit-v3'
  domain: 'security'
  slug: string
  title: string
  conceptSlug?: string
  current: AtlasSecurityObservationV3
  currentDigest: AuditSha256
  history: AuditObservationHistoryReferenceV3
}

export interface AuditObservationHistoryEntryV3 {
  observationId: AtlasObservationId
  observationDigest: AuditSha256
  previousEntryDigest: AuditSha256 | null
  observation: AtlasSecurityObservationV3
  entryDigest: AuditSha256
}

export interface AuditObservationHistoryV3 {
  formatVersion: 1
  format: 'atlas-audit-history-v1'
  domain: 'security'
  slug: string
  entries: AuditObservationHistoryEntryV3[]
}

export interface AuditObservationLoadResult {
  observations: AtlasSecurityCurrentLedgerV3[]
  historyAhead: string[]
  diagnostics: AuditDiagnostic[]
}

export interface AuditObservationHistoryLoadResult {
  histories: AuditObservationHistoryV3[]
  diagnostics: AuditDiagnostic[]
}

export interface PreparedAuditObservationPublication {
  ledger: AtlasSecurityCurrentLedgerV3
  historyEntry: AuditObservationHistoryEntryV3
  currentBytes: string
  historyBytes: string
}

export interface AuditObservationPublicationResult {
  currentPath: string
  historyPath: string
  appendedObservationId: string
  status: 'appended' | 'resumed' | 'already-current'
}

export interface AuditDiagnostic {
  code: string
  path: string
  message: string
}

export type AuditParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; diagnostics: AuditDiagnostic[] }
