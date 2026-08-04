import {
  canonicalJson,
  readBoundedAuditJson,
} from './audit-core.js'
import fs from 'node:fs'
import path from 'node:path'
import {
  loadAuditReviewPolicy,
  readAuditTrackedInventory,
  classifyAuditInventory,
} from './audit-policy.js'
import type {
  AuditProviderFileOutcome,
  AuditProviderResult,
  AuditProviderTarget,
} from './audit-providers.js'
import {
  computeAtlasFindingId,
  computeAtlasFingerprint,
  computeAtlasObservationId,
  computeAtlasOccurrenceId,
  computeAuditInventoryDigest,
  computeAuditScopeHash,
  computeExactScopeIdentityDigest,
  prepareAuditObservationPublication,
  publishAuditObservation,
} from './audit-v3.js'
import type {
  AtlasSecurityObservationV3,
  AuditExactInventoryScopeV3,
  AuditFileReceiptV3,
  AuditSha256,
} from './audit-v3-types.js'
import { updateAuditCoverage } from './audit-coverage-generator.js'
import { git, headCommitFull } from './scan.js'
import { GROK_SUPPORTED_CLI_VERSION } from './audit-provider-grok.js'

// Terminal publication seam for first-party provider runs.
//
// A completed `audit run security` invocation proves its evidence in the
// clone-local journal; this module is the terminal step of the run pipeline
// (history -> current -> coverage): it turns the validated synthesis output
// into per-unit V3 observations under the same locked, history-first,
// byte-idempotent publication discipline as every other producer (see
// prepareAuditObservationPublication/publishAuditObservation). Raw
// transcripts and run receipts stay clone-local under
// .atlas/.runtime/audit-runs; only their digests enter the published
// producer receipt.

const REPOSITORY_ID_RE = /^repo_[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/u
const CONFIG_BYTE_LIMIT = 1024 * 1024

export interface AuditRunPublicationOptions {
  result: AuditProviderResult
  targets: readonly AuditProviderTarget[]
}

export interface AuditRunPublicationUnit {
  slug: string
  observationId: string
  status: 'appended' | 'resumed' | 'already-current'
  currentPath: string
  historyPath: string
  findings: number
}

export interface AuditRunPublication {
  units: AuditRunPublicationUnit[]
  coverage: { current: boolean; wrote: boolean }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  )
}

function loadRepositoryId(root: string): string {
  const config = readBoundedAuditJson(root, '.atlas/config.json', CONFIG_BYTE_LIMIT)
  if (
    !isPlainObject(config) ||
    typeof config.repositoryId !== 'string' ||
    !REPOSITORY_ID_RE.test(config.repositoryId)
  ) {
    throw new Error('.atlas/config.json does not declare a stable repo_ identity')
  }
  return config.repositoryId
}

function worktreeDirty(root: string, revision: string | null): boolean {
  const differs = (args: string[]): boolean => {
    try {
      git(root, args)
      return false
    } catch {
      return true
    }
  }
  if (differs(['diff', '--quiet'])) return true
  return revision !== null && differs(['diff', '--cached', '--quiet'])
}

// The V3 validator re-reads every receipt blob's bytes from the Git object
// store, but a dirty-worktree run audits bytes that exist only in the
// worktree. Publication registers them with `git hash-object -w` —
// content-addressed and idempotent — after proving the worktree bytes are
// still exactly what the run audited; drift fails closed before any
// publication is attempted. Committing the files later recreates the same
// objects permanently, since blob identity is content-derived.
function ensureReceiptBlobsAvailable(
  root: string,
  files: readonly AuditProviderFileOutcome[],
): void {
  for (const file of files) {
    const match = /^git-(?:sha1|sha256):([0-9a-f]+)$/.exec(file.blob)
    if (match === null) {
      throw new Error(`run output file has a malformed blob identity: ${file.path}`)
    }
    const objectId = match[1]
    let available = true
    try {
      git(root, ['cat-file', '-e', objectId])
    } catch {
      available = false
    }
    if (available) continue
    const bytes = fs.readFileSync(path.join(root, ...file.path.split('/')))
    const written = git(root, ['hash-object', '-w', '--stdin'], bytes.toString('utf8')).trim()
    if (written !== objectId) {
      throw new Error(
        `worktree bytes for ${file.path} drifted since the run: expected ${file.blob}, worktree now hashes to ${written}`,
      )
    }
  }
}

interface UnitContext {
  slug: string
  title: string
  include: readonly string[]
  except: readonly string[]
  files: AuditProviderFileOutcome[]
}

// The run receipt deliberately carries no wall-clock fields, so publication
// timestamps come from the publish clock. Transcript digests carry session
// entropy (fresh sessions get fresh ids, and live transcripts embed them), so
// two fresh but otherwise identical runs never share a transcript digest.
// Neither is identity material: re-publishing an observation that is
// canonically identical apart from observedAt/reviewedAt/transcriptDigest
// adopts the already-published values, making an unchanged re-run a
// byte-identical no-op instead of a conflicting history append. Any other
// difference is genuine divergence and still fails closed.
function stabilizeRunTimestamps(
  root: string,
  slug: string,
  observation: AtlasSecurityObservationV3,
): AtlasSecurityObservationV3 {
  let existing: unknown
  try {
    existing = readBoundedAuditJson(root, `.atlas/audits/${slug}.json`, CONFIG_BYTE_LIMIT)
  } catch {
    return observation
  }
  if (!isPlainObject(existing) || !isPlainObject(existing.current)) return observation
  const current = existing.current
  if (current.observationId !== observation.observationId) return observation
  const strip = (value: unknown): unknown => {
    const clone = JSON.parse(JSON.stringify(value)) as Record<string, unknown>
    clone.observedAt = ''
    if (isPlainObject(clone.producer)) delete clone.producer.transcriptDigest
    const scope = clone.scope
    if (isPlainObject(scope) && Array.isArray(scope.files)) {
      for (const file of scope.files) {
        if (isPlainObject(file)) delete file.reviewedAt
      }
    }
    return clone
  }
  if (
    canonicalJson(strip(current)) !== canonicalJson(strip(observation))
  ) {
    return observation
  }
  const priorReviewedAt = new Map<string, string>()
  if (isPlainObject(current.scope) && Array.isArray(current.scope.files)) {
    for (const file of current.scope.files) {
      if (isPlainObject(file) && typeof file.path === 'string' && typeof file.reviewedAt === 'string') {
        priorReviewedAt.set(file.path, file.reviewedAt)
      }
    }
  }
  if (typeof current.observedAt !== 'string') return observation
  observation.observedAt = current.observedAt
  const exactScope = observation.scope as AuditExactInventoryScopeV3
  for (const file of exactScope.files) {
    const prior = priorReviewedAt.get(file.path)
    if (prior !== undefined) file.reviewedAt = prior
  }
  if (
    isPlainObject(current.producer) &&
    typeof current.producer.transcriptDigest === 'string' &&
    isPlainObject(observation.producer)
  ) {
    observation.producer.transcriptDigest = current.producer.transcriptDigest as AuditSha256
  }
  return observation
}

export function publishAuditProviderRunObservations(
  root: string,
  options: AuditRunPublicationOptions,
): AuditRunPublication {
  const { result, targets } = options
  const receipt = result.receipt

  const repositoryId = loadRepositoryId(root)
  const policyLoad = loadAuditReviewPolicy(root)
  if (policyLoad.policy === null) {
    throw new Error(
      'audit run security cannot publish without a valid .atlas/review-policy.json: ' +
      policyLoad.diagnostics.map((diagnostic) => diagnostic.message).join('; '),
    )
  }
  const reviewPolicy = policyLoad.policy
  const inventory = readAuditTrackedInventory(root)
  if (inventory.diagnostics.length > 0) {
    throw new Error(
      'audit run security cannot publish against an unreadable tracked inventory: ' +
      inventory.diagnostics.map((diagnostic) => diagnostic.message).join('; '),
    )
  }
  const classification = classifyAuditInventory(inventory.files, reviewPolicy)
  if (classification.diagnostics.length > 0) {
    throw new Error(
      'audit run security cannot publish against an ambiguous policy classification: ' +
      classification.diagnostics.map((diagnostic) => diagnostic.message).join('; '),
    )
  }

  const unitByPath = new Map<string, string>()
  // Only files a run could actually read count as owned by a unit: a deleted
  // path, or one with no current blob, is not reviewable and never appears in a
  // run's output. Mixing them in would make the completeness check below reject
  // every legitimate run.
  const reviewableUnitFiles = new Map<string, string>()
  for (const file of classification.files) {
    const slug =
      file.classification.kind === 'review'
        ? file.classification.domains.security?.unit
        : undefined
    if (slug === undefined) continue
    unitByPath.set(file.path, slug)
    if (!file.deleted && file.currentBlob !== null) {
      reviewableUnitFiles.set(file.path, slug)
    }
  }
  const filesByUnit = new Map<string, AuditProviderFileOutcome[]>()
  for (const file of result.files) {
    const slug = unitByPath.get(file.path)
    if (slug === undefined) {
      throw new Error(`run output file is not owned by a security unit: ${file.path}`)
    }
    const group = filesByUnit.get(slug) ?? []
    group.push(file)
    filesByUnit.set(slug, group)
  }

  // A published observation becomes the unit's whole `current`, and freshness is
  // read from `current` alone — so publishing a subset of a unit deletes the
  // evidence for every file left out. That is silent: coverage simply reports
  // those files as missing again. Refuse instead, and name the selection that
  // covers a unit completely.
  for (const [slug, reviewed] of filesByUnit) {
    const owned = [...reviewableUnitFiles.entries()]
      .filter(([, unitSlug]) => unitSlug === slug)
      .map(([repoPath]) => repoPath)
    const seen = new Set(reviewed.map((file) => file.path))
    const uncovered = owned.filter((repoPath) => !seen.has(repoPath)).sort()
    if (uncovered.length > 0) {
      throw new Error(
        `audit run security cannot publish a partial scope for ${slug}: ` +
        `${uncovered.length} file(s) owned by the unit were not reviewed, and ` +
        'publishing would drop their standing receipts — rerun with ' +
        `\`repo-atlas audit run security --provider grok --unit ${slug}\` ` +
        `(first uncovered: ${uncovered.slice(0, 3).join(', ')})`,
      )
    }
  }

  const revision = headCommitFull(root)
  const dirty = worktreeDirty(root, revision)
  const observedAt = new Date().toISOString()

  const reviewTargets = targets.filter((target) => target.role === 'review')
  for (const file of result.files) {
    if (!reviewTargets.some((target) => target.path === file.path)) {
      throw new Error(`run output file was not a review target: ${file.path}`)
    }
  }
  // Which chunk actually produced each receipt, taken from the run rather than
  // guessed from a path's position. Batch membership is chosen by the placement
  // heuristic, and a run that carried receipts forward batches only the files it
  // re-reviewed — a positional formula names a batch that never held the file.
  const carriedByPath = new Map(
    result.carriedReceipts.map((carried) => [carried.path, carried]),
  )
  const reviewUnitOf = (repoPath: string): string => {
    const unit = result.reviewUnitByPath[repoPath]
    if (unit === undefined) {
      throw new Error(
        `run output file ${repoPath} names no review chunk and carries no prior receipt`,
      )
    }
    return unit
  }
  const verificationUnitOf = (fingerprint: string): string | undefined =>
    result.verificationUnitByFingerprint[fingerprint]

  const buildObservation = (unit: UnitContext): AtlasSecurityObservationV3 => {
    const reportable = result.findings.filter(
      (finding) =>
        finding.disposition === 'reportable' &&
        unit.files.some((file) => file.path === finding.path),
    )
    const scopeIdentityDigest = computeExactScopeIdentityDigest({
      mode: 'unit',
      includePaths: unit.include,
      excludePaths: unit.except,
      files: unit.files.map((file) => ({ path: file.path, blob: file.blob })),
    })
    const targetId = `grok-worktree/${unit.slug}`
    const observationId = computeAtlasObservationId({
      slug: unit.slug,
      adapter: receipt.adapter,
      runId: result.invocationId,
      producerIdentityDigest: receipt.ruleset.digest,
      targetId,
      targetIdentityDigest: receipt.snapshotManifestDigest,
      scopeIdentityDigest,
    })

    const findings = reportable
      .map((finding) => {
        const atlas = computeAtlasFingerprint({
          repositoryId,
          domain: 'security',
          ruleId: finding.ruleId,
          anchor: finding.fingerprint,
        })
        return {
          findingId: computeAtlasFindingId(atlas),
          occurrenceId: computeAtlasOccurrenceId(observationId, atlas),
          decisionLedger: unit.slug,
          ruleId: finding.ruleId,
          identity: { anchor: finding.fingerprint },
          fingerprints: [
            { scheme: 'atlas/v1', value: atlas, role: 'canonical' as const },
            { scheme: 'grok-cli/v1', value: finding.fingerprint, role: 'producer' as const },
          ],
          title: finding.title,
          summary: finding.summary,
          severity: { level: finding.severity },
          confidence: { level: finding.confidence },
          taxonomy: { category: finding.ruleId.split('/')[0] ?? finding.ruleId },
          locations: [
            {
              path: finding.path,
              startLine: finding.startLine,
              ...(finding.endLine !== undefined ? { endLine: finding.endLine } : {}),
            },
          ],
          remediation: finding.fix,
          validation: {
            method: 'independent-verification',
            disposition: finding.disposition,
            summary: finding.dispositionRationale,
          },
          attackPath: { summary: finding.detail },
          provenance: { source: receipt.adapter, candidateId: finding.fingerprint },
        }
      })
      .sort((left, right) => left.findingId.localeCompare(right.findingId))
    const occurrenceIdsByPath = new Map<string, string[]>()
    for (const finding of findings) {
      const rows = occurrenceIdsByPath.get(finding.locations[0]!.path) ?? []
      rows.push(finding.occurrenceId)
      occurrenceIdsByPath.set(finding.locations[0]!.path, rows)
    }

    // Publication requires strictly increasing UTF-16 path order, and the
    // provider's output arrives in unit-completion order — which is whatever the
    // concurrent pool finished first, not path order. Nothing sorted it, so the
    // first run ever to reach publication failed on it: four units published,
    // the fifth had one file out of order at index 122 and aborted mid-publish.
    const orderedUnitFiles = [...unit.files].sort((left, right) =>
      left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
    )
    const files: AuditFileReceiptV3[] = orderedUnitFiles.map((file) => {
      const occurrenceIds = [...(occurrenceIdsByPath.get(file.path) ?? [])].sort()
      const carried = carriedByPath.get(file.path)
      if (carried !== undefined) {
        // A carried receipt keeps the provenance of the review that actually
        // happened: its own timestamp, reviewer and ruleset, none of which this
        // run re-earned. Stamping `observedAt` here would refresh evidence
        // nothing re-read.
        //
        // `carried-from:<observationId>` is what tells a reader this receipt was
        // not proven by this run, and where its proof lives. It is omitted in
        // exactly one case: when this observation IS that observation (identical
        // snapshot, identical producer identity, so the same observation id), the
        // reference would point at itself and the prior receipt refs still hold.
        //
        // The outcome is restated from the receipt, not re-derived from the
        // occurrences published here: if those two ever disagreed, re-deriving
        // would quietly downgrade a findings-bearing carried file to clean.
        if ((occurrenceIds.length > 0) !== (carried.outcome === 'findings')) {
          throw new Error(
            `carried receipt for ${file.path} says ${carried.outcome} but this observation ` +
            `publishes ${String(occurrenceIds.length)} occurrence(s) for it`,
          )
        }
        const selfCarried = carried.observationId === observationId
        return {
          path: file.path,
          blob: file.blob,
          lines: file.lines,
          status: 'reviewed',
          outcome: carried.outcome,
          ...(carried.reviewedAt !== undefined
            ? {
                reviewedAt: carried.reviewedAt,
                reviewedAtPrecision: carried.reviewedAtPrecision ?? 'timestamp',
              }
            : {}),
          ...(carried.reviewedBy !== undefined ? { reviewedBy: carried.reviewedBy } : {}),
          ...(carried.ruleset !== undefined ? { ruleset: carried.ruleset } : {}),
          findingOccurrenceIds: occurrenceIds,
          receiptRefs: selfCarried
            ? [...carried.receiptRefs].sort()
            : [`carried-from:${carried.observationId}`],
        }
      }
      const receiptRefs = new Set<string>([`phase:review:${reviewUnitOf(file.path)}`])
      for (const finding of reportable) {
        if (finding.path !== file.path) continue
        const verificationUnit = verificationUnitOf(finding.fingerprint)
        if (verificationUnit !== undefined) {
          receiptRefs.add(`phase:verification:${verificationUnit}`)
        }
      }
      return {
        path: file.path,
        blob: file.blob,
        lines: file.lines,
        status: 'reviewed',
        // A V3 outcome binds reportable occurrences, not the discovery-stage
        // receipt: a candidate whose terminal disposition is not reportable
        // leaves the file clean.
        outcome: occurrenceIds.length > 0 ? 'findings' : 'clean',
        reviewedAt: observedAt,
        reviewedAtPrecision: 'timestamp',
        reviewedBy: `${receipt.model} via grok-cli`,
        ruleset: receipt.ruleset.id,
        findingOccurrenceIds: occurrenceIds,
        receiptRefs: [...receiptRefs].sort(),
      }
    })
    const inventoryDigest = computeAuditInventoryDigest(files)

    return {
      observationId,
      observedAt,
      reviewState: 'complete',
      producer: {
        kind: 'grok-cli',
        name: 'grok',
        version: GROK_SUPPORTED_CLI_VERSION,
        adapter: receipt.adapter,
        adapterVersion: receipt.adapterVersion,
        runId: result.invocationId,
        identityDigest: receipt.ruleset.digest,
        identityBasis: 'ruleset',
        ruleset: receipt.ruleset,
        prompt: receipt.prompt,
        effectiveConfigDigest: receipt.effectiveConfigDigest,
        environmentPolicyDigest: receipt.environmentPolicyDigest,
        transcriptDigest: receipt.transcriptDigest,
      },
      target: dirty
        ? {
            kind: 'git-worktree' as const,
            repositoryId,
            targetId,
            identityDigest: receipt.snapshotManifestDigest,
            identityBasis: 'snapshot' as const,
            snapshotDigest: receipt.snapshotManifestDigest,
            ...(revision !== null ? { revision } : {}),
            dirty: true as const,
          }
        : {
            kind: 'git-worktree' as const,
            repositoryId,
            targetId,
            identityDigest: receipt.snapshotManifestDigest,
            identityBasis: 'snapshot' as const,
            snapshotDigest: receipt.snapshotManifestDigest,
            revision:
              revision ??
              (() => {
                throw new Error('a clean worktree run requires a HEAD revision')
              })(),
            dirty: false as const,
          },
      scope: {
        mode: 'unit',
        identityDigest: scopeIdentityDigest,
        identityBasis: 'exact-inventory',
        includePaths: [...unit.include],
        excludePaths: [...unit.except],
        scopeHash: computeAuditScopeHash({
          mode: 'unit',
          includePaths: unit.include,
          excludePaths: unit.except,
          inventoryDigest,
        }),
        inventoryDigest,
        fileCount: files.length,
        files,
        artifactsReviewed: [],
        limitations: [],
      },
      exactCoverage: {
        completeness: 'complete',
        basis: 'full-read-receipts',
        reviewedFileCount: files.length,
        unreviewed: [],
      },
      semanticCoverage: {
        mode: 'unit',
        completeness: 'unknown',
        inventoryStrategy: 'unit',
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      },
      findings,
      evidenceRefs: [],
      sourceArtifacts: [],
      producerExtensions: [],
    }
  }

  const publications: AuditRunPublicationUnit[] = []
  const sortedUnits = [...filesByUnit.entries()].sort((left, right) =>
    left[0].localeCompare(right[0]),
  )
  ensureReceiptBlobsAvailable(root, result.files)
  for (const [slug, files] of sortedUnits) {
    const unit = reviewPolicy.units.find(
      (candidate) => candidate.domain === 'security' && candidate.slug === slug,
    )
    if (unit === undefined) {
      throw new Error(`run output unit is missing from the review policy: ${slug}`)
    }
    const sortedFiles = [...files].sort((left, right) => left.path.localeCompare(right.path))
    const observation = buildObservation({
      slug,
      title: unit.title,
      include: unit.include,
      except: unit.except,
      files: sortedFiles,
    })
    const prepared = prepareAuditObservationPublication(
      root,
      stabilizeRunTimestamps(root, slug, observation),
      { slug, title: unit.title, conceptSlug: 'security' },
    )
    const publication = publishAuditObservation(root, prepared.ledger)
    publications.push({
      slug,
      observationId: prepared.ledger.current.observationId,
      status: publication.status,
      currentPath: publication.currentPath,
      historyPath: publication.historyPath,
      findings: prepared.ledger.current.findings.length,
    })
  }

  const coverage = updateAuditCoverage(root, { allowIncomplete: true })
  return {
    units: publications,
    coverage: { current: coverage.current, wrote: coverage.wrote },
  }
}
