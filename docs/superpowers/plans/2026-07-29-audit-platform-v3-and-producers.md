# Repo Atlas Audit Platform V3 and Producers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every behavior change follows RED-GREEN-REFACTOR; do not write production code before the named failing test exists and has been observed failing.

**Goal:** Turn Repo Atlas into the owner of a closed-world, exact-byte audit platform whose V3 model preserves Atlas V2, RelayOS legacy security evidence, and Codex Security 1.0 semantics; add deterministic policy/coverage, decisions, history, migration, Codex import, and an explicitly invoked isolated Grok producer.

**Architecture:** Keep V1/V2 as compatibility readers and make V3 the only current write format. New small modules own canonical JSON and identifiers, strict V3 parsing, current/history storage, append-only decisions and reconciliation, review-policy classification, deterministic coverage generation, import/migration adapters, and producer orchestration. `src/audits.ts` projects verified V3 observations into the existing viewer portfolio while richer V3 state is exposed directly. `src/cli.ts` delegates the hierarchical `audit ...` surface to `src/audit-cli.ts`. All repository reads and writes reject symlink escapes and all state-changing commands use an audit lock plus atomic replacement.

**Tech Stack:** TypeScript 5.8, Node.js 20+, Node test runner, Git blob IDs, SHA-256/SHA-1, picomatch 4, JSON, child-process adapters for Git and Grok.

**Normative design:** `docs/superpowers/specs/2026-07-29-audit-platform-v3-and-producers-design.md`

---

## File structure

- `src/audit-core.ts` — canonical JSON, validated repository paths, bounded JSON reads, deterministic IDs, atomic writes, and audit lock.
- `src/audit-v3-types.ts` — V3 observation/finding/receipt/history/decision/policy/provider types.
- `src/audit-v3.ts` — strict V3 parser, current/history loading, observation publication, V1/V2 compatibility projection.
- `src/audit-decisions.ts` — append-only decision, retirement, reconciliation, effective-state reduction, guardrail expiry/regression checks.
- `src/audit-policy.ts` — strict generic review-policy/provider-policy parsing, tracked inventory, classification, unit assignment.
- `src/audit-coverage-generator.ts` — exact-byte and semantic coverage join, deterministic report generation, enforcement, and update.
- `src/audit-import-codex.ts` — sealed offline Codex Security bundle importer.
- `src/audit-migrate-relayos.ts` — deterministic RelayOS legacy migration and receipt generation.
- `src/audit-providers.ts` — provider interface, phase graph, snapshot manifest, transcript verification, and resume state.
- `src/audit-provider-grok.ts` — explicit isolated Grok CLI adapter.
- `src/audit-cli.ts` — hierarchical audit command parser and exit-code policy.
- `src/types.ts`, `src/audits.ts`, `src/build.ts`, `src/serve.ts`, `src/cli.ts` — compatibility and product integration.
- `viewer/Security.tsx`, `viewer/AuditCoverage.tsx`, `viewer/AuditNav.tsx` — V3 finding/decision/coverage presentation.
- `test/audit-core.test.mjs` — path, size, ID, lock, and atomic-write tests.
- `test/audit-v3.test.mjs` — schema, compatibility, publication, and history tests.
- `test/audit-decisions.test.mjs` — append-only lifecycle and policy tests.
- `test/audit-policy-generator.test.mjs` — closed-world classification and deterministic coverage tests.
- `test/audit-import-codex.test.mjs` — Codex adapter fixtures and fail-closed inputs.
- `test/audit-migrate-relayos.test.mjs` — legacy ledger/candidate/disposition migration fixtures.
- `test/audit-provider-grok.test.mjs` — fake Grok executable, isolation, transcript, and resume tests.
- `test/audit-cli.test.mjs` — command/exit-code/wiring tests.
- `test/fixtures/codex-security/*` — sealed adapter fixtures.
- `test/fixtures/relayos-security/*` — minimal deterministic legacy fixtures.
- `README.md`, `package.json` — public workflow and reproducible Git-package build.

### Task 1: Add audit core safety and deterministic identity primitives

**Files:**
- Create: `src/audit-core.ts`
- Create: `test/audit-core.test.mjs`
- Modify: `package.json`

- [ ] **Step 1: Write the failing safety/identity tests**

Add tests for normalized repository paths, bounded UTF-8 JSON, canonical key
ordering, deterministic IDs, safe directory creation, atomic replacement, and
lock contention. Include hostile duplicate-key/depth/member/string JSON,
aggregate canonical/ID limits, redirected `GIT_*` environment,
parent-directory swap injection, durability failures, and asynchronous lock
settlement. The core fixture assertions are:

```js
assert.equal(normalizeAuditRepoPath('src/a.ts'), 'src/a.ts')
assert.throws(() => normalizeAuditRepoPath('../outside'), /normalized repository-relative/)
assert.throws(() => normalizeAuditRepoPath('src\\a.ts'), /normalized repository-relative/)
assert.equal(canonicalJson({ z: 1, a: { d: 2, b: 1 } }),
  '{"a":{"b":1,"d":2},"z":1}')
assert.equal(stableAuditId('aobs', 'atlas-observation/v1',
  ['repo', 'security', 'unit', 'blob']).length, 29)
assert.equal(
  stableAuditId('aobs', 'atlas-observation/v1', ['repo', 'security', 'unit', 'blob']),
  stableAuditId('aobs', 'atlas-observation/v1', ['repo', 'security', 'unit', 'blob']),
)
```

Use a symlinked `.atlas/audits` fixture and assert both reads and writes fail
without touching the outside canary. Acquire the same lock twice and assert
the second acquisition reports the live lock rather than overwriting it. Assert
the lock is in worktree-specific Git administrative state outside tracked
`.atlas` and that no `.atlas/.audit.lock` is created.

- [ ] **Step 2: Run the focused test and verify RED**

```bash
pnpm build:cli && node --test test/audit-core.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `dist/audit-core.js`.

- [ ] **Step 3: Implement the primitives**

Export this public surface:

```ts
export const AUDIT_LIMITS = {
  jsonBytes: 32 * 1024 * 1024,
  collectionItems: 1_000_000,
  textCodeUnits: 256 * 1024,
  textTotalCodeUnits: 8 * 1024 * 1024,
} as const

export function normalizeAuditRepoPath(value: string): string
export function readBoundedAuditBytes(root: string, repoPath: string, maxBytes?: number): Uint8Array
export function readBoundedAuditJsonDocument(
  root: string,
  repoPath: string,
  maxBytes?: number,
): { bytes: Uint8Array; value: unknown }
export function readBoundedAuditJson(root: string, repoPath: string, maxBytes?: number): unknown
export function canonicalJson(value: unknown): string
export function stableAuditId(
  prefix: 'aobs' | 'atocc' | 'adev' | 'amig',
  domainTag: string,
  parts: readonly string[],
): string
export function atomicWriteAuditFile(root: string, repoPath: string, contents: string): void
export function withAuditLock<T>(root: string, operation: () => T): T
```

`stableAuditId` is
`${prefix}_${first24(sha256(domainTag + NUL + parts.join(NUL)))}`. Callers use
the exact domain tags and ordered identity members in the normative spec;
repository IDs are committed producer-neutral `repo_...` values rather than
being synthesized by this helper. `canonicalJson` is the compact RFC 8785
digest form: it recursively sorts object keys, preserves array order, rejects
invalid Unicode, non-finite numbers, undefined, cycles, and unsupported
values, and has no presentation whitespace or trailing newline. Stored JSON
documents append exactly one newline after canonicalization. The lock lives
outside tracked `.atlas` in
worktree-specific Git administrative state, keyed by real worktree path. It
contains PID, host, process start time, command, and source snapshot, uses
`wx`, and is always released in `finally`; a stale lock is never silently
stolen without explicit liveness-checked recovery. Atomic replacement fsyncs
the temporary file and best-effort fsyncs the containing directory after
rename.

The raw bounded reader returns the exact safely opened bytes, including binary
or invalid UTF-8, so sealed producer artifacts can be hashed without
canonicalizing or reopening a pathname. `readBoundedAuditJsonDocument` returns
those same one-read bytes plus the value parsed from them; an importer hashes
the returned bytes and maps the returned value, never reopening the document.
The convenience JSON reader only projects `.value`. All three share one
descriptor-anchored implementation. JSON decoding is fatal UTF-8 and uses a
bounded grammar parser rather than calling `JSON.parse` before
depth/member/duplicate-key checks. Integer-valued JSON numbers outside
JavaScript's safe-integer range are rejected instead of silently rounded;
finite non-integer IEEE-754 values retain RFC 8785 semantics. Readers retain
the root, parent, and file identities through the whole read and aggregate
primary plus descriptor
cleanup failures. Git discovery removes environment variables that can
redirect repository administration and verifies the requested real top level.
Async operations retain the state lock until their thenable settles. Directory
fsync suppresses only known unsupported platform errors; real I/O failures
propagate. The generic NUL-domain helper does not claim the direct
`atf_ = sha256(fingerprint)` formula—Task 2 supplies formula-specific helpers
and golden vectors.

Safe file operations and the Git-admin lock retain verified root/parent
descriptors for their whole transaction; no exported API returns a bare
pathname described as safe for later I/O. Reader and lock cleanup use the same
aggregate-error discipline as atomic writes. The supported security backend is
Linux `/proc/self/fd`; missing capability fails before any mutation. Tests cover
root replacement, Git-lock parent replacement, linked-worktree isolation,
bounded nonblocking lock reads, post-create `fstat` failure, cleanup/release
errors, and ignored-versus-real directory-fsync failures.

The threat contract does not claim confinement if a malicious
same-credential process relocates the already-open parent inode outside the
repository during the final rename. That relocation is detected and reported,
but may move the atomically replaced owned inode; replacement symlinks or
different outside inodes must remain untouched.

- [ ] **Step 4: Verify GREEN and package reproducibility**

Add `"prepack": "pnpm build"` so a Git dependency pinned by full commit builds `dist` before packing.

```bash
pnpm build:cli
node --test test/audit-core.test.mjs
pnpm pack --pack-destination "$(mktemp -d)"
```

Expected: all tests PASS and the tarball contains `dist/cli.js`.

- [ ] **Step 5: Commit Task 1**

```bash
git add package.json src/audit-core.ts test/audit-core.test.mjs
git commit -m "feat(audit): add safe deterministic storage primitives"
```

### Task 2: Define and strictly load the V3 observation model

**Files:**
- Create: `src/audit-v3-types.ts`
- Create: `src/audit-v3.ts`
- Create: `test/audit-v3.test.mjs`
- Modify: `src/types.ts`
- Modify: `src/audits.ts`

- [ ] **Step 1: Write failing V3 contract and compatibility tests**

Create a one-file Git fixture and build a valid V3 **current ledger wrapper**
whose `current` member is an `AtlasSecurityObservation`. Production helpers
may assemble the fixture, but independent literal golden vectors must lock
every normative identity formula so a uniformly wrong helper cannot make the
test pass. Use this exact structural split:

```js
const repositoryId = 'repo_fixture'
const blob = `git-sha1:${gitBlob(root, 'src/a.ts')}`
const findingId = atlasFindingId(repositoryId, 'security', ruleId, anchor, instance)
const observationId = atlasObservationId({
  slug: 'security-runtime',
  adapter: 'repo-atlas/migration-v1',
  runId: 'fixture-run',
  producerIdentityDigest: rulesetDigest,
  targetId: 'fixture-target',
  targetIdentityDigest: snapshotDigest,
  scopeIdentityDigest,
})
const occurrenceId = atlasOccurrenceId(observationId, atlasFingerprint)
const current = {
  observationId,
  observedAt: '2026-07-29T12:34:56.000Z',
  reviewState: 'complete',
  producer: {
    kind: 'migration',
    name: 'relayos-security-scan',
    version: '1',
    adapter: 'repo-atlas/migration-v1',
    adapterVersion: '0.1.0',
    runId: 'fixture-run',
    identityDigest: rulesetDigest,
    identityBasis: 'ruleset',
    ruleset: { id: 'relayos-security-v1', digest: rulesetDigest },
    effectiveConfigDigest,
    environmentPolicyDigest,
  },
  target: {
    kind: 'git-worktree',
    repositoryId,
    targetId: 'fixture-target',
    identityDigest: snapshotDigest,
    identityBasis: 'snapshot',
    revision,
    snapshotDigest,
    dirty: false,
  },
  scope: {
    mode: 'unit',
    identityDigest: scopeIdentityDigest,
    identityBasis: 'exact-inventory',
    includePaths: ['src/**'],
    excludePaths: [],
    scopeHash,
    inventoryDigest,
    fileCount: 1,
    files: [{
      path: 'src/a.ts',
      blob,
      lines: 1,
      status: 'reviewed',
      outcome: 'findings',
      reviewedAt: '2026-07-29T12:34:56.000Z',
      reviewedAtPrecision: 'timestamp',
      reviewedBy: 'fixture migrator',
      ruleset: 'relayos-security-v1',
      findingOccurrenceIds: [occurrenceId],
      receiptRefs: ['migration:fixture'],
    }],
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
  findings: [validRichFinding({ findingId, occurrenceId, blob })],
  evidenceRefs: [],
  sourceArtifacts: [],
  producerExtensions: [],
}
const history = historyEnvelopeWith(current)
const ledger = {
  formatVersion: 3,
  format: 'atlas-audit-v3',
  domain: 'security',
  slug: 'security-runtime',
  title: 'Runtime',
  current,
  currentDigest: canonicalSha256(current),
  history: {
    path: '.atlas/audit-history/security-runtime.json',
    observationId,
    entryDigest: history.entries.at(-1).entryDigest,
  },
}
```

Assert strict unknown-field rejection at every nested envelope,
path/hash/timestamp validation, duplicate IDs/paths rejection,
occurrence-to-finding/file consistency, bounded nonempty text, line bounds,
snippet size, producer receipt digest, and semantic coverage shape. Add V1/V2
fixtures and assert they still project to the existing
`SecurityAuditUnit`/`TestAuditUnit`.

The RED matrix must additionally cover:

- the complete producer/target/scope/exact-coverage/artifact-integrity
  discriminated unions, including every required/forbidden member pair;
- fixed golden vectors for exact and semantic identities, fingerprint, finding,
  occurrence, observation, inventory, scope, current, and history digests;
- the cycle-breaking invariant: changing exact result receipts changes result
  digests but not scope identity or observation ID; semantic result surfaces
  likewise do not change semantic declaration identity;
- repository identity, filename/slug/history path, timestamp/precision,
  Codex timestamp equality, first-party clean-worktree revision, and the Codex
  source-kind/source-coordinate matrix without an invented dirty or verified
  revision claim;
- upstream-optional versus V3-required member boundaries: severity requires
  only level; locations require path/startLine; code evidence requires its
  common core but not endLine/language/role; root-cause references and
  semantic follow-up prompts remain optional without invented placeholders;
- duplicate and unknown references across files, findings, fingerprints,
  snippets, semantic surfaces, artifacts, and extensions;
- the exact-blob versus sealed-producer-snippet code-evidence union, including
  required/forbidden blob/source-seal members, sealed artifact and JSON-pointer
  cross-references, and proof that producer snippets never create exact
  coverage;
- extension JSON-pointer/namespace/digest/size/depth/member limits and recursive
  data-only JSON values rather than `unknown`;
- complete/partial exact-coverage arithmetic and semantic closure;
- code-evidence blob/line/content and per-snippet/aggregate bounds; and
- independently resealed wrong identities so surrounding digest failures do
  not mask the identity check.

- [ ] **Step 2: Run the focused test and verify RED**

```bash
pnpm build:cli && node --test test/audit-v3.test.mjs
```

Expected: FAIL because the V3 modules do not exist.

- [ ] **Step 3: Implement strict types and parser**

Define the discriminated public contracts from the normative design, including
recursive `AuditJsonValue` and required/forbidden-member unions rather than
interfaces with freely optional fields:

```ts
export type AuditReviewStatus = 'reviewed' | 'not-reviewed'
export type AuditReviewOutcome = 'clean' | 'findings' | 'unknown'
export type AuditProducerKind = 'grok-cli' | 'codex-security' | 'migration' | 'manual'
export type AuditConfidence = 'low' | 'medium' | 'high'

export interface AuditFileReceiptV3 {
  path: string
  blob: `git-sha1:${string}` | `git-sha256:${string}`
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

export interface AtlasSecurityCurrentLedgerV3 {
  formatVersion: 3
  format: 'atlas-audit-v3'
  domain: 'security'
  slug: string
  title: string
  conceptSlug?: string
  current: AtlasSecurityObservationV3
  currentDigest: `sha256:${string}`
  history: { path: string; observationId: string; entryDigest: `sha256:${string}` }
}

export interface AtlasSecurityObservationV3 {
  observationId: string
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
```

Every parser returns `{ ok: true, value } | { ok: false, diagnostics }`; it
never drops malformed entries. V3 current files remain
`.atlas/audits/<slug>.json`; the hash-chain envelope is
`.atlas/audit-history/<slug>.json`; and the stable producer-neutral
`repositoryId` comes from committed Atlas config/identity state.

The discriminated receipt types also include the verified Codex 1.0
amendments in the normative spec: producer/target/scope
`identityDigest`+`identityBasis`, optional producer `sourceContract`,
exact-inventory versus semantic-declaration scope, full-read versus unavailable
exact coverage, source-artifact `integrityKind`, and preserved
`producerSource`. A semantic-only observation has no file/count/blob claims and
cannot project as exact coverage.

For exact scope, `scope.identityDigest` is the pre-result canonical digest of
scope mode, include/exclude patterns, and sorted path/blob input pairs. It
excludes status/outcome/receipt/occurrence results. `inventoryDigest` and
`scopeHash` continue to seal the full result receipts. This prevents the
observation-ID → occurrence-ID → result-scope-digest cycle.

Semantic-declaration scope omits `scopeHash`, `inventoryDigest`, `fileCount`,
and `files`; its identity uses only the documented source declaration inputs.
Codex targets retain canonical Atlas `kind` plus exact `sourceKind`, and
revision-coordinate identity hashes the source spelling. Snapshot-basis target
identity requires and equals `snapshotDigest`.

- [ ] **Step 4: Publish observations without losing history**

Implement:

```ts
export function loadAuditObservations(root: string): AuditObservationLoadResult
export function loadAuditObservationHistory(root: string): AuditObservationHistoryLoadResult
export function prepareAuditObservationPublication(
  root: string,
  observation: AtlasSecurityObservationV3,
  metadata: { slug: string; title?: string; conceptSlug?: string },
): {
  ledger: AtlasSecurityCurrentLedgerV3
  historyEntry: AuditObservationHistoryEntryV3
  currentBytes: string
  historyBytes: string
}
export function publishAuditObservation(root: string, ledger: AtlasSecurityCurrentLedgerV3): {
  currentPath: string
  historyPath: string
  appendedObservationId: string
}
```

Preparation validates the observation and repository bytes, loads and
validates the existing chain, selects the next history head, and derives
canonical history/current bytes without mutation. Every producer uses this
single seam. Publication revalidates that prepared state under the lock,
appends a new hash-chain history entry first, rejects conflicting history
IDs/digests, then atomically switches the current wrapper. The current
observation/digest must equal the latest history entry exactly.

Tests inject a pre-held lock, traversal and symlink targets, history-write and
current-switch failures, same-ID/different-digest conflicts, forked/reordered
chains, entry/embedded-observation mismatches, and unknown history members.
Every rejected publication preserves prior bytes; an interrupted current
switch leaves only the documented resumable history-ahead state and no owned
temporary files.

- [ ] **Step 5: Project V3 into existing portfolios**

Extend `src/audits.ts` so V3 security observations load alongside V1/V2
security/test/design ledgers. Projection keeps rich finding IDs, confidence,
implicit-open disposition, exact files/hashes, evidence refs, and stale status.
Absent Codex ruleset and exact scope project as `null`/empty rather than an
invented label or freshness claim. Mutated exact source bytes become stale,
and V3-looking polyglots or malformed wrappers cannot downgrade to V1/V2.
Existing V1/V2 tests must remain unchanged and pass.

- [ ] **Step 6: Verify and commit**

```bash
pnpm build:cli
node --test test/audit-v3.test.mjs test/audits.test.mjs test/review-coverage.test.mjs
git add src/audit-v3-types.ts src/audit-v3.ts src/types.ts src/audits.ts test/audit-v3.test.mjs
git commit -m "feat(audit): add strict V3 observations and history"
```

### Task 3: Add append-only decisions, retirement, and reconciliation

**Files:**
- Create: `src/audit-decisions.ts`
- Create: `test/audit-decisions.test.mjs`
- Modify: `src/audit-v3-types.ts`

- [ ] **Step 1: Write failing lifecycle tests**

Cover implicit open state, remediated, accepted-risk, separate-design, false-positive, superseded, reopened, deleted, moved, staged deletion, uncommitted-snapshot-absent, and reconciliation. The reducer assertion is:

```js
const index = buildAuditDecisionIndex(histories, decisionLedgers)
const state = reduceAuditDecisionState(index, policy, now)
assert.deepEqual(state.findings.get(findingId), {
  disposition: 'accepted-risk',
  blocking: false,
  eventId: accepted.eventId,
  expiresAt: '2026-08-28T00:00:00.000Z',
})
```

Add table-driven RED fixtures for:

- exact closed unions for every finding action, retirement reason, temporal
  reconciliation, identity-alias reconciliation, proof, review, regression,
  and action-evidence variant;
- independent literal `eventId` and `entryDigest` golden vectors;
- tampered, forked, reordered, duplicate, and colliding chains, while a
  deterministic migration chain with nonmonotonic `createdAt` remains valid;
- a global history index containing historical-only findings/occurrences,
  stable single-ledger ownership, and unknown/mismatched path/blob/ruleset
  references;
- implicit open plus every action, automatic reopen/carry rules, earlier-only
  compatible supersession, and same-ID deterministic append idempotence;
- exact expiry/warning/30-day/90-day boundaries relative to event `createdAt`,
  two distinct evidence-bearing approve reviews independent from actor/owner,
  and reject/duplicate reviewers that do not count;
- revision/blob-bound passing remediation regressions, source evidence,
  replacement/deletion/no-replacement proof, and stale guardrail evidence;
- every retirement branch, staged-to-deleted supersession, moved successor
  blob equality, and date-only precision preservation; and
- one-to-many/many-to-one high-equivalent temporal reconciliation, correction,
  conflict/cycle/many-to-many rejection, plus legacy alias mapping that never
  drives lifecycle by itself.

- [ ] **Step 2: Run and verify RED**

```bash
pnpm build:cli && node --test test/audit-decisions.test.mjs
```

- [ ] **Step 3: Implement append-only event contracts**

Store one stable decision-ledger unit at
`.atlas/audit-decisions/<decisionLedger>.json`. It is the
`atlas-audit-decisions-v1` append-only hash-chain envelope from the normative
spec; each entry binds `previousEntryDigest`, repeats `eventId`, contains one
event discriminant, and has an `entryDigest`.

```ts
export type AuditFindingAction =
  | 'open'
  | 'remediated'
  | 'accepted-risk'
  | 'separate-design'
  | 'false-positive'
  | 'superseded'
  | 'reopened'

export type AuditRetirementReason =
  | 'deleted'
  | 'moved'
  | 'superseded'
  | 'staged-deletion'
  | 'uncommitted-snapshot-absent'

export type AuditFindingDispositionEventV3 =
  | AuditOpenDecisionEventV3
  | AuditReopenedDecisionEventV3
  | AuditAcceptedRiskDecisionEventV3
  | AuditSeparateDesignDecisionEventV3
  | AuditFalsePositiveDecisionEventV3
  | AuditRemediatedDecisionEventV3
  | AuditSupersededDecisionEventV3

export type AuditDecisionEventV3 =
  | AuditFindingDispositionEventV3
  | AuditScopeRetirementEventV3
  | AuditFindingReconciliationEventV3
  | AuditIdentityAliasReconciliationEventV3
```

Implement strict hash-chain JSON reading, duplicate/collision detection, atomic
append-and-replace while locked, effective-state reduction, decision-policy
validation, expiry warning at 14 days, event-relative maximums at 30/90 days,
immediate blocking on reopen/regression, and a stable `decisionLedger` home
unit. The schema-owned global index covers every V3 history, not only current
observations. Entry reduction uses chain order and never timestamp sorting.

- [ ] **Step 4: Implement retirement and reconciliation**

Retirement events are reason-discriminated and carry self-contained
history/absence/deletion/successor proof plus timestamp precision. Temporal
finding reconciliation and legacy identity-alias reconciliation are separate
event types. Temporal events use explicit comparison IDs, deterministic global
home ledgers, earlier-event corrections, and validated split/merge groups;
alias events map producer identities to canonical finding/occurrence IDs
without mutating observations or manufacturing lifecycle equivalence.

- [ ] **Step 5: Verify and commit**

```bash
pnpm build:cli
node --test test/audit-decisions.test.mjs test/audit-v3.test.mjs
git add src/audit-decisions.ts src/audit-v3-types.ts test/audit-decisions.test.mjs
git commit -m "feat(audit): add append-only finding lifecycle"
```

### Task 4: Move policy classification and coverage generation into Repo Atlas

**Files:**
- Create: `src/audit-policy.ts`
- Create: `src/audit-coverage-generator.ts`
- Create: `test/audit-policy-generator.test.mjs`
- Modify: `src/audits.ts`
- Modify: `src/audit-v3.ts`
- Modify: `src/review-coverage.ts`
- Modify: `src/types.ts`

- [ ] **Step 1: Write failing policy and exact-coverage tests**

Port the proven RelayOS fixture matrix into temporary Git repositories. Assert:

- every tracked regular file is exactly one of review/excluded/unclassified/conflict;
- domain rules union while domain/exclusion overlap fails;
- executable/config exclusions need exact owned exceptions;
- every `(path, domain)` matches exactly one unit;
- deleted, symlink, submodule, newline, option-like, and non-UTF-8 paths fail safely;
- a receipt is fresh only for exact path/blob/unit/accepted ruleset and full-read attestation;
- decisions never manufacture exact coverage;
- semantic claims are independently reported as covered/unknown/gap;
- canonical output is byte-stable and contains no generation timestamp;
- `--allow-incomplete` writes honest incomplete state but policy/ledger invalidity still exits nonzero.

Also port the proven hostile RelayOS fixture semantics without copying its
module layout:

- canonical policy hashing is insensitive to whitespace/key order;
- inventory uses sanitized Git environment and fatal UTF-8, rejects Windows
  drive aliases, case collisions, symlinks, gitlinks, unresolved stages, and
  unsafe modes, and records current/index blobs plus explicit deletions;
- classification preserves every rule ID, rejects unmatched units, and never
  treats unit context as ownership;
- exact evidence must match the assigned same-domain unit; eligible V1/V2/V3
  receipts join, while rejected rulesets, stale/mismatched bytes, missing
  full-read proof, semantic completion, or decision state cannot;
- update writes compact canonical bytes plus one newline, while check requires
  those exact bytes and the hostile reader continues to accept structurally
  valid legacy pretty reports; and
- `allowIncomplete` changes success only for honest missing/stale evidence,
  never policy, conflict, invalid-ledger, self-proof, or byte-drift failures.

The generic policy header and embedded decision policy are:

```json
{
  "formatVersion": 1,
  "format": "atlas-review-policy-v1",
  "rules": [],
  "units": [],
  "securityDecisions": {
    "requireDisposition": true,
    "blockingActions": ["open", "reopened"],
    "acceptedRulesets": ["relayos-security-v3", "codex-security-1.0"]
  }
}
```

- [ ] **Step 2: Run and verify RED**

```bash
pnpm build:cli && node --test test/audit-policy-generator.test.mjs
```

- [ ] **Step 3: Implement strict policy, inventory, and unit assignment**

Export:

```ts
export function loadAuditReviewPolicy(root: string): AuditReviewPolicyResult
export function readAuditTrackedInventory(root: string): AuditInventoryResult
export function classifyAuditInventory(
  inventory: readonly AuditTrackedFile[],
  policy: AuditReviewPolicyV1,
): AuditClassificationResult
```

Use NUL-safe `git ls-files --stage -z`, hash working-tree bytes, reject stage conflicts and non-regular modes, compile picomatch with `{ dot: true }`, and preserve all matching rule IDs.

Do not copy RelayOS's repository-specific broad-glob probes. Reject universal
swallowing patterns syntactically and evaluate other broad exclusions against
the actual inventory. Add one schema-owned normalized exact-evidence export
from `audits.ts`/`audit-v3.ts` containing version, domain, slug, nullable
ruleset, stale state, exact path/blob/full-read receipts, and invalid claimed
paths. The generator and hostile report reader consume this seam; neither
re-parses audit ledgers.

- [ ] **Step 4: Generate and enforce canonical coverage**

Export:

```ts
export function buildAuditCoverageReport(input: AuditCoverageInput): ReviewCoverageReport
export function updateAuditCoverage(root: string, options?: { allowIncomplete?: boolean }): AuditCoverageResult
export function checkAuditCoverage(root: string, options?: { allowIncomplete?: boolean }): AuditCoverageResult
```

`AuditCoverageResult` distinguishes `ok`, committed-byte `current`, `wrote`,
canonical bytes, diagnostics, and runtime-only semantic/ruleset/lifecycle
assurance. Those runtime projections never become invented
`atlas-review-coverage-v1` fields. `update` always writes an honest valid
complete or incomplete report; `allowIncomplete` changes return/exit success,
not the bytes or policy validity.

Continue emitting and validating `atlas-review-coverage-v1`; changing ownership
does not bump the wire format. Exact V3 receipt eligibility is expressed by the
existing per-domain fresh/missing/stale/invalid evidence plus unit references.
Semantic coverage, accepted-ruleset status, and lifecycle blocking are separate
runtime assurance projections, not invented V2 coverage fields. The self-entry
still uses `GENERATED-PROOF`.

- [ ] **Step 5: Verify and commit**

```bash
pnpm build:cli
node --test test/audit-policy-generator.test.mjs test/review-coverage.test.mjs test/audit-coverage-fixtures.test.mjs
git add src/audit-policy.ts src/audit-coverage-generator.ts src/review-coverage.ts src/types.ts test/audit-policy-generator.test.mjs
git commit -m "feat(audit): own closed-world coverage generation"
```

### Task 5: Add the sealed Codex Security 1.0 importer

**Files:**
- Create: `src/audit-import-codex.ts`
- Create: `test/audit-import-codex.test.mjs`
- Create: `test/fixtures/codex-security/clean-bundle.json`
- Create: `test/fixtures/codex-security/finding-bundle.json`
- Create: `test/fixtures/codex-security/malformed-bundle.json`

- [ ] **Step 1: Write failing adapter fixtures**

Construct the real three-document Codex Security 1.0 directory bundle:
`scan-manifest.json`, `findings.json`, and `coverage.json`, plus only the
artifacts referenced by the manifest. Assert rich finding fields, normalized
locations, sealed-producer code evidence, exact source IDs in
provenance/extensions, canonical Atlas target/source-kind coordinates,
semantic-declaration scope, semantic coverage, and
`exactCoverage: { completeness: "unknown", basis: "unavailable", ... }`.
Codex 1.0 supplies no ruleset and no exact per-file/full-read receipts, so the
adapter must not invent either.

Reject URL-like bundle inputs, non-local or symlinked bundle members, missing
canonical documents, scan-ID/reference/timestamp mismatch, digest mismatch,
unsafe or duplicate artifact paths, duplicate/colliding findings, unsupported
document types/versions, invalid Codex identity formulas, findings with no
location in the declared scope, and unknown fields that cannot be preserved
within V3 bounds. Require at least one finding location in the declared scope,
but preserve safe same-repository supporting locations/evidence outside it.
`sourceSeal` is adapter-derived; malformed source-seal pointer rejection
belongs to Task 2 V3 parser tests. Missing full-read proof is an honest
semantic import, not an import failure.

- [ ] **Step 2: Run and verify RED**

```bash
pnpm build:cli && node --test test/audit-import-codex.test.mjs
```

- [ ] **Step 3: Implement offline-only import**

Export:

```ts
export interface CodexSecurityImportOptions {
  bundlePath: string
  unitSlug: string
  unitTitle?: string
  conceptSlug?: string
  apply?: boolean
}

export interface CodexSecurityImportResult {
  observation: AtlasSecurityObservationV3
  ledger: AtlasSecurityCurrentLedgerV3
  historyEntry: AuditObservationHistoryEntryV3
  currentBytes: string
  applied: boolean
  publication?: {
    currentPath: string
    historyPath: string
    appendedObservationId: string
  }
}

export function importCodexSecurityBundle(
  root: string,
  options: CodexSecurityImportOptions,
): CodexSecurityImportResult
```

Read only local regular files under the supplied bundle root; never invoke
Codex or fetch a URL. Use bounded duplicate-key-aware JSON reads, verify the
manifest's actual seal relationships against exact raw bytes from
`readBoundedAuditJsonDocument` (and `readBoundedAuditBytes` for non-JSON
artifacts) before mapping, and describe the
unsealed manifest itself as `adapter-bundle`, never producer-manifest. Preserve
every schema-permitted unmapped source field as a bounded namespaced extension
at its exact JSON pointer or reject the import. Use distinct
`codex-security.scan-manifest/1.0`, `codex-security.findings/1.0`, and
`codex-security.coverage/1.0` namespaces so identical pointers in different
documents cannot collide. Import code evidence as
`sealed-producer-snippet` unless Atlas independently proves the referenced
source blob and lines; neither variant manufactures full-read coverage.

Task 2 exposes a shared
`prepareAuditObservationPublication(root, observation, metadata)` helper that
selects and validates the history head, derives the next history entry/current
wrapper, and returns canonical bytes without writing. Import, migration, and
provider producers all use it; only `publishAuditObservation` performs the
locked history-first mutation. Dry-run and apply therefore build identical
bytes and no producer reimplements chain logic.

- [ ] **Step 4: Verify and commit**

```bash
pnpm build:cli
node --test test/audit-import-codex.test.mjs test/audit-v3.test.mjs
git add src/audit-import-codex.ts test/audit-import-codex.test.mjs test/fixtures/codex-security
git commit -m "feat(audit): import sealed Codex Security bundles"
```

### Task 6: Add deterministic RelayOS legacy migration

**Files:**
- Create: `src/audit-migrate-relayos.ts`
- Create: `test/audit-migrate-relayos.test.mjs`
- Create: `test/fixtures/relayos-security/ledger.json`
- Create: `test/fixtures/relayos-security/candidates.v1.json`
- Create: `test/fixtures/relayos-security/dispositions.v1.json`
- Create: `test/fixtures/relayos-security/phase-zero-provenance.v1.json`

- [ ] **Step 1: Write failing migration tests**

Assert:

- all legacy scanned file records map to V3 file receipts, including clean files;
- active/retired occurrences retain deterministic identities and provenance;
- 55/16/3/3/5 disposition categories map without collapsing meaning;
- source candidate duplicates reconcile to one canonical finding with explicit events;
- exact hashes are preserved only when they match repository bytes;
- absent legacy confidence remains absent;
- semantic coverage is `unknown`, never fabricated;
- dry-run and apply return identical canonical bytes;
- input reordering produces identical IDs and output;
- rerun is idempotent and a changed input produces a new deterministic migration receipt;
- malformed/inconsistent source artifacts fail without partial writes.

- [ ] **Step 2: Run and verify RED**

```bash
pnpm build:cli && node --test test/audit-migrate-relayos.test.mjs
```

- [ ] **Step 3: Implement migration mapping and receipts**

Export:

```ts
export interface RelayOSMigrationOptions {
  sourceRoot?: string
  apply?: boolean
}

export interface RelayOSMigrationResult {
  migrationId: string
  receipt: AuditMigrationReceiptV3
  observations: AuditObservationV3[]
  decisionEvents: AuditDecisionEventV3[]
  retirementEvents: AuditRetirementEventV3[]
  reconciliationEvents: AuditReconciliationEventV3[]
  writes: Array<{ path: string; sha256: string }>
}

export function migrateRelayOSAudit(
  root: string,
  options?: RelayOSMigrationOptions,
): RelayOSMigrationResult
```

Partition observations by policy unit. The receipt at `.atlas/migrations/<migrationId>.json` contains sorted source digest/input/output mappings and no wall-clock field. Apply validates every output first, then writes under one lock; it never deletes legacy material.

- [ ] **Step 4: Verify and commit**

```bash
pnpm build:cli
node --test test/audit-migrate-relayos.test.mjs test/audit-decisions.test.mjs
git add src/audit-migrate-relayos.ts test/audit-migrate-relayos.test.mjs test/fixtures/relayos-security
git commit -m "feat(audit): migrate RelayOS legacy evidence"
```

### Task 7: Add provider orchestration and the isolated Grok CLI adapter

**Files:**
- Create: `src/audit-providers.ts`
- Create: `src/audit-provider-grok.ts`
- Create: `test/audit-provider-grok.test.mjs`
- Modify: `src/audit-v3-types.ts`

- [ ] **Step 1: Write failing fake-Grok tests**

Create an executable fixture that records argv/env/cwd/stdin and emits controlled JSON. Assert:

- Grok is never invoked by `audit check`, `status`, `build`, install, or hooks;
- `audit run security --provider grok` is required;
- execution uses a temporary HOME/XDG/config directory and a read-only source snapshot;
- ambient hooks/plugins/MCP/config are absent;
- phase order is inventory → parallel bounded review → verification → synthesis;
- configured concurrency and timeouts are enforced;
- every phase emits a transcript chunk digest and the final receipt covers all chunks;
- invalid JSON, missing file receipts, changed snapshot bytes, timeout, signal, or transcript mismatch prevents publication;
- resume reuses only verified snapshot/phase outputs and reruns corrupt/missing work;
- original repository files are never modified.

- [ ] **Step 2: Run and verify RED**

```bash
pnpm build:cli && node --test test/audit-provider-grok.test.mjs
```

- [ ] **Step 3: Implement provider abstraction**

```ts
export interface AuditProvider {
  readonly name: string
  run(context: AuditProviderContext): Promise<AuditProviderResult>
}

export interface AuditProviderContext {
  repoRoot: string
  snapshotRoot: string
  invocationId: string
  policy: AuditProviderPolicy
  prompt: string
  targets: AuditTarget[]
  resumeDir: string
}
```

Snapshot all selected exact bytes into a temp directory, mark files read-only, write a canonical manifest, and validate it before and after every phase. Store clone-local resume/transcript state under `.atlas/.runtime/audit-runs/<invocationId>/`, which is ignored and never coverage evidence.

- [ ] **Step 4: Implement Grok invocation**

Spawn `grok` with an explicit command/model/output mode from provider policy, `shell: false`, exact argv, sanitized allowlisted environment, isolated HOME/XDG variables, bounded stdout/stderr, abort controller timeout, and no network-related flags beyond what the explicit Grok binary itself requires. Prompts tell the orchestrator to dispatch bounded parallel sub-reviews and require one receipt for every target file.

- [ ] **Step 5: Verify and commit**

```bash
pnpm build:cli
node --test test/audit-provider-grok.test.mjs test/audit-v3.test.mjs
git add src/audit-providers.ts src/audit-provider-grok.ts src/audit-v3-types.ts test/audit-provider-grok.test.mjs
git commit -m "feat(audit): add isolated explicit Grok producer"
```

### Task 8: Expose the hierarchical audit CLI

**Files:**
- Create: `src/audit-cli.ts`
- Create: `test/audit-cli.test.mjs`
- Modify: `src/cli.ts`

- [ ] **Step 1: Write failing CLI tests**

Cover help, unknown arguments, dry-run/apply separation, exit codes, stdout JSON, and no ambient provider calls for:

```text
repo-atlas audit check [--allow-incomplete]
repo-atlas audit coverage check [--allow-incomplete]
repo-atlas audit coverage update [--allow-incomplete]
repo-atlas audit status [--json]
repo-atlas audit run security --provider grok [--unit <slug> | --all | --stale] [--resume <id>]
repo-atlas audit import codex-security <scan-dir> --slug <slug> [--apply]
repo-atlas audit migrate relayos-security-v1 --scan-root <path> --policy <path> [--include-history] [--apply]
repo-atlas audit migrate relayos-root-audits-v1 --audits-root <path> --source-revision <commit> [--apply]
repo-atlas audit decision set <finding-or-occurrence> <action>
repo-atlas audit reconcile <before> <after>
repo-atlas audit retire <path>
repo-atlas audit retire --finalize-staged
repo-atlas audit localization input --locale <locale>
repo-atlas audit localization check
```

- [ ] **Step 2: Run and verify RED**

```bash
pnpm build:cli && node --test test/audit-cli.test.mjs
```

- [ ] **Step 3: Implement strict dispatch and exit policy**

`audit check` validates V3/V2/V1 ledgers, history, decisions, migration receipts, current exact/semantic coverage, lifecycle policy, and transcript/provenance references. Exit `0` only for complete state, or honest incomplete state with `--allow-incomplete`; structural invalidity is always nonzero. Mutating commands accept explicit `--apply` except decision append/run/update, whose command name already states the write.

- [ ] **Step 4: Preserve legacy commands**

Keep `audit-stamp`, `audit-import`, and existing localization aliases as deprecated compatibility commands. They must call the same safe implementations and print migration guidance.

- [ ] **Step 5: Verify and commit**

```bash
pnpm build:cli
node --test test/audit-cli.test.mjs test/audits.test.mjs test/audit-localizations.test.mjs
git add src/audit-cli.ts src/cli.ts test/audit-cli.test.mjs
git commit -m "feat(audit): expose V3 audit command surface"
```

### Task 9: Integrate V3 state into build, live viewer, and localization

**Files:**
- Modify: `src/types.ts`
- Modify: `src/build.ts`
- Modify: `src/serve.ts`
- Modify: `src/audit-assurance.ts`
- Modify: `viewer/Security.tsx`
- Modify: `viewer/AuditCoverage.tsx`
- Modify: `viewer/AuditNav.tsx`
- Modify: `test/build.test.mjs`
- Modify: `test/audit-assurance.test.mjs`
- Modify: `test/audit-localization-viewer.test.mjs`
- Modify: `viewer/locales/en/messages.po`
- Modify: `viewer/locales/ja/messages.po`
- Modify: `viewer/locales/zh/messages.po`
- Modify: `viewer/locales/ko/messages.po`

- [ ] **Step 1: Write failing presentation tests**

Assert the payload and pure presentation distinguish:

- exact complete/incomplete/invalid from semantic covered/unknown/gap;
- finding severity/confidence/status;
- open, accepted, expired, reopened, remediated, false-positive, superseded;
- current observation versus history;
- producer/provenance/transcript proof;
- migrated unknown semantic coverage;
- stale exact bytes and policy drift.

- [ ] **Step 2: Run and verify RED**

```bash
pnpm build:cli
node --test test/build.test.mjs test/audit-assurance.test.mjs test/audit-localization-viewer.test.mjs
```

- [ ] **Step 3: Add payload and viewer projections**

Keep derivation pure in `src/audit-assurance.ts`; the React viewer only renders the derived model. Never label migrated or partial evidence as Codex-equivalent. Show missing confidence as “not supplied,” not low confidence.

- [ ] **Step 4: Extract, translate, compile, and test**

```bash
pnpm i18n:extract
pnpm i18n:compile
pnpm build:viewer
node --test test/build.test.mjs test/audit-assurance.test.mjs test/audit-localization-viewer.test.mjs
```

Populate every new message in all four catalogs before compiling.

- [ ] **Step 5: Commit**

```bash
git add src/types.ts src/build.ts src/serve.ts src/audit-assurance.ts viewer/Security.tsx viewer/AuditCoverage.tsx viewer/AuditNav.tsx test/build.test.mjs test/audit-assurance.test.mjs test/audit-localization-viewer.test.mjs viewer/locales/en/messages.po viewer/locales/ja/messages.po viewer/locales/zh/messages.po viewer/locales/ko/messages.po src/vendor/viewer.js src/vendor/viewer.css
git commit -m "feat(audit): present V3 assurance and lifecycle"
```

### Task 10: Document, harden, and release the platform contract

**Files:**
- Modify: `README.md`
- Modify: `package.json`
- Modify: existing relevant tests

- [ ] **Step 1: Add copy-boundary and package tests**

Extend `test/audit-copy-boundary.test.mjs` and CLI tests to assert:

- Repo Atlas owns no RelayOS product policy or prompt content;
- adapter fixtures are bounded test data, not consumer scripts;
- the npm/Git package contains `dist`, prompt templates required by providers, and no runtime worktree;
- default commands never invoke Grok;
- all deprecated commands point to V3 replacements.

- [ ] **Step 2: Document the complete workflow**

README sections must include current layout, V1/V2 compatibility, V3 guarantees, policy ownership, exact versus semantic coverage, decisions/retirement, explicit Grok execution, sealed Codex import, RelayOS migration dry-run/apply, lock/recovery, and CI examples.

- [ ] **Step 3: Run focused security and hostile-input verification**

```bash
pnpm build
node --test test/audit-core.test.mjs test/audit-v3.test.mjs test/audit-decisions.test.mjs test/audit-policy-generator.test.mjs test/audit-import-codex.test.mjs test/audit-migrate-relayos.test.mjs test/audit-provider-grok.test.mjs test/audit-cli.test.mjs test/audit-copy-boundary.test.mjs
```

- [ ] **Step 4: Run the full project verification**

```bash
pnpm test
pnpm typecheck
pnpm pack --pack-destination "$(mktemp -d)"
git status --short
```

Expected: every test passes, both typecheck projects pass, package creation succeeds, and only intentional documentation/source/test/bundle changes remain.

- [ ] **Step 5: Commit and push**

```bash
git add README.md package.json test/audit-copy-boundary.test.mjs
git commit -m "docs(audit): publish the V3 platform workflow"
git push origin feat/codex-security-atlas-adapter
```

## Final requirement review

- [ ] V1/V2 remain readable but every new write is V3.
- [ ] Exact coverage, semantic coverage, finding lifecycle, and producer integrity are independently represented.
- [ ] V3 semantically covers Atlas V2, RelayOS legacy, and Codex Security 1.0 without inventing unsupported legacy facts.
- [ ] Every reviewed file has an exact blob and explicit reviewed/not-reviewed plus clean/findings/unknown outcome.
- [ ] Decisions and retirements are append-only, self-contained, expiry-aware, and regression-aware.
- [ ] Policy and deterministic coverage generation are Repo Atlas capabilities.
- [ ] Grok runs only through an explicit command in an isolated snapshot with transcript proof.
- [ ] Codex Security import is offline, sealed, digest-checked, and loss-preserving.
- [ ] RelayOS migration is deterministic, idempotent, non-destructive, and emits a canonical receipt.
- [ ] Viewer/localization distinguish unknown from clean and exact from semantic.
- [ ] Full tests, typechecks, packaging, and Git status are freshly verified.
