# Repo Atlas audit platform V3 and security producers

Date: 2026-07-29
Status: proposed
Supersedes: `2026-07-29-codex-security-adapter-and-assurance-design.md`

## Executive decision

Repo Atlas becomes the owner of repository audit execution, canonical audit
evidence, finding lifecycle, closed-world review coverage, and the viewer
projection of those facts.

The first complete implementation has two security producers:

1. a first-party Grok CLI producer that Repo Atlas invokes explicitly and
   orchestrates itself; and
2. a strict offline adapter for sealed OpenAI Codex Security bundles.

Consumer repositories provide policy, scope, and an optional prompt extension.
They do not carry scanner implementations, orchestration scripts, raw model
transcripts, batch directories, or a second audit database.

`atlas-audit-v3` is not a copy of the Codex Security wire format. Its capability
floor is the semantic union of:

- Repo Atlas V2's exact-scope ledger and viewer portfolio;
- RelayOS's exact-blob, per-file scan history, candidate reconciliation,
  disposition, remediation, regression, expiry, and retirement controls; and
- Codex Security 1.0's sealed target/scope manifest, threat model, semantic
  coverage, stable identities, structured code evidence, root cause,
  validation, attack path, severity rationale, and remediation guidance.

Every durable fact from those three inputs must have a first-class V3 mapping
or an explicit, documented exclusion. Importers and migrators never silently
drop an unknown field.

## Research basis

This design was checked against:

- Repo Atlas at `d893b14`, including V1/V2 loaders, audit localization,
  `atlas-review-coverage-v1`, the Security viewer, and 208 passing tests;
- RelayOS `origin/main` at `3ae77061`, including 457 historical per-file
  security scan records, 82 canonical findings, 82 current dispositions, the
  security-scan enforcement gate, and the generic review-coverage
  implementation currently living under `scripts/checks`;
- OpenAI `codex-security` at `f22d4a36f26d16287bcdfd707b369116e02a08c3`,
  SDK 0.1.1 and bundled plugin 0.1.14, including the three sealed 1.0 JSON
  contracts, workbench history, comparison, append-only decisions, and
  false-positive feedback; and
- local Grok CLI 0.2.82, including its headless flags, configuration discovery,
  session transcript, read-tool records, hooks, plugins, permissions, MCP
  configuration, and session storage.

The installed Grok configuration demonstrated why command-line flags alone are
not an adequate trust boundary: `grok inspect --json` exposed executable
user-level hooks and plugin hooks even when the requested task was read-only.
The producer therefore creates an isolated Grok home, performs the preflight in
that same environment, and validates the resulting transcript.

## Problem statement

Repo Atlas currently consumes audit ledgers but does not own the complete
workflow that makes them trustworthy. A consumer can therefore accumulate:

- scanner-specific scripts;
- prompts and raw outputs mixed with durable evidence;
- a private candidate and disposition schema;
- a second coverage implementation;
- lifecycle rules that the Atlas viewer cannot understand; and
- historical audit directories outside `.atlas`.

This splits the source of truth. It also makes "complete" ambiguous:

- an LLM can complete its semantic review without reading every current file;
- an exact-blob ledger can prove file freshness without proving that every
  security surface was considered; and
- a finding can disappear from a later run without being proven remediated.

Repo Atlas must represent those claims separately and compose them without
turning one into another.

## Product boundary

### Repo Atlas owns

- schemas and fail-closed loaders for current observations, history, decisions,
  migration receipts, policy, and coverage;
- deterministic finding and occurrence identity;
- producer lifecycle and concurrency;
- Grok prompt phases, parsing, transcript verification, and fact checking;
- Codex Security seal verification and semantic mapping;
- current-vs-history reconciliation;
- policy classification and exact review-coverage generation;
- decision and retirement validation;
- atomic writes, locks, and recovery;
- CLI, localization input, and viewer projections; and
- compatibility readers and migrators.

### The consumer repository owns

- `.atlas/review-policy.json`: which tracked paths require which review domain,
  unit assignment, exclusions, and decision thresholds;
- optional `.atlas/pipeline/security.extra.md`: repository-specific threat
  context and review instructions, treated as security-sensitive policy input;
- optional `.atlas/audit-providers.json`: explicit provider model, limits, and
  approved effective-configuration digests;
- checked-in canonical `.atlas` evidence and decisions; and
- project-specific runtime invariants that are not generic audit machinery.

### Clone-local state

Attempts, session transcripts, temporary snapshots, locks, process journals,
resume tokens, and model stdout live outside the repository in an XDG cache or
worktree-local Git metadata. They are never required to render or validate a
committed Atlas and are never added to `.atlas`.

## Non-goals

- Reimplementing the Codex Security scanner or private prompts.
- Claiming that Grok and Codex produce identical findings.
- Running an LLM from `status`, `check`, `build`, `serve`, coverage validation,
  localization, or pre-commit unless the user explicitly invokes
  `audit run`.
- Treating a producer fingerprint as proof of semantic equivalence.
- Committing model credentials, raw transcripts, complete source archives,
  workbench databases, full PoCs, long vulnerability reports, or hidden chain
  of thought.
- Requiring Codex Security to be installed for normal Repo Atlas use.
- Making V1 or V2 writable after V3 ships.
- Moving product-specific security invariants into Repo Atlas.

## Assurance model

Atlas reports four independent states.

| State | Question | Canonical source |
| --- | --- | --- |
| exact coverage | Were these exact current Git blobs reviewed? | per-file V3 receipts + generated review coverage |
| semantic coverage | Which threat surfaces were completed, deferred, rejected, or not applicable? | V3 semantic coverage |
| finding lifecycle | Is a finding open, accepted, false-positive, remediated, superseded, or reopened, and why? | append-only decision events |
| producer integrity | Which producer, prompt, configuration, source snapshot, and validation path created this observation? | producer and target receipts |

No state substitutes for another. In particular:

- semantic `complete` does not satisfy exact file coverage;
- zero findings means "no issue reported in the evidenced scope", not "safe";
- an absent finding is not automatically resolved;
- a stale disposition does not close a current occurrence; and
- a failed or partial model attempt is not a completed observation.

## Canonical repository layout

```text
.atlas/
  audits/
    <slug>.json                    # current V1/V2/V3 projection
  audit-history/
    <slug>.json                    # append-only V3 observation chain
  audit-decisions/
    <slug>.json                    # append-only decision/reconciliation chain
  migrations/
    <migration-id>.json            # deterministic migration receipt
  artifacts/
    ...                            # bounded reader-facing projections
  pipeline/
    security.extra.md              # optional policy prompt, not executable
  audit-providers.json             # optional provider policy
  review-policy.json               # closed-world classification + gates
  review-coverage.json             # deterministic generated proof
```

All paths are normalized, repository-relative POSIX paths. Loaders reject
absolute paths, `.` or `..` segments, backslashes, NULs, symlinks,
non-regular files, case-ambiguous duplicates, and containment changes between
open and read.

## Version evolution

| Format | Role after this change | Writable | Capabilities |
| --- | --- | --- | --- |
| `atlas-audit-v1` | legacy imported per-file/security compatibility | compatibility maintenance only | envelope freshness and optional hashes |
| `atlas-audit-v2` | stable portfolio compatibility for security/test/design | compatibility maintenance only | typed domains, exact scope, findings, viewer/localization |
| `atlas-audit-v3` | current security model | yes | rich observations, exact + semantic coverage, identities, code evidence, lifecycle references, provenance |

V1 and V2 continue to load, render, localize, and stamp where previously
supported. V2 retains its existing exact-hash coverage contribution; V1
remains recorded compatibility evidence but does not directly establish fresh
closed-world coverage. Existing commands remain as deprecated aliases during
one minor release. Only an explicitly requested legacy import or maintenance
command writes V1/V2; new first-party producers and migrations emit only V3.

V3 initially supports `domain: "security"`. Test and design V2 ledgers remain
valid. Extending V3 to another domain requires a domain-specific finding schema
and viewer, not a loose `unknown` payload.

Compatibility projection must remain lossless about absence. In particular,
the shared portfolio `ruleset` field is nullable: a Codex-contract observation
that supplied no ruleset projects `null`, never an invented
`"unknown"`, `"codex-security-1.0"`, or adapter label. Exact scope, hashes, and
freshness likewise project only from exact-inventory receipts. A wrapper that
claims V3 is dispatched only to the strict V3 parser and can never downgrade
into a permissive V1/V2 interpretation.

## V3 current ledger

The checked-in current projection is self-contained for readers and is bound to
the latest history entry:

```json
{
  "formatVersion": 3,
  "format": "atlas-audit-v3",
  "domain": "security",
  "slug": "security-identity-access",
  "title": "Identity and access security",
  "conceptSlug": "identity-access",
  "current": {},
  "currentDigest": "sha256:<64 lowercase hex>",
  "history": {
    "path": ".atlas/audit-history/security-identity-access.json",
    "observationId": "aobs_<24 lowercase hex>",
    "entryDigest": "sha256:<64 lowercase hex>"
  }
}
```

`current` is one `AtlasSecurityObservation`. `currentDigest` is SHA-256 over
RFC 8785 canonical JSON for `current`; the implementation exposes one
canonical serializer and never hashes pretty-printed bytes. The latest history
entry must contain the byte-for-byte same canonical observation and digest.
The slug is lowercase kebab-case, begins with `security-`, and exactly matches
the current/history/decision filename stem.

### Observation envelope

```json
{
  "observationId": "aobs_<24 lowercase hex>",
  "observedAt": "2026-07-29T12:00:00.000Z",
  "reviewState": "complete",
  "producer": {},
  "target": {},
  "scope": {},
  "exactCoverage": {},
  "semanticCoverage": {},
  "threatModel": {},
  "findings": [],
  "evidenceRefs": [],
  "sourceArtifacts": [],
  "producerExtensions": []
}
```

`reviewState` means the producer transaction was finalized and validated. V3
does not serialize a pending model attempt as `reviewState: "incomplete"`;
partiality is represented honestly inside exact or semantic coverage.

`observationId` is derived from:

```text
"aobs_" + first24(sha256(
  "atlas-observation/v1" NUL
  slug NUL
  producer.adapter NUL
  producer.runId NUL
  producer.identityDigest NUL
  target.targetId NUL
  target.identityDigest NUL
  scope.identityDigest
))
```

The adapter rejects duplicate IDs with different digests. Wall-clock time is
not identity material. Codex imports use the sealed producer run ID plus the
contract/target/scope identity receipts defined below; RelayOS migrations
derive run IDs and identity receipts from sealed source facts; Grok runs
allocate their run ID before execution and use ruleset, snapshot, and exact
inventory digests. A dry-run and apply over the same migration/import inputs
therefore produce the same observation IDs.

### Producer receipt

```json
{
  "kind": "grok-cli | codex-security | migration | manual",
  "name": "grok",
  "version": "0.2.82",
  "adapter": "repo-atlas/grok-v1",
  "adapterVersion": "0.1.0",
  "runId": "<provider or Atlas run id>",
  "identityDigest": "sha256:<hex>",
  "identityBasis": "ruleset | codex-contract",
  "ruleset": {
    "id": "atlas-security-v3",
    "digest": "sha256:<hex>"
  },
  "prompt": {
    "builtinVersion": "atlas-security-prompt-v1",
    "digest": "sha256:<hex>",
    "extraPath": ".atlas/pipeline/security.extra.md",
    "extraDigest": "sha256:<hex>"
  },
  "effectiveConfigDigest": "sha256:<hex>",
  "environmentPolicyDigest": "sha256:<hex>",
  "transcriptDigest": "sha256:<hex>",
  "sourceContract": {
    "namespace": "codex-security/1.0",
    "status": "completed",
    "startedAt": "<exact source string>",
    "completedAt": "<exact source string>",
    "sealedAt": "<exact source string>",
    "manifestPath": "scan-manifest.json",
    "coverageRef": "coverage.json",
    "findingsRef": "findings.json"
  }
}
```

Optional members are omitted, never `null`. `transcriptDigest` proves which
clone-local transcript was validated without committing it. It is not a claim
that the transcript can be recovered from Git.

The public contract is a strict discriminated union, not one interface with
independently optional members:

- `grok-cli`, `migration`, and `manual` use `identityBasis: "ruleset"`, require
  `ruleset`, require `identityDigest === ruleset.digest`, and reject
  `sourceContract`;
- `codex-security` uses `identityBasis: "codex-contract"`, requires the Codex
  `sourceContract`, rejects ruleset/prompt/config/environment/transcript claims
  unavailable from that contract, and recomputes the canonical contract
  identity; and
- prompt extension path/digest members are either both present or both absent.

For `codex-security/1.0`, the three document names are literal contract
members: `scan-manifest.json`, `findings.json`, and `coverage.json`. Their
`sourceArtifacts` rows use `mediaType: "application/json"`. The manifest is an
`adapter-bundle` because it cannot self-seal; findings and coverage are
`producer-manifest` artifacts whose `integrityIndex` is exactly
`scan-manifest.json`.

The same required/forbidden-member rule applies to target, scope, exact
coverage, and artifact-integrity variants. TypeScript declarations use
discriminated unions with `never` exclusions, and runtime parsing enforces the
same matrix after reading untrusted JSON.

The ruleset digest includes the built-in prompt version, prompt text,
repository extension bytes, domain policy, unit scope, threat model input,
model identifier, adapter version, and validation rubric. A changed prompt or
effective provider configuration therefore makes existing evidence stale for
policies that require that ruleset.

First-party and migrated observations use `identityBasis: "ruleset"` and set
`identityDigest` to the ruleset digest. Codex Security 1.0 does not seal its
prompt or scanner ruleset, so the importer must not invent them. It uses
`identityBasis: "codex-contract"` and hashes this canonical value:

```json
{
  "namespace": "repo-atlas/codex-contract-identity/v1",
  "documents": [
    "codex-security.scan-manifest/1.0",
    "codex-security.findings/1.0",
    "codex-security.coverage/1.0"
  ],
  "producer": { "name": "<source>", "version": "<source>" },
  "adapter": { "name": "<Atlas adapter>", "version": "<Atlas adapter version>" }
}
```

That digest identifies a contract interpretation, not a hidden producer
prompt. It does not satisfy policy that requires evidence from a named accepted
ruleset. A Codex receipt omits unavailable `ruleset`, `prompt`,
effective-config, environment-policy, and transcript fields. Its
`sourceContract` retains exact source timestamps, status, and refs;
`observedAt` normalizes `completedAt`, and import requires `sealedAt` to be
byte-for-byte equal to `completedAt`.

### Target receipt

```json
{
  "kind": "git-revision | git-worktree | git-diff | directory-snapshot",
  "sourceKind": "git_revision",
  "repositoryId": "repo_<stable lowercase identifier>",
  "targetId": "<stable producer-neutral target id>",
  "identityDigest": "sha256:<hex>",
  "identityBasis": "snapshot | revision-coordinate",
  "displayName": "<bounded text>",
  "revision": "<full commit, when applicable>",
  "baseRevision": "<full commit, when applicable>",
  "headRevision": "<full commit, when applicable>",
  "snapshotDigest": "sha256:<hex, when supplied>",
  "dirty": false
}
```

The first-party Grok producer audits a snapshot of current tracked worktree
bytes and records `kind: "git-worktree"`. A clean worktree also records the
full HEAD revision. `kind` is Atlas's canonical producer-neutral spelling.
An imported Codex target is a separate strict union branch. It records the
canonical `kind`, exact source spelling (`git_revision`, `git_worktree`,
`git_diff`, or `directory_snapshot`) in `sourceKind`, and every source
coordinate actually present in `sourceRevision`, `sourceBaseRevision`,
`sourceHeadRevision`, and `sourceSnapshotDigest`. It forbids `dirty` because
Codex Security 1.0 does not supply that fact, and forbids the verified Atlas
`revision`/`baseRevision`/`headRevision` members. The upstream contract permits
opaque coordinates such as the official fixture's `deadbeef`; those are
preserved but never promoted into a verified full Git object ID. First-party
targets omit all `source*` members. Target kinds that cannot be joined to
current exact blobs may still carry semantic evidence, but exact coverage
remains `unknown`.

The pinned Codex Security 1.0 schema requires `revision` for `git_revision`
and `snapshotDigest` for `git_worktree`, `git_diff`, and
`directory_snapshot`. It permits `baseRevision` and `headRevision`
independently rather than requiring either pair, so Atlas must not invent a
missing diff coordinate. The adapter preserves any additional schema-permitted
coordinate but applies identity as follows: every valid source snapshot uses
the snapshot branch; only a `git_revision` without a source snapshot uses the
revision-coordinate branch.

`repositoryId` is the committed, producer-neutral identity initialized in
`.atlas/config.json`. It survives revision, worktree, unit, and provider
changes. An existing repository migration creates it once and records the
derivation in a migration receipt; later remote or directory renames do not
change it. `targetId` identifies this particular producer target and may change
between observations.

`target.identityDigest` is the snapshot digest for first-party exact snapshots.
`identityBasis: "snapshot"` requires `snapshotDigest` and exact equality
between those two digests. When an imported Codex target cannot prove a
snapshot, the importer hashes this canonical receipt:

```json
{
  "namespace": "repo-atlas/revision-coordinate/v1",
  "sourceKind": "git_revision",
  "targetId": "<exact source target id>",
  "sourceRevision": "<exact source value or omitted>",
  "sourceBaseRevision": "<exact source value or omitted>",
  "sourceHeadRevision": "<exact source value or omitted>",
  "sourceSnapshotDigest": "<exact source value or omitted>"
}
```

Only members present in the source are included. It labels the result
`revision-coordinate`; it never serializes or describes that coordinate digest
as a content snapshot. A first-party canonical `git-revision` target requires
verified `revision`; a first-party clean `git-worktree` requires the full
`revision`; and a first-party `git-diff` requires applicable verified
base/head coordinates. The Codex branch instead enforces the upstream
required-minimum matrix while preserving every optional source coordinate. A valid Codex
`codex-security-snapshot/v1:sha256:<hex>` is preserved verbatim as
`sourceSnapshotDigest`, normalized to `snapshotDigest: "sha256:<hex>"`, and
requires `identityBasis: "snapshot"`; this identity still does not imply
per-file receipts or exact coverage. The strict target union rejects
invented verified Atlas members and a revision-coordinate claim when the
source supplied a snapshot.

Remote URLs are optional metadata and never identity material. An importer
rejects a remote containing userinfo, query, fragment, backslash ambiguity,
control characters, or an opaque or relative form. It never strips unsafe
parts and continues. A safe canonical absolute URL is preserved exactly.

### Scope and per-file receipts

The following is the `exact-inventory` variant. `scopeHash`,
`inventoryDigest`, `fileCount`, and `files` belong only to this variant:

```json
{
  "mode": "repository | scoped_path | unit | diff | custom",
  "identityDigest": "sha256:<hex>",
  "identityBasis": "exact-inventory | semantic-declaration",
  "includePaths": ["apps/daemon/**"],
  "excludePaths": ["**/*.snap"],
  "scopeHash": "sha256:<hex>",
  "inventoryDigest": "sha256:<hex>",
  "fileCount": 2,
  "files": [
    {
      "path": "apps/daemon/src/a.ts",
      "blob": "git-sha1:<40 hex>",
      "lines": 120,
      "status": "reviewed | not-reviewed",
      "outcome": "clean | findings | unknown",
      "reviewedAt": "2026-07-29T12:00:00.000Z",
      "reviewedAtPrecision": "timestamp | date",
      "reviewedBy": "grok-4.5 via grok-cli",
      "ruleset": "atlas-security-v3",
      "findingOccurrenceIds": ["atocc_..."],
      "receiptRefs": ["phase:validation:unit-1"]
    }
  ],
  "summary": "<optional bounded text>",
  "artifactsReviewed": [],
  "runtimeStatus": "<optional bounded text>",
  "validationMode": "<optional bounded text>",
  "context": "<optional bounded text>",
  "limitations": []
}
```

`blob` is the Git object ID of the exact worktree bytes, computed as Git would
hash a blob; SHA-256 repositories use `git-sha256:`. Importers may preserve an
explicit producer digest as an additional receipt but may not relabel it as a
Git blob.

The sorted tuple `(path, blob, status, outcome, findingOccurrenceIds,
receiptRefs)` determines
`inventoryDigest`. Scope configuration plus that digest determines
`scopeHash`. Per-file `reviewedAt`, `reviewedBy`, `ruleset`, and status are
first-class so a RelayOS migration does not flatten 457 distinct historical
facts into one synthetic timestamp.

`scope.identityDigest` is intentionally a pre-result input identity, distinct
from both digests above. For `exact-inventory`, it is SHA-256 over canonical:

```json
{
  "namespace": "repo-atlas/exact-scope-identity/v1",
  "mode": "<scope mode>",
  "includePaths": [],
  "excludePaths": [],
  "files": [
    { "path": "<normalized path>", "blob": "git-sha1:<hex>" }
  ]
}
```

Files sort by path. This identity excludes status, outcome, review metadata,
receipt refs, and finding occurrence IDs. That separation is required because
an occurrence ID depends on the observation ID; making the observation ID
depend on a receipt digest that already contained occurrence IDs would create
a cryptographic cycle. `inventoryDigest` and `scopeHash` still seal all result
receipts and are themselves protected by `currentDigest` and the history
chain.

`artifactsReviewed` and `limitations` are independently optional storage
members. First-party ruleset producers emit them explicitly, including honest
empty arrays. Codex imports preserve their source absence because the pinned
1.0 manifest schema requires only `includePaths` and `excludePaths`; an
adapter must not turn “not recorded” into “recorded none.”

`outcome: "clean"` means this observation associated no reportable occurrence
with that exact file/blob; it is not a safety guarantee. `findings` requires at
least one listed occurrence bound to the file/blob. `unknown` is used only when
a legacy or imported producer cannot make the distinction. Drift policy may
treat a formerly finding-bearing blob more strictly than a clean receipt.

For a ruleset-basis producer, every `status: "reviewed"` receipt requires
`ruleset` equal to `producer.ruleset.id`. A `not-reviewed` context receipt may
omit it, but if present it also equals that ID. A file receipt cannot introduce
an unrelated accepted-ruleset label that is not bound by the producer digest.
Relay migration uses the canonical `relayos-security-v1` receipt ID and keeps
the older source spelling only in provenance.

Date-only legacy facts normalize to midnight UTC with
`reviewedAtPrecision: "date"` and retain the original calendar date in
provenance. This is a deterministic encoding, not invented timestamp
precision.

A semantic-only Codex import has no exact inventory. It sets
`identityBasis: "semantic-declaration"` and hashes:

```json
{
  "namespace": "repo-atlas/codex-semantic-scope/v1",
  "mode": "<source coverage mode>",
  "inventoryStrategy": "<source inventory strategy>",
  "includePaths": [],
  "excludePaths": [],
  "explicitExclusions": [
    { "pattern": "<exact source pattern>", "reason": "<exact source reason>" }
  ]
}
```

Paths and exclusions use their validated deterministic order. Surfaces,
dispositions, receipt references, deferred work, open questions, findings, and
all result metadata are deliberately excluded. The semantic variant omits
`scopeHash`, `inventoryDigest`, `fileCount`, and `files`; those members belong
only to `exact-inventory`. `currentDigest` and history still seal the complete
semantic result. Semantic paths, finding locations, code snippets, target
revisions, and aggregate snapshot digests are never promoted into per-file
blob receipts.

Semantic selectors preserve Codex Security 1.0's safe source spelling,
including the official fixture's `src/` directory selector and the repository
selector `.`. They may contain globs and one trailing slash, but never an
absolute path, backslash, NUL, `..`, an unsafe empty/interior-dot segment, or
a lone surrogate. This validator is deliberately separate from the stricter
exact-inventory/policy glob validator.

### Exact coverage

```json
{
  "completeness": "complete | partial | unknown",
  "basis": "full-read-receipts | unavailable",
  "reason": "<required when unavailable>",
  "reviewedFileCount": 2,
  "unreviewed": [
    {
      "path": "apps/daemon/src/b.ts",
      "reason": "read receipt did not cover the full file"
    }
  ]
}
```

`complete` requires every scoped file to have a successful full-file read
receipt against the recorded blob. A model statement that it read a file is
not a receipt. For very large files the producer may prove contiguous,
non-overlapping ranges whose union covers all lines. Failed reads, truncated
tool results, missing ranges, source changes, or unverified transcript formats
make the result partial or prevent finalization according to policy.

`basis: "full-read-receipts"` is required for complete or partial exact
coverage. A semantic-only Codex import uses `completeness: "unknown"`,
`basis: "unavailable"`, and the stable reason that Codex Security 1.0 did not
supply exact per-file blob receipts. The full-read form requires
`reviewedFileCount` and `unreviewed` and omits `reason`; the unavailable form
requires `reason` and omits those count/row claims.

### Semantic coverage

```json
{
  "mode": "repository | scoped_path | diff | commit | branch_diff | working_tree | deep_repository | unit | custom",
  "completeness": "complete | partial | unknown",
  "inventoryStrategy": "repository | scoped_path | diff | directory | custom | unit",
  "surfaces": [
    {
      "id": "authz-boundaries",
      "label": "Authorization boundaries",
      "disposition": "reported | no_issue_found | rejected | not_applicable | needs_follow_up",
      "receiptRefs": ["finding:atf_..."],
      "riskArea": "authorization",
      "notes": "<optional>"
    }
  ],
  "explicitExclusions": [
    {
      "pattern": "vendor/**",
      "reason": "third-party vendored source"
    }
  ],
  "deferred": [
    {
      "id": "runtime-proof",
      "reason": "requires a live environment",
      "paths": [],
      "surfaceIds": ["authz-boundaries"]
    }
  ],
  "openQuestions": [
    {
      "question": "Can lower-trust callers reach the admin adapter?",
      "followUpPrompt": "Trace all registrations of the adapter."
    }
  ]
}
```

Codex Security fields map without renaming their meanings. Atlas adds `unit`
where its own policy supplies the inventory. Semantic `complete` requires no
deferred rows and no `needs_follow_up` surface, matching Codex's closure
semantics, but still says nothing about exact file reads.

The top-level `openQuestions` array is optional because Codex Security 1.0
allows it to be absent. When present, `openQuestions[].question` is required
and `followUpPrompt` is optional.
`deferred[].paths` and `surfaceIds` are independently optional in imported
semantic evidence; absent source members remain absent rather than becoming
invented empty arrays.

### Threat model

```json
{
  "summary": "<bounded text>",
  "assets": [],
  "trustBoundaries": [],
  "attackerCapabilities": [],
  "securityObjectives": [],
  "assumptions": []
}
```

An absent threat model is omitted. An empty invented object is invalid.
`summary` is required when the object exists; `assets`, `trustBoundaries`,
`attackerCapabilities`, `securityObjectives`, and `assumptions` are
independently optional exactly as in the pinned Codex Security 1.0 schema.

`sourceArtifacts` is a bounded inventory of producer artifacts:

```json
{
  "path": "artifacts/02_analysis/receipt.json",
  "sha256": "<hex>",
  "mediaType": "application/json",
  "integrityKind": "producer-manifest | adapter-bundle",
  "integrityIndex": "scan-manifest.json",
  "referencedBy": ["/semanticCoverage/surfaces/0/receiptRefs/0"],
  "retainedInAtlas": false
}
```

Every sealed Codex manifest artifact is represented even when its content is
not copied. Receipt references are resolved to this inventory. Grok
clone-local transcripts are represented only by `producer.transcriptDigest`,
not as recoverable source artifacts.

`producer-manifest` means the source manifest listed the path exactly once and
its SHA-256 matched safely opened raw bytes; `integrityIndex` is then required.
`adapter-bundle` means Atlas safely hashed bytes presented at import but the
producer manifest did not protect them. That digest becomes protected only by
the Atlas observation/history chain. Neither label claims a signature,
producer authentication, or a self-sealed manifest. The Codex manifest itself
is `adapter-bundle`; canonical findings, coverage, and sealed coverage receipts
are `producer-manifest`. A write-up or hardening artifact is
`producer-manifest` only when the manifest actually listed its exact path.

## V3 security finding

```json
{
  "findingId": "atf_<24 lowercase hex>",
  "occurrenceId": "atocc_<24 lowercase hex>",
  "decisionLedger": "security-identity-access",
  "ruleId": "authorization/cross-tenant-write",
  "identity": {
    "anchor": "identity-access/session-revoke",
    "instance": "admin-path"
  },
  "fingerprints": [
    {
      "scheme": "atlas/v1",
      "value": "atlas/v1:sha256:<64 hex>",
      "role": "canonical"
    },
    {
      "scheme": "codex-security/v1",
      "value": "codex-security/v1:sha256:<64 hex>",
      "role": "producer"
    }
  ],
  "title": "<text>",
  "summary": "<text>",
  "severity": {},
  "confidence": {},
  "taxonomy": {},
  "locations": [],
  "codeEvidence": [],
  "rootCause": {},
  "remediation": "<text>",
  "validation": {},
  "attackPath": {},
  "remediationTests": [],
  "preventiveControls": [],
  "provenance": {},
  "artifactRefs": [],
  "extensions": []
}
```

Required fields are `findingId`, `occurrenceId`, `decisionLedger`, `ruleId`,
`identity`, `fingerprints`, `title`, `summary`, `severity`, `taxonomy`,
`locations`, `remediation`, and `provenance`. `confidence` is required by
first-party Grok and Codex Security imports but may be absent for a lossless
legacy migration whose source recorded none. Rich optional sections are
omitted when unavailable; placeholders such as `"unknown"` are rejected.

`decisionLedger` is the policy unit that owned the finding's first accepted
occurrence. It is stable even if later source movement assigns the occurrence
to another unit. All disposition events for one `findingId` live in exactly
that one decision document; loaders build a global portfolio index and reject
the same finding's dispositions in two ledgers. This keeps append order
unambiguous without putting the unit slug into finding identity.

### Identity

Atlas computes its own identity:

```text
atlas fingerprint =
  "atlas/v1:sha256:" + sha256(
    "atlas/v1" NUL target.repositoryId NUL domain NUL ruleId NUL
    identity.anchor NUL (identity.instance or "")
  )

findingId =
  "atf_" + first24(sha256(atlas fingerprint))

occurrenceId =
  "atocc_" + first24(sha256(
    "atlas-occurrence/v1" NUL observationId NUL atlas fingerprint
  ))
```

Imported provider IDs and fingerprints are aliases, not Atlas IDs. Atlas
recomputes the documented Codex Security fingerprint and IDs before accepting
them. RelayOS identity keys are retained as
`scheme: "relayos-security-scan/v1"`.

The Atlas fingerprint is stable across revisions and producers within one
committed repository identity. An identical Atlas fingerprint or exact
provider alias is a deterministic same-identity reconciliation signal, but it
does not carry a stale occurrence decision onto changed bytes: current-blob,
expiry, and remediation checks still apply.

Non-identical cross-provider or cross-scan semantic equivalence requires an
explicit reconciliation event. One-to-many and many-to-one match groups are
supported because scanners can split or merge the same root cause.

### Severity and confidence

```json
{
  "level": "critical | high | medium | low | informational",
  "score": 7.5,
  "scoringSystem": "CVSS:3.1",
  "vector": "CVSS:3.1/...",
  "rationale": "<text>",
  "changeConditions": "<what raises or lowers this rating>"
}
```

```json
{
  "level": "high | medium | low",
  "rationale": "<text>"
}
```

V2 `info` maps to V3 `informational` and renders as `info`. Numeric scores must
be finite and between 0 and 10. Only `level` is required. `score`,
`scoringSystem`, `vector`, `rationale`, and `changeConditions` are independently
optional and are omitted rather than filled with placeholders.

### Taxonomy and locations

```json
{
  "category": "authorization",
  "cwe": ["CWE-862"]
}
```

```json
{
  "path": "apps/daemon/src/service.ts",
  "startLine": 237,
  "endLine": 247,
  "role": "root_control"
}
```

At least one safe location is required. Lines must be positive and ordered.
Only `path` and `startLine` are required; `endLine` and `role` are optional.
When `endLine` is absent, validation and rendering treat the range as the
single `startLine` without manufacturing a stored member. Locations may
reference a historical blob only when provenance makes that explicit; a
current observation cannot imply that stale line numbers match current bytes.

### Structured code evidence

Code evidence is a strict discriminated union. Exact evidence is joined to
repository bytes:

```json
{
  "evidenceBasis": "exact-blob",
  "id": "admin-revoke",
  "label": "Admin path skips ownership",
  "path": "apps/daemon/src/service.ts",
  "startLine": 237,
  "endLine": 247,
  "language": "typescript",
  "role": "root_control",
  "code": "<small exact snippet>",
  "explanation": "<connective security reasoning>",
  "blob": "git-sha1:<hex>"
}
```

When the producer supplied a sealed snippet but Atlas cannot independently
join it to exact repository bytes, the evidence remains first-class without
inventing a blob:

```json
{
  "evidenceBasis": "sealed-producer-snippet",
  "id": "admin-revoke",
  "label": "Admin path skips ownership",
  "path": "apps/daemon/src/service.ts",
  "startLine": 237,
  "endLine": 247,
  "language": "typescript",
  "role": "root_control",
  "code": "<small producer snippet>",
  "explanation": "<connective security reasoning>",
  "sourceSeal": {
    "artifactPath": "findings.json",
    "artifactSha256": "<64 lowercase hex>",
    "jsonPointer": "/findings/0/codeEvidence/0"
  }
}
```

The two variants have the same bounded common fields. Common required members
are `evidenceBasis`, `id`, `label`, `path`, `startLine`, `code`, and
`explanation`; `endLine`, `language`, and `role` are independently optional.
An absent `endLine` denotes the single `startLine` but remains absent in
storage. `exact-blob` additionally requires `blob` and forbids `sourceSeal`.
`sealed-producer-snippet` requires `sourceSeal` and forbids `blob`. Its
artifact path and digest must resolve to exactly one `sourceArtifacts` entry with
`integrityKind: "producer-manifest"`, and the JSON pointer must be a strict
pointer into that sealed artifact. A sealed producer snippet is not an exact
file-read or blob receipt and never contributes exact coverage.
For a `codex-security/1.0` producer, that artifact is literally
`findings.json`, and the pointer must name the matching
`/findings/<index>/codeEvidence/<index>` slot; a consistently resealed
reference to `coverage.json` is invalid.

This preserves canonical Codex Security code-evidence meaning as a
first-class V3 fact. Atlas adds an exact source blob only when it independently
possesses and validates those bytes. Import is rejected when an
`exact-blob` snippet does not match its claimed lines/blob, or when a
`sealed-producer-snippet` cannot be traced to its sealed source artifact.

Bounds prevent V3 from becoming a source archive: at most 32 snippets per
finding, 16 KiB per snippet, 128 KiB total snippet bytes per finding, and 1 MiB
for one ledger unless an explicit policy raises the bound. A producer that
exceeds a bound must reduce evidence or retain it as an external sealed
artifact; the importer never truncates silently.

### Root cause, validation, and attack path

`rootCause` is either normalized from a legacy string or:

```json
{
  "summary": "<violated invariant and source-backed cause>",
  "evidenceRefs": ["admin-revoke"],
  "legacyCode": {
    "code": "<older producer single snippet>",
    "language": "typescript"
  }
}
```

For the object variant only `summary` is required. `evidenceRefs` and
`legacyCode` are optional; within `legacyCode`, `code` is required and
`language` is optional. The importer preserves source absence instead of
creating empty arrays or empty language labels.

`validation` supports the durable Codex fields:

```json
{
  "method": "static source trace",
  "disposition": "reportable | suppressed | not_applicable | deferred",
  "summary": "<direct observations>",
  "confidence": "high | medium | low",
  "confidenceRationale": "<text>",
  "evidenceRefs": [],
  "assertions": [],
  "evidence": [],
  "counterevidenceOrProofGap": [],
  "remainingUncertainty": [],
  "limitations": [],
  "artifactRefs": []
}
```

`attackPath` supports:

```json
{
  "summary": "<minimum realistic trigger sequence>",
  "dataflow": {
    "summary": "<source to outcome>",
    "source": "<text>",
    "transformations": [],
    "sink": "<text>",
    "outcome": "<text>",
    "evidenceRefs": []
  },
  "reachability": {
    "summary": "<text>",
    "attacker": "<text>",
    "entrypoint": "<text>",
    "accessRequirements": [],
    "preconditions": [],
    "outcome": "<text>"
  },
  "impact": {
    "level": "critical | high | medium | low | informational",
    "why": "<text>"
  },
  "likelihood": {
    "level": "high | medium | low",
    "why": "<text>"
  },
  "evidenceRefs": [],
  "limitations": []
}
```

Arrays and optional fields are omitted when absent. Arbitrary JSON objects in a
Codex 1.0 `validation` or `attackPath` are recursively bounded and preserved
under the namespaced extension mechanism if they do not match these documented
fields. An explicitly present Codex `validation: null` or `attackPath: null`
remains explicit `null` in V3; absence remains absence.

Because Codex 1.0 intentionally leaves both objects open, import uses a
projection-and-preservation algorithm:

1. project a documented member only when its value has the documented type and
   meaning;
2. never coerce incompatible scalar/array shapes;
3. preserve every unprojected member at its exact source JSON pointer;
4. when a spelling is renamed or normalized, preserve the original pointer and
   value in addition to the semantic projection;
5. reject conflicting accepted spellings that would populate one destination
   differently; and
6. never silently truncate a value to satisfy Atlas bounds.

For example, upstream `counterEvidence` may project to
`counterevidenceOrProofGap`, but its original pointer/value is still retained.
The same rule applies to workbench spellings such as
`confidence_rationale`, `remaining_uncertainty`, or `artifact_paths` when they
occur in sealed findings. An entirely unrecognized subtree is preserved at the
highest unrecognized pointer without duplicating recognized descendants.

### Provenance and external artifacts

```json
{
  "source": "codex-security",
  "producerSource": "<exact finding.provenance.source>",
  "sourceFindingId": "csf_...",
  "sourceOccurrenceId": "occ_...",
  "candidateId": "<optional>",
  "ledgerRowId": "<optional>",
  "reportId": "<optional>"
}
```

`source` identifies the Atlas producer family. `producerSource` preserves the
original Codex value instead of overwriting it. Additional source provenance
properties remain namespaced extensions at their exact JSON pointers.

`artifactRefs` retain bounded integrity metadata for a detailed write-up,
hardening portfolio, validation artifact, or coverage receipt without copying
sensitive content:

```json
{
  "kind": "external",
  "sourceArtifactPath": "findings/csf_.../csf_....md",
  "integrityKind": "producer-manifest | adapter-bundle",
  "sha256": "<hex>",
  "mediaType": "text/markdown",
  "retainedInAtlas": false
}
```

Full reports, PoCs, command output, and raw transcripts are intentionally
excluded from Git. Their bounded structured conclusions remain in V3.

### Extension preservation

```json
{
  "namespace": "codex-security.findings/1.0",
  "path": "/findings/0/validation/customField",
  "value": {},
  "digest": "sha256:<hex>"
}
```

Documented stable fields are first-class. Schema-permitted unknown properties
are either preserved exactly as bounded canonical JSON in `producerExtensions`
or `extensions`, or the import fails with their JSON pointers. There is no
"ignore unknown fields" mode.

Codex extensions use the source-document namespaces
`codex-security.scan-manifest/1.0`,
`codex-security.findings/1.0`, and `codex-security.coverage/1.0`. The `path`
is an exact JSON pointer within that document. The document-specific namespace
is part of extension identity, so the same pointer in two canonical documents
cannot collide. The generic `codex-security/1.0` namespace is not accepted for
an imported source pointer.

Each extension value is limited to 64 KiB, nesting depth 16, 1,000 members, and
the ledger-wide size limit. Keys containing control characters, prototype
names, or unsafe paths are rejected.

Parsed public values use a recursive JSON-value type (`null`, boolean, finite
number, string, array, or data-only string-keyed object), never TypeScript
`unknown`. Stable fields with documented structure are modeled before this
fallback is used. Functions, symbols, `undefined`, accessors, class instances,
non-finite numbers, sparse arrays, prototype-control keys, and cyclic values
are invalid. Extension `(namespace, path)` pairs are unique, paths are strict
JSON Pointers, namespaces are bounded lowercase contract identifiers, and each
stored digest must equal the canonical extension value.

## Observation history

`.atlas/audit-history/<slug>.json` has:

```json
{
  "formatVersion": 1,
  "format": "atlas-audit-history-v1",
  "domain": "security",
  "slug": "security-identity-access",
  "entries": [
    {
      "observationId": "aobs_...",
      "observationDigest": "sha256:...",
      "previousEntryDigest": null,
      "observation": {},
      "entryDigest": "sha256:..."
    }
  ]
}
```

`entryDigest` hashes every member except itself. Later entries bind the previous
entry digest. Normal writers append only. `audit check` verifies the chain,
unique observation and occurrence IDs, and exact equality between the latest
entry referenced by the current ledger and the embedded current observation.
That referenced entry is normally the latest. It may be the penultimate entry
only in the valid one-entry history-ahead interruption state, or absent only
during the valid one-entry genesis history-ahead state.

Git history remains the authority for proving that an old prefix was not
rewritten. The hash chain makes accidental rewriting or partial merge damage
visible in one checkout.

A V3 update commits the new observation to history before switching the
current projection. If interrupted between those steps, validation reports an
unreferenced latest history entry and exact coverage remains at the older
state; it never overstates freshness.

Publication compares descriptor-verified raw document bytes with the canonical
compact bytes plus one trailing newline. If a logically identical current or
history document has only whitespace/key-order byte drift, publication rewrites
it canonically under the lock without appending a duplicate history entry or
changing the logical `already-current` result.

## Decisions, retirement, and reconciliation

`.atlas/audit-decisions/<slug>.json` is a second append-only hash chain. Facts
produced by scans are never rewritten to encode a later human or remediation
decision.

Its envelope is:

```json
{
  "formatVersion": 1,
  "format": "atlas-audit-decisions-v1",
  "domain": "security",
  "slug": "security-identity-access",
  "entries": [
    {
      "eventId": "adev_<24 hex>",
      "previousEntryDigest": null,
      "event": {},
      "entryDigest": "sha256:<hex>"
    }
  ]
}
```

`eventId` appears in both the entry and event and must agree:

```text
eventId =
  "adev_" + first24(sha256(
    "atlas-decision-event/v1" NUL
    canonicalJson(event excluding eventId)
  ))

entryDigest =
  "sha256:" + sha256Utf8(canonicalJson({
    eventId,
    previousEntryDigest,
    event
  }))
```

The stored file's single trailing newline is not part of either digest.
Genesis uses `previousEntryDigest: null`; every later entry repeats the exact
previous entry digest. Array/chain order is authoritative. Timestamps need not
be monotonic, especially for deterministic migrations, and are never used to
sort or repair a chain.

The decision-chain golden vector uses this canonical first event input
(without `eventId`):

```json
{"aliases":[{"scheme":"relayos-security-scan/v1","value":"SEC-ABC123"}],"createdAt":"2026-07-29T12:34:56.000Z","createdAtBasis":"source-revision-upper-bound","decisionLedger":"security-identity-access","evidenceRefs":[],"findingId":"atf_0d465ed12cdccf67f62645b4","occurrenceIds":["atocc_fe401c5bdff9b7bbde7c5fe6"],"relationship":"canonical","source":{"kind":"migration","name":"relayos-security-scan","version":"1"},"type":"identity-alias-reconciliation"}
```

Its event ID is `adev_070b9b350a2dde2bae75a794`. With
`previousEntryDigest: null`, the genesis entry digest is
`sha256:cf599f11d6339bf9460e2222c5159fde9a903fb675be1d14c5f8d8dcf2d4e1cf`.
The second event input deliberately has an earlier timestamp so that the
vector also proves chain order is not timestamp order:

```json
{"aliases":[{"scheme":"relayos-security-scan/v1","value":"SEC-OLDER-TIMESTAMP"}],"createdAt":"2026-07-01T00:00:00.000Z","createdAtBasis":"source-revision-upper-bound","decisionLedger":"security-identity-access","evidenceRefs":[],"findingId":"atf_0d465ed12cdccf67f62645b4","occurrenceIds":["atocc_fe401c5bdff9b7bbde7c5fe6"],"relationship":"canonical","source":{"kind":"migration","name":"relayos-security-scan","version":"1"},"type":"identity-alias-reconciliation"}
```

Its event ID is `adev_2ad52a2807387d80876f3807`. With the genesis digest
above as `previousEntryDigest`, its entry digest is
`sha256:38594e57db9ef22ff1fdab17f9a31a67d4f84f14ae9ec25c089ba13df2368d14`.
These literal outputs are always tested against the literal canonical inputs;
a production helper never generates the expected side of its own test.

Production hashing is not injectable. Duplicate and collision handling is
factored after independent recomputation into the pure registry seam:

```ts
interface AuditIdentityRecord {
  namespace: 'decision-event' | 'decision-entry' | 'comparison'
  id: string
  digest: `sha256:${string}`
  location: string
}

validateUniqueAuditIdentityRecords(
  records: readonly AuditIdentityRecord[],
): AuditDiagnostic[]
```

The same ID/digest twice is a duplicate, the same ID with a different digest
is a collision, and a prohibited digest under different IDs is a digest alias.
Tests exercise these states directly rather than weakening production hashing
or attempting an infeasible truncated-SHA collision fixture.

The storage API is:

```ts
loadAuditDecisionLedgers(root): AuditDecisionLedgerPortfolioResult
prepareAuditDecisionAppend(
  ledger,
  domain,
  slug,
  eventWithoutEventId,
): AuditDecisionAppendPlan
appendAuditDecision(
  root,
  slug,
  eventWithoutEventId,
): AuditDecisionAppendResult
```

Preparation is pure and returns canonical bytes plus either `append` or
`already-present`. Mutation takes the worktree audit lock, safely re-reads and
revalidates the current chain, recomputes the plan, and atomically replaces the
one ledger. The exact same deterministic event is the only idempotent no-op;
the same ID with different canonical event or digest is a collision.

Manual events use their actual recording time. Migrated events use a sealed
source timestamp when one exists; otherwise they use the phase-zero source
revision's committer time plus
`createdAtBasis: "source-revision-upper-bound"`. That time means "the decision
existed by this revision", not "the original reviewer acted at this instant".
Optional times such as `regression.observedAt` remain absent when the source
did not record them.

### Finding disposition event

```json
{
  "eventId": "adev_<24 hex>",
  "type": "finding-disposition",
  "findingId": "atf_...",
  "occurrenceId": "atocc_...",
  "action": "open | accepted-risk | separate-design | false-positive | remediated | superseded | reopened",
  "actor": "identity:reviewer@example.invalid",
  "owner": "identity-access",
  "reason": "<required>",
  "createdAt": "<RFC 3339>",
  "createdAtBasis": "recorded | source | source-revision-upper-bound",
  "expiresAt": "<action-specific RFC 3339, null, or omitted>",
  "reviewContext": {
    "observationId": "aobs_...",
    "bindings": [
      { "path": "apps/daemon/src/service.ts", "blob": "git-sha1:<hex>" }
    ],
    "ruleset": {
      "id": "atlas-security-v3",
      "digest": "sha256:<hex>"
    },
    "policyDigest": "sha256:<canonical review policy>"
  },
  "evidenceRefs": [],
  "proofs": [
    {
      "kind": "current-review | post-fix | source-evidence | replacement | deletion | no-replacement",
      "...": "<strict kind-specific members>"
    }
  ],
  "regression": {
    "kind": "test | guardrail | check | manual",
    "name": "<text>",
    "command": "<text>",
    "result": "passed | failed | not-run",
    "binding": {
      "repositoryRevision": "<full commit>",
      "observationId": "aobs_<optional>",
      "files": [
        { "path": "apps/daemon/src/service.ts", "blob": "git-sha1:<hex>" }
      ]
    },
    "observedAt": "<optional RFC 3339>"
  },
  "reviews": [
    {
      "reviewer": "<stable reviewer identity>",
      "verdict": "approve | reject",
      "reason": "<text>",
      "evidence": "<bounded reviewer evidence>",
      "evidenceRefs": [],
      "createdAt": "<RFC 3339>"
    }
  ],
  "actionEvidence": {},
  "supersedesEventId": "<action-specific earlier event id or omitted>"
}
```

This display example is a union of possible members. Runtime and TypeScript
contracts are closed, action-discriminated variants:

- `open` omits `expiresAt`, `regression`, and closing `actionEvidence`; it may
  supersede an earlier closure when explicitly reopening policy state;
- `reopened` omits expiry, requires `supersedesEventId` naming an earlier
  closing event for the same finding, and binds the new occurrence's
  `reviewContext`;
- `accepted-risk` and `separate-design` require a non-null `expiresAt`,
  `reviewContext`, and current-review proof;
- `false-positive` requires `expiresAt: null`, `reviewContext`, and structured
  `actionEvidence: { kind: "source-evidence", ... }`;
- `remediated` omits expiry, requires a revision-bound passing `regression`,
  post-fix proof, and
  `actionEvidence: { kind: "remediation", beforeBindings, afterBindings,
  fixRevision }`; and
- `superseded` omits expiry and requires exactly one strict action-evidence
  branch: a canonical `replacementFindingId` with replacement proof, or a full
  `deletionCommit` with bounded `noReplacementEvidence`.

Members from another action are rejected rather than ignored. `reviewContext`
bindings are a nonempty, unique, sorted set covering every authoritative
finding location for that occurrence, so one unqualified blob can never stand
for a multi-file finding. Its ruleset and policy digests describe the exact
context in which Atlas validated the decision, including a deterministic
migration validation context when the historical source predates Atlas.
Every explicit finding-disposition event, including `open`, `remediated`, and
`superseded`, requires this context. Implicit open has no event and therefore
needs none. A semantic-only Codex occurrence cannot receive a closing decision
or explicit acknowledgment until a later exact Atlas validation observation
provides a real ruleset and exact bindings; the importer never invents a Codex
ruleset.

Proofs are themselves closed unions (`current-review`, `post-fix`,
`source-evidence`, `replacement`, `deletion`, and `no-replacement`) with
kind-specific required fields. When a proof cites a source artifact it requires
the normalized source path, full repository revision, Git blob, SHA-256, and a
self-contained bounded conclusion; a path alone is invalid. Regression proof
always binds its command/result to a full repository revision and exact file
blobs. `observedAt` is optional because a migrated source may not have recorded
it.

The shared decision records are:

```ts
type AuditNonEmptyArray<T> = [T, ...T[]]

interface AuditBlobBindingV3 {
  path: string
  blob: `git-sha1:${string}` | `git-sha256:${string}`
}

interface AuditDecisionSourceArtifactV3 {
  path: string
  repositoryRevision: string
  gitBlob: `git-sha1:${string}` | `git-sha256:${string}`
  sha256: `sha256:${string}`
}

interface AuditRevisionBindingV3 {
  repositoryRevision: string
  observationId?: string
  files: AuditNonEmptyArray<AuditBlobBindingV3>
}
```

Every repository revision is a full commit ID in the repository's object
format. Binding arrays are nonempty, unique, and sorted by `(path, blob)`.
Every observation, finding, occurrence, path, and blob reference resolves
through the verified global history index.

The exact proof variants are:

```ts
type AuditDecisionProofV3 =
  | {
      kind: 'current-review'
      observationId: string
      reviewedBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      outcome: 'finding-present'
      summary: string
      sourceArtifact?: AuditDecisionSourceArtifactV3
    }
  | {
      kind: 'post-fix'
      beforeObservationId: string
      afterObservationId: string
      beforeBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      afterBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      fixRevision: string
      outcome: 'finding-absent-after-fix'
      summary: string
      sourceArtifact?: AuditDecisionSourceArtifactV3
    }
  | {
      kind: 'source-evidence'
      observationId: string
      reviewedBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      outcome: 'not-reportable'
      summary: string
      sourceArtifact?: AuditDecisionSourceArtifactV3
    }
  | {
      kind: 'replacement'
      observationId: string
      replacementFindingId: string
      replacementOccurrenceId: string
      replacementBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      outcome: 'replacement-tracks-root-cause'
      summary: string
      sourceArtifact?: AuditDecisionSourceArtifactV3
    }
  | {
      kind: 'deletion'
      deletionCommit: string
      parentRevision: string
      deletedBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      outcome: 'exact-source-deleted'
      summary: string
      sourceArtifact?: AuditDecisionSourceArtifactV3
    }
  | {
      kind: 'no-replacement'
      observationId: string
      searchRevision: string
      reviewedBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      outcome: 'no-reportable-replacement'
      summary: string
      sourceArtifact?: AuditDecisionSourceArtifactV3
    }
```

Migrated proofs require the sealed `sourceArtifact`; native Atlas proofs may
omit it. Current-review bindings equal the event review context. Post-fix
before bindings equal the reviewed occurrence; its after bindings and
`fixRevision` equal both remediation evidence and the passing regression.
Replacement occurrences belong to the named replacement finding. A deletion
parent contains every deleted binding and the deletion commit contains none of
those paths. A no-replacement observation targets `searchRevision` and covers
every reviewed binding.

The exact action-evidence variants are:

```ts
type AuditActionEvidenceV3 =
  | {
      kind: 'source-evidence'
      reviewedBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      conclusion: 'not-reportable'
      rationale: string
    }
  | {
      kind: 'remediation'
      beforeBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      afterBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      fixRevision: string
    }
  | {
      kind: 'replacement'
      replacementFindingId: string
      replacementOccurrenceId: string
    }
  | {
      kind: 'deletion'
      deletionCommit: string
      deletedBindings: AuditNonEmptyArray<AuditBlobBindingV3>
      noReplacementEvidence: {
        observationId: string
        searchRevision: string
        reviewedBindings: AuditNonEmptyArray<AuditBlobBindingV3>
        summary: string
      }
    }
```

The closed member/proof matrix is:

| Action | Expiry | Regression | Proofs | Action evidence | Supersedes |
| --- | --- | --- | --- | --- | --- |
| `open` | forbidden | forbidden | zero or more `current-review` | forbidden | optional earlier same-finding closure |
| `reopened` | forbidden | forbidden | one or more `current-review` | forbidden | required earlier same-finding closure |
| `accepted-risk` | required non-null | forbidden | one or more `current-review` | forbidden | forbidden |
| `separate-design` | required non-null | forbidden | one or more `current-review` | forbidden | forbidden |
| `false-positive` | required `null` | forbidden | one or more `source-evidence` | `source-evidence` | forbidden |
| `remediated` | forbidden | required passing | one or more `post-fix` | `remediation` | forbidden |
| `superseded` replacement | forbidden | forbidden | one or more `replacement` | `replacement` | forbidden |
| `superseded` deletion | forbidden | forbidden | at least one `deletion` and one `no-replacement` | `deletion` | forbidden |

Proof kinds from another row are invalid rather than supplemental prose.

`actor`, `owner`, and reviewer identities use lowercase NFC strings matching
`^[a-z0-9][a-z0-9._:@/+-]{0,127}$`; noncanonical input is rejected rather
than silently normalized. Equality is exact byte equality. Only
`verdict: "approve"` counts toward an independent-review minimum. Counted
reviewers are distinct from the event actor and accountable owner, contain
nonempty evidence when policy requires it, and count once even if multiple
receipts exist. Reject reviews remain auditable but never satisfy closure.

Derived state is the latest valid event in chain order, not the latest
timestamp. A current occurrence with no disposition event derives to implicit
`open`; policy may require an explicit closing decision, and an implicit open
is always blocking when `requireDisposition` is enabled. Producers do not
forge a human `open` event merely to make the chain nonempty.

Reduction never validates against one current observation alone. Loaders first
build a fail-closed global history/decision index:

```text
occurrenceId -> findingId, observationId, decisionLedger, exact file/blob bindings, ruleset
findingId    -> stable decisionLedger, every historical/current occurrence
eventId      -> decisionLedger, chain index, event digest
```

This permits decisions for remediated or superseded historical occurrences
without copying them into a current observation. Unknown references, identity
collisions, or the same finding owned by two decision ledgers invalidate the
decision portfolio; malformed events are never skipped.

The index API receives verified current wrappers as well as histories:

```ts
buildAuditDecisionIndex(currentLedgers, histories, decisionLedgers)
```

Every verified history entry remains reference-addressable, but the current
wrapper's referenced observation is the sole authoritative current
observation. Exactly one trailing history entry after that pointer is the
resumable history-ahead state produced by an interrupted publication. A
decision may already reference that trailing entry, but it does not drive
implicit state, automatic reopen, severity, expiry, or current lifecycle until
the current wrapper switches. On first publication, a slug with no current
wrapper may have exactly one genesis history entry; this is also history-ahead
and exposes no authoritative current observation. More than one trailing
entry, a current pointer that is not a history prefix, or current bytes that
differ from its referenced history entry invalidates the portfolio.

`reopened` must supersede a closing event. `remediated` requires a fix blob and
self-contained post-fix proof under policy. `false-positive` requires the exact
reviewed blob and rationale. `accepted-risk` and `separate-design` require an
expiry when policy demands one. High-risk independent review requirements are
policy checks, not comments.

A later reportable occurrence reconciled to a previously remediated,
false-positive, or superseded finding derives to blocking `reopened` even
before an acknowledgment event is appended. An accepted-risk or
separate-design decision may carry to a later occurrence only when its exact
review bindings still match, it is unexpired, and the policy/ruleset digests
match its recorded `reviewContext`. A changed blob or policy derives to
blocking `open`. An explicit
`reopened` event records acknowledgment; it is not required for Atlas to notice
the reappearance.

`proofs` carry every structured fact needed to validate a decision after a
legacy source artifact is deleted. A source-artifact path by itself is never
sufficient. Its Git blob and SHA-256 keep the raw bytes recoverable at the
recorded revision without making normal validation depend on that path.

Effective reduction returns an explicit provenance-bearing state:

```ts
interface AuditEffectiveFindingStateV3 {
  disposition:
    | 'open'
    | 'remediated'
    | 'accepted-risk'
    | 'separate-design'
    | 'false-positive'
    | 'superseded'
    | 'reopened'
  blocking: boolean
  derivation:
    | 'implicit-open'
    | 'explicit-event'
    | 'carried'
    | 'carry-invalidated'
    | 'automatic-reopen'
    | 'reconciliation-conflict'
  lifecycle: 'new' | 'persisting' | 'resolved' | 'reopened' | 'unknown'
  currentOccurrenceIds: string[]
  eventId: string | null
  basisEventIds: string[]
  expiresAt: string | null
  expiryState: 'not-applicable' | 'active' | 'warning' | 'expired'
  reopenAcknowledged: boolean
}
```

`currentOccurrenceIds` and `basisEventIds` are unique and sorted by UTF-16
code units. Reducers and renderers must not leak discovery, filesystem, or
insertion order through either array.

`eventId` is non-null only when one explicit disposition event directly
governs the effective finding state. This includes a terminal historical
`remediated` state with no current occurrence. `basisEventIds` records earlier
decisions used for carry, invalidation, merge, or automatic reopen. An
automatic reopen without an event has `eventId: null`, the prior closure IDs
in `basisEventIds`,
`disposition: "reopened"`, `blocking: true`, and
`reopenAcknowledged: false`. An explicit reopened event carries its own ID,
retains the closure ID as a basis, and acknowledges the reopen. A carried
acceptance has no new event ID and names the earlier acceptance as its basis.
Malformed or policy-invalid events invalidate reduction; they are not silently
converted into an open state. Expiry and later evidence drift are valid
effective-state changes and use the explicit invalidation derivation.

False-positive decisions for the same target may be rendered into a future
producer input as untrusted reviewer feedback. The prompt labels the material
as data, and the new validation phase must independently establish whether the
reason still applies.

### Scope retirement event

```json
{
  "eventId": "adev_...",
  "type": "scope-retirement",
  "decisionLedger": "security-runtime",
  "path": "apps/old.ts",
  "blob": "git-sha1:<hex>",
  "reason": "deleted | moved | superseded | staged-deletion | uncommitted-snapshot-absent",
  "retiredAt": "<RFC 3339>",
  "retiredAtPrecision": "timestamp | date",
  "originalRetiredDate": "<required YYYY-MM-DD when precision is date>",
  "actor": "<stable identity>",
  "createdAt": "<RFC 3339>",
  "createdAtBasis": "recorded | source | source-revision-upper-bound",
  "historyProof": {
    "slug": "security-runtime",
    "observationId": "aobs_...",
    "path": "apps/old.ts",
    "blob": "git-sha1:<hex>"
  },
  "deletionCommit": "<reason-specific full commit>",
  "successor": {
    "path": "apps/new.ts",
    "blob": "git-sha1:<same bytes>"
  },
  "evidenceRefs": [],
  "supersedesEventId": "<optional staged event>"
}
```

Retirement is two-phase: the old receipt remains in history, then a verified
retirement event proves why it no longer belongs to current scope. A missing
path without this event is drift, not a successful cleanup.

`audit retire` first appends `staged-deletion` when a tracked path is absent
from the worktree but no deletion commit exists. After the deletion is
committed it appends a `deleted` event that supersedes the staged event and
verifies the deleted blob and full deletion commit. A migrated
`uncommitted_snapshot_absent` fact normalizes to
`uncommitted-snapshot-absent` and retains its legacy proof; it never claims a
deletion commit.

Retirement is a strict reason-discriminated union. `staged-deletion` requires a
worktree/index absence proof and forbids a deletion commit.
`deleted` requires a full deletion commit and, when a matching staged event
exists, explicitly supersedes it without rewriting it. `moved` requires
`successor.path` and `successor.blob`; the successor must exist at the verified
revision and have exactly the retired blob bytes. `superseded` requires either
a validated successor or structured no-replacement proof.
`uncommitted-snapshot-absent` requires the sealed migration source proof and
forbids claims about a deletion commit. Every branch binds the retired
`(path, blob)` to an observation-history proof.

Every retirement event carries `decisionLedger`. The containing envelope slug,
that member, and `historyProof.slug` are equal. The home is the unique history
slug owning an exact reviewed `(path, blob)` receipt; it is not selected
lexicographically. Context-only `not-reviewed` receipts do not establish
ownership. Zero or multiple owning histories fail closed.

The reason-specific proof records are:

```ts
interface AuditRetirementHistoryProofV3 {
  slug: string
  observationId: string
  path: string
  blob: `git-sha1:${string}` | `git-sha256:${string}`
}

interface AuditStagedDeletionAbsenceProofV3 {
  kind: 'worktree-index-absence'
  headRevision: string
  headBinding: AuditBlobBindingV3
  indexState: 'absent'
  worktreeState: 'absent'
}

interface AuditDeletionCommitProofV3 {
  kind: 'git-deletion'
  parentRevision: string
  parentBindings: AuditNonEmptyArray<AuditBlobBindingV3>
  absentPaths: AuditNonEmptyArray<string>
}

interface AuditVerifiedTreeStateV3 {
  kind: 'git-tree-state'
  repositoryRevision: string
  presentBindings: AuditBlobBindingV3[]
  absentPaths: string[]
}

interface AuditMigrationSourceProofV3 {
  kind: 'sealed-migration-source'
  sourceArtifact: AuditDecisionSourceArtifactV3
  jsonPointer: string
  sourceReason: 'uncommitted_snapshot_absent'
  summary: string
}
```

The additional-member matrix is:

| Reason | Required | Forbidden |
| --- | --- | --- |
| `staged-deletion` | `absenceProof` | deletion commit/proof, successor, revision proof, migration proof, supersession |
| `deleted` | `deletionCommit`, `deletionProof`; `supersedesEventId` exactly when a matching active staged event exists | successor, revision proof, no-replacement proof, migration proof |
| `moved` | `successor`, `revisionProof` | deletion commit/proof, no-replacement proof, migration proof, supersession |
| `superseded` | exactly one successor branch or no-replacement branch, with `revisionProof` | deletion commit/proof, migration proof, supersession |
| `uncommitted-snapshot-absent` | `migrationSourceProof` | deletion commit/proof, successor, revision proof, no-replacement proof, supersession |

For staged deletion, `headBinding` equals the retired binding. A deleted
parent contains the retired binding and its proof's `absentPaths` contains the
retired path. A moved or successor proof contains the successor binding and
the retired path as absent; moved bytes equal the retired blob exactly. The
superseded no-replacement branch additionally carries a
`no-replacement` decision proof. All path arrays are unique and sorted, and
the present and absent sets are disjoint.

Date-only legacy retirements normalize to midnight UTC, set
`retiredAtPrecision: "date"`, and retain the exact source calendar date.
Timestamp precision is never invented.

### Reconciliation event

```json
{
  "eventId": "adev_...",
  "type": "finding-reconciliation",
  "comparisonId": "acmp_<24 hex>",
  "decisionLedger": "security-identity-access",
  "beforeOccurrenceIds": ["atocc_old"],
  "afterOccurrenceIds": ["atocc_new"],
  "outcome": "equivalent | distinct | uncertain",
  "confidence": "high | medium | low",
  "reason": "<root-cause comparison>",
  "source": {
    "kind": "grok-cli | codex-security | migration | manual",
    "name": "<bounded producer or actor>",
    "version": "<bounded version>",
    "sourceArtifact": "<optional sealed artifact ref>"
  },
  "createdAt": "<RFC 3339>",
  "createdAtBasis": "recorded | source | source-revision-upper-bound",
  "evidenceRefs": [],
  "supersedesEventId": "<optional earlier reconciliation correction>"
}
```

Only high-confidence `equivalent` groups affect lifecycle derivation.
`uncertain` remains visible and prevents automatic `resolved` or `reopened`
classification. Each occurrence appears in at most one confirmed group for a
comparison. Atlas supports one-to-many and many-to-one groups and rejects
many-to-many, empty, overlapping, duplicate, conflicting, or cyclic groups.

`comparisonId` deterministically binds the sorted before/after observation
sets, making the comparison boundary explicit instead of attempting to invert
occurrence IDs. A correction must have the same `comparisonId`, point to the
earlier active reconciliation event, and live later in the same chain. The
event's global home is the lexicographically smallest stable
`decisionLedger` among the indexed findings involved; the event is stored once
and the global index projects it to every endpoint. A many-to-one merge carries
a prior closure only when every applicable prior effective decision is
compatible and its review context remains valid; disagreement fails closed to
`open`/`unknown`.

Endpoint occurrence IDs resolve through the global index and define:

```text
boundary = {
  beforeObservationIds: sorted unique observation IDs,
  afterObservationIds: sorted unique observation IDs
}

comparisonId =
  "acmp_" + first24(sha256(
    "atlas-finding-comparison/v1" NUL
    canonicalJson(boundary)
  ))
```

Both arrays are nonempty and disjoint. Direction is identity-bearing. For the
literal boundary

```json
{
  "beforeObservationIds": ["aobs_111111111111111111111111"],
  "afterObservationIds": ["aobs_222222222222222222222222"]
}
```

the canonical boundary bytes are
`{"afterObservationIds":["aobs_222222222222222222222222"],"beforeObservationIds":["aobs_111111111111111111111111"]}`,
the full SHA-256 is
`49e952b6b12da976599461aa0be7eb52ce0c9495e89b02bf5671f7d33425c0d4`,
and the required ID is `acmp_49e952b6b12da976599461aa`.

Temporal and alias reconciliation share one closed source union:

```ts
type AuditReconciliationSourceV3 =
  | {
      kind: 'grok-cli' | 'codex-security' | 'migration'
      name: string
      version: string
      sourceArtifact?: AuditDecisionSourceArtifactV3
    }
  | {
      kind: 'manual'
      name: string
      version?: never
      sourceArtifact?: AuditDecisionSourceArtifactV3
    }
```

For manual sources, `name` is the canonical actor identity. No other source
members are accepted.

Legacy/provider aliases are a different fact and use a separate event:

```json
{
  "eventId": "adev_...",
  "type": "identity-alias-reconciliation",
  "decisionLedger": "security-identity-access",
  "aliases": [
    { "scheme": "relayos-security-scan/v1", "value": "SEC-ABC123" }
  ],
  "findingId": "atf_...",
  "occurrenceIds": ["atocc_..."],
  "relationship": "canonical | duplicate-of",
  "source": {
    "kind": "migration",
    "name": "relayos-security-scan",
    "version": "1"
  },
  "createdAt": "<RFC 3339>",
  "createdAtBasis": "recorded | source | source-revision-upper-bound",
  "evidenceRefs": []
}
```

Alias events preserve legacy identity-to-canonical mappings but do not by
themselves drive temporal lifecycle. Their home is the canonical finding's
stable decision ledger. Alias pairs and canonical endpoints are unique; a
single alias cannot name two canonical findings.

For one-to-many reconciliation, each after occurrence's exact bindings form a
nonempty partition of the prior reviewed bindings. For many-to-one, the union
of prior reviewed bindings equals the after occurrence bindings. New or changed
blobs prevent carry.

| Prior effective states | Many-to-one result |
| --- | --- |
| all `open` or `reopened` | `open`, persisting, blocking |
| all `accepted-risk` | carry only with the same owner, ruleset/policy digests, still-valid reviews, binding-union equality, and the earliest expiry |
| all `separate-design` | the same carry rule as accepted risk |
| all the same terminal closure (`remediated`, `false-positive`, or `superseded`) followed by a reportable occurrence | automatic `reopened`, blocking |
| different retained actions, different terminal actions, retained mixed with terminal/open, implicit undecided mixed with closure, or invalid context | `open`, lifecycle `unknown`, derivation `reconciliation-conflict`, blocking |

One-to-many applies the equivalent rule independently to every after
occurrence. Lifecycle `resolved` means only a valid `remediated` event with
post-fix proof and no later reportable confirmed equivalent. Mere absence never
resolves. Historical `false-positive` and `superseded` dispositions retain
their action but have temporal lifecycle `unknown`; a later reportable
equivalent still reopens them.

Published occurrence frontiers are computed by canonical `findingId` across
all observation histories, not independently per history slug. History-chain
order proves succession within one slug. When two histories leave unconnected
frontiers for the same finding and no temporal reconciliation proves their
order, reduction fails closed to blocking `open` with lifecycle `unknown`; it
must not restore an earlier terminal closure merely because both current
observations are now clean. Because one canonical finding ID is deterministic
identity, a reconciliation whose before/after finding-ID sets intersect is
valid only as high-confidence `equivalent`; `distinct`, `uncertain`, or
lower-confidence equivalent events contradict that identity and invalidate the
decision portfolio.

Derived labels are:

- `new`: no confirmed earlier equivalent;
- `persisting`: confirmed equivalent and previous derived decision remains
  open or accepted;
- `reopened`: a later reportable occurrence confirmed equivalent after a valid
  closing decision, whether or not an acknowledgment event exists;
- `resolved`: a closing event with post-fix evidence, never mere absence; and
- `unknown`: missing/partial semantic coverage or uncertain reconciliation.

The viewer may additionally show `reopenAcknowledged: true` when an explicit
`reopened` event exists. `audit check` gates on the derived `reopened` action,
not on acknowledgment, and remains blocking until a new valid closing decision
is appended.

## Review policy and generated coverage

Repo Atlas adopts the generic grammar currently implemented in RelayOS and
renames the owner-neutral format to `atlas-review-policy-v1`:

```json
{
  "formatVersion": 1,
  "format": "atlas-review-policy-v1",
  "rules": [
    {
      "id": "runtime-source",
      "include": ["apps/**/*.ts"],
      "except": ["apps/**/*.test.ts"],
      "rationale": "<why>",
      "domains": ["security"]
    },
    {
      "id": "documentation",
      "include": ["docs/**"],
      "rationale": "<why>",
      "excluded": {
        "category": "documentation",
        "reason": "<why>",
        "owner": "<optional generator/source>"
      }
    }
  ],
  "units": [
    {
      "domain": "security",
      "slug": "security-identity-access",
      "title": "Identity and access",
      "include": ["apps/daemon/src/identity/**"],
      "except": [],
      "context": [
        "packages/protocols/identity-access/**"
      ]
    }
  ],
  "securityDecisions": {
    "requireDisposition": true,
    "blockingActions": ["open", "reopened"],
    "drift": {
      "findingBearing": "blocking",
      "clean": "advisory",
      "unknown": "blocking"
    },
    "expiry": {
      "warningDays": 14,
      "requiredFor": ["accepted-risk", "separate-design"],
      "acceptedRiskMaximumDays": 90,
      "separateDesignMaximumDays": 90,
      "falsePositiveMustBeNull": true,
      "severityOverrides": [
        {
          "severities": ["critical", "high"],
          "maximumDays": 30,
          "minimumIndependentReviews": 2,
          "reviewEvidenceRequired": true
        }
      ]
    },
    "remediation": {
      "fixBlobRequired": true,
      "postFixProofRequired": true,
      "passingRegressionRequired": true,
      "allowedRegressionKinds": ["test", "guardrail", "check"]
    },
    "falsePositive": {
      "reviewedBlobRequired": true,
      "sourceEvidenceRequired": true
    },
    "superseded": {
      "replacementOrDeletionProofRequired": true,
      "existingPathRequiresCurrentReview": true
    },
    "retirement": {
      "historyProofRequired": true,
      "allowedReasons": [
        "deleted",
        "moved",
        "superseded",
        "staged-deletion",
        "uncommitted-snapshot-absent"
      ]
    },
    "acceptedRulesets": ["atlas-security-v3"]
  }
}
```

Accepted rulesets match only an exact `producer.ruleset.id` and its bound
digest. A migrated RelayOS observation may use the canonical
`relayos-security-v1` ID while preserving the source spelling
`relayos-secscan-v1` in provenance. Codex Security's
`identityBasis: "codex-contract"` is not a ruleset and is never relabeled as
one; Codex semantic evidence needs a later exact Atlas validation observation
before a disposition can close or carry it.

Expiry maximums are validated once against the event, using
`expiresAt - createdAt`, never against the moving check time. Otherwise an
initially invalid overlong acceptance could become valid merely by aging.
Effective-state evaluation treats `now >= expiresAt` as expired/blocking and
warns when `now < expiresAt <= now + warningDays`. A decision exactly at the
maximum duration is valid; a decision one instant beyond it is invalid.
Severity overrides use the finding severity bound by the indexed occurrence.

Rules classify every Git-tracked regular file as review-required or explicitly
excluded. Conflicts, unclassified paths, broad executable exclusions,
unowned generated executable files, unsafe glob syntax, unmatched units, and
duplicate IDs fail closed.

Unit `context` globs are optional supporting source, not coverage ownership.
Context files enter the producer snapshot and scope with
`status: "not-reviewed"` unless that same observation also owns and fully
reviews them. This preserves cross-file call/dataflow analysis without letting
one unit discharge another unit's obligation.

Policy may also carry the closed migration-only field
`historicalUnitAssignments`. It is never consulted by current inventory
classification or coverage:

```ts
interface AuditHistoricalUnitAssignmentV1 {
  id: string
  sourceKind: 'relayos-security-scan/v1'
  domain: 'security'
  unit: string
  include: string[]
}
```

The RelayOS migration uses exactly:

```json
[
  {
    "id": "relayos-retired-daemon-host",
    "sourceKind": "relayos-security-scan/v1",
    "domain": "security",
    "unit": "security-apps-runtime",
    "include": ["apps/cloud-daemon-host/**"]
  },
  {
    "id": "relayos-retired-edge-apps",
    "sourceKind": "relayos-security-scan/v1",
    "domain": "security",
    "unit": "security-apps-edge",
    "include": [
      "apps/cloudflare-marketplace-worker/**",
      "apps/cloudflare-sandbox-worker/**",
      "apps/daemon-edge/**",
      "apps/telemetry-gateway-worker/**",
      "apps/telemetry-tail-worker/**"
    ]
  },
  {
    "id": "relayos-retired-web",
    "sourceKind": "relayos-security-scan/v1",
    "domain": "security",
    "unit": "security-apps-product",
    "include": ["apps/web/**"]
  }
]
```

An assignment applies only to a sealed source row whose path is absent at the
validation revision and has a valid retirement. Its unit exists in the same
domain. Active rows and candidate records cannot use it, each assignment must
match at least one sealed row, and each otherwise-unassigned historical path
matches exactly one assignment. No pattern may match a current tracked path or
active receipt. The migration receipt seals both the expanded exact path set
and assignment digest. The Relay fixture is literal and must expand to
runtime 3, edge 30, product 25, total 58 with zero unmapped.

The implementation moves policy parsing, Git inventory, ledger joining,
summary calculation, canonical serialization, and self-proof handling from
RelayOS into Repo Atlas. It continues to emit
`atlas-review-coverage-v1`; changing the producer does not require a coverage
wire-format bump.

V3 contributes fresh evidence only for per-file receipts whose blob equals the
current worktree blob, status is `reviewed`, ledger slug equals the path's
policy-assigned unit, ruleset is explicitly accepted, and the producer supplied
the exact-read attestation required by that ruleset. Producer kind alone
neither grants nor denies coverage.

A migrated legacy receipt can count only when policy explicitly accepts its
ruleset and the migrator preserves the source schema's exact-blob, full-file
review attestation. It cannot discharge a different unit or turn 241 legacy
receipts into repository-wide completeness. Codex semantic imports with no
exact file receipts do not satisfy file coverage.

For compatibility evidence, `atlas-audit-v2`'s strict
`reviewState: "complete"` plus a complete exact `hashes` map is its schema-owned
full-read attestation. V1 has no equivalent closed-world attestation and never
contributes fresh coverage directly; a V1-derived source must first migrate to
V3 with an independently validated explicit attestation. Hash presence alone
is not promoted into `fullRead: true`.

The unchanged `atlas-review-coverage-v1` wire records SHA-1 blobs. On a
SHA-256-object-format repository, policy loading and V3 evidence remain
readable but coverage update/check fail closed with
`unsupported-object-format` before writing; supporting that repository in
generated coverage requires a later coverage wire revision rather than
silently widening V1.

Coverage generation distinguishes:

- missing/stale/invalid review evidence;
- security/test/dual-domain requirements;
- exclusions;
- invalid ledgers;
- exact drift that is advisory versus blocking under policy.

Finding decisions remain a separate assurance state. An exact reviewed blob
can be fresh while its finding is open, expired, or otherwise blocking.
`audit check` composes both gates and reports both failures; it never rewrites
exact evidence status to hide a lifecycle problem.

`review-coverage.json` is generated last. A crash therefore understates
coverage. The self-referential coverage file uses the existing reserved
generated-proof exclusion and exact canonical regeneration. An invalid
classification or evidence join still serializes a structurally valid,
deterministic `verdict: "invalid"` report for inspection, atomically replaces
stale complete bytes, and returns failure; `allowIncomplete` never relaxes it.
On first generation an untracked coverage path is outside the tracked
inventory. Once tracked, the next generation includes the reserved self entry.
Inventory rejects index/worktree executable-bit drift and uses the
locale-independent collision key `NFC(path).toLowerCase()` after requiring the
stored path itself to be NFC.

## First-party Grok producer

### Explicit invocation only

Only this command launches Grok:

```text
repo-atlas audit run security --provider grok \
  [--unit <slug> | --all | --stale] \
  [--model <id>] [--concurrency <n>] \
  [--resume <atlas-run-id>] [--json]
```

An external AI orchestrator may invoke the command, but it does not need to
invent prompts or spawn scanner subagents. Repo Atlas owns the phase graph and
starts one bounded Grok process per unit/phase. Grok itself runs with
`--no-subagents`.

`--all` and broad repository scans require an explicit flag. Default behavior
is one named unit or stale units from policy. Concurrency is bounded by policy
and defaults to the smaller of four and available CPUs.

### Isolated execution environment

For every Atlas run:

1. resolve the Grok executable and record its binary/version before changing
   the environment;
2. create a mode-0700 temporary home and session root outside the repository;
3. authenticate with an explicit API-key environment where available, or copy
   only the existing Grok authentication record into the temporary home with
   mode 0600; never copy config, hooks, plugins, MCP, memory, or sessions;
4. create a byte-copy snapshot of the exact unit-owned and policy-declared
   context worktree files; do not use hardlinks; make snapshot files read-only;
5. run `grok inspect --json` in the same temporary environment and snapshot;
6. reject executable hooks, plugins, MCP servers, project instructions,
   unexpected permission sources, or a changed effective configuration unless
   their canonical digest is explicitly approved in
   `.atlas/audit-providers.json`;
7. run Grok with an isolated leader socket and session ID; and
8. parse and validate the session transcript before deleting the temporary
   home and snapshot.

Credentials, credential digests, and credential-bearing environment values
never enter logs, observations, error messages, or migration receipts.

The original repository is hashed before and after the run. Any changed
tracked byte aborts finalization. The disposable snapshot protects the
original from normal tool writes; configuration isolation and transcript
validation protect against ambient extensions. Atlas reports that this is an
application-level boundary, not an OS security sandbox.

### Grok flags

The 0.2.82 adapter uses the semantic equivalent of:

```text
grok --single \
  --no-plan \
  --permission-mode dontAsk \
  --tools Read,Grep,Glob \
  --no-memory \
  --no-subagents \
  --disable-web-search \
  --output-format streaming-json \
  --session-id <uuid> \
  --cwd <snapshot> \
  --prompt-file <generated-prompt>
```

It never uses `--always-approve`, `bypassPermissions`, Bash, write/edit tools,
web tools, memory, MCP, plugins, or model-managed subagents.

The adapter probes `--help`, `--version`, and `inspect --json`. A CLI version
whose flags, transcript events, tool names, session layout, or permission
semantics differ is unsupported until its adapter is updated. Provider
compatibility is a versioned contract, not a best-effort shell command.

Grok `--json-schema` is not used for analytical phases. Local experiments
showed that schema-constrained responses could return structurally valid
answers without performing source reads. Atlas instead requires ordinary
tool-using analysis, then parses a bounded final JSON block and independently
validates it.

### Phase graph

```text
policy + exact source snapshot
             |
             v
       threat model
             |
             v
  parallel bounded discovery
             |
             v
 deterministic candidate identity/dedupe
             |
             v
 independent validation + attack path
             |
             v
 deterministic reconciliation/finalization
             |
             v
 history -> current -> coverage
```

Threat modeling identifies assets, trust boundaries, attacker capabilities,
objectives, assumptions, and semantic surfaces. Discovery traces inputs,
controls, transformations, sinks, and outcomes across files; it is not reduced
to one prompt per file. Unit policy supplies a bounded file inventory while
concept-level review preserves cross-file behavior.

Every candidate receives one terminal validation disposition:
`reportable`, `suppressed`, `not_applicable`, or `deferred`. The fact checker
receives the candidate, exact source snapshot, threat model, and rubric, but
not the discovery model's hidden reasoning or transcript. It must construct
its own evidence trace.

Reconciliation is deterministic for exact aliases and explicit duplicate maps.
Semantic historical matching may invoke a separate restricted Grok comparison,
but its output is only a proposed reconciliation event and must obey the
one-to-many, uniqueness, confidence, and uncertainty constraints.

### Transcript proof

Streaming stdout is progress, not evidence. The adapter reads the isolated
session's `chat_history.jsonl` and requires:

- one successful terminal result;
- only the allowed read/grep/glob tools;
- no write, shell, network, MCP, memory, subagent, or unknown tool call;
- every tool path contained in the snapshot;
- successful tool results linked to their tool-call IDs;
- complete line-range coverage for every file claimed `reviewed`;
- no tool error hidden by a later prose claim;
- a final response within size/depth bounds; and
- source blobs unchanged from the snapshot inventory.

A raw tool-call count is insufficient. A `Read` call with an offset/limit must
prove the returned range; repeated partial reads are unioned only when
contiguous coverage is established.

Malformed JSON, a zero-read response, missing transcript, unsupported event,
partial scope, timeout, budget exhaustion, killed process, changed file,
unknown tool, or failed validation remains a clone-local failed attempt. It
cannot update history, current V3, decisions, or coverage.

### Resume

Atlas owns resume at the phase/unit boundary. Completed phase outputs in the
clone-local journal are content-addressed by source snapshot, prompt digest,
provider version, and effective config. A changed input invalidates them.

Atlas never tells Grok to resume an opaque conversation after source or prompt
drift. `--resume <atlas-run-id>` reuses only independently validated phase
receipts and starts fresh sessions for missing phases.

## Codex Security adapter

```text
repo-atlas audit import codex-security <scan-dir> \
  --slug <unit-slug> \
  [--title <title>] \
  [--concept <concept-slug>] \
  [--apply] [--json]
```

Dry-run is the default. `--apply` writes history and current projection after
all checks pass.

The adapter accepts only a completed, sealed Codex Security bundle whose three
canonical documents use schema 1.0. It:

1. opens the scan directory and artifacts without following symlinks;
2. enforces regular-file, containment, path, size, count, and JSON depth
   limits;
3. validates `scan-manifest.json`, `findings.json`, and `coverage.json`;
4. validates matching scan IDs, target/scope invariants, artifact seals, and
   every referenced coverage receipt;
5. recomputes Codex fingerprint, finding ID, and occurrence ID formulas;
6. verifies code-evidence references, paths, lines, and available snippets;
7. maps every stable field into V3 and preserves bounded unknown properties;
8. computes Atlas identities without equating them to Codex identities;
9. records semantic coverage exactly as produced; and
10. sets exact coverage only when Atlas independently possesses exact per-file
    blob receipts.

Every imported source path is a safe repository-relative path. A finding must
have at least one location matched by the declared Codex scope, as required by
the upstream scan workflow; additional supporting locations and code evidence
may be elsewhere in the same repository and are retained. Supporting evidence
outside the requested scope is not rejected merely for being supporting
context.

Artifact seals are checked against the exact bounded raw bytes returned by the
same descriptor-anchored core reader used for audit state. For JSON documents,
one read returns both the bytes to hash and the strictly parsed value to map.
Parsing and canonical reserialization never stand in for a producer byte seal,
and the adapter never reopens a pathname after a safety check.

Atlas intentionally applies a stricter resource policy than Codex Security's
maximum wire allowances: each imported canonical JSON document is limited to
the core 32 MiB byte cap, each preserved extension value to 64 KiB, and the
canonical V3 ledger to 1 MiB unless repository policy explicitly raises that
output bound. Codex permits a findings document up to 128 MiB; an otherwise
valid bundle above Atlas's configured limit fails with an explicit limit
diagnostic. No input, extension, snippet, or finding is silently truncated.

All completed Codex target/mode combinations can be represented. A diff,
directory snapshot, branch, working-tree, deep-repository, or custom inventory
does not fail merely because it cannot satisfy current exact coverage. Its
semantic evidence remains useful and is labeled honestly.

### Codex 1.0 coverage matrix

| Codex field | Atlas V3 treatment |
| --- | --- |
| producer, timestamps, target, scope | first-class receipts; exact source timestamps/refs retained in `sourceContract` |
| threat model | first-class threat model |
| hardening portfolio | producer-manifest artifact only when listed; otherwise adapter-bundle metadata; content not copied |
| manifest artifacts/seals | integrity-kind-aware observation inventory; content not copied by default |
| finding/occurrence IDs | verified provider aliases in provenance |
| rule, anchor, instance, fingerprint | first-class identity + producer alias |
| title, summary | first-class |
| severity score/system/vector/rationale/change conditions | first-class |
| confidence level/rationale | first-class |
| category/CWE | first-class taxonomy |
| locations and roles | first-class structured locations |
| code evidence | first-class bounded snippets; exact-blob only when independently joined, otherwise sealed-producer-snippet |
| root cause | first-class normalized structure |
| remediation | first-class |
| validation | documented fields first-class; bounded unknowns preserved |
| attack path | documented fields first-class; bounded unknowns preserved |
| remediation tests/preventive controls | first-class |
| provenance/extensions | first-class provenance + namespaced extensions |
| detailed write-up path | producer-manifest or adapter-bundle external ref according to actual source integrity; body excluded |
| coverage mode/completeness/inventory | first-class semantic coverage |
| surfaces/dispositions/receipt refs | first-class |
| explicit exclusions/deferred/open questions | first-class |

### Normative Codex 1.0 adapter appendix

The adapter targets document type/schema pairs exactly:

```text
codex-security.scan-manifest / 1.0
codex-security.findings      / 1.0
codex-security.coverage      / 1.0
```

The complete known-key inventory is normative:

- manifest root: `documentType`, `schemaVersion`, `scan`;
- `scan`: `id`, `producer`, `status`, `startedAt`, `completedAt`, `sealedAt`,
  `target`, `scope`, `threatModel`, `hardening`, `coverageRef`,
  `findingsRef`, `artifacts`;
- `producer`: `name`, `version`;
- `target`: `kind`, `targetId`, `displayName`, `remote`, `revision`,
  `baseRevision`, `headRevision`, `snapshotDigest`;
- `scope`: `includePaths`, `excludePaths`, `summary`,
  `artifactsReviewed`, `runtimeStatus`, `validationMode`, `context`,
  `limitations`;
- `threatModel`: `summary`, `assets`, `trustBoundaries`,
  `attackerCapabilities`, `securityObjectives`, `assumptions`;
- `hardening`: `portfolioPath`;
- each manifest artifact: `path`, `sha256`, `mediaType`;
- findings root: `documentType`, `schemaVersion`, `scanId`, `findings`;
- each finding: `findingId`, `occurrenceId`, `ruleId`, `identity`,
  `fingerprints`, `title`, `summary`, `severity`, `confidence`, `taxonomy`,
  `locations`, `writeup`, `codeEvidence`, `rootCause`, `remediation`,
  `validation`, `attackPath`, `remediationTests`, `preventiveControls`,
  `provenance`, `extensions`;
- `identity`: `anchor`, `instance`;
- `fingerprints`: `algorithm`, `primary`;
- `severity`: `level`, `score`, `scoringSystem`, `vector`, `rationale`,
  `changeConditions`;
- `confidence`: `level`, `rationale`;
- `taxonomy`: `category`, `cwe`;
- each location: `path`, `startLine`, `endLine`, `role`;
- `writeup`: `reportPath`;
- each code-evidence item: `id`, `label`, `path`, `startLine`, `endLine`,
  `language`, `role`, `code`, `explanation`;
- object root cause: `summary`, `evidenceRefs`, `code`, `language`;
- documented validation semantics: method, disposition, summary, confidence,
  confidence rationale, evidence refs/assertions/evidence,
  counterevidence/proof gap, remaining uncertainty, limitations, and artifact
  refs;
- documented attack-path semantics: summary, dataflow, reachability, evidence
  refs, impact, likelihood, and limitations, including their source,
  transformation, sink, outcome, attacker, entrypoint, access, and
  precondition members;
- `provenance`: `source`;
- `extensions`: `candidateId`, `ledgerRowId`, `reportId`;
- coverage root: `documentType`, `schemaVersion`, `scanId`, `mode`,
  `completeness`, `inventoryStrategy`, `includePaths`, `excludePaths`,
  `surfaces`, `explicitExclusions`, `deferred`, `openQuestions`;
- each surface: `id`, `label`, `disposition`, `receiptRefs`, `riskArea`,
  `notes`;
- each explicit exclusion: `pattern`, `reason`;
- each deferred item: `id`, `reason`, `paths`, `surfaceIds`; and
- each open question: `question`, `followUpPrompt`.

For every JSON pointer represented by those keys, the matrix above specifies a
first-class destination or an explicit sealed-artifact/content exclusion.
Any other schema-permitted property is a bounded namespaced extension; failure
to retain it is an import error.

The exact identity checks are:

```text
codexFingerprint =
  "codex-security/v1:sha256:" + sha256(
    [
      "codex-security/v1",
      manifest.scan.target.targetId,
      finding.ruleId,
      finding.identity.anchor,
      finding.identity.instance or ""
    ].join(NUL)
  )

codexFindingId =
  "csf_" + first24(sha256(codexFingerprint))

codexOccurrenceId =
  "occ_" + first24(sha256(
    [manifest.scan.id, codexFingerprint].join(NUL)
  ))
```

The adapter requires `fingerprints.algorithm == "codex-security/v1"` and
`fingerprints.primary == codexFingerprint`, plus exact finding and occurrence
IDs. It validates all manifest artifact seals before trusting referenced
content. `scan-manifest.json` is the seal index and is not falsely described as
self-sealed.

The following Codex workbench data is intentionally outside the sealed bundle
and is not imported as an observation: raw candidates, ranking shards, worker
state, progress, private prompts, session transcripts, SQLite workbench state,
hooks, full source archives, report projections, SARIF/CSV, and full PoCs.
Atlas has its own history, decisions, and reconciliation model for the durable
facts represented by Codex's workbench.

## RelayOS legacy migration adapter

Repo Atlas ships a generic, explicitly named migrator:

```text
repo-atlas audit migrate relayos-security-v1 \
  --scan-root audits/security-scan \
  --policy .atlas/review-policy.json \
  [--include-history] \
  [--apply] [--json]

repo-atlas audit migrate relayos-root-audits-v1 \
  --audits-root audits \
  --source-revision <phase-zero-full-commit> \
  --design-ledgers .atlas/audits \
  --historical-artifacts .atlas/artifacts/historical-audits \
  [--apply] [--json]
```

It is implemented in Repo Atlas, not copied into RelayOS. Dry-run is the
default. The detailed source-to-target mapping and deletion sequence live in
the RelayOS migration design, while the adapter itself is tested with fixtures
and remains usable for that historical schema.

The migrator emits:

- per-policy-unit V3 history entries preserving every per-file scan record;
- per-policy-unit current projections derived from non-retired current blobs;
- V3 findings and provider aliases for every canonical candidate;
- append-only decision and retirement events;
- a migration receipt with exact inputs, counts, mappings, outputs, parity
  checks, zero/unmapped items, and safe-to-delete paths.

The security migrator discovers and validates the known ledger, candidates,
dispositions, phase-zero provenance, imports, reconciliation indexes, and every
referenced current/post-fix artifact under `--scan-root`. An unexpected
canonical input or unreferenced field fails closed.

Migration observations set semantic coverage to `unknown`; they do not invent
surface closure. Exact legacy receipts can count only under the explicit
ruleset/unit/attestation rules above. Files are partitioned by policy unit so a
history or current document remains under the standard size bound; splitting
never truncates a record.

Within each migrated decision ledger, append order is deterministic:

1. scope-retirement events sorted by `(retiredAt, path, blob)`;
2. identity-alias reconciliation events sorted by `(scheme, value, findingId)`;
3. temporal reconciliation events sorted by
   `(comparisonId, beforeOccurrenceIds, afterOccurrenceIds)`;
4. finding-disposition events sorted by legacy finding ID; and
5. any remaining bounded extension event sorted by `(type, eventId)`.

The type order is migration serialization, not a claim that the original human
decisions occurred in that order. `createdAt` therefore need not be monotonic.
Original source timing remains in event provenance when available.

The root-audits migrator seals and projects historical reports and verifies
existing design-ledger parity. Product-specific egress-policy relocation
remains an ordinary reviewed RelayOS edit, but its before/after paths and seals
enter the receipt. `--source-revision` is a required full commit and supplies
pre-move Git blobs when an old path no longer exists in the worktree. Neither
migrator deletes source files.

## Migration receipt

```json
{
  "formatVersion": 1,
  "format": "atlas-audit-migration-v1",
  "migrationId": "amig_<24 hex>",
  "source": {
    "kind": "relayos-security-scan/v1",
    "repositoryRevision": "<full commit>",
    "files": [
      {
        "path": "audits/security-scan/ledger.json",
        "gitBlob": "<hex>",
        "sha256": "<hex>"
      }
    ]
  },
  "converter": {
    "name": "repo-atlas",
    "version": "<version>",
    "commit": "<full commit>"
  },
  "recordedAt": "<source-revision committer time, RFC 3339>",
  "recordedAtBasis": "source-revision",
  "counts": {},
  "mappings": [],
  "unmapped": [],
  "outputs": [
    {
      "path": ".atlas/audits/security-apps-daemon.json",
      "sha256": "<hex>"
    }
  ],
  "parityChecks": [
    {
      "name": "all dispositions represented",
      "status": "passed",
      "details": "<bounded text>"
    }
  ],
  "safeToDelete": [],
  "receiptDigest": "sha256:<hex>"
}
```

`unmapped` must be empty before `--apply` succeeds. `safeToDelete` is an
informational, exact-path list and does not authorize deletion. Counts and
histograms are recomputed from source bytes; README numbers are never inputs.

The receipt filename is exactly `<migrationId>.json`, where:

```text
migrationId =
  "amig_" + first24(sha256(
    "atlas-migration/v1" NUL
    source.kind NUL
    source.repositoryRevision NUL
    converter.name NUL
    converter.version NUL
    converter.commit NUL
    canonicalJson(sorted source.files path/gitBlob/sha256 tuples)
  ))
```

`receiptDigest` is SHA-256 over RFC 8785 canonical receipt JSON excluding only
`receiptDigest`. Migration receipts contain no wall-clock execution fields;
clone-local journals may record operational timing. `recordedAt` is the sealed
source revision's committer time, so dry-run and apply over unchanged inputs
propose identical IDs, receipt bytes, and output digests.

## CLI surface

```text
repo-atlas audit status [--json]
repo-atlas audit check [--strict-stale] [--allow-incomplete] [--json]
repo-atlas audit run security --provider grok ...
repo-atlas audit import codex-security <scan-dir> ...
repo-atlas audit migrate relayos-security-v1 ...
repo-atlas audit policy check [--json]
repo-atlas audit coverage update [--json]
repo-atlas audit coverage check [--allow-incomplete] [--json]
repo-atlas audit decision set <finding-or-occurrence> ...
repo-atlas audit reconcile <before> <after> ...
repo-atlas audit retire <path> ...
repo-atlas audit retire --finalize-staged ...
repo-atlas audit localization input --locale <locale>
repo-atlas audit localization check
```

`audit check` is the deterministic superset gate. It validates schemas,
containment, canonical bytes, history and decision chains, current/history
equality, identities, code-evidence references, decision policy, migration
receipts, exact freshness, and canonical coverage regeneration. It never
contacts a provider. Its `--allow-incomplete` has the same narrow coverage
meaning described below; it never relaxes finding, decision, retirement,
canonicality, or policy errors.

`audit coverage update` is the only command that rewrites generated review
coverage. `audit coverage check` regenerates in memory and byte-compares.
`--allow-incomplete` still rejects invalid canonical bytes, policy errors,
unclassified/conflicted paths, invalid ledgers, inventory drift, and bad
self-proof; it changes only honest missing/stale evidence from a nonzero exit
to a reported rollout state. The flag is for staged adoption and is visible in
text and JSON output.

Subcommand ownership is explicit:

| Command | Input | Output |
| --- | --- | --- |
| `audit import codex-security` | sealed external bundle | V3 semantic observation |
| `audit import legacy-v1` | old Atlas `scans[]` ledger | compatibility V1 |
| `audit migrate relayos-security-v1` | known RelayOS scan root | per-unit V3/history/decisions/receipt |
| `audit migrate relayos-root-audits-v1` | known RelayOS root audit set | bounded artifacts/design parity/receipt |

Deprecated flat aliases exist for one minor release:

- `audit-stamp` -> `audit stamp`;
- `audit-import` -> `audit import legacy-v1`;
- `audit-localization-input` -> `audit localization input`; and
- `audit-localization-check` -> `audit localization check`.

## Locks, writes, and recovery

Locks live outside tracked `.atlas`, keyed by real worktree path. Mutating
commands acquire:

1. one repository audit-state lock; and
2. sorted per-ledger locks when more granular work is required.

Stale locks contain PID, host, process start time, command, and source
snapshot. Atlas verifies process liveness before offering recovery.

Every write uses a sibling temporary file created with exclusive mode, fsync,
rename, and directory fsync where supported. Files are committed in this
order:

1. history append;
2. decision/reconciliation append;
3. current ledger;
4. bounded viewer artifacts/localizations;
5. migration receipt, when applicable; and
6. generated review coverage.

An operation journal records intended digests outside the repo. On restart,
Atlas either finishes a digest-matching transaction or reports precise repair
steps. It never rolls back user files or infers that a partially written state
is complete.

## Viewer and localization

The Security portfolio keeps V1/V2 behavior and adds:

- separate exact and semantic coverage panels;
- producer, target, prompt/ruleset, and configuration provenance;
- threat model and reviewed surfaces;
- stable finding and occurrence identities with provider aliases;
- structured root cause, validation, attack path, code evidence, severity
  calibration, remediation tests, and preventive controls;
- current decision, expiry, reviewers, remediation proof, and regression;
- new/persisting/resolved/reopened/unknown lifecycle labels; and
- history and reconciliation receipts.

Zero findings renders as "No reportable findings in this evidenced scope."
Missing, stale, partial, unknown, or deferred coverage remains visually
prominent.

Localization digests include all reader-facing canonical prose but not code
snippets, paths, IDs, commands, hashes, or producer extension JSON. A changed
source digest invalidates the derived locale as today.

## Limits and hostile-input handling

All loaders use shared limits before allocating deeply:

- document size, array member count, object member count, nesting depth, and
  string length;
- at most 256 MiB of unique exact Git-blob bytes per V3 state-load operation,
  with one descriptor-verified read cached per canonical blob ID across current
  wrappers and history entries;
- unique normalized paths and IDs;
- regular-file and file-descriptor identity checks;
- bounded canonicalization;
- finite numbers only, with every integer-valued durable JSON number inside
  the safe-integer domain so programmatic publication and bounded disk parsing
  accept the same values;
- no prototype keys;
- no remote credentials/query/fragments;
- no source-root replacement or symlink traversal; and
- exact schema/version dispatch.

Errors carry stable codes and JSON pointers but do not echo credentials,
unbounded producer prose, source snippets, or absolute private scan paths.

### Filesystem threat boundary

The V3 audit-state reader/writer and lock backend requires Linux with an
available `/proc/self/fd` filesystem. Other Repo Atlas features remain
portable, but V3 state operations fail before creating directories,
temporaries, targets, or locks when this capability is unavailable. The CLI
and README report this requirement explicitly; RelayOS CI and migration run on
that supported backend.

Descriptor anchoring protects against untrusted repository paths, symlinks,
parent replacement, and path races before a kernel operation. It does not
claim to confine an already-open directory inode against a malicious
same-credential process that renames that exact inode outside the repository
during the final kernel mutation. Linux exposes no atomic
"rename only while this open directory remains beneath that root" primitive
through Node. Atlas detects the relocation immediately after the operation and
fails, but the relocated inode may contain the completed atomic replacement.
This actor already has direct write/rename authority over both locations and
is outside the repository-content threat model. Atlas must never follow a
replacement symlink or mutate a different outside inode, even in this race.

## Test strategy

### Schema and identity

- valid V1/V2/V3 mixed portfolios;
- strict V3 required/optional fields and canonical digest fixtures;
- Atlas/Codex identity formula golden vectors;
- duplicate/collision/mismatch rejection;
- unknown-field preservation or explicit bounded failure; and
- code-evidence line/blob/reference validation.

### History and decisions

- append-only chain, current/latest equality, merge damage, duplicate events;
- every disposition transition and expiry;
- two-reviewer high-risk policy;
- remediation/regression proof;
- path retirement and moved successor;
- one-to-many/many-to-one reconciliation;
- uncertain matches never imply resolution; and
- false-positive feedback is rendered as untrusted data.

### Coverage and policy

- port all RelayOS policy, path, ledger, coverage, hostile-input, and canonical
  byte tests before deleting their original implementation;
- dirty tracked bytes, index/worktree disagreement, symlinks, non-UTF-8 paths,
  executable exclusions, conflicts, unclassified paths, and self-proof;
- V1/V2/V3 evidence join;
- semantic completion never satisfies exact coverage; and
- advisory versus blocking clean drift.

### Grok producer

- fake Grok binaries for every supported event and failure;
- isolated home contains only approved auth/config;
- preflight rejects hooks/plugins/MCP/instructions/permission drift;
- exact flags and no dangerous tool capabilities;
- transcript tool-call/result linkage and full-range reads;
- partial/failed/zero-read/unknown-tool/timeouts never publish;
- source mutation and snapshot mismatch;
- independent discovery/fact-check context;
- resume invalidation; and
- redaction of auth and environment values.

One opt-in live smoke test may run only when credentials and an explicit
environment flag are present. CI never spends model credits by default.

### Codex adapter

- official completed-scan fixtures;
- every field in the coverage matrix;
- seals, IDs, snippets, receipt refs, unknown properties, and size limits;
- every target and coverage mode;
- symlink, traversal, non-regular, descriptor race, remote credential, malformed
  JSON, and seal mismatch adversarial fixtures; and
- no absolute scan path or sensitive raw artifact copied into `.atlas`.

### RelayOS migration fixtures

- all legacy scan statuses, retirements, candidates, duplicate map shapes,
  dispositions, expiry, high-risk reviews, post-fix scans, regression receipts,
  and missing/malformed links;
- exact count/histogram parity;
- deterministic output and dry-run;
- zero unmapped requirement; and
- source tree never deleted or modified by the adapter.

## Delivery sequence

1. Add V3 types, canonical JSON, hostile-input primitives, history, decisions,
   and tests without changing existing V1/V2 behavior.
2. Port generic review-policy and coverage generation from RelayOS, retaining
   `atlas-review-coverage-v1`.
3. Add deterministic `audit check`, hierarchical CLI aliases, and viewer
   support.
4. Add the Codex Security adapter and full field matrix tests.
5. Add the isolated Grok provider behind explicit `audit run`.
6. Add the RelayOS legacy migrator and fixtures.
7. Release and pin Repo Atlas in RelayOS.
8. Run RelayOS dry migration, parity gates, and canonical regeneration.
9. Switch RelayOS CI to Repo Atlas commands.
10. Delete verified redundant RelayOS scripts and root audit artifacts in a
    separate, reviewable cleanup commit.

No cleanup happens before parity. At each stage deterministic commands remain
LLM-free and old ledgers remain readable.

## Acceptance criteria

- V3 is a semantic superset of the V2 security model, RelayOS legacy security
  evidence, and the documented stable Codex Security 1.0 contract.
- Every Codex 1.0 field maps first-class, is retained as a bounded extension,
  or is explicitly excluded by this design.
- Grok runs only through explicit `audit run`, in an isolated configuration and
  source snapshot, with transcript-proven read coverage.
- Failed model attempts cannot update canonical evidence or coverage.
- Exact and semantic coverage remain separate in data, gates, and UI.
- History, decisions, retirement, and reconciliation are append-only and
  independently auditable.
- Consumer repositories need no generic audit scripts or root `audits/`
  implementation directory.
- RelayOS can migrate every verified legacy fact with zero unmapped records and
  preserve its current enforcement semantics before deletion.
- V1/V2 compatibility and all pre-existing Repo Atlas tests remain intact.
