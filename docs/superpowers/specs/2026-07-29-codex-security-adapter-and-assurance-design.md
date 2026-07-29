# Codex Security adapter and two-axis assurance design

Date: 2026-07-29
Status: proposed

## Context

Repo Atlas already treats security as an assurance portfolio rather than a
finding counter. Its two existing inputs answer:

1. `.atlas/audits/*.json`: what an audit unit found in the exact bytes it
   reviewed;
2. `.atlas/review-coverage.json`: whether current Git-tracked files are
   completely classified and backed by current exact-blob evidence.

OpenAI's public `codex-security` repository adds a useful third kind of
evidence. A completed scan has a sealed, versioned contract:

- `scan-manifest.json` binds producer, target, scope, threat model, artifact
  hashes, and completion;
- `findings.json` carries stable semantic identities, calibrated confidence,
  CWE taxonomy, validation, attack-path analysis, and remediation proof;
- `coverage.json` records reviewed security surfaces, exclusions, deferred
  work, and open questions.

That contract is richer than `atlas-audit-v2`, but its coverage claim answers a
different question. `coverage.completeness: "complete"` means the producer
finished its requested semantic workflow. It does not, by itself, prove the
exact current Git blob for every file in the requested scope. Atlas must not
translate one claim into the other.

The scanner is also an expensive, stateful, pre-1.0 external producer. Test
scans against Repo Atlas reached a nominal USD 1 cost cap without completing;
in-flight requests allowed the final reported cost to exceed the cap slightly.
The incomplete runs produced useful threat-model context but no sealed
findings/coverage bundle that Atlas could safely accept. This makes the scanner
unsuitable for Atlas's normal build, serve, status, or pre-commit path.

## Decision

Repo Atlas will consume Codex Security as an optional external evidence
producer through a strict, offline import adapter. Atlas will not embed,
authenticate, launch, supervise, or pay for the scanner.

The change introduces `atlas-audit-v3` for rich producer-neutral security
evidence and a CLI command:

```text
repo-atlas audit-import-codex-security <scan-dir> \
  --slug <unit-slug> \
  --title <unit-title> \
  [--concept <concept-slug>] \
  [--require-exact-scope] \
  [--replace] \
  [--dry-run] \
  [--json]
```

Assurance remains two-dimensional:

- **Exact file coverage** is the current, closed-world Git/blob claim already
  enforced by `atlas-review-coverage-v1`.
- **Semantic coverage** is the producer's threat/surface claim imported into
  `atlas-audit-v3`.

Neither axis substitutes for the other. The Security viewer displays them
separately and never describes a zero-finding scan as clean.

## Goals

- Import only completed, sealed Codex Security schema `1.0` bundles.
- Preserve stable finding identity, confidence rationale, taxonomy, root
  cause, validation, attack path, remediation tests, and preventive controls.
- Add threat-model and reviewed-surface context to Security unit detail.
- Preserve Atlas's exact-file, exact-blob coverage semantics without weakening
  existing v1/v2 contracts.
- Keep raw scan artifacts outside the repository and project only bounded,
  reviewable semantic fields into `.atlas/audits`.
- Fail closed on stale targets, unsafe paths, symlinks, digest drift, partial
  work, unsupported modes, or ambiguous coverage.
- Keep scanner installation, credentials, runtime, cost, and release churn
  outside Repo Atlas.

## Non-goals

- Running `@openai/codex-security`, its CLI, Codex, or an LLM from Repo Atlas.
- Importing partial, unknown, deferred, diff, branch, commit, working-tree, deep
  repository, directory, or custom-inventory scans in the first version.
- Copying raw code excerpts, proof-of-concept payloads, logs, detailed
  write-ups, Markdown reports, or private scan-directory paths into Atlas.
- Treating a producer fingerprint as conclusive proof that two findings share
  a root cause.
- Inferring `new`, `persisting`, `reopened`, or `resolved` lifecycle state.
- Maintaining a mutable finding-history database.
- Replacing repository-owned security policy or `atlas-review-coverage-v1`.
- Adding a RelayOS Codex Security SDK job. That is a separate follow-up project
  after the Atlas consumer contract is proven.
- Importing RelayOS's private security-scan ledger format.

## Trust boundaries

The importer crosses three boundaries:

```text
untrusted/private scan directory
            |
            | strict schema, seal, path, target, and size validation
            v
bounded atlas-audit-v3 projection
            |
            | current Git revision/blob validation
            v
Security viewer + optional review-coverage evidence join
```

The scan directory is sensitive input, not a trusted workspace. The manifest is
not self-hashed, so the importer safely reads it first and then treats its
artifact records as the seal for every referenced artifact. The derived Atlas
ledger is still security-sensitive and must be reviewed before publication;
the adapter limits the copied surface but cannot prove that arbitrary producer
prose contains no confidential fact.

All imported prose is data. The viewer renders it as text through React and
never evaluates Markdown, raw HTML, Mermaid, URLs, or code from the bundle.

## `atlas-audit-v3` wire contract

Version 3 is initially accepted only for `domain: "security"`. V1 and v2 remain
byte-for-byte and behaviorally unchanged.

A representative supplemental projection is:

```json
{
  "formatVersion": 3,
  "format": "atlas-audit-v3",
  "domain": "security",
  "reviewState": "complete",
  "slug": "repo-atlas-codex-security",
  "title": "Repo Atlas — Codex Security",
  "conceptSlug": "security",
  "ruleset": "codex-security/1.0",
  "scanned_at": "2026-07-29T09:00:00Z",
  "coverageRole": "supplemental",
  "exactScope": null,
  "producer": {
    "adapter": "codex-security-v1",
    "documentSchema": "1.0",
    "name": "codex-security-plugin",
    "version": "0.1.14",
    "scanId": "scan_...",
    "target": {
      "kind": "git_worktree",
      "targetId": "target_...",
      "revision": "<full-head-commit>",
      "snapshotDigest": "codex-security-snapshot/v1:sha256:..."
    },
    "canonicalArtifacts": {
      "manifestSha256": "<64 lowercase hex>",
      "findingsSha256": "<64 lowercase hex>",
      "coverageSha256": "<64 lowercase hex>"
    }
  },
  "threatModel": {
    "summary": "…",
    "assets": ["…"],
    "trustBoundaries": ["…"],
    "attackerCapabilities": ["…"],
    "securityObjectives": ["…"],
    "assumptions": ["…"]
  },
  "semanticCoverage": {
    "mode": "repository",
    "completeness": "complete",
    "inventoryStrategy": "repository",
    "includePaths": ["."],
    "excludePaths": [],
    "surfaces": [
      {
        "id": "artifact-rendering",
        "label": "Artifact rendering",
        "riskArea": "XSS",
        "disposition": "no_issue_found",
        "notes": "…",
        "receiptSha256": ["<64 lowercase hex>"]
      }
    ],
    "explicitExclusions": [],
    "openQuestions": []
  },
  "findings": []
}
```

### Exact scope

`coverageRole` is exactly one of:

- `supplemental`: semantic assurance only. `exactScope` must be `null`; this
  unit can never satisfy a file in `atlas-review-coverage-v1`.
- `primary`: semantic assurance plus a verified exact file inventory.
  `exactScope` must contain `files`, `hashes`, `fileCount`, `scopeHash`, and
  `inventoryReceiptSha256`.

Primary scope uses the existing Atlas definitions:

```json
{
  "files": ["src/audits.ts"],
  "hashes": {
    "src/audits.ts": "<git-blob-sha1>"
  },
  "fileCount": 1,
  "scopeHash": "<sha1-of-sorted-blob-and-path-lines>",
  "inventoryReceiptSha256": "<sealed-receipt-sha256>"
}
```

`scopeHash` is SHA-1 over sorted UTF-8
`<git-blob-sha1>  <repository-relative-path>` lines with one final newline,
matching Atlas's current audit-ledger algorithm. Every path is a unique,
normalized, Git-tracked regular file at stage zero, and a primary inventory
must contain at least one file. Every hash is recomputed from current bytes
with Git's blob algorithm; no hash supplied by the scan is trusted.

Codex Security's standard repository/scoped-path workflow defines
`artifacts/02_discovery/in_scope_files.txt` as its deterministic inventory.
Atlas promotes a unit to `primary` only when that exact path:

1. exists as a regular non-symlink file;
2. is listed in `manifest.scan.artifacts`;
3. is referenced by at least one `coverage.surfaces[].receiptRefs`;
4. matches the manifest's SHA-256 seal;
5. parses as a lossless, unique, normalized newline-delimited inventory; and
6. matches current tracked regular files and blobs.

Otherwise the import succeeds only as `supplemental`. `--require-exact-scope`
makes absence or invalidity of that proof an error instead of allowing the
supplemental fallback. Repository paths containing CR or LF make primary
promotion impossible because the upstream receipt format is line-delimited.

### Producer and target binding

`producer` records traceability, not trust. `adapter` is the ownership marker
used for safe replacement. Producer name/version are informational; acceptance
is pinned to canonical document schema `1.0`, not to a particular pre-1.0 npm
package version.

The first importer accepts target kind `git_revision` or `git_worktree` only.
The target must include a revision that resolves exactly to the current
repository `HEAD`. The normalized ledger records the full commit ID. For
`git_worktree`, primary promotion additionally requires the producer's
`snapshotDigest` to equal the public v1 clean-worktree digest (the digest of an
empty full-index `HEAD` diff and no untracked files). Every primary-scope path
must have one stage-zero index entry equal to `HEAD:<path>`, and the current
worktree bytes must hash to that same blob. A dirty scan target, dirty/staged
scope path, untracked receipt entry, conflict, symlink, or gitlink therefore
remains supplemental or fails under `--require-exact-scope`.

The clean-worktree digest is
`codex-security-snapshot/v1:sha256:1d74df0bc5da366ec7aad16a4841552de3d91d1cb5319d4e849096130ccb54eb`,
derived with the public length-prefixed v1 target algorithm. A regression test
recomputes rather than merely repeating this constant.

The v3 loader rechecks the recorded target revision. A later `HEAD` makes the
unit stale even when exact-scope file bytes happen to be unchanged, because
semantic reachability and threat surfaces may have changed elsewhere.

### Threat model

The adapter copies only the documented structured threat-model fields:
`summary`, `assets`, `trustBoundaries`, `attackerCapabilities`,
`securityObjectives`, and `assumptions`. Each value is bounded non-empty plain
text. Unknown properties are ignored after the source document passes safe-JSON
validation.

Threat-model data is context, not a finding and not proof that a control was
tested. The viewer labels it accordingly.

### Semantic coverage

The importer accepts only:

- `coverage.completeness === "complete"`;
- `coverage.mode` of `repository` or `scoped_path`;
- matching `inventoryStrategy` of `repository` or `scoped_path`;
- no `deferred` entries; and
- no surface with disposition `needs_follow_up`.

Manifest and coverage `includePaths` and `excludePaths` must be byte-for-byte
equal arrays after each element independently passes safe scope-path
validation. They are not glob-expanded by Atlas.

Imported surfaces retain bounded `id`, `label`, optional `riskArea`, optional
`notes`, and disposition. Private receipt paths are replaced by the SHA-256
digests already bound in the manifest. Explicit exclusions retain only
`pattern` and `reason`; open questions retain only `question` and optional
`followUpPrompt`.

Semantic completeness is shown as the producer's claim. It never changes the
denominator, verdict, or freshness calculation of
`atlas-review-coverage-v1`.

### Rich security finding

V3 findings use a structured, producer-neutral shape:

```json
{
  "id": "csf_...",
  "occurrenceId": "occ_...",
  "ruleId": "path-traversal.archive-extraction",
  "identity": {
    "anchor": "archive-entry-write-without-containment",
    "instance": null
  },
  "fingerprint": "codex-security/v1:sha256:...",
  "severity": {
    "level": "high",
    "score": 8.1,
    "scoringSystem": "CVSS:3.1",
    "vector": null,
    "rationale": "…",
    "changeConditions": "…"
  },
  "confidence": {
    "level": "high",
    "rationale": "…"
  },
  "category": "path-traversal",
  "cwe": ["CWE-22"],
  "title": "Unsafe archive extraction can escape the output directory",
  "summary": "…",
  "locations": [
    {
      "path": "src/extract.ts",
      "startLine": 41,
      "endLine": 44,
      "role": "sink"
    }
  ],
  "rootCause": {
    "summary": "…"
  },
  "validation": {
    "method": "static source trace",
    "summary": "…",
    "assertions": ["…"],
    "limitations": ["…"]
  },
  "attackPath": {
    "summary": "…",
    "dataflow": "…",
    "reachability": "…",
    "impact": {
      "level": "high",
      "why": "…"
    },
    "likelihood": {
      "level": "medium",
      "why": "…"
    },
    "limitations": ["…"]
  },
  "remediation": "…",
  "remediationTests": ["…"],
  "preventiveControls": ["…"],
  "provenance": {
    "source": "local_plugin"
  },
  "disposition": "open"
}
```

The adapter maps only documented values and a whitelist of known
validation/attack-path subfields. Unknown arbitrary objects are not copied.
Missing optional rich sections remain absent; they are never synthesized from
the rendered Markdown report.

Canonical v3 severity levels are Atlas's existing `info`, `low`, `medium`,
`high`, and `critical`; Codex Security `informational` maps deterministically
to `info`. Category comes from `taxonomy.category`, CWE values from
`taxonomy.cwe`, and every newly imported disposition starts as `open`. Known
optional scalar members are represented as `null`; optional rich sections are
omitted when the source has no supported content.

For backward-compatible presentation, normalized v3 findings derive the
existing compact `dataflow` display from `attackPath.dataflow`, then
`attackPath.summary`, then `summary`. The compact `fix` display is
`remediation`. This derivation is for existing viewer selectors only; the
structured canonical fields remain available to the v3 detail view.

The following source fields are intentionally excluded:

- `codeEvidence[].code` and all source excerpts;
- `writeup.reportPath` and detailed finding Markdown;
- evidence-reference IDs whose target excerpts are not copied;
- proof-of-concept files and validation artifacts;
- candidate/workbench/ledger extension identifiers;
- raw receipt paths, logs, prompts, database state, and report projections;
- remote URL and local absolute paths.

### Finding identity validation

For every finding the adapter recomputes:

```text
fingerprint =
  "codex-security/v1:sha256:" +
  sha256([
    "codex-security/v1",
    manifest.scan.target.targetId,
    finding.ruleId,
    finding.identity.anchor,
    finding.identity.instance || ""
  ].join(NUL))

findingId = "csf_" + sha256(fingerprint).slice(0, 24)

occurrenceId =
  "occ_" +
  sha256([manifest.scan.id, fingerprint].join(NUL)).slice(0, 24)
```

The algorithm label, primary fingerprint, finding ID, and occurrence ID must
all match. Finding IDs, occurrence IDs, fingerprints, rule IDs, and location
tuples must be unique where the upstream contract requires uniqueness.

Identity is a matching signal, not a lifecycle verdict. Re-import may preserve
an existing Atlas `disposition` only for an exact primary-fingerprint match; it
does not call an absent finding resolved or a returning finding reopened.

## Import validation pipeline

The command completes every validation before writing:

1. Resolve the repository root and enumerate all of its Git worktree roots.
2. Resolve `<scan-dir>` and require it to be a regular directory outside every
   worktree and outside `.atlas`.
3. On POSIX, require the scan directory to be owned by the current user with no
   group/other permission bits. Skip only this ownership check on platforms
   that do not expose POSIX ownership.
4. Open `scan-manifest.json` through the contained-file reader with a 16 MiB
   limit. Reject symlinks, non-regular files, realpath escape, root inode
   replacement, unsafe JSON, unsupported document type/schema, and extra reads
   after an abort.
5. Require canonical refs `findings.json` and `coverage.json`, completed status,
   parseable timestamps, and `sealedAt === completedAt`.
6. Open findings and coverage through the same reader with 128 MiB and 32 MiB
   limits. Require matching document types, schema `1.0`, and scan IDs.
7. Validate every manifest artifact path, uniqueness, containment, regular-file
   identity, size budget, and SHA-256. `findings.json` and `coverage.json` must
   both be sealed artifacts with JSON media types.
8. Require every coverage receipt to live below `artifacts/`, be listed in the
   seal, and retain the same file identity while hashing. Do not print its
   contents.
9. Validate target/revision, scope equality, supported coverage semantics,
   finding identities, strict values, text bounds, path bounds, line ranges,
   and duplicate rules.
10. Attempt exact-scope promotion only under the rules above; otherwise select
    supplemental unless `--require-exact-scope` was requested.
11. Build the bounded v3 object, canonicalize its JSON, then re-parse it through
    Atlas's v3 ledger validator.
12. Check replacement ownership and write once through Atlas's existing
    non-symlink atomic ledger writer.

Contained reads use file descriptors and pre/post `fstat` identity checks where
the platform supports them. A path component becoming a symlink, a file
changing during read/hash, or the scan root being replaced makes the import
fail. On POSIX, scan files must have one link; duplicate `(device, inode)`
identities across manifest artifacts are rejected. JSON is recursively checked
with a bounded pre-parse nesting scan and iterative post-parse validation for
depth, collection-count, text-size, and finite-number limits before field
projection.

The fixed resource ceilings are 10,000 sealed artifacts, 128 MiB per sealed
artifact, 512 MiB across sealed artifacts, 32 MiB for the exact-scope receipt,
and 32 MiB for the resulting Atlas ledger. Canonical document limits remain
16 MiB for the manifest, 128 MiB for findings, and 32 MiB for coverage.
Individual projected prose fields are limited to 64 KiB UTF-8. Exceeding a
limit is an input error, never truncation.

The command never executes a scan-bundle file and never dynamically imports
the upstream package.

## Output and replacement behavior

`--slug` and `--title` are required; Atlas does not infer routing or product
taxonomy from model-authored prose. `--concept` is optional and must name a
route-safe concept slug.

The output path is exactly `.atlas/audits/<slug>.json`.

- By default, any existing path is a hard error.
- `--replace` may replace only a structurally valid `atlas-audit-v3` ledger
  whose `producer.adapter` is `codex-security-v1` and whose slug matches the
  requested slug.
- A v1/v2 ledger, foreign v3 producer, malformed file, symlink, or slug mismatch
  is never overwritten.
- On replacement, only an existing local `disposition` is preserved, and only
  when the new finding has the same primary fingerprint. All producer-owned
  fields come from the new sealed observation.

`--dry-run` performs the complete read, seal, target, scope, projection, and
replacement checks, prints the intended role/counts/path, and makes no write.
Validation errors still return nonzero.

`--json` emits one bounded machine-readable result object to stdout. Human
diagnostics go to stderr. Neither mode prints finding prose, receipt contents,
absolute scan paths, tokens, or raw bundle JSON. The result includes output
path, scan ID, target revision, coverage role, finding count, surface count,
exact file count, and canonical source digests.

## Loader and freshness

The v3 loader is strict and bounded:

- exact known top-level and nested keys;
- only security domain in version 3;
- completed review state;
- route-safe slug and concept slug;
- parseable timestamps and lowercase digests;
- bounded non-empty text;
- normalized repository-relative locations;
- valid severity, confidence, disposition, CWE, surface disposition, and
  coverage enums;
- unique finding/fingerprint/surface/path identities;
- `supplemental` iff `exactScope` is null;
- `primary` iff exact scope is internally complete and current.

At load, Atlas verifies the producer target revision against current `HEAD`.
For primary units it also recomputes exact-scope blobs and `scopeHash`. Any
failure marks the unit stale or invalid; it never falls back to a current
supplemental claim.

Normalized v1/v2 objects retain their current API. Normalized v3 objects add
`coverageRole`, nullable `exactScope`, `producer`, `threatModel`,
`semanticCoverage`, and structured findings.

## Closed-world coverage integration

`atlas-review-coverage-v1` remains unchanged on disk.

When joining its entries to audit portfolios:

- v1/v2 behavior is unchanged;
- a v3 `primary` unit may satisfy exact file evidence when the report names its
  slug and the current blob appears in the verified `exactScope`;
- a v3 `supplemental` unit is ignored for `fresh`, `missing`, `stale`, and
  `invalid` file-evidence arithmetic, even if the report incorrectly names it;
- a report that claims supplemental evidence as fresh is invalid with a stable
  diagnostic code;
- semantic surface counts never enter file-coverage summary identities.

This keeps the coverage report producer-neutral while preventing a semantic
scan from silently widening its authority.

## Viewer behavior

Security home and unit detail present two independent assurance cards:

1. **Exact file coverage** — current `fresh / required`, gaps, drift, and
   invalid evidence from `atlas-review-coverage-v1`.
2. **Semantic coverage** — imported completeness, inventory strategy, reviewed
   surface outcomes, explicit exclusions, and open questions.

Supplemental units carry a visible “does not prove exact file coverage” label.
Primary units show their sealed inventory digest and current exact-file count.

V3 finding cards show:

- severity, category, CWE, confidence, rule ID, and stable finding ID;
- role-aware affected locations with source navigation;
- summary;
- collapsible root cause;
- collapsible validation and limitations;
- collapsible dataflow/reachability with impact and likelihood;
- remediation, remediation tests, and preventive controls.

Unit detail also has a plain-text threat-model section. Surface dispositions
use distinct labels for reported, no issue found, rejected, and not applicable.

Zero findings is rendered as “No reportable findings in this completed
semantic scan.” It is never “clean”, “safe”, or “no vulnerabilities”. The page
also states the independent exact-file coverage verdict; unknown, missing,
stale, or incomplete file coverage remains prominent.

The current Security home filters, counts, action queues, concept association,
and v1/v2 routes remain functional. Rich sections are progressive enhancement
for v3.

## Localization

Viewer chrome for every new field uses Lingui messages.

Canonical producer prose remains in its source language. The audit
localization sidecar is extended additively for v3 prose:

- unit threat-model strings;
- finding summary, severity rationale/change conditions, confidence rationale,
  root cause, validation, attack path, remediation, remediation tests, and
  preventive controls;
- semantic surface labels/notes, exclusion reasons, and open questions.

The v3 finding source digest covers the complete structured finding, including
machine fields and canonical prose. The unit source digest additionally covers
producer target identity, threat model, semantic coverage, and sorted finding
digests. Existing v2 digests and localization files remain valid.

Fallback is field-local. A missing or stale translation for one v3 section
shows that section's canonical source text; it does not suppress current
translations for other fields and never attaches translation text to a changed
finding.

## Lifecycle and history

Imported v3 files are immutable observations plus a small Atlas-local
`disposition`. The first version has no history table.

The importer does not compare scans to infer lifecycle. A missing fingerprint
may mean fixed, excluded, not reviewed, split, merged, renamed, or producer
drift. Codex Security's own comparison logic uses model-assisted root-cause
matching in addition to fingerprints; Atlas will not approximate that with an
absence check.

A future history feature must store mutable triage separately from sealed
observations and define an explicit matching/confirmation workflow.

## Failure behavior

The importer exits nonzero and writes nothing for:

- missing, malformed, oversized, unsealed, partial, unknown, or future-schema
  documents;
- budget-stopped scans without a completed canonical bundle;
- mismatched scan IDs, scope arrays, target revision, timestamps, artifact
  digests, finding identities, or counts;
- unsupported scan mode, inventory strategy, target kind, deferred work, or
  follow-up surface;
- unsafe/duplicate paths, aliases, symlinks, gitlinks, conflicts, unreadable
  files, realpath escape, root replacement, or concurrent mutation;
- invalid primary inventory, when `--require-exact-scope` is set;
- invalid v3 projection or unsafe/foreign output replacement.

No partially derived ledger is left behind. Atomic write failure leaves an
existing valid ledger unchanged.

## Tests and verification

Implementation follows RED-GREEN-REFACTOR.

### Import contract tests

Fixtures cover:

- valid sealed supplemental and primary bundles;
- zero and multiple findings;
- manifest/findings/coverage schema and scan-ID mismatch;
- `sealedAt` mismatch and missing canonical artifact records;
- canonical and receipt digest tampering;
- duplicate artifact/receipt/finding/location identities;
- traversal, absolute, backslash, NUL, CR/LF, symlink, hardlink alias where
  detectable, and realpath escape;
- root/file mutation during read;
- manifest/findings/coverage/receipt size limits and JSON depth/count limits;
- target kind/revision/HEAD mismatch;
- partial/unknown completeness, deferred work, follow-up surfaces, unsupported
  mode/strategy, and scope-array mismatch;
- fingerprint, finding-ID, and occurrence-ID mismatch;
- absent, unsealed, malformed, duplicate, untracked, dirty, staged, conflicted,
  symlinked, gitlink, and stale exact-scope inventory;
- supplemental fallback and `--require-exact-scope`;
- dry-run, JSON output redaction, foreign overwrite refusal, owned replacement,
  disposition preservation, and atomic-write safety.

Fixtures are independently authored minimal documents. Repo Atlas does not copy
the upstream plugin, prompts, runtime, or private scan output. If future tests
copy a schema/example verbatim, its Apache-2.0 notice must be retained.

### Loader and coverage tests

- v1/v2 byte and normalized compatibility;
- strict v3 top-level/nested schemas and bounds;
- supplemental/primary invariants;
- HEAD and blob freshness;
- rich finding and semantic-coverage normalization;
- only primary v3 ledgers satisfying coverage evidence;
- fail-closed diagnostics when a report names supplemental evidence.

### Viewer and localization tests

- independent exact/semantic assurance cards;
- supplemental warning and primary inventory metadata;
- threat model and surface outcomes;
- stable identity, CWE, confidence, role-aware locations, and rich sections;
- no raw code evidence, private receipt path, HTML, Markdown execution, or
  unsafe link;
- zero-finding wording under complete, unknown, missing, stale, and invalid
  exact coverage;
- v1/v2 presentation regression coverage;
- field-local translation fallback, digest invalidation, keyboard interaction,
  headings, labels, and accessible disclosure controls.

### Final verification

```text
pnpm test
pnpm typecheck
pnpm i18n:extract
pnpm i18n:compile
pnpm build
git diff --check
```

Any repository-specific check discovered in package scripts is added to the
implementation plan and run before completion.

## Operational workflow

The scanner remains a deliberate external operation:

1. Run Codex Security outside the repository/worktree and give it an explicit
   budget appropriate for the scope.
2. Require a completed sealed bundle. For primary Atlas coverage, ensure the
   standard `artifacts/02_discovery/in_scope_files.txt` inventory is included
   as a coverage receipt before finalization.
3. Run the Atlas importer with `--dry-run`; use `--require-exact-scope` when
   exact coverage is required.
4. Inspect the bounded `.atlas/audits/<slug>.json` projection, then commit it
   through the repository's normal review.
5. Generate/update `.atlas/review-coverage.json` with the repository-owned
   policy checker if the unit should satisfy closed-world coverage.

Scanner failures or cost exhaustion do not alter Atlas state. Repo Atlas's
build, serve, status, and pre-commit workflows remain deterministic and
offline.

## Alternatives considered

### Embed the Codex Security SDK in Repo Atlas

Rejected. It would couple a deterministic repository viewer to authentication,
model access, cost, cancellation, sandboxing, pre-1.0 APIs, and long-running
state. It would also make a normal Atlas command capable of spending money and
producing sensitive artifacts.

### Import `report.md`

Rejected. The report is an unsealed deterministic projection, loses structured
identity and coverage semantics, and creates a Markdown/HTML trust boundary.
Only the canonical JSON contract is accepted.

### Copy the complete canonical bundle into `.atlas`

Rejected. Raw code evidence, write-ups, validation artifacts, receipts, and
private paths may be sensitive and are unnecessary for the portfolio UI.

### Treat `coverage.complete` as closed-world file coverage

Rejected. The canonical semantic contract has no mandatory exact file/blob
inventory. That conversion would overstate assurance.

### Require exact scope for every import

Rejected. A completed sealed semantic scan remains useful even when its file
inventory was not sealed as a receipt. It is imported honestly as
supplemental. Repositories that require primary evidence use
`--require-exact-scope`.

### Replace `atlas-review-coverage-v1` with semantic surfaces

Rejected. File accountability and threat-surface review answer different
questions and can disagree legitimately.

## Rollout

1. Add v3 types/strict loader while preserving v1/v2 fixtures.
2. Add the standalone safe Codex Security bundle reader and TDD fixture set.
3. Add CLI projection, dry-run, replacement, and exact-scope promotion.
4. Make review coverage reject supplemental evidence and accept verified
   primary v3 evidence.
5. Add Security unit-detail and localization support.
6. Document the external scan/import workflow and its beta/cost/privacy
   constraints.
7. Run the complete verification suite and independently review the security
   boundary before merging.

The implementation does not change RelayOS. Once Repo Atlas proves the
consumer contract, a separate RelayOS design may evaluate an asynchronous,
explicitly budgeted Codex Security producer that emits this public projection.

## Reference baseline

This design was checked against:

- [`openai/codex-security`](https://github.com/openai/codex-security) commit
  `e94d6bef9797a192febfde89a26ec7f831bc09b2` (SDK package `0.1.1`, bundled
  plugin `0.1.14`);
- the official [Codex Security overview](https://learn.chatgpt.com/docs/security);
- the official [CLI](https://learn.chatgpt.com/docs/security/cli) and
  [SDK](https://learn.chatgpt.com/docs/security/sdk) documentation.

The adapter is intentionally pinned to canonical schema `1.0`. A future schema
or changed identity/seal rule requires an explicit adapter version and design
review rather than optimistic parsing.
