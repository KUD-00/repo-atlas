# repo-atlas

Incremental codebase atlas: per-path descriptions with git-hash staleness tracking and a
self-contained HTML viewer (folder tree on the left, description on the right).

The point: descriptions are written **once** (by you or a coding agent), tracked against the
exact git hash they were written for, and only the paths whose code actually changed get
flagged for re-review. No full regeneration, no wasted tokens.

## How it works

- **Ledger** — `.atlas/notes/` in the target repo, one markdown file per described path:
  - directory `apps/daemon` → `.atlas/notes/apps/daemon/__dir__.md`
  - file `apps/daemon/x.ts` → `.atlas/notes/apps/daemon/x.ts.md`
  - repo root → `.atlas/notes/__dir__.md`

  Each note has frontmatter managed by the tool; the body is yours.
  Commit `.atlas/` — descriptions are versioned with the code.

  - `hash` — git blob hash of the content the note was stamped against (the staleness predicate)
  - `anchor` — HEAD commit at stamp time: the reference point for "what changed since",
    powering rename detection and change-size triage
  - `dirty: true` — the stamped content wasn't in `anchor` (uncommitted worktree state)
  - `stamped` — timestamp, informational only

- **Staleness** — a file's hash is its git blob hash. A directory's hash covers its
  *immediate children* (child file contents + child dir names), so editing a file flags the
  file and its direct parent; adding/removing/renaming entries flags the directory. Deep
  edits don't cascade to every ancestor.

  "Outdated" is not one thing, so `status` splits it:

  - **outdated** — content changed in place; shown with `(+a/-b)` diff size against the
    note's anchor so an import shuffle is distinguishable from a rewrite at a glance.
  - **moved** — the path is gone but its note's content turned up elsewhere: an orphan
    note whose stamped blob hash equals a new path's current hash (pure move, zero git
    calls), or a rename `git diff -M <anchor>` reports (edited moves, with a similarity
    score, uncommitted moves included). Directory notes follow their children by vote.
    `repo-atlas migrate --apply` relocates these notes: identical moves are re-stamped,
    edited ones stay outdated for revision, and inline references to the old paths in
    every note body are rewritten.
  - **broken refs** — a note's prose references another path as inline code and that
    path no longer resolves. The subject of the *referencing* note didn't change, so hash
    staleness can never catch this; `status` re-runs the viewer's link resolution over all
    note bodies and reports what stopped resolving, with a suggestion when the move map or
    a unique basename identifies the new home. Heuristic by design — treat as warnings.

- **Scan scope** — `git ls-files` (tracked + untracked-not-ignored), so `.gitignore` is
  respected for free; `.atlas/config.json` `exclude` patterns (picomatch) filter on top
  (lockfiles, binaries, snapshots by default).

## Usage

```sh
cd /path/to/some/repo
repo-atlas init                # creates .atlas/ (config + notes dir)
repo-atlas status              # missing / outdated (+diff size) / moved / broken refs
repo-atlas status --json       # machine-readable, for agents
repo-atlas migrate             # print which notes would follow moved paths
repo-atlas migrate --apply     # relocate them (and fix old-path refs in note prose)
repo-atlas notepath apps/x.ts  # where to write the note for a path
# ... write note bodies ...
repo-atlas stamp               # stamp all notes with current hashes + HEAD anchor
repo-atlas stamp apps/x.ts     # or stamp specific paths ("." = repo root)
repo-atlas build               # write .atlas/atlas.html (open in a browser)
repo-atlas check               # validate code: anchors (links + embeds) in note bodies
repo-atlas audit-stamp         # per-file hashes into .atlas/audits/*.json (drift detail)
repo-atlas audit-import audits/security-scan/ledger.json
                               # convert a legacy scans[] ledger without losing scan-time hashes
repo-atlas readability         # mechanical code-readability features + repo-relative
                               # outliers (no LLM; design: docs/readability-audit.md)
repo-atlas quality             # mechanical DESIGN defects: import cycles, upward layer
                               # imports, rotting markers, type escapes, one declaration
                               # spelling absence two ways, boolean-trap signatures
                               # (no LLM; design: docs/design-audit.md)
repo-atlas serve               # dev server at http://localhost:4400 (-p to change)
```

`serve` rebuilds on every request and auto-reloads open pages (SSE) whenever the
working tree or `.atlas/notes/` changes — leave it open while writing notes. The
output is still a single self-contained page (viewer prebuilt + committed, see
"Viewer" below); nothing builds at run time.

The selected path is recorded in the URL hash (`…:4400/#packages/kernel`), so
routes are deep-linkable and browser back/forward work. The doc header is a
breadcrumb (every ancestor segment navigates), and inline code in a note that
resolves to a scanned path — absolute (`packages/kernel/core`), relative to the
note's directory (`core`, `src/queue.ts`), or with a `/`/`*` tail — renders as
a link to that path's page. Notes stay plain markdown; linking is view-side.

### Attention control plane

Concept freshness and human follow-up are deliberately different states. A
page can still be `outdated` after a reader has understood the change, and a
freshly restamped page does not prove that anyone followed it. The first
primary viewer surface therefore tracks concept snapshots that need a person:

- **Needs attention** shows open and snoozed concept versions, the stamped
  anchor → current snapshot, and only mechanically verified changed paths or
  declared source scope. Atlas does not invent a semantic change summary.
- **Review history** keeps version-bound receipts for acknowledgement,
  understanding, decisions, not-relevant outcomes, snoozes, manual reopens,
  and automatic source-driven reopens. “Understood” and “decision” require a
  note, so those outcomes carry more evidence than acknowledgement alone.
- **System health** keeps missing/outdated notes, broken concept sources,
  broken references, and orphans separate from the human queue.

Every concept gets a total SHA-256 snapshot over its ordered declared sources.
Present sources contribute their type and scan hash; absent sources contribute
an explicit missing marker. This means a remaining source can still reopen the
item while another source is broken. An unchanged snapshot preserves the
reader's workflow even if the page remains stale; any observed snapshot change
reopens it. Fresh concepts establish a quiet initial baseline but create no
review receipt.

Persistent actions require `repo-atlas serve`. They are stored outside the
tracked atlas at the worktree-local path returned by
`git rev-parse --git-path repo-atlas/attention-v1.json`, written atomically
with owner-only permissions. A linked worktree therefore keeps its own current
snapshots and receipts instead of fighting another branch through the shared
Git common directory. The file is local Git metadata and is never committed.

Every item also carries a monotonic workflow revision. Atlas checks both that
revision and the source snapshot before accepting an action, so a tab opened
before another review cannot replace the newer outcome. State mutations run as
locked read-modify-write transactions across `serve` processes; concurrent
actions on different concepts retain both receipts. If the lock cannot be
acquired, Atlas reports a conflict instead of overwriting either action. A
revision conflict returns HTTP 409 with the latest attention payload; the viewer
loads it and keeps a page-level warning visible with the winning outcome before
asking you to retry.

Invalid, oversized, structurally unknown, symlinked, or non-regular state fails
closed: the dashboard remains readable, actions are disabled, and Atlas will not
overwrite the file. Move the bad file aside or repair its version-1 JSON, then
restart `serve`. Atlas also uses a sibling `.lock` file during a short state
transaction. Non-regular or symlink locks are left untouched and rejected;
regular stale locks are reclaimed only when their same-host owner process is
provably gone. File and supported directory sync failures propagate to the
action endpoint instead of acknowledging a receipt whose durability is unknown.
A static `repo-atlas build` contains the same dashboard as a read-only current
projection, without personal history.

### Live audit ledgers

Completed audits live at `.atlas/audits/<slug>.json`. Freshness is shared across
domains: `status` compares scan-time `files` / `scope_hash` / optional complete
`hashes` with the working tree and reports stale scopes, exact changed/missing
files, and findings that point at drifted files. Domain validation is an extra
layer on top of that shared envelope — never a bypass.

**Viewer-grade ledgers use `atlas-audit-v2`.** `domain` is required
(`security` | `test` | `design`). `reviewState` must be exactly `complete` before a ledger
enters a viewer portfolio; incomplete or partial runs must not publish an empty
`findings: []` as if the review were finished with no issues. The filename stem
must equal `slug`. Unknown domains, format/version mismatches, and
domain-invalid findings stay out of the portfolio and remain visible in
`status` as stale + invalid.

**`design` is ledger-grade, not viewer-grade.** It shares the envelope, the
freshness contract, and `audit-stamp`, but it has no portfolio and makes no
coverage claim: its findings reach a reader as artifact cards on the pages they
concern, and `review-coverage` closure covers the portfolio domains only
(`PortfolioDomain` = security | test). See [docs/design-audit.md](docs/design-audit.md)
for the axis as a whole — the machine-decidable half is `repo-atlas quality`, and
only that half may gate CI.

Security v2 (optional `conceptSlug` associates the unit with a concept page —
slug equality alone is not enough for v2). Digest values below are illustrative
40-character lowercase hex only; real ledgers must compute them from exact
scope bytes:

```json
{
  "formatVersion": 2,
  "format": "atlas-audit-v2",
  "domain": "security",
  "reviewState": "complete",
  "slug": "runtime-auth",
  "title": "Runtime authentication",
  "ruleset": "security-v1",
  "scanned_at": "2026-07-21",
  "scope_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "file_count": 1,
  "files": ["src/auth.ts"],
  "hashes": {"src/auth.ts": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
  "conceptSlug": "auth",
  "findings": [{
    "severity": "high",
    "category": "boundary",
    "title": "unauthenticated sink",
    "locations": ["src/auth.ts:12"],
    "dataflow": "request to privileged handler",
    "fix": "require a session before the sink"
  }]
}
```

Security findings: `severity` ∈ `info|low|medium|high|critical`; non-empty
`category`, `title`, `dataflow`, `fix`; one or more normalized `locations`
(`path`, `path:line`, or `path#symbol`); optional `confidence`.

Test v2:

```json
{
  "formatVersion": 2,
  "format": "atlas-audit-v2",
  "domain": "test",
  "reviewState": "complete",
  "slug": "auth-suite",
  "title": "Auth suite gaps",
  "ruleset": "test-v1",
  "scanned_at": "2026-07-21",
  "scope_hash": "cccccccccccccccccccccccccccccccccccccccc",
  "file_count": 1,
  "files": ["test/auth.test.ts"],
  "hashes": {"test/auth.test.ts": "dddddddddddddddddddddddddddddddddddddddd"},
  "findings": [{
    "impact": "blocking",
    "category": "missing-invariant",
    "title": "gate not asserted",
    "invariant": "handler rejects unauthenticated callers",
    "evidence": "suite mocks auth away",
    "fix": "assert the real gate",
    "locations": ["test/auth.test.ts:1"]
  }]
}
```

Test findings: `impact` ∈ `blocking|warning|advisory`; `category` ∈
`missing-invariant|weak-assertion|mock-only|nondeterminism|isolation-leak|
fixture-drift|coverage-gap|privileged-side-effect`; non-empty `title`,
`invariant`, `evidence`, `fix`; one or more normalized `locations`; optional
`confidence`. The schema is about whether a test proves the intended invariant,
not whether the product is secure.

Design v2:

```json
{
  "formatVersion": 2,
  "format": "atlas-audit-v2",
  "domain": "design",
  "reviewState": "complete",
  "slug": "design-contracts",
  "title": "Contract layer shape",
  "ruleset": "atlas-designscan-v1",
  "scanned_at": "2026-07-25",
  "scope_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "file_count": 1,
  "files": ["src/types.ts"],
  "hashes": {"src/types.ts": "ffffffffffffffffffffffffffffffffffffffff"},
  "findings": [{
    "severity": "medium",
    "category": "dead-forward-compat",
    "title": "reserved field has no reader",
    "locations": ["src/types.ts:14"],
    "evidence": "searched the repo for `reserved`: definition + barrel re-export only, zero consumers",
    "fix": "delete it until a consumer exists",
    "disposition": "open"
  }]
}
```

Design findings: `severity` ∈ `low|medium|high` — a reasonableness defect costs
clarity, not correctness, so there is deliberately no `critical` (that would be a
bug, and belongs to another domain). `category` is one of the 19 ids in
`atlas-designscan-v1` (see docs/design-audit.md §4); non-empty `title`,
`evidence`, `fix`; one or more normalized `locations`; optional `confidence` and
`disposition` ∈ `open | accepted-design | deferred`. `evidence` is required
because the bar is "the proof, not the impression" — grep counts, call-site
tallies, behaviour comparisons. Taste is not a finding.

**Compatibility:** v1 ledgers with `finalPass: true` and the strict security
finding schema still load as legacy security units. v1 generic ledgers
(design/readability and friends) still participate in status only. v1
`finalPass: false` is never viewer-grade. There is no filename or `ruleset`
prefix inference of domain.

**Empty portfolio:** an empty domain portfolio shows "No completed audit evidence"
and never claims zero findings or complete coverage. A stale unit keeps
historical findings but is marked for re-audit. Malformed ledgers never become
empty finished units. A fresh unit with zero open findings is shown as
"No actionable findings in current completed review" only when a current coverage
report has repository verdict `complete` — never from ledger absence or from a
domain that merely looks complete in isolation.

### Review coverage report

`.atlas/review-coverage.json` is the optional closed-world coverage join
(`format: atlas-review-coverage-v1`, `formatVersion: 1`). The report is
deterministic (no generation timestamp). Its `verdict` is one of:

- **complete** — zero unclassified paths, conflicts, invalid ledgers, missing
  evidence, and stale evidence for the claimed inventory;
- **incomplete** — structurally valid report with one or more explicit gaps
  (allowed so progress is visible; enforcement still fails until complete);
- **invalid** — deterministic analysis could not produce trustworthy
  classifications or evidence joins; at least one `reportErrors` entry is
  required, and Atlas ignores all embedded fresh/covered claims.

**Ownership:** the report owns *what must be reviewed* (required paths,
classifications, per-domain evidence status). Audit units under
`.atlas/audits/` own *what was reviewed* (exact files/hashes, findings,
ruleset, scan time, optional `evidenceRefs`). Neither substitutes for the
other.

**Missing report:** when the file is absent or unreadable, coverage is
**unknown** — never treated as zero required paths or as fully covered.
Primary Security/Tests suffix priority is: **unknown** → **gaps** → **open**
→ **covered**.

**Code / config excludes never define audit coverage.** `.atlas/config.json`
`exclude` only filters the Code tree and note scan. Ledger scope hashing is
independent of those excludes. An excluded-from-Code path can still be
required for Security or Tests by the coverage report.

**v1 ledgers** (`finalPass: true` security schema) remain recorded evidence for
compatibility and still load as legacy security units, but they **cannot
establish closed-world coverage** on their own. Only a validated
`atlas-review-coverage-v1` report can assert required scope completeness.

**v2 dispositions and evidenceRefs:** Security findings may carry
`disposition` ∈ `open | accepted-risk | separate-design` (default `open`).
Accepted-risk and separate-design findings are retained risk, not attention
queue items. Units may carry `evidenceRefs` (unique safe repo-relative paths)
identifying producer-owned evidence accepted when the ledger was built; the
repository checker—not mere presence in the viewer—decides authenticity.

**Viewer routes** (hash paths; valid even when the portfolio is empty):

- `view:attention` / `view:attention/history` / `view:attention/health` — human
  queue, durable receipts, and separate machine health
- `audit:security` / `audit:security/<slug>` — security portfolio home / unit
- `audit:test` / `audit:test/<slug>` — test portfolio home / unit
- `view:concepts` — concept index / honest empty state

Legacy `#security` redirects to `#audit:security`. A real tracked path named
`security` stays a Code route. Primary sidebar views are route-derived:
Attention, Code, Concepts, Security, Tests.

`audit-stamp` only adds per-file detail when the ledger's existing
`scope_hash` still matches current bytes. It refuses stale ledgers, so a dated
verdict cannot be made fresh by stamping it after the code changed. Historical
`{ scans: [...] }` ledgers should use `audit-import`; it preserves their
original `git_blob_sha1` values and needs no after-the-fact stamp. Import is
all-or-nothing: malformed/duplicate scope entries or invalid finding counts
reject the migration instead of silently shrinking it. Ledger scope hashing is
independent of `.atlas/config.json` excludes, so an excluded but existing audit
target is not mislabeled as gone. Corrupt/unsupported ledgers remain visible in
`status` as stale + invalid; if a stale ledger has no complete per-file hash set,
finding drift is reported as unknown rather than `0/N`.

The canonical readability recipe is:

```sh
repo-atlas readability --out .atlas/readability.json --artifacts
```

That versioned report records the blob hash of the exact bytes analysed, writes
a thin `.atlas/audits/readability.json` index, and retains its comparison with
the previous report (modified/added/removed plus exact improved/worsened counts
and top-N detail). `status` reads the thin index rather than reparsing the full
feature corpus, so it stays cheap while still showing drift and the last trend.

The design equivalent (mechanical half) is:

```sh
repo-atlas quality --write --artifacts
```

Same shape: `.atlas/quality.json` holds the findings, `.atlas/audits/quality.json`
is the thin hash-bound index `status` reads, and `--artifacts` writes a
`quality.md` card onto every page a finding touches. Detectors whose precision
is ~1 can gate CI — `repo-atlas quality --fail-on import-cycle --fail-on layer-violation`
exits nonzero — while the judgment-level half of the axis stays report-only in
`domain: design` ledgers. Declare the dependency order once in
`.atlas/config.json` to activate the layer detector (TOP layer first; an import
climbing toward index 0 is the violation):

```jsonc
{ "layers": [
    { "name": "app",       "paths": ["apps/**"] },
    { "name": "domains",   "paths": ["packages/domains/**"] },
    { "name": "kernel",    "paths": ["packages/kernel/**"] }
] }
```

If the repo already has a stronger layering gate of its own, leave `layers`
unset rather than duplicating a weaker rule — the report says out loud that the
detector is inactive. Full axis: [docs/design-audit.md](docs/design-audit.md).

On a file page, notes can also anchor into the file's own source. Both forms
take content markers (symbol names), resolved against the CURRENT source at
render time — they follow the code as it moves, and there are no stored line
numbers or copied code to rot:

- `[label](code:StartMarker..EndMarker)` — a jump link: click scrolls +
  highlights the range in the preview pane. A single marker is a one-line
  anchor; the range runs from the start marker up to just before the end
  marker's line.
- `![label](code:StartMarker..EndMarker)` — an embed: the slice is transcluded
  in place as a highlighted code block (with a jump-to-preview affordance).
  A single marker embeds its whole brace-balanced block. Long embeds collapse
  behind a "show all" toggle.

Use links for big clusters the preview pane should own, embeds only where the
code's shape IS the point being made. A marker that no longer resolves
degrades to plain text (`repo-atlas check` reports the rot); the static
`build` output has no source to slice, so embeds degrade there too.

## Audit platform (V3)

The audit platform is the closed-world, exact-byte layer underneath the
ledger formats described above. V3 is the only format new audit evidence is
published in; every state operation goes through the hierarchical
`repo-atlas audit <verb>` surface (`src/audit-cli.ts`), and all of it is
deterministic local I/O with exactly one exception: `audit run security`,
the only command that can launch a provider process.

### State layout

Committed audit state lives under `.atlas/` in the target repo:

- `.atlas/audits/<slug>.json` — current observation ledgers. New writes are
  `atlas-audit-v3`; legacy `atlas-audit-v1`/`atlas-audit-v2` ledgers share
  the directory and stay readable (see "Live audit ledgers").
- `.atlas/audit-history/<slug>.json` — append-only observation history
  (`atlas-audit-history-v1`), one digest-chained entry per publication.
- `.atlas/audit-decisions/<slug>.json` — append-only decision ledgers
  (`atlas-audit-decisions-v1`): finding dispositions, scope retirements,
  reconciliations.
- `.atlas/review-policy.json` — the consumer-owned review policy
  (`atlas-review-policy-v1`): classification rules, review units, and the
  decision policy. You write it; the tool validates, classifies, and seals
  its hash — it never writes this file.
- `.atlas/review-coverage.json` — the generated closed-world coverage
  report (`atlas-review-coverage-v1`), written only by
  `audit coverage update` and byte-compared by `audit coverage check`.
- `.atlas/migrations/amig_*.json` — sealed migration receipts
  (`atlas-audit-migration-v1`).
- `.atlas/audit-providers.json` — the consumer-owned provider policy
  (`atlas-audit-providers/v1`) that `audit run security` requires.
- `.atlas/.runtime/audit-runs/<invocationId>/` — clone-local provider run
  state (receipts, transcripts, resume chunks). Gitignored, never
  committed, and never coverage evidence.
- `.atlas/artifacts/historical-audits/` — bounded historical artifacts
  retained by the root-audits migrator.

On the tool side, the platform is small single-purpose modules under
`src/`: `audit-core` (canonical JSON, bounded hostile-input readers,
deterministic IDs, atomic writes, the audit lock), `audit-v3-types` +
`audit-v3` (the V3 model, strict parsing, publication, V1/V2 projection),
`audit-decisions` (append-only lifecycle), `audit-policy` (policy parsing,
tracked inventory, classification), `audit-coverage-generator` (the
exact/semantic join), `audit-import-codex` (sealed Codex Security 1.0
importer), `audit-migrate-relayos` + `audit-migrate-relayos-root-audits`
(consumer migrations), `audit-providers` + `audit-provider-grok` (provider
orchestration and the Grok adapter), `audit-cli` (the command surface).
`qa/` carries the optional LLM note/audit pipeline and its prompt
templates; `test/fixtures/` is bounded test data that never ships.

### V1/V2 compatibility

V1 (`finalPass: true` security schema) and V2 ledgers remain first-class
readable state: `status` tracks their drift, the viewer renders their
portfolios, and the coverage report joins them as legacy exact evidence
under the documented restrictions (V2 needs `reviewState: "complete"` and
a complete hashes map; V1 never becomes fresh from hashes alone). No
command produces new V2 ledgers. The single grandfathered write is
`audit import legacy-v1`, which converts a historical `scans[]` ledger
into the readable V1 form while preserving its scan-time hashes — a
compatibility conversion, not new evidence. Everything else — Codex
imports, migrations, and any future producer publication — writes V3.

### V3 guarantees

- Every reviewed file carries an exact blob identity, an explicit
  reviewed/not-reviewed status, and a clean/findings/unknown outcome —
  unknown is never rendered as clean, and semantic coverage is never
  manufactured from exact bytes (or vice versa).
- Observations seal producer, target, and scope identity digests, so a
  finding's provenance is checkable without trusting the producer's prose.
- Current ledgers, history entries, decision events, and migration
  receipts are canonical RFC 8785 JSON with deterministic IDs
  (`aobs_`/`atocc_`/`adev_`/`amig_`) and digest-verified chains; `audit
  check` revalidates every area.
- All readers are bounded and hostile-input safe (fatal UTF-8,
  duplicate-key/depth/member limits, symlink rejection); all writes are
  atomic replacements under the audit lock.

### Policy ownership

Repo Atlas owns the *generic* machinery and no product content: the
review-policy schema and classifier, the deterministic coverage generator,
the decision-policy guardrails, and the provider prompt/ruleset envelope.
The consumer repository owns its *product* policy — which paths need
review, which units they belong to, which rulesets are accepted, and how
decisions expire — as `.atlas/review-policy.json`, committed like code.
The tool ships no consumer ruleset text and no consumer policy (a
boundary the test suite greps for); the RelayOS migrators recognize the
legacy source formats but the policy they migrate *to* always comes from
the consumer via `--policy`.

### Exact versus semantic coverage

These are independent axes and the platform keeps them separate
everywhere. **Exact coverage** is per-file proof: the reviewed bytes (Git
blob identity) plus full-read receipts, joined by the coverage generator
into fresh/stale/missing/invalid evidence per required path. **Semantic
coverage** is the reviewer's claim about what the unit meaningfully covers
(surfaces, exclusions, open questions), reported as
covered/unknown/gap — the Codex Security 1.0 contract, for example,
carries semantic coverage with exact coverage honestly unknown. The
coverage report's `verdict` is `complete`, `incomplete` (honest gaps,
visible so progress shows; enforcement still fails without
`--allow-incomplete`), or `invalid` (structurally untrustworthy; all
embedded claims ignored). `audit coverage check` regenerates the report in
memory and byte-compares it against the committed file, so hand edits and
drift both fail.

### Decisions and retirement

Finding lifecycle is append-only: events are added to
`.atlas/audit-decisions/<slug>.json` and never edited or removed, so the
full trail survives. Every event is self-contained (actor, reason, review
context with exact blob bindings, evidence refs, proofs) and re-applying
the same event is an idempotent no-op (`already-present`).

```sh
repo-atlas audit decision set <finding-or-occurrence> <action> --event <event.json>
repo-atlas audit reconcile <before> <after> --event <event.json>
repo-atlas audit retire <path> --event <event.json>
repo-atlas audit retire --finalize-staged --event <event.json>
```

Disposition actions: `open`, `remediated`, `accepted-risk`,
`separate-design`, `false-positive`, `superseded`, `reopened`. The policy's
`securityDecisions` block makes them **expiry-aware** — `accepted-risk`
and `separate-design` must carry `expiresAt` within policy maximums
(severity overrides can tighten the ceiling and demand independent
reviews), `false-positive` must not expire but demands reviewed-blob and
source evidence — and **regression-aware** — `remediated` demands a fix
blob, post-fix proof, and a passing regression of an allowed kind.
Retirement reasons are `deleted`, `moved`, `superseded`,
`uncommitted-snapshot-absent`, and `staged-deletion` — a staged deletion
records the absence proof first and is later finalized by a superseding
event that retires the same path/blob (`--finalize-staged`), so a path
leaves coverage scope only with its history proven.

### Explicit Grok execution

```sh
repo-atlas audit run security --provider grok [--unit <slug> | --all | --stale] [--resume <id>]
```

This is the only command that launches a provider, and it refuses to run
without an explicit `--provider grok` and a valid
`.atlas/audit-providers.json` (command, model, concurrency, batch and
timeout limits). Default target selection is `--stale`: files whose exact
security evidence is not fresh, derived from the coverage generator's own
join — never a heuristic scan. Every other command, including all import,
migration, coverage, and legacy-alias paths, is deterministic local I/O;
the suite proves it with a recording fake `grok` that must stay silent.

The provider never sees your working tree. Each run copies the selected
files into a read-only byte-exact snapshot, spawns the CLI with
`shell: false`, exact argv, an allowlisted environment, an isolated
mode-0700 HOME, bounded stdout/stderr, and a timeout; session transcripts
are parsed and validated before any output is accepted, and the source
snapshot plus the original targets are re-verified afterwards. The sealed
run receipt (snapshot manifest, prompt template digest, ruleset digest,
transcript digests, per-file outcomes — no wall-clock fields) and the
transcripts stay clone-local under `.atlas/.runtime/audit-runs/<id>/`;
`--resume <id>` reuses completed chunks from a failed run. The CLI version
is probed against the supported contract before any analysis starts.

### Sealed Codex Security import

```sh
repo-atlas audit import codex-security <scan-dir> --slug <slug> [--apply]
```

Imports a sealed Codex Security completed-scan contract 1.0 bundle as a
V3 semantic observation. The import is offline and digest-checked: the
manifest must declare `codex-security.scan-manifest` schema 1.0 with
`status: completed` and `sealedAt` equal to `completedAt`, and every
artifact's recorded SHA-256 is verified against its exact bytes before
anything is read further. It is loss-preserving — because the 1.0
contract supplies no exact per-file blob receipts, the observation records
semantic coverage and leaves exact coverage unknown rather than inventing
receipts. Dry-run is the default; `--apply` publishes the current ledger
and appends history under the audit lock.

### RelayOS migrations (removed)

The two single-use RelayOS V1 migrators (`audit migrate relayos-security-v1` and
`relayos-root-audits-v1`) were deleted once that migration completed and the
consumer's legacy `audits/` tree was removed. `audit migrate` has no registered
migrations and the verb is gone.

Their sealed receipts remain at `.atlas/migrations/<migrationId>.json` in the
consumer repository and are still revalidated by `audit check`: each receipt's
digest covers both revisions, the repository identity, the policy seal, the
historical-assignment digest, the converter name/version/commit, and the sorted
raw input seals. The record of what was converted therefore survives the
converter.

### Audit lock and recovery

Canonical audit state operations — `audit check`, `audit status`,
`audit coverage check|update`, `audit decision set`, `audit reconcile`,
`audit retire`, observation publication (`import --apply`), and migration
applies — run under a single audit lock. The lock lives outside tracked
`.atlas/` in worktree-specific Git administrative state, at the path
printed by `git rev-parse --git-path repo-atlas/audit-state.lock`, so a
linked worktree never fights another branch. It is an exclusive-create
(`O_EXCL`), mode-0600 file whose canonical receipt records the pid, host,
process start time, command, and the source HEAD snapshot, and it is
always released when the operation settles.

A conflicting acquisition fails closed: `audit state lock is already held
by pid <pid> (<operation>)`. Atlas never steals, reclaims, or times out a
lock automatically — there is no stale-lock recovery inside the tool. If a
crashed run leaves one behind, read the receipt at the path above, confirm
the recorded process is gone, and delete the file yourself. If the receipt
is unreadable the error names "an unsafe or malformed existing lock" —
apply the same manual check.

### CI

`audit check` is the whole-state gate (policy, observations, decisions,
legacy ledgers, migration receipts, and canonical coverage in one exit
code); `audit coverage check` is the coverage-only byte-compare:

```sh
# strict — only a complete, current state passes
repo-atlas audit check

# progress-visible — honest missing/stale evidence is reported but allowed;
# structural invalidity (bad policy, corrupt ledgers, byte drift) still fails
repo-atlas audit check --allow-incomplete
repo-atlas audit coverage check --allow-incomplete
```

Because `audit coverage check` byte-compares the committed report, CI that
runs it also catches a `review-coverage.json` that drifted from what
`audit coverage update` would generate. The flat aliases (`audit-stamp`,
`audit-import`, `audit-localization-input`, `audit-localization-check`)
still work but print deprecation guidance naming their `audit ...`
replacements; new automation should use the hierarchical surface.

## Concept pages

The third page kind: an explainer for one important mechanism end-to-end
(often readable by non-developers), anchored to a SET of repo paths instead
of a single one.

- **Storage** — `.atlas/concepts/<slug>.md`, frontmatter + markdown body:

  ```
  ---
  title: 一通 IVR 电话的一生
  audience: general          # dev | general (general pages get a 👥 badge)
  sources: ["application/classes/model/app/ivrmodel.php", "application/classes/tts"]
  sources_hash: <sha1>       # managed by stamp — hashes of the sources, in order
  anchor: <commit>
  stamped: <iso>
  ---
  ```

- **Stamp** — `repo-atlas stamp .atlas/concepts/<slug>.md` (canonical; the
  shorthand `concepts/<slug>` also works when it doesn't collide with a real
  repo path) recomputes `sources_hash` — each source's current scan hash
  (blob hash for files, dir hash for dirs), concatenated in `sources` order
  and sha1'd — plus `anchor` and `stamped`. `stamp --all` covers concept
  pages too.

- **Freshness** — any source's hash changing flips the page to `outdated`; a
  source that no longer resolves in the scan is `broken-source` (reported per
  page by `status`, human and `--json` alike). There is no `missing`: concept
  pages exist only once someone writes them. Dir sources have dir-hash
  semantics — direct children only, deep edits flag the nested dir, so list
  the specific subdirs you actually lean on.

- **Viewer** — concept pages sit in a dedicated Concepts view and render like
  any note (mermaid, raw HTML, glossary). The default **Overview** is derived
  from the opening markdown of that same canonical page and shows the section
  map; **Full walkthrough** reveals the unchanged complete body. There is no
  second summary file to drift. Because a concept has no file of its own,
  `code:` anchors must carry a full repo path:
  `[label](code:path/to/file.ts#StartMarker..EndMarker)` — same marker semantics
  as file pages, link and `![embed]` forms both.

## Raw HTML in notes

Notes are markdown, and raw HTML (including inline styles) passes through —
when a concept is clearer drawn than told and mermaid's rigid layouts can't
express it, free-form HTML is encouraged: byte/memory layout diagrams,
annotated timelines, color-coded comparison matrices, nested-box topology.
The bar is conceptual gain — layout should carry meaning, not decorate.

Three ready-made classes come styled by the viewer, for when you don't want
to hand-roll styles:

- `<div class="callout"> … </div>` — highlighted aside (deep-dive details,
  warnings).
- `<details><summary>label</summary> … </details>` — collapsible section for
  material most readers should skip.
- `<div class="cols"><div>…</div><div>…</div></div>` — side-by-side columns
  (each child `<div>` is one column; stacks on narrow screens).

Custom layouts should inline their styles (the viewer theme is light:
`#fbfbfa` background, `#e7e5e1` borders, `#3d6b54` accent). Gotcha: markdown
inside a block-level HTML tag only renders if a BLANK LINE separates it from
the tag — `<div class="callout">`, blank line, markdown, blank line, `</div>`.

Two things are derived from the code, not written in notes: **import
relations** — every page shows "imports → / ← imported by" chips (exact files
for a file, grouped to package roots for a directory), resolved from relative
imports and workspace package names, memoized by blob hash so serve stays
fast. And the **glossary** — define project jargon once in
`.atlas/glossary.md` (`## term`, optional `别名：`/`aliases:` line, body);
every occurrence in note prose gets a dotted underline with a hover popover,
so terminology can't drift between notes.

Selecting a path splits the right side into description + a multi-mode panel
with three tabs. **Code** — the source, syntax-highlighted (served from
`/raw`; only paths inside the scan, never arbitrary disk paths). **Changes**
— `git diff` from the note's anchor commit to the working tree: what happened
to this file since the note was written, i.e. the review that decides whether
the note is still trustworthy. **Contents** — the reading tree of the "book"
the page belongs to: `basePoints` in `.atlas/config.json` lists self-contained
subtrees (e.g. `apps/daemon`), and the contents view roots at the nearest one
rather than the file's immediate parent; it shows pure reading structure (no
staleness dots — those are the maintainer's concern, the sidebar keeps them).
Both the sidebar and the panel collapse to thin rails. The static `build`
output carries descriptions only — code and diff show a hint instead.

## Viewer

The viewer is a small React app in `viewer/` (App/Tree/Doc/Preview components +
`lib.js` helpers), prebuilt into `src/vendor/viewer.js` + `viewer.css` and
COMMITTED — target repos still run the tool with zero install and zero build.
To hack on it:

```sh
pnpm install
pnpm dev:viewer      # esbuild --watch; repo-atlas serve picks the bundle up per request
pnpm build:viewer    # minified bundle — commit the regenerated vendor files
```

Syntax highlighting is a vendored highlight.js bundle (`src/vendor/hljs.js`),
regenerated with:

```sh
pnpm dlx esbuild src/vendor/hljs-entry.mjs --bundle --minify --format=iife --outfile=src/vendor/hljs.js
```

Note bodies may contain ` ```mermaid ` fences — they render as diagrams in the
viewer. The vendored mermaid bundle (`src/vendor/mermaid.js`, ~3.4MB, copied from
`node_modules/mermaid/dist/mermaid.min.js`) is embedded into the output HTML only
when at least one note actually uses a mermaid fence; a fence that fails to parse
falls back to showing the error plus the source.

No install needed — run straight from GitHub with whichever runner you have
(deliberately NOT a dependency of target repos):

```sh
bunx github:KUD-00/repo-atlas serve
npx  github:KUD-00/repo-atlas serve
pnpm dlx github:KUD-00/repo-atlas serve
```

For a resident `repo-atlas` command (or to hack on the tool):

```sh
git clone git@github.com:KUD-00/repo-atlas.git && cd repo-atlas
pnpm install && pnpm link --global
```

## Versioning contract

The only coupling between tool and data is the `.atlas/` format, tracked as
`formatVersion` in `config.json` (absent = 1). The tool migrates older data
forward transparently; data written by a NEWER tool fails with a clear
"update the tool" error. Target repos never pin the tool.

## Agent workflow

The core tool deliberately does **not** call an LLM. Description quality comes from letting a
coding agent (Claude Code etc.) actually read the code:

1. `repo-atlas status --json` → lists `missing`, `outdated` (with diff size), `moved`,
   `brokenRefs`, audit drift, and readability drift/trend.
2. `repo-atlas migrate --apply` → notes follow moved paths mechanically; only genuinely
   changed content is left for reading.
3. Agent reads the code for each remaining path, writes/updates the note body in
   `.atlas/notes/...` (keep frontmatter lines if present; `stamp` rewrites them anyway).
4. `repo-atlas stamp` → marks those notes current (recording the HEAD anchor).
5. `repo-atlas build` → refreshed HTML.

For an `outdated` path, `git diff <anchor> -- <path>` (the anchor is in the note's
frontmatter) shows exactly what changed since the note was written — revise against
that rather than rewriting from scratch. Note bodies talk about the CODE, never
about the atlas itself — no viewer-manual prose ("click the heading", "jumps
the preview pane", "check will flag the rot"); anchors and embeds are invisible
infrastructure, so write labels that still read as plain prose if the link
never renders. Check `brokenRefs` after any reorganization:
those notes' subjects didn't change, only their references to other paths did.

Suggested note shape: 1–3 sentences of *what this is and why it exists*, then bullets for
anything non-obvious (invariants, gotchas, who calls it). Directory notes describe the
area's role and how its children divide the work — not a file-by-file inventory.

## QA pipeline (optional LLM suite)

[`qa/`](qa/README.md) is a self-contained batch pipeline that generates and quality-gates
notes at scale: per-note blind-reader review (N readers, empty-cwd isolation) + read-only
fact-checking against current source + revision loops behind a rubric gate, with a sweep
driver for whole-repo runs. It shells out to a headless agent CLI (grok by default) and is
strictly optional — the core stays LLM-free. Per-repo customization (prompt overrides,
extra rules, rubric tweaks) lives in the target repo's `.atlas/pipeline/`.
See [qa/README.md](qa/README.md) for the new-repo recipe.

The same suite carries the judgment-level audits, which produce ledgers rather
than notes: `qa/audit.ts` (security, per concept page) and `qa/design.ts`
(design reasonableness, per path set from `.atlas/pipeline/design-units.json`).
Both run read-only behind a tool-evidence gate and a per-finding fact-check
gate, and neither may overwrite a review that still holds for the current bytes.
