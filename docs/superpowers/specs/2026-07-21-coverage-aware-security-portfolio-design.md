# Coverage-aware security portfolio design

Date: 2026-07-21
Status: approved

## Context

Repo Atlas now has first-class Code, Concepts, Security, and Tests navigation,
but the Security projection only knows completed `.atlas/audits/*.json` units.
That creates an unsafe ambiguity:

- zero loaded units is displayed as `0`, even when a repository has audit
  evidence in another producer-owned format;
- completed units prove what was reviewed, but do not define what should have
  been reviewed;
- a zero-finding unit can look clean even when other required paths are absent;
- the right-hand repository tree is a Code navigation surface, not a security
  coverage model.

RelayOS demonstrates the mismatch. It currently has 4,528 Git-tracked paths,
2,554 paths in the configured Atlas Code index, approximately 800 test-like
paths excluded from that Code index, and 242 active exact-blob security scan
records. None of those numbers is interchangeable. The Code index cannot be a
security denominator, and the existing scan ledger cannot prove that an absent
path was deliberately excluded.

The approved RelayOS closed-world audit design already separates three facts:

1. policy says which review domains a tracked path requires;
2. audit ledgers say which exact bytes an auditor reviewed;
3. a deterministic coverage report joins current Git inventory, policy, and
   evidence.

This design makes that third fact a generic Atlas input and reorganizes the
Security viewer around coverage, risk, and evidence without teaching Atlas any
RelayOS-specific policy semantics.

## Decision

Security becomes a coverage-first assurance portfolio.

The primary navigation entity is a stable audit unit or security area, not a
raw repository path. The Security home answers, in order:

1. Is the claimed review universe complete and current?
2. What actionable or explicitly retained risk exists?
3. What recent audit produced the claim, and what exact evidence backs it?

Files remain available as searchable drill-down evidence inside an audit unit
or coverage-gap view. The generic Code tree is collapsed by default on audit
routes and opens only as a contextual source/evidence inspector.

Coverage and risk are orthogonal. A fully covered unit may contain findings. A
unit with zero findings is not clean when its coverage is missing, stale,
invalid, or unknown.

## Goals

- Render already-reviewed scope without implying that recorded scope is the
  complete universe.
- Render missing, stale, unclassified, conflicting, and invalid evidence as
  first-class non-clean states.
- Keep Security and Tests separate while supporting paths that require both.
- Group the portfolio by stable architectural audit units and retain a precise
  per-file drill-down.
- Show current actionable findings, retained risk, ruleset, scan time, and
  evidence identity without embedding producer-specific raw audit systems.
- Make missing or malformed coverage data visibly unknown rather than `0` or
  clean.
- Let repositories generate partial progress reports while enforcement still
  fails until coverage is complete.

## Non-goals

- Atlas does not run an LLM, classify repository paths, adjudicate findings, or
  decide whether a policy is appropriate.
- File review coverage is not presented as proof that software has no unknown
  vulnerabilities.
- The first version does not introduce a threat-control or invariant matrix.
  That can later become a second assurance dimension once producers have a
  stable control catalog.
- Atlas does not ingest RelayOS's private `audits/security-scan/**` formats.
- The viewer does not embed raw Grok transcripts or maintain a historical
  findings database. It shows current validated units and their current audit
  metadata.

## Sources of truth and ownership

Each repository owns its policy and evidence production. Atlas consumes only
versioned, producer-neutral projections:

- `.atlas/audits/*.json` contains completed `atlas-audit-v2` Security or Tests
  units, exact file scope, hashes, findings, and current audit metadata.
- `.atlas/review-coverage.json` contains an `atlas-review-coverage-v1` report
  joining the complete Git-tracked universe to policy and fresh evidence.

The repository's checker remains authoritative for its policy semantics and
enforcement. Atlas independently validates the generic report structure,
contained paths, current Git inventory, and current file blobs. It never
reimplements the repository's pattern language or exclusion rules.

For RelayOS, `.atlas/review-policy.json` remains a RelayOS-owned input to its
checker. Atlas neither loads nor interprets it.

## Generic coverage report contract

The report is deterministic and contains no generation timestamp. Its verdict
may be `complete`, `incomplete`, or `invalid`. Writing an incomplete report is
allowed so Atlas can display migration progress; CI and pre-commit require a
current report whose verdict is `complete`.

```json
{
  "formatVersion": 1,
  "format": "atlas-review-coverage-v1",
  "verdict": "incomplete",
  "policy": {
    "format": "relayos-review-policy-v1",
    "hash": "<sha256-of-canonical-policy>"
  },
  "inventoryHash": "<sha256-of-current-tracked-inventory>",
  "units": [
    {
      "domain": "security",
      "slug": "security-apps-daemon",
      "title": "Daemon"
    }
  ],
  "summary": {
    "tracked": 4528,
    "securityRequired": 1900,
    "securityFresh": 242,
    "securityMissing": 1658,
    "securityStale": 0,
    "securityInvalid": 0,
    "testRequired": 800,
    "testFresh": 0,
    "testMissing": 800,
    "testStale": 0,
    "testInvalid": 0,
    "dualRequired": 20,
    "excluded": 1848,
    "unclassified": 0,
    "conflicted": 0,
    "invalidLedgers": 0
  },
  "entries": [
    {
      "path": "apps/daemon/src/index.ts",
      "blob": "<git-blob-sha1>",
      "ruleIds": ["first-party-runtime"],
      "classification": {
        "kind": "review",
        "domains": {
          "security": {
            "unit": "security-apps-daemon"
          }
        }
      },
      "evidence": {
        "security": {
          "status": "fresh",
          "ledgers": ["security-apps-daemon"]
        }
      }
    }
  ],
  "invalidLedgerDetails": [],
  "reportErrors": []
}
```

`invalidLedgerDetails` entries contain the safe repository-relative ledger
path, an optional validated slug, and a stable error code plus explanatory
message. `reportErrors` uses the same code/message shape and may additionally
name an affected repository path. It records policy or inventory failures that
prevent a trustworthy join; it is non-empty when verdict is `invalid`.

Summary values are recomputed by both producer and Atlas rather than trusted as
display metadata. `securityFresh + securityMissing + securityStale +
securityInvalid` equals `securityRequired`, with the equivalent identity for
Tests. `tracked` equals unique review-classified paths plus excluded,
unclassified, and conflicted paths; dual-domain paths occur once in `tracked`
and in both required-domain totals.

`units` is the stable portfolio registry. Each entry has one domain, a
route-safe unique slug, and a non-empty title. Every required domain on every
review-classified path names exactly one registered unit of the same domain,
even when that path has no evidence yet. Completed ledger slugs normally match
their registered unit; supplementary ledgers may also appear in the evidence
array. This separation is what lets Atlas calculate `fresh / required` and
show an entirely unaudited area without inventing a file-tree denominator.

### Classification states

Each tracked path has exactly one classification:

- `review`, with one or both required domains and one registered target unit
  for each domain;
- `excluded`, with category, reason, rule ID, and optional owner;
- `unclassified`;
- `conflict` when policy rules produce incompatible decisions.

A required domain has exactly one evidence status:

- `fresh`: one or more completed ledgers contain the exact current blob;
- `missing`: no completed ledger claims the path/domain pair;
- `stale`: a ledger claims the pair but its blob differs or disappeared;
- `invalid`: only structurally invalid evidence claims the pair.

An exclusion never receives an evidence status. A path requiring both domains
has independent Security and Tests states.

### Report verdict

`complete` requires zero unclassified paths, conflicts, invalid ledgers,
missing evidence, and stale evidence. `incomplete` is a structurally valid
report with one or more explicit gaps. `invalid` represents a deterministic
analysis that could not produce trustworthy classifications or evidence joins.
An invalid report must contain at least one `reportErrors` entry; Atlas may show
its diagnostic paths but ignores all embedded fresh/covered claims. Complete
and incomplete reports require an empty `reportErrors` array.

The report generator may atomically write all three verdicts. Enforcement
fails unless the committed bytes are current and the verdict is `complete`.
This does not bless a gap: the artifact explicitly proves the gap and the gate
still rejects it.

### Freshness and self-reference

The producer derives `inventoryHash` as SHA-256 over sorted
`<git-blob-sha1>  <path>` lines with a final newline. Atlas re-enumerates
Git-tracked paths with NUL-safe handling and recomputes current blob IDs. It
reports added, removed, and changed paths relative to the coverage report
before trusting the embedded verdict.

Atlas may use stage-zero blobs from `git ls-files --stage -z` for index-clean
regular files and rehash only paths reported by `git diff-files -z`. This is an
exact Git/worktree snapshot, not a timestamp cache, and avoids rereading every
tracked file during each live-server poll. Symlink mode, gitlinks, unresolved
index stages, unreadable dirty paths, or duplicate aliases fail closed.

The report's own tracked path uses one reserved generated-proof exclusion and
has no self-referential blob. For that exact entry only, both producer and
Atlas substitute the literal blob field `GENERATED-PROOF` in the inventory-hash
line. Its generator byte-compares canonical output. No other path may omit its
blob or use the marker.

Malformed JSON, unsupported versions, duplicate or unsafe paths, symlinked
files/directories, inconsistent summaries, unknown statuses, missing required
domain evidence, unknown or cross-domain unit references, mismatched ledger
slugs, or blob drift make the viewer state invalid or stale. They never degrade
to an empty portfolio.

## Audit unit contract changes

Atlas exposes the validated unit's normalized `files` array to the viewer so a
unit detail can show its reviewed scope. Per-file current/evidence state comes
from the coverage report, not from a second UI-side join.

Version 2 Security findings may carry two optional producer-neutral fields:

- `id`: a stable finding identity;
- `disposition`: `open | accepted-risk | separate-design`.

Absence of `disposition` means `open`. Remediated and false-positive historical
records do not enter the active findings array. Producers may expose those as
page artifacts, but Atlas does not count them as current risk.

Version 2 units may also carry `evidenceRefs`, a unique array of normalized,
safe repository-relative regular-file paths. These references identify the
producer-owned evidence accepted when the completed ledger was built. Atlas
may open them as artifacts or source, but the repository checker—not their mere
presence in the viewer—decides whether they are authentic.

`isCleanAuditUnit` is replaced by an assurance-state calculation. The phrase
`clean` is not used. A fresh, fully covered unit with no open findings is shown
as `no actionable findings`; accepted risk and separate-design findings remain
visible and named.

## Viewer information architecture

### Primary navigation suffix

The Security and Tests primary buttons no longer show a bare total-finding
count. They show the highest-priority concise state:

1. `unknown` when the report is missing or invalid;
2. `<n> gaps` when coverage is incomplete or stale;
3. `<n> open` when coverage is complete and actionable findings exist;
4. `covered` when coverage is complete and no actionable findings exist.

Accessible labels contain the full domain and state; color is never the only
signal.

### Security sidebar

The Security sidebar contains:

- Overview;
- Needs attention, with the current actionable count;
- Coverage gaps, with the current gap count;
- a divider followed by stable Security audit units.

Unit rows show two independent compact states: coverage and current risk. They
are ordered by required action: invalid/unknown, missing/stale, highest open
severity, then title. Raw paths do not appear in this navigation.

### Security overview

The overview begins with one explicit repository-level statement:

- `Coverage complete and current`;
- `Coverage incomplete — N required reviews are missing`;
- `Coverage stale — source changed after review`;
- `Coverage unavailable or invalid`.

It then renders three separate summaries:

1. Coverage: required, fresh, missing, stale, unclassified, excluded, and
   dual-domain counts.
2. Risk: open findings by severity plus accepted-risk and separate-design
   counts.
3. Evidence: completed/current units, invalid units, rulesets, and most recent
   scan.

The next section is a single prioritized action queue. Coverage failures sort
before findings because findings cannot describe an unknown scope. Within
findings, severity determines order. Accepted risks and separate-design items
remain visible but are not mixed into the open-action count.

The portfolio table follows, one row per registered stable Security unit,
including units that do not yet have a completed ledger. Each row shows:

- unit title;
- fresh/required file pairs;
- gap state;
- open and retained finding counts;
- ruleset and latest scan date.

A final recent-audits section sorts current units by `scannedAt` and reports
unit, file count, ruleset, finding outcome, and whether the coverage report
currently accepts the evidence. It does not infer historical transitions.

### Unit detail

Selecting a unit opens one page with three sections or tabs:

- Findings: open, accepted-risk, and separate-design findings with code jumps;
- Coverage: searchable in-scope files and their fresh/missing/stale/invalid
  domain states;
- Evidence: scan time, ruleset, scope hash, rounds, exact ledger slug, and
  coverage-report acceptance.

The Coverage section is the only file-tree-like surface. It is a flat,
searchable status table by default; optional directory grouping is a display
aid and never changes the denominator.

### Contextual right panel

On first entry to Security or Tests, the generic Code/Changes/Contents panel is
closed. An explicit user reopen remains respected within that audit session.
Clicking a finding location or coverage path opens it directly in Code mode at
the selected source. Clicking an evidence reference opens the corresponding
artifact. Returning to the overview does not automatically replace the chosen
source with an unrelated root repository tree.

### Empty and failure states

- Missing coverage report: `Coverage has not been established`; loaded audit
  units may still be shown as recorded evidence, but never as complete.
- No audit units: `No completed audit evidence`; never `0 = clean`.
- Complete coverage and zero open findings: `No actionable findings in current
  completed review`; never `secure` or `vulnerability-free`.
- Incomplete report: show exact gaps and already-fresh counts together.
- Invalid report or ledger: show the exact validation reason and exclude its
  claims from clean counts.

Tests uses the same coverage shell and navigation semantics, but keeps its
domain-specific impact, category, invariant, and evidence vocabulary. Security
findings are never coerced into Test findings or vice versa.

## Data flow

1. A repository-owned checker enumerates the complete tracked universe,
   evaluates its reviewed policy and stable unit assignment, validates current
   domain ledgers, and writes the deterministic coverage report atomically.
2. Atlas performs its normal source scan plus one independent coverage load.
3. Atlas validates report structure, inventory membership, blobs, summary
   totals, and ledger references without interpreting repository policy rules.
4. `build` and `serve` add a typed coverage portfolio to `AtlasPayload`.
5. The viewer derives domain summary, priority queue, unit state, recent audit
   list, and file drill-down from that portfolio and the existing audit units.
6. Live serve rebuilds this data on source, ledger, or coverage-report change;
   current filters and route state remain stable.

The CLI `status` command reports the same coverage verdict and failure buckets
as the viewer. A static HTML build embeds the validated report, so it does not
require the repository checker or a server at view time.

## RelayOS migration

RelayOS implements its existing closed-world plan with these refinements:

- change the materialized output format from
  `relayos-review-coverage-v1` to the generic `atlas-review-coverage-v1`;
- allow deterministic incomplete and invalid reports during baseline creation,
  while keeping enforcement fail-closed until `complete`;
- project only current, fully validated legacy security evidence into stable
  architectural `atlas-audit-v2` units;
- assign every required path/domain pair to a registered stable unit before
  evidence exists, so missing coverage remains attributable and actionable;
- include stable IDs and retained dispositions for accepted-risk and
  separate-design findings;
- audit every remaining Security and Tests path with the planned independent
  primary/verification passes;
- wire the completed report into root check, pre-commit, and CI only after all
  required domain gaps are zero.

The projection does not rewrite historical source blobs, infer clean results,
or read stale/failed Grok output. Existing candidate, disposition, raw-envelope,
and post-fix enforcement remains authoritative and continues to run before the
new coverage gate.

## Compatibility

Legacy `atlas-audit-v1` Security units remain readable as recorded evidence but
cannot establish closed-world coverage without a valid coverage report. The
current `audit:security/<slug>` and `audit:test/<slug>` routes remain valid.
No RelayOS-private format becomes an Atlas dependency.

Repositories without a coverage report continue to use Code and Concepts and
may browse completed audit units. Their Security/Tests pages explicitly show
coverage as unavailable; they do not receive a fabricated denominator.

## Testing

Atlas parser tests cover complete, incomplete, invalid, missing, malformed,
future-version, duplicate-path, unsafe-path, symlink, inventory-drift,
per-domain stale, summary-mismatch, self-entry, and unknown-ledger-reference
reports. Temporary Git repositories cover NUL-safe filenames and added/deleted
tracked paths.

Viewer tests cover primary suffix priority, unknown and partial states,
coverage/risk separation, dual-domain paths, unit ordering, actionable and
retained dispositions, recent-audit ordering, searchable file drill-down,
right-panel default collapse, source/evidence jumps, and the prohibition on
clean wording without complete current coverage.

RelayOS checker tests cover total classification, broad exclusions, executable
exceptions, fresh/missing/stale joins, dual-domain requirements, deterministic
partial and complete reports, atomic writes, self-reference, and enforcement
failure for every non-complete verdict. Projection and Grok baseline tests
remain exact-blob, fail-closed, and independently verified.

End-to-end acceptance builds Atlas against RelayOS at three fixtures:

1. no coverage report plus current legacy evidence;
2. incomplete coverage with both already-fresh and missing paths;
3. complete coverage with open, accepted-risk, and separate-design findings.

## Completion criteria

- Atlas never uses its Code tree as a Security or Tests denominator.
- RelayOS classifies every tracked path and has fresh evidence for every
  required domain pair.
- Atlas renders coverage, current risk, and recent evidence as separate facts.
- Files are available as drill-down evidence, not primary Security navigation.
- Missing, partial, stale, or invalid data is visibly non-clean.
- RelayOS root check, pre-commit, CI, all focused checks, full tests, and Atlas
  build/viewer tests pass without bypasses.
