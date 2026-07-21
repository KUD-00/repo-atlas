# Coverage-aware Security Portfolio Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Repo Atlas render closed-world Security and Tests coverage, current risk, and exact audit evidence as separate trustworthy facts, with audit units as navigation and files as drill-down.

**Architecture:** A strict `review-coverage` loader consumes the generic deterministic report and independently validates Git inventory, blobs, summary arithmetic, unit ownership, and audit-ledger references. A pure `audit-assurance` layer derives all presentation state; React renders that model without inventing coverage from the Code tree. RelayOS remains responsible for classification, evidence production, and enforcement.

**Tech Stack:** TypeScript 5.8, Node.js test runner, React 19, Lingui, Tailwind 4, Git blob hashes, JSON contracts.

---

## File structure

- `src/review-coverage.ts` — strict coverage report parsing, safe tracked-inventory hashing, freshness overlay, summary/unit/ledger cross-validation.
- `src/audit-assurance.ts` — pure domain summaries, nav suffix, action ordering, unit rows, file rows, recent audit derivation.
- `src/audit-panel.ts` — pure audit-route panel transition policy.
- `src/types.ts` — coverage report/runtime types plus richer audit-unit and finding types.
- `src/audits.ts` — v2 audit metadata validation and runtime projection.
- `src/build.ts`, `src/serve.ts`, `src/cli.ts` — payload, live digest, static build, and status integration.
- `viewer/AuditCoverage.tsx` — shared coverage/status/evidence presentation primitives.
- `viewer/AuditNav.tsx` — overview/action/gap controls and unit dual-state navigation.
- `viewer/Security.tsx`, `viewer/TestAudit.tsx` — domain-specific portfolio and unit detail panes.
- `viewer/App.tsx` — coverage-aware primary suffix and contextual panel behavior.
- `test/review-coverage.test.mjs` — temporary-repository contract, path, freshness, and cross-reference tests.
- `test/audit-assurance.test.mjs` — pure portfolio semantics.
- `test/audit-panel.test.mjs` — direct-entry and transition behavior.
- Existing `test/audits.test.mjs`, `test/build.test.mjs`, and `test/audit-routes.test.mjs` — compatibility and wiring regression coverage.
- `README.md`, `viewer/locales/*/messages.po`, `src/vendor/viewer.{js,css}` — public contract, translations, and committed viewer bundle.

Temporary `.superpowers/` and `.gstack/` files are tooling state and must never be staged with product commits.

### Task 1: Expose trustworthy v2 audit-unit evidence

**Files:**
- Modify: `src/types.ts`
- Modify: `src/audits.ts`
- Modify: `test/audits.test.mjs`
- Modify: `test/helpers.mjs`

- [ ] **Step 1: Write failing v2 metadata tests**

Extend the existing `writeV2` fixtures with complete hashes, evidence references, and Security dispositions. Add tests with these exact assertions:

```js
test('v2 security units expose exact scope, evidence refs, and normalized dispositions', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    write(root, 'audits/evidence/a.json', '{}\n')
    commitAll(root)
    writeV2(root, 'security', 'security-runtime', ['src/a.ts'], [{
      id: 'SEC-1',
      severity: 'medium',
      category: 'boundary',
      title: 'boundary is open',
      locations: ['src/a.ts:1'],
      dataflow: 'input to sink',
      fix: 'validate it',
      disposition: 'accepted-risk',
    }], {
      hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') },
      evidenceRefs: ['audits/evidence/a.json'],
    })
    const unit = loadAuditPortfolios(root).security[0]
    assert.deepEqual(unit.files, ['src/a.ts'])
    assert.deepEqual(unit.hashes, { 'src/a.ts': gitBlob(root, 'src/a.ts') })
    assert.deepEqual(unit.evidenceRefs, ['audits/evidence/a.json'])
    assert.equal(unit.findings[0].disposition, 'accepted-risk')
  } finally { cleanup(root) }
})

test('v2 security finding without disposition normalizes to open', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writeV2(root, 'security', 'security-runtime', ['src/a.ts'], [{
      severity: 'low', category: 'boundary', title: 'open by default',
      locations: ['src/a.ts:1'], dataflow: 'input to sink', fix: 'validate it',
    }], { hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') } })
    assert.equal(loadAuditPortfolios(root).security[0].findings[0].disposition, 'open')
  } finally { cleanup(root) }
})

test('v2 units reject invalid dispositions and unsafe or duplicate evidence refs', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    writeV2(root, 'security', 'security-bad', ['src/a.ts'], [{
      severity: 'low', category: 'boundary', title: 'bad disposition',
      locations: ['src/a.ts:1'], dataflow: 'input to sink', fix: 'validate it',
      disposition: 'ignored',
    }], { evidenceRefs: ['../outside', '../outside'] })
    assert.equal(loadAuditPortfolios(root).security.length, 0)
    const invalid = auditStatusEntries(root, scan(root, { exclude: [] }))
      .find((entry) => entry.name === 'security-bad')
    assert.match(invalid.invalidReason, /disposition|evidence ref|normalized/i)
  } finally { cleanup(root) }
})
```

Add and use this helper beside `scopeHash` in `test/helpers.mjs`:

```js
export function gitBlob(root, file) {
  return execFileSync('git', ['hash-object', '--', file], {
    cwd: root,
    encoding: 'utf8',
  }).trim()
}
```

Add separate fixtures for duplicate refs, a missing ref, and a symlinked ref;
each must be omitted from the portfolio and have a matching invalid status
reason. Keep those fixtures separate so one earlier validation error cannot
mask another.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
pnpm build:cli && node --test --test-name-pattern='scope, evidence refs|disposition|evidence ref' test/audits.test.mjs
```

Expected: FAIL because runtime units do not expose `files`, `hashes`, or `evidenceRefs`, and findings do not normalize disposition.

- [ ] **Step 3: Add the strict runtime contract**

Add these types to `src/types.ts` and use them consistently:

```ts
export type SecurityFindingDisposition = 'open' | 'accepted-risk' | 'separate-design'

export interface AuditFinding {
  id?: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  category: string
  title: string
  locations: string[]
  dataflow: string
  fix: string
  confidence?: string
  disposition: SecurityFindingDisposition
}

export interface BaseAuditUnit {
  formatVersion: 1 | 2
  domain: AuditDomain
  slug: string
  title: string
  ruleset: string
  scannedAt: string
  scopeHash: string
  fileCount: number
  files: string[]
  hashes: Record<string, string> | null
  evidenceRefs: string[]
  droppedCount: number
  roundCount: number
  stale: boolean
}
```

In `src/audits.ts`, validate optional raw `id`, `disposition`, and `evidenceRefs`. IDs are non-empty strings of at most 256 code units. Evidence refs are unique normalized repository-relative paths that resolve through `isSafeRepoFile`. Normalize absent Security dispositions to `open`. Project `files`, `scope_hash`, complete hashes or `null`, and evidence refs into every runtime unit. Legacy v1 units get `hashes: null` and `evidenceRefs: []`.

- [ ] **Step 4: Run focused and existing audit tests**

Run:

```bash
pnpm build:cli && node --test test/audits.test.mjs test/audit-routes.test.mjs
```

Expected: PASS.

- [ ] **Step 5: Commit only Task 1 files**

```bash
git add src/types.ts src/audits.ts test/audits.test.mjs test/helpers.mjs
git commit -m "feat: expose exact audit unit evidence"
```

### Task 2: Parse deterministic coverage reports fail-closed

**Files:**
- Create: `src/review-coverage.ts`
- Create: `test/review-coverage.test.mjs`
- Modify: `src/types.ts`

- [ ] **Step 1: Define fixture builders and write structural RED tests**

In `test/review-coverage.test.mjs`, create temporary Git repositories with
`makeRepo`, write one valid v2 ledger, and build a canonical report fixture
shaped exactly as the approved spec. The tests are named:

- `missing coverage report is unknown rather than zero coverage`: omit the
  file and assert `{ state: 'missing', report: null }`.
- `complete and incomplete reports preserve explicit verdicts`: write the same
  structurally valid fixture with each verdict and assert the declared verdict
  survives only when its failure buckets agree.
- `invalid report ignores every embedded fresh claim`: declare `invalid`, add a
  report error and a fake fresh count, then assert state invalid and no trusted
  report projection.
- `coverage report rejects malformed JSON and future versions`: exercise `{not
  json` and `formatVersion: 99`, checking stable diagnostics.
- `coverage report rejects duplicate paths, units, and unsafe aliases`: mutate
  the valid fixture independently for each case and require invalid state.
- `coverage report recomputes summary identities and unit ownership`: change
  each summary identity and cross-domain unit slug independently and require
  invalid state.

The valid fixture must contain:

```js
{
  formatVersion: 1,
  format: 'atlas-review-coverage-v1',
  verdict: 'incomplete',
  policy: { format: 'fixture-policy-v1', hash: 'a'.repeat(64) },
  inventoryHash,
  units: [{ domain: 'security', slug: 'security-src', title: 'Source' }],
  summary: {
    tracked: 4,
    securityRequired: 1,
    securityFresh: 1,
    securityMissing: 0,
    securityStale: 0,
    securityInvalid: 0,
    testRequired: 0,
    testFresh: 0,
    testMissing: 0,
    testStale: 0,
    testInvalid: 0,
    dualRequired: 0,
    excluded: 3,
    unclassified: 0,
    conflicted: 0,
    invalidLedgers: 0,
  },
  entries: [
    {
      path: 'src/a.ts', blob: gitBlob(root, 'src/a.ts'), ruleIds: ['source'],
      classification: { kind: 'review', domains: { security: { unit: 'security-src' } } },
      evidence: { security: { status: 'fresh', ledgers: ['security-src'] } },
    },
    {
      path: '.atlas/review-coverage.json', ruleIds: ['generated-proof'],
      classification: {
        kind: 'excluded', ruleId: 'generated-proof', category: 'generated-proof',
        reason: 'canonical report validates its own bytes',
      },
      evidence: {},
    },
    {
      path: '.atlas/config.json', blob: gitBlob(root, '.atlas/config.json'),
      ruleIds: ['fixture-config'],
      classification: {
        kind: 'excluded', ruleId: 'fixture-config', category: 'fixture',
        reason: 'fixture configuration is outside this parser test',
      },
      evidence: {},
    },
    {
      path: '.atlas/audits/security-src.json',
      blob: gitBlob(root, '.atlas/audits/security-src.json'),
      ruleIds: ['generated-ledger'],
      classification: {
        kind: 'excluded', ruleId: 'generated-ledger', category: 'generated',
        reason: 'strict fixture builder output',
      },
      evidence: {},
    },
  ],
  invalidLedgerDetails: [],
  reportErrors: [],
}
```

Write and commit the config, source, and ledger first. Write the report, stage
it with `git add .atlas/review-coverage.json` so `git ls-files -z` includes the
self entry, and compute `inventoryHash` with the specified `GENERATED-PROOF`
marker. Never make the fixture omit a tracked path merely to simplify totals.

Assert a missing file returns `{ state: 'missing' }`; invalid JSON returns `{ state: 'invalid' }` with a stable error; an invalid declared verdict requires non-empty `reportErrors`; complete/incomplete require none; and embedded summary mismatches are rejected rather than displayed.

- [ ] **Step 2: Run the structural tests and verify RED**

```bash
pnpm build:cli && node --test --test-name-pattern='coverage report|missing coverage|complete and incomplete|invalid report' test/review-coverage.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `dist/review-coverage.js`.

- [ ] **Step 3: Add coverage report and portfolio types**

Define the exact discriminated types in `src/types.ts`:

```ts
export type ReviewCoverageVerdict = 'complete' | 'incomplete' | 'invalid'
export type CoverageEvidenceStatus = 'fresh' | 'missing' | 'stale' | 'invalid'

export interface CoverageUnitRef {
  domain: AuditDomain
  slug: string
  title: string
}

export type CoverageClassification =
  | { kind: 'review'; domains: Partial<Record<AuditDomain, { unit: string }>> }
  | { kind: 'excluded'; ruleId: string; category: string; reason: string; owner?: string }
  | { kind: 'unclassified' }
  | { kind: 'conflict' }

export interface CoverageEntry {
  path: string
  blob?: string
  ruleIds: string[]
  classification: CoverageClassification
  evidence: Partial<Record<AuditDomain, { status: CoverageEvidenceStatus; ledgers: string[] }>>
}

export interface CoverageDiagnostic {
  code: string
  message: string
  path?: string
  slug?: string
}

export interface ReviewCoverageSummary {
  tracked: number
  securityRequired: number
  securityFresh: number
  securityMissing: number
  securityStale: number
  securityInvalid: number
  testRequired: number
  testFresh: number
  testMissing: number
  testStale: number
  testInvalid: number
  dualRequired: number
  excluded: number
  unclassified: number
  conflicted: number
  invalidLedgers: number
}

export interface ReviewCoverageReport {
  formatVersion: 1
  format: 'atlas-review-coverage-v1'
  verdict: ReviewCoverageVerdict
  policy: { format: string; hash: string }
  inventoryHash: string
  units: CoverageUnitRef[]
  summary: ReviewCoverageSummary
  entries: CoverageEntry[]
  invalidLedgerDetails: CoverageDiagnostic[]
  reportErrors: CoverageDiagnostic[]
}

export interface ReviewCoveragePortfolio {
  state: 'missing' | 'invalid' | 'current' | 'stale'
  report: ReviewCoverageReport | null
  errors: CoverageDiagnostic[]
  drift: { added: string[]; removed: string[]; changed: string[] }
}
```

Do not represent unknown JSON with casts in viewer code; every raw field enters
the runtime types only after strict validation.

- [ ] **Step 4: Implement strict structural parsing**

Create `src/review-coverage.ts` with this public boundary:

```ts
export function reviewCoveragePath(root: string): string
export function loadReviewCoverage(
  root: string,
  portfolios: AuditPortfolios,
): ReviewCoveragePortfolio
```

Read only the exact `.atlas/review-coverage.json` path with `readRepoFile`; reject a symlinked `.atlas` directory or coverage file. Validate exact known top-level fields, unique normalized entries, 40-hex blobs, 64-hex policy/inventory hashes, route-safe unit slugs, same-domain unit references, evidence-state/ledger array shape, diagnostic limits, and all summary arithmetic. Apply size limits before parsing: 32 MiB report bytes, 1,000,000 entries, 100,000 diagnostics, and 100,000 units. Declared `invalid` reports return state `invalid` and never expose fresh claims as trusted.

- [ ] **Step 5: Run structural coverage tests**

```bash
pnpm build:cli && node --test --test-name-pattern='coverage report|missing coverage|complete and incomplete|invalid report' test/review-coverage.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/types.ts src/review-coverage.ts test/review-coverage.test.mjs
git commit -m "feat: parse review coverage reports"
```

### Task 3: Revalidate Git inventory and audit evidence

**Files:**
- Modify: `src/review-coverage.ts`
- Modify: `test/review-coverage.test.mjs`

- [ ] **Step 1: Write freshness and adversarial RED tests**

Add exact-byte tests with these operations and assertions:

- `coverage inventory detects added removed and changed tracked paths`: start
  current, then commit one addition, deletion, and byte change; assert all three
  sorted drift arrays and stale state.
- `coverage inventory is NUL-safe for newline and option-like paths`: commit
  `src/line\nbreak.ts` and `--option.ts`, then assert two distinct entries.
- `coverage inventory uses index blobs but rehashes unstaged bytes`: stage one
  version, change the worktree again without staging, and assert the second
  version's Git blob is used.
- `coverage inventory rejects symlinks gitlinks and unresolved index stages`:
  create each index mode in a separate fixture and assert invalid diagnostics.
- `GENERATED-PROOF marker is accepted only for the exact self entry`: omit the
  self blob and verify current; omit any other blob and verify invalid.
- `fresh evidence requires a current v2 same-domain ledger containing the exact
  blob`: mutate ledger domain, scope, hash, version, and stale state in separate
  fixtures; each must invalidate the fresh claim.
- `unknown cross-domain and stale ledger references fail closed`: reference a
  nonexistent slug and a Tests slug from Security; assert exact diagnostics.
- `coverage loading never follows source or ledger symlinks`: create external
  canaries and symlink the report, one source, and one evidence ref separately;
  assert invalid state and unchanged canary bytes.

The drift test first loads a current report, then changes one tracked file, adds one committed path, and removes one committed path. Assert sorted `added`, `removed`, and `changed` lists and `state === 'stale'`. The NUL-safe test uses a filename containing a newline and another beginning with `--` and asserts both remain distinct.

- [ ] **Step 2: Run freshness tests and verify RED**

```bash
pnpm build:cli && node --test --test-name-pattern='inventory|index blobs|gitlinks|GENERATED-PROOF|fresh evidence|ledger references|symlink' test/review-coverage.test.mjs
```

Expected: FAIL because Task 2 only validates structure.

- [ ] **Step 3: Implement one-pass tracked inventory validation**

Use `git(root, ['ls-files', '--stage', '-z'])`, split records only on NUL, and
parse the fixed `<mode> <blob> <stage>\t<path>` prefix at the first tab. Reject
duplicate paths, unsafe paths, non-stage-zero entries, symlink mode `120000`,
gitlink mode `160000`, and all modes other than regular `100644`/`100755`.
Those stage-zero Git blobs are the exact snapshot for index-clean files.

Run `git(root, ['diff-files', '--name-only', '-z'])` and pass only those dirty
tracked paths once to `hashFilePaths`; overwrite their index blobs with exact
worktree blobs, and report deleted/unreadable paths. This avoids rereading every
tracked file on `serve`'s 1.5-second poll while still representing staged and
unstaged bytes exactly. Do not call `scan()`: it includes untracked files and
applies Code presentation excludes. Compute SHA-256 over sorted lines:

```ts
const line = repoPath === '.atlas/review-coverage.json'
  ? `GENERATED-PROOF  ${repoPath}`
  : `${currentHashes.get(repoPath)}  ${repoPath}`
```

Compare current inventory to report entries before trusting verdict. A source byte change produces drift, not a rewritten embedded blob. Unsafe, unreadable, submodule, or symlink paths produce invalid diagnostics.

- [ ] **Step 4: Cross-check fresh ledger evidence**

Index v2 units by domain and slug. For each `fresh` domain claim, require a non-empty ledger list and at least one referenced current non-stale v2 unit whose `files` contains the path and whose complete `hashes[path]` equals the report blob. Every named ledger must exist in the same domain. Missing claims require an empty list. Stale/invalid claims never contribute to fresh counts. Every report unit must be referenced by at least one classified path; a missing-evidence unit is valid even when it has no ledger.

- [ ] **Step 5: Run all coverage tests**

```bash
pnpm build:cli && node --test test/review-coverage.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

```bash
git add src/review-coverage.ts test/review-coverage.test.mjs
git commit -m "feat: verify coverage against git and audits"
```

### Task 4: Derive coverage and risk without a clean shortcut

**Files:**
- Create: `src/audit-assurance.ts`
- Create: `test/audit-assurance.test.mjs`
- Modify: `src/audit-routes.ts`
- Modify: `test/audit-routes.test.mjs`

- [ ] **Step 1: Write pure assurance RED tests**

Cover these exact names and outcomes, using small literal coverage/unit fixtures:

- `domain suffix priority is unknown then gaps then open then covered`: assert
  all four exact returned texts and kinds.
- `coverage and risk remain orthogonal for every unit`: combine a complete unit
  with a high finding and an incomplete unit with no findings; assert separate
  coverage/risk fields.
- `accepted risk and separate design stay visible but are not actionable`:
  assert retained counts are one each and open count remains zero.
- `coverage actions sort before findings and findings sort by severity`: assert
  action kinds then critical/high/medium/low/info order.
- `unit rows include registered units with no completed ledger`: register two
  units, load one ledger, and assert both rows.
- `unit rows order invalid unknown gap open severity then title`: construct one
  row per state and assert exact slug order.
- `dual-domain paths contribute independently to security and tests`: give only
  Security fresh evidence and assert Tests missing.
- `recent audits sort current accepted units by scannedAt`: include stale and
  rejected units and assert only accepted units in descending date order.

Assert no returned label contains `clean` or claims vulnerability absence.

- [ ] **Step 2: Run assurance tests and verify RED**

```bash
pnpm build:cli && node --test test/audit-assurance.test.mjs
```

Expected: FAIL because `dist/audit-assurance.js` does not exist.

- [ ] **Step 3: Implement the pure presentation model**

Export stable functions, not React-dependent state:

```ts
export function domainAssurance(
  domain: AuditDomain,
  coverage: ReviewCoveragePortfolio,
  units: ReadonlyArray<SecurityAuditUnit | TestAuditUnit>,
): DomainAssurance

export function domainNavSuffix(model: DomainAssurance): {
  text: string
  ariaLabel: string
  kind: 'unknown' | 'gap' | 'open' | 'covered'
}

export function auditUnitRows(model: DomainAssurance): AuditUnitRow[]
export function auditActionQueue(model: DomainAssurance): AuditAction[]
export function auditFilesForUnit(model: DomainAssurance, slug: string): AuditFileRow[]
export function recentAuditUnits(model: DomainAssurance): AuditUnitRow[]
```

Count `disposition === 'open'` as actionable. Retain accepted-risk and separate-design counts independently. Coverage gaps are required-domain entries whose current effective state is missing, stale, invalid, unclassified, conflict, or whose report/inventory is unavailable. Derive unit required counts from `classification.domains[domain].unit`, not ledger membership.

- [ ] **Step 4: Remove the clean helper and update its regression test**

Delete `isCleanAuditUnit` from `src/audit-routes.ts`. Replace the old `audit route clean label only for fresh zero-finding units` test with an assertion that route helpers remain presentation-neutral and assurance state comes only from `audit-assurance.ts`.

- [ ] **Step 5: Run pure and route tests**

```bash
pnpm build:cli && node --test test/audit-assurance.test.mjs test/audit-routes.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit Task 4**

```bash
git add src/audit-assurance.ts src/audit-routes.ts test/audit-assurance.test.mjs test/audit-routes.test.mjs
git commit -m "feat: derive audit assurance state"
```

### Task 5: Carry coverage through build, serve, and status

**Files:**
- Modify: `src/types.ts`
- Modify: `src/build.ts`
- Modify: `src/serve.ts`
- Modify: `src/cli.ts`
- Modify: `test/build.test.mjs`
- Modify: `test/review-coverage.test.mjs`

- [ ] **Step 1: Write payload and CLI RED tests**

Add:

```js
test('payload carries review coverage and defaults to missing', () => {
  const defaults = buildPayload({ repoName: 'fixture', commit: null, status })
  assert.equal(defaults.reviewCoverage.state, 'missing')
  const withCoverage = buildPayload({
    repoName: 'fixture', commit: null, status, reviewCoverage: coverage,
  })
  assert.deepEqual(withCoverage.reviewCoverage, coverage)
})

test('status json reports the same coverage verdict and failure buckets', () => {
  const run = spawnSync(process.execPath, [CLI, 'status', '--json'], {
    cwd: root,
    encoding: 'utf8',
  })
  assert.equal(run.status, 0, run.stderr)
  const output = JSON.parse(run.stdout)
  assert.equal(output.coverage.state, 'current')
  assert.equal(output.coverage.verdict, 'incomplete')
  assert.equal(output.coverage.summary.securityMissing, 1)
})
```

- [ ] **Step 2: Run wiring tests and verify RED**

```bash
pnpm build:cli && node --test --test-name-pattern='payload carries review coverage|status json reports' test/build.test.mjs test/review-coverage.test.mjs
```

Expected: FAIL because `AtlasPayload` and CLI output omit coverage.

- [ ] **Step 3: Integrate one loader result everywhere**

Add required `reviewCoverage: ReviewCoveragePortfolio` to `AtlasPayload`; let `BuildInput.reviewCoverage` default to `missingReviewCoverage()`. In CLI build and serve render, load audit portfolios first, then call `loadReviewCoverage(root, portfolios)`, then pass the same result into `buildPayload`/`buildHtml`. Add the serialized coverage portfolio to the live digest so a report-only edit emits reload.

In `status`, use the already computed audit statuses to load portfolios, then coverage. JSON output adds:

```ts
coverage: {
  state,
  verdict: report?.verdict ?? null,
  summary: report?.summary ?? null,
  drift,
  errors,
}
```

Text output names unavailable/invalid/incomplete/current state and gap counts; it never calls absence clean.

- [ ] **Step 4: Run build/status tests and typecheck**

```bash
pnpm build:cli && node --test test/build.test.mjs test/review-coverage.test.mjs
pnpm typecheck
```

Expected: PASS.

- [ ] **Step 5: Commit Task 5**

```bash
git add src/types.ts src/build.ts src/serve.ts src/cli.ts test/build.test.mjs test/review-coverage.test.mjs
git commit -m "feat: publish coverage in atlas payloads"
```

### Task 6: Make audit navigation coverage-aware

**Files:**
- Modify: `viewer/AuditNav.tsx`
- Modify: `viewer/App.tsx`
- Modify: `src/audit-assurance.ts`
- Modify: `test/audit-assurance.test.mjs`

- [ ] **Step 1: Add RED tests for navigation projection**

Extend pure tests to assert the UI-ready model contains:

```js
assert.deepEqual(model.sidebar.slice(0, 3).map((row) => row.kind), [
  'overview', 'attention', 'gaps',
])
assert.equal(domainNavSuffix(unknown).text, 'unknown')
assert.equal(domainNavSuffix(gapped).text, '2 gaps')
assert.equal(domainNavSuffix(open).text, '1 open')
assert.equal(domainNavSuffix(covered).text, 'covered')
```

Assert raw finding totals never become the primary suffix.

- [ ] **Step 2: Run navigation model tests and verify RED**

```bash
pnpm build:cli && node --test --test-name-pattern='sidebar|suffix' test/audit-assurance.test.mjs
```

Expected: FAIL because the sidebar projection is absent.

- [ ] **Step 3: Add sidebar modes to the pure model**

Define `AuditViewMode = 'overview' | 'attention' | 'gaps'`. Add `auditSidebarRows(model)` returning the three fixed rows followed by unit rows. Overview/attention/gaps are local domain view state; existing `audit:security/<slug>` and `audit:test/<slug>` routes remain unchanged.

- [ ] **Step 4: Replace AuditNav and primary count wiring**

Make `AuditNav` accept `DomainAssurance`, selected mode, selected unit slug, `onMode`, and `onSelect`. Render Overview, Needs attention, Coverage gaps, then registered units with separate coverage/risk labels. In `App`, hold independent Security and Tests modes, reset to overview on a primary-button click, and compute the primary suffix from `domainNavSuffix`. Replace the header findings shortcut with the highest-priority domain action; omit it only when there are neither recorded units nor a coverage report.

- [ ] **Step 5: Typecheck and run assurance regressions**

```bash
pnpm typecheck
pnpm build:cli && node --test test/audit-assurance.test.mjs test/audit-routes.test.mjs
```

Expected: PASS.

- [ ] **Step 6: Commit Task 6**

```bash
git add viewer/AuditNav.tsx viewer/App.tsx src/audit-assurance.ts test/audit-assurance.test.mjs
git commit -m "feat: navigate audit coverage and risk"
```

### Task 7: Render Security and Tests portfolios and unit evidence

**Files:**
- Create: `viewer/AuditCoverage.tsx`
- Modify: `viewer/Security.tsx`
- Modify: `viewer/TestAudit.tsx`
- Modify: `viewer/App.tsx`
- Modify: `src/audit-assurance.ts`
- Modify: `test/audit-assurance.test.mjs`

- [ ] **Step 1: Add RED tests for view-model filters and files**

Add literal-fixture tests with these exact outcomes:

- `attention mode contains gaps before open findings and excludes retained
  risk`: assert gap action, critical open action, then lower severities; accepted
  risk and separate design are absent.
- `gaps mode contains already fresh and missing counts without hiding either`:
  assert both numerator and denominator plus explicit missing rows.
- `unit file rows are searchable stable and domain-specific`: assert sorted
  paths and that Security search never returns a Tests-only requirement.
- `unit evidence exposes ruleset scan scope rounds refs and acceptance`: assert
  exact runtime metadata from one accepted current ledger.
- `zero findings wording requires complete current coverage`: assert the phrase
  appears only for complete/current/zero-open and never for missing, invalid,
  incomplete, or stale portfolios.

The final test asserts only the complete/current/no-open fixture yields `No actionable findings in current completed review`; missing, invalid, incomplete, and stale fixtures yield explicit non-clean states.

- [ ] **Step 2: Run view-model tests and verify RED**

```bash
pnpm build:cli && node --test --test-name-pattern='attention mode|gaps mode|unit file|unit evidence|zero findings' test/audit-assurance.test.mjs
```

Expected: FAIL because the detailed projections are missing.

- [ ] **Step 3: Complete the domain view model**

Add mode filtering, severity/impact filters, unit file rows, unit evidence metadata, and empty-state keys to `audit-assurance.ts`. Keep Security severity/disposition vocabulary and Tests impact/category vocabulary distinct. Do not create a generic finding type or card.

- [ ] **Step 4: Implement shared coverage primitives**

Create `viewer/AuditCoverage.tsx` with five focused named exports:

- `CoverageStatement({ model })`: exact current/incomplete/stale/invalid/missing
  verdict sentence;
- `CoverageSummary({ model })`: required, fresh, gap, excluded, and dual counts;
- `AuditUnitPortfolio({ model, onSelect })`: registered unit rows;
- `AuditFileTable({ rows, query })`: flat filtered file/status table;
- `AuditEvidenceSummary({ row })`: ruleset, scan time, scope hash, rounds,
  evidence refs, and coverage acceptance.

Use native buttons/tables, visible focus, textual state labels, and existing color tokens. Directory grouping is not required in v1.

- [ ] **Step 5: Refactor SecurityPane and TestAuditPane**

Security overview renders the repository statement, Coverage/Risk/Evidence summaries, action queue, unit portfolio, and recent audits. Unit selection renders Findings, Coverage, and Evidence sections. Security findings show disposition; only open findings enter actionable filters.

Tests uses the same coverage primitives but preserves `blocking | warning | advisory`, test categories, invariant, evidence, and fix fields. Remove every `clean` and `no findings — clean` phrase. Missing coverage and no units are separate messages.

- [ ] **Step 6: Typecheck and build the viewer**

```bash
pnpm typecheck
pnpm build:viewer
```

Expected: PASS and regenerate both `src/vendor/viewer.js` and the deterministic
`src/vendor/viewer.css`; stage either file only when its bytes changed.

- [ ] **Step 7: Commit Task 7**

```bash
git add viewer/AuditCoverage.tsx viewer/Security.tsx viewer/TestAudit.tsx viewer/App.tsx src/audit-assurance.ts test/audit-assurance.test.mjs src/vendor/viewer.js src/vendor/viewer.css
git commit -m "feat: render coverage-first audit portfolios"
```

### Task 8: Make the code panel contextual on audit routes

**Files:**
- Create: `src/audit-panel.ts`
- Create: `test/audit-panel.test.mjs`
- Modify: `viewer/App.tsx`

- [ ] **Step 1: Write panel-policy RED tests**

```js
test('direct audit entry starts with the code panel closed', () => {
  assert.equal(initialPanelOpen(false, 'security'), false)
  assert.equal(initialPanelOpen(false, 'tests'), false)
  assert.equal(initialPanelOpen(false, 'code'), true)
})

test('entering an audit closes an unrelated panel only once', () => {
  assert.equal(shouldClosePanelOnPrimaryTransition('code', 'security'), true)
  assert.equal(shouldClosePanelOnPrimaryTransition('security', 'security'), false)
  assert.equal(shouldClosePanelOnPrimaryTransition('security', 'tests'), false)
})
```

- [ ] **Step 2: Run panel tests and verify RED**

```bash
pnpm build:cli && node --test test/audit-panel.test.mjs
```

Expected: FAIL because the module is absent.

- [ ] **Step 3: Implement and wire panel transitions**

Export `initialPanelOpen(compact, primaryView)` and `shouldClosePanelOnPrimaryTransition(previous, next)`. Initialize desktop panel state from the current route. Track the previous primary view and close only when entering an audit from Code/Concepts; do not re-close a panel explicitly reopened within Security/Tests. Preserve the existing `atlas-code-jump` effect so a finding or coverage path opens Code mode. Do not reset `conceptCodePath` to the repository root when returning to overview.

- [ ] **Step 4: Run panel and route tests plus typecheck**

```bash
pnpm build:cli && node --test test/audit-panel.test.mjs test/audit-routes.test.mjs
pnpm typecheck
```

Expected: PASS.

- [ ] **Step 5: Commit Task 8**

```bash
git add src/audit-panel.ts test/audit-panel.test.mjs viewer/App.tsx
git commit -m "fix: make audit code inspection contextual"
```

### Task 9: Publish docs, translations, and verified assets

**Files:**
- Modify: `README.md`
- Modify: `viewer/locales/en/messages.po`
- Modify: `viewer/locales/zh/messages.po`
- Modify: `viewer/locales/ja/messages.po`
- Modify: `viewer/locales/ko/messages.po`
- Modify: `src/vendor/viewer.js`
- Modify: `src/vendor/viewer.css`

- [ ] **Step 1: Update the public data contract and semantics**

Document `.atlas/review-coverage.json`, the three verdicts, report/unit ownership, missing-report behavior, primary suffix priority, and why Code excludes never define audit coverage. State that v1 ledgers are recorded evidence only and cannot establish closed-world coverage.

- [ ] **Step 2: Extract and translate every new UI string**

```bash
pnpm i18n:extract
```

Fill every new `msgstr` in English, Chinese, Japanese, and Korean catalogs. Preserve domain terms such as Security, Tests, coverage, accepted risk, and separate design consistently. Then run:

```bash
pnpm i18n:compile
```

Expected: no missing/invalid catalog errors.

- [ ] **Step 3: Rebuild committed viewer assets**

```bash
pnpm build:viewer
git diff --check
```

Expected: generated viewer assets match source and no whitespace errors exist.

- [ ] **Step 4: Run the full automated suite**

```bash
pnpm test
pnpm typecheck
pnpm build
```

Expected: all tests pass, both TypeScript projects pass, and CLI/viewer builds succeed.

- [ ] **Step 5: Run three browser acceptance fixtures**

Build/serve temporary repositories representing:

1. no coverage report plus a completed audit unit;
2. incomplete coverage with one fresh and one missing required path;
3. complete coverage with one open, one accepted-risk, and one separate-design Security finding plus an independent Tests unit.

For each, verify the primary suffix, coverage statement, action ordering, unit rows, file drill-down, evidence metadata, right-panel default, and code jumps. Capture console errors and require none.

- [ ] **Step 6: Commit Task 9**

```bash
git add README.md viewer/locales/en/messages.po viewer/locales/zh/messages.po viewer/locales/ja/messages.po viewer/locales/ko/messages.po src/vendor/viewer.js src/vendor/viewer.css
git commit -m "docs: publish coverage-aware audit contract"
```

### Task 10: Final Atlas verification and independent review

**Files:**
- Review every file changed since `61c83f4`

- [ ] **Step 1: Verify the final diff is scoped and generated assets are current**

```bash
git status --short
git diff 61c83f4 --check
pnpm build:viewer
git diff --exit-code -- src/vendor/viewer.js src/vendor/viewer.css
```

Expected: only intended tooling-state files remain untracked/unstaged; no product diff appears after regeneration.

- [ ] **Step 2: Run final tests**

```bash
pnpm test && pnpm typecheck && pnpm build
```

Expected: all commands exit zero.

- [ ] **Step 3: Run specification review**

Use a fresh read-only Grok session to map every design requirement to code/tests. Material omissions block completion.

- [ ] **Step 4: Run quality/security review**

Use a second fresh read-only Grok session focused on unsafe paths/symlinks, malformed report fail-open behavior, summary arithmetic, inventory TOCTOU, stale ledger references, large-report resource bounds, live-render hot-path cost, and UI states that could imply clean without coverage. Correct every material finding with a failing regression first.

- [ ] **Step 5: Record the verified Atlas boundary**

Report exact test counts, coverage fixture outcomes, remaining compatibility behavior, and the commit range ready for RelayOS integration. Do not claim RelayOS closed-world coverage until its separate producer plan is complete.
