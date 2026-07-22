# Audit Content Localization and Worktree Deletions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make unstaged tracked deletions ordinary stale coverage drift and provide hash-bound Chinese audit prose while preserving one canonical English audit source.

**Architecture:** Repo Atlas first separates deleted index paths from dirty files that still require worktree hashing. A new server-side `audit-localizations` boundary then derives stable SHA-256 identities from canonical audit units, strictly validates bounded locale sidecars, and exposes verified presentation data in the shared payload. The viewer applies only verified prose to copies of canonical units and coverage titles; RelayOS configures Chinese as the default, checks the projection in CI, and stores a Grok-produced Chinese sidecar whose digests are independently verified.

**Tech Stack:** TypeScript, Node.js built-ins, React, Lingui, `node:test`, Git plumbing, pnpm, Grok CLI.

---

## File map

Repo Atlas:

- Modify `src/review-coverage.ts`: classify unstaged deletions before hashing dirty tracked paths.
- Modify `test/review-coverage.test.mjs`: cover unstaged deletion and fail-closed type changes.
- Modify `src/types.ts`: add locale config, localization portfolio, and payload contracts.
- Create `src/audit-localizations.ts`: canonical JSON digests, source extraction, safe sidecar loader, checker input/output.
- Create `test/audit-localizations.test.mjs`: strict schema, digest, completeness, and safe-path tests.
- Modify `src/build.ts`: carry locale configuration and verified localization portfolios.
- Modify `src/serve.ts`: load localization data on each render/live refresh.
- Modify `src/cli.ts`: add `audit-localization-input` and `audit-localization-check`, and wire build inputs.
- Modify `test/build.test.mjs`: prove build and payload behavior.
- Create `src/audit-localization-presentation.ts`: browser-safe presentation-copy localization.
- Create `test/audit-localization-viewer.test.mjs`: test translation application and fallback without DOM coupling.
- Modify `viewer/i18n.ts`: use payload default only when no valid stored preference exists.
- Modify `viewer/App.tsx`: localize before deriving assurance and show fallback state.
- Modify `viewer/Security.tsx` and `viewer/TestAudit.tsx`: render the explicit translation notice.
- Modify `viewer/locales/{en,ja,zh,ko}/messages.po`: catalog the new fallback notice.
- Regenerate `viewer/locales/{en,ja,zh,ko}/messages.ts` and `src/vendor/viewer.js` through existing builds.

RelayOS:

- Modify `.atlas/config.json`: configure `defaultLocale`, `auditSourceLocale`, and required Chinese content.
- Modify `.atlas/review-policy.json`: classify `.atlas/locales/**` as a derived localization artifact.
- Create `.atlas/locales/zh/audits.json`: checked-in digest-bound Chinese projection.
- Modify `package.json`: expose the existing coverage checker and a repository-owned localization wrapper as adjacent gates.
- Create `scripts/checks/check-atlas-audit-localization.ts`: invoke the pinned local Atlas CLI contract in development and independently fail closed on the checked-in sidecar in CI.
- Create `scripts/checks/check-atlas-audit-localization.test.ts`: assert the RelayOS wrapper follows the Atlas v1 wire contract.
- Modify `scripts/checks/project-security-atlas.test.ts`: assert RelayOS locale config and the derived-localization policy rule.
- Regenerate `.atlas/review-coverage.json` and current `.atlas/audits/*.json` only through their existing producers.

### Task 1: Treat unstaged tracked deletion as removed drift

**Files:**

- Modify: `test/review-coverage.test.mjs`
- Modify: `src/review-coverage.ts:719-816`

- [ ] **Step 1: Write the failing deletion regression**

Add a fixture that writes and commits a complete coverage report, removes a tracked file from the worktree without staging that deletion, then asserts:

```js
test('unstaged tracked deletion is stale removed drift rather than unreadable inventory', () => {
  const root = prepareFixtureRepo()
  try {
    const report = buildReport(root, { verdict: 'complete' })
    writeCoverage(root, report)
    commitAll(root)

    fs.unlinkSync(path.join(root, 'src/a.ts'))
    const portfolio = load(root)

    assert.equal(portfolio.state, 'stale')
    assert.deepEqual(portfolio.drift.removed, ['src/a.ts'])
    assert.equal(portfolio.errors.some((error) => error.code === 'unreadable-path'), false)
  } finally {
    cleanup(root)
  }
})
```

- [ ] **Step 2: Run the focused test and observe RED**

Run: `pnpm build:cli && node --test --test-name-pattern='unstaged tracked deletion' test/review-coverage.test.mjs`

Expected: FAIL because the portfolio state is `invalid` with `unreadable-path`.

- [ ] **Step 3: Separate dirty and deleted Git path sets**

In `readTrackedInventory`, read both NUL-delimited outputs:

```ts
const dirtyRaw = git(root, ['diff-files', '--name-only', '-z'])
const deletedRaw = git(root, ['diff-files', '--diff-filter=D', '--name-only', '-z'])
const dirtyPaths = parseNulPaths(dirtyRaw)
const deletedPaths = new Set(parseNulPaths(deletedRaw))
```

Validate every deletion is normalized, present in the stage-zero inventory, and included in `dirtyPaths`. Delete those paths from the current inventory map; hash every remaining dirty path exactly as before. A path that disappears without being reported deleted must continue producing `unreadable-path`.

- [ ] **Step 4: Add a symlink/type-change regression**

Replace a tracked regular file with a symlink without staging it and assert the state remains `invalid` and includes `unreadable-path`. This proves `--diff-filter=D` cannot turn a worktree type change into ordinary removal.

- [ ] **Step 5: Run focused and full coverage tests**

Run:

```bash
pnpm build:cli
node --test test/review-coverage.test.mjs
```

Expected: all review-coverage tests PASS.

- [ ] **Step 6: Commit the deletion fix only**

```bash
git add -- src/review-coverage.ts test/review-coverage.test.mjs
git commit -m "fix: classify tracked worktree deletions as drift"
```

### Task 2: Define localization contracts and canonical digests

**Files:**

- Modify: `src/types.ts`
- Create: `src/audit-localizations.ts`
- Create: `test/audit-localizations.test.mjs`

- [ ] **Step 1: Write failing digest and source-registry tests**

Exercise these public functions before they exist:

```js
import {
  auditFindingSourceDigest,
  auditUnitSourceDigest,
  buildAuditLocalizationSources,
} from '../dist/audit-localizations.js'

assert.equal(auditFindingSourceDigest(findingA), auditFindingSourceDigest(findingBWithReorderedKeys))
assert.notEqual(auditFindingSourceDigest(findingA), auditFindingSourceDigest({ ...findingA, severity: 'high' }))
assert.equal(source.units.find((unit) => unit.slug === 'security-empty').findings.length, 0)
```

The source registry must combine coverage-registered zero-ledger units with loaded security/test ledgers and reject contradictory domain/slug/title ownership.

- [ ] **Step 2: Run the focused test and observe RED**

Run: `pnpm build:cli && node --test test/audit-localizations.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `dist/audit-localizations.js`.

- [ ] **Step 3: Add exact shared types**

Add these concepts to `src/types.ts`:

```ts
export type AtlasLocale = 'en' | 'ja' | 'zh' | 'ko'
export type AuditLocalizationState = 'complete' | 'incomplete' | 'invalid' | 'missing'

export interface AuditLocalizationDiagnostic {
  code: string
  message: string
  locale: AtlasLocale
  domain?: AuditDomain
  slug?: string
  sourceDigest?: string
}

export interface VerifiedAuditFindingTranslation {
  sourceDigest: string
  title: string
  dataflow?: string
  invariant?: string
  evidence?: string
  fix: string
}

export interface VerifiedAuditUnitTranslation {
  domain: AuditDomain
  slug: string
  sourceDigest: string
  title: string
  findings: VerifiedAuditFindingTranslation[]
}

export interface AuditLocalizationPortfolio {
  locale: AtlasLocale
  state: AuditLocalizationState
  units: VerifiedAuditUnitTranslation[]
  errors: AuditLocalizationDiagnostic[]
}
```

Extend `AtlasConfig` with optional `defaultLocale`, `auditSourceLocale`, and `auditContentLocales`; extend `AtlasPayload` with resolved locale fields and `auditLocalizations`.

- [ ] **Step 4: Implement canonical JSON and source construction**

In `src/audit-localizations.ts`, recursively sort object keys, preserve array order, append `\n`, and hash UTF-8 bytes with SHA-256. Finding digests cover the complete canonical finding object. Unit digests cover domain, slug, title, and sorted finding digests.

Return a deterministic source document shaped as:

```ts
{
  formatVersion: 1,
  format: 'atlas-audit-localization-input-v1',
  sourceLocale: 'en',
  targetLocale: 'zh',
  units: [{ domain, slug, sourceDigest, title, findings: [{ sourceDigest, ...sourceProse }] }],
}
```

- [ ] **Step 5: Run digest/source tests**

Run: `pnpm build:cli && node --test test/audit-localizations.test.mjs`

Expected: the digest and registered-unit tests PASS.

### Task 3: Strictly load and verify locale sidecars

**Files:**

- Modify: `src/audit-localizations.ts`
- Modify: `test/audit-localizations.test.mjs`

- [ ] **Step 1: Add RED tests for every loader state**

Use temporary Git repositories to cover:

```js
assert.equal(loadAuditLocalization(root, 'zh', source).state, 'missing')
assert.equal(loadAuditLocalization(root, 'zh', sourceWithOneMissingUnit).state, 'incomplete')
assert.equal(loadAuditLocalization(root, 'zh', completeSource).state, 'complete')
assert.equal(loadAuditLocalization(root, 'zh', malformedSource).state, 'invalid')
```

Also assert invalid for extra top-level/unit/finding keys, wrong locale/version/format, duplicate or unknown units/findings, stale unit/finding digest, whitespace-only or over-limit prose, oversized files, a symlinked `.atlas/locales`, and a symlinked `audits.json`.

- [ ] **Step 2: Observe RED**

Run: `pnpm build:cli && node --test --test-name-pattern='localization loader' test/audit-localizations.test.mjs`

Expected: FAIL because the loader is not implemented.

- [ ] **Step 3: Implement contained bounded reading and strict shape checks**

Use `lstatSync`, `realpathSync`, and `readRepoFile` to require the configured path (for RelayOS, `.atlas/locales/zh/audits.json`) to be a contained regular file. Read at most 32 MiB plus one byte. Reject unknown object keys and enforce:

```ts
formatVersion === 1
format === 'atlas-audit-localizations-v1'
locale === requestedLocale
```

Security finding translations must have exactly `sourceDigest,title,dataflow,fix`; test translations exactly `sourceDigest,title,invariant,evidence,fix`. Bound entry counts to canonical source counts and prose fields to non-empty trimmed strings with a 65,536 code-unit maximum.

- [ ] **Step 4: Verify by digest and keep only current units**

Map source units and findings by digest. A structurally valid sidecar with missing or stale entries is `incomplete`; include only fully current unit translations in `portfolio.units`. A structurally unsafe/ambiguous file is `invalid` and returns an empty verified unit list.

- [ ] **Step 5: Run all localization loader tests**

Run: `pnpm build:cli && node --test test/audit-localizations.test.mjs`

Expected: PASS.

- [ ] **Step 6: Commit localization core**

```bash
git add -- src/types.ts src/audit-localizations.ts test/audit-localizations.test.mjs
git commit -m "feat: verify hash-bound audit localizations"
```

### Task 4: Wire build, serve, and CLI guardrails

**Files:**

- Modify: `src/scan.ts`
- Modify: `src/build.ts`
- Modify: `src/serve.ts`
- Modify: `src/cli.ts`
- Modify: `test/build.test.mjs`
- Modify: `test/audit-localizations.test.mjs`

- [ ] **Step 1: Add RED config and payload tests**

Assert invalid locale values, duplicate configured content locales, and a content locale equal to the source locale are rejected by `loadConfig`. Assert `buildPayload` defaults old repositories to English and carries an explicitly loaded Chinese portfolio.

- [ ] **Step 2: Add RED CLI tests**

Create fixtures proving:

```bash
repo-atlas audit-localization-input --locale zh --json
repo-atlas audit-localization-check --json
```

The input command must emit only canonical translatable prose plus digests. The check must exit 0 only when every locale from `auditContentLocales` is `complete`; missing, stale, incomplete, or invalid projections must exit nonzero with JSON diagnostics.

- [ ] **Step 3: Observe RED**

Run: `pnpm build:cli && node --test test/build.test.mjs test/audit-localizations.test.mjs`

Expected: FAIL for absent config validation, payload fields, and CLI commands.

- [ ] **Step 4: Validate and resolve config**

In `loadConfig`, validate locale fields against `en|ja|zh|ko`, uniqueness, and source/content separation. Resolve absent fields as:

```ts
defaultLocale: config.defaultLocale ?? 'en'
auditSourceLocale: config.auditSourceLocale ?? 'en'
auditContentLocales: config.auditContentLocales ?? []
```

- [ ] **Step 5: Share one portfolio-loading function**

Add `loadConfiguredAuditLocalizations(root, config, reviewCoverage, portfolios)` and call it from both `serve` and `build`. Pass the resolved locale metadata and portfolios to `buildPayload`; do not recompute or mutate canonical audit arrays inside `buildPayload`.

- [ ] **Step 6: Add CLI commands and exit semantics**

Add both commands to `USAGE` and `dispatch`. `audit-localization-input` requires `--locale zh` (or another supported locale different from the source locale) and prints deterministic JSON. `audit-localization-check` loads every configured locale, prints a human summary or JSON, and sets `process.exitCode = 1` unless all are complete.

- [ ] **Step 7: Run build/CLI tests**

Run:

```bash
pnpm build:cli
node --test test/build.test.mjs test/audit-localizations.test.mjs
```

Expected: PASS.

- [ ] **Step 8: Commit runtime and CLI wiring**

```bash
git add -- src/scan.ts src/build.ts src/serve.ts src/cli.ts test/build.test.mjs test/audit-localizations.test.mjs
git commit -m "feat: expose audit localization guardrails"
```

### Task 5: Apply translations only in the viewer presentation layer

**Files:**

- Create: `src/audit-localization-presentation.ts`
- Create: `test/audit-localization-viewer.test.mjs`
- Modify: `viewer/i18n.ts`
- Modify: `viewer/App.tsx`
- Modify: `viewer/Security.tsx`
- Modify: `viewer/TestAudit.tsx`
- Modify: `viewer/locales/en/messages.po`
- Modify: `viewer/locales/ja/messages.po`
- Modify: `viewer/locales/zh/messages.po`
- Modify: `viewer/locales/ko/messages.po`
- Regenerate: `viewer/locales/*/messages.ts`
- Regenerate: `src/vendor/viewer.js`

- [ ] **Step 1: Add RED presentation-copy tests**

Test pure helpers that receive canonical audits, coverage, locale metadata, and verified portfolios. Assert Chinese copies replace only allowed prose, English returns the canonical values, missing/stale Chinese falls back unit-by-unit, coverage registry titles are localized, input objects remain deeply equal to snapshots, and severity/category/locations/disposition/hashes never change.

- [ ] **Step 2: Add RED default-locale tests**

Export a browser-safe resolver from `src/audit-localization-presentation.ts`:

```ts
resolveInitialLocale(defaultLocale, storedValue)
```

Assert valid stored preference wins, invalid/missing storage uses configured default, and an invalid default fails back to English.

- [ ] **Step 3: Observe RED**

Run: `pnpm build:cli && node --test test/audit-localization-viewer.test.mjs`

Expected: FAIL because the presentation module does not exist.

- [ ] **Step 4: Implement immutable localized projections**

Build maps by `domain/slug` and finding source digest. Return cloned `audits`, `testAudits`, and a cloned `reviewCoverage.report.units`; assign only title/dataflow/fix or title/invariant/evidence/fix from verified entries. Return a status describing source-locale, complete translation, or fallback.

- [ ] **Step 5: Localize before assurance derivation**

In `App`, initialize locale from `data.defaultLocale`, derive presentation data with `useMemo`, and pass localized copies to `domainAssurance`, routing, audit panels, and print views. A live payload refresh must preserve the current user locale.

- [ ] **Step 6: Render an explicit fallback notice**

Pass the localization presentation status into `SecurityView` and `TestAuditView`. For a non-source locale whose portfolio is not complete, render:

```tsx
<p role="status">{t(i18n)`Audit content translation is unavailable or incomplete; canonical source text is shown.`}</p>
```

Use `pnpm i18n:extract`, provide real translations in all four `.po` catalogs, and run `pnpm i18n:compile`.

- [ ] **Step 7: Run viewer tests and builds**

Run:

```bash
pnpm i18n:extract
pnpm i18n:compile
pnpm build:viewer
pnpm typecheck
node --test test/audit-localization-viewer.test.mjs test/audit-copy-boundary.test.mjs
```

Expected: all commands PASS.

- [ ] **Step 8: Commit the viewer integration**

```bash
git add -- src/audit-localization-presentation.ts test/audit-localization-viewer.test.mjs viewer/i18n.ts viewer/App.tsx viewer/Security.tsx viewer/TestAudit.tsx viewer/locales src/vendor/viewer.js
git commit -m "feat: present verified localized audit content"
```

### Task 6: Run Repo Atlas integration verification

**Files:**

- Verify all modified Repo Atlas paths.

- [ ] **Step 1: Run the full test suite**

Run: `pnpm test`

Expected: every Node test passes.

- [ ] **Step 2: Run both compilers and the viewer build**

Run:

```bash
pnpm typecheck
pnpm build:viewer
git diff --check
```

Expected: all commands exit 0.

- [ ] **Step 3: Confirm the feature branch contains no unintended staged paths**

Run: `git status --short` and inspect every path. Do not discard or stage pre-existing unrelated changes.

### Task 7: Configure RelayOS and regenerate canonical audit state

**Files:**

- Modify: `.atlas/config.json`
- Modify: `.atlas/review-policy.json`
- Modify: `package.json`
- Create: `scripts/checks/check-atlas-audit-localization.ts`
- Create: `scripts/checks/check-atlas-audit-localization.test.ts`
- Modify: `scripts/checks/project-security-atlas.test.ts`
- Regenerate: `.atlas/review-coverage.json`
- Regenerate only current producer-owned files under `.atlas/audits/`

- [ ] **Step 1: Record RelayOS status and confirm the existing guardrail entry points**

Run:

```bash
git status --short
rg -n "review-coverage|repo-atlas|audit.*check|security.*invariant" package.json scripts/checks .github .atlas
```

Expected: confirm `scripts/checks/check-audit-coverage.ts`, `audits/review-baseline/build-ledgers.ts`, and `scripts/checks/project-security-atlas.test.ts` without modifying unrelated dirty files.

- [ ] **Step 2: Add failing config/policy assertions**

Extend `scripts/checks/project-security-atlas.test.ts` to require:

```json
{
  "defaultLocale": "zh",
  "auditSourceLocale": "en",
  "auditContentLocales": ["zh"]
}
```

and require `.atlas/locales/**` to match exactly one derived-localization exclusion rule.

- [ ] **Step 3: Observe RED, then update config and policy**

Run the focused project guardrail test, observe the missing fields/rule, then edit only `.atlas/config.json` and `.atlas/review-policy.json` to satisfy it.

- [ ] **Step 4: Regenerate canonical ledgers and coverage through exact project commands**

Run:

```bash
pnpm exec tsx audits/review-baseline/build-ledgers.ts --update
pnpm exec tsx scripts/checks/check-audit-coverage.ts --update
```

Never hand-edit hashes or coverage arithmetic. Re-run the Atlas worktree CLI with `status --json`; the ten intentional unstaged deletions must appear under coverage `drift.removed`, not `unreadable-path`.

- [ ] **Step 5: Wire the localization check beside coverage**

Add `check:audit-coverage` as `tsx scripts/checks/check-audit-coverage.ts` and `check:audit-localization` as `tsx scripts/checks/check-atlas-audit-localization.ts --json` in `package.json`; chain both adjacent entries into `check`. The wrapper reads canonical RelayOS ledgers and the Atlas v1 sidecar, recomputes the same sorted-key SHA-256 digests, and fails closed on missing, malformed, extra, incomplete, or stale Chinese content. `scripts/checks/check-atlas-audit-localization.test.ts` supplies complete, missing, stale, and extra-key fixtures. The command should initially fail because the Chinese sidecar has not been generated yet; retain that RED evidence.

### Task 8: Produce and verify Chinese audit prose with Grok CLI

**Files:**

- Create: `.atlas/locales/zh/audits.json`

- [ ] **Step 1: Generate deterministic translation input**

Run the locally built Atlas CLI from the Atlas worktree with the RelayOS worktree as its current directory and capture stdout directly in the coordinator:

```bash
node /home/kud/.config/superpowers/worktrees/repo-atlas/domain-audits-navigation/dist/cli.js audit-localization-input --locale zh --json
```

Confirm the captured JSON contains only allowed source prose and source digests; do not create a repository file at this step.

- [ ] **Step 2: Ask Grok for translation in read-only mode**

Load the `using-grok-cli` skill. Invoke Grok with filesystem writes disabled and a prompt that requires one JSON object, exact key preservation, Simplified Chinese prose, no fact reinterpretation, no markdown, and no commentary. Grok may translate only title/dataflow/fix or title/invariant/evidence/fix.

- [ ] **Step 3: Validate before writing**

Parse Grok output outside the repository, compare every domain/slug/sourceDigest and every required key to the deterministic input, reject additions/omissions, then run the Atlas loader/checker against a temporary copy. Only after this validation, use `apply_patch` to add `.atlas/locales/zh/audits.json`.

- [ ] **Step 4: Run both RelayOS audit gates**

Run:

```bash
pnpm exec tsx scripts/checks/check-audit-coverage.ts
node /home/kud/.config/superpowers/worktrees/repo-atlas/domain-audits-navigation/dist/cli.js audit-localization-check --json
```

Expected: coverage has no `unreadable-path` deletion diagnostics and Chinese localization state is `complete`.

### Task 9: Review, browser verification, and handoff

**Files:**

- Review all Atlas and RelayOS paths changed by this plan.

- [ ] **Step 1: Run two sequential delegated security reviews**

First ask the existing specification reviewer to compare the final diff against the approved design, especially single-source truth, digest binding, and fail-closed path semantics. Resolve every material finding. Then ask the distinct quality/security reviewer to inspect parser bounds, symlink/realpath handling, config/public-contract compatibility, mutation risks, and tests. Resolve every material finding and re-run focused tests after each correction.

- [ ] **Step 2: Run final Atlas verification from a fresh build**

Run:

```bash
pnpm test
pnpm typecheck
pnpm build:viewer
git diff --check
```

Expected: all PASS.

- [ ] **Step 3: Run final RelayOS guardrails**

Run:

```bash
pnpm exec vitest run scripts/checks/project-security-atlas.test.ts scripts/checks/check-audit-coverage.test.ts
pnpm exec vitest run scripts/checks/check-atlas-audit-localization.test.ts
pnpm exec tsx audits/review-baseline/build-ledgers.ts --check-results
pnpm exec tsx scripts/checks/check-audit-coverage.ts
pnpm exec tsx scripts/checks/check-atlas-audit-localization.ts --json
node /home/kud/.config/superpowers/worktrees/repo-atlas/domain-audits-navigation/dist/cli.js audit-localization-check --json
pnpm exec tsc --noEmit
git diff --check -- .atlas/config.json .atlas/review-policy.json .atlas/review-coverage.json .atlas/locales package.json scripts/checks/check-atlas-audit-localization.ts scripts/checks/check-atlas-audit-localization.test.ts scripts/checks/project-security-atlas.test.ts
```

Expected: every command exits 0.

- [ ] **Step 4: Restart port 4400 from the updated Atlas build**

Stop only the known Atlas process owned by this task, rebuild, and start `repo-atlas serve -p 4400 --host 0.0.0.0` in the RelayOS security worktree. Verify `/data` reports `defaultLocale: "zh"`, source locale `en`, and a complete `zh` portfolio.

- [ ] **Step 5: Run a real browser smoke test**

Use a fresh browser profile to open `http://100.65.250.41:4400/#audit:security`. Assert no console error, Chinese is selected, unit and finding prose are Chinese, the ten deleted paths are not `unreadable-path`, and selecting English restores canonical English prose.

- [ ] **Step 6: Final status audit**

Run `git status --short` in both worktrees, list only files owned by this implementation, and preserve every unrelated pending change. Report verification evidence and any intentionally uncommitted generated/integration files.
