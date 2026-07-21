# Domain-aware Audit Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add strict Security and Tests audit domains to Repo Atlas and expose Code, Concepts, Security, and Tests as route-driven vertical primary navigation.

**Architecture:** Keep `.atlas/audits/` and its freshness engine shared, but parse viewer-grade `atlas-audit-v2` ledgers through a discriminated security/test validator. Preserve v1 security loading, add a separate test portfolio to the payload, and make namespaced routes the sole source of primary-navigation state.

**Tech Stack:** TypeScript, Node.js, React 19, Lingui, Tailwind CSS, Node test runner, happy-dom, esbuild.

---

## File structure

- `src/types.ts` — shared v2 finding/unit/payload types.
- `src/audits.ts` — shared envelope validation, domain validation, status, and portfolio loading.
- `src/audit-routes.ts` — pure namespaced route parsing/building used by the viewer and tests.
- `src/build.ts`, `src/serve.ts`, `src/cli.ts` — carry both portfolios into generated/live payloads.
- `src/audit-location.ts` — pure location parsing shared by viewer and tests.
- `viewer/AuditLocation.tsx` — shared source-location control only.
- `viewer/Security.tsx` — security-specific cards and pane.
- `viewer/TestAudit.tsx` — test-specific cards and pane.
- `viewer/AuditNav.tsx` — domain unit lists and counts for the sidebar.
- `viewer/App.tsx` — route-derived four-section shell and scoped controls.
- `test/audits.test.mjs`, `test/audit-routes.test.mjs`, `test/build.test.mjs` — contract, routing, and payload regression tests.
- `README.md`, `viewer/locales/*/messages.po`, `src/vendor/viewer.{js,css}` — public contract, i18n catalogs, committed viewer build.

### Task 1: Define and validate the v2 domain contract

**Files:**
- Modify: `src/types.ts`
- Modify: `src/audits.ts`
- Modify: `test/audits.test.mjs`

- [ ] **Step 1: Write failing v2 projection tests**

Add helpers and cases that write one complete security ledger and one complete test ledger:

```js
const v2Envelope = (domain, slug, files, findings) => ({
  formatVersion: 2,
  format: 'atlas-audit-v2',
  domain,
  reviewState: 'complete',
  slug,
  title: slug,
  ruleset: `fixture-${domain}-v1`,
  scanned_at: '2026-07-21',
  scope_hash: scopeHash(root, files),
  file_count: files.length,
  files,
  findings,
})

assert.equal(loadAuditPortfolios(root).security[0].slug, 'security-runtime')
assert.equal(loadAuditPortfolios(root).tests[0].slug, 'test-runtime')
assert.equal(loadAudits(root)[0].slug, 'security-runtime')
```

Also assert that `domain: 'test'` with security-shaped findings, unknown domains,
`reviewState !== 'complete'`, an unknown test category, empty locations, and a
version/format mismatch produce invalid stale status and no portfolio unit.

- [ ] **Step 2: Run the contract tests and observe RED**

Run: `pnpm build:cli && node --test --test-name-pattern='v2|domain' test/audits.test.mjs`

Expected: FAIL because `loadAuditPortfolios` and the v2 types do not exist.

- [ ] **Step 3: Add discriminated runtime types**

Define the exact public types:

```ts
export type AuditDomain = 'security' | 'test'
export type TestAuditImpact = 'blocking' | 'warning' | 'advisory'
export type TestAuditCategory =
  | 'missing-invariant' | 'weak-assertion' | 'mock-only' | 'nondeterminism'
  | 'isolation-leak' | 'fixture-drift' | 'coverage-gap' | 'privileged-side-effect'

export interface TestAuditFinding {
  impact: TestAuditImpact
  category: TestAuditCategory
  title: string
  invariant: string
  evidence: string
  fix: string
  locations: string[]
  confidence?: string
}

export interface BaseAuditUnit {
  formatVersion: 1 | 2
  domain: AuditDomain
  slug: string
  title: string
  ruleset: string
  scannedAt: string
  fileCount: number
  droppedCount: number
  roundCount: number
  stale: boolean
}

export interface SecurityAuditUnit extends BaseAuditUnit {
  domain: 'security'
  findings: AuditFinding[]
  conceptSlug?: string
}

export interface TestAuditUnit extends BaseAuditUnit {
  domain: 'test'
  findings: TestAuditFinding[]
}

export type AuditUnit = SecurityAuditUnit
```

- [ ] **Step 4: Implement shared-envelope and domain validators**

Extend `RawLedger` with `domain`, `reviewState`, and `conceptSlug`. Accept v1 or
v2 in the shared contract, then validate v2 with exact predicates:

```ts
function isV2(j: RawLedger): boolean {
  return j.formatVersion === 2 && j.format === 'atlas-audit-v2'
}

function v2EnvelopeError(j: RawLedger): string | null {
  if (!isV2(j)) return 'version 2 ledgers must use format atlas-audit-v2'
  if (j.domain !== 'security' && j.domain !== 'test') return 'unsupported audit domain'
  if (j.reviewState !== 'complete') return 'reviewState must be complete'
  return null
}
```

Validate all required finding strings with `.trim().length > 0`, validate test
impact/category against closed sets, require at least one normalized location,
and retain the existing 100,000-finding and safe-scope limits. V1
`finalPass: true` remains legacy security; v1 generic ledgers remain status-only.

- [ ] **Step 5: Run tests and commit the contract slice**

Run: `pnpm build:cli && node --test --test-name-pattern='v2|domain|legacy|malformed|future' test/audits.test.mjs`

Expected: all selected tests PASS.

Commit:

```bash
git add src/types.ts src/audits.ts test/audits.test.mjs
git commit -m "feat: add domain-aware audit contract"
```

### Task 2: Load both portfolios through one directory pass

**Files:**
- Modify: `src/audits.ts`
- Modify: `src/build.ts`
- Modify: `src/serve.ts`
- Modify: `src/cli.ts`
- Modify: `src/types.ts`
- Modify: `test/audits.test.mjs`
- Create: `test/build.test.mjs`

- [ ] **Step 1: Write failing portfolio ordering and payload tests**

Assert the public loader and payload shape:

```js
const portfolios = loadAuditPortfolios(root, statuses)
assert.deepEqual(portfolios.security.map((u) => u.slug), ['security-high', 'security-low'])
assert.deepEqual(portfolios.tests.map((u) => u.slug), ['test-stale', 'test-blocking', 'test-advisory'])
assert.deepEqual(buildPayload(input).testAudits, portfolios.tests)
```

Cover a malformed v2 ledger remaining present as `status: 'stale'` with a
non-null `invalidReason`; it must not turn into an empty clean unit.

- [ ] **Step 2: Run the focused tests and observe RED**

Run: `pnpm build:cli && node --test --test-name-pattern='portfolio|payload' test/audits.test.mjs test/build.test.mjs`

Expected: FAIL because only `AuditUnit[]` is currently loaded and carried.

- [ ] **Step 3: Implement the one-pass portfolio loader**

Export:

```ts
export interface AuditPortfolios {
  security: SecurityAuditUnit[]
  tests: TestAuditUnit[]
}

export function loadAuditPortfolios(
  root: string,
  statuses?: AuditStatusEntry[],
): AuditPortfolios

export function loadAudits(root: string, statuses?: AuditStatusEntry[]): AuditUnit[] {
  return loadAuditPortfolios(root, statuses).security
}
```

Read each ledger once, select the legacy/v2 domain, call the matching strict
validator, reuse the known status or scope hash, and push only a valid complete
unit. Sort security by worst severity then slug. Sort tests by stale first,
worst impact (`blocking`, `warning`, `advisory`) then slug.

- [ ] **Step 4: Carry tests through build, CLI, and live serve**

Add `testAudits?: TestAuditUnit[]` to `BuildInput` and `testAudits:
TestAuditUnit[]` to `AtlasPayload`. `buildPayload` defaults it to `[]`. CLI build
and serve call `loadAuditPortfolios` once and pass both arrays. Live-reload
digest includes both arrays.

- [ ] **Step 5: Run tests/typecheck and commit**

Run: `pnpm test && pnpm typecheck`

Expected: 0 failures and 0 TypeScript errors.

Commit:

```bash
git add src/audits.ts src/build.ts src/serve.ts src/cli.ts src/types.ts test/audits.test.mjs test/build.test.mjs
git commit -m "feat: project security and test audit portfolios"
```

### Task 3: Introduce collision-free audit routes

**Files:**
- Create: `src/audit-routes.ts`
- Create: `test/audit-routes.test.mjs`
- Modify: `viewer/App.tsx`
- Modify: `viewer/Security.tsx`

- [ ] **Step 1: Write route parser tests**

```js
assert.deepEqual(parseAuditRoute('audit:security'), { domain: 'security', slug: null })
assert.deepEqual(parseAuditRoute('audit:test/test-runtime'), { domain: 'test', slug: 'test-runtime' })
assert.equal(parseAuditRoute('security'), null)
assert.equal(parseAuditRoute('audit:ops'), null)
assert.equal(auditRoute('security', 'runtime-auth'), 'audit:security/runtime-auth')
assert.equal(primaryViewForRoute('security', () => true), 'code')
```

- [ ] **Step 2: Run route tests and observe RED**

Run: `pnpm build:cli && node --test --test-name-pattern='audit route' test/audit-routes.test.mjs`

Expected: FAIL because `dist/audit-routes.js` does not exist.

- [ ] **Step 3: Implement pure route helpers**

```ts
export type PrimaryView = 'code' | 'concepts' | 'security' | 'tests'

export function auditRoute(domain: AuditDomain, slug?: string): string {
  if (slug && !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(slug)) throw new Error('invalid audit slug')
  return `audit:${domain}${slug ? `/${slug}` : ''}`
}

export function parseAuditRoute(route: string): { domain: AuditDomain; slug: string | null } | null {
  const match = /^audit:(security|test)(?:\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?))?$/u.exec(route)
  if (!match) return null
  return { domain: match[1] as AuditDomain, slug: match[2] ?? null }
}
```

Add helpers for `view:concepts`, route-to-primary-view, and validating a unit
slug against the corresponding portfolio.

- [ ] **Step 4: Replace the security pseudo-route**

Make `App` accept namespaced portfolio/unit routes even for empty portfolios,
derive the active primary view from the route, and redirect legacy `#security`
to `#audit:security` with `history.replaceState`. Update all security links to
`auditRoute('security')`. A tracked path literally named `security` continues to
resolve through `nodesByPath` as Code.

- [ ] **Step 5: Run tests/typecheck and commit**

Run: `pnpm test && pnpm typecheck`

Expected: all tests PASS and viewer typecheck succeeds.

Commit:

```bash
git add src/audit-routes.ts test/audit-routes.test.mjs viewer/App.tsx viewer/Security.tsx
git commit -m "fix: namespace audit viewer routes"
```

### Task 4: Build the Tests pane and vertical primary navigation

**Files:**
- Create: `src/audit-location.ts`
- Create: `viewer/AuditLocation.tsx`
- Create: `viewer/AuditNav.tsx`
- Create: `viewer/TestAudit.tsx`
- Modify: `viewer/Security.tsx`
- Modify: `viewer/Concept.tsx`
- Modify: `viewer/App.tsx`

- [ ] **Step 1: Extract and test location parsing**

Put location parsing in the CLI-compiled pure helper and import it from the
viewer control and route test:

```ts
export function parseAuditLocation(value: string): { path: string; line: number } | null {
  const match = /^([^:#]+)(?::(\d+)|#(.+))?$/u.exec(value)
  if (!match) return null
  return { path: match[1], line: match[2] ? Number(match[2]) : 1 }
}
```

Assert invalid/empty locations return `null` and valid chips dispatch
`atlas-code-jump` with the parsed path/line.

- [ ] **Step 2: Implement test-specific cards and filters**

`TestAuditPane` renders impact chips, category chips, stale-only filtering,
unit metadata, and findings with labelled `invariant`, `evidence`, and `fix`
sections. It uses `AuditLocation` but not the security `FindingCard`. Empty
portfolio text is exactly `No completed audits yet`; only a fresh completed
zero-finding unit says clean.

Update `ConceptPane` to accept only `SecurityAuditUnit`. In `App`, associate v2
security units by explicit `conceptSlug`; apply slug equality only to legacy v1
units marked by the loader. A test unit with the same textual slug must never
appear in a concept security section.

- [ ] **Step 3: Implement four vertical primary buttons**

`AuditNav` renders domain unit buttons and counts. `App` renders four persistent
full-width rows in this order with icons and `aria-current`:

```ts
const PRIMARY = [
  ['code', Code2],
  ['concepts', LibraryBig],
  ['security', ShieldAlert],
  ['tests', FlaskConical],
] as const
```

Code controls render only for Code. Concepts uses its own `conceptQuery` and
freshness state. Security/Tests show their unit lists and do not read the code
query, status, ignored, or sort state. Unit clicks navigate to namespaced unit
routes and focus that unit in the main pane; primary domain clicks navigate to
portfolio homes. `view:concepts` renders the concept index or an honest empty
state when no concept exists.

- [ ] **Step 4: Verify UI behavior locally**

Run: `pnpm build:viewer && pnpm typecheck`

Expected: viewer bundle builds and TypeScript reports no errors. Open the
fixture viewer and confirm keyboard focus, active labels, empty states, unit
routes, code jumps, compact sidebar, and back/forward behavior.

- [ ] **Step 5: Commit the UI slice**

```bash
git add src/audit-location.ts viewer/AuditLocation.tsx viewer/AuditNav.tsx viewer/TestAudit.tsx viewer/Security.tsx viewer/Concept.tsx viewer/App.tsx test/audit-routes.test.mjs
git commit -m "feat: add first-class security and test navigation"
```

### Task 5: Finish docs, translations, and committed viewer assets

**Files:**
- Modify: `README.md`
- Modify: `viewer/locales/en/messages.po`
- Modify: `viewer/locales/zh/messages.po`
- Modify: `viewer/locales/ja/messages.po`
- Modify: `viewer/locales/ko/messages.po`
- Modify: `src/vendor/viewer.js`
- Modify: `src/vendor/viewer.css`

- [ ] **Step 1: Document the v2 schemas and routes**

Add a compact `atlas-audit-v2` example for each domain, state that v1
`finalPass` security remains readable, document `reviewState: complete`, and
list the `audit:security[/slug]` and `audit:test[/slug]` routes.

- [ ] **Step 2: Extract and compile Lingui catalogs**

Run: `pnpm i18n:extract`

Expected: new primary-navigation, test-field, filter, empty-state, and audit
status messages appear in all four `.po` catalogs. Fill Chinese/Japanese/Korean
translations rather than leaving new production labels blank.

Run: `pnpm i18n:compile`

Expected: all catalogs compile successfully.

- [ ] **Step 3: Rebuild committed viewer assets**

Run: `pnpm build:viewer`

Expected: `src/vendor/viewer.js` and, if styles changed, `viewer.css` are updated.

- [ ] **Step 4: Run complete verification**

Run: `pnpm test && pnpm typecheck && pnpm build`

Expected: all tests pass, both TypeScript projects pass, and CLI/viewer builds
finish without warnings or dirty generated catalogs.

- [ ] **Step 5: Commit the delivery slice**

```bash
git add README.md viewer/locales/en/messages.po viewer/locales/zh/messages.po viewer/locales/ja/messages.po viewer/locales/ko/messages.po src/vendor/viewer.js src/vendor/viewer.css
git commit -m "docs: publish domain audit viewer contract"
```

### Task 6: Final diff and regression review

**Files:**
- Review all files changed since `0cf0075`

- [ ] **Step 1: Inspect scope and generated artifacts**

Run: `git diff --check 0cf0075..HEAD && git status --short && git diff --stat 0cf0075..HEAD`

Expected: no whitespace errors, only planned files changed, and no uncommitted
generated drift.

- [ ] **Step 2: Run the complete verification again from a clean tree**

Run: `pnpm test && pnpm typecheck && pnpm build`

Expected: 0 failures.

- [ ] **Step 3: Independently review requirements**

Verify v1 compatibility, v2 fail-closed behavior, domain isolation,
namespaced deep links, four persistent vertical buttons, filter scoping,
accessibility, compact layout, translations, and committed assets. Material
findings block handoff and must be corrected with a failing regression test.
