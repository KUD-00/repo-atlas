# Atlas Attention Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Repo Atlas from a freshness report into a human attention control plane that remembers which concept snapshots need review, what the reviewer concluded, and when source changes must reopen an item, while making long concept pages easier to enter without creating a second copy of the documentation.

**Architecture:** A deterministic concept snapshot is computed from every declared source, including explicit missing-source markers. A clone-local JSON store under Git's common directory persists current workflow state plus append-only events; the store is never written into the repository. Live serve reconciles source snapshots with that store, while static builds expose the same dashboard read-only. The viewer presents three intentionally separate surfaces: human attention, review history, and machine health. Concept pages gain a single-source Overview projection derived from the opening markdown, with the existing full page preserved as the authoritative walkthrough.

**Tech Stack:** TypeScript, Node.js built-ins, React 19, Lingui, Tailwind, `node:test`, Git plumbing, pnpm.

---

## File map

- Modify `src/types.ts`: add snapshot, attention, event, health, and concept projection contracts.
- Modify `src/conceptPages.ts`: calculate a total deterministic snapshot even when sources are missing.
- Modify `test/build.test.mjs`: cover snapshot and static-payload behavior.
- Create `src/attention.ts`: state machine, reconciliation, static projection, validation, and atomic local persistence.
- Create `src/attention-presentation.ts`: keep explicit review receipts separate from quiet fresh baselines.
- Create `test/attention.test.mjs`: cover first observation, reopen, snooze expiry, outcomes, stale actions, malformed state, and non-repository storage.
- Create `test/attention-presentation.test.mjs`: prevent fresh baselines from being presented as human-reviewed.
- Modify `src/build.ts`: carry attention payloads and derive Overview HTML/section metadata from canonical concept markdown.
- Modify `src/serve.ts`: load/reconcile the store and expose the bounded same-origin JSON action endpoint.
- Create `test/attention-server.test.mjs`: exercise live persistence and HTTP validation through the real server.
- Modify `src/audit-routes.ts` and `test/audit-routes.test.mjs`: add attention, history, and system-health locations.
- Modify `src/audit-panel.ts` and `test/audit-panel.test.mjs`: make attention a non-browse primary surface with correct panel behavior.
- Create `viewer/Attention.tsx`: render Needs attention, History, and System health, plus review/snooze controls.
- Modify `viewer/App.tsx`: wire attention navigation, live payload replacement, and concept deep links.
- Modify `viewer/App.tsx`: expose Attention as the first primary destination and its unread count.
- Modify `viewer/Concept.tsx`: render Overview/Full controls and a version-bound change notice.
- Modify `viewer/locales/{en,ja,zh,ko}/messages.po`: catalog the new interface text.
- Regenerate `viewer/locales/{en,ja,zh,ko}/messages.ts` and `src/vendor/viewer.{js,css}` through existing commands.
- Regenerate tracked `dist/*.js` CLI artifacts through `pnpm build:cli`.
- Modify `README.md`: document the dashboard, state location, action semantics, and static/live distinction.

### Task 1: Define deterministic concept snapshots

**Files:**

- Modify: `test/build.test.mjs`
- Modify: `src/types.ts`
- Modify: `src/conceptPages.ts`

- [x] **Step 1: Write a failing snapshot regression**

Add fixtures with one present and one absent concept source, then assert that each `ConceptStatusEntry` has a stable `snapshot`; changing the present file must change the snapshot even while the other source remains absent.

```js
const first = computeStatus(scan(root), config).concepts[0]
assert.match(first.snapshot, /^[a-f0-9]{64}$/)
write(root, 'src/present.ts', 'export const value = 2\n')
const second = computeStatus(scan(root), config).concepts[0]
assert.notEqual(second.snapshot, first.snapshot)
assert.deepEqual(second.brokenSources, ['src/missing.ts'])
```

- [x] **Step 2: Run RED**

Run: `pnpm build:cli && node --test --test-name-pattern='concept snapshot' test/build.test.mjs`

Expected: FAIL because `snapshot` is absent.

- [x] **Step 3: Add the exact snapshot contract**

Extend `ConceptStatusEntry` and `ConceptNode` with:

```ts
currentSourcesHash: string | null
snapshot: string
```

Keep `currentSourcesHash` nullable so stamping semantics remain unchanged. Compute `snapshot` as SHA-256 over canonical ordered records of `{ source, digest }`, where `digest` is the scanned file/directory digest or the literal missing marker. Every declared source therefore participates even when another source is broken.

- [x] **Step 4: Run GREEN**

Run: `pnpm build:cli && node --test --test-name-pattern='concept snapshot' test/build.test.mjs`

Expected: PASS, including the broken-source mutation case.

### Task 2: Implement the attention state machine and local store

**Files:**

- Create: `test/attention.test.mjs`
- Create: `src/attention.ts`
- Modify: `src/types.ts`

- [x] **Step 1: Write failing domain tests**

Cover these invariants before the module exists:

```js
const first = reconcileAttention(emptyState(), concepts, now)
assert.equal(item(first, 'runtime').workflow, 'open')

const reviewed = applyAttentionAction(first.state, current, {
  slug: 'runtime', snapshot: 'snapshot-a', action: 'understood', note: 'The scheduler now leases jobs.',
}, now)
assert.equal(item(reconcileAttention(reviewed, concepts, later), 'runtime').workflow, 'done')

const changed = reconcileAttention(reviewed, [{ ...current, snapshot: 'snapshot-b' }], later)
assert.equal(item(changed, 'runtime').workflow, 'open')
```

Also assert: fresh concepts initialize done; outdated/broken concepts initialize open; unchanged done items remain done even if document freshness remains outdated; expired snoozes reopen; acknowledgement remains distinguishable from understanding; `understood` and `decided` require a note; a stale snapshot action is rejected; notes and event arrays are bounded.

- [x] **Step 2: Run RED**

Run: `pnpm build:cli && node --test test/attention.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `dist/attention.js`.

- [x] **Step 3: Add versioned shared contracts**

Define:

```ts
type AttentionWorkflow = 'open' | 'snoozed' | 'done'
type AttentionOutcome = 'acknowledged' | 'understood' | 'decided' | 'not-relevant'
type AttentionAction = AttentionOutcome | 'snooze' | 'reopen'

interface AttentionEvent {
  id: string
  slug: string
  snapshot: string
  type: 'reviewed' | 'snoozed' | 'reopened' | 'source-reopened'
  at: string
  outcome?: AttentionOutcome
  note?: string
  until?: string
}
```

Add bounded `AttentionItem`, `AttentionSummary`, `AttentionHealth`, and `AttentionPayload` types. Items include evidence paths and the page's stamped anchor, but never claim a semantic invariant that Atlas did not verify.

- [x] **Step 4: Implement pure reconciliation and action validation**

Use snapshot equality as the only automatic close/reopen boundary. Freshness can create a first open item but cannot close a human item. `snooze` requires a valid future timestamp at most 365 days away. `understood` and `decided` require trimmed notes; all notes are limited to 10,000 Unicode code units. Reject unknown slugs and mismatched snapshots.

- [x] **Step 5: Write failing persistence tests**

Use a temporary initialized Git repository and assert:

```js
const location = attentionStatePath(root)
assert.equal(location.startsWith(path.join(gitCommonDir(root), 'repo-atlas')), true)
assert.equal(location.includes(`${path.sep}.atlas${path.sep}`), false)
```

The Git common directory is outside a linked worktree but normally lives at
`<root>/.git` in a primary checkout; the invariant is Git metadata rather than
repository content, not lexical distance from the checkout root.

Round-trip a state, verify mode `0600` where supported, ensure a malformed existing file is reported and not overwritten, and ensure a symlink state file is rejected.

- [x] **Step 6: Implement safe atomic persistence**

Resolve `git rev-parse --git-common-dir` against the repository root, create only the `repo-atlas` state directory, write a unique same-directory temporary file with mode `0600`, `fsync`, and rename. Strictly parse `formatVersion: 1`; fail closed on malformed/oversized/non-regular state files. Expose an injectable path only for tests.

- [x] **Step 7: Run GREEN**

Run: `pnpm build:cli && node --test test/attention.test.mjs`

Expected: all state-machine and persistence tests PASS.

### Task 3: Integrate static and live payloads

**Files:**

- Modify: `test/build.test.mjs`
- Modify: `src/build.ts`
- Modify: `src/serve.ts`
- Create: `test/attention-server.test.mjs`

- [x] **Step 1: Write failing payload tests**

Assert a normal static `buildPayload` contains `attention.mode === 'static'`, exposes current outdated/broken concepts as read-only open items, and has no fabricated events. Assert a supplied live payload is preserved exactly.

- [x] **Step 2: Implement static projection and live injection**

Add `attention?: AttentionPayload` to `BuildInput`. When absent, derive a read-only payload from current concept state; when present, use the reconciled live payload. Keep machine health counts in `attention.health`, separate from workflow counts.

- [x] **Step 3: Write failing real-server API tests**

Start `serve` on an ephemeral loopback port with an injectable attention state path. Fetch `/data`, post a valid review to `/attention/action`, fetch again, restart the server, and prove the done state and event persist. Also assert 400/409 behavior for invalid actions, missing required notes, unknown concepts, and stale snapshots; assert non-JSON requests are rejected.

- [x] **Step 4: Implement live reconciliation and the action endpoint**

During render, reconcile current concept entries against the local store and pass the resulting live payload to `buildPayload`. Add a `POST /attention/action` branch beside existing chat endpoints. Require `application/json`, reuse the bounded body reader, validate against the current snapshot, persist atomically, rerender, and notify live-reload clients. Never mutate repository files.

- [x] **Step 5: Run focused server tests**

Run:

```bash
pnpm build:cli
node --test test/attention.test.mjs test/attention-server.test.mjs test/build.test.mjs
```

Expected: all focused tests PASS.

### Task 4: Add Attention routes and navigation

**Files:**

- Modify: `test/audit-routes.test.mjs`
- Modify: `test/audit-panel.test.mjs`
- Modify: `src/audit-routes.ts`
- Modify: `src/audit-panel.ts`

- [x] **Step 1: Write failing route tests**

Assert canonical parsing/serialization for:

```ts
'view:attention'
'view:attention/history'
'view:attention/health'
```

Assert Attention is a primary view, deep links round-trip, entering it from code closes the source panel, and leaving it restores only the remembered code/concept location rather than treating Attention as browse history.

- [x] **Step 2: Run RED**

Run: `pnpm build:cli && node --test test/audit-routes.test.mjs test/audit-panel.test.mjs`

Expected: route parsing and panel assertions FAIL.

- [x] **Step 3: Extend the pure route state machine**

Add `'attention'` to `PrimaryView`; add `AttentionLocation = { kind: 'attention'; section: 'needs' | 'history' | 'health' }`; serialize the `needs` section as the short canonical `view:attention`. Treat all three attention sections as non-browse locations in panel transitions.

- [x] **Step 4: Run GREEN**

Run: `pnpm build:cli && node --test test/audit-routes.test.mjs test/audit-panel.test.mjs`

Expected: all route/panel tests PASS.

### Task 5: Build the usable Attention, History, and Health UI

**Files:**

- Create: `viewer/Attention.tsx`
- Modify: `viewer/App.tsx`
- Modify: `viewer/App.tsx`
- Modify: `viewer/locales/en/messages.po`
- Modify: `viewer/locales/ja/messages.po`
- Modify: `viewer/locales/zh/messages.po`
- Modify: `viewer/locales/ko/messages.po`

- [x] **Step 1: Add a failing viewer compile boundary**

Wire the new location and component imports before creating `viewer/Attention.tsx`, then run `pnpm typecheck:viewer`.

Expected: FAIL because the new component and exhaustive location handling do not exist.

- [x] **Step 2: Implement the three surfaces**

`Attention.tsx` must provide:

- Needs attention: open cards first, snoozed cards separately, with concept status, snapshot version, declared/changed evidence, stamped anchor, and direct concept link.
- Review control: optional note for acknowledgement/not-relevant, required note for understood/decided, explicit outcome buttons, and bounded snooze presets.
- History: reverse-chronological immutable events with outcome, note, version, and concept deep link.
- System health: concept/document freshness and broken-source counts only; no review buttons and no implication that machine freshness equals human understanding.
- Static behavior: all controls disabled with an explanation that persistent review state requires `atlas serve`.

Use existing Relay-style utilities and icons; do not introduce a second design system or raw style sheet.

- [x] **Step 3: Wire live updates and unread count**

In `App.tsx`, let a successful action replace only `data.attention` in local state. Route concept links through the existing location machinery. In the existing inline sidebar, place Attention first and show the open count; do not mix the count into Audit badges.

- [x] **Step 4: Extract and compile localization catalogs**

Run:

```bash
pnpm i18n:extract
pnpm i18n:compile
pnpm typecheck:viewer
```

Translate the concise navigation and workflow labels in all four catalogs; longer operational copy may intentionally fall back to the English source where existing catalog policy permits it.

- [x] **Step 5: Build the viewer artifact**

Run: `pnpm build:viewer`

Expected: `src/vendor/viewer.js` and `src/vendor/viewer.css` regenerate without errors.

### Task 6: Add a single-source Overview projection for concept readability

**Files:**

- Modify: `test/build.test.mjs`
- Modify: `src/types.ts`
- Modify: `src/build.ts`
- Modify: `viewer/Concept.tsx`

- [x] **Step 1: Write failing projection tests**

Build a concept whose body has opening orientation prose followed by multiple headings. Assert `briefHtml` contains the orientation prose but not later walkthrough content, while `html` remains complete. Assert `sections` preserves document order and heading levels. A page without a post-title heading must use the full body as its overview.

- [x] **Step 2: Run RED**

Run: `pnpm build:cli && node --test --test-name-pattern='concept overview projection' test/build.test.mjs`

Expected: FAIL because `briefHtml` and `sections` are absent.

- [x] **Step 3: Derive the projection from canonical markdown**

Add to `ConceptNode`:

```ts
briefHtml: string
sections: Array<{ level: number; title: string }>
```

Take the markdown before the first level 2–6 heading as the Overview and parse it through the same marked/sanitization path as the full body. Extract heading labels mechanically from the same body. Do not persist or ask an LLM to maintain a parallel summary.

- [x] **Step 4: Add Overview/Full reading controls**

Default a newly selected concept to Overview. Show the opening projection, section map, source evidence, and current attention/change receipt if present. “Read full walkthrough” switches to the existing full HTML without changing anchors or source-panel behavior. Preserve an explicit way back to Overview.

- [x] **Step 5: Run viewer and build tests**

Run:

```bash
pnpm build:cli
node --test test/build.test.mjs
pnpm typecheck:viewer
pnpm build:viewer
```

Expected: all tests and builds PASS.

### Task 7: Document, verify, and review the implementation

**Files:**

- Modify: `README.md`
- Modify: `docs/superpowers/plans/2026-07-22-atlas-attention-control-plane.md`

- [x] **Step 1: Document the user contract**

Explain that source freshness, attention workflow, and epistemic outcomes are separate. Document the live dashboard, review outcomes, automatic snapshot reopen, state path under the Git common directory, static read-only behavior, malformed-state recovery guidance, and the Overview/Full concept view.

- [x] **Step 2: Run formatting/build/test gates from a clean command context**

Run:

```bash
pnpm i18n:extract
pnpm i18n:compile
pnpm build
pnpm typecheck
pnpm test
git diff --check
```

Expected: every command exits 0 and the full suite has no failures.

- [x] **Step 3: Inspect the exact diff and repository status**

Run:

```bash
git status --short
git diff --stat
git diff -- src/types.ts src/conceptPages.ts src/attention.ts src/build.ts src/serve.ts
```

Confirm every changed path belongs to this feature and no generated or user-owned change was lost.

- [ ] **Step 4: Commit only the feature paths**

Stage the explicit files listed in this plan, verify `git diff --cached --check`, and commit without bypassing hooks:

```bash
git commit -m "feat: add an attention control plane"
```

- [ ] **Step 5: Request one independent code review**

Give the reviewer the feature requirements, base SHA, head SHA, state-file trust boundary, and verification output. Treat correctness, durability, data-loss, path-safety, stale-tab actions, and accessibility findings as blocking.

- [ ] **Step 6: Fix findings through RED-GREEN and rerun all gates**

For every material finding, add or adjust a failing test first, implement the minimum correction, rerun the focused test, then rerun the full command set from Step 2. Amend or add a follow-up commit without bypassing hooks.
