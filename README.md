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

### Live audit ledgers

Completed audits can live at `.atlas/audits/<name>.json` with the
`atlas-audit-v1` fields `ruleset`, `scanned_at`, `scope_hash`, `files`,
`hashes`, `findings`, and `stamped`. `status` compares those scan-time blob
hashes with the working tree and reports stale scopes, exact changed/missing
files, and findings that point at drifted files. The security viewer keeps its
stricter `finalPass` + security-finding schema; generic design/readability
ledgers still participate in status without being rendered as security cards.

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

- **Viewer** — concept pages sit in a "concepts" group at the top of the
  sidebar and render like any note (mermaid, raw HTML, glossary). Because a
  concept has no file of its own, `code:` anchors must carry a full repo
  path: `[label](code:path/to/file.ts#StartMarker..EndMarker)` — same marker
  semantics as file pages, link and `![embed]` forms both.

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
