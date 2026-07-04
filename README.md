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

Two things are derived from the code, not written in notes: **import
relations** — every page shows "imports → / ← imported by" chips (exact files
for a file, grouped to package roots for a directory), resolved from relative
imports and workspace package names, memoized by blob hash so serve stays
fast. And the **glossary** — define project jargon once in
`.atlas/glossary.md` (`## term`, optional `别名：`/`aliases:` line, body);
every occurrence in note prose gets a dotted underline with a hover popover,
so terminology can't drift between notes.

Selecting a file splits the right side into description + source preview
(syntax-highlighted). Contents come from the server's `/raw` endpoint — only
paths inside the scan are served, never arbitrary disk paths — so the preview
pane works under `serve`; the static `build` output carries descriptions only
and shows a hint instead.

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

This tool deliberately does **not** call an LLM. Description quality comes from letting a
coding agent (Claude Code etc.) actually read the code:

1. `repo-atlas status --json` → lists `missing`, `outdated` (with diff size), `moved`,
   and `brokenRefs`.
2. `repo-atlas migrate --apply` → notes follow moved paths mechanically; only genuinely
   changed content is left for reading.
3. Agent reads the code for each remaining path, writes/updates the note body in
   `.atlas/notes/...` (keep frontmatter lines if present; `stamp` rewrites them anyway).
4. `repo-atlas stamp` → marks those notes current (recording the HEAD anchor).
5. `repo-atlas build` → refreshed HTML.

For an `outdated` path, `git diff <anchor> -- <path>` (the anchor is in the note's
frontmatter) shows exactly what changed since the note was written — revise against
that rather than rewriting from scratch. Check `brokenRefs` after any reorganization:
those notes' subjects didn't change, only their references to other paths did.

Suggested note shape: 1–3 sentences of *what this is and why it exists*, then bullets for
anything non-obvious (invariants, gotchas, who calls it). Directory notes describe the
area's role and how its children divide the work — not a file-by-file inventory.
