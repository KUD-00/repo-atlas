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

  Each note has frontmatter (`hash`, `stamped`) managed by the tool; the body is yours.
  Commit `.atlas/` — descriptions are versioned with the code.

- **Staleness** — a file's hash is its git blob hash. A directory's hash covers its
  *immediate children* (child file contents + child dir names), so editing a file flags the
  file and its direct parent; adding/removing/renaming entries flags the directory. Deep
  edits don't cascade to every ancestor.

- **Scan scope** — `git ls-files` (tracked + untracked-not-ignored), so `.gitignore` is
  respected for free; `.atlas/config.json` `exclude` patterns (picomatch) filter on top
  (lockfiles, binaries, snapshots by default).

## Usage

```sh
cd /path/to/some/repo
repo-atlas init                # creates .atlas/ (config + notes dir)
repo-atlas status              # what's missing / outdated / fresh
repo-atlas status --json       # machine-readable, for agents
repo-atlas notepath apps/x.ts  # where to write the note for a path
# ... write note bodies ...
repo-atlas stamp               # stamp all notes with current hashes
repo-atlas stamp apps/x.ts     # or stamp specific paths ("." = repo root)
repo-atlas build               # write .atlas/atlas.html (open in a browser)
repo-atlas serve               # dev server at http://localhost:4400 (-p to change)
```

`serve` rebuilds on every request and auto-reloads open pages (SSE) whenever the
working tree or `.atlas/notes/` changes — leave it open while writing notes. No
bundler involved; the viewer is a single self-contained page.

Selecting a file splits the right side into description + source preview
(syntax-highlighted). Contents come from the server's `/raw` endpoint — only
paths inside the scan are served, never arbitrary disk paths — so the preview
pane works under `serve`; the static `build` output carries descriptions only
and shows a hint instead.

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

1. `repo-atlas status --json` → lists `missing` and `outdated` paths.
2. Agent reads the code for each path, writes/updates the note body in `.atlas/notes/...`
   (keep frontmatter lines if present; `stamp` rewrites them anyway).
3. `repo-atlas stamp` → marks those notes current.
4. `repo-atlas build` → refreshed HTML.

For an `outdated` path, the agent should diff what changed since `stamped` and revise the
note rather than rewrite from scratch.

Suggested note shape: 1–3 sentences of *what this is and why it exists*, then bullets for
anything non-obvious (invariants, gotchas, who calls it). Directory notes describe the
area's role and how its children divide the work — not a file-by-file inventory.
