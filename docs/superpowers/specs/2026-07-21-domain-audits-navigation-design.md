# Domain-aware audit navigation design

Date: 2026-07-21
Status: design approved; pending written-spec review

## Problem

Repo Atlas currently presents Code and Concepts as the only primary sidebar
views. Security is reached through a findings counter and the bare `#security`
pseudo-route, while generic audit ledgers are freshness-only records and tests
have no viewer contract. This creates three structural problems:

1. `finalPass: true` doubles as both pipeline completion and an implicit
   "security" discriminator.
2. Security shares the repository-path route namespace and can leave the
   sidebar showing unrelated code/concept controls.
3. A future test audit would either have to impersonate the security finding
   schema or remain invisible.

The change makes Security and Tests first-class audit domains without splitting
the producer-neutral `.atlas/audits/` store.

## Goals

- Show Code, Concepts, Security, and Tests as four persistent, vertically
  stacked primary sidebar buttons.
- Give security and test audits separate strict schemas and viewer projections.
- Preserve one freshness/stamping implementation for every audit domain.
- Make malformed, incomplete, stale, and future-format data visibly non-clean.
- Remove collisions between virtual pages and real repository paths.
- Keep old security ledgers readable while giving new ledgers an explicit,
  safely versioned contract.

## Non-goals

- Repo Atlas will not run an LLM or decide whether source code is secure or
  tests are good. Producers own those judgments.
- This change will not turn readability or design ledgers into test audits.
- It will not add a general dashboard framework or arbitrary user-defined
  sidebar modules.
- It will not move notes, concepts, or audit ledgers into separate physical
  domain directories.

## Audit contract

### Shared envelope

New viewer-grade ledgers use `atlas-audit-v2`:

```json
{
  "formatVersion": 2,
  "format": "atlas-audit-v2",
  "domain": "security",
  "reviewState": "complete",
  "slug": "security-runtime-auth",
  "title": "Runtime authentication",
  "ruleset": "relayos-security-v1",
  "scanned_at": "2026-07-21",
  "scope_hash": "<sha1>",
  "file_count": 12,
  "files": ["..."],
  "hashes": {"...": "<blob-sha1>"},
  "findings": []
}
```

`domain` is a required discriminator with the initial closed set `security |
test`. `reviewState` must be exactly `complete` before a ledger can enter a
viewer portfolio. Producers must publish completed ledgers atomically; a
partial run cannot use an empty findings array to appear clean.

The existing normalized-path, unique-file, SHA-1, count, size-limit, regular
file, symlink, and atomic-write protections apply unchanged. Freshness remains
derived from the shared `files`, `scope_hash`, and optional complete `hashes`
set. Domain validation is an additional layer, not a bypass around the shared
contract.

### Compatibility

- Version 1 ledgers with `finalPass: true` and the existing strict finding
  schema continue to load as legacy security units.
- Version 1 generic ledgers continue to participate in status only.
- Version 2 ledgers require an explicit supported domain and `reviewState`.
- Older tools already reject unsupported `formatVersion` values, so they fail
  visibly rather than rendering a test ledger as security.
- `audit-import` may continue producing version 1 compatibility ledgers; new
  domain-aware producers write version 2.

There is no filename or `ruleset` prefix inference. Unknown domains, mismatched
format/version pairs, and domain-invalid findings produce an invalid stale
status and are omitted from clean viewer portfolios with a warning.

### Security findings

The current strict fields remain:

- `severity`: `info | low | medium | high | critical`
- non-empty `category`, `title`, `dataflow`, and `fix`
- normalized `locations`
- optional `confidence`

The version 2 security ledger envelope may additionally carry an optional
`conceptSlug`. Concept pages embed only explicitly associated security units.
Slug equality is no longer treated as a concept relationship.

### Test findings

Tests use a distinct schema:

- `impact`: `blocking | warning | advisory`
- `category`: one of `missing-invariant`, `weak-assertion`, `mock-only`,
  `nondeterminism`, `isolation-leak`, `fixture-drift`, `coverage-gap`, or
  `privileged-side-effect`
- non-empty `title`, `invariant`, `evidence`, and `fix`
- one or more normalized `locations`
- optional `confidence`

The schema describes whether a test proves the intended invariant, not whether
the production feature is secure. Privileged tests may also appear in a
separate security ledger; domain membership is intentionally not exclusive.

### Runtime types and loading

The loader is refactored around a shared envelope validator followed by a
domain validator. Public runtime types become a discriminated model:

- `BaseAuditUnit`
- `SecurityAuditUnit`
- `TestAuditUnit`

For payload compatibility, `AtlasPayload.audits` remains the security
portfolio and `AtlasPayload.testAudits` is added for tests. `AuditUnit` remains
an alias of `SecurityAuditUnit` during this migration. Internal loading returns
both portfolios in one pass so malformed-ledger warnings, status lookup, scope
hashing, and ordering cannot drift between two directory walks.

Security ordering remains worst severity then slug. Tests order stale units
first, then worst impact (`blocking`, `warning`, `advisory`), then slug.

## Navigation and viewer behavior

### Namespaced routes

Virtual routes use the same explicit namespace discipline as concepts:

- `audit:security`
- `audit:security/<slug>`
- `audit:test`
- `audit:test/<slug>`
- `view:concepts` for the concept index/empty state

Both routes are valid even when their portfolio is empty, because a persistent
first-class entry must have an honest empty state. The old `#security` route is
accepted only as a migration alias and replaced with `#audit:security`. A real
tracked path named `security` therefore always remains a code route.

The selected primary view is derived from the route, not maintained as an
independent state that can disagree with the main pane:

- repository path -> Code
- `concept:<slug>` -> Concepts
- `audit:security` -> Security
- `audit:test` -> Tests

Clicking Code returns to the last selected repository path (the repository root
initially). Clicking Concepts returns to the last selected concept or
`view:concepts` when none exists. Security and Tests open their portfolio home;
selecting a unit uses the corresponding domain/slug route. Browser back/forward
restores both the main pane and matching sidebar view.

### Sidebar

The sidebar begins with four full-width compact buttons stacked vertically.
Each has an icon, text label, active state, and a concise count/status suffix;
color is never the only state signal. Buttons use native button semantics,
visible keyboard focus, and `aria-current` for the active view.

Controls below the primary navigation are view-specific:

- Code: path search, outdated/missing/ignored filters, and tree sort.
- Concepts: a separate concept search and concept freshness filter.
- Security: security audit-unit list with finding and stale counts.
- Tests: test audit-unit list with finding and stale counts.

Code filter state may be retained when the user leaves Code, but those controls
are not rendered and cannot affect another domain. Security severity/staleness
filters and test impact/category/staleness filters remain local to their panes.

On compact layouts the same navigation appears inside the existing sidebar
drawer; no second mobile-only navigation model is introduced.

### Main panes and code jumps

`SecurityPane` continues to render severity-filtered security units. A new
`TestAuditPane` renders test impact/category filters and test-specific evidence
cards. Both reuse a small location-control primitive that dispatches the
existing `atlas-code-jump` event. They do not share a generic finding card,
because their explanatory fields and risk vocabularies are materially
different.

An empty domain displays "No completed audits yet" and never "clean". A fresh,
completed unit with zero findings may display clean. A stale unit retains its
historical findings but is prominently marked as requiring re-audit.

## Failure behavior

- Invalid JSON, unsafe paths, symlinked ledgers/directories, unsupported
  versions/domains, duplicate scope paths, incomplete review state, and invalid
  domain findings never enter a portfolio.
- Invalid ledgers remain visible through audit status as stale/invalid with the
  exact reason.
- Duplicate slugs are rejected within a domain. Cross-domain relationships are
  explicit and never inferred from matching slugs.
- A concept security section accepts only `SecurityAuditUnit` records with a
  matching explicit `conceptSlug` (legacy v1 keeps the existing slug fallback).
- Unknown finding categories or impacts fail closed rather than being silently
  downgraded.

## Testing

Implementation follows test-driven development.

Parser/status tests must cover v1 security compatibility, v1 generic status,
valid security/test v2 projection, unknown domains, incomplete ledgers,
domain-schema crossover, future versions, slug/filename mismatch, unsafe
paths, symlinks, stale scopes, and zero-finding incomplete ledgers.

Viewer tests must cover namespaced route parsing, the old-route redirect, a
real root path named `security`, route-derived primary navigation, empty-domain
states, domain-specific filters, concept/security association, cross-domain
slug isolation, and location jumps. Build, typecheck, all tests, Lingui extract
and compile, and regenerated committed viewer assets are required before
completion.

## Delivery boundary

This repo delivers the generic contract, loader, navigation, viewer panes,
documentation, translations, and tests. Individual repositories remain
responsible for classifying their files, producing complete audit ledgers, and
enforcing their own coverage policy.
