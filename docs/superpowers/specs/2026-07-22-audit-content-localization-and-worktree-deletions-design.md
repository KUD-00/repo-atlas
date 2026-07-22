# Audit Content Localization and Worktree Deletions

**Status:** Approved design

**Date:** 2026-07-22

## Problem

Repo Atlas already localizes its viewer chrome into English, Japanese, Chinese,
and Korean. Audit content is different: unit titles and finding narratives are
loaded verbatim from the canonical audit ledgers. Selecting Chinese therefore
translates labels such as “Coverage” and “Findings” while leaving the actual
finding title, data flow, and fix in English.

The coverage inventory also conflates an ordinary unstaged Git deletion with
an unsafe or unreadable file. `git diff-files --name-only` names every dirty
tracked path, after which Atlas attempts to hash all of them. A tracked file
deleted from the worktree cannot be hashed and is reported as
`unreadable-path`; the whole coverage portfolio becomes invalid. The current
inventory should instead omit an intentional deletion and report it as
`drift.removed`, leaving the prior report visible but stale.

## Goals

- Keep exactly one authoritative audit ledger and review policy.
- Let the viewer switch canonical audit prose into a verified Chinese
  presentation without changing any security fact.
- Make localized audit content deterministic, offline-capable, versioned, and
  safe to discard and regenerate.
- Make RelayOS open Atlas in Chinese by default and require complete Chinese
  audit content in its repository checks.
- Classify unstaged tracked deletions as ordinary inventory drift.
- Keep symlinks, unreadable files, unsupported modes, unresolved index stages,
  and concurrent disappearance fail-closed as invalid inventory.

## Non-goals

- Translating source paths, symbols, ruleset identifiers, categories, severity,
  impact, disposition, hashes, or evidence references.
- Treating translated prose as audit evidence or as a second source of truth.
- Browser-time machine translation.
- Generating Japanese or Korean audit prose in this change. The format supports
  those locales, but RelayOS initially requires only Chinese.
- Reinterpreting or correcting findings during translation.

## Alternatives Considered

### Store every language inside the canonical ledger

Rejected. It creates multiple truth-bearing narrative fields, changes evidence
bytes whenever wording changes, and permits translations to drift semantically
inside the security record.

### Translate in the browser at render time

Rejected. It is non-deterministic, unavailable to static/offline builds, leaks
content to a third party during viewing, and can produce different security
wording on every render.

### Hash-bound derived localization

Selected. Canonical ledgers remain authoritative. Locale files contain only
display prose, are validated against canonical source digests, and are ignored
whenever they are missing, malformed, or stale.

## Sources of Truth

The only authoritative inputs remain:

- `.atlas/review-policy.json` for registered audit units and canonical titles;
- `.atlas/audits/<slug>.json` for audit evidence and findings;
- `.atlas/review-coverage.json` for the closed-world coverage verdict.

Localized content lives at:

```text
.atlas/locales/<locale>/audits.json
```

It is a presentation projection. Deleting the file loses no audit evidence.

## Repository Configuration

`AtlasConfig` gains three validated fields:

```json
{
  "defaultLocale": "zh",
  "auditSourceLocale": "en",
  "auditContentLocales": ["zh"]
}
```

- `defaultLocale` selects the initial viewer locale only when the user has not
  already stored an explicit preference.
- `auditSourceLocale` identifies the language of canonical audit prose and
  defaults to `en`.
- `auditContentLocales` is a unique list drawn from `en`, `ja`, `zh`, and `ko`.
  A locale equal to `auditSourceLocale` is rejected because the canonical
  ledger already supplies it.

RelayOS sets the exact values above. Other repositories remain backward
compatible: absent fields preserve the current English viewer and require no
locale projection.

## Localization Wire Format

Each locale file has this strict top-level shape:

```json
{
  "formatVersion": 1,
  "format": "atlas-audit-localizations-v1",
  "locale": "zh",
  "units": [
    {
      "domain": "security",
      "slug": "security-apps-daemon",
      "sourceDigest": "<64 lowercase hex>",
      "title": "守护进程应用",
      "findings": [
        {
          "sourceDigest": "<64 lowercase hex>",
          "title": "……",
          "dataflow": "……",
          "fix": "……"
        }
      ]
    }
  ]
}
```

Test-audit finding translations use the same finding `sourceDigest` key and
contain exactly `title`, `invariant`, `evidence`, and `fix`. Security findings
contain exactly `title`, `dataflow`, and `fix`. Unknown or extra keys are
invalid. Empty or surrounding-whitespace strings are invalid. Strings retain
the existing audit text byte/code-unit bounds.

The sidecar cannot represent severity, impact, category, locations,
disposition, confidence, file scope, hashes, rounds, or evidence references, so
it cannot override those fields accidentally or maliciously.

## Digest Binding

All digests are SHA-256 over UTF-8 canonical JSON with recursively sorted
object keys and a trailing newline.

A finding source digest covers the complete canonical finding object, including
its machine fields and original narrative. Any change to severity, path,
disposition, or prose therefore prevents an old translation from attaching to
a changed finding.

A unit source digest covers:

```json
{
  "domain": "security|test",
  "slug": "<slug>",
  "title": "<canonical title>",
  "findingDigests": ["<sorted finding digests>"]
}
```

Sorting finding digests makes harmless canonical array reordering irrelevant.
Changing the title or finding set invalidates the unit translation.

## Loading and Validation

The localization loader builds the registered-unit set from the coverage report
and canonical ledgers. It then validates each configured locale without
modifying those inputs.

Each locale produces a portfolio with one of four states:

- `complete`: every registered unit and finding has a current translation;
- `incomplete`: the file is readable and structurally valid, but entries are
  missing or stale;
- `invalid`: unsafe path, malformed JSON, unsupported version, duplicate or
  unknown unit/finding, locale mismatch, extra fields, or invalid text;
- `missing`: no locale file exists.

Only digest-current unit translations enter the verified translation map.
Missing or stale units fall back independently to canonical prose. An invalid
file contributes no translated prose at all. Diagnostics identify the exact
locale, unit, and finding digest.

Locale files are bounded before parsing and read only as contained regular
repository files. Symlinks and realpath escapes are rejected.

## Viewer Data Flow

`build` and `serve` load canonical audits and coverage first, then load the
configured audit localization portfolios. `AtlasPayload` carries:

- `defaultLocale`;
- `auditSourceLocale`;
- verified localization portfolios and diagnostics.

On locale selection, the viewer derives localized audit objects by copying only
the permitted translated prose onto canonical audit objects. `domainAssurance`
then consumes that derived presentation copy; all coverage and acceptance
decisions still come from canonical hashes, scopes, and evidence.

The review-coverage unit registry is localized from the same verified unit
title, including units that do not yet have a completed ledger. Concept audit
sections, navigation rows, action queues, and unit detail pages therefore use
the same localized presentation.

When the selected locale is neither the source locale nor a complete/current
translation, the audit page shows a localized “audit content translation is
unavailable or incomplete” notice. Canonical prose remains visible; the viewer
never crashes and never presents fallback English as translated Chinese.

## Translation Production

Grok CLI may translate source prose, but it is not trusted to edit files or to
make security decisions.

The workflow is:

1. Atlas emits a deterministic translation input containing canonical unit
   titles, finding source digests, and translatable source fields only.
2. Grok runs read-only and returns Chinese fields in the exact output shape.
3. The coordinator parses the result, rejects extra/missing fields, verifies
   every source digest and required entry, and writes the canonical locale file.
4. Atlas reloads and independently validates the written projection.

Grok never chooses or modifies severity, category, location, disposition,
coverage status, or evidence. Translation output is not accepted merely because
it is valid JSON.

## Guardrail

Repo Atlas exposes a deterministic audit-localization check. It exits non-zero
when any locale declared in `auditContentLocales` is missing, invalid,
incomplete, or stale. The check prints structured diagnostics and supports JSON
output for CI.

RelayOS runs this check alongside its audit-coverage gate. A new canonical
finding or unit title therefore cannot land without updating the required
Chinese projection. Locale files themselves are explicitly classified as
derived localization artifacts in the closed-world review policy; they never
count as security evidence.

## Dirty Tracked Deletions

The tracked-inventory overlay separates dirty paths into deleted and
non-deleted sets using NUL-safe Git output.

1. Read the stage-zero tracked inventory exactly as today.
2. Read all dirty tracked names from `git diff-files --name-only -z`.
3. Read unstaged deletions from
   `git diff-files --diff-filter=D --name-only -z`.
4. Require every reported deletion to be a normalized path present in both the
   index and dirty set.
5. Remove those deleted paths from the current hash map.
6. Hash every remaining dirty path from the worktree.

If a remaining dirty path disappears between Git classification and hashing,
or resolves to a symlink/non-regular/outside-root path, the inventory remains
invalid. A worktree symlink replacement is a type change rather than a deletion
and therefore cannot bypass the unsafe-path checks.

The resulting ordinary deletion reaches `inventoryDrift`, which reports the
path under `removed` and returns a `stale` coverage portfolio with the old
report still visible.

## RelayOS Migration

After both Atlas changes pass their own tests:

1. Configure RelayOS with Chinese as the default viewer locale, English as the
   canonical audit source locale, and Chinese as required audit content.
2. Classify `.atlas/locales/**` as derived localization in the review policy.
3. Regenerate canonical audit ledgers and review coverage from the current
   security-hardening worktree before translating anything.
4. Generate the Chinese localization input from those finalized canonical
   ledgers.
5. Use Grok CLI read-only to translate the input, validate it, and write the
   locale projection.
6. Re-run audit coverage and audit-localization checks.
7. Rebuild and restart Atlas on port 4400.

Historical English evidence remains unchanged. The Chinese projection covers
the current canonical portfolio only.

## Testing

Repo Atlas adds tests for:

- an unstaged tracked deletion becoming `stale` with `drift.removed`;
- a committed deletion continuing to appear as ordinary removed drift;
- a symlink replacement, unreadable regular file, and concurrent disappearance
  remaining invalid;
- strict localization schema/version/locale/path/size validation;
- finding and unit digest determinism;
- rejection of unknown, duplicate, missing, and stale translations;
- inability to override machine/evidence fields;
- per-unit canonical fallback with an explicit diagnostic;
- source-locale passthrough and Chinese/English switching;
- configured default locale without overriding a stored user preference;
- `serve` and static `build` carrying identical localization data;
- the localization check failing on incomplete Chinese content.

RelayOS adds tests that its config requires Chinese, its review policy classifies
locale artifacts, and its checked-in Chinese projection is complete for the
current canonical audit portfolio.

## Acceptance Criteria

- `#audit:security` opens in Chinese for a fresh RelayOS browser profile.
- Every current security unit title and every current finding title/dataflow/fix
  is Chinese when Chinese is selected.
- Switching to English immediately restores canonical English audit prose.
- No localized value can alter a security fact or coverage verdict.
- A stale or malformed Chinese projection visibly falls back instead of
  crashing or silently claiming completeness.
- The ten current RelayOS worktree deletions appear as removed inventory drift,
  not `unreadable-path` diagnostics.
- Atlas, RelayOS audit coverage, localization guardrails, type checks, and a
  real browser smoke test all pass.
