# design-scan — findings (fixture round 1: example layer)

- **Scanned:** 2026-07-01 by `fixture-scanner` (ruleset `relayos-design-v1`)
- **Scope:** 3 fixture files of the example layer.
- **Result:** 1 clean · 2 with findings · **2 findings** (0 high · 1 medium · 1 low). Clean-file records live in [`ledger.json`](./ledger.json); this file details only findings.
- **Report only.** Nothing here is fixed — these are decisions for the owner.

---

## MEDIUM

### packages/example/core/src/types.ts

- **[MEDIUM][optionality][high]** `types.ts:12` — `FixturePort.enabled?: boolean` is optional, but its sole producer `flattenFixturePort` always sets it, and the upstream contract field is non-optional. **Fix:** make it a non-optional `boolean`.

---

## LOW

### packages/example/app/src/format.ts

- **[LOW][dead-forward-compat][high]** `format.ts:3,9` — `LegacyFormatAlias` has zero references repo-wide and only renames `FixtureFormat`. **Fix:** delete the alias.

---

## Deliberately not flagged (bar held)

Candidates that looked like smells but proved load-bearing — recorded so a re-scan doesn't re-litigate them:

- **`z.unknown()` fixture outputs** (types/format) — a fixture convention for read-models whose typed shape lives in a package the fixture cannot import.
