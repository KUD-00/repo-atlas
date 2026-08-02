# design-scan

> Fixture stand-in for the historical round-1 design scan. This axis now lives
> in Atlas: the 2 findings were migrated into
> `.atlas/audits/design-fixture-layer.json` (`atlas-audit-v2`, `domain:
> design`), with scan-time `git_blob_sha1` values preserved as the ledger
> `hashes`. This directory's `ledger.json` / `findings.md` / `check.mjs` are
> kept as the original record and are no longer updated.

Records of **design-reasonableness** audits of fixture source files — the
sibling of `security-scan`, same machinery, different ruleset.

## Files

- **`ledger.json`** — one entry per scanned file: path, `git_blob_sha1`, line
  count, `scanned_at`, `scanned_by`, ruleset id, `status`, `max_severity`,
  `finding_count`, `findings_ref`.
- **`findings.md`** — human-readable detail for files with findings.

## Ruleset `relayos-design-v1`

| id | what it catches |
|---|---|
| `optionality` | a `?:` / `\| null` that is never actually absent/null |
| `dead-forward-compat` | field/type kept "for later" with zero current references |

**Bar:** strict, high-confidence only. Every finding cites `file:line` plus the
evidence that proves it.
