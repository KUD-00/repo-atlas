import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { atlasDir } from './scan.js'
import type { AuditFinding, AuditUnit } from './types.js'

/**
 * Security-audit units — verdict archives an optional pipeline (qa/audit.ts)
 * produced per audit unit (a concept page's sources = a trust boundary). Like
 * artifacts, they hang off the atlas without being part of the notes: status/
 * stamp ignore them, freshness is recomputed HERE at load so the viewer can
 * flag "this audit's bytes drifted, re-audit needed" instead of trusting a
 * stale verdict.
 *
 * Storage convention: `.atlas/audits/<slug>.json` with formatVersion 1:
 *   { slug, title, ruleset, scanned_at, scope_hash, sources, file_count,
 *     files, findings[], dropped[], rounds[], finalPass }
 *
 * scope_hash contract (must stay byte-compatible with qa/audit.ts):
 * sha1 hex over the sorted lines `<git blob sha1>  <path>` (two spaces) for
 * every audited file, joined with '\n' plus a trailing '\n'.
 */

const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical'])

function currentScopeHash(root: string, files: string[]): string | null {
  try {
    const pairs: string[] = []
    for (const f of files) {
      if (!fs.existsSync(path.join(root, f))) return null // a file vanished → drifted
      const sha = execFileSync('git', ['hash-object', '--', f], { cwd: root, encoding: 'utf8' }).trim()
      pairs.push(`${sha}  ${f}`)
    }
    pairs.sort()
    return createHash('sha1').update(pairs.join('\n') + '\n').digest('hex')
  } catch {
    return null
  }
}

function validFinding(f: any): f is AuditFinding {
  return f && SEVERITIES.has(f.severity) && typeof f.category === 'string' &&
    typeof f.title === 'string' && Array.isArray(f.locations) &&
    typeof f.dataflow === 'string' && typeof f.fix === 'string'
}

/** All audit units under .atlas/audits/, freshness-checked, sorted by worst
 * severity then slug. Files failing to parse or with a newer formatVersion
 * are skipped (warned) — a pipeline newer than the engine must not break builds. */
export function loadAudits(root: string): AuditUnit[] {
  const base = path.join(atlasDir(root), 'audits')
  if (!fs.existsSync(base)) return []
  const rank = (s: string) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(s)
  const out: AuditUnit[] = []
  for (const entry of fs.readdirSync(base)) {
    if (!entry.endsWith('.json')) continue
    let a: any
    try {
      a = JSON.parse(fs.readFileSync(path.join(base, entry), 'utf8'))
    } catch {
      console.warn(`  ⚠ .atlas/audits/${entry}: 解析失败，跳过`)
      continue
    }
    const v = a.formatVersion ?? 1
    if (v !== 1) {
      console.warn(`  ⚠ .atlas/audits/${entry}: formatVersion ${v} 超出本引擎认知（1），跳过——升级 repo-atlas`)
      continue
    }
    if (a.finalPass !== true || !Array.isArray(a.files) || !Array.isArray(a.findings)) continue
    const files = a.files.filter((f: any) => typeof f === 'string')
    const current = currentScopeHash(root, files)
    out.push({
      slug: typeof a.slug === 'string' ? a.slug : entry.replace(/\.json$/, ''),
      title: typeof a.title === 'string' ? a.title : entry.replace(/\.json$/, ''),
      ruleset: String(a.ruleset ?? ''),
      scannedAt: String(a.scanned_at ?? ''),
      fileCount: Number(a.file_count ?? files.length),
      findings: a.findings.filter(validFinding),
      droppedCount: Array.isArray(a.dropped) ? a.dropped.length : 0,
      roundCount: Array.isArray(a.rounds) ? a.rounds.length : 0,
      stale: current === null || current !== a.scope_hash,
    })
  }
  out.sort((x, y) => {
    const wx = Math.min(...x.findings.map((f) => rank(f.severity)), 5)
    const wy = Math.min(...y.findings.map((f) => rank(f.severity)), 5)
    return wx - wy || x.slug.localeCompare(y.slug)
  })
  return out
}
