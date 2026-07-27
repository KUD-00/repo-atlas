import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { auditStatusEntries, loadAuditPortfolios, stampAudits } from '../dist/audits.js'
import { scan } from '../dist/scan.js'
import { cleanup, commitAll, gitBlob, makeRepo, scopeHash, write } from './helpers.mjs'

/**
 * The design domain is ledger-grade, not viewer-grade: same envelope and
 * freshness contract as security/test, but no portfolio and no coverage claim.
 * These tests pin both halves of that — accepted by status, absent from the
 * portfolios — plus the strict finding schema.
 */

function designFinding(file, extra = {}) {
  return {
    severity: 'medium',
    category: 'optionality',
    title: 'required field declared optional',
    locations: [`${file}:1`],
    evidence: 'sole producer always sets it; 0 of 4 call sites omit it',
    fix: 'make it non-optional',
    ...extra,
  }
}

function designLedger(root, slug, files, findings, extra = {}) {
  const value = {
    formatVersion: 2,
    format: 'atlas-audit-v2',
    domain: 'design',
    reviewState: 'complete',
    slug,
    title: slug,
    ruleset: 'atlas-designscan-v1',
    scanned_at: '2026-07-25',
    scope_hash: scopeHash(root, files),
    file_count: files.length,
    files,
    findings,
    ...extra,
  }
  write(root, `.atlas/audits/${slug}.json`, JSON.stringify(value, null, 2) + '\n')
  return value
}

function clearLedgers(root) {
  for (const entry of fs.readdirSync(path.join(root, '.atlas/audits'))) {
    fs.unlinkSync(path.join(root, '.atlas/audits', entry))
  }
}

test('a design ledger is fresh in status and absent from every portfolio', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export interface A { required?: boolean }\n')
    commitAll(root)
    designLedger(root, 'design-contracts', ['src/a.ts'], [designFinding('src/a.ts')])

    const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(status.invalidReason, null)
    assert.equal(status.status, 'fresh')
    assert.equal(status.name, 'design-contracts')
    assert.equal(status.ruleset, 'atlas-designscan-v1')
    assert.equal(status.findingCount, 1)

    // No portfolio, and no "unsupported domain" warning path either.
    assert.deepEqual(loadAuditPortfolios(root), { security: [], tests: [] })
  } finally { cleanup(root) }
})

test('design scope drift is reported per file once stamped', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export interface A { required?: boolean }\n')
    write(root, 'src/b.ts', 'export const b = 1\n')
    commitAll(root)
    designLedger(root, 'design-contracts', ['src/a.ts', 'src/b.ts'], [designFinding('src/a.ts')])

    const stamp = stampAudits(root, scan(root, { exclude: [] }))
    assert.deepEqual(stamp.stamped, ['design-contracts'])

    write(root, 'src/a.ts', 'export interface A { required: boolean }\n')
    const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(status.status, 'stale')
    assert.deepEqual(status.changedFiles, ['src/a.ts'])
    assert.equal(status.findingsWithDrift, 1)
  } finally { cleanup(root) }
})

test('design findings fail closed on schema violations', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)

    const cases = [
      { slug: 'no-evidence', findings: [{ ...designFinding('src/a.ts'), evidence: '' }] },
      { slug: 'no-fix', findings: [{ ...designFinding('src/a.ts'), fix: '   ' }] },
      { slug: 'bad-category', findings: [{ ...designFinding('src/a.ts'), category: 'code-smell' }] },
      { slug: 'bad-severity', findings: [{ ...designFinding('src/a.ts'), severity: 'critical' }] },
      { slug: 'no-locations', findings: [{ ...designFinding('src/a.ts'), locations: [] }] },
      { slug: 'absolute-location', findings: [{ ...designFinding('src/a.ts'), locations: ['/etc/passwd:1'] }] },
      { slug: 'bad-disposition', findings: [{ ...designFinding('src/a.ts'), disposition: 'accepted-risk' }] },
      { slug: 'security-crossover', findings: [{
        severity: 'medium', category: 'boundary', title: 'wrong domain',
        locations: ['src/a.ts:1'], dataflow: 'input to sink', fix: 'validate it',
      }] },
    ]

    for (const item of cases) {
      clearLedgers(root)
      designLedger(root, item.slug, ['src/a.ts'], item.findings)
      const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
      assert.equal(status.status, 'stale', item.slug)
      assert.match(status.invalidReason ?? '', /design finding/i, item.slug)
    }
  } finally { cleanup(root) }
})

test('an incomplete or mis-slugged design review never counts as a review', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)

    clearLedgers(root)
    designLedger(root, 'in-progress', ['src/a.ts'], [], { reviewState: 'in-progress' })
    let [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.match(status.invalidReason ?? '', /reviewState must be complete/i)

    clearLedgers(root)
    const value = designLedger(root, 'design-mismatch', ['src/a.ts'], [designFinding('src/a.ts')])
    write(root, '.atlas/audits/design-mismatch.json', JSON.stringify({ ...value, slug: 'other' }, null, 2) + '\n')
    ;[status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.match(status.invalidReason ?? '', /slug must match its ledger filename/i)
  } finally { cleanup(root) }
})

test('design dispositions and confidence survive validation', () => {
  const root = makeRepo()
  try {
    write(root, 'src/a.ts', 'export const a = 1\n')
    commitAll(root)
    designLedger(root, 'design-dispositions', ['src/a.ts'], [
      designFinding('src/a.ts', { disposition: 'accepted-design', confidence: 'medium' }),
      designFinding('src/a.ts', { disposition: 'deferred', category: 'dead-forward-compat', severity: 'low' }),
      designFinding('src/a.ts', { category: 'naming-drift', severity: 'high', locations: ['src/a.ts#A'] }),
    ], { hashes: { 'src/a.ts': gitBlob(root, 'src/a.ts') } })
    const [status] = auditStatusEntries(root, scan(root, { exclude: [] }))
    assert.equal(status.invalidReason, null)
    assert.equal(status.status, 'fresh')
    assert.equal(status.findingCount, 3)
  } finally { cleanup(root) }
})
