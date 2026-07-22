import assert from 'node:assert/strict'
import test from 'node:test'

import {
  localizeAuditPresentation,
  resolveInitialLocale,
} from '../dist/audit-localization-presentation.js'

const securityFinding = {
  severity: 'high',
  category: 'authorization',
  title: 'Canonical security title',
  locations: ['src/security.ts:12'],
  dataflow: 'canonical security dataflow',
  fix: 'canonical security fix',
  disposition: 'open',
}

const testFinding = {
  impact: 'blocking',
  category: 'missing-invariant',
  title: 'Canonical test title',
  invariant: 'canonical invariant',
  evidence: 'canonical evidence',
  fix: 'canonical test fix',
  locations: ['src/security.test.ts:20'],
}

const securityUnit = {
  formatVersion: 2,
  domain: 'security',
  slug: 'security-runtime',
  title: 'Runtime security',
  ruleset: 'security-v1',
  scannedAt: '2026-07-22',
  scopeHash: 'a'.repeat(40),
  fileCount: 1,
  files: ['src/security.ts'],
  hashes: { 'src/security.ts': 'b'.repeat(40) },
  evidenceRefs: [],
  droppedCount: 0,
  roundCount: 1,
  stale: false,
  findings: [securityFinding],
}

const testUnit = {
  formatVersion: 2,
  domain: 'test',
  slug: 'test-runtime',
  title: 'Runtime tests',
  ruleset: 'tests-v1',
  scannedAt: '2026-07-22',
  scopeHash: 'c'.repeat(40),
  fileCount: 1,
  files: ['src/security.test.ts'],
  hashes: { 'src/security.test.ts': 'd'.repeat(40) },
  evidenceRefs: [],
  droppedCount: 0,
  roundCount: 1,
  stale: false,
  findings: [testFinding],
}

const coverage = {
  state: 'current',
  report: {
    formatVersion: 1,
    format: 'atlas-review-coverage-v1',
    verdict: 'complete',
    policy: { format: 'fixture-v1', hash: 'e'.repeat(64) },
    inventoryHash: 'f'.repeat(64),
    units: [
      { domain: 'security', slug: 'security-runtime', title: 'Runtime security' },
      { domain: 'test', slug: 'test-runtime', title: 'Runtime tests' },
      { domain: 'security', slug: 'security-empty', title: 'Empty security' },
    ],
    summary: {},
    entries: [],
    invalidLedgerDetails: [],
    reportErrors: [],
  },
  errors: [],
  drift: { added: [], removed: [], changed: [] },
}

const zhUnits = [
  {
    domain: 'security',
    slug: 'security-runtime',
    sourceDigest: '1'.repeat(64),
    title: '运行时安全',
    findings: [{
      sourceDigest: '2'.repeat(64),
      title: '调用方权限未校验',
      dataflow: '请求身份流入特权写入操作',
      fix: '写入前验证调用方权限',
    }],
  },
  {
    domain: 'test',
    slug: 'test-runtime',
    sourceDigest: '3'.repeat(64),
    title: '运行时测试',
    findings: [{
      sourceDigest: '4'.repeat(64),
      title: '缺少权限拒绝测试',
      invariant: '未认证调用必须被拒绝',
      evidence: '当前套件绕过了真实鉴权',
      fix: '通过真实入口断言权限门',
    }],
  },
  {
    domain: 'security',
    slug: 'security-empty',
    sourceDigest: '5'.repeat(64),
    title: '空安全单元',
    findings: [],
  },
]

test('verified translations create prose-only presentation copies', () => {
  const canonical = {
    audits: [securityUnit],
    testAudits: [testUnit],
    coverage,
  }
  const before = structuredClone(canonical)

  const localized = localizeAuditPresentation({
    locale: 'zh',
    sourceLocale: 'en',
    localizations: {
      zh: { locale: 'zh', state: 'complete', units: zhUnits, errors: [] },
    },
    audits: canonical.audits,
    testAudits: canonical.testAudits,
    reviewCoverage: canonical.coverage,
  })

  assert.equal(localized.state, 'translated')
  assert.equal(localized.audits[0].title, '运行时安全')
  assert.equal(localized.audits[0].findings[0].title, '调用方权限未校验')
  assert.equal(localized.audits[0].findings[0].dataflow, '请求身份流入特权写入操作')
  assert.equal(localized.audits[0].findings[0].fix, '写入前验证调用方权限')
  assert.equal(localized.audits[0].findings[0].severity, 'high')
  assert.equal(localized.audits[0].findings[0].category, 'authorization')
  assert.deepEqual(localized.audits[0].findings[0].locations, ['src/security.ts:12'])
  assert.equal(localized.audits[0].findings[0].disposition, 'open')

  assert.equal(localized.testAudits[0].title, '运行时测试')
  assert.equal(localized.testAudits[0].findings[0].invariant, '未认证调用必须被拒绝')
  assert.equal(localized.testAudits[0].findings[0].evidence, '当前套件绕过了真实鉴权')
  assert.equal(localized.testAudits[0].findings[0].impact, 'blocking')
  assert.equal(localized.testAudits[0].findings[0].category, 'missing-invariant')

  assert.deepEqual(
    localized.reviewCoverage.report.units.map((unit) => unit.title),
    ['运行时安全', '运行时测试', '空安全单元'],
  )
  assert.equal(localized.reviewCoverage.report.verdict, 'complete')
  assert.deepEqual(canonical, before)
})

test('source locale passes canonical prose and incomplete locale falls back per unit', () => {
  const source = localizeAuditPresentation({
    locale: 'en',
    sourceLocale: 'en',
    localizations: {},
    audits: [securityUnit],
    testAudits: [testUnit],
    reviewCoverage: coverage,
  })
  assert.equal(source.state, 'source')
  assert.equal(source.audits[0].title, 'Runtime security')

  const fallback = localizeAuditPresentation({
    locale: 'zh',
    sourceLocale: 'en',
    localizations: {
      zh: {
        locale: 'zh',
        state: 'incomplete',
        units: [zhUnits[0]],
        errors: [{ code: 'missing-unit', message: 'test unit missing', locale: 'zh' }],
      },
    },
    audits: [securityUnit],
    testAudits: [testUnit],
    reviewCoverage: coverage,
  })
  assert.equal(fallback.state, 'fallback')
  assert.equal(fallback.audits[0].title, '运行时安全')
  assert.equal(fallback.testAudits[0].title, 'Runtime tests')
  assert.deepEqual(
    fallback.reviewCoverage.report.units.map((unit) => unit.title),
    ['运行时安全', 'Runtime tests', 'Empty security'],
  )
})

test('configured default locale never overrides a valid stored preference', () => {
  assert.equal(resolveInitialLocale('zh', null), 'zh')
  assert.equal(resolveInitialLocale('zh', 'en'), 'en')
  assert.equal(resolveInitialLocale('zh', 'not-a-locale'), 'zh')
  assert.equal(resolveInitialLocale(undefined, null), 'en')
})

test('legacy payload without review coverage fails closed instead of crashing', () => {
  const localized = localizeAuditPresentation({
    locale: 'en',
    sourceLocale: 'en',
    localizations: undefined,
    audits: [],
    testAudits: [],
    reviewCoverage: undefined,
  })
  assert.equal(localized.state, 'source')
  assert.equal(localized.reviewCoverage.state, 'missing')
  assert.equal(localized.reviewCoverage.report, null)
})
