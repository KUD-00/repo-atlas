import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test, { afterEach } from 'node:test'

import {
  auditFindingSourceDigest,
  auditUnitSourceDigest,
  buildAuditLocalizationInput,
  loadAuditLocalization,
  loadConfiguredAuditLocalizations,
} from '../dist/audit-localizations.js'
import { loadConfig } from '../dist/scan.js'

const roots = []

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true })
})

const securityFinding = {
  severity: 'medium',
  category: 'authorization',
  title: 'Caller authority is not checked',
  locations: ['src/runtime.ts:7'],
  dataflow: 'request identity reaches the privileged write',
  fix: 'authorize the caller before writing',
  disposition: 'open',
}

const securityUnit = {
  formatVersion: 2,
  domain: 'security',
  slug: 'security-runtime',
  title: 'Runtime security',
  ruleset: 'fixture-security-v1',
  scannedAt: '2026-07-22',
  scopeHash: 'a'.repeat(40),
  fileCount: 1,
  files: ['src/runtime.ts'],
  hashes: { 'src/runtime.ts': 'b'.repeat(40) },
  evidenceRefs: [],
  droppedCount: 0,
  roundCount: 1,
  stale: false,
  findings: [securityFinding],
}

function coverageWithUnits(units) {
  return {
    state: 'current',
    report: { units },
    errors: [],
    drift: { added: [], removed: [], changed: [] },
  }
}

function localizationRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-localization-'))
  roots.push(root)
  fs.mkdirSync(path.join(root, '.atlas', 'locales', 'zh'), { recursive: true })
  return root
}

function completeInput() {
  return buildAuditLocalizationInput(
    'en',
    'zh',
    coverageWithUnits([
      { domain: 'security', slug: 'security-empty', title: 'Empty security unit' },
      { domain: 'security', slug: 'security-runtime', title: 'Runtime security' },
    ]),
    { security: [securityUnit], tests: [] },
  )
}

function sidecarFrom(input) {
  return {
    formatVersion: 1,
    format: 'atlas-audit-localizations-v1',
    locale: input.targetLocale,
    units: structuredClone(input.units),
  }
}

function writeSidecar(root, value) {
  fs.writeFileSync(
    path.join(root, '.atlas', 'locales', 'zh', 'audits.json'),
    typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`,
  )
}

function writeConfig(root, value) {
  fs.writeFileSync(
    path.join(root, '.atlas', 'config.json'),
    `${JSON.stringify(value, null, 2)}\n`,
  )
}

test('finding and unit source digests are deterministic and fact-bound', () => {
  const reordered = {
    disposition: 'open',
    fix: 'authorize the caller before writing',
    dataflow: 'request identity reaches the privileged write',
    locations: ['src/runtime.ts:7'],
    title: 'Caller authority is not checked',
    category: 'authorization',
    severity: 'medium',
  }

  assert.equal(
    auditFindingSourceDigest(securityFinding),
    auditFindingSourceDigest(reordered),
  )
  assert.notEqual(
    auditFindingSourceDigest(securityFinding),
    auditFindingSourceDigest({ ...securityFinding, severity: 'high' }),
  )

  const findingDigest = auditFindingSourceDigest(securityFinding)
  assert.equal(
    auditUnitSourceDigest('security', 'security-runtime', 'Runtime security', [findingDigest]),
    auditUnitSourceDigest('security', 'security-runtime', 'Runtime security', [findingDigest]),
  )
  assert.notEqual(
    auditUnitSourceDigest('security', 'security-runtime', 'Runtime security', [findingDigest]),
    auditUnitSourceDigest('security', 'security-runtime', 'Runtime boundary security', [findingDigest]),
  )
})

test('localization input combines registered empty units with canonical ledgers', () => {
  const input = buildAuditLocalizationInput(
    'en',
    'zh',
    coverageWithUnits([
      { domain: 'security', slug: 'security-empty', title: 'Empty security unit' },
      { domain: 'security', slug: 'security-runtime', title: 'Runtime security' },
    ]),
    { security: [securityUnit], tests: [] },
  )

  assert.equal(input.formatVersion, 1)
  assert.equal(input.format, 'atlas-audit-localization-input-v1')
  assert.equal(input.sourceLocale, 'en')
  assert.equal(input.targetLocale, 'zh')
  assert.deepEqual(input.units.map((unit) => unit.slug), [
    'security-empty',
    'security-runtime',
  ])
  assert.deepEqual(input.units[0].findings, [])
  assert.equal(input.units[0].title, 'Empty security unit')
  assert.equal(input.units[1].findings.length, 1)
  assert.deepEqual(Object.keys(input.units[1].findings[0]).sort(), [
    'dataflow',
    'fix',
    'sourceDigest',
    'title',
  ])
})

test('localization source fails closed without a registry and rejects duplicate canonical findings', () => {
  assert.throws(
    () => buildAuditLocalizationInput(
      'en',
      'zh',
      { state: 'missing', report: null, errors: [], drift: { added: [], removed: [], changed: [] } },
      { security: [securityUnit], tests: [] },
    ),
    /coverage registry/i,
  )

  assert.throws(
    () => buildAuditLocalizationInput(
      'en',
      'zh',
      coverageWithUnits([
        { domain: 'security', slug: 'security-runtime', title: 'Runtime security' },
      ]),
      {
        security: [{
          ...securityUnit,
          findings: [securityFinding, structuredClone(securityFinding)],
        }],
        tests: [],
      },
    ),
    /duplicate canonical findings/i,
  )
})

test('localization loader reports missing incomplete complete and invalid states', () => {
  const input = completeInput()

  const missingRoot = localizationRoot()
  const missing = loadAuditLocalization(missingRoot, 'zh', input)
  assert.equal(missing.state, 'missing')
  assert.deepEqual(missing.units, [])

  const incompleteRoot = localizationRoot()
  const partial = sidecarFrom(input)
  partial.units = partial.units.slice(0, 1)
  writeSidecar(incompleteRoot, partial)
  const incomplete = loadAuditLocalization(incompleteRoot, 'zh', input)
  assert.equal(incomplete.state, 'incomplete')
  assert.deepEqual(incomplete.units.map((unit) => unit.slug), ['security-empty'])
  assert.ok(incomplete.errors.some((error) => error.code === 'missing-unit'))

  const completeRoot = localizationRoot()
  writeSidecar(completeRoot, sidecarFrom(input))
  const complete = loadAuditLocalization(completeRoot, 'zh', input)
  assert.equal(complete.state, 'complete')
  assert.deepEqual(complete.units.map((unit) => unit.slug), [
    'security-empty',
    'security-runtime',
  ])
  assert.deepEqual(complete.errors, [])

  const invalidRoot = localizationRoot()
  const extraKey = sidecarFrom(input)
  extraKey.units[0].severity = 'critical'
  writeSidecar(invalidRoot, extraKey)
  const invalid = loadAuditLocalization(invalidRoot, 'zh', input)
  assert.equal(invalid.state, 'invalid')
  assert.deepEqual(invalid.units, [])
  assert.ok(invalid.errors.some((error) => error.code === 'invalid-shape'))
})

test('localization loader bounds unit and finding arrays to the canonical source', () => {
  const input = completeInput()

  const tooManyUnitsRoot = localizationRoot()
  const tooManyUnits = sidecarFrom(input)
  tooManyUnits.units.push(structuredClone(tooManyUnits.units[0]))
  writeSidecar(tooManyUnitsRoot, tooManyUnits)
  const unitResult = loadAuditLocalization(tooManyUnitsRoot, 'zh', input)
  assert.equal(unitResult.state, 'invalid')
  assert.equal(unitResult.errors[0]?.code, 'too-many-units')

  const tooManyFindingsRoot = localizationRoot()
  const tooManyFindings = sidecarFrom(input)
  tooManyFindings.units[1].findings.push(
    structuredClone(tooManyFindings.units[1].findings[0]),
  )
  writeSidecar(tooManyFindingsRoot, tooManyFindings)
  const findingResult = loadAuditLocalization(tooManyFindingsRoot, 'zh', input)
  assert.equal(findingResult.state, 'invalid')
  assert.equal(findingResult.errors[0]?.code, 'too-many-findings')
})

test('stale units fall back independently while symlinks fail closed', () => {
  const input = completeInput()
  const staleRoot = localizationRoot()
  const staleSidecar = sidecarFrom(input)
  staleSidecar.units[1].sourceDigest = '0'.repeat(64)
  writeSidecar(staleRoot, staleSidecar)

  const stale = loadAuditLocalization(staleRoot, 'zh', input)
  assert.equal(stale.state, 'incomplete')
  assert.deepEqual(stale.units.map((unit) => unit.slug), ['security-empty'])
  assert.ok(stale.errors.some((error) => error.code === 'stale-unit'))

  const symlinkRoot = localizationRoot()
  const outside = path.join(symlinkRoot, 'outside.json')
  fs.writeFileSync(outside, `${JSON.stringify(sidecarFrom(input))}\n`)
  fs.symlinkSync(outside, path.join(symlinkRoot, '.atlas', 'locales', 'zh', 'audits.json'))

  const symlinked = loadAuditLocalization(symlinkRoot, 'zh', input)
  assert.equal(symlinked.state, 'invalid')
  assert.deepEqual(symlinked.units, [])
  assert.ok(symlinked.errors.some((error) => error.code === 'unsafe-path'))
})

test('config rejects unsupported duplicate and source-equal audit locales', () => {
  const invalidConfigs = [
    { formatVersion: 1, defaultLocale: 'fr' },
    { formatVersion: 1, auditSourceLocale: 'fr' },
    { formatVersion: 1, auditContentLocales: 'zh' },
    { formatVersion: 1, auditContentLocales: ['zh', 'zh'] },
    { formatVersion: 1, auditSourceLocale: 'en', auditContentLocales: ['en'] },
  ]

  for (const config of invalidConfigs) {
    const root = localizationRoot()
    writeConfig(root, config)
    assert.throws(() => loadConfig(root), /locale/i, JSON.stringify(config))
  }

  const validRoot = localizationRoot()
  writeConfig(validRoot, {
    formatVersion: 1,
    defaultLocale: 'zh',
    auditSourceLocale: 'en',
    auditContentLocales: ['zh'],
  })
  assert.deepEqual(loadConfig(validRoot), {
    formatVersion: 1,
    defaultLocale: 'zh',
    auditSourceLocale: 'en',
    auditContentLocales: ['zh'],
  })
})

test('configured loader returns verified portfolios keyed by target locale', () => {
  const root = localizationRoot()
  const input = completeInput()
  writeSidecar(root, sidecarFrom(input))
  const coverage = coverageWithUnits([
    { domain: 'security', slug: 'security-empty', title: 'Empty security unit' },
    { domain: 'security', slug: 'security-runtime', title: 'Runtime security' },
  ])

  const loaded = loadConfiguredAuditLocalizations(
    root,
    {
      formatVersion: 1,
      defaultLocale: 'zh',
      auditSourceLocale: 'en',
      auditContentLocales: ['zh'],
    },
    coverage,
    { security: [securityUnit], tests: [] },
  )

  assert.equal(loaded.sourceLocale, 'en')
  assert.equal(loaded.portfolios.zh?.state, 'complete')
  assert.deepEqual(loaded.portfolios.zh?.units.map((unit) => unit.slug), [
    'security-empty',
    'security-runtime',
  ])
})
