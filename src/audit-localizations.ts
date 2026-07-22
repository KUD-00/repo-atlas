import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { TextDecoder } from 'node:util'
import type { AuditPortfolios } from './audits.js'
import { atlasDir, readRepoFile } from './scan.js'
import type {
  AuditDomain,
  AuditLocalizationDiagnostic,
  AuditLocalizationPortfolio,
  AtlasConfig,
  AtlasLocale,
  AuditFinding,
  ReviewCoveragePortfolio,
  TestAuditFinding,
  VerifiedAuditFindingTranslation,
  VerifiedAuditUnitTranslation,
} from './types.js'

export interface SecurityLocalizationSourceFinding {
  sourceDigest: string
  title: string
  dataflow: string
  fix: string
}

export interface TestLocalizationSourceFinding {
  sourceDigest: string
  title: string
  invariant: string
  evidence: string
  fix: string
}

export type AuditLocalizationSourceFinding =
  | SecurityLocalizationSourceFinding
  | TestLocalizationSourceFinding

export interface AuditLocalizationSourceUnit {
  domain: AuditDomain
  slug: string
  sourceDigest: string
  title: string
  findings: AuditLocalizationSourceFinding[]
}

export interface AuditLocalizationInput {
  formatVersion: 1
  format: 'atlas-audit-localization-input-v1'
  sourceLocale: AtlasLocale
  targetLocale: AtlasLocale
  units: AuditLocalizationSourceUnit[]
}

const LOCALIZATION_FORMAT = 'atlas-audit-localizations-v1' as const
const MAX_LOCALIZATION_BYTES = 32 * 1024 * 1024
const MAX_LOCALIZATION_TEXT_CODE_UNITS = 65_536
const MAX_LOCALIZATION_UNITS = 100_000
const SHA256_RE = /^[0-9a-f]{64}$/u
const UTF8 = new TextDecoder('utf-8', { fatal: true })

const TOP_LEVEL_KEYS = ['formatVersion', 'format', 'locale', 'units'] as const
const UNIT_KEYS = ['domain', 'slug', 'sourceDigest', 'title', 'findings'] as const
const SECURITY_FINDING_KEYS = ['sourceDigest', 'title', 'dataflow', 'fix'] as const
const TEST_FINDING_KEYS = ['sourceDigest', 'title', 'invariant', 'evidence', 'fix'] as const

function canonicalValue(value: unknown): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonical JSON cannot contain a non-finite number')
    return value
  }
  if (Array.isArray(value)) return value.map(canonicalValue)
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value).sort()) {
      const child = (value as Record<string, unknown>)[key]
      if (child !== undefined) out[key] = canonicalValue(child)
    }
    return out
  }
  throw new Error(`canonical JSON cannot contain ${typeof value}`)
}

export function canonicalAuditLocalizationJson(value: unknown): string {
  return `${JSON.stringify(canonicalValue(value))}\n`
}

function sourceDigest(value: unknown): string {
  return createHash('sha256')
    .update(canonicalAuditLocalizationJson(value), 'utf8')
    .digest('hex')
}

export function auditFindingSourceDigest(finding: AuditFinding | TestAuditFinding): string {
  return sourceDigest(finding)
}

export function auditUnitSourceDigest(
  domain: AuditDomain,
  slug: string,
  title: string,
  findingDigests: readonly string[],
): string {
  return sourceDigest({
    domain,
    slug,
    title,
    findingDigests: [...findingDigests].sort(),
  })
}

function securitySourceFinding(finding: AuditFinding): SecurityLocalizationSourceFinding {
  return {
    sourceDigest: auditFindingSourceDigest(finding),
    title: finding.title,
    dataflow: finding.dataflow,
    fix: finding.fix,
  }
}

function testSourceFinding(finding: TestAuditFinding): TestLocalizationSourceFinding {
  return {
    sourceDigest: auditFindingSourceDigest(finding),
    title: finding.title,
    invariant: finding.invariant,
    evidence: finding.evidence,
    fix: finding.fix,
  }
}

interface UnitAccumulator {
  domain: AuditDomain
  slug: string
  title: string
  findings: AuditLocalizationSourceFinding[]
}

function unitKey(domain: AuditDomain, slug: string): string {
  return `${domain}\0${slug}`
}

function exactKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index])
}

function validLocalizedText(value: unknown): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_LOCALIZATION_TEXT_CODE_UNITS &&
    value === value.trim()
}

function localizationDiagnostic(
  locale: AtlasLocale,
  code: string,
  message: string,
  extra: Pick<AuditLocalizationDiagnostic, 'domain' | 'slug' | 'sourceDigest'> = {},
): AuditLocalizationDiagnostic {
  return { code, message, locale, ...extra }
}

function invalidLocalization(
  locale: AtlasLocale,
  errors: AuditLocalizationDiagnostic[],
): AuditLocalizationPortfolio {
  return { locale, state: 'invalid', units: [], errors }
}

export function auditLocalizationPath(root: string, locale: AtlasLocale): string {
  return path.join(atlasDir(root), 'locales', locale, 'audits.json')
}

function localizationFileState(root: string, locale: AtlasLocale): 'missing' | 'unsafe' | 'file' {
  const atlas = atlasDir(root)
  const locales = path.join(atlas, 'locales')
  const localeDir = path.join(locales, locale)
  for (const directory of [atlas, locales, localeDir]) {
    const stat = fs.lstatSync(directory, { throwIfNoEntry: false })
    if (!stat) return 'missing'
    if (!stat.isDirectory() || stat.isSymbolicLink()) return 'unsafe'
  }
  const stat = fs.lstatSync(path.join(localeDir, 'audits.json'), { throwIfNoEntry: false })
  if (!stat) return 'missing'
  return stat.isFile() && !stat.isSymbolicLink() ? 'file' : 'unsafe'
}

function parseFindingTranslation(
  locale: AtlasLocale,
  domain: AuditDomain,
  value: unknown,
  slug: string,
): { value: VerifiedAuditFindingTranslation } | { error: AuditLocalizationDiagnostic } {
  const expected = domain === 'security' ? SECURITY_FINDING_KEYS : TEST_FINDING_KEYS
  if (!exactKeys(value, expected)) {
    return { error: localizationDiagnostic(
      locale,
      'invalid-shape',
      `localized ${domain} finding has missing or extra fields`,
      { domain, slug },
    ) }
  }
  if (typeof value.sourceDigest !== 'string' || !SHA256_RE.test(value.sourceDigest)) {
    return { error: localizationDiagnostic(
      locale,
      'invalid-digest',
      `localized ${domain} finding sourceDigest must be lowercase SHA-256`,
      { domain, slug },
    ) }
  }
  const proseKeys = domain === 'security'
    ? ['title', 'dataflow', 'fix'] as const
    : ['title', 'invariant', 'evidence', 'fix'] as const
  for (const key of proseKeys) {
    if (!validLocalizedText(value[key])) {
      return { error: localizationDiagnostic(
        locale,
        'invalid-text',
        `localized ${domain} finding ${key} must be bounded nonempty text without surrounding whitespace`,
        { domain, slug, sourceDigest: value.sourceDigest },
      ) }
    }
  }
  return { value: value as unknown as VerifiedAuditFindingTranslation }
}

export function loadAuditLocalization(
  root: string,
  locale: AtlasLocale,
  source: AuditLocalizationInput,
): AuditLocalizationPortfolio {
  if (source.targetLocale !== locale) {
    return invalidLocalization(locale, [localizationDiagnostic(
      locale,
      'locale-mismatch',
      `localization source targets ${source.targetLocale}, not ${locale}`,
    )])
  }

  let fileState: ReturnType<typeof localizationFileState>
  try {
    fileState = localizationFileState(root, locale)
  } catch {
    fileState = 'unsafe'
  }
  if (fileState === 'missing') return { locale, state: 'missing', units: [], errors: [] }
  if (fileState === 'unsafe') {
    return invalidLocalization(locale, [localizationDiagnostic(
      locale,
      'unsafe-path',
      `audit localization path is symlinked, outside the repository, or not a regular file`,
    )])
  }

  const rel = `.atlas/locales/${locale}/audits.json`
  const opened = readRepoFile(root, rel, MAX_LOCALIZATION_BYTES + 1)
  if (!opened) {
    return invalidLocalization(locale, [localizationDiagnostic(
      locale,
      'unsafe-path',
      'audit localization file is unsafe or unreadable',
    )])
  }
  if (opened.truncated || opened.size > MAX_LOCALIZATION_BYTES) {
    return invalidLocalization(locale, [localizationDiagnostic(
      locale,
      'file-too-large',
      `audit localization file exceeds the ${MAX_LOCALIZATION_BYTES} byte limit`,
    )])
  }

  let raw: unknown
  try {
    raw = JSON.parse(UTF8.decode(opened.buffer)) as unknown
  } catch {
    return invalidLocalization(locale, [localizationDiagnostic(
      locale,
      'invalid-json',
      'audit localization file is malformed JSON or invalid UTF-8',
    )])
  }
  if (!exactKeys(raw, TOP_LEVEL_KEYS) ||
      raw.formatVersion !== 1 ||
      raw.format !== LOCALIZATION_FORMAT ||
      raw.locale !== locale ||
      !Array.isArray(raw.units) ||
      raw.units.length > MAX_LOCALIZATION_UNITS) {
    return invalidLocalization(locale, [localizationDiagnostic(
      locale,
      'invalid-shape',
      'audit localization top-level contract is invalid',
    )])
  }
  if (raw.units.length > source.units.length) {
    return invalidLocalization(locale, [localizationDiagnostic(
      locale,
      'too-many-units',
      'audit localization contains more units than the canonical source',
    )])
  }

  const sourceByUnit = new Map(source.units.map((unit) => [unitKey(unit.domain, unit.slug), unit]))
  const seenUnits = new Set<string>()
  const verified: VerifiedAuditUnitTranslation[] = []
  const incomplete: AuditLocalizationDiagnostic[] = []

  for (const value of raw.units) {
    if (!exactKeys(value, UNIT_KEYS) ||
        (value.domain !== 'security' && value.domain !== 'test') ||
        typeof value.slug !== 'string' || !value.slug ||
        typeof value.sourceDigest !== 'string' || !SHA256_RE.test(value.sourceDigest) ||
        !validLocalizedText(value.title) ||
        !Array.isArray(value.findings)) {
      return invalidLocalization(locale, [localizationDiagnostic(
        locale,
        'invalid-shape',
        'localized audit unit has missing, extra, or invalid fields',
      )])
    }

    const domain = value.domain
    const slug = value.slug
    const key = unitKey(domain, slug)
    if (seenUnits.has(key)) {
      return invalidLocalization(locale, [localizationDiagnostic(
        locale,
        'duplicate-unit',
        `localized audit unit appears more than once: ${domain}/${slug}`,
        { domain, slug },
      )])
    }
    seenUnits.add(key)

    const sourceUnit = sourceByUnit.get(key)
    if (!sourceUnit) {
      return invalidLocalization(locale, [localizationDiagnostic(
        locale,
        'unknown-unit',
        `localized audit unit is not registered by the canonical source: ${domain}/${slug}`,
        { domain, slug },
      )])
    }
    if (value.findings.length > sourceUnit.findings.length) {
      return invalidLocalization(locale, [localizationDiagnostic(
        locale,
        'too-many-findings',
        `localized audit unit contains more findings than the canonical source: ${domain}/${slug}`,
        { domain, slug },
      )])
    }

    const parsedFindings: VerifiedAuditFindingTranslation[] = []
    const seenFindings = new Set<string>()
    for (const finding of value.findings) {
      const parsed = parseFindingTranslation(locale, domain, finding, slug)
      if ('error' in parsed) return invalidLocalization(locale, [parsed.error])
      if (seenFindings.has(parsed.value.sourceDigest)) {
        return invalidLocalization(locale, [localizationDiagnostic(
          locale,
          'duplicate-finding',
          `localized finding appears more than once in ${domain}/${slug}`,
          { domain, slug, sourceDigest: parsed.value.sourceDigest },
        )])
      }
      seenFindings.add(parsed.value.sourceDigest)
      parsedFindings.push(parsed.value)
    }

    if (value.sourceDigest !== sourceUnit.sourceDigest) {
      incomplete.push(localizationDiagnostic(
        locale,
        'stale-unit',
        `localized audit unit is bound to stale canonical bytes: ${domain}/${slug}`,
        { domain, slug, sourceDigest: value.sourceDigest },
      ))
      continue
    }

    const sourceFindingDigests = new Set(sourceUnit.findings.map((finding) => finding.sourceDigest))
    for (const finding of parsedFindings) {
      if (!sourceFindingDigests.has(finding.sourceDigest)) {
        return invalidLocalization(locale, [localizationDiagnostic(
          locale,
          'unknown-finding',
          `localized finding is not present in the current canonical unit: ${domain}/${slug}`,
          { domain, slug, sourceDigest: finding.sourceDigest },
        )])
      }
    }
    const translatedByDigest = new Map(parsedFindings.map((finding) => [finding.sourceDigest, finding]))
    const missingFinding = sourceUnit.findings.find(
      (finding) => !translatedByDigest.has(finding.sourceDigest),
    )
    if (missingFinding) {
      incomplete.push(localizationDiagnostic(
        locale,
        'missing-finding',
        `current canonical finding has no localized prose: ${domain}/${slug}`,
        { domain, slug, sourceDigest: missingFinding.sourceDigest },
      ))
      continue
    }

    verified.push({
      domain,
      slug,
      sourceDigest: value.sourceDigest,
      title: value.title,
      findings: sourceUnit.findings.map(
        (finding) => translatedByDigest.get(finding.sourceDigest)!,
      ),
    })
  }

  for (const sourceUnit of source.units) {
    const key = unitKey(sourceUnit.domain, sourceUnit.slug)
    if (!seenUnits.has(key)) {
      incomplete.push(localizationDiagnostic(
        locale,
        'missing-unit',
        `canonical audit unit has no localized prose: ${sourceUnit.domain}/${sourceUnit.slug}`,
        { domain: sourceUnit.domain, slug: sourceUnit.slug },
      ))
    }
  }

  return {
    locale,
    state: incomplete.length === 0 ? 'complete' : 'incomplete',
    units: verified,
    errors: incomplete,
  }
}

export function buildAuditLocalizationInput(
  sourceLocale: AtlasLocale,
  targetLocale: AtlasLocale,
  coverage: ReviewCoveragePortfolio,
  portfolios: AuditPortfolios,
): AuditLocalizationInput {
  if (sourceLocale === targetLocale) {
    throw new Error('audit localization target locale must differ from the source locale')
  }
  if (!coverage.report) {
    throw new Error('audit localization requires an available review coverage registry')
  }

  const byUnit = new Map<string, UnitAccumulator>()
  for (const unit of coverage.report.units) {
    const key = unitKey(unit.domain, unit.slug)
    if (byUnit.has(key)) {
      throw new Error(`duplicate canonical audit unit: ${unit.domain}/${unit.slug}`)
    }
    byUnit.set(key, {
      domain: unit.domain,
      slug: unit.slug,
      title: unit.title,
      findings: [],
    })
  }

  const ledgerUnits = new Set<string>()
  for (const unit of [...portfolios.security, ...portfolios.tests]) {
    const key = unitKey(unit.domain, unit.slug)
    if (ledgerUnits.has(key)) {
      throw new Error(`duplicate canonical audit unit: ${unit.domain}/${unit.slug}`)
    }
    ledgerUnits.add(key)
    const registered = byUnit.get(key)
    if (registered && registered.title !== unit.title) {
      throw new Error(
        `audit localization unit title disagrees with coverage registry: ${unit.domain}/${unit.slug}`,
      )
    }
    const findings = unit.domain === 'security'
      ? unit.findings.map(securitySourceFinding)
      : unit.findings.map(testSourceFinding)
    if (new Set(findings.map((finding) => finding.sourceDigest)).size !== findings.length) {
      throw new Error(`duplicate canonical findings: ${unit.domain}/${unit.slug}`)
    }
    byUnit.set(key, {
      domain: unit.domain,
      slug: unit.slug,
      title: unit.title,
      findings,
    })
  }

  const units = [...byUnit.values()]
    .sort((left, right) =>
      left.domain.localeCompare(right.domain) || left.slug.localeCompare(right.slug))
    .map((unit): AuditLocalizationSourceUnit => {
      const findingDigests = unit.findings.map((finding) => finding.sourceDigest)
      return {
        ...unit,
        sourceDigest: auditUnitSourceDigest(
          unit.domain,
          unit.slug,
          unit.title,
          findingDigests,
        ),
      }
    })

  return {
    formatVersion: 1,
    format: 'atlas-audit-localization-input-v1',
    sourceLocale,
    targetLocale,
    units,
  }
}

export interface ConfiguredAuditLocalizations {
  sourceLocale: AtlasLocale
  portfolios: Partial<Record<AtlasLocale, AuditLocalizationPortfolio>>
}

export function loadConfiguredAuditLocalizations(
  root: string,
  config: AtlasConfig,
  coverage: ReviewCoveragePortfolio,
  auditPortfolios: AuditPortfolios,
): ConfiguredAuditLocalizations {
  const sourceLocale = config.auditSourceLocale ?? 'en'
  const portfolios: Partial<Record<AtlasLocale, AuditLocalizationPortfolio>> = {}
  for (const locale of config.auditContentLocales ?? []) {
    try {
      const source = buildAuditLocalizationInput(
        sourceLocale,
        locale,
        coverage,
        auditPortfolios,
      )
      portfolios[locale] = loadAuditLocalization(root, locale, source)
    } catch (error) {
      portfolios[locale] = invalidLocalization(locale, [localizationDiagnostic(
        locale,
        'invalid-source',
        `canonical audit localization source is inconsistent: ${error instanceof Error ? error.message : String(error)}`,
      )])
    }
  }
  return { sourceLocale, portfolios }
}
