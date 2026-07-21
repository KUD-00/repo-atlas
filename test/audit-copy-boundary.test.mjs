/**
 * Source-boundary + catalog-completeness gate for audit assurance i18n.
 *
 * Model-owned English labels (coverage statements, suffix text, coverage/risk
 * labels, action labels, outcome/acceptance labels, file status labels) must
 * never be rendered directly by viewer consumers. Localization goes through
 * compile-time Lingui msgids in viewer/audit-copy.ts only — never by feeding
 * a model English string into a dynamic i18n lookup.
 */
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const CONSUMERS = [
  'viewer/AuditCoverage.tsx',
  'viewer/AuditNav.tsx',
  'viewer/Security.tsx',
  'viewer/TestAudit.tsx',
  'viewer/App.tsx',
]
const LOCALES = ['en', 'zh', 'ja', 'ko']
const EMPTY_AUDIT_COPY = 'No completed audit evidence'
const FORBIDDEN_EMPTY_COPY = 'No completed audits yet'

/**
 * Explicit assurance msgids owned by the semantic copy module.
 * English msgstr may equal msgid; zh/ja/ko must be translated (non-empty and
 * not identical to the English msgid for non-technical free-form phrases).
 */
/** Exact msgids produced by viewer/audit-copy.ts compile-time `t` macros. */
const ASSURANCE_MSGIDS = [
  // Coverage statements
  'Coverage unknown because no review coverage report exists',
  'Coverage invalid — diagnostics present; no trusted coverage numerator',
  'Coverage stale — recorded evidence is visible but not current',
  'Coverage incomplete — required reviews are missing',
  'Coverage incomplete — 1 required review is missing',
  'Coverage incomplete — {missingCount} required reviews are missing',
  'Coverage complete and current',
  // Coverage labels
  'invalid coverage',
  '{0} invalid evidence',
  'coverage unknown',
  '{0} missing',
  '{0} stale',
  '{0} invalid',
  '{n} coverage gaps',
  '{0}/{1} fresh',
  // Risk labels
  '1 open ({highest})',
  '{0} open (highest {highest})',
  '1 accepted risk',
  '{0} accepted risk',
  '1 separate design',
  '{0} separate design',
  'No open findings recorded',
  // File / evidence / outcome labels
  'fresh evidence',
  'missing evidence',
  'stale evidence',
  'invalid evidence',
  'unclassified path',
  'policy conflict',
  'No completed audit evidence',
  'Accepted by current coverage report',
  'Not accepted by current coverage report',
  'Stale audit evidence — re-audit needed',
  'Coverage has not been established',
  'Coverage invalid for this unit',
  'Coverage incomplete for this unit',
  '{0} open findings (highest {1})',
  '{0} open findings',
  'No actionable findings in current completed review',
  'Recorded audit evidence',
  // Primary suffix / ARIA states
  'unknown',
  '{n} gaps',
  '{0} open',
  'covered',
  'Security',
  'Tests',
  '{name} coverage unknown or unavailable',
  '{name} {n} coverage gaps',
  '{name} {0} open findings',
  '{name} coverage complete',
  // Action format: orphan path/status; assigned unit title + path + status; findings
  '{0}: {status}',
  '{unitTitle}: {0} {status}',
  '{0}: {1}',
]

/**
 * Technical names that intentionally stay English, plus punctuation-only action
 * formats where Japanese/Korean naturally equal English. Unknown/covered/fresh/
 * open/gaps/evidence/outcome phrases must not be allowed to regress to English.
 */
const ALLOW_ENGLISH_FALLBACK = new Set([
  'Security',
  'Tests',
  '{0}: {1}',
  '{0}: {status}',
  '{unitTitle}: {0} {status}',
])

/** Obsolete assurance phrases that must not remain in active or obsolete catalogs. */
const FORBIDDEN_ASSURANCE_PHRASES = ['clean', 'no findings', 'no findings — clean']

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), 'utf8')
}

function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
}

/**
 * Parse active (non-obsolete) PO entries.
 * @returns {Map<string, string>}
 */
function parsePoEntries(poText) {
  /** @type {Map<string, string>} */
  const map = new Map()
  const blocks = poText.split(/\n\n+/)
  for (const block of blocks) {
    if (/^#~\s/m.test(block)) continue // obsolete
    const msgidParts = []
    const msgstrParts = []
    let mode = null
    for (const line of block.split('\n')) {
      if (line.startsWith('msgid ')) {
        mode = 'id'
        msgidParts.length = 0
        msgstrParts.length = 0
        msgidParts.push(line.slice('msgid '.length))
      } else if (line.startsWith('msgstr ')) {
        mode = 'str'
        msgstrParts.push(line.slice('msgstr '.length))
      } else if (line.startsWith('"') && mode === 'id') {
        msgidParts.push(line)
      } else if (line.startsWith('"') && mode === 'str') {
        msgstrParts.push(line)
      }
    }
    if (msgidParts.length === 0) continue
    const unquote = (parts) =>
      parts
        .map((p) => {
          try {
            return JSON.parse(p)
          } catch {
            return p.replace(/^"|"$/g, '').replace(/\\n/g, '\n').replace(/\\"/g, '"')
          }
        })
        .join('')
    const id = unquote(msgidParts)
    const str = unquote(msgstrParts)
    if (id) map.set(id, str)
  }
  return map
}

/**
 * Collect msgid text from both active and obsolete (#~) entries.
 * @returns {string[]}
 */
function parseAllPoMsgids(poText) {
  /** @type {string[]} */
  const ids = []
  const blocks = poText.split(/\n\n+/)
  for (const block of blocks) {
    const msgidParts = []
    let mode = null
    for (const line of block.split('\n')) {
      const active = line.startsWith('msgid ')
      const obsolete = line.startsWith('#~ msgid ')
      if (active || obsolete) {
        mode = 'id'
        msgidParts.length = 0
        msgidParts.push(line.replace(/^#~\s*/, '').slice('msgid '.length))
      } else if (line.startsWith('msgstr ') || line.startsWith('#~ msgstr ')) {
        mode = 'str'
      } else if ((line.startsWith('"') || line.startsWith('#~ "')) && mode === 'id') {
        msgidParts.push(line.replace(/^#~\s*/, ''))
      }
    }
    if (msgidParts.length === 0) continue
    const unquote = (parts) =>
      parts
        .map((p) => {
          try {
            return JSON.parse(p)
          } catch {
            return p.replace(/^"|"$/g, '').replace(/\\n/g, '\n').replace(/\\"/g, '"')
          }
        })
        .join('')
    const id = unquote(msgidParts)
    if (id) ids.push(id)
  }
  return ids
}

describe('audit copy source boundary', () => {
  test('consumers never render model-owned English assurance fields', () => {
    /** @type {string[]} */
    const violations = []

    for (const rel of CONSUMERS) {
      const raw = read(rel)
      const src = stripComments(raw)
      const tag = (msg) => `${rel}: ${msg}`

      // Coverage statement: never call model English coverageStatementText
      if (/\bcoverageStatementText\b/.test(src)) {
        violations.push(tag('imports or calls coverageStatementText'))
      }

      // Forbid raw model domainNavSuffix import/call — not localizedDomainNavSuffix.
      // Strip localized name first so residual domainNavSuffix is a hard fail.
      const withoutLocalizedSuffix = src.replace(/\blocalizedDomainNavSuffix\b/g, '')
      if (/\bdomainNavSuffix\b/.test(withoutLocalizedSuffix)) {
        violations.push(tag('imports or calls raw domainNavSuffix (model English suffix)'))
      }

      // Sidebar coverage/risk labels
      if (/\.coverageLabel\b/.test(src)) {
        violations.push(tag('renders coverageLabel'))
      }
      if (/\.riskLabel\b/.test(src)) {
        violations.push(tag('renders riskLabel'))
      }

      // Unit portfolio coverage/risk .label
      if (/\.coverage\.label\b/.test(src)) {
        violations.push(tag('renders coverage.label'))
      }
      if (/\.risk\.label\b/.test(src)) {
        violations.push(tag('renders risk.label'))
      }

      // Action queue English
      if (/\baction\.label\b/.test(src)) {
        violations.push(tag('renders action.label'))
      }

      // Outcome labels
      if (/\.outcomeLabel\b/.test(src)) {
        violations.push(tag('renders outcomeLabel'))
      }

      // File row status label
      if (/\brow\.label\b/.test(src)) {
        violations.push(tag('renders AuditFileRow row.label'))
      }

      // Evidence acceptance label
      if (/\.acceptanceLabel\b/.test(src)) {
        violations.push(tag('renders acceptanceLabel'))
      }

      // strongZeroFindingPhrase must be boolean gate only — never raw string children
      if (/\bstrongZeroFindingPhrase\b/.test(src) && /\{\s*strong\s*\}/.test(src)) {
        violations.push(
          tag('renders strongZeroFindingPhrase return string ({strong}) instead of compile-time message'),
        )
      }

      // No dynamic msgid lookup of model English fields
      if (/\bi18n\._\s*\(/.test(src) || /\bi18n\.t\s*\(/.test(src)) {
        violations.push(tag('uses dynamic i18n lookup (i18n._ / i18n.t)'))
      }
    }

    assert.equal(
      violations.length,
      0,
      `model-owned English fields still rendered by consumers:\n  - ${violations.join('\n  - ')}`,
    )
  })

  test('action labels preserve assigned unit title without action.label', () => {
    const copy = read('viewer/audit-copy.ts')
    // Optional unitTitle (or equally typed input) on the localized action helper.
    assert.match(
      copy,
      /export function localizedActionLabel\s*\([\s\S]*?\bunitTitle\b/,
      'localizedActionLabel must accept optional unitTitle (or equally typed input)',
    )
    // Assigned coverage: unit title + path + status (not action.label, not path alone).
    assert.match(
      copy,
      /\$\{unitTitle\}:\s*\$\{(?:action\.)?path\}\s+\$\{status\}|\$\{unitTitle\}.*\$\{(?:action\.)?path\}.*\$\{status\}/,
      'assigned coverage actions must format unit title + path + status',
    )
    // Orphan coverage keeps path: status
    assert.match(
      copy,
      /\$\{(?:action\.)?path\}:\s*\$\{status\}/,
      'orphan coverage actions must format path: status',
    )

    for (const rel of ['viewer/Security.tsx', 'viewer/TestAudit.tsx']) {
      const src = stripComments(read(rel))
      // One slug→title map built from the model (not per-action unitRows.find).
      assert.match(
        src,
        /(?:unitTitleBySlug|titleBySlug|slugToTitle|unitTitles)\b/,
        `${rel}: ActionQueue must build one slug-to-title map`,
      )
      assert.match(
        src,
        /new Map[\s\S]{0,200}(?:unitRows|\.slug|\.title)/,
        `${rel}: slug-to-title map must come from model unit rows`,
      )
      // Pass title into localizedActionLabel (second/third arg or options).
      assert.match(
        src,
        /localizedActionLabel\s*\(\s*i18n\s*,\s*action\s*,/,
        `${rel}: must pass unit title into localizedActionLabel`,
      )
      assert.doesNotMatch(src, /\baction\.label\b/, `${rel}: must not render action.label`)
    }
  })

  test('zero-unit empty copy is exactly the approved evidence phrase', () => {
    const nav = read('viewer/AuditNav.tsx')
    assert.match(
      nav,
      new RegExp(EMPTY_AUDIT_COPY.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      `AuditNav zero-unit copy must be exactly ${JSON.stringify(EMPTY_AUDIT_COPY)}`,
    )
    assert.doesNotMatch(
      nav,
      new RegExp(FORBIDDEN_EMPTY_COPY.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      `AuditNav must not use ${JSON.stringify(FORBIDDEN_EMPTY_COPY)}`,
    )

    const readme = read('README.md')
    assert.match(
      readme,
      new RegExp(EMPTY_AUDIT_COPY.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      `README empty portfolio phrase must be ${JSON.stringify(EMPTY_AUDIT_COPY)}`,
    )
    assert.doesNotMatch(
      readme,
      new RegExp(FORBIDDEN_EMPTY_COPY.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      `README must not use ${JSON.stringify(FORBIDDEN_EMPTY_COPY)}`,
    )

    // AuditNav must build one unit map before rendering (not find per row).
    const navSrc = stripComments(nav)
    assert.doesNotMatch(
      navSrc,
      /unitRows\.map\([\s\S]*?model\.unitRows\.find\b/,
      'AuditNav must not call model.unitRows.find per rendered row',
    )
    assert.match(
      navSrc,
      /new Map[\s\S]{0,240}(?:unitRows|\.slug)/,
      'AuditNav must build one slug→unit map before rendering unit rows',
    )
    assert.doesNotMatch(
      navSrc,
      /\{\s*row\.suffix\s*\}/,
      'AuditNav must not render the model-owned English unknown suffix directly',
    )
    assert.match(
      navSrc,
      /localizedSidebarSuffix\s*\(/,
      'AuditNav mode suffixes must pass through the shared localized copy boundary',
    )
  })

  test('App no-action header uses localized Security suffix plus security label', () => {
    const app = stripComments(read('viewer/App.tsx'))
    // Renamed variables make localized nature explicit.
    assert.match(
      app,
      /\blocalizedSecuritySuffix\b/,
      'App must name the security suffix variable as localizedSecuritySuffix',
    )
    assert.match(
      app,
      /\blocalizedTestSuffix\b/,
      'App must name the test suffix variable as localizedTestSuffix',
    )
    // No-action fallback must include localized suffix text, not security alone.
    assert.match(
      app,
      /localizedSecuritySuffix\.text/,
      'App header/body must use localizedSecuritySuffix.text (allowed localized suffix text)',
    )
    // Header no-action branch should compose security label with suffix.
    const headerShortcut = app.match(
      /headerDomainAction[\s\S]{0,800}?localizedSecuritySuffix\.text/,
    )
    assert.ok(
      headerShortcut,
      'no-action header fallback must compose with localizedSecuritySuffix.text',
    )
  })

  test('all audit coverage numerators cross one trusted-count boundary', () => {
    const sharedRel = 'viewer/AuditCoverageFacts.tsx'
    assert.ok(
      fs.existsSync(path.join(ROOT, sharedRel)),
      `${sharedRel} must own the shared trusted-count rendering boundary`,
    )
    const shared = stripComments(read(sharedRel))
    assert.match(
      shared,
      /coverageCountsAvailable\s*\(\s*model\s*\)/,
      'shared coverage facts must gate every numeric numerator/denominator on coverageCountsAvailable(model)',
    )
    assert.match(
      shared,
      /Coverage counts unavailable/,
      'the untrusted branch must render the approved non-numeric unavailable copy',
    )

    for (const rel of ['viewer/Security.tsx', 'viewer/TestAudit.tsx']) {
      const src = stripComments(read(rel))
      assert.match(
        src,
        /AuditUnitCoverageFacts/,
        `${rel}: unit coverage must use the shared trusted-count component`,
      )
      assert.match(
        src,
        /AuditGapCoverageFacts/,
        `${rel}: gap coverage must use the shared trusted-count component`,
      )
      assert.doesNotMatch(
        src,
        /unitRow\.coverage\.(?:fresh|required)/,
        `${rel}: must not render unit numerator/denominator directly`,
      )
      assert.doesNotMatch(
        src,
        /gaps\.(?:numerator|denominator|missing)/,
        `${rel}: must not render gap counts outside the shared trust boundary`,
      )
    }
  })

  test('assurance msgids exist in all catalogs with nonempty msgstr', () => {
    /** @type {string[]} */
    const missing = []

    for (const locale of LOCALES) {
      const poPath = path.join(ROOT, 'viewer/locales', locale, 'messages.po')
      assert.ok(fs.existsSync(poPath), `missing catalog ${poPath}`)
      const entries = parsePoEntries(fs.readFileSync(poPath, 'utf8'))

      for (const msgid of ASSURANCE_MSGIDS) {
        if (!entries.has(msgid)) {
          missing.push(`${locale}: missing msgid ${JSON.stringify(msgid)}`)
          continue
        }
        const msgstr = entries.get(msgid) ?? ''
        if (!msgstr.trim()) {
          missing.push(`${locale}: empty msgstr for ${JSON.stringify(msgid)}`)
          continue
        }
        if (locale !== 'en' && !ALLOW_ENGLISH_FALLBACK.has(msgid) && msgstr === msgid) {
          missing.push(
            `${locale}: untranslated English fallback for ${JSON.stringify(msgid)}`,
          )
        }
      }
    }

    assert.equal(
      missing.length,
      0,
      `assurance catalog incomplete:\n  - ${missing.join('\n  - ')}`,
    )
  })

  test('catalogs and sources have no obsolete audit-assurance clean phrases', () => {
    /** @type {string[]} */
    const hits = []

    for (const locale of LOCALES) {
      const poPath = path.join(ROOT, 'viewer/locales', locale, 'messages.po')
      const ids = parseAllPoMsgids(fs.readFileSync(poPath, 'utf8'))
      for (const id of ids) {
        if (FORBIDDEN_ASSURANCE_PHRASES.includes(id)) {
          hits.push(`${locale}: forbidden msgid ${JSON.stringify(id)}`)
        }
      }
    }

    const sourceFiles = [
      'README.md',
      'viewer/audit-copy.ts',
      'viewer/AuditCoverage.tsx',
      'viewer/AuditNav.tsx',
      'viewer/Security.tsx',
      'viewer/TestAudit.tsx',
      'viewer/App.tsx',
    ]
    for (const rel of sourceFiles) {
      const src = read(rel)
      // Exact obsolete assurance slogans — not "no findings match the current filter".
      if (/\bno findings — clean\b/.test(src) || /(?<![\w-])\bclean\b(?![\w-])/.test(src) && /no findings/.test(src)) {
        // Only flag exact phrases or clean used as assurance zero-finding claim.
      }
      if (/\bno findings — clean\b/.test(src)) {
        hits.push(`${rel}: contains "no findings — clean"`)
      }
      // Bare msgid-style assurance "clean" as zero-findings claim in audit sources/README.
      if (rel === 'README.md' || rel.startsWith('viewer/')) {
        if (/\b0\s*=\s*clean\b|\bno findings\b.*\bclean\b|\bclean\b.*\bno findings\b/.test(src)) {
          hits.push(`${rel}: clean/no-findings assurance phrase`)
        }
      }
    }

    assert.equal(
      hits.length,
      0,
      `obsolete clean/no-findings assurance phrases remain:\n  - ${hits.join('\n  - ')}`,
    )
  })
})
