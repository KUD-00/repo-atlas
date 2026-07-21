/**
 * Deterministic browser-acceptance coverage fixture repositories.
 *
 * Generates three self-contained Git repos under a base directory so root can
 * serve them and run headless browser acceptance:
 *   1. missing  — no coverage report + one current completed v2 Security unit
 *   2. incomplete — current incomplete coverage (security required=2/fresh=1/missing=1)
 *   3. complete — current complete coverage + Security dispositions + Tests unit
 *
 * Self-contained (qa is published): Node fs/crypto/child_process only, plus the
 * current dist/cli.js build. Never imports test/helpers.
 *
 * CLI: node qa/audit-coverage-fixtures.mjs [outputDir]
 *   - no arg → mkdtemp base
 *   - explicit nonexistent dir → create there
 *   - existing dir → refuse (never delete/overwrite)
 * Prints one JSON object to stdout.
 */

import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = path.resolve(HERE, '..')
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js')

const COVERAGE_REL = '.atlas/review-coverage.json'
const SELF_PATH = COVERAGE_REL
const GENERATED_PROOF = 'GENERATED-PROOF'
const HTML_REL = path.join('.atlas', 'atlas.html')

const POLICY = { format: 'fixture-policy-v1', hash: 'a'.repeat(64) }

function write(root, rel, contents) {
  const file = path.join(root, rel)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, contents)
}

function git(root, args, opts = {}) {
  return execFileSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    ...opts,
  }).trim()
}

function initRepo(root) {
  fs.mkdirSync(root, { recursive: true })
  git(root, ['init', '-q'])
  git(root, ['config', 'user.email', 'repo-atlas-fixture@example.invalid'])
  git(root, ['config', 'user.name', 'repo-atlas fixture'])
  write(root, '.atlas/config.json', JSON.stringify({ formatVersion: 1, exclude: [] }) + '\n')
  fs.mkdirSync(path.join(root, '.atlas', 'audits'), { recursive: true })
}

function commitAll(root, message) {
  git(root, ['add', '-A'])
  git(root, ['commit', '-qm', message])
}

function gitBlob(root, file) {
  return git(root, ['hash-object', '--', file])
}

function scopeHash(root, files) {
  const lines = files.map((file) => {
    const sha = gitBlob(root, file)
    return `${sha}  ${file}`
  }).sort()
  return createHash('sha1').update(lines.join('\n') + '\n').digest('hex')
}

function fileHashes(root, files) {
  const hashes = {}
  for (const file of files) hashes[file] = gitBlob(root, file)
  return hashes
}

function inventoryHashFor(entries) {
  const lines = entries.map((entry) => {
    const marker = entry.path === SELF_PATH ? GENERATED_PROOF : entry.blob
    return `${marker}  ${entry.path}`
  }).sort()
  return createHash('sha256').update(lines.join('\n') + '\n').digest('hex')
}

function summaryFrom(entries, invalidLedgerDetails = []) {
  let securityRequired = 0
  let securityFresh = 0
  let securityMissing = 0
  let securityStale = 0
  let securityInvalid = 0
  let testRequired = 0
  let testFresh = 0
  let testMissing = 0
  let testStale = 0
  let testInvalid = 0
  let dualRequired = 0
  let excluded = 0
  let unclassified = 0
  let conflicted = 0

  for (const entry of entries) {
    const kind = entry.classification.kind
    if (kind === 'excluded') {
      excluded += 1
      continue
    }
    if (kind === 'unclassified') {
      unclassified += 1
      continue
    }
    if (kind === 'conflict') {
      conflicted += 1
      continue
    }
    const domains = entry.classification.domains
    const hasSecurity = Boolean(domains.security)
    const hasTest = Boolean(domains.test)
    if (hasSecurity && hasTest) dualRequired += 1
    if (hasSecurity) {
      securityRequired += 1
      const status = entry.evidence.security?.status
      if (status === 'fresh') securityFresh += 1
      else if (status === 'missing') securityMissing += 1
      else if (status === 'stale') securityStale += 1
      else if (status === 'invalid') securityInvalid += 1
    }
    if (hasTest) {
      testRequired += 1
      const status = entry.evidence.test?.status
      if (status === 'fresh') testFresh += 1
      else if (status === 'missing') testMissing += 1
      else if (status === 'stale') testStale += 1
      else if (status === 'invalid') testInvalid += 1
    }
  }

  return {
    tracked: entries.length,
    securityRequired,
    securityFresh,
    securityMissing,
    securityStale,
    securityInvalid,
    testRequired,
    testFresh,
    testMissing,
    testStale,
    testInvalid,
    dualRequired,
    excluded,
    unclassified,
    conflicted,
    invalidLedgers: invalidLedgerDetails.length,
  }
}

function excludedEntry(root, repoPath, ruleId, category, reason) {
  return {
    path: repoPath,
    blob: gitBlob(root, repoPath),
    ruleIds: [ruleId],
    classification: {
      kind: 'excluded',
      ruleId,
      category,
      reason,
    },
    evidence: {},
  }
}

function selfEntry() {
  return {
    path: SELF_PATH,
    ruleIds: ['generated-proof'],
    classification: {
      kind: 'excluded',
      ruleId: 'generated-proof',
      category: 'generated-proof',
      reason: 'canonical report validates its own bytes',
    },
    evidence: {},
  }
}

function reviewEntry(root, repoPath, domains, evidence) {
  return {
    path: repoPath,
    blob: gitBlob(root, repoPath),
    ruleIds: ['source'],
    classification: {
      kind: 'review',
      domains,
    },
    evidence,
  }
}

function writeV2(root, { domain, slug, title, files, findings, evidenceRefs = [] }) {
  const value = {
    formatVersion: 2,
    format: 'atlas-audit-v2',
    domain,
    reviewState: 'complete',
    slug,
    title,
    ruleset: `fixture-${domain}-v1`,
    scanned_at: '2026-07-21',
    scope_hash: scopeHash(root, files),
    file_count: files.length,
    files,
    hashes: fileHashes(root, files),
    findings,
    dropped: [],
    rounds: [],
  }
  if (evidenceRefs.length) value.evidenceRefs = evidenceRefs
  write(root, `.atlas/audits/${slug}.json`, JSON.stringify(value, null, 2) + '\n')
  return value
}

function writeCoverage(root, { verdict, units, reviewEntries, excludedPaths }) {
  const entries = [
    ...reviewEntries,
    selfEntry(),
    excludedEntry(root, '.atlas/config.json', 'fixture-config', 'fixture', 'fixture configuration is outside browser acceptance inventory'),
    ...excludedPaths.map((repoPath) =>
      excludedEntry(root, repoPath, 'generated-ledger', 'generated', 'strict fixture builder output'),
    ),
  ]

  // Stable ordering for human diffs; inventoryHash sorts independently.
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))

  const report = {
    formatVersion: 1,
    format: 'atlas-review-coverage-v1',
    verdict,
    policy: POLICY,
    inventoryHash: inventoryHashFor(entries),
    units,
    summary: summaryFrom(entries),
    entries,
    invalidLedgerDetails: [],
    reportErrors: [],
  }
  write(root, COVERAGE_REL, JSON.stringify(report, null, 2) + '\n')
  git(root, ['add', '--', COVERAGE_REL])
  return report
}

function buildHtml(root) {
  if (!fs.existsSync(CLI)) {
    throw new Error(`repo-atlas CLI missing at ${CLI}; run pnpm build:cli first`)
  }
  const result = spawnSync(process.execPath, [CLI, 'build', '-o', HTML_REL], {
    cwd: root,
    encoding: 'utf8',
  })
  if (result.status !== 0) {
    throw new Error(
      `repo-atlas build failed in ${root}:\n${result.stderr || result.stdout || 'no output'}`,
    )
  }
  const html = path.join(root, HTML_REL)
  if (!fs.existsSync(html)) {
    throw new Error(`build did not produce ${html}`)
  }
  return html
}

function securityFinding({ id, disposition, severity = 'medium', file, title }) {
  return {
    id,
    severity,
    category: 'boundary',
    title,
    locations: [`${file}:1`],
    dataflow: 'untrusted input reaches a privileged sink',
    fix: 'validate and authorize at the boundary',
    disposition,
  }
}

function testFinding({ impact = 'blocking', file, title }) {
  return {
    impact,
    category: 'missing-invariant',
    title,
    invariant: 'handler rejects unauthenticated callers',
    evidence: 'suite mocks auth away without asserting the gate',
    fix: 'assert the real authentication gate on the path',
    locations: [`${file}:1`],
  }
}

/** Fixture 1: missing coverage report + one current completed v2 Security unit. */
function createMissingFixture(root) {
  initRepo(root)
  write(root, 'src/app.ts', 'export function handle(req: string): string {\n  return req\n}\n')
  commitAll(root, 'source')

  writeV2(root, {
    domain: 'security',
    slug: 'security-main',
    title: 'Security Main',
    files: ['src/app.ts'],
    findings: [
      securityFinding({
        id: 'SEC-OPEN-1',
        disposition: 'open',
        severity: 'high',
        file: 'src/app.ts',
        title: 'input reaches response without validation',
      }),
    ],
  })
  commitAll(root, 'security ledger')

  const html = buildHtml(root)
  return { root, html }
}

/**
 * Fixture 2: current incomplete coverage with one fresh and one missing
 * required Security path (required=2 / fresh=1 / missing=1).
 */
function createIncompleteFixture(root) {
  initRepo(root)
  write(root, 'src/covered.ts', 'export const covered = 1\n')
  write(root, 'src/gap.ts', 'export const gap = 1\n')
  commitAll(root, 'source')

  writeV2(root, {
    domain: 'security',
    slug: 'security-src',
    title: 'Security Source',
    files: ['src/covered.ts'],
    findings: [
      securityFinding({
        id: 'SEC-FRESH-1',
        disposition: 'open',
        severity: 'medium',
        file: 'src/covered.ts',
        title: 'covered path finding',
      }),
    ],
  })
  commitAll(root, 'security ledger')

  writeCoverage(root, {
    verdict: 'incomplete',
    units: [{ domain: 'security', slug: 'security-src', title: 'Security Source' }],
    reviewEntries: [
      reviewEntry(
        root,
        'src/covered.ts',
        { security: { unit: 'security-src' } },
        { security: { status: 'fresh', ledgers: ['security-src'] } },
      ),
      reviewEntry(
        root,
        'src/gap.ts',
        { security: { unit: 'security-src' } },
        { security: { status: 'missing', ledgers: [] } },
      ),
    ],
    excludedPaths: ['.atlas/audits/security-src.json'],
  })
  commitAll(root, 'incomplete coverage report')

  const html = buildHtml(root)
  return { root, html }
}

/**
 * Fixture 3: current complete coverage + open / accepted-risk / separate-design
 * Security findings + independent Tests unit with test-only vocabulary and
 * exact v2 evidenceRefs.
 */
function createCompleteFixture(root) {
  initRepo(root)
  write(root, 'src/secure.ts', 'export function authorize(user: string): boolean {\n  return user === "admin"\n}\n')
  write(root, 'src/service.ts', 'export function run(): number {\n  return 42\n}\n')
  write(root, 'audits/evidence/security.json', JSON.stringify({ kind: 'security-evidence', ref: 'SEC' }) + '\n')
  write(root, 'audits/evidence/tests.json', JSON.stringify({ kind: 'test-evidence', ref: 'TEST' }) + '\n')
  commitAll(root, 'source and evidence')

  const securityEvidence = ['audits/evidence/security.json']
  const testEvidence = ['audits/evidence/tests.json']

  writeV2(root, {
    domain: 'security',
    slug: 'security-complete',
    title: 'Security Complete',
    files: ['src/secure.ts'],
    evidenceRefs: securityEvidence,
    findings: [
      securityFinding({
        id: 'SEC-OPEN',
        disposition: 'open',
        severity: 'high',
        file: 'src/secure.ts',
        title: 'authorization bypass is open',
      }),
      securityFinding({
        id: 'SEC-ACCEPTED',
        disposition: 'accepted-risk',
        severity: 'medium',
        file: 'src/secure.ts',
        title: 'admin string compare accepted risk',
      }),
      securityFinding({
        id: 'SEC-SEPARATE',
        disposition: 'separate-design',
        severity: 'low',
        file: 'src/secure.ts',
        title: 'token rotation tracked as separate design',
      }),
    ],
  })

  writeV2(root, {
    domain: 'test',
    slug: 'test-complete',
    title: 'Tests Complete',
    files: ['src/service.ts'],
    evidenceRefs: testEvidence,
    findings: [
      testFinding({
        impact: 'blocking',
        file: 'src/service.ts',
        title: 'service lacks invariant coverage',
      }),
    ],
  })
  commitAll(root, 'security and test ledgers')

  writeCoverage(root, {
    verdict: 'complete',
    units: [
      { domain: 'security', slug: 'security-complete', title: 'Security Complete' },
      { domain: 'test', slug: 'test-complete', title: 'Tests Complete' },
    ],
    reviewEntries: [
      reviewEntry(
        root,
        'src/secure.ts',
        { security: { unit: 'security-complete' } },
        { security: { status: 'fresh', ledgers: ['security-complete'] } },
      ),
      reviewEntry(
        root,
        'src/service.ts',
        { test: { unit: 'test-complete' } },
        { test: { status: 'fresh', ledgers: ['test-complete'] } },
      ),
    ],
    excludedPaths: [
      '.atlas/audits/security-complete.json',
      '.atlas/audits/test-complete.json',
      'audits/evidence/security.json',
      'audits/evidence/tests.json',
    ],
  })
  commitAll(root, 'complete coverage report')

  const html = buildHtml(root)
  return { root, html }
}

/**
 * Create the three coverage fixture repositories under baseDir.
 *
 * @param {string} [baseDir] optional absolute/relative output directory.
 *   - omitted → mkdtemp under os.tmpdir()
 *   - provided and nonexistent → created
 *   - provided and existing → throws (never overwrite/delete)
 * @returns {{
 *   baseDir: string,
 *   missing: { root: string, html: string },
 *   incomplete: { root: string, html: string },
 *   complete: { root: string, html: string },
 * }}
 */
export function createAuditCoverageFixtures(baseDir) {
  let base
  if (baseDir === undefined || baseDir === null || baseDir === '') {
    base = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-coverage-fixtures-'))
  } else {
    base = path.resolve(baseDir)
    if (fs.existsSync(base)) {
      throw new Error(
        `refusing to overwrite existing directory: ${base}`,
      )
    }
    fs.mkdirSync(base, { recursive: true })
  }

  const missing = createMissingFixture(path.join(base, 'missing'))
  const incomplete = createIncompleteFixture(path.join(base, 'incomplete'))
  const complete = createCompleteFixture(path.join(base, 'complete'))

  return {
    baseDir: base,
    missing,
    incomplete,
    complete,
  }
}

function isMain() {
  const entry = process.argv[1]
  if (!entry) return false
  try {
    return fileURLToPath(import.meta.url) === path.resolve(entry)
  } catch {
    return false
  }
}

function main() {
  const arg = process.argv[2]
  try {
    const fixtures = createAuditCoverageFixtures(arg)
    process.stdout.write(JSON.stringify(fixtures, null, 2) + '\n')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(message + '\n')
    process.exitCode = 1
  }
}

if (isMain()) main()
