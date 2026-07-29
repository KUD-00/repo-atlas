import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  AUDIT_LIMITS,
  atomicWriteAuditFile,
  canonicalJson,
  normalizeAuditRepoPath,
  readBoundedAuditJson,
  resolveSafeAuditFile,
  stableAuditId,
  withAuditLock,
} from '../dist/audit-core.js'

function makeRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-audit-core-'))
}

function cleanup(root) {
  fs.rmSync(root, { recursive: true, force: true })
}

function write(root, repoPath, contents) {
  const file = path.join(root, ...repoPath.split('/'))
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, contents)
  return file
}

function initGit(root) {
  execFileSync('git', ['init', '-q', root])
}

function auditLockPath(root) {
  const gitDir = execFileSync(
    'git',
    ['-C', root, 'rev-parse', '--path-format=absolute', '--absolute-git-dir'],
    { encoding: 'utf8' },
  ).trim()
  return path.join(gitDir, 'repo-atlas', 'audit-state.lock')
}

test('normalizes repository-relative POSIX paths and rejects path aliases', () => {
  assert.equal(normalizeAuditRepoPath('src/a.ts'), 'src/a.ts')
  assert.equal(normalizeAuditRepoPath('.atlas/audits/security.json'), '.atlas/audits/security.json')

  for (const invalid of [
    '',
    '.',
    '..',
    '/absolute',
    'C:\\absolute',
    './src/a.ts',
    'src/./a.ts',
    'src/../outside',
    '../outside',
    'src//a.ts',
    'src/a.ts/',
    'src\\a.ts',
    'src/\0a.ts',
  ]) {
    assert.throws(
      () => normalizeAuditRepoPath(invalid),
      /normalized repository-relative POSIX path/,
      invalid,
    )
  }
})

test('reads only bounded, strict UTF-8 JSON from safe regular files', () => {
  const root = makeRoot()
  try {
    write(root, 'data/value.json', Buffer.from('{"ok":"✓"}\n', 'utf8'))
    assert.deepEqual(readBoundedAuditJson(root, 'data/value.json'), { ok: '✓' })
    assert.equal(
      resolveSafeAuditFile(root, 'data/value.json', { mustExist: true, regularFile: true }),
      path.join(root, 'data/value.json'),
    )

    assert.throws(
      () => readBoundedAuditJson(root, 'data/value.json', 4),
      /byte limit|too large|exceeds/i,
    )

    write(root, 'data/invalid-utf8.json', Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3, 0x28, 0x7d]))
    assert.throws(
      () => readBoundedAuditJson(root, 'data/invalid-utf8.json'),
      /UTF-8/i,
    )

    write(root, 'data/invalid-json.json', '{"unterminated":')
    assert.throws(
      () => readBoundedAuditJson(root, 'data/invalid-json.json'),
      /JSON/i,
    )

    assert.throws(
      () => readBoundedAuditJson(root, 'data/missing.json'),
      /safe|missing|regular/i,
    )
  } finally {
    cleanup(root)
  }
})

test('canonical JSON recursively sorts keys into compact digest bytes', () => {
  assert.equal(
    canonicalJson({ z: 1, a: { d: 2, b: 1 }, list: [{ y: true, x: null }, 3] }),
    '{"a":{"b":1,"d":2},"list":[{"x":null,"y":true},3],"z":1}',
  )
  assert.equal(canonicalJson(['z', { b: 2, a: 1 }]), '["z",{"a":1,"b":2}]')
  assert.equal(canonicalJson({ 2: 'two', 10: 'ten' }), '{"10":"ten","2":"two"}')
  assert.equal(canonicalJson('\0\n\t'), '"\\u0000\\n\\t"')
  assert.equal(canonicalJson({ a: 1 }).endsWith('\n'), false)
})

test('canonical JSON rejects unsupported, cyclic, non-finite, lone-surrogate, and over-limit values', () => {
  const cyclic = { ok: true }
  cyclic.self = cyclic
  const sparse = []
  sparse.length = 1

  for (const invalid of [
    undefined,
    1n,
    Symbol('audit'),
    () => true,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    { missing: undefined },
    [undefined],
    sparse,
    new Date('2026-07-29T00:00:00.000Z'),
    cyclic,
    '\ud800',
    { '\udfff': 'invalid key' },
    'x'.repeat(AUDIT_LIMITS.textCodeUnits + 1),
  ]) {
    assert.throws(() => canonicalJson(invalid), /canonical JSON|unsupported|cyclic|finite|surrogate|limit/i)
  }
})

test('stable audit IDs use approved prefixes and a domain-separated SHA-256 vector', () => {
  const domainTag = 'atlas-observation/v1'
  const parts = ['repo_fixture', 'security', 'unit', 'blob']
  const expectedDigest = createHash('sha256')
    .update(`${domainTag}\0${parts.join('\0')}`, 'utf8')
    .digest('hex')
    .slice(0, 24)

  assert.equal(stableAuditId('aobs', domainTag, parts), `aobs_${expectedDigest}`)
  assert.equal(stableAuditId('aobs', domainTag, parts).length, 29)
  assert.equal(
    stableAuditId('aobs', domainTag, parts),
    stableAuditId('aobs', domainTag, [...parts]),
  )
  for (const prefix of ['atf', 'atocc', 'adev', 'amig']) {
    assert.match(
      stableAuditId(prefix, `atlas-${prefix}/v1`, parts),
      new RegExp(`^${prefix}_[0-9a-f]{24}$`),
    )
  }

  assert.throws(() => stableAuditId('arepo', domainTag, parts), /prefix/i)
  assert.throws(() => stableAuditId('aobs', domainTag, ['ok', 1]), /parts|string/i)
  assert.throws(() => stableAuditId('aobs', 'bad\0domain', parts), /domain|NUL/i)
  assert.throws(() => stableAuditId('aobs', domainTag, ['bad\0part']), /parts|NUL/i)
})

test('safe reads and writes reject a symlinked audit directory without touching outside files', () => {
  const root = makeRoot()
  const outside = makeRoot()
  try {
    fs.mkdirSync(path.join(root, '.atlas'))
    fs.mkdirSync(path.join(outside, 'audits'))
    const canary = write(outside, 'audits/security.json', '{"outside":true}\n')
    fs.symlinkSync(path.join(outside, 'audits'), path.join(root, '.atlas/audits'), 'dir')

    assert.throws(
      () => resolveSafeAuditFile(root, '.atlas/audits/security.json', {
        mustExist: true,
        regularFile: true,
      }),
      /symlink|safe|outside/i,
    )
    assert.throws(
      () => readBoundedAuditJson(root, '.atlas/audits/security.json'),
      /symlink|safe|outside/i,
    )
    assert.throws(
      () => atomicWriteAuditFile(root, '.atlas/audits/security.json', '{"inside":true}\n'),
      /symlink|safe|outside/i,
    )
    assert.equal(fs.readFileSync(canary, 'utf8'), '{"outside":true}\n')
    assert.deepEqual(fs.readdirSync(path.join(outside, 'audits')), ['security.json'])
  } finally {
    cleanup(root)
    cleanup(outside)
  }
})

test('atomic writes create safe directories, replace files, and clean sibling temporary files', () => {
  const root = makeRoot()
  const outside = makeRoot()
  try {
    const repoPath = '.atlas/audits/security.json'
    atomicWriteAuditFile(root, repoPath, '{"version":1}\n')
    assert.equal(fs.readFileSync(path.join(root, repoPath), 'utf8'), '{"version":1}\n')

    atomicWriteAuditFile(root, repoPath, '{"version":2}\n')
    assert.equal(fs.readFileSync(path.join(root, repoPath), 'utf8'), '{"version":2}\n')
    assert.deepEqual(fs.readdirSync(path.join(root, '.atlas/audits')), ['security.json'])

    const canary = write(outside, 'canary.json', '{"outside":true}\n')
    fs.unlinkSync(path.join(root, repoPath))
    fs.symlinkSync(canary, path.join(root, repoPath))
    assert.throws(
      () => atomicWriteAuditFile(root, repoPath, '{"outside":false}\n'),
      /symlink|safe|regular/i,
    )
    assert.equal(fs.readFileSync(canary, 'utf8'), '{"outside":true}\n')
    assert.deepEqual(fs.readdirSync(path.join(root, '.atlas/audits')), ['security.json'])
  } finally {
    cleanup(root)
    cleanup(outside)
  }
})

test('the audit lock is exclusive, lives in Git administration, and releases in finally', () => {
  const root = makeRoot()
  try {
    initGit(root)
    const lock = auditLockPath(root)

    const result = withAuditLock(root, function primaryOperation() {
      assert.equal(fs.existsSync(lock), true)
      assert.equal(fs.existsSync(path.join(root, '.atlas/.audit.lock')), false)
      const before = fs.readFileSync(lock, 'utf8')
      const receipt = JSON.parse(before)
      assert.equal(receipt.pid, process.pid)
      assert.equal(receipt.operation, 'primaryOperation')
      assert.equal(typeof receipt.hostname, 'string')
      assert.match(receipt.startedAt, /^\d{4}-\d{2}-\d{2}T/)
      assert.match(receipt.processStartedAt, /^\d{4}-\d{2}-\d{2}T/)
      assert.equal(typeof receipt.sourceSnapshot, 'string')

      assert.throws(
        () => withAuditLock(root, () => 'second'),
        /audit.*lock|contended|already held|busy/i,
      )
      assert.equal(fs.readFileSync(lock, 'utf8'), before)
      return 'done'
    })

    assert.equal(result, 'done')
    assert.equal(fs.existsSync(lock), false)
    assert.throws(
      () => withAuditLock(root, function failingOperation() {
        throw new Error('operation failed')
      }),
      /operation failed/,
    )
    assert.equal(fs.existsSync(lock), false)
  } finally {
    cleanup(root)
  }
})

test('an existing audit lock is never stolen, including when its claimed owner is stale', () => {
  const root = makeRoot()
  try {
    initGit(root)
    const lock = auditLockPath(root)
    fs.mkdirSync(path.dirname(lock), { recursive: true })
    const stale = '{"pid":999999999,"hostname":"fixture.invalid","operation":"stale"}\n'
    fs.writeFileSync(lock, stale)

    assert.throws(
      () => withAuditLock(root, () => 'must not run'),
      /audit.*lock|contended|already held|busy/i,
    )
    assert.equal(fs.readFileSync(lock, 'utf8'), stale)
  } finally {
    cleanup(root)
  }
})
