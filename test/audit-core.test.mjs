import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import * as auditCore from '../dist/audit-core.js'
import {
  AUDIT_LIMITS,
  atomicWriteAuditFile,
  canonicalJson,
  normalizeAuditRepoPath,
  readBoundedAuditJson,
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

function commitFixture(root, message = 'fixture') {
  execFileSync('git', ['-C', root, 'add', '.'])
  execFileSync(
    'git',
    [
      '-C',
      root,
      '-c',
      'user.name=Audit Fixture',
      '-c',
      'user.email=audit@example.invalid',
      'commit',
      '-qm',
      message,
    ],
  )
}

function gitObjectReceipt(root, revision) {
  const algorithm = execFileSync(
    'git',
    ['-C', root, 'rev-parse', '--show-object-format'],
    { encoding: 'utf8' },
  ).trim()
  const objectId = execFileSync(
    'git',
    ['-C', root, 'rev-parse', revision],
    { encoding: 'utf8' },
  ).trim()
  return `git-${algorithm}:${objectId}`
}

function auditLockPath(root) {
  const gitDir = execFileSync(
    'git',
    ['-C', root, 'rev-parse', '--path-format=absolute', '--absolute-git-dir'],
    { encoding: 'utf8' },
  ).trim()
  return path.join(gitDir, 'repo-atlas', 'audit-state.lock')
}

function flattenedErrorMessages(error) {
  if (error instanceof AggregateError) {
    return error.errors.flatMap((nested) => flattenedErrorMessages(nested))
  }
  return [error instanceof Error ? error.message : String(error)]
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

test('does not export a bare-path safety primitive', () => {
  assert.equal(Object.hasOwn(auditCore, 'resolveSafeAuditFile'), false)
})

test('reads only bounded, strict UTF-8 JSON from safe regular files', () => {
  const root = makeRoot()
  try {
    write(root, 'data/value.json', Buffer.from('{"ok":"✓"}\n', 'utf8'))
    assert.deepEqual(readBoundedAuditJson(root, 'data/value.json'), { ok: '✓' })

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

test('bounded readers open FIFOs nonblocking before rejecting them', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  let observedFlags = null
  try {
    const fifo = path.join(root, 'data/value.json')
    fs.mkdirSync(path.dirname(fifo), { recursive: true })
    execFileSync('mkfifo', [fifo])
    fs.openSync = function observingFifoOpen(file, flags, ...rest) {
      if (String(file).endsWith('/value.json')) {
        observedFlags = flags
        if ((flags & (fs.constants.O_NONBLOCK ?? 0)) === 0) {
          throw new Error('reader would block without O_NONBLOCK')
        }
      }
      return originalOpen.call(fs, file, flags, ...rest)
    }

    assert.throws(
      () => auditCore.readBoundedAuditBytes(root, 'data/value.json'),
      /safe regular file/i,
    )
    assert.notEqual(observedFlags, null)
    assert.notEqual(observedFlags & (fs.constants.O_NONBLOCK ?? 0), 0)
    assert.notEqual(observedFlags & (fs.constants.O_NOFOLLOW ?? 0), 0)
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
  }
})

test('reads exact bounded binary bytes for upstream SHA-256 seals', () => {
  const root = makeRoot()
  try {
    const source = Buffer.from([0x00, 0xff, 0x80, 0x41, 0x00, 0xc3, 0x28])
    write(root, 'data/artifact.bin', source)
    const bytes = auditCore.readBoundedAuditBytes(root, 'data/artifact.bin')
    assert.ok(bytes instanceof Uint8Array)
    assert.deepEqual(Buffer.from(bytes), source)
    assert.equal(
      createHash('sha256').update(bytes).digest('hex'),
      createHash('sha256').update(source).digest('hex'),
    )
    assert.throws(
      () => auditCore.readBoundedAuditBytes(root, 'data/artifact.bin', source.length - 1),
      /byte limit|too large|exceeds/i,
    )
  } finally {
    cleanup(root)
  }
})

test('reads JSON bytes and value from one descriptor snapshot', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  const originalRead = fs.readSync
  const originalClose = fs.closeSync
  const openedTargetFds = new Set()
  const readTargetFds = new Set()
  let targetOpenCount = 0
  let targetReadCount = 0
  let replacedAfterClose = false
  try {
    const source = Buffer.from('{"kind":"original","n":1}\n')
    const replacement = Buffer.from('{"kind":"replacement","n":2}\n')
    const file = write(root, 'data/document.json', source)

    fs.openSync = function trackingDocumentOpen(openedPath, flags, ...rest) {
      const fd = originalOpen.call(fs, openedPath, flags, ...rest)
      const isReadOnly = typeof flags === 'number' &&
        (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) === 0
      if (isReadOnly && String(openedPath).endsWith('/document.json')) {
        targetOpenCount += 1
        openedTargetFds.add(fd)
      }
      return fd
    }
    fs.readSync = function trackingDocumentRead(fd, ...rest) {
      if (openedTargetFds.has(fd)) {
        targetReadCount += 1
        readTargetFds.add(fd)
      }
      return originalRead.call(fs, fd, ...rest)
    }
    fs.closeSync = function replacingDocumentClose(fd) {
      const isTarget = openedTargetFds.has(fd)
      const result = originalClose.call(fs, fd)
      if (isTarget && !replacedAfterClose) {
        replacedAfterClose = true
        fs.writeFileSync(file, replacement)
      }
      return result
    }

    const document = auditCore.readBoundedAuditJsonDocument(
      root,
      'data/document.json',
    )
    assert.deepEqual(Buffer.from(document.bytes), source)
    assert.equal(
      createHash('sha256').update(document.bytes).digest('hex'),
      createHash('sha256').update(source).digest('hex'),
    )
    assert.deepEqual(document.value, { kind: 'original', n: 1 })
    assert.equal(targetOpenCount, 1)
    assert.ok(targetReadCount >= 1)
    assert.equal(readTargetFds.size, 1)
    assert.equal(fs.readFileSync(file, 'utf8'), replacement.toString('utf8'))
  } finally {
    fs.openSync = originalOpen
    fs.readSync = originalRead
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('raw byte reads reject a replacement root opened after validation', () => {
  const root = makeRoot()
  const parked = `${root}-parked`
  const originalOpen = fs.openSync
  try {
    write(root, 'data/artifact.bin', Buffer.from('original'))
    let swapped = false
    fs.openSync = function swappingRawRootOpen(file, flags, ...rest) {
      if (
        !swapped &&
        path.resolve(String(file)) === root &&
        (flags & (fs.constants.O_DIRECTORY ?? 0)) !== 0
      ) {
        swapped = true
        fs.renameSync(root, parked)
        fs.mkdirSync(root)
        write(root, 'data/artifact.bin', Buffer.from('replacement'))
      }
      return originalOpen.call(fs, file, flags, ...rest)
    }

    assert.throws(
      () => auditCore.readBoundedAuditBytes(root, 'data/artifact.bin'),
      /root.*changed|root.*identity|safe repository/i,
    )
    assert.equal(fs.readFileSync(path.join(parked, 'data/artifact.bin'), 'utf8'), 'original')
    assert.equal(fs.readFileSync(path.join(root, 'data/artifact.bin'), 'utf8'), 'replacement')
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
    cleanup(parked)
  }
})

test('raw byte reads detect parent replacement during the first read', () => {
  const root = makeRoot()
  const outside = makeRoot()
  const originalRead = fs.readSync
  try {
    write(root, 'data/artifact.bin', Buffer.from([0x00, 0xff]))
    const parent = path.join(root, 'data')
    const parked = path.join(root, 'data-parked')
    const outsideParent = path.join(outside, 'data')
    fs.mkdirSync(outsideParent)
    const canary = write(outside, 'data/artifact.bin', Buffer.from('canary'))
    let swapped = false
    fs.readSync = function swappingRawRead(fd, ...rest) {
      if (!swapped && fs.fstatSync(fd).isFile()) {
        swapped = true
        fs.renameSync(parent, parked)
        fs.symlinkSync(outsideParent, parent, 'dir')
      }
      return originalRead.call(fs, fd, ...rest)
    }

    assert.throws(
      () => auditCore.readBoundedAuditBytes(root, 'data/artifact.bin'),
      /changed|parent|identity|symlink|safe|outside/i,
    )
    assert.equal(fs.readFileSync(canary, 'utf8'), 'canary')
  } finally {
    fs.readSync = originalRead
    cleanup(root)
    cleanup(outside)
  }
})

test('raw byte reader aggregates a read failure with both descriptor close failures', () => {
  const root = makeRoot()
  const originalRead = fs.readSync
  const originalClose = fs.closeSync
  const closeAttempts = []
  try {
    const file = write(root, 'data/artifact.bin', Buffer.from([0x00, 0xff]))
    let readFailed = false
    fs.readSync = function failingRawRead(fd, ...rest) {
      let openedPath = ''
      try {
        openedPath = fs.realpathSync(`/proc/self/fd/${fd}`)
      } catch {
        return originalRead.call(fs, fd, ...rest)
      }
      if (!readFailed && openedPath === file) {
        readFailed = true
        throw new Error('injected raw read failure')
      }
      return originalRead.call(fs, fd, ...rest)
    }
    fs.closeSync = function failingRawClose(fd) {
      let openedPath = ''
      try {
        openedPath = fs.realpathSync(`/proc/self/fd/${fd}`)
      } catch {
        return originalClose.call(fs, fd)
      }
      if (openedPath === file || openedPath === path.dirname(file)) {
        const kind = openedPath === file ? 'file' : 'parent'
        closeAttempts.push(kind)
        originalClose.call(fs, fd)
        throw new Error(`injected raw ${kind} close failure`)
      }
      return originalClose.call(fs, fd)
    }

    let failure
    try {
      auditCore.readBoundedAuditBytes(root, 'data/artifact.bin')
    } catch (error) {
      failure = error
    }
    assert.ok(failure instanceof AggregateError)
    assert.deepEqual(closeAttempts, ['file', 'parent'])
    assert.deepEqual(
      flattenedErrorMessages(failure),
      [
        'injected raw read failure',
        'injected raw file close failure',
        'injected raw parent close failure',
      ],
    )
  } finally {
    fs.readSync = originalRead
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('raw byte reader retries a descriptor close that failed before closing', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const file = write(root, 'data/artifact.bin', Buffer.from([0x00, 0xff]))
  let fileFd = null
  let closeAttempts = 0
  try {
    fs.openSync = function trackingRawOpen(fileToOpen, flags, ...rest) {
      const fd = originalOpen.call(fs, fileToOpen, flags, ...rest)
      let openedPath = ''
      try {
        openedPath = fs.realpathSync(`/proc/self/fd/${fd}`)
      } catch {
        // Non-file descriptors opened by the operation are irrelevant here.
      }
      if (openedPath === file) fileFd = fd
      return fd
    }
    fs.closeSync = function failingFirstRawClose(fd) {
      if (fd === fileFd) {
        closeAttempts += 1
        if (closeAttempts === 1) {
          throw new Error('injected pre-close failure')
        }
      }
      return originalClose.call(fs, fd)
    }

    assert.throws(
      () => auditCore.readBoundedAuditBytes(root, 'data/artifact.bin'),
      /injected pre-close failure/,
    )
    assert.equal(closeAttempts, 2)
    assert.notEqual(fileFd, null)
    assert.throws(
      () => fs.fstatSync(fileFd),
      (error) => error?.code === 'EBADF',
      'raw file descriptor remained open after a retryable close failure',
    )
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    if (fileFd !== null) {
      try {
        originalClose.call(fs, fileFd)
      } catch {
        // The successful retry above should already have closed the descriptor.
      }
    }
    cleanup(root)
  }
})

test('safe reads reject a replacement root opened after root validation', () => {
  const root = makeRoot()
  const parked = `${root}-parked`
  const originalOpen = fs.openSync
  try {
    write(root, 'data/value.json', '{"identity":"original"}\n')
    let swapped = false
    fs.openSync = function swappingRootOpen(file, flags, ...rest) {
      if (
        !swapped &&
        path.resolve(String(file)) === root &&
        (flags & (fs.constants.O_DIRECTORY ?? 0)) !== 0
      ) {
        swapped = true
        fs.renameSync(root, parked)
        fs.mkdirSync(root)
        write(root, 'data/value.json', '{"identity":"replacement"}\n')
      }
      return originalOpen.call(fs, file, flags, ...rest)
    }

    assert.throws(
      () => readBoundedAuditJson(root, 'data/value.json'),
      /root.*changed|root.*identity|safe repository/i,
    )
    assert.equal(
      fs.readFileSync(path.join(parked, 'data/value.json'), 'utf8'),
      '{"identity":"original"}\n',
    )
    assert.equal(
      fs.readFileSync(path.join(root, 'data/value.json'), 'utf8'),
      '{"identity":"replacement"}\n',
    )
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
    cleanup(parked)
  }
})

test('missing Linux descriptor anchoring capability fails before any state mutation', () => {
  const root = makeRoot()
  const originalLstat = fs.lstatSync
  let callbackRan = false
  try {
    initGit(root)
    write(root, 'data/value.json', '{"ok":true}\n')
    const gitDir = execFileSync(
      'git',
      ['-C', root, 'rev-parse', '--path-format=absolute', '--absolute-git-dir'],
      { encoding: 'utf8' },
    ).trim()
    fs.lstatSync = function missingProc(file, ...rest) {
      if (String(file).startsWith('/proc/self/fd')) {
        const error = new Error('mock /proc unavailable')
        error.code = 'ENOENT'
        throw error
      }
      return originalLstat.call(fs, file, ...rest)
    }

    assert.throws(
      () => readBoundedAuditJson(root, 'data/value.json'),
      /Linux|proc|descriptor|capability/i,
    )
    assert.throws(
      () => atomicWriteAuditFile(root, '.atlas/audits/security.json', '{}\n'),
      /Linux|proc|descriptor|capability/i,
    )
    assert.throws(
      () => withAuditLock(root, () => {
        callbackRan = true
      }),
      /Linux|proc|descriptor|capability/i,
    )
    assert.equal(callbackRan, false)
    assert.equal(fs.existsSync(path.join(root, '.atlas')), false)
    assert.equal(fs.existsSync(path.join(gitDir, 'repo-atlas')), false)
  } finally {
    fs.lstatSync = originalLstat
    cleanup(root)
  }
})

test('bounded JSON parsing rejects duplicate keys and hostile structure before accepting values', () => {
  const root = makeRoot()
  try {
    const hostile = [
      ['duplicate.json', '{"a":1,"a":2}', /duplicate.*key/i],
      ['nested-duplicate.json', '{"outer":{"a":1,"a":2}}', /duplicate.*key/i],
      ['surrogate.json', '{"value":"\\ud800"}', /surrogate/i],
      ['prototype.json', '{"__proto__":{"polluted":true}}', /prototype/i],
      ['constructor.json', '{"constructor":"unsafe"}', /prototype/i],
      ['invalid-escape.json', '{"value":"\\x"}', /escape|JSON/i],
      ['control.json', '{"value":"line\nbreak"}', /control|JSON/i],
      [
        'deep.json',
        `${'['.repeat(258)}0${']'.repeat(258)}`,
        /depth|nesting/i,
      ],
    ]
    for (const [name, source, pattern] of hostile) {
      write(root, `data/${name}`, source)
      assert.throws(() => readBoundedAuditJson(root, `data/${name}`), pattern)
    }

    const memberBomb = `[${'0,'.repeat(AUDIT_LIMITS.collectionItems)}0]`
    write(root, 'data/member-bomb.json', memberBomb)
    assert.throws(
      () => readBoundedAuditJson(root, 'data/member-bomb.json'),
      /collection|member|item.*limit/i,
    )

    const objectMemberBomb = `{${Array.from(
      { length: AUDIT_LIMITS.collectionItems + 1 },
      (_unused, index) => `"k${index}":0`,
    ).join(',')}}`
    write(root, 'data/object-member-bomb.json', objectMemberBomb)
    assert.throws(
      () => readBoundedAuditJson(root, 'data/object-member-bomb.json'),
      /collection|member|item.*limit/i,
    )

    const aggregateStrings = JSON.stringify(Array.from(
      {
        length: Math.floor(
          AUDIT_LIMITS.textTotalCodeUnits / AUDIT_LIMITS.textCodeUnits,
        ) + 1,
      },
      () => 'x'.repeat(AUDIT_LIMITS.textCodeUnits),
    ))
    write(root, 'data/string-bomb.json', aggregateStrings)
    assert.throws(
      () => readBoundedAuditJson(root, 'data/string-bomb.json'),
      /aggregate|string.*limit/i,
    )
  } finally {
    cleanup(root)
  }
})

test('bounded JSON parsing rejects unsafe integer-valued numbers without rounding', () => {
  const root = makeRoot()
  try {
    write(root, 'data/unsafe-literal.json', '9007199254740993')
    assert.throws(
      () => readBoundedAuditJson(root, 'data/unsafe-literal.json'),
      /safe integer|precision/i,
    )

    write(root, 'data/unsafe-exponent.json', '1e20')
    assert.throws(
      () => readBoundedAuditJson(root, 'data/unsafe-exponent.json'),
      /safe integer|precision/i,
    )

    write(
      root,
      'data/safe-boundaries.json',
      '[-9007199254740991,9007199254740991]',
    )
    assert.deepEqual(
      readBoundedAuditJson(root, 'data/safe-boundaries.json'),
      [-9007199254740991, 9007199254740991],
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

test('canonical JSON matches RFC 8785 number and UTF-16 property ordering vectors', () => {
  assert.equal(
    canonicalJson([333333333.33333329, 1e30, 4.50, 2e-3, 1e-27, -0]),
    '[333333333.3333333,1e+30,4.5,0.002,1e-27,0]',
  )
  assert.equal(
    canonicalJson({
      '\u20ac': 'Euro Sign',
      '\r': 'Carriage Return',
      '\ufb33': 'Hebrew Letter Dalet With Dagesh',
      '1': 'One',
      '\ud83d\ude00': 'Emoji: Grinning Face',
      '\u0080': 'Control',
      '\u00f6': 'Latin Small Letter O With Diaeresis',
    }),
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
  )
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

test('canonical JSON rejects array accessors and extra properties without executing them', () => {
  const value = []
  let getterCalls = 0
  Object.defineProperty(value, 0, {
    configurable: true,
    enumerable: true,
    get() {
      getterCalls += 1
      return 'executed'
    },
  })

  assert.throws(
    () => canonicalJson(value),
    /array|enumerable data propert|accessor/i,
  )
  assert.equal(getterCalls, 0)

  const numericExtra = []
  Object.defineProperty(numericExtra, '4294967295', {
    enumerable: true,
    value: 'ignored by array length',
  })
  assert.throws(
    () => canonicalJson(numericExtra),
    /array|extra propert|enumerable data propert/i,
  )
})

test('canonical JSON enforces aggregate text and serialized byte bounds', () => {
  assert.throws(
    () => canonicalJson(Array.from(
      {
        length: Math.floor(
          AUDIT_LIMITS.textTotalCodeUnits / AUDIT_LIMITS.textCodeUnits,
        ) + 1,
      },
      () => 'x'.repeat(AUDIT_LIMITS.textCodeUnits),
    )),
    /aggregate|string.*limit/i,
  )
  assert.throws(
    () => canonicalJson(
      Array.from(
        { length: AUDIT_LIMITS.textTotalCodeUnits / AUDIT_LIMITS.textCodeUnits },
        () => '\0'.repeat(AUDIT_LIMITS.textCodeUnits),
      ),
    ),
    /byte|serialized|document.*limit/i,
  )
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
  for (const prefix of ['atocc', 'adev', 'amig']) {
    assert.match(
      stableAuditId(prefix, `atlas-${prefix}/v1`, parts),
      new RegExp(`^${prefix}_[0-9a-f]{24}$`),
    )
  }

  assert.throws(() => stableAuditId('arepo', domainTag, parts), /prefix/i)
  assert.throws(() => stableAuditId('atf', domainTag, parts), /prefix/i)
  assert.throws(() => stableAuditId('aobs', domainTag, ['ok', 1]), /parts|string/i)
  assert.throws(() => stableAuditId('aobs', 'bad\0domain', parts), /domain|NUL/i)
  assert.throws(() => stableAuditId('aobs', domainTag, ['bad\0part']), /parts|NUL/i)
  assert.throws(
    () => stableAuditId('aobs', domainTag, Array.from({ length: 65 }, () => 'part')),
    /part.*count|too many/i,
  )
  assert.throws(
    () => stableAuditId('aobs', domainTag, ['😀'.repeat(AUDIT_LIMITS.textCodeUnits / 2)]),
    /total|byte.*limit/i,
  )
})

test('stable audit IDs reject accessor parts before they can change tuple identity', () => {
  const domainTag = 'atlas-observation/v1'
  const legitimate = stableAuditId('aobs', domainTag, ['left', 'right'])
  const hostile = []
  let getterCalls = 0
  Object.defineProperty(hostile, 0, {
    configurable: true,
    enumerable: true,
    get() {
      getterCalls += 1
      return getterCalls < 4 ? 'left' : 'left\0right'
    },
  })

  assert.throws(
    () => stableAuditId('aobs', domainTag, hostile),
    /parts|array|enumerable data propert|accessor/i,
  )
  assert.equal(getterCalls, 0)
  assert.equal(
    legitimate,
    stableAuditId('aobs', domainTag, ['left', 'right']),
  )
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

test('safe reads fail closed when the opened file parent is swapped', () => {
  const root = makeRoot()
  const outside = makeRoot()
  const originalOpen = fs.openSync
  try {
    write(root, '.atlas/audits/security.json', '{"inside":true}\n')
    const parent = path.join(root, '.atlas/audits')
    const parked = path.join(root, '.atlas/audits-parked')
    const outsideParent = path.join(outside, 'audits')
    fs.mkdirSync(outsideParent)
    const canary = write(outside, 'audits/security.json', '{"outside":"canary"}\n')
    let swapped = false
    fs.openSync = function patchedOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      if (!swapped && String(file).endsWith('/security.json') && (flags & fs.constants.O_RDONLY) === fs.constants.O_RDONLY) {
        swapped = true
        fs.renameSync(parent, parked)
        fs.symlinkSync(outsideParent, parent, 'dir')
      }
      return fd
    }

    assert.throws(
      () => readBoundedAuditJson(root, '.atlas/audits/security.json'),
      /changed|parent|symlink|safe|outside/i,
    )
    assert.equal(fs.readFileSync(canary, 'utf8'), '{"outside":"canary"}\n')
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
    cleanup(outside)
  }
})

test('safe reads detect a parent swap triggered inside the first file read', () => {
  const root = makeRoot()
  const outside = makeRoot()
  const originalRead = fs.readSync
  try {
    write(root, '.atlas/audits/security.json', '{"inside":true}\n')
    const parent = path.join(root, '.atlas/audits')
    const parked = path.join(root, '.atlas/audits-parked')
    const outsideParent = path.join(outside, 'audits')
    fs.mkdirSync(outsideParent)
    const canary = write(outside, 'audits/security.json', '{"outside":"canary"}\n')
    let swapped = false
    fs.readSync = function swappingRead(fd, ...rest) {
      if (!swapped && fs.fstatSync(fd).isFile()) {
        swapped = true
        fs.renameSync(parent, parked)
        fs.symlinkSync(outsideParent, parent, 'dir')
      }
      return originalRead.call(fs, fd, ...rest)
    }

    assert.throws(
      () => readBoundedAuditJson(root, '.atlas/audits/security.json'),
      /changed|parent|identity|symlink|safe|outside/i,
    )
    assert.equal(fs.readFileSync(canary, 'utf8'), '{"outside":"canary"}\n')
  } finally {
    fs.readSync = originalRead
    cleanup(root)
    cleanup(outside)
  }
})

test('safe reader preserves its primary error and attempts both descriptor closes', () => {
  const root = makeRoot()
  const originalClose = fs.closeSync
  const closeAttempts = []
  try {
    write(root, 'data/value.json', '{"value":"unterminated')
    fs.closeSync = function failingReaderClose(fd) {
      let openedPath = ''
      try {
        openedPath = fs.realpathSync(`/proc/self/fd/${fd}`)
      } catch {
        return originalClose.call(fs, fd)
      }
      if (
        openedPath === path.join(root, 'data/value.json') ||
        openedPath === path.join(root, 'data')
      ) {
        const kind = openedPath.endsWith('value.json') ? 'file' : 'parent'
        closeAttempts.push(kind)
        originalClose.call(fs, fd)
        throw new Error(`injected reader ${kind} close failure`)
      }
      return originalClose.call(fs, fd)
    }

    let failure
    try {
      readBoundedAuditJson(root, 'data/value.json')
    } catch (error) {
      failure = error
    }
    assert.ok(failure instanceof AggregateError)
    assert.deepEqual(closeAttempts, ['file', 'parent'])
    assert.deepEqual(
      flattenedErrorMessages(failure),
      [
        'audit document is not valid JSON (unterminated string): data/value.json',
        'injected reader file close failure',
        'injected reader parent close failure',
      ],
    )
  } finally {
    fs.closeSync = originalClose
    cleanup(root)
  }
})

test('audit-parent traversal closes the opened child when an ancestor close fails', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const openedDirectoryFds = new Set()
  let injected = false
  try {
    fs.mkdirSync(path.join(root, '.atlas'))
    fs.openSync = function trackingDirectoryOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      if ((flags & (fs.constants.O_DIRECTORY ?? 0)) !== 0) {
        openedDirectoryFds.add(fd)
      }
      return fd
    }
    fs.closeSync = function failingAncestorClose(fd) {
      let openedPath = ''
      try {
        openedPath = fs.realpathSync(`/proc/self/fd/${fd}`)
      } catch {
        return originalClose.call(fs, fd)
      }
      if (!injected && openedPath === path.join(root, '.atlas')) {
        injected = true
        originalClose.call(fs, fd)
        throw new Error('injected ancestor close failure')
      }
      return originalClose.call(fs, fd)
    }

    assert.throws(
      () => atomicWriteAuditFile(
        root,
        '.atlas/audits/security.json',
        '{"version":1}\n',
      ),
      /injected ancestor close failure/,
    )
    assert.equal(injected, true)
    fs.closeSync = originalClose
    for (const fd of openedDirectoryFds) {
      assert.throws(
        () => fs.fstatSync(fd),
        (error) => error?.code === 'EBADF',
        `descriptor ${fd} leaked after traversal failure`,
      )
    }
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    for (const fd of openedDirectoryFds) {
      try {
        originalClose.call(fs, fd)
      } catch {
        // The assertion above requires every descriptor to have been closed.
      }
    }
    cleanup(root)
  }
})

test('atomic writes fail closed and clean anchored temporaries when the parent is swapped', () => {
  const root = makeRoot()
  const outside = makeRoot()
  const originalFsync = fs.fsyncSync
  try {
    const repoPath = '.atlas/audits/security.json'
    atomicWriteAuditFile(root, repoPath, '{"version":1}\n')
    const parent = path.join(root, '.atlas/audits')
    const parked = path.join(root, '.atlas/audits-parked')
    const outsideParent = path.join(outside, 'audits')
    fs.mkdirSync(outsideParent)
    const canary = write(outside, 'audits/security.json', '{"outside":"canary"}\n')
    let swapped = false
    fs.fsyncSync = function patchedFsync(fd) {
      const result = originalFsync.call(fs, fd)
      if (!swapped && fs.fstatSync(fd).isFile()) {
        swapped = true
        fs.renameSync(parent, parked)
        fs.symlinkSync(outsideParent, parent, 'dir')
      }
      return result
    }

    assert.throws(
      () => atomicWriteAuditFile(root, repoPath, '{"version":2}\n'),
      /changed|parent|symlink|safe|outside/i,
    )
    assert.equal(fs.readFileSync(canary, 'utf8'), '{"outside":"canary"}\n')
    assert.equal(fs.readFileSync(path.join(parked, 'security.json'), 'utf8'), '{"version":1}\n')
    assert.deepEqual(fs.readdirSync(parked), ['security.json'])
  } finally {
    fs.fsyncSync = originalFsync
    cleanup(root)
    cleanup(outside)
  }
})

test('atomic-write cleanup never deletes a replacement created after exclusive open', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  let replacement = ''
  let swapped = false
  try {
    fs.openSync = function replacingTemporaryAfterOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      if (
        !swapped &&
        String(file).endsWith('.tmp') &&
        (flags & fs.constants.O_CREAT) !== 0
      ) {
        swapped = true
        replacement = path.join(
          fs.realpathSync(path.dirname(String(file))),
          path.basename(String(file)),
        )
        fs.unlinkSync(replacement)
        fs.writeFileSync(replacement, '{"outside":"replacement"}\n')
      }
      return fd
    }

    assert.throws(
      () => atomicWriteAuditFile(
        root,
        '.atlas/audits/security.json',
        '{"version":1}\n',
      ),
      (error) => {
        assert.ok(
          flattenedErrorMessages(error).some((message) =>
            /changed identity|changed.*creation|not removed/i.test(message)
          ),
        )
        return true
      },
    )
    assert.equal(swapped, true)
    assert.equal(
      fs.readFileSync(replacement, 'utf8'),
      '{"outside":"replacement"}\n',
    )
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
  }
})

test('atomic rename reports external parent relocation without touching replacement inodes', () => {
  const root = makeRoot()
  const outside = makeRoot()
  const originalRename = fs.renameSync
  try {
    const repoPath = '.atlas/audits/security.json'
    atomicWriteAuditFile(root, repoPath, '{"version":1}\n')
    const parent = path.join(root, '.atlas/audits')
    const relocatedParent = path.join(outside, 'relocated-owned-parent')
    const replacementParent = path.join(outside, 'replacement-parent')
    fs.mkdirSync(replacementParent)
    const canary = write(outside, 'replacement-parent/security.json', '{"outside":"canary"}\n')
    let attackerTemporary = ''
    let swapped = false
    fs.renameSync = function swappingFinalRename(source, destination) {
      if (
        !swapped &&
        String(destination).endsWith('/security.json') &&
        String(source).endsWith('.tmp')
      ) {
        swapped = true
        originalRename.call(fs, parent, relocatedParent)
        fs.symlinkSync(replacementParent, parent, 'dir')
        attackerTemporary = path.join(replacementParent, path.basename(String(source)))
        fs.writeFileSync(attackerTemporary, '{"outside":"attacker temp"}\n')
      }
      return originalRename.call(fs, source, destination)
    }

    assert.throws(
      () => atomicWriteAuditFile(root, repoPath, '{"version":2}\n'),
      /changed|parent|identity|symlink|safe|outside/i,
    )
    assert.equal(fs.readFileSync(canary, 'utf8'), '{"outside":"canary"}\n')
    assert.equal(
      fs.readFileSync(path.join(relocatedParent, 'security.json'), 'utf8'),
      '{"version":2}\n',
    )
    assert.equal(fs.readFileSync(attackerTemporary, 'utf8'), '{"outside":"attacker temp"}\n')
  } finally {
    fs.renameSync = originalRename
    cleanup(root)
    cleanup(outside)
  }
})

test('atomic write preserves an unowned temporary when post-create fstat fails', () => {
  const root = makeRoot()
  const originalFstat = fs.fstatSync
  try {
    const repoPath = '.atlas/audits/security.json'
    const file = path.join(root, repoPath)
    atomicWriteAuditFile(root, repoPath, '{"version":1}\n')
    fs.fstatSync = function failingTemporaryFstat(fd, ...rest) {
      let openedPath = ''
      try {
        openedPath = fs.realpathSync(`/proc/self/fd/${fd}`)
      } catch {
        return originalFstat.call(fs, fd, ...rest)
      }
      if (openedPath.endsWith('.tmp')) {
        const error = new Error('injected post-create fstat failure')
        error.code = 'EIO'
        throw error
      }
      return originalFstat.call(fs, fd, ...rest)
    }

    assert.throws(
      () => atomicWriteAuditFile(root, repoPath, '{"version":2}\n'),
      /injected post-create fstat failure/,
    )
    assert.equal(fs.readFileSync(file, 'utf8'), '{"version":1}\n')
    const entries = fs.readdirSync(path.dirname(file))
    assert.equal(entries.includes('security.json'), true)
    assert.equal(entries.filter((entry) => entry.endsWith('.tmp')).length, 1)
  } finally {
    fs.fstatSync = originalFstat
    cleanup(root)
  }
})

test('atomic write preserves the original and durably cleans its temporary after file fsync failure', () => {
  const root = makeRoot()
  const originalFsync = fs.fsyncSync
  try {
    const repoPath = '.atlas/audits/security.json'
    const file = path.join(root, repoPath)
    atomicWriteAuditFile(root, repoPath, '{"version":1}\n')
    let failedFileFsync = false
    let directoryFsyncs = 0
    fs.fsyncSync = function failingFileFsync(fd) {
      const opened = fs.fstatSync(fd)
      if (opened.isFile() && !failedFileFsync) {
        failedFileFsync = true
        const error = new Error('injected file fsync failure')
        error.code = 'EIO'
        throw error
      }
      if (opened.isDirectory()) directoryFsyncs += 1
      return originalFsync.call(fs, fd)
    }

    assert.throws(
      () => atomicWriteAuditFile(root, repoPath, '{"version":2}\n'),
      /injected file fsync failure/,
    )
    assert.equal(fs.readFileSync(file, 'utf8'), '{"version":1}\n')
    assert.deepEqual(fs.readdirSync(path.dirname(file)), ['security.json'])
    assert.equal(directoryFsyncs, 1)
  } finally {
    fs.fsyncSync = originalFsync
    cleanup(root)
  }
})

test('atomic write reports both the primary failure and an owned-temp cleanup failure', () => {
  const root = makeRoot()
  const originalFsync = fs.fsyncSync
  const originalUnlink = fs.unlinkSync
  try {
    const repoPath = '.atlas/audits/security.json'
    const file = path.join(root, repoPath)
    atomicWriteAuditFile(root, repoPath, '{"version":1}\n')
    fs.fsyncSync = function failingFileFsync(fd) {
      if (fs.fstatSync(fd).isFile()) {
        const error = new Error('injected primary fsync failure')
        error.code = 'EIO'
        throw error
      }
      return originalFsync.call(fs, fd)
    }
    fs.unlinkSync = function failingTemporaryCleanup(fileToRemove) {
      if (String(fileToRemove).endsWith('.tmp')) {
        const error = new Error('injected temporary cleanup failure')
        error.code = 'EPERM'
        throw error
      }
      return originalUnlink.call(fs, fileToRemove)
    }

    let failure
    try {
      atomicWriteAuditFile(root, repoPath, '{"version":2}\n')
    } catch (error) {
      failure = error
    }
    assert.ok(failure instanceof AggregateError)
    assert.deepEqual(
      failure.errors.map((error) => error.message),
      ['injected primary fsync failure', 'injected temporary cleanup failure'],
    )
    assert.equal(fs.readFileSync(file, 'utf8'), '{"version":1}\n')
    assert.equal(
      fs.readdirSync(path.dirname(file)).filter((entry) => entry.endsWith('.tmp')).length,
      1,
    )
  } finally {
    fs.fsyncSync = originalFsync
    fs.unlinkSync = originalUnlink
    cleanup(root)
  }
})

test('atomic write propagates rename and real directory-fsync failures without leaking temporaries', () => {
  const root = makeRoot()
  const originalRename = fs.renameSync
  const originalFsync = fs.fsyncSync
  try {
    const repoPath = '.atlas/audits/security.json'
    const file = path.join(root, repoPath)
    atomicWriteAuditFile(root, repoPath, '{"version":1}\n')

    fs.renameSync = function failingRename() {
      const error = new Error('injected rename failure')
      error.code = 'EIO'
      throw error
    }
    assert.throws(
      () => atomicWriteAuditFile(root, repoPath, '{"version":2}\n'),
      /injected rename failure/,
    )
    fs.renameSync = originalRename
    assert.equal(fs.readFileSync(file, 'utf8'), '{"version":1}\n')
    assert.deepEqual(fs.readdirSync(path.dirname(file)), ['security.json'])

    fs.fsyncSync = function failingDirectoryFsync(fd) {
      if (fs.fstatSync(fd).isDirectory()) {
        const error = new Error('injected directory fsync failure')
        error.code = 'EIO'
        throw error
      }
      return originalFsync.call(fs, fd)
    }
    assert.throws(
      () => atomicWriteAuditFile(root, repoPath, '{"version":3}\n'),
      /injected directory fsync failure/,
    )
    assert.equal(fs.readFileSync(file, 'utf8'), '{"version":3}\n')
    assert.deepEqual(fs.readdirSync(path.dirname(file)), ['security.json'])
  } finally {
    fs.renameSync = originalRename
    fs.fsyncSync = originalFsync
    cleanup(root)
  }
})

test('directory fsync ignores only documented unsupported error codes', () => {
  const root = makeRoot()
  const originalFsync = fs.fsyncSync
  try {
    const repoPath = '.atlas/audits/security.json'
    const file = path.join(root, repoPath)
    atomicWriteAuditFile(root, repoPath, '{"version":0}\n')
    for (const [index, code] of [
      'EINVAL',
      'ENOSYS',
      'ENOTSUP',
      'EOPNOTSUPP',
    ].entries()) {
      fs.fsyncSync = function unsupportedDirectoryFsync(fd) {
        if (fs.fstatSync(fd).isDirectory()) {
          const error = new Error(`injected ${code}`)
          error.code = code
          throw error
        }
        return originalFsync.call(fs, fd)
      }
      const contents = `{"version":${index + 1}}\n`
      atomicWriteAuditFile(root, repoPath, contents)
      assert.equal(fs.readFileSync(file, 'utf8'), contents)
    }
  } finally {
    fs.fsyncSync = originalFsync
    cleanup(root)
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

test('audit lock creation stays anchored when its visible parent is replaced', () => {
  const root = makeRoot()
  const outside = makeRoot()
  const originalOpen = fs.openSync
  let callbackRan = false
  try {
    initGit(root)
    const lock = auditLockPath(root)
    const parent = path.dirname(lock)
    fs.mkdirSync(parent, { recursive: true })
    const parked = `${parent}-parked`
    const outsideParent = path.join(outside, 'lock-parent')
    fs.mkdirSync(outsideParent)
    let swapped = false
    fs.openSync = function swappingLockCreate(file, flags, ...rest) {
      if (
        !swapped &&
        String(file).endsWith('/audit-state.lock') &&
        (flags & fs.constants.O_CREAT) !== 0
      ) {
        swapped = true
        fs.renameSync(parent, parked)
        fs.symlinkSync(outsideParent, parent, 'dir')
      }
      return originalOpen.call(fs, file, flags, ...rest)
    }

    assert.throws(
      () => withAuditLock(root, () => {
        callbackRan = true
      }),
      /lock parent|parent.*changed|symlink|identity|safe/i,
    )
    assert.equal(callbackRan, false)
    assert.equal(fs.existsSync(path.join(outsideParent, 'audit-state.lock')), false)
    assert.deepEqual(fs.readdirSync(parked), [])
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
    cleanup(outside)
  }
})

test('lock cleanup never deletes a replacement created after exclusive open', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  let replacement = ''
  let callbackRan = false
  let swapped = false
  try {
    initGit(root)
    fs.openSync = function replacingLockAfterOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      if (
        !swapped &&
        String(file).endsWith('/audit-state.lock') &&
        (flags & fs.constants.O_CREAT) !== 0
      ) {
        swapped = true
        replacement = path.join(
          fs.realpathSync(path.dirname(String(file))),
          path.basename(String(file)),
        )
        fs.unlinkSync(replacement)
        fs.writeFileSync(replacement, '{"outside":"replacement"}\n')
      }
      return fd
    }

    assert.throws(
      () => withAuditLock(root, () => {
        callbackRan = true
      }),
      (error) => {
        assert.ok(
          flattenedErrorMessages(error).some((message) =>
            /changed identity|changed.*creation|not removed/i.test(message)
          ),
        )
        return true
      },
    )
    assert.equal(callbackRan, false)
    assert.equal(swapped, true)
    assert.equal(
      fs.readFileSync(replacement, 'utf8'),
      '{"outside":"replacement"}\n',
    )
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
  }
})

test('existing lock inspection stays anchored when its visible parent is replaced', () => {
  const root = makeRoot()
  const outside = makeRoot()
  const originalOpen = fs.openSync
  try {
    initGit(root)
    const lock = auditLockPath(root)
    const parent = path.dirname(lock)
    fs.mkdirSync(parent, { recursive: true })
    const parked = `${parent}-parked`
    const outsideParent = path.join(outside, 'lock-parent')
    fs.mkdirSync(outsideParent)
    fs.writeFileSync(lock, '{"pid":123,"operation":"old"}\n')
    const canary = write(outside, 'lock-parent/audit-state.lock', '{"pid":456}\n')
    let swapped = false
    fs.openSync = function swappingLockInspection(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      if (
        !swapped &&
        String(file).endsWith('/audit-state.lock') &&
        (flags & fs.constants.O_CREAT) === 0 &&
        (flags & fs.constants.O_WRONLY) === 0
      ) {
        swapped = true
        fs.renameSync(parent, parked)
        fs.symlinkSync(outsideParent, parent, 'dir')
      }
      return fd
    }

    assert.throws(
      () => withAuditLock(root, () => 'must not run'),
      /lock parent|parent.*changed|symlink|identity|safe/i,
    )
    assert.equal(fs.readFileSync(canary, 'utf8'), '{"pid":456}\n')
    assert.equal(fs.readFileSync(path.join(parked, 'audit-state.lock'), 'utf8'), '{"pid":123,"operation":"old"}\n')
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
    cleanup(outside)
  }
})

test('audit lock release is anchored and reports visible-parent replacement', () => {
  const root = makeRoot()
  const outside = makeRoot()
  try {
    initGit(root)
    const lock = auditLockPath(root)
    const parent = path.dirname(lock)
    const parked = `${parent}-parked`
    const outsideParent = path.join(outside, 'lock-parent')
    fs.mkdirSync(outsideParent)
    const canary = path.join(outsideParent, 'audit-state.lock')

    assert.throws(
      () => withAuditLock(root, () => {
        fs.renameSync(parent, parked)
        fs.symlinkSync(outsideParent, parent, 'dir')
        fs.writeFileSync(canary, '{"outside":"canary"}\n')
        return 'must not return successfully'
      }),
      /lock parent|parent.*changed|symlink|identity|release|cleanup/i,
    )
    assert.equal(fs.readFileSync(canary, 'utf8'), '{"outside":"canary"}\n')
    assert.deepEqual(fs.readdirSync(parked), [])
  } finally {
    cleanup(root)
    cleanup(outside)
  }
})

test('audit lock release reports an owned lock unlinked during the operation', () => {
  const root = makeRoot()
  try {
    initGit(root)
    const lock = auditLockPath(root)
    assert.throws(
      () => withAuditLock(root, () => {
        fs.unlinkSync(lock)
        return 'must not return successfully'
      }),
      /owned audit lock is missing|release failed/i,
    )
    assert.equal(fs.existsSync(lock), false)
  } finally {
    cleanup(root)
  }
})

test('existing FIFO locks are inspected with O_NONBLOCK and O_NOFOLLOW', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  let inspectionFlags = null
  try {
    initGit(root)
    const lock = auditLockPath(root)
    fs.mkdirSync(path.dirname(lock), { recursive: true })
    execFileSync('mkfifo', [lock])
    fs.openSync = function observingExistingLockOpen(file, flags, ...rest) {
      if (
        String(file).endsWith('/audit-state.lock') &&
        (flags & fs.constants.O_CREAT) === 0 &&
        (flags & fs.constants.O_WRONLY) === 0
      ) {
        inspectionFlags = flags
      }
      return originalOpen.call(fs, file, flags, ...rest)
    }

    assert.throws(
      () => withAuditLock(root, () => 'must not run'),
      /unsafe|malformed|lock|busy|held/i,
    )
    assert.notEqual(inspectionFlags, null)
    assert.notEqual(inspectionFlags & (fs.constants.O_NONBLOCK ?? 0), 0)
    assert.notEqual(inspectionFlags & (fs.constants.O_NOFOLLOW ?? 0), 0)
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
  }
})

test('existing lock inspection bounds a file that grows after fstat', () => {
  const root = makeRoot()
  const originalFstat = fs.fstatSync
  const originalOpen = fs.openSync
  const originalRead = fs.readSync
  const lockByteLimit = 16 * 1024
  let lockReadFd = null
  let grew = false
  let requestedBytes = 0
  try {
    initGit(root)
    const lock = auditLockPath(root)
    fs.mkdirSync(path.dirname(lock), { recursive: true })
    fs.writeFileSync(lock, '{"pid":123}\n')
    const identity = fs.lstatSync(lock)
    fs.openSync = function observingLockRead(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      if (
        String(file).endsWith('/audit-state.lock') &&
        (flags & fs.constants.O_CREAT) === 0 &&
        (flags & fs.constants.O_WRONLY) === 0
      ) {
        lockReadFd = fd
      }
      return fd
    }
    fs.fstatSync = function growingAfterFstat(fd, ...rest) {
      const stat = originalFstat.call(fs, fd, ...rest)
      if (
        !grew &&
        stat.dev === identity.dev &&
        stat.ino === identity.ino
      ) {
        grew = true
        fs.appendFileSync(lock, ' '.repeat(lockByteLimit + 1))
      }
      return stat
    }
    fs.readSync = function observingBoundedRead(fd, buffer, offset, length, position) {
      if (fd === lockReadFd) requestedBytes += length
      return originalRead.call(fs, fd, buffer, offset, length, position)
    }

    assert.throws(
      () => withAuditLock(root, () => 'must not run'),
      (error) => {
        assert.match(error.message, /unsafe|malformed|oversize|limit/i)
        assert.doesNotMatch(error.message, /pid 123/)
        return true
      },
    )
    assert.ok(requestedBytes > 0)
    assert.ok(requestedBytes <= lockByteLimit + 1)
  } finally {
    fs.fstatSync = originalFstat
    fs.openSync = originalOpen
    fs.readSync = originalRead
    cleanup(root)
  }
})

test('main and linked worktrees hold independent audit locks', () => {
  const root = makeRoot()
  const holder = makeRoot()
  const linked = path.join(holder, 'linked')
  try {
    initGit(root)
    write(root, 'tracked.txt', 'main\n')
    commitFixture(root, 'main')
    execFileSync('git', ['-C', root, 'worktree', 'add', '-qb', 'linked-audit-core', linked])
    const mainLock = auditLockPath(root)
    const linkedLock = auditLockPath(linked)
    assert.notEqual(mainLock, linkedLock)

    withAuditLock(root, () => withAuditLock(linked, () => {
      assert.equal(fs.existsSync(mainLock), true)
      assert.equal(fs.existsSync(linkedLock), true)
    }))
    assert.equal(fs.existsSync(mainLock), false)
    assert.equal(fs.existsSync(linkedLock), false)
  } finally {
    cleanup(holder)
    cleanup(root)
  }
})

test('the audit lock remains held until returned promises resolve or reject', async () => {
  const root = makeRoot()
  try {
    initGit(root)
    const lock = auditLockPath(root)
    let resolveOperation
    const pending = withAuditLock(root, () => new Promise((resolve) => {
      resolveOperation = resolve
    }))
    assert.equal(fs.existsSync(lock), true)
    assert.throws(() => withAuditLock(root, () => 'contender'), /already held|busy|lock/i)
    resolveOperation('resolved')
    assert.equal(await pending, 'resolved')
    assert.equal(fs.existsSync(lock), false)

    let rejectOperation
    const rejected = withAuditLock(root, () => new Promise((_resolve, reject) => {
      rejectOperation = reject
    }))
    assert.equal(fs.existsSync(lock), true)
    assert.throws(() => withAuditLock(root, () => 'contender'), /already held|busy|lock/i)
    rejectOperation(new Error('deferred failure'))
    await assert.rejects(rejected, /deferred failure/)
    assert.equal(fs.existsSync(lock), false)

    const throwingThenable = Object.defineProperty({}, 'then', {
      get() {
        throw new Error('then getter failed')
      },
    })
    assert.throws(
      () => withAuditLock(root, () => throwingThenable),
      /then getter failed/,
    )
    assert.equal(fs.existsSync(lock), false)
  } finally {
    cleanup(root)
  }
})

test('audit lock cleanup preserves operation and release failures across every completion path', async () => {
  const scenarios = [
    {
      name: 'sync resolve',
      operation: () => 'resolved',
      primary: null,
    },
    {
      name: 'sync reject',
      operation: () => {
        throw new Error('sync operation failure')
      },
      primary: 'sync operation failure',
    },
    {
      name: 'promise resolve',
      operation: () => Promise.resolve('resolved'),
      primary: null,
    },
    {
      name: 'promise reject',
      operation: () => Promise.reject(new Error('promise operation failure')),
      primary: 'promise operation failure',
    },
    {
      name: 'then getter',
      operation: () => Object.defineProperty({}, 'then', {
        get() {
          throw new Error('then getter operation failure')
        },
      }),
      primary: 'then getter operation failure',
    },
  ]

  for (const scenario of scenarios) {
    const root = makeRoot()
    const originalOpen = fs.openSync
    const originalClose = fs.closeSync
    const originalUnlink = fs.unlinkSync
    let closeAttempted = false
    let lockFd = null
    let unlinkAttempted = false
    try {
      initGit(root)
      fs.openSync = function trackingOwnedLockOpen(file, flags, ...rest) {
        const fd = originalOpen.call(fs, file, flags, ...rest)
        if (
          String(file).endsWith('/audit-state.lock') &&
          (flags & fs.constants.O_CREAT) !== 0
        ) {
          lockFd = fd
        }
        return fd
      }
      fs.closeSync = function failingLockClose(fd) {
        if (fd === lockFd) {
          closeAttempted = true
          originalClose.call(fs, fd)
          throw new Error('injected lock close failure')
        }
        return originalClose.call(fs, fd)
      }
      fs.unlinkSync = function failingLockUnlink(file) {
        if (String(file).endsWith('/audit-state.lock')) {
          unlinkAttempted = true
          originalUnlink.call(fs, file)
          throw new Error('injected lock unlink failure')
        }
        return originalUnlink.call(fs, file)
      }

      let failure
      try {
        await withAuditLock(root, scenario.operation)
      } catch (error) {
        failure = error
      }
      assert.ok(failure, scenario.name)
      const messages = flattenedErrorMessages(failure)
      if (scenario.primary) assert.ok(messages.includes(scenario.primary), scenario.name)
      assert.ok(messages.includes('injected lock close failure'), scenario.name)
      assert.ok(messages.includes('injected lock unlink failure'), scenario.name)
      assert.equal(closeAttempted, true, scenario.name)
      assert.equal(unlinkAttempted, true, scenario.name)
    } finally {
      fs.openSync = originalOpen
      fs.closeSync = originalClose
      fs.unlinkSync = originalUnlink
      cleanup(root)
    }
  }
})

test('audit Git calls ignore redirecting GIT_* variables and require the exact worktree root', () => {
  const root = makeRoot()
  const hostile = makeRoot()
  const previous = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => key.startsWith('GIT_')),
  )
  try {
    initGit(root)
    initGit(hostile)
    write(root, 'identity.txt', 'requested root\n')
    write(hostile, 'identity.txt', 'hostile root\n')
    const commitEnv = {
      ...process.env,
      GIT_AUTHOR_NAME: 'Audit Fixture',
      GIT_AUTHOR_EMAIL: 'audit@example.invalid',
      GIT_COMMITTER_NAME: 'Audit Fixture',
      GIT_COMMITTER_EMAIL: 'audit@example.invalid',
    }
    execFileSync('git', ['-C', root, 'add', 'identity.txt'], { env: commitEnv })
    execFileSync('git', ['-C', root, 'commit', '-qm', 'requested root'], { env: commitEnv })
    execFileSync('git', ['-C', hostile, 'add', 'identity.txt'], { env: commitEnv })
    execFileSync('git', ['-C', hostile, 'commit', '-qm', 'hostile root'], { env: commitEnv })
    const rootHead = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
    }).trim()
    const hostileHead = execFileSync('git', ['-C', hostile, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
    }).trim()
    assert.notEqual(rootHead, hostileHead)
    const expectedLock = auditLockPath(root)
    process.env.GIT_DIR = path.join(hostile, '.git')
    process.env.GIT_WORK_TREE = hostile
    process.env.GIT_CONFIG_COUNT = '1'
    process.env.GIT_CONFIG_KEY_0 = 'core.bare'
    process.env.GIT_CONFIG_VALUE_0 = 'true'

    withAuditLock(root, () => {
      assert.equal(fs.existsSync(expectedLock), true)
      assert.equal(fs.existsSync(path.join(hostile, '.git/repo-atlas/audit-state.lock')), false)
      const receipt = JSON.parse(fs.readFileSync(expectedLock, 'utf8'))
      assert.equal(receipt.sourceSnapshot, rootHead)
    })

    const child = path.join(root, 'child')
    fs.mkdirSync(child)
    assert.throws(
      () => withAuditLock(child, () => 'wrong root'),
      /top-level|worktree root|exact/i,
    )
  } finally {
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('GIT_')) delete process.env[key]
    }
    Object.assign(process.env, previous)
    cleanup(root)
    cleanup(hostile)
  }
})

test('audit Git subprocesses never follow a transient replacement of the requested root', () => {
  const root = makeRoot()
  const replacement = makeRoot()
  const tooling = makeRoot()
  const parked = `${root}-parked`
  const originalPath = process.env.PATH
  let callbackRan = false
  try {
    initGit(root)
    write(root, 'identity.txt', 'original\n')
    commitFixture(root, 'original')
    initGit(replacement)
    write(replacement, 'identity.txt', 'replacement\n')
    commitFixture(replacement, 'replacement')
    const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim()
    const wrapper = path.join(tooling, 'git')
    fs.writeFileSync(
      wrapper,
      `#!/usr/bin/env node
const fs = require('node:fs')
const { spawnSync } = require('node:child_process')
fs.renameSync(process.env.AUDIT_SWAP_ROOT, process.env.AUDIT_SWAP_PARKED)
fs.renameSync(process.env.AUDIT_SWAP_REPLACEMENT, process.env.AUDIT_SWAP_ROOT)
let result
try {
  result = spawnSync(process.env.AUDIT_REAL_GIT, process.argv.slice(2))
} finally {
  fs.renameSync(process.env.AUDIT_SWAP_ROOT, process.env.AUDIT_SWAP_REPLACEMENT)
  fs.renameSync(process.env.AUDIT_SWAP_PARKED, process.env.AUDIT_SWAP_ROOT)
}
if (result.stdout) process.stdout.write(result.stdout)
if (result.stderr) process.stderr.write(result.stderr)
process.exit(result.status === null ? 1 : result.status)
`,
      { mode: 0o700 },
    )
    process.env.PATH = `${tooling}${path.delimiter}${originalPath ?? ''}`
    process.env.AUDIT_REAL_GIT = realGit
    process.env.AUDIT_SWAP_ROOT = root
    process.env.AUDIT_SWAP_PARKED = parked
    process.env.AUDIT_SWAP_REPLACEMENT = replacement

    let failure
    try {
      withAuditLock(root, () => {
        callbackRan = true
      })
    } catch (error) {
      failure = error
    }
    assert.equal(callbackRan, false)
    assert.ok(failure)
    assert.equal(
      fs.existsSync(path.join(replacement, '.git/repo-atlas')),
      false,
    )
  } finally {
    if (originalPath === undefined) delete process.env.PATH
    else process.env.PATH = originalPath
    for (const key of [
      'AUDIT_REAL_GIT',
      'AUDIT_SWAP_ROOT',
      'AUDIT_SWAP_PARKED',
      'AUDIT_SWAP_REPLACEMENT',
    ]) {
      delete process.env[key]
    }
    cleanup(root)
    cleanup(parked)
    cleanup(replacement)
    cleanup(tooling)
  }
})

test('source snapshot remains bound to the retained Git administration inode', () => {
  const root = makeRoot()
  const replacement = makeRoot()
  const tooling = makeRoot()
  const originalPath = process.env.PATH
  try {
    initGit(root)
    write(root, 'identity.txt', 'original\n')
    commitFixture(root, 'original')
    initGit(replacement)
    write(replacement, 'identity.txt', 'replacement\n')
    commitFixture(replacement, 'replacement')
    const rootHead = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {
      encoding: 'utf8',
    }).trim()
    const replacementHead = execFileSync(
      'git',
      ['-C', replacement, 'rev-parse', 'HEAD'],
      { encoding: 'utf8' },
    ).trim()
    assert.notEqual(rootHead, replacementHead)

    const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim()
    const wrapper = path.join(tooling, 'git')
    fs.writeFileSync(
      wrapper,
      `#!/usr/bin/env node
const fs = require('node:fs')
const { spawnSync } = require('node:child_process')
fs.renameSync(process.env.AUDIT_ROOT_GIT, process.env.AUDIT_PARKED_GIT)
fs.renameSync(process.env.AUDIT_REPLACEMENT_GIT, process.env.AUDIT_ROOT_GIT)
let result
try {
  result = spawnSync(process.env.AUDIT_REAL_GIT, process.argv.slice(2))
} finally {
  fs.renameSync(process.env.AUDIT_ROOT_GIT, process.env.AUDIT_REPLACEMENT_GIT)
  fs.renameSync(process.env.AUDIT_PARKED_GIT, process.env.AUDIT_ROOT_GIT)
}
if (result.stdout) process.stdout.write(result.stdout)
if (result.stderr) process.stderr.write(result.stderr)
process.exit(result.status === null ? 1 : result.status)
`,
      { mode: 0o700 },
    )
    process.env.PATH = `${tooling}${path.delimiter}${originalPath ?? ''}`
    process.env.AUDIT_REAL_GIT = realGit
    process.env.AUDIT_ROOT_GIT = path.join(root, '.git')
    process.env.AUDIT_PARKED_GIT = path.join(root, '.git-parked')
    process.env.AUDIT_REPLACEMENT_GIT = path.join(replacement, '.git')

    const lock = auditLockPath(root)
    withAuditLock(root, () => {
      const receipt = JSON.parse(fs.readFileSync(lock, 'utf8'))
      assert.equal(receipt.sourceSnapshot, rootHead)
    })
  } finally {
    if (originalPath === undefined) delete process.env.PATH
    else process.env.PATH = originalPath
    for (const key of [
      'AUDIT_REAL_GIT',
      'AUDIT_ROOT_GIT',
      'AUDIT_PARKED_GIT',
      'AUDIT_REPLACEMENT_GIT',
    ]) {
      delete process.env[key]
    }
    cleanup(root)
    cleanup(replacement)
    cleanup(tooling)
  }
})

test('Git-admin discovery rejects replacement before the discovered inode is opened', () => {
  const root = makeRoot()
  const outside = makeRoot()
  const originalOpen = fs.openSync
  let callbackRan = false
  let swapped = false
  try {
    initGit(root)
    const gitDirectory = path.join(root, '.git')
    const parked = path.join(root, '.git-parked')
    const replacement = path.join(outside, 'replacement-git-admin')
    fs.mkdirSync(replacement)
    fs.writeFileSync(path.join(replacement, 'canary'), 'replacement\n')
    fs.openSync = function replacingGitAdminBeforeOpen(file, flags, ...rest) {
      if (
        !swapped &&
        path.resolve(String(file)) === gitDirectory &&
        (flags & (fs.constants.O_DIRECTORY ?? 0)) !== 0
      ) {
        swapped = true
        fs.renameSync(gitDirectory, parked)
        fs.renameSync(replacement, gitDirectory)
      }
      return originalOpen.call(fs, file, flags, ...rest)
    }

    assert.throws(
      () => withAuditLock(root, () => {
        callbackRan = true
      }),
      /administration|identity|changed|Git/i,
    )
    assert.equal(swapped, true)
    assert.equal(callbackRan, false)
    assert.equal(
      fs.readFileSync(path.join(gitDirectory, 'canary'), 'utf8'),
      'replacement\n',
    )
    assert.equal(
      fs.existsSync(path.join(gitDirectory, 'repo-atlas')),
      false,
    )
  } finally {
    fs.openSync = originalOpen
    cleanup(root)
    cleanup(outside)
  }
})

test('lock-context validation closes the already-open lock parent on failure', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  const originalRealpath = fs.realpathSync
  let callbackRan = false
  let parentFd = null
  let parentProcChecks = 0
  try {
    initGit(root)
    fs.openSync = function trackingLockParentOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      if (
        String(file).endsWith('/repo-atlas') &&
        (flags & (fs.constants.O_DIRECTORY ?? 0)) !== 0
      ) {
        parentFd = fd
      }
      return fd
    }
    fs.realpathSync = function failingSecondLockParentCheck(file, ...rest) {
      if (parentFd !== null && String(file) === `/proc/self/fd/${parentFd}`) {
        parentProcChecks += 1
        if (parentProcChecks === 2) {
          throw new Error('injected lock-context validation failure')
        }
      }
      return originalRealpath.call(fs, file, ...rest)
    }

    assert.throws(
      () => withAuditLock(root, () => {
        callbackRan = true
      }),
      /injected lock-context validation failure|lock parent changed/i,
    )
    assert.equal(callbackRan, false)
    assert.notEqual(parentFd, null)
    fs.realpathSync = originalRealpath
    assert.throws(
      () => fs.fstatSync(parentFd),
      (error) => error?.code === 'EBADF',
      'lock parent descriptor leaked after context validation failure',
    )
  } finally {
    fs.openSync = originalOpen
    fs.realpathSync = originalRealpath
    if (parentFd !== null) {
      try {
        fs.closeSync(parentFd)
      } catch {
        // The assertion above requires the descriptor to have been closed.
      }
    }
    cleanup(root)
  }
})

test('audit Git discovery rejects root replacement after a subprocess', () => {
  const root = makeRoot()
  const replacement = makeRoot()
  const tooling = makeRoot()
  const parked = `${root}-parked`
  const originalPath = process.env.PATH
  let callbackRan = false
  try {
    initGit(root)
    write(root, 'identity.txt', 'original\n')
    commitFixture(root, 'original')
    initGit(replacement)
    write(replacement, 'identity.txt', 'replacement\n')
    commitFixture(replacement, 'replacement')
    const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim()
    const marker = path.join(tooling, 'swapped')
    const wrapper = path.join(tooling, 'git')
    fs.writeFileSync(
      wrapper,
      `#!/usr/bin/env node
const fs = require('node:fs')
const { spawnSync } = require('node:child_process')
const result = spawnSync(process.env.AUDIT_REAL_GIT, process.argv.slice(2))
if (!fs.existsSync(process.env.AUDIT_SWAP_MARKER)) {
  fs.renameSync(process.env.AUDIT_SWAP_ROOT, process.env.AUDIT_SWAP_PARKED)
  fs.renameSync(process.env.AUDIT_SWAP_REPLACEMENT, process.env.AUDIT_SWAP_ROOT)
  fs.writeFileSync(process.env.AUDIT_SWAP_MARKER, 'done')
}
if (result.stdout) process.stdout.write(result.stdout)
if (result.stderr) process.stderr.write(result.stderr)
process.exit(result.status === null ? 1 : result.status)
`,
      { mode: 0o700 },
    )
    process.env.PATH = `${tooling}${path.delimiter}${originalPath ?? ''}`
    process.env.AUDIT_REAL_GIT = realGit
    process.env.AUDIT_SWAP_ROOT = root
    process.env.AUDIT_SWAP_PARKED = parked
    process.env.AUDIT_SWAP_REPLACEMENT = replacement
    process.env.AUDIT_SWAP_MARKER = marker

    assert.throws(
      () => withAuditLock(root, () => {
        callbackRan = true
      }),
      /root.*changed|root.*identity|worktree.*changed|safe repository/i,
    )
    assert.equal(callbackRan, false)
    assert.equal(
      fs.existsSync(path.join(root, '.git/repo-atlas')),
      false,
    )
  } finally {
    if (originalPath === undefined) delete process.env.PATH
    else process.env.PATH = originalPath
    for (const key of [
      'AUDIT_REAL_GIT',
      'AUDIT_SWAP_ROOT',
      'AUDIT_SWAP_PARKED',
      'AUDIT_SWAP_REPLACEMENT',
      'AUDIT_SWAP_MARKER',
    ]) {
      delete process.env[key]
    }
    cleanup(root)
    cleanup(parked)
    cleanup(replacement)
    cleanup(tooling)
  }
})

test('bounded Git blob reads return exact bytes in normal and linked worktrees', () => {
  const root = makeRoot()
  const linked = makeRoot()
  fs.rmdirSync(linked)
  const bytes = Buffer.from([0x00, 0x41, 0xff, 0x0a])
  try {
    initGit(root)
    write(root, 'artifact.bin', bytes)
    commitFixture(root, 'blob fixture')
    const blob = gitObjectReceipt(root, 'HEAD:artifact.bin')

    assert.deepEqual(
      Buffer.from(auditCore.readBoundedAuditGitBlob(root, blob, bytes.length)),
      bytes,
    )
    execFileSync(
      'git',
      ['-C', root, 'worktree', 'add', '-q', '-b', 'audit-blob-linked', linked, 'HEAD'],
    )
    assert.deepEqual(
      Buffer.from(auditCore.readBoundedAuditGitBlob(linked, blob, bytes.length)),
      bytes,
    )
  } finally {
    cleanup(linked)
    cleanup(root)
  }
})

test('bounded Git blob reads reject malformed, wrong-algorithm, non-blob, missing, and oversized claims', () => {
  const root = makeRoot()
  const bytes = Buffer.from('bounded Git bytes\n')
  try {
    initGit(root)
    write(root, 'artifact.txt', bytes)
    commitFixture(root, 'blob validation fixture')
    const blob = gitObjectReceipt(root, 'HEAD:artifact.txt')
    const tree = gitObjectReceipt(root, 'HEAD^{tree}')
    const algorithm = blob.startsWith('git-sha1:') ? 'sha1' : 'sha256'
    const wrongAlgorithm = algorithm === 'sha1' ? 'sha256' : 'sha1'
    const wrongLength = wrongAlgorithm === 'sha1' ? 40 : 64
    const missingLength = algorithm === 'sha1' ? 40 : 64

    assert.throws(
      () => auditCore.readBoundedAuditGitBlob(root, blob.slice(blob.indexOf(':') + 1)),
      /prefixed|Git blob|sha1|sha256/i,
    )
    assert.throws(
      () => auditCore.readBoundedAuditGitBlob(
        root,
        `git-${wrongAlgorithm}:${'a'.repeat(wrongLength)}`,
      ),
      /algorithm|object format/i,
    )
    assert.throws(
      () => auditCore.readBoundedAuditGitBlob(root, tree),
      /blob|object type/i,
    )
    assert.throws(
      () => auditCore.readBoundedAuditGitBlob(
        root,
        `git-${algorithm}:${'f'.repeat(missingLength)}`,
      ),
      /missing|unavailable|object/i,
    )
    assert.throws(
      () => auditCore.readBoundedAuditGitBlob(root, blob, bytes.length - 1),
      /limit|exceeds|size/i,
    )
    assert.throws(
      () => auditCore.readBoundedAuditGitBlob(root, blob, -1),
      /nonnegative|limit|safe integer/i,
    )
    assert.deepEqual(
      Buffer.from(auditCore.readBoundedAuditGitBlob(root, blob, bytes.length)),
      bytes,
    )
  } finally {
    cleanup(root)
  }
})

test('bounded Git blob reads ignore hostile Git environment redirects', () => {
  const root = makeRoot()
  const hostile = makeRoot()
  const previousGitEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => key.startsWith('GIT_')),
  )
  try {
    initGit(root)
    write(root, 'artifact.txt', 'trusted\n')
    commitFixture(root, 'trusted fixture')
    initGit(hostile)
    write(hostile, 'artifact.txt', 'hostile\n')
    commitFixture(hostile, 'hostile fixture')
    const blob = gitObjectReceipt(root, 'HEAD:artifact.txt')

    for (const key of Object.keys(process.env)) {
      if (key.startsWith('GIT_')) delete process.env[key]
    }
    process.env.GIT_DIR = path.join(hostile, '.git')
    process.env.GIT_WORK_TREE = hostile
    process.env.GIT_CONFIG_COUNT = '1'
    process.env.GIT_CONFIG_KEY_0 = 'core.bare'
    process.env.GIT_CONFIG_VALUE_0 = 'true'

    assert.equal(
      Buffer.from(auditCore.readBoundedAuditGitBlob(root, blob)).toString('utf8'),
      'trusted\n',
    )
  } finally {
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('GIT_')) delete process.env[key]
    }
    Object.assign(process.env, previousGitEnvironment)
    cleanup(root)
    cleanup(hostile)
  }
})

test('bounded Git blob reads retain root and Git-admin capabilities across transient replacements', () => {
  for (const mode of ['root', 'git-admin']) {
    const root = makeRoot()
    const replacement = makeRoot()
    const tooling = makeRoot()
    const parkedRoot = `${root}-parked`
    const parkedGit = path.join(root, '.git-parked')
    const originalPath = process.env.PATH
    try {
      initGit(root)
      write(root, 'artifact.txt', 'trusted\n')
      commitFixture(root, 'trusted fixture')
      initGit(replacement)
      write(replacement, 'artifact.txt', 'hostile\n')
      commitFixture(replacement, 'hostile fixture')
      const blob = gitObjectReceipt(root, 'HEAD:artifact.txt')
      const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim()
      const wrapper = path.join(tooling, 'git')
      fs.writeFileSync(
        wrapper,
        `#!/usr/bin/env node
const fs = require('node:fs')
const { spawnSync } = require('node:child_process')
const arguments_ = process.argv.slice(2)
const shouldSwap = arguments_.includes('cat-file')
if (shouldSwap && process.env.AUDIT_SWAP_MODE === 'root') {
  fs.renameSync(process.env.AUDIT_SWAP_ROOT, process.env.AUDIT_SWAP_PARKED_ROOT)
  fs.renameSync(process.env.AUDIT_SWAP_REPLACEMENT, process.env.AUDIT_SWAP_ROOT)
}
if (shouldSwap && process.env.AUDIT_SWAP_MODE === 'git-admin') {
  fs.renameSync(process.env.AUDIT_ROOT_GIT, process.env.AUDIT_PARKED_GIT)
  fs.renameSync(process.env.AUDIT_REPLACEMENT_GIT, process.env.AUDIT_ROOT_GIT)
}
let result
try {
  result = spawnSync(process.env.AUDIT_REAL_GIT, arguments_)
} finally {
  if (shouldSwap && process.env.AUDIT_SWAP_MODE === 'root') {
    fs.renameSync(process.env.AUDIT_SWAP_ROOT, process.env.AUDIT_SWAP_REPLACEMENT)
    fs.renameSync(process.env.AUDIT_SWAP_PARKED_ROOT, process.env.AUDIT_SWAP_ROOT)
  }
  if (shouldSwap && process.env.AUDIT_SWAP_MODE === 'git-admin') {
    fs.renameSync(process.env.AUDIT_ROOT_GIT, process.env.AUDIT_REPLACEMENT_GIT)
    fs.renameSync(process.env.AUDIT_PARKED_GIT, process.env.AUDIT_ROOT_GIT)
  }
}
if (result.stdout) process.stdout.write(result.stdout)
if (result.stderr) process.stderr.write(result.stderr)
process.exit(result.status === null ? 1 : result.status)
`,
        { mode: 0o700 },
      )
      process.env.PATH = `${tooling}${path.delimiter}${originalPath ?? ''}`
      process.env.AUDIT_REAL_GIT = realGit
      process.env.AUDIT_SWAP_MODE = mode
      process.env.AUDIT_SWAP_ROOT = root
      process.env.AUDIT_SWAP_PARKED_ROOT = parkedRoot
      process.env.AUDIT_SWAP_REPLACEMENT = replacement
      process.env.AUDIT_ROOT_GIT = path.join(root, '.git')
      process.env.AUDIT_PARKED_GIT = parkedGit
      process.env.AUDIT_REPLACEMENT_GIT = path.join(replacement, '.git')

      assert.equal(
        Buffer.from(auditCore.readBoundedAuditGitBlob(root, blob)).toString('utf8'),
        'trusted\n',
        mode,
      )
    } finally {
      if (originalPath === undefined) delete process.env.PATH
      else process.env.PATH = originalPath
      for (const key of [
        'AUDIT_REAL_GIT',
        'AUDIT_SWAP_MODE',
        'AUDIT_SWAP_ROOT',
        'AUDIT_SWAP_PARKED_ROOT',
        'AUDIT_SWAP_REPLACEMENT',
        'AUDIT_ROOT_GIT',
        'AUDIT_PARKED_GIT',
        'AUDIT_REPLACEMENT_GIT',
      ]) {
        delete process.env[key]
      }
      cleanup(root)
      cleanup(parkedRoot)
      cleanup(replacement)
      cleanup(tooling)
    }
  }
})

test('bounded Git blob reads verify the final byte length and Git object identity', () => {
  const root = makeRoot()
  const tooling = makeRoot()
  const originalPath = process.env.PATH
  try {
    initGit(root)
    write(root, 'artifact.txt', 'original\n')
    commitFixture(root, 'identity fixture')
    const blob = gitObjectReceipt(root, 'HEAD:artifact.txt')
    const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim()
    const wrapper = path.join(tooling, 'git')
    fs.writeFileSync(
      wrapper,
      `#!/usr/bin/env node
const { spawnSync } = require('node:child_process')
const arguments_ = process.argv.slice(2)
const result = spawnSync(process.env.AUDIT_REAL_GIT, arguments_)
if (arguments_.includes('cat-file') && arguments_.includes('blob') && result.status === 0) {
  process.stdout.write('hostile!\\n')
} else if (result.stdout) {
  process.stdout.write(result.stdout)
}
if (result.stderr) process.stderr.write(result.stderr)
process.exit(result.status === null ? 1 : result.status)
`,
      { mode: 0o700 },
    )
    process.env.PATH = `${tooling}${path.delimiter}${originalPath ?? ''}`
    process.env.AUDIT_REAL_GIT = realGit

    assert.throws(
      () => auditCore.readBoundedAuditGitBlob(root, blob),
      /identity|digest|object/i,
    )
  } finally {
    if (originalPath === undefined) delete process.env.PATH
    else process.env.PATH = originalPath
    delete process.env.AUDIT_REAL_GIT
    cleanup(root)
    cleanup(tooling)
  }
})

test('bounded Git blob reads aggregate primary and descriptor cleanup failures', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const trackedFds = new Map()
  try {
    initGit(root)
    write(root, 'artifact.txt', 'cleanup\n')
    commitFixture(root, 'cleanup fixture')
    const algorithm = execFileSync(
      'git',
      ['-C', root, 'rev-parse', '--show-object-format'],
      { encoding: 'utf8' },
    ).trim()
    const missing = `git-${algorithm}:${'f'.repeat(algorithm === 'sha1' ? 40 : 64)}`

    fs.openSync = function trackingGitCapabilityOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      let real = ''
      try {
        real = fs.realpathSync(`/proc/self/fd/${fd}`)
      } catch {
        // Non-directory descriptors are irrelevant.
      }
      if (real === root || real === path.join(root, '.git')) {
        trackedFds.set(fd, real === root ? 'root' : 'git-admin')
      }
      return fd
    }
    fs.closeSync = function failingGitCapabilityClose(fd) {
      const kind = trackedFds.get(fd)
      const result = originalClose.call(fs, fd)
      if (kind) throw new Error(`injected Git ${kind} close failure`)
      return result
    }

    let failure
    try {
      auditCore.readBoundedAuditGitBlob(root, missing)
    } catch (error) {
      failure = error
    }
    assert.ok(failure instanceof AggregateError)
    const messages = flattenedErrorMessages(failure)
    assert.ok(messages.some((message) => /missing|unavailable|object/i.test(message)))
    assert.ok(messages.includes('injected Git root close failure'))
    assert.ok(messages.includes('injected Git git-admin close failure'))
    assert.equal(trackedFds.size, 2)
    for (const fd of trackedFds.keys()) {
      assert.throws(
        () => fs.fstatSync(fd),
        (error) => error?.code === 'EBADF',
        'Git capability descriptor leaked after cleanup failure',
      )
    }
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    for (const fd of trackedFds.keys()) {
      try {
        originalClose.call(fs, fd)
      } catch {
        // Assertions above require every tracked descriptor to be closed.
      }
    }
    cleanup(root)
  }
})

test('bounded audit directory listing is descriptor-anchored, sorted, complete, and bounded', () => {
  const root = makeRoot()
  const outside = makeRoot()
  try {
    assert.deepEqual(
      auditCore.listBoundedAuditDirectory(root, '.atlas/audits'),
      [],
    )
    write(root, '.atlas/audits/z.json', '{}\n')
    write(root, '.atlas/audits/a.txt', 'malformed\n')
    write(root, '.atlas/audits/-option', 'option-like\n')
    write(root, '.atlas/audits/line\nbreak', 'newline\n')
    write(root, '.atlas/audits/ä.json', '{}\n')
    fs.symlinkSync(
      path.join(outside, 'missing.json'),
      path.join(root, '.atlas/audits/link.json'),
    )
    assert.deepEqual(
      auditCore.listBoundedAuditDirectory(root, '.atlas/audits'),
      ['-option', 'a.txt', 'line\nbreak', 'link.json', 'z.json', 'ä.json'],
    )
    assert.throws(
      () => auditCore.listBoundedAuditDirectory(root, '.atlas/audits', 2),
      /directory|entry|limit|2/i,
    )
    assert.throws(
      () => auditCore.listBoundedAuditDirectory(root, '../outside'),
      /normalized|relative|path/i,
    )
    for (const invalid of [-1, Number.MAX_SAFE_INTEGER + 1, 1.5]) {
      assert.throws(
        () => auditCore.listBoundedAuditDirectory(root, '.atlas/audits', invalid),
        /nonnegative|safe integer|limit/i,
      )
    }

    const rawName = Buffer.concat([
      Buffer.from(`${path.join(root, '.atlas/audits')}${path.sep}`),
      Buffer.from([0xff]),
    ])
    fs.writeFileSync(rawName, 'non-UTF8\n')
    assert.throws(
      () => auditCore.listBoundedAuditDirectory(root, '.atlas/audits'),
      /UTF-8|filename|entry name/i,
    )
  } finally {
    cleanup(root)
    cleanup(outside)
  }
})

test('bounded audit directory listing aggregates primary and descriptor cleanup failures', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const originalOpendir = fs.opendirSync
  const trackedFds = new Map()
  try {
    write(root, '.atlas/audits/a.json', '{}\n')
    fs.openSync = function trackingListedDirectoryOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      let real = ''
      try {
        real = fs.realpathSync(`/proc/self/fd/${fd}`)
      } catch {
        // Non-directory descriptors are irrelevant.
      }
      if (
        real === root ||
        real === path.join(root, '.atlas') ||
        real === path.join(root, '.atlas/audits')
      ) {
        trackedFds.set(fd, real === root ? 'root' : path.basename(real))
      }
      return fd
    }
    fs.opendirSync = function failingAnchoredDirectoryRead(file, ...rest) {
      const directory = originalOpendir.call(fs, file, ...rest)
      if (
        String(file).startsWith('/proc/self/fd/') &&
        fs.realpathSync(String(file)) === path.join(root, '.atlas/audits')
      ) {
        directory.readSync = function failingDirectoryRead() {
          throw new Error('injected audit directory listing failure')
        }
        const close = directory.closeSync.bind(directory)
        directory.closeSync = function failingDirectoryIteratorClose() {
          close()
          throw new Error('injected audit directory iterator close failure')
        }
      }
      return directory
    }
    fs.closeSync = function failingListedDirectoryClose(fd) {
      const label = trackedFds.get(fd)
      const result = originalClose.call(fs, fd)
      if (label) throw new Error(`injected ${label} directory close failure`)
      return result
    }

    let failure
    try {
      auditCore.listBoundedAuditDirectory(root, '.atlas/audits')
    } catch (error) {
      failure = error
    }
    assert.ok(failure instanceof AggregateError)
    const messages = flattenedErrorMessages(failure)
    assert.ok(messages.includes('injected audit directory listing failure'))
    assert.ok(messages.includes('injected audit directory iterator close failure'))
    assert.ok(messages.some((message) => /audits directory close failure/.test(message)))
    assert.ok(messages.some((message) => /\.atlas directory close failure/.test(message)))
    assert.ok(messages.some((message) => /root directory close failure/.test(message)))
    assert.equal(trackedFds.size, 3)
    for (const fd of trackedFds.keys()) {
      assert.throws(
        () => fs.fstatSync(fd),
        (error) => error?.code === 'EBADF',
        'audit directory descriptor leaked after cleanup failure',
      )
    }
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    fs.opendirSync = originalOpendir
    for (const fd of trackedFds.keys()) {
      try {
        originalClose.call(fs, fd)
      } catch {
        // Assertions above require all descriptors to be closed.
      }
    }
    cleanup(root)
  }
})

test('bounded audit directory listing rejects symlink and replacement races', () => {
  const root = makeRoot()
  const outside = makeRoot()
  const originalOpendir = fs.opendirSync
  const directory = path.join(root, '.atlas/audits')
  const parked = path.join(root, '.atlas/audits-parked')
  try {
    fs.mkdirSync(path.join(root, '.atlas'), { recursive: true })
    fs.symlinkSync(outside, directory)
    assert.throws(
      () => auditCore.listBoundedAuditDirectory(root, '.atlas/audits'),
      /symlink|safe|directory/i,
    )
    fs.unlinkSync(directory)
    write(root, '.atlas/audits/original.json', '{}\n')
    let swapped = false
    fs.opendirSync = function swappingListedDirectory(file, ...rest) {
      if (
        !swapped &&
        String(file).startsWith('/proc/self/fd/') &&
        (() => {
          try {
            return fs.realpathSync(String(file)) === directory
          } catch {
            return false
          }
        })()
      ) {
        swapped = true
        fs.renameSync(directory, parked)
        fs.mkdirSync(directory)
        fs.writeFileSync(path.join(directory, 'hostile.json'), '{}\n')
      }
      return originalOpendir.call(fs, file, ...rest)
    }
    assert.throws(
      () => auditCore.listBoundedAuditDirectory(root, '.atlas/audits'),
      /directory|parent|changed|identity/i,
    )
    assert.equal(swapped, true)
    assert.deepEqual(fs.readdirSync(directory), ['hostile.json'])
    assert.deepEqual(fs.readdirSync(parked), ['original.json'])
  } finally {
    fs.opendirSync = originalOpendir
    cleanup(root)
    cleanup(outside)
  }
})

test('bounded audit directory listing reads incrementally and stops at hard bounds', () => {
  const root = makeRoot()
  const originalOpendir = fs.opendirSync
  const originalReaddir = fs.readdirSync
  let opendirCalls = 0
  let readCalls = 0
  try {
    write(root, '.atlas/audits/a.json', '{}\n')
    write(root, '.atlas/audits/b.json', '{}\n')
    write(root, '.atlas/audits/c.json', '{}\n')
    fs.readdirSync = function rejectingFullDirectoryAllocation(file, ...rest) {
      if (
        String(file).startsWith('/proc/self/fd/') &&
        fs.realpathSync(String(file)) === path.join(root, '.atlas/audits')
      ) {
        throw new Error('full audit directory allocation is forbidden')
      }
      return originalReaddir.call(fs, file, ...rest)
    }
    fs.opendirSync = function trackingIncrementalDirectoryRead(file, ...rest) {
      const directory = originalOpendir.call(fs, file, ...rest)
      if (
        String(file).startsWith('/proc/self/fd/') &&
        fs.realpathSync(String(file)) === path.join(root, '.atlas/audits')
      ) {
        opendirCalls += 1
        const read = directory.readSync.bind(directory)
        directory.readSync = function countedDirectoryRead() {
          readCalls += 1
          return read()
        }
      }
      return directory
    }
    assert.throws(
      () => auditCore.listBoundedAuditDirectory(root, '.atlas/audits', 2),
      /directory|entry|limit|2/i,
    )
    assert.equal(opendirCalls, 1)
    assert.equal(readCalls, 3, 'listing must stop immediately at entryLimit + 1')
  } finally {
    fs.opendirSync = originalOpendir
    fs.readdirSync = originalReaddir
    cleanup(root)
  }
})

test('bounded audit directory listing enforces aggregate name bounds while streaming', () => {
  const root = makeRoot()
  const originalOpendir = fs.opendirSync
  let readCalls = 0
  try {
    write(root, '.atlas/audits/seed', 'seed\n')
    fs.opendirSync = function syntheticLargeDirectoryRead(file, ...rest) {
      const directory = originalOpendir.call(fs, file, ...rest)
      if (
        String(file).startsWith('/proc/self/fd/') &&
        fs.realpathSync(String(file)) === path.join(root, '.atlas/audits')
      ) {
        directory.readSync = function largeSyntheticDirectoryRead() {
          readCalls += 1
          return {
            name: Buffer.alloc(auditCore.AUDIT_LIMITS.textCodeUnits, 0x61),
          }
        }
      }
      return directory
    }
    assert.throws(
      () => auditCore.listBoundedAuditDirectory(root, '.atlas/audits'),
      /aggregate|string|text|name|byte|limit/i,
    )
    assert.ok(readCalls > 1)
    assert.ok(readCalls < 100, 'aggregate bound must fail before unbounded allocation')
  } finally {
    fs.opendirSync = originalOpendir
    cleanup(root)
  }
})

test('bounded audit directory listing closes a child opened before verification failure', () => {
  const root = makeRoot()
  const originalOpen = fs.openSync
  const originalClose = fs.closeSync
  const originalRealpath = fs.realpathSync
  const trackedFds = new Map()
  const auditsPath = path.join(root, '.atlas/audits')
  let injected = false
  try {
    write(root, '.atlas/audits/a.json', '{}\n')
    fs.openSync = function trackingDirectoryOpen(file, flags, ...rest) {
      const fd = originalOpen.call(fs, file, flags, ...rest)
      let real = ''
      try {
        real = originalRealpath.call(fs, `/proc/self/fd/${fd}`)
      } catch {
        // Non-directory descriptors are irrelevant.
      }
      if (
        real === root ||
        real === path.join(root, '.atlas') ||
        real === auditsPath
      ) {
        trackedFds.set(fd, real)
      }
      return fd
    }
    fs.realpathSync = function failingPostOpenDirectoryVerification(file, ...rest) {
      if (!injected && file === auditsPath) {
        const auditsWasOpened = [...trackedFds.values()].includes(auditsPath)
        if (auditsWasOpened) {
          injected = true
          throw new Error('injected post-open audit directory verification failure')
        }
      }
      return originalRealpath.call(fs, file, ...rest)
    }
    fs.closeSync = function failingOpenedChildClose(fd) {
      const real = trackedFds.get(fd)
      const result = originalClose.call(fs, fd)
      if (real === auditsPath) {
        throw new Error('injected opened child directory close failure')
      }
      return result
    }

    let failure
    try {
      auditCore.listBoundedAuditDirectory(root, '.atlas/audits')
    } catch (error) {
      failure = error
    }
    assert.equal(injected, true)
    assert.ok(failure instanceof AggregateError)
    const messages = flattenedErrorMessages(failure)
    assert.ok(
      messages.some((message) =>
        /post-open audit directory verification failure|changed or is no longer safe/.test(message)
      ),
    )
    assert.ok(messages.includes('injected opened child directory close failure'))
    assert.equal(trackedFds.size, 3)
    for (const fd of trackedFds.keys()) {
      assert.throws(
        () => fs.fstatSync(fd),
        (error) => error?.code === 'EBADF',
        'opened-but-unadopted directory descriptor leaked',
      )
    }
  } finally {
    fs.openSync = originalOpen
    fs.closeSync = originalClose
    fs.realpathSync = originalRealpath
    for (const fd of trackedFds.keys()) {
      try {
        originalClose.call(fs, fd)
      } catch {
        // Assertions above require all descriptors to be closed.
      }
    }
    cleanup(root)
  }
})

test('bounded audit directory listing rejects a missing directory created before linearization', () => {
  const root = makeRoot()
  const originalLstat = fs.lstatSync
  try {
    fs.mkdirSync(path.join(root, '.atlas'))
    let injected = false
    fs.lstatSync = function creatingMissingAuditDirectory(file, options, ...rest) {
      const result = originalLstat.call(fs, file, options, ...rest)
      if (
        !injected &&
        result === undefined &&
        String(file).startsWith('/proc/self/fd/') &&
        String(file).endsWith('/audits')
      ) {
        injected = true
        fs.mkdirSync(path.join(root, '.atlas/audits'))
        fs.writeFileSync(path.join(root, '.atlas/audits/appeared.json'), '{}\n')
      }
      return result
    }
    assert.throws(
      () => auditCore.listBoundedAuditDirectory(root, '.atlas/audits'),
      /appeared|changed|race|directory/i,
    )
    assert.equal(injected, true)
  } finally {
    fs.lstatSync = originalLstat
    cleanup(root)
  }
})
