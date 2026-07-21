import assert from 'node:assert/strict'
import test from 'node:test'

import {
  auditLocationJumpDetail,
  parseAuditLocation,
} from '../dist/audit-location.js'

test('audit location parse accepts path, line, and symbol forms; rejects empty/invalid', () => {
  assert.deepEqual(parseAuditLocation('src/a.ts'), { path: 'src/a.ts', line: 1 })
  assert.deepEqual(parseAuditLocation('src/a.ts:12'), { path: 'src/a.ts', line: 12 })
  assert.deepEqual(parseAuditLocation('src/a.ts#symbol'), { path: 'src/a.ts', line: 1 })
  assert.deepEqual(parseAuditLocation('pkg/mod.py:1'), { path: 'pkg/mod.py', line: 1 })
  assert.equal(parseAuditLocation(''), null)
  assert.equal(parseAuditLocation(':12'), null)
  assert.equal(parseAuditLocation('#'), null)
  // whitespace-only path is not a jump target (plan: invalid → null)
  assert.equal(parseAuditLocation('   '), null)
  assert.equal(parseAuditLocation('\t\n'), null)
  // strict positive line: no zero, no leading zeros, no unsafe integers
  assert.equal(parseAuditLocation('src/a.ts:0'), null)
  assert.equal(parseAuditLocation('src/a.ts:01'), null)
  assert.equal(parseAuditLocation('src/a.ts:00'), null)
  assert.equal(parseAuditLocation(`src/a.ts:${BigInt(Number.MAX_SAFE_INTEGER) + 1n}`), null)
})

test('audit location jump detail carries path/line/endLine for atlas-code-jump chips', () => {
  assert.deepEqual(auditLocationJumpDetail('src/a.ts:12'), {
    path: 'src/a.ts',
    line: 12,
    endLine: 12,
  })
  assert.deepEqual(auditLocationJumpDetail('src/a.ts#Symbol'), {
    path: 'src/a.ts',
    line: 1,
    endLine: 1,
  })
  assert.deepEqual(auditLocationJumpDetail('only/path'), {
    path: 'only/path',
    line: 1,
    endLine: 1,
  })
  assert.equal(auditLocationJumpDetail(''), null)
  assert.equal(auditLocationJumpDetail(':nope'), null)
})
