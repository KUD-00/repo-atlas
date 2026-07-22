import assert from 'node:assert/strict'
import { execFileSync, spawn, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  ATTENTION_EVENT_LIMIT,
  applyAttentionAction,
  applyStoredAttentionAction,
  attentionStatePath,
  emptyAttentionState,
  loadAttentionState,
  reconcileAttention,
  reconcileStoredAttention,
  saveAttentionState,
  updateAttentionState,
} from '../dist/attention.js'
import { cleanup, commitAll, makeRepo, write } from './helpers.mjs'

const NOW = '2026-07-22T10:00:00.000Z'
const LATER = '2026-07-22T11:00:00.000Z'

function concept(overrides = {}) {
  return {
    slug: 'runtime',
    title: 'Runtime',
    audience: 'dev',
    chapter: 'Core',
    status: 'outdated',
    sources: ['src/runtime.ts'],
    currentSourcesHash: '1'.repeat(40),
    snapshot: 'a'.repeat(64),
    brokenSources: [],
    stamped: '2026-07-20T00:00:00.000Z',
    anchor: '1234567890abcdef',
    file: '/repo/.atlas/concepts/runtime.md',
    body: 'Runtime.',
    ...overrides,
  }
}

function subject(state, slug = 'runtime') {
  const found = state.concepts[slug]
  assert.ok(found, `missing attention state for ${slug}`)
  return found
}

function actionFor(state, current, action, overrides = {}) {
  return {
    slug: current.slug,
    snapshot: current.snapshot,
    revision: subject(state, current.slug).revision,
    action,
    ...overrides,
  }
}

test('attention reconciliation starts only stale concepts open', () => {
  const stale = concept()
  const fresh = concept({ slug: 'identity', title: 'Identity', status: 'fresh', snapshot: 'b'.repeat(64) })

  const result = reconcileAttention(emptyAttentionState(), [stale, fresh], NOW)

  assert.equal(result.changed, true)
  assert.equal(subject(result.state).workflow, 'open')
  assert.equal(subject(result.state).revision, 1)
  assert.equal(subject(result.state).firstSeenAt, NOW)
  assert.equal(subject(result.state, 'identity').workflow, 'done')
  assert.deepEqual(result.state.events, [])
})

test('attention state treats prototype-shaped concept slugs as ordinary keys', () => {
  const unusual = concept({ slug: '__proto__' })
  const result = reconcileAttention(emptyAttentionState(), [unusual], NOW)

  assert.equal(Object.hasOwn(result.state.concepts, '__proto__'), true)
  assert.equal(subject(result.state, '__proto__').workflow, 'open')
  assert.deepEqual(result.state.events, [])
})

test('human completion survives document staleness but a new snapshot reopens it', () => {
  const current = concept()
  const initial = reconcileAttention(emptyAttentionState(), [current], NOW).state
  const reviewed = applyAttentionAction(initial, [current], actionFor(initial, current, 'understood', {
    note: 'The scheduler now leases jobs before dispatch.',
  }), LATER)

  const unchanged = reconcileAttention(reviewed, [current], '2026-07-22T12:00:00.000Z')
  assert.equal(unchanged.changed, false)
  assert.equal(subject(unchanged.state).workflow, 'done')
  assert.equal(subject(unchanged.state).lastOutcome, 'understood')
  assert.equal(subject(unchanged.state).revision, 2)

  const next = concept({ snapshot: 'c'.repeat(64), currentSourcesHash: '2'.repeat(40) })
  const reopened = reconcileAttention(reviewed, [next], '2026-07-22T13:00:00.000Z')
  assert.equal(subject(reopened.state).workflow, 'open')
  assert.equal(subject(reopened.state).snapshot, next.snapshot)
  assert.equal(subject(reopened.state).lastOutcome, undefined)
  assert.equal(subject(reopened.state).revision, 3)
  assert.equal(reopened.state.events.at(-1).type, 'source-reopened')
  assert.equal(reopened.state.events.at(-1).snapshot, next.snapshot)
})

test('attention outcomes retain epistemic strength and validate explanatory notes', () => {
  const current = concept()
  const state = reconcileAttention(emptyAttentionState(), [current], NOW).state

  const acknowledged = applyAttentionAction(state, [current], actionFor(state, current, 'acknowledged'), LATER)
  assert.equal(subject(acknowledged).workflow, 'done')
  assert.equal(subject(acknowledged).lastOutcome, 'acknowledged')
  assert.equal(acknowledged.events.at(-1).outcome, 'acknowledged')

  assert.throws(() => applyAttentionAction(state, [current], actionFor(state, current, 'understood', {
    note: '   ',
  }), LATER), /note/i)
  assert.throws(() => applyAttentionAction(
    state, [current], actionFor(state, current, 'decided'), LATER,
  ), /note/i)
  assert.throws(() => applyAttentionAction(state, [current], actionFor(state, current, 'acknowledged', {
    note: 'x'.repeat(10_001),
  }), LATER), /10,000/)
})

test('same-snapshot stale tabs cannot replace a newer human outcome', () => {
  const current = concept()
  const state = reconcileAttention(emptyAttentionState(), [current], NOW).state
  const staleRequest = actionFor(state, current, 'acknowledged')
  const understood = applyAttentionAction(state, [current], actionFor(state, current, 'understood', {
    note: 'The scheduler now leases jobs before dispatch.',
  }), LATER)

  assert.throws(
    () => applyAttentionAction(understood, [current], staleRequest, '2026-07-22T12:00:00.000Z'),
    /revision/i,
  )
  assert.equal(subject(understood).workflow, 'done')
  assert.equal(subject(understood).lastOutcome, 'understood')
  assert.equal(understood.events.length, 1)
})

test('snooze reopens once at expiry and stale-tab actions fail closed', () => {
  const current = concept()
  const state = reconcileAttention(emptyAttentionState(), [current], NOW).state
  const snoozed = applyAttentionAction(state, [current], actionFor(state, current, 'snooze', {
    until: '2026-07-23T10:00:00.000Z',
  }), LATER)

  assert.equal(subject(snoozed).workflow, 'snoozed')
  assert.equal(subject(snoozed).snoozedUntil, '2026-07-23T10:00:00.000Z')
  const before = reconcileAttention(snoozed, [current], '2026-07-23T09:59:59.000Z')
  assert.equal(before.changed, false)
  assert.equal(subject(before.state).workflow, 'snoozed')

  const expired = reconcileAttention(snoozed, [current], '2026-07-23T10:00:00.000Z')
  assert.equal(expired.changed, true)
  assert.equal(subject(expired.state).workflow, 'open')
  assert.equal(expired.state.events.at(-1).type, 'reopened')
  assert.equal(
    reconcileAttention(expired.state, [current], '2026-07-23T10:00:01.000Z').changed,
    false,
  )

  assert.throws(() => applyAttentionAction(state, [current], {
    ...actionFor(state, current, 'acknowledged'),
    snapshot: 'f'.repeat(64),
  }, LATER), /snapshot/i)
  assert.throws(() => applyAttentionAction(state, [current], {
    ...actionFor(state, current, 'acknowledged'),
    slug: 'unknown',
  }, LATER), /unknown concept/i)
  assert.throws(() => applyAttentionAction(state, [current], actionFor(state, current, 'snooze', {
    until: '2026-07-22T10:30:00.000Z',
  }), LATER), /future/i)
})

test('attention history refuses overflow instead of discarding receipts', () => {
  const current = concept()
  const base = reconcileAttention(emptyAttentionState(), [current], NOW).state
  const event = {
    id: 'event',
    slug: current.slug,
    snapshot: current.snapshot,
    type: 'reviewed',
    at: NOW,
    outcome: 'acknowledged',
  }
  const full = { ...base, events: Array.from({ length: ATTENTION_EVENT_LIMIT }, (_, i) => ({ ...event, id: `event-${i}` })) }
  assert.throws(() => applyAttentionAction(
    full, [current], actionFor(full, current, 'acknowledged'), LATER,
  ), /history capacity/i)
  assert.equal(full.events.length, ATTENTION_EVENT_LIMIT)
})

test('attention store lives in worktree-local Git metadata and round-trips atomically', () => {
  const root = makeRepo()
  try {
    const gitPath = path.resolve(root, execFileSync('git', ['rev-parse', '--git-path', 'repo-atlas/attention-v1.json'], {
      cwd: root,
      encoding: 'utf8',
    }).trim())
    const file = attentionStatePath(root)
    assert.equal(file, gitPath)
    assert.equal(file.includes(`${path.sep}.atlas${path.sep}`), false)

    const current = concept()
    const state = reconcileAttention(emptyAttentionState(), [current], NOW).state
    saveAttentionState(root, state)
    const loaded = loadAttentionState(root)

    assert.deepEqual(loaded.diagnostics, [])
    assert.deepEqual(loaded.state, state)
    assert.equal(fs.statSync(file).mode & 0o777, 0o600)
    assert.deepEqual(
      fs.readdirSync(path.dirname(file)).filter((name) => name.includes('.tmp-')),
      [],
    )
  } finally {
    cleanup(root)
  }
})

test('attention store reports directory fsync I/O failures instead of claiming durability', () => {
  const root = makeRepo()
  const originalFsync = fs.fsyncSync
  try {
    const current = concept()
    const state = reconcileAttention(emptyAttentionState(), [current], NOW).state
    fs.fsyncSync = (fd) => {
      if (fs.fstatSync(fd).isDirectory()) {
        throw Object.assign(new Error('injected directory fsync failure'), { code: 'EIO' })
      }
      return originalFsync(fd)
    }
    assert.throws(() => saveAttentionState(root, state), /injected directory fsync failure/)

    fs.fsyncSync = (fd) => {
      if (fs.fstatSync(fd).isDirectory()) {
        throw Object.assign(new Error('directory fsync unsupported'), { code: 'EINVAL' })
      }
      return originalFsync(fd)
    }
    assert.doesNotThrow(() => saveAttentionState(root, state))
  } finally {
    fs.fsyncSync = originalFsync
    cleanup(root)
  }
})

test('a nonregular attention lock fails closed without blocking or replacing it', {
  skip: process.platform === 'win32',
}, () => {
  const root = makeRepo()
  try {
    const lock = `${attentionStatePath(root)}.lock`
    fs.mkdirSync(path.dirname(lock), { recursive: true })
    execFileSync('mkfifo', [lock])
    const moduleUrl = new URL('../dist/attention.js', import.meta.url).href
    const source = `
      import { reconcileStoredAttention } from ${JSON.stringify(moduleUrl)}
      const [root, conceptsJson] = process.argv.slice(1)
      try {
        reconcileStoredAttention(root, JSON.parse(conceptsJson), ${JSON.stringify(NOW)})
        process.exitCode = 2
      } catch (error) {
        if (error?.name !== 'AttentionConflictError') throw error
      }
    `
    const result = spawnSync(process.execPath, [
      '--input-type=module', '-e', source, root, JSON.stringify([concept()]),
    ], { encoding: 'utf8', timeout: 3_000 })

    assert.equal(result.status, 0, result.stderr || result.error?.message)
    assert.equal(fs.lstatSync(lock).isFIFO(), true)
  } finally {
    cleanup(root)
  }
})

test('linked worktrees keep independent current-snapshot state', () => {
  const root = makeRepo()
  const linked = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-linked-'))
  fs.rmSync(linked, { recursive: true })
  try {
    write(root, 'src/runtime.ts', 'export const runtime = 1\n')
    commitAll(root)
    execFileSync('git', ['worktree', 'add', '-q', '-b', 'linked-attention-test', linked], { cwd: root })

    assert.notEqual(attentionStatePath(root), attentionStatePath(linked))

    const mainConcept = concept({ snapshot: 'a'.repeat(64) })
    const linkedConcept = concept({ snapshot: 'b'.repeat(64) })
    const mainState = reconcileStoredAttention(root, [mainConcept], NOW).state
    const linkedState = reconcileStoredAttention(linked, [linkedConcept], NOW).state

    assert.equal(subject(mainState).snapshot, mainConcept.snapshot)
    assert.equal(subject(linkedState).snapshot, linkedConcept.snapshot)
    assert.equal(loadAttentionState(root).state.events.length, 0)
    assert.equal(loadAttentionState(linked).state.events.length, 0)
  } finally {
    fs.rmSync(linked, { recursive: true, force: true })
    cleanup(root)
  }
})

test('cross-process state transactions preserve receipts for different concepts', async () => {
  const root = makeRepo()
  const ready = path.join(root, 'transaction-ready')
  const actorReady = path.join(root, 'actor-ready')
  const release = path.join(root, 'transaction-release')
  let holder = null
  let actor = null
  try {
    const runtime = concept()
    const identity = concept({ slug: 'identity', title: 'Identity', snapshot: 'b'.repeat(64) })
    const concepts = [runtime, identity]
    const initial = reconcileStoredAttention(root, concepts, NOW).state
    const runtimeRequest = actionFor(initial, runtime, 'understood', { note: 'Runtime understood.' })
    const identityRequest = actionFor(initial, identity, 'decided', { note: 'Identity decision.' })
    const moduleUrl = new URL('../dist/attention.js', import.meta.url).href
    const holderSource = `
      import fs from 'node:fs'
      import { applyAttentionAction, updateAttentionState } from ${JSON.stringify(moduleUrl)}
      const [root, ready, release, conceptsJson, requestJson] = process.argv.slice(1)
      const concepts = JSON.parse(conceptsJson)
      const request = JSON.parse(requestJson)
      updateAttentionState(root, (state) => {
        fs.writeFileSync(ready, 'ready')
        const waiter = new Int32Array(new SharedArrayBuffer(4))
        while (!fs.existsSync(release)) Atomics.wait(waiter, 0, 0, 5)
        return applyAttentionAction(state, concepts, request, ${JSON.stringify(LATER)})
      })
    `
    const actorSource = `
      import fs from 'node:fs'
      import { applyStoredAttentionAction } from ${JSON.stringify(moduleUrl)}
      const [root, ready, conceptsJson, requestJson] = process.argv.slice(1)
      fs.writeFileSync(ready, 'ready')
      applyStoredAttentionAction(root, JSON.parse(conceptsJson), JSON.parse(requestJson), ${JSON.stringify(LATER)})
    `
    holder = spawn(process.execPath, [
      '--input-type=module', '-e', holderSource,
      root, ready, release, JSON.stringify(concepts), JSON.stringify(runtimeRequest),
    ], { stdio: ['ignore', 'ignore', 'pipe'] })

    const deadline = Date.now() + 2_000
    while (!fs.existsSync(ready) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 5))
    }
    assert.equal(fs.existsSync(ready), true, 'first process did not acquire the state transaction')

    actor = spawn(process.execPath, [
      '--input-type=module', '-e', actorSource,
      root, actorReady, JSON.stringify(concepts), JSON.stringify(identityRequest),
    ], { stdio: ['ignore', 'ignore', 'pipe'] })
    const actorDeadline = Date.now() + 2_000
    while (!fs.existsSync(actorReady) && Date.now() < actorDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 5))
    }
    assert.equal(fs.existsSync(actorReady), true, 'second process did not enter the transaction call')
    await new Promise((resolve) => setTimeout(resolve, 25))
    assert.equal(actor.exitCode, null, 'second process completed without contending on the held lock')
    fs.writeFileSync(release, 'release')

    const waitForChild = (child) => new Promise((resolve, reject) => {
      let stderr = ''
      child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8') })
      if (child.exitCode !== null) {
        child.exitCode === 0 ? resolve() : reject(new Error(`child exited ${child.exitCode}`))
        return
      }
      child.once('error', reject)
      child.once('exit', (code) => code === 0 ? resolve() : reject(new Error(stderr || `child exited ${code}`)))
    })
    await Promise.all([waitForChild(holder), waitForChild(actor)])

    const loaded = loadAttentionState(root).state
    assert.equal(subject(loaded, 'runtime').lastOutcome, 'understood')
    assert.equal(subject(loaded, 'identity').lastOutcome, 'decided')
    assert.deepEqual(loaded.events.map((event) => event.slug).sort(), ['identity', 'runtime'])
  } finally {
    for (const child of [holder, actor]) {
      if (child && child.exitCode === null) child.kill('SIGKILL')
    }
    cleanup(root)
  }
})

test('attention store refuses malformed and symlink state without overwriting it', () => {
  const root = makeRepo()
  try {
    const file = attentionStatePath(root)
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, '{not-json\n')

    const malformed = loadAttentionState(root)
    assert.equal(malformed.state, null)
    assert.equal(malformed.diagnostics[0].code, 'invalid-json')
    assert.equal(fs.readFileSync(file, 'utf8'), '{not-json\n')

    fs.unlinkSync(file)
    const target = path.join(path.dirname(file), 'target.json')
    fs.writeFileSync(target, JSON.stringify(emptyAttentionState()))
    fs.symlinkSync(target, file)
    const linked = loadAttentionState(root)
    assert.equal(linked.state, null)
    assert.equal(linked.diagnostics[0].code, 'unsafe-state-file')
  } finally {
    cleanup(root)
  }
})

test('attention store rejects deeply nested unknown fields instead of preserving them', () => {
  const root = makeRepo()
  try {
    const file = attentionStatePath(root)
    fs.mkdirSync(path.dirname(file), { recursive: true })
    const nested = '{"next":'.repeat(8_000) + 'null' + '}'.repeat(8_000)
    const raw = `{"formatVersion":1,"concepts":{"runtime":{"snapshot":"${'a'.repeat(64)}","revision":1,"workflow":"open","firstSeenAt":"${NOW}"}},"events":[{"id":"deep","slug":"runtime","snapshot":"${'a'.repeat(64)}","type":"reviewed","at":"${NOW}","outcome":"acknowledged","extra":${nested}}]}`
    fs.writeFileSync(file, raw)

    const loaded = loadAttentionState(root)
    assert.equal(loaded.state, null)
    assert.equal(loaded.diagnostics[0].code, 'invalid-state')
  } finally {
    cleanup(root)
  }
})
