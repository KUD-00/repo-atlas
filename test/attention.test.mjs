import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import {
  ATTENTION_EVENT_LIMIT,
  applyAttentionAction,
  attentionStatePath,
  emptyAttentionState,
  loadAttentionState,
  reconcileAttention,
  saveAttentionState,
} from '../dist/attention.js'
import { cleanup, makeRepo } from './helpers.mjs'

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

test('attention reconciliation starts only stale concepts open', () => {
  const stale = concept()
  const fresh = concept({ slug: 'identity', title: 'Identity', status: 'fresh', snapshot: 'b'.repeat(64) })

  const result = reconcileAttention(emptyAttentionState(), [stale, fresh], NOW)

  assert.equal(result.changed, true)
  assert.equal(subject(result.state).workflow, 'open')
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
  const reviewed = applyAttentionAction(initial, [current], {
    slug: current.slug,
    snapshot: current.snapshot,
    action: 'understood',
    note: 'The scheduler now leases jobs before dispatch.',
  }, LATER)

  const unchanged = reconcileAttention(reviewed, [current], '2026-07-22T12:00:00.000Z')
  assert.equal(unchanged.changed, false)
  assert.equal(subject(unchanged.state).workflow, 'done')
  assert.equal(subject(unchanged.state).lastOutcome, 'understood')

  const next = concept({ snapshot: 'c'.repeat(64), currentSourcesHash: '2'.repeat(40) })
  const reopened = reconcileAttention(reviewed, [next], '2026-07-22T13:00:00.000Z')
  assert.equal(subject(reopened.state).workflow, 'open')
  assert.equal(subject(reopened.state).snapshot, next.snapshot)
  assert.equal(subject(reopened.state).lastOutcome, undefined)
  assert.equal(reopened.state.events.at(-1).type, 'source-reopened')
  assert.equal(reopened.state.events.at(-1).snapshot, next.snapshot)
})

test('attention outcomes retain epistemic strength and validate explanatory notes', () => {
  const current = concept()
  const state = reconcileAttention(emptyAttentionState(), [current], NOW).state

  const acknowledged = applyAttentionAction(state, [current], {
    slug: current.slug,
    snapshot: current.snapshot,
    action: 'acknowledged',
  }, LATER)
  assert.equal(subject(acknowledged).workflow, 'done')
  assert.equal(subject(acknowledged).lastOutcome, 'acknowledged')
  assert.equal(acknowledged.events.at(-1).outcome, 'acknowledged')

  assert.throws(() => applyAttentionAction(state, [current], {
    slug: current.slug,
    snapshot: current.snapshot,
    action: 'understood',
    note: '   ',
  }, LATER), /note/i)
  assert.throws(() => applyAttentionAction(state, [current], {
    slug: current.slug,
    snapshot: current.snapshot,
    action: 'decided',
  }, LATER), /note/i)
  assert.throws(() => applyAttentionAction(state, [current], {
    slug: current.slug,
    snapshot: current.snapshot,
    action: 'acknowledged',
    note: 'x'.repeat(10_001),
  }, LATER), /10,000/)
})

test('snooze reopens once at expiry and stale-tab actions fail closed', () => {
  const current = concept()
  const state = reconcileAttention(emptyAttentionState(), [current], NOW).state
  const snoozed = applyAttentionAction(state, [current], {
    slug: current.slug,
    snapshot: current.snapshot,
    action: 'snooze',
    until: '2026-07-23T10:00:00.000Z',
  }, LATER)

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
    slug: current.slug,
    snapshot: 'f'.repeat(64),
    action: 'acknowledged',
  }, LATER), /snapshot/i)
  assert.throws(() => applyAttentionAction(state, [current], {
    slug: 'unknown',
    snapshot: current.snapshot,
    action: 'acknowledged',
  }, LATER), /unknown concept/i)
  assert.throws(() => applyAttentionAction(state, [current], {
    slug: current.slug,
    snapshot: current.snapshot,
    action: 'snooze',
    until: '2026-07-22T10:30:00.000Z',
  }, LATER), /future/i)
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
  assert.throws(() => applyAttentionAction(full, [current], {
    slug: current.slug,
    snapshot: current.snapshot,
    action: 'acknowledged',
  }, LATER), /history capacity/i)
  assert.equal(full.events.length, ATTENTION_EVENT_LIMIT)
})

test('attention store lives in Git metadata and round-trips atomically', () => {
  const root = makeRepo()
  try {
    const common = path.resolve(root, execFileSync('git', ['rev-parse', '--git-common-dir'], {
      cwd: root,
      encoding: 'utf8',
    }).trim())
    const file = attentionStatePath(root)
    assert.equal(file, path.join(common, 'repo-atlas', 'attention-v1.json'))
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
