import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

import { attentionStatePath } from '../dist/attention.js'
import { serve } from '../dist/serve.js'
import { cleanup, commitAll, makeRepo, write } from './helpers.mjs'

async function start(root) {
  const server = serve(root, { exclude: [] }, 0)
  if (!server.listening) await new Promise((resolve) => server.once('listening', resolve))
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  return { server, base: `http://127.0.0.1:${address.port}` }
}

async function close(server) {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
}

async function json(response) {
  const body = await response.text()
  return body ? JSON.parse(body) : null
}

test('live attention endpoint persists reviews and rejects stale or invalid actions', async () => {
  const root = makeRepo()
  let running = null
  try {
    write(root, 'src/runtime.ts', 'export const runtime = 1\n')
    commitAll(root, 'source baseline')
    const anchor = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
    write(root, '.atlas/concepts/runtime.md', `---
title: Runtime
audience: dev
sources: ["src/runtime.ts"]
sources_hash: stale
anchor: ${anchor}
stamped: 2026-07-20T00:00:00.000Z
---
Runtime orientation.
`)
    write(root, 'src/runtime.ts', 'export const runtime = 2\n')
    commitAll(root, 'runtime changes')

    running = await start(root)
    const first = await json(await fetch(`${running.base}/data`))
    assert.equal(first.attention.mode, 'live')
    assert.equal(first.attention.state, 'ready')
    assert.equal(first.attention.items[0].workflow, 'open')
    assert.deepEqual(first.attention.items[0].changedPaths, ['src/runtime.ts'])
    const snapshot = first.attention.items[0].snapshot

    const wrongType = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: '{}',
    })
    assert.equal(wrongType.status, 415)

    const missingNote = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'runtime', snapshot, action: 'understood' }),
    })
    assert.equal(missingNote.status, 400)

    const stale = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'runtime', snapshot: 'f'.repeat(64), action: 'acknowledged' }),
    })
    assert.equal(stale.status, 409)

    const unknown = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'unknown', snapshot, action: 'acknowledged' }),
    })
    assert.equal(unknown.status, 400)

    const reviewedResponse = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        slug: 'runtime',
        snapshot,
        action: 'understood',
        note: 'Runtime now exports the second scheduler generation.',
      }),
    })
    assert.equal(reviewedResponse.status, 200)
    const reviewed = await json(reviewedResponse)
    assert.equal(reviewed.items[0].workflow, 'done')
    assert.equal(reviewed.events.at(-1).outcome, 'understood')

    await close(running.server)
    running = null
    running = await start(root)
    const restarted = await json(await fetch(`${running.base}/data`))
    assert.equal(restarted.attention.items[0].workflow, 'done')
    assert.equal(restarted.attention.summary.history, 1)
    assert.equal(restarted.attention.events[0].note, 'Runtime now exports the second scheduler generation.')
  } finally {
    if (running) await close(running.server)
    cleanup(root)
  }
})

test('live attention fails closed without overwriting malformed local state', async () => {
  const root = makeRepo()
  let running = null
  try {
    write(root, 'src/runtime.ts', 'export const runtime = 1\n')
    write(root, '.atlas/concepts/runtime.md', `---
title: Runtime
audience: dev
sources: ["src/runtime.ts"]
---
Runtime orientation.
`)
    commitAll(root)
    const stateFile = attentionStatePath(root)
    fs.mkdirSync(path.dirname(stateFile), { recursive: true })
    fs.writeFileSync(stateFile, '{malformed\n')

    running = await start(root)
    const data = await json(await fetch(`${running.base}/data`))
    assert.equal(data.attention.mode, 'live')
    assert.equal(data.attention.state, 'invalid')
    assert.equal(data.attention.diagnostics[0].code, 'invalid-json')

    const response = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        slug: 'runtime',
        snapshot: data.attention.items[0].snapshot,
        action: 'acknowledged',
      }),
    })
    assert.equal(response.status, 409)
    assert.equal(fs.readFileSync(stateFile, 'utf8'), '{malformed\n')
  } finally {
    if (running) await close(running.server)
    cleanup(root)
  }
})
