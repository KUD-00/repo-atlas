import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
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

async function postChunks(url, chunks) {
  return await new Promise((resolve, reject) => {
    const target = new URL(url)
    const request = http.request({
      hostname: target.hostname,
      port: target.port,
      path: target.pathname,
      method: 'POST',
      headers: { 'content-type': 'application/json' },
    }, (response) => {
      const body = []
      response.on('data', (chunk) => body.push(chunk))
      response.on('end', () => resolve({
        status: response.statusCode,
        body: Buffer.concat(body).toString('utf8'),
      }))
    })
    request.on('error', reject)
    request.setNoDelay(true)
    const writeNext = (index) => {
      if (index === chunks.length) {
        request.end()
        return
      }
      request.write(chunks[index])
      setTimeout(() => writeNext(index + 1), 10)
    }
    writeNext(0)
  })
}

function deeplyNestedAttentionState() {
  const snapshot = 'a'.repeat(64)
  const nested = '{"next":'.repeat(8_000) + 'null' + '}'.repeat(8_000)
  return `{"formatVersion":1,"concepts":{"runtime":{"snapshot":"${snapshot}","revision":1,"workflow":"open","firstSeenAt":"2026-07-22T10:00:00.000Z"}},"events":[{"id":"deep","slug":"runtime","snapshot":"${snapshot}","type":"reviewed","at":"2026-07-22T10:00:00.000Z","outcome":"acknowledged","extra":${nested}}]}`
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
    const revision = first.attention.items[0].revision

    const wrongType = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: '{}',
    })
    assert.equal(wrongType.status, 415)

    const missingNote = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'runtime', snapshot, revision, action: 'understood' }),
    })
    assert.equal(missingNote.status, 400)

    const missingRevision = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'runtime', snapshot, action: 'acknowledged' }),
    })
    assert.equal(missingRevision.status, 400)

    const stale = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'runtime', snapshot: 'f'.repeat(64), revision, action: 'acknowledged' }),
    })
    assert.equal(stale.status, 409)

    const unknown = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'unknown', snapshot, revision, action: 'acknowledged' }),
    })
    assert.equal(unknown.status, 400)

    const reviewedResponse = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        slug: 'runtime',
        snapshot,
        revision,
        action: 'understood',
        note: 'Runtime now exports the second scheduler generation.',
      }),
    })
    assert.equal(reviewedResponse.status, 200)
    const reviewed = await json(reviewedResponse)
    assert.equal(reviewed.items[0].workflow, 'done')
    assert.equal(reviewed.events.at(-1).outcome, 'understood')

    const staleWorkflow = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'runtime', snapshot, revision, action: 'acknowledged' }),
    })
    assert.equal(staleWorkflow.status, 409)
    const conflict = await json(staleWorkflow)
    assert.equal(conflict.error, 'attention action workflow revision is stale')
    assert.equal(conflict.attention.items[0].lastOutcome, 'understood')
    assert.equal(conflict.attention.events.length, 1)
    const afterConflict = await json(await fetch(`${running.base}/data`))
    assert.equal(afterConflict.attention.items[0].lastOutcome, 'understood')
    assert.equal(afterConflict.attention.events.length, 1)

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

test('live attention preserves a UTF-8 note split across request chunks', async () => {
  const root = makeRepo()
  let running = null
  try {
    write(root, 'src/runtime.ts', 'export const runtime = 1\n')
    write(root, '.atlas/concepts/runtime.md', `---
title: Runtime
audience: dev
sources: ["src/runtime.ts"]
sources_hash: stale
---
Runtime orientation.
`)
    commitAll(root)
    running = await start(root)
    const first = await json(await fetch(`${running.base}/data`))
    const item = first.attention.items[0]
    const note = '我已理解调度器的租约变化。'
    const encoded = Buffer.from(JSON.stringify({
      slug: item.slug,
      snapshot: item.snapshot,
      revision: item.revision,
      action: 'understood',
      note,
    }))
    const chinese = Buffer.from('理')
    const byteStart = encoded.indexOf(chinese)
    assert.notEqual(byteStart, -1)

    const response = await postChunks(`${running.base}/attention/action`, [
      encoded.subarray(0, byteStart + 1),
      encoded.subarray(byteStart + 1),
    ])
    assert.equal(response.status, 200, response.body)
    const payload = JSON.parse(response.body)
    assert.equal(payload.events.at(-1).note, note)
  } finally {
    if (running) await close(running.server)
    cleanup(root)
  }
})

test('live attention reports persistence I/O failure instead of acknowledging a receipt', async () => {
  const root = makeRepo()
  const originalFsync = fs.fsyncSync
  let running = null
  try {
    write(root, 'src/runtime.ts', 'export const runtime = 1\n')
    write(root, '.atlas/concepts/runtime.md', `---
title: Runtime
audience: dev
sources: ["src/runtime.ts"]
sources_hash: stale
---
Runtime orientation.
`)
    commitAll(root)
    running = await start(root)
    const first = await json(await fetch(`${running.base}/data`))
    const item = first.attention.items[0]
    fs.fsyncSync = (fd) => {
      if (fs.fstatSync(fd).isDirectory()) {
        throw Object.assign(new Error('injected directory fsync failure'), { code: 'EIO' })
      }
      return originalFsync(fd)
    }

    const response = await fetch(`${running.base}/attention/action`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        slug: item.slug,
        snapshot: item.snapshot,
        revision: item.revision,
        action: 'acknowledged',
      }),
    })
    assert.equal(response.status, 500)
    assert.match(await response.text(), /injected directory fsync failure/)
  } finally {
    fs.fsyncSync = originalFsync
    if (running) await close(running.server)
    cleanup(root)
  }
})

test('live attention remains readable when version-1 JSON contains deep unknown fields', async () => {
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
    fs.writeFileSync(stateFile, deeplyNestedAttentionState())

    running = await start(root)
    const response = await fetch(`${running.base}/data`)
    assert.equal(response.status, 200)
    const data = await json(response)
    assert.equal(data.attention.state, 'invalid')
    assert.equal(data.attention.diagnostics[0].code, 'invalid-state')
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
        revision: data.attention.items[0].revision,
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
