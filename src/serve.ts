import fs from 'node:fs'
import http from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { scan, headCommit, hashFor } from './scan.js'
import { loadNotes, writeNoteBody } from './notes.js'
import { computeStatus } from './status.js'
import { buildHtml, buildPayload } from './build.js'
import { buildImportGraph } from './deps.js'
import { loadGlossaryRaw, parseGlossary } from './glossary.js'
import { loadArtifacts } from './artifacts.js'
import type { AtlasConfig, ChatMessage, ScanResult } from './types.js'

const POLL_MS = 1500

const PREVIEW_CAP = 500_000

interface ChatPollSlot {
  resolve: (msg: ChatMessage | { type: 'timeout' }) => void
}

interface ChatState {
  history: ChatMessage[]
  pending: ChatMessage[]
  polls: ChatPollSlot[]
  workingId: string | null
  progress: string | null
}

export function serve(root: string, config: AtlasConfig, port: number, host = '127.0.0.1') {
  let lastScan: ScanResult | null = null

  const render = () => {
    const scanResult = scan(root, config)
    lastScan = scanResult
    const status = computeStatus(root, scanResult)
    const glossaryRaw = loadGlossaryRaw(root)
    const artifacts = loadArtifacts(root)
    const input = {
      repoName: path.basename(root),
      commit: headCommit(root),
      status,
      graph: buildImportGraph(root, scanResult),
      glossary: parseGlossary(glossaryRaw),
      basePoints: config.basePoints ?? [],
      artifacts,
    }
    const payload = buildPayload(input)
    const html = buildHtml({ ...input, payload })
    const digest = createHash('sha1')
      .update(
        JSON.stringify(status.entries) + JSON.stringify(status.orphans) +
        JSON.stringify(status.concepts) + glossaryRaw + JSON.stringify(artifacts),
      )
      .digest('hex')
    return { html, digest, payloadJson: JSON.stringify(payload) }
  }

  const clients = new Set<ServerResponse>()
  let lastDigest = render().digest

  const chat: ChatState = { history: [], pending: [], polls: [], workingId: null, progress: null }
  let chatSeq = 0
  const chatBroadcast = (msg: ChatMessage | { type: string; [key: string]: unknown }) => {
    for (const c of clients) c.write(`event: chat\ndata: ${JSON.stringify(msg)}\n\n`)
  }
  const chatStatus = () => chatBroadcast({
    type: 'status',
    connected: chat.polls.length > 0 || chat.workingId !== null,
    working: chat.workingId !== null,
  })
  const handToAgent = (msg: ChatMessage) => {
    chat.workingId = msg.id
    queueMicrotask(chatStatus)
    return msg
  }

  setInterval(() => {
    if (clients.size === 0) return
    try {
      const { digest } = render()
      if (digest !== lastDigest) {
        lastDigest = digest
        for (const res of clients) res.write('event: reload\ndata: 1\n\n')
      }
    } catch (err) {
      console.error(`watch error: ${err instanceof Error ? err.message : String(err)}`)
    }
  }, POLL_MS)

  const readJson = (req: IncomingMessage, res: ServerResponse, cb: (body: Record<string, unknown>) => void) => {
    let raw = ''
    req.on('data', (chunk) => {
      raw += chunk
      if (raw.length > 2_000_000) req.destroy()
    })
    req.on('end', () => {
      try {
        cb(JSON.parse(raw) as Record<string, unknown>)
      } catch (err) {
        res.writeHead(400, { 'content-type': 'text/plain' }).end(String(err instanceof Error ? err.message : err))
      }
    })
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    const json = { 'content-type': 'application/json', 'cache-control': 'no-store' }

    if (url.pathname === '/chat/history') {
      res.writeHead(200, json)
      res.end(JSON.stringify({
        messages: chat.history,
        connected: chat.polls.length > 0 || chat.workingId !== null,
        working: chat.workingId !== null,
        progress: chat.progress,
      }))
      return
    }
    if (url.pathname === '/chat/progress' && req.method === 'POST') {
      readJson(req, res, ({ text }) => {
        chat.progress = typeof text === 'string' && text.trim() ? text : null
        chatBroadcast({ type: 'progress', text: chat.progress })
        res.writeHead(200, json).end('{}')
      })
      return
    }
    if (url.pathname === '/chat/cancel' && req.method === 'POST') {
      readJson(req, res, ({ id }) => {
        const msg = chat.history.find((m) => m.id === id && m.role === 'user')
        if (!msg || msg.cancelled) {
          res.writeHead(404, { 'content-type': 'text/plain' }).end('no such active message')
          return
        }
        msg.cancelled = true
        const qi = chat.pending.findIndex((m) => m.id === id)
        if (qi >= 0) chat.pending.splice(qi, 1)
        else if (chat.workingId === id) {
          const note: ChatMessage = {
            id: 'm' + ++chatSeq, role: 'user', system: true,
            text: `[the user retracted message ${id} — drop that request and just briefly acknowledge]`,
            time: Date.now(),
          }
          const poll = chat.polls.shift()
          if (poll) poll.resolve(handToAgent(note))
          else chat.pending.push(note)
        }
        chatBroadcast({ type: 'cancelled', id })
        res.writeHead(200, json).end(JSON.stringify({ id }))
      })
      return
    }
    if (url.pathname === '/chat/send' && req.method === 'POST') {
      readJson(req, res, ({ text, context }) => {
        if (typeof text !== 'string' || !text.trim()) {
          res.writeHead(400, { 'content-type': 'text/plain' }).end('expected {text}')
          return
        }
        const msg: ChatMessage = {
          id: 'm' + ++chatSeq, role: 'user', text,
          context: (context as string | null) ?? null, time: Date.now(),
        }
        chat.history.push(msg)
        chatBroadcast(msg)
        const poll = chat.polls.shift()
        if (poll) poll.resolve(handToAgent(msg))
        else chat.pending.push(msg)
        res.writeHead(200, json).end(JSON.stringify({ id: msg.id }))
      })
      return
    }
    if (url.pathname === '/chat/poll') {
      const timeout = Math.min(Number(url.searchParams.get('timeout')) || 270_000, 600_000)
      const next = chat.pending.shift()
      if (next) {
        res.writeHead(200, json).end(JSON.stringify(handToAgent(next)))
        return
      }
      const poll: ChatPollSlot = { resolve: () => {} }
      const drop = () => {
        const i = chat.polls.indexOf(poll)
        if (i >= 0) chat.polls.splice(i, 1)
      }
      const timer = setTimeout(() => {
        drop()
        res.writeHead(200, json).end(JSON.stringify({ type: 'timeout' }))
        chatStatus()
      }, timeout)
      poll.resolve = (msg) => {
        clearTimeout(timer)
        drop()
        res.writeHead(200, json).end(JSON.stringify(msg))
        chatStatus()
      }
      chat.polls.push(poll)
      chatStatus()
      req.on('close', () => {
        clearTimeout(timer)
        drop()
        chatStatus()
      })
      return
    }
    if (url.pathname === '/chat/reply' && req.method === 'POST') {
      readJson(req, res, ({ text, replyTo }) => {
        if (typeof text !== 'string' || !text.trim()) {
          res.writeHead(400, { 'content-type': 'text/plain' }).end('expected {text}')
          return
        }
        const msg: ChatMessage = {
          id: 'm' + ++chatSeq, role: 'agent', text,
          replyTo: (replyTo as string | null) ?? null, time: Date.now(),
        }
        chat.history.push(msg)
        chat.workingId = null
        chat.progress = null
        chatBroadcast(msg)
        chatStatus()
        res.writeHead(200, json).end(JSON.stringify({ id: msg.id }))
      })
      return
    }
    if (url.pathname === '/raw') {
      const p = url.searchParams.get('p') ?? ''
      const known = () => lastScan!.files.has(p) || lastScan!.ignored.has(p)
      if (!lastScan) render()
      if (!known()) lastScan = scan(root, config)
      if (!known()) {
        res.writeHead(404, { 'content-type': 'text/plain' }).end('not in scan')
        return
      }
      try {
        const buf = fs.readFileSync(path.join(root, p))
        const headers: Record<string, string> = {
          'content-type': 'text/plain; charset=utf-8',
          'cache-control': 'no-store',
        }
        if (buf.subarray(0, 8192).includes(0)) {
          headers['x-atlas-binary'] = '1'
          res.writeHead(200, headers).end('')
          return
        }
        let text = buf.toString('utf8')
        if (text.length > PREVIEW_CAP) {
          text = text.slice(0, PREVIEW_CAP)
          headers['x-atlas-truncated'] = '1'
        }
        res.writeHead(200, headers).end(text)
      } catch (err) {
        res.writeHead(500, { 'content-type': 'text/plain' }).end(String(err instanceof Error ? err.message : err))
      }
      return
    }
    if (url.pathname === '/data') {
      // fresh payload for in-place refresh — open pages re-render on change
      // events instead of reloading (scroll, panel modes, tree state survive)
      try {
        const { digest, payloadJson } = render()
        lastDigest = digest
        res.writeHead(200, json).end(payloadJson)
      } catch (err) {
        res.writeHead(500, { 'content-type': 'text/plain' }).end(String(err instanceof Error ? err.message : err))
      }
      return
    }
    if (url.pathname === '/diff') {
      // change-review mode: what happened to this file since the note's anchor
      // commit (= HEAD at stamp time). Working tree included — the review is
      // "note vs code as it is NOW".
      const p = url.searchParams.get('p') ?? ''
      if (!lastScan) render()
      if (!lastScan!.files.has(p)) {
        res.writeHead(404, { 'content-type': 'text/plain' }).end('not in scan')
        return
      }
      const anchor = loadNotes(root).get(p)?.anchor ?? null
      if (!anchor) {
        res.writeHead(200, {
          'content-type': 'text/plain; charset=utf-8',
          'cache-control': 'no-store',
          'x-atlas-no-anchor': '1',
        }).end('')
        return
      }
      const git = spawnSync(
        'git',
        ['diff', '--no-color', '--no-ext-diff', anchor, '--', p],
        { cwd: root, encoding: 'utf8', maxBuffer: 8_000_000 },
      )
      if (git.status !== 0) {
        res.writeHead(500, { 'content-type': 'text/plain' }).end(git.stderr || 'git diff failed')
        return
      }
      res.writeHead(200, {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
        'x-atlas-anchor': anchor.slice(0, 10),
      }).end(git.stdout)
      return
    }
    if (url.pathname === '/live') {
      res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' }).end('ok')
      return
    }
    if (url.pathname === '/note' && req.method === 'POST') {
      let raw = ''
      req.on('data', (chunk) => {
        raw += chunk
        if (raw.length > 2_000_000) req.destroy()
      })
      req.on('end', () => {
        try {
          const { path: p, body } = JSON.parse(raw) as { path?: unknown; body?: unknown }
          if (typeof p !== 'string' || typeof body !== 'string') {
            res.writeHead(400, { 'content-type': 'text/plain' }).end('expected {path, body}')
            return
          }
          const fresh = scan(root, config)
          lastScan = fresh
          const found = hashFor(fresh, p)
          if (!found) {
            res.writeHead(404, { 'content-type': 'text/plain' }).end('path not in scan')
            return
          }
          const file = writeNoteBody(root, p, found.type, body, found.hash)
          const { digest } = render()
          lastDigest = digest
          for (const c of clients) c.write('event: reload\ndata: 1\n\n')
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ file: path.relative(root, file) }))
        } catch (err) {
          res.writeHead(500, { 'content-type': 'text/plain' }).end(String(err instanceof Error ? err.message : err))
        }
      })
      return
    }
    if (req.url === '/events') {
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-store',
        connection: 'keep-alive',
      })
      res.write(': connected\n\n')
      clients.add(res)
      req.on('close', () => clients.delete(res))
      return
    }
    if (req.url === '/' || req.url === '/index.html') {
      try {
        const { html, digest } = render()
        lastDigest = digest
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
        res.end(html)
      } catch (err) {
        res.writeHead(500, { 'content-type': 'text/plain' })
        res.end(String(err instanceof Error ? err.stack : err))
      }
      return
    }
    res.writeHead(404).end('not found')
  })

  server.listen(port, host, () => {
    console.log(`atlas dev server: http://${host === '0.0.0.0' ? 'localhost' : host}:${port}`)
    if (host === '0.0.0.0') {
      const { networkInterfaces } = os
      for (const addrs of Object.values(networkInterfaces())) {
        for (const a of addrs ?? []) {
          if (a.family === 'IPv4' && !a.internal) console.log(`             http://${a.address}:${port}`)
        }
      }
    }
    console.log(`watching ${root} — auto-reloads on change`)
  })
  return server
}