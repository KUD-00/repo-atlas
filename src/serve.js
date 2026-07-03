import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { scan, headCommit } from './scan.js'
import { computeStatus } from './status.js'
import { buildHtml } from './build.js'
import { buildImportGraph } from './deps.js'
import { loadGlossaryRaw, parseGlossary } from './glossary.js'

const LIVE_SNIPPET = `<script>
new EventSource('/events').addEventListener('reload', () => location.reload());
</script>`

const POLL_MS = 1500

/**
 * Dev server: rebuilds the atlas on every request (a full scan is ~100ms even on
 * thousands of files) and pushes an SSE reload whenever the working tree or the
 * notes ledger changes. No bundler — the viewer is a single self-contained page.
 */
const PREVIEW_CAP = 500_000

export function serve(root, config, port, host = '127.0.0.1') {
  let lastFiles = null

  const render = () => {
    const scanResult = scan(root, config)
    lastFiles = scanResult.files
    const status = computeStatus(root, scanResult)
    const glossaryRaw = loadGlossaryRaw(root)
    const html = buildHtml({
      repoName: path.basename(root),
      commit: headCommit(root),
      status,
      graph: buildImportGraph(root, scanResult),
      glossary: parseGlossary(glossaryRaw),
    })
    const digest = createHash('sha1')
      .update(JSON.stringify(status.entries) + JSON.stringify(status.orphans) + glossaryRaw)
      .digest('hex')
    // inject before the LAST </body> — embedded vendor bundles may contain the
    // literal string "</body>" (mermaid's sanitizer does), and String.replace
    // would splice the snippet into the middle of that script
    const at = html.lastIndexOf('</body>')
    return { html: html.slice(0, at) + LIVE_SNIPPET + html.slice(at), digest }
  }

  const clients = new Set()
  let lastDigest = render().digest

  setInterval(() => {
    if (clients.size === 0) return
    try {
      const { digest } = render()
      if (digest !== lastDigest) {
        lastDigest = digest
        for (const res of clients) res.write('event: reload\ndata: 1\n\n')
      }
    } catch (err) {
      console.error(`watch error: ${err.message}`)
    }
  }, POLL_MS)

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost')
    // raw file contents for the preview pane; only paths present in the scan
    // are served (never arbitrary disk paths)
    if (url.pathname === '/raw') {
      const p = url.searchParams.get('p') ?? ''
      if (!lastFiles) render()
      if (!lastFiles.has(p)) {
        const fresh = scan(root, config).files
        lastFiles = fresh
      }
      if (!lastFiles.has(p)) {
        res.writeHead(404, { 'content-type': 'text/plain' }).end('not in scan')
        return
      }
      try {
        const buf = fs.readFileSync(path.join(root, p))
        const headers = { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }
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
        res.writeHead(500, { 'content-type': 'text/plain' }).end(String(err.message))
      }
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
        res.end(String(err.stack ?? err))
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
    console.log(`watching ${root} (working tree + .atlas/notes) — auto-reloads on change`)
  })
  return server
}
