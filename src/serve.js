import http from 'node:http'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { scan, headCommit } from './scan.js'
import { computeStatus } from './status.js'
import { buildHtml } from './build.js'

const LIVE_SNIPPET = `<script>
new EventSource('/events').addEventListener('reload', () => location.reload());
</script>`

const POLL_MS = 1500

/**
 * Dev server: rebuilds the atlas on every request (a full scan is ~100ms even on
 * thousands of files) and pushes an SSE reload whenever the working tree or the
 * notes ledger changes. No bundler — the viewer is a single self-contained page.
 */
export function serve(root, config, port) {
  const render = () => {
    const status = computeStatus(root, scan(root, config))
    const html = buildHtml({ repoName: path.basename(root), commit: headCommit(root), status })
    const digest = createHash('sha1')
      .update(JSON.stringify(status.entries) + JSON.stringify(status.orphans))
      .digest('hex')
    return { html: html.replace('</body>', LIVE_SNIPPET + '</body>'), digest }
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

  server.listen(port, '127.0.0.1', () => {
    console.log(`atlas dev server: http://localhost:${port}`)
    console.log(`watching ${root} (working tree + .atlas/notes) — auto-reloads on change`)
  })
  return server
}
