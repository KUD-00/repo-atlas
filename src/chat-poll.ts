#!/usr/bin/env node
// Agent-side driver for the atlas in-viewer chat (see serve.ts /chat/* routes).

const SLICE_MS = 270_000

const args = process.argv.slice(2)
const flag = (name: string) => {
  const i = args.indexOf(name)
  return i >= 0 ? args[i + 1] : null
}
const port = Number(flag('--port') ?? 4400)
const base = `http://127.0.0.1:${port}`

async function main() {
  const progressIdx = args.indexOf('--progress')
  if (progressIdx >= 0) {
    const res = await fetch(`${base}/chat/progress`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: args[progressIdx + 1] ?? '' }),
    })
    if (!res.ok) throw new Error(`progress failed: ${res.status} ${await res.text()}`)
    return
  }

  const replyIdx = args.indexOf('--reply')
  if (replyIdx >= 0) {
    const text = args[replyIdx + 1]
    if (!text) {
      console.error('usage: chat-poll --reply "text" [--to <msgId>]')
      process.exit(1)
    }
    const res = await fetch(`${base}/chat/reply`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text, replyTo: flag('--to') ?? null }),
    })
    if (!res.ok) throw new Error(`reply failed: ${res.status} ${await res.text()}`)
    console.log(await res.text())
    return
  }

  const total = Number(flag('--timeout') ?? 3_600_000)
  const deadline = Date.now() + total
  while (Date.now() < deadline) {
    const slice = Math.min(SLICE_MS, deadline - Date.now())
    let res: Response
    try {
      res = await fetch(`${base}/chat/poll?timeout=${slice}`)
    } catch {
      throw new Error(`no atlas dev server on ${base} — run \`repo-atlas serve\` first`)
    }
    const msg = await res.json() as { type?: string }
    if (msg.type === 'timeout') continue
    console.log(JSON.stringify(msg))
    return
  }
  console.log(JSON.stringify({ type: 'timeout' }))
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err))
  process.exit(1)
})