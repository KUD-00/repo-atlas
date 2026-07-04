import { git } from './scan.js'
import type { MoveRecord, NoteRecord, Orphan, ScanResult, StatusEntry } from './types.js'

function suffixScore(a: string, b: string): number {
  const as = a.split('/')
  const bs = b.split('/')
  let n = 0
  while (n < as.length && n < bs.length && as[as.length - 1 - n] === bs[bs.length - 1 - n]) n++
  return n
}

function pickBest(from: string, candidates: string[]): string {
  return [...candidates].sort((a, b) =>
    suffixScore(from, b) - suffixScore(from, a) || (a < b ? -1 : 1))[0]
}

export function detectMoves(
  root: string,
  scanResult: ScanResult,
  entries: StatusEntry[],
  orphans: Orphan[],
  notes: Map<string, NoteRecord>,
): MoveRecord[] {
  const missingFiles = new Set(
    entries.filter((e) => e.status === 'missing' && e.type === 'file').map((e) => e.path),
  )
  const missingDirs = new Set(
    entries.filter((e) => e.status === 'missing' && e.type === 'dir').map((e) => e.path),
  )
  const orphanFiles = orphans.filter((o) => o.type === 'file')
  const moved: MoveRecord[] = []
  if (orphanFiles.length && missingFiles.size) {
    const byBlob = new Map<string, string[]>()
    for (const p of missingFiles) {
      const h = scanResult.files.get(p)!
      if (!byBlob.has(h)) byBlob.set(h, [])
      byBlob.get(h)!.push(p)
    }
    const claimedTo = new Set<string>()
    const claimedFrom = new Set<string>()

    for (const o of orphanFiles) {
      const note = notes.get(o.path)
      if (!note?.hash) continue
      const candidates = (byBlob.get(note.hash) ?? []).filter((p) => !claimedTo.has(p))
      if (!candidates.length) continue
      const to = pickBest(o.path, candidates)
      moved.push({ from: o.path, to, type: 'file', similarity: 100 })
      claimedTo.add(to)
      claimedFrom.add(o.path)
    }

    const byAnchor = new Map<string, Set<string>>()
    for (const o of orphanFiles) {
      if (claimedFrom.has(o.path)) continue
      const anchor = notes.get(o.path)?.anchor
      if (!anchor) continue
      if (!byAnchor.has(anchor)) byAnchor.set(anchor, new Set())
      byAnchor.get(anchor)!.add(o.path)
    }
    for (const [anchor, fromPaths] of byAnchor) {
      let out: string
      try {
        out = git(root, ['diff', '-M', '--name-status', '--diff-filter=R', anchor])
      } catch {
        continue
      }
      for (const line of out.split('\n')) {
        const m = line.match(/^R(\d+)\t([^\t]+)\t(.+)$/)
        if (!m) continue
        const [, score, from, to] = m
        if (!fromPaths.has(from) || claimedFrom.has(from)) continue
        if (!missingFiles.has(to) || claimedTo.has(to)) continue
        moved.push({ from, to, type: 'file', similarity: Number(score) })
        claimedTo.add(to)
        claimedFrom.add(from)
      }
    }
  }

  const fileMoves = moved.filter((m) => m.type === 'file')
  for (const o of orphans.filter((x) => x.type === 'dir')) {
    const votes = new Map<string, number>()
    for (const m of fileMoves) {
      if (!m.from.startsWith(o.path + '/')) continue
      const rel = m.from.slice(o.path.length + 1)
      if (m.to.endsWith('/' + rel)) {
        const target = m.to.slice(0, -(rel.length + 1))
        votes.set(target, (votes.get(target) ?? 0) + 1)
      }
    }
    const best = [...votes.entries()].sort((a, b) => b[1] - a[1])[0]
    if (!best) continue
    const [to, count] = best
    if (!missingDirs.has(to)) continue
    moved.push({ from: o.path, to, type: 'dir', similarity: null, votes: count })
    missingDirs.delete(to)
  }

  return moved
}

export function attachDeltas(
  root: string,
  entries: StatusEntry[],
  notes: Map<string, NoteRecord>,
): void {
  const byAnchor = new Map<string, StatusEntry[]>()
  for (const e of entries) {
    if (e.status !== 'outdated') continue
    const anchor = notes.get(e.path)?.anchor
    if (!anchor) continue
    if (!byAnchor.has(anchor)) byAnchor.set(anchor, [])
    byAnchor.get(anchor)!.push(e)
  }
  for (const [anchor, anchored] of byAnchor) {
    let out: string
    try {
      out = git(root, ['diff', '--numstat', '-M', anchor])
    } catch {
      continue
    }
    const stat = new Map<string, [number, number]>()
    for (const line of out.split('\n')) {
      const m = line.match(/^(\d+|-)\t(\d+|-)\t(.+)$/)
      if (!m) continue
      const p = m[3].replace(/\{([^{}]*) => ([^{}]*)\}/g, '$2').replace(/^(.*) => (.*)$/, '$2')
        .replace(/\/\//g, '/')
      stat.set(p, [m[1] === '-' ? 0 : Number(m[1]), m[2] === '-' ? 0 : Number(m[2])])
    }
    for (const e of anchored) {
      let added = 0
      let removed = 0
      let files = 0
      for (const [p, [a, r]] of stat) {
        if (e.type === 'file' ? p !== e.path : (e.path !== '' && p !== e.path && !p.startsWith(e.path + '/'))) continue
        added += a
        removed += r
        files++
      }
      if (files) e.delta = { added, removed, files }
    }
  }
}