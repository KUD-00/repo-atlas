import { loadNotes, noteFileFor } from './notes.js'
import { detectMoves, attachDeltas } from './reconcile.js'
import { checkRefs } from './refs.js'
import type { ComputeStatusResult, EntryStatus, ScanResult, StatusEntry } from './types.js'

export function computeStatus(
  root: string,
  scanResult: ScanResult,
  opts: { deltas?: boolean } = {},
): ComputeStatusResult {
  const notes = loadNotes(root)
  const entries: StatusEntry[] = []
  const judge = (path: string, type: 'file' | 'dir', hash: string) => {
    const note = notes.get(path)
    if (!note) return { path, type, status: 'missing' as const }
    return {
      path,
      type,
      status: (note.hash === hash ? 'fresh' : 'outdated') as EntryStatus,
      stamped: note.stamped,
      body: note.body,
      noteFile: note.file,
      order: note.order,
    }
  }
  for (const [p, hash] of scanResult.dirs) entries.push(judge(p, 'dir', hash))
  for (const [p, hash] of scanResult.files) entries.push(judge(p, 'file', hash))

  const ignoredFiles = scanResult.ignored ?? new Set<string>()
  const ignoredDirs = new Set<string>()
  for (const p of ignoredFiles) {
    let d = p
    while (d.includes('/')) {
      d = d.slice(0, d.lastIndexOf('/'))
      if (!scanResult.dirs.has(d)) ignoredDirs.add(d)
    }
  }
  const judgeIgnored = (path: string, type: 'file' | 'dir') => {
    const note = notes.get(path)
    return {
      path, type, status: 'ignored' as const,
      stamped: note?.stamped, body: note?.body, noteFile: note?.file,
    }
  }
  for (const p of ignoredDirs) entries.push(judgeIgnored(p, 'dir'))
  for (const p of ignoredFiles) entries.push(judgeIgnored(p, 'file'))

  let orphans = [...notes.entries()]
    .filter(([p, n]) => (n.type === 'dir' ? !scanResult.dirs.has(p) : !scanResult.files.has(p)))
    .filter(([p]) => !ignoredFiles.has(p) && !ignoredDirs.has(p))
    .map(([p, n]) => ({ path: p, type: n.type, noteFile: n.file }))

  const moved = detectMoves(root, scanResult, entries, orphans, notes)
  if (moved.length) {
    const byTo = new Map(moved.map((m) => [m.to, m]))
    const claimedFrom = new Set(moved.map((m) => m.from))
    for (const e of entries) {
      const m = e.status === 'missing' ? byTo.get(e.path) : undefined
      if (!m) continue
      const note = notes.get(m.from)
      if (!note) continue
      Object.assign(e, {
        status: 'moved' as const,
        movedFrom: m.from,
        similarity: m.similarity,
        stamped: note.stamped,
        noteFile: note.file,
        expectedNoteFile: noteFileFor(root, e.path, e.type),
      })
    }
    orphans = orphans.filter((o) => !claimedFrom.has(o.path))
  }

  if (opts.deltas) attachDeltas(root, entries, notes)

  entries.sort((a, b) => (a.path < b.path ? -1 : 1))
  return { entries, orphans, brokenRefs: checkRefs(root, scanResult, notes, moved) }
}

export function summarize(status: ComputeStatusResult) {
  const counts = { fresh: 0, outdated: 0, missing: 0, moved: 0, ignored: 0 }
  for (const e of status.entries) counts[e.status]++
  return {
    ...counts,
    total: status.entries.length - counts.ignored,
    orphans: status.orphans.length,
    brokenRefs: status.brokenRefs.length,
  }
}