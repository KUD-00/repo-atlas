import { loadNotes, noteFileFor } from './notes.js'
import { detectMoves, attachDeltas } from './reconcile.js'
import { checkRefs } from './refs.js'

/**
 * Compare a scan against the notes ledger.
 * Every scanned path gets one of: fresh | outdated | missing | moved.
 * `moved` = a missing path whose note was found under a former path
 * (orphan × missing reconciliation) — the note follows via `migrate`.
 * Notes whose target is gone AND unmatched stay orphans.
 * Broken inline path references in note prose are reported separately.
 *
 * opts.deltas: also diff each outdated note's anchor (extra git calls — CLI
 * status wants this; serve's per-request rebuilds don't).
 */
export function computeStatus(root, scanResult, opts = {}) {
  const notes = loadNotes(root)
  const entries = []
  const judge = (path, type, hash) => {
    const note = notes.get(path)
    if (!note) return { path, type, status: 'missing' }
    return {
      path,
      type,
      status: note.hash === hash ? 'fresh' : 'outdated',
      stamped: note.stamped,
      body: note.body,
      noteFile: note.file,
    }
  }
  for (const [p, hash] of scanResult.dirs) entries.push(judge(p, 'dir', hash))
  for (const [p, hash] of scanResult.files) entries.push(judge(p, 'file', hash))

  let orphans = [...notes.entries()]
    .filter(([p, n]) => (n.type === 'dir' ? !scanResult.dirs.has(p) : !scanResult.files.has(p)))
    .map(([p, n]) => ({ path: p, type: n.type, noteFile: n.file }))

  const moved = detectMoves(root, scanResult, entries, orphans, notes)
  if (moved.length) {
    const byTo = new Map(moved.map((m) => [m.to, m]))
    const claimedFrom = new Set(moved.map((m) => m.from))
    for (const e of entries) {
      const m = e.status === 'missing' ? byTo.get(e.path) : undefined
      if (!m) continue
      const note = notes.get(m.from)
      Object.assign(e, {
        status: 'moved',
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

export function summarize(status) {
  const counts = { fresh: 0, outdated: 0, missing: 0, moved: 0 }
  for (const e of status.entries) counts[e.status]++
  return {
    ...counts,
    total: status.entries.length,
    orphans: status.orphans.length,
    brokenRefs: status.brokenRefs.length,
  }
}
