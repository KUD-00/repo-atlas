import { loadNotes } from './notes.js'

/**
 * Compare a scan against the notes ledger.
 * Every scanned path gets one of: fresh | outdated | missing.
 * Notes whose target no longer exists are orphans.
 */
export function computeStatus(root, scanResult) {
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

  const orphans = [...notes.entries()]
    .filter(([p, n]) => (n.type === 'dir' ? !scanResult.dirs.has(p) : !scanResult.files.has(p)))
    .map(([p, n]) => ({ path: p, type: n.type, noteFile: n.file }))

  entries.sort((a, b) => (a.path < b.path ? -1 : 1))
  return { entries, orphans }
}

export function summarize(status) {
  const counts = { fresh: 0, outdated: 0, missing: 0 }
  for (const e of status.entries) counts[e.status]++
  return { ...counts, total: status.entries.length, orphans: status.orphans.length }
}
