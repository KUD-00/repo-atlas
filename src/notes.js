import fs from 'node:fs'
import path from 'node:path'
import { atlasDir } from './scan.js'

const DIR_NOTE = '__dir__.md'

export function notesRoot(root) {
  return path.join(atlasDir(root), 'notes')
}

/**
 * Note file location for a repo path.
 * dir  apps/daemon      -> .atlas/notes/apps/daemon/__dir__.md   (repo root '' -> .atlas/notes/__dir__.md)
 * file apps/daemon/x.ts -> .atlas/notes/apps/daemon/x.ts.md
 */
export function noteFileFor(root, relPath, type) {
  const base = notesRoot(root)
  if (type === 'dir') return path.join(base, relPath, DIR_NOTE)
  return path.join(base, relPath + '.md')
}

function parseNote(raw) {
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/)
  const meta = {}
  let body = raw
  if (m) {
    body = raw.slice(m[0].length)
    for (const line of m[1].split(/\r?\n/)) {
      const kv = line.match(/^(\w+):\s*(.*)$/)
      if (kv) meta[kv[1]] = kv[2].trim()
    }
  }
  return {
    hash: meta.hash ?? null,
    anchor: meta.anchor || null,
    dirty: meta.dirty === 'true',
    stamped: meta.stamped ?? null,
    body,
  }
}

function serializeNote(note) {
  const lines = [`hash: ${note.hash ?? ''}`]
  if (note.anchor) lines.push(`anchor: ${note.anchor}`)
  if (note.dirty) lines.push('dirty: true')
  lines.push(`stamped: ${note.stamped ?? ''}`)
  return `---\n${lines.join('\n')}\n---\n${note.body}`
}

/**
 * Load every note under .atlas/notes.
 * Returns Map<repoPath, {type, hash, stamped, body, file}>; repo root dir is keyed ''.
 */
export function loadNotes(root) {
  const base = notesRoot(root)
  const notes = new Map()
  if (!fs.existsSync(base)) return notes
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(full)
      } else if (entry.isFile() && entry.name.endsWith('.md')) {
        const rel = path.relative(base, full).split(path.sep).join('/')
        const isDirNote = entry.name === DIR_NOTE
        const repoPath = isDirNote
          ? rel.slice(0, -DIR_NOTE.length).replace(/\/$/, '')
          : rel.slice(0, -'.md'.length)
        notes.set(repoPath, {
          type: isDirNote ? 'dir' : 'file',
          file: full,
          ...parseNote(fs.readFileSync(full, 'utf8')),
        })
      }
    }
  }
  walk(base)
  return notes
}

/** Write a note's body (creating parent dirs on first write), stamped with the given hash. */
export function writeNoteBody(root, relPath, type, body, hash, meta = {}) {
  const file = noteFileFor(root, relPath, type)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, serializeNote({
    hash, anchor: meta.anchor, dirty: meta.dirty, stamped: new Date().toISOString(), body,
  }))
  return file
}

/**
 * Rewrite a note's frontmatter with a new hash, preserving the body.
 * meta.anchor is the commit the stamp was taken against (for later diffing /
 * rename detection); meta.dirty marks that the stamped content was not in
 * that commit (uncommitted worktree state).
 */
export function stampNote(file, hash, meta = {}) {
  const note = parseNote(fs.readFileSync(file, 'utf8'))
  note.hash = hash
  note.anchor = meta.anchor ?? note.anchor
  note.dirty = meta.anchor !== undefined ? Boolean(meta.dirty) : note.dirty
  note.stamped = new Date().toISOString()
  fs.writeFileSync(file, serializeNote(note))
}

/** Relocate a note file to the ledger slot for a new repo path, body untouched. */
export function moveNoteFile(root, note, toPath, toType) {
  const dest = noteFileFor(root, toPath, toType)
  fs.mkdirSync(path.dirname(dest), { recursive: true })
  fs.renameSync(note.file, dest)
  return dest
}
