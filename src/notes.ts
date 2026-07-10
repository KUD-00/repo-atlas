import fs from 'node:fs'
import path from 'node:path'
import { atlasDir } from './scan.js'
import type { NoteRecord, ParsedNote, PathType } from './types.js'

const DIR_NOTE = '__dir__.md'

export function notesRoot(root: string): string {
  return path.join(atlasDir(root), 'notes')
}

export function noteFileFor(root: string, relPath: string, type: PathType): string {
  const base = notesRoot(root)
  if (type === 'dir') return path.join(base, relPath, DIR_NOTE)
  return path.join(base, relPath + '.md')
}

function parseNote(raw: string): ParsedNote {
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/)
  const meta: Record<string, string> = {}
  let body = raw
  if (m) {
    body = raw.slice(m[0].length)
    for (const line of m[1].split(/\r?\n/)) {
      const kv = line.match(/^(\w+):\s*(.*)$/)
      if (kv) meta[kv[1]] = kv[2].trim()
    }
  }
  let order: string[] | null = null
  if (meta.order) {
    try {
      const parsed: unknown = JSON.parse(meta.order)
      if (Array.isArray(parsed)) order = parsed.filter((x): x is string => typeof x === 'string')
    } catch {
      /* malformed order — treat as absent rather than failing the whole note */
    }
  }
  return {
    hash: meta.hash ?? null,
    anchor: meta.anchor || null,
    dirty: meta.dirty === 'true',
    stamped: meta.stamped ?? null,
    order,
    body,
  }
}

function serializeNote(note: ParsedNote): string {
  const lines = [`hash: ${note.hash ?? ''}`]
  if (note.anchor) lines.push(`anchor: ${note.anchor}`)
  if (note.dirty) lines.push('dirty: true')
  lines.push(`stamped: ${note.stamped ?? ''}`)
  // one-line JSON array: unambiguous for the minimal key:value parser above
  if (note.order?.length) lines.push(`order: ${JSON.stringify(note.order)}`)
  return `---\n${lines.join('\n')}\n---\n${note.body}`
}

export function loadNotes(root: string): Map<string, NoteRecord> {
  const base = notesRoot(root)
  const notes = new Map<string, NoteRecord>()
  if (!fs.existsSync(base)) return notes
  const walk = (dir: string) => {
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

export function writeNoteBody(
  root: string,
  relPath: string,
  type: PathType,
  body: string,
  hash: string,
  meta: { anchor?: string | null; dirty?: boolean; order?: string[] | null } = {},
): string {
  const file = noteFileFor(root, relPath, type)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  // a body rewrite must not lose an existing reading order
  let order = meta.order ?? null
  if (order === null && fs.existsSync(file)) {
    order = parseNote(fs.readFileSync(file, 'utf8')).order
  }
  fs.writeFileSync(file, serializeNote({
    hash,
    anchor: meta.anchor ?? null,
    dirty: meta.dirty ?? false,
    stamped: new Date().toISOString(),
    order,
    body,
  }))
  return file
}

/** Rewrite ONLY the body, leaving every freshness field (hash, anchor, stamped,
 *  dirty, order) exactly as it was. This is the viewer's plain "save": you edit
 *  the prose without asserting the note now matches the current code, so an
 *  outdated note stays outdated. A brand-new note is created unstamped — written,
 *  but not yet verified against any commit. */
export function updateNoteBody(
  root: string,
  relPath: string,
  type: PathType,
  body: string,
): string {
  const file = noteFileFor(root, relPath, type)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const prev: ParsedNote = fs.existsSync(file)
    ? parseNote(fs.readFileSync(file, 'utf8'))
    : { hash: null, anchor: null, dirty: false, stamped: null, order: null, body: '' }
  fs.writeFileSync(file, serializeNote({ ...prev, body }))
  return file
}

export function stampNote(
  file: string,
  hash: string,
  meta: { anchor?: string | null; dirty?: boolean } = {},
): void {
  const note = parseNote(fs.readFileSync(file, 'utf8'))
  note.hash = hash
  note.anchor = meta.anchor ?? note.anchor
  note.dirty = meta.anchor !== undefined ? Boolean(meta.dirty) : note.dirty
  note.stamped = new Date().toISOString()
  fs.writeFileSync(file, serializeNote(note))
}

export function moveNoteFile(root: string, note: NoteRecord, toPath: string, toType: PathType): string {
  const dest = noteFileFor(root, toPath, toType)
  fs.mkdirSync(path.dirname(dest), { recursive: true })
  fs.renameSync(note.file, dest)
  return dest
}