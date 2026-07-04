import fs from 'node:fs'
import path from 'node:path'
import type { BrokenRef, MoveRecord, NoteRecord, ScanResult } from './types.js'

const INLINE_CODE = /`([^`\n]{1,120})`/g
const FENCE = /^```[\s\S]*?^```[^\S\n]*$/gm
const BARE_FILE_EXT = /\.[cm]?tsx?$/

function pathlike(t: string): boolean {
  if (/[\s"'$(){}<>\\]/.test(t)) return false
  if (/^[@\-#/~.]/.test(t)) return false
  if (t.includes('@') || t.includes('://') || t.startsWith('node:')) return false
  if (!/^[\w./-]+$/.test(t)) return false
  if (!t.includes('/')) return BARE_FILE_EXT.test(t)
  const segments = t.split('/')
  if (segments.slice(0, -1).some((s) => s.includes('.'))) return false
  if (segments.every((s) => /^[a-z]+$/.test(s))) return false
  return true
}

function normalize(t: string): string | null {
  const stripped = t.replace(/\/$/, '').replace(/\/?\*$/, '').replace(/-\*$/, '')
  return stripped.includes('*') ? null : stripped
}

function searchBases(base: string): string[] {
  const out: string[] = []
  let p = base
  while (p) {
    out.push(p, p + '/src')
    p = p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : ''
  }
  out.push('', 'src')
  return out
}

export function checkRefs(
  root: string,
  scanResult: ScanResult,
  notes: Map<string, NoteRecord>,
  moved: MoveRecord[] = [],
): BrokenRef[] {
  const present = (p: string) => scanResult.files.has(p) || scanResult.dirs.has(p) ||
    fs.existsSync(path.join(root, p))
  const exists = (p: string) => {
    if (present(p)) return true
    if (/\.[cm]?js$/.test(p)) return present(p.replace(/\.([cm]?)js$/, '.$1ts')) || present(p.replace(/\.js$/, '.tsx'))
    if (!/\.\w+$/.test(p)) {
      return ['.ts', '.tsx', '.js', '/index.ts'].some((ext) => present(p + ext))
    }
    return false
  }
  const movedTo = new Map(moved.map((m) => [m.from, m.to]))

  const basenames = new Map<string, string[]>()
  for (const p of scanResult.files.keys()) {
    const b = path.posix.basename(p)
    if (!basenames.has(b)) basenames.set(b, [])
    basenames.get(b)!.push(p)
  }

  const broken: BrokenRef[] = []

  // reading-order entries must name current children of their directory;
  // ignored children still count as present (order survives an exclude)
  const childNames = new Map<string, Set<string>>()
  const addChain = (p: string) => {
    const segs = p.split('/')
    for (let i = 0; i < segs.length; i++) {
      const parent = segs.slice(0, i).join('/')
      let set = childNames.get(parent)
      if (!set) childNames.set(parent, (set = new Set()))
      set.add(segs[i])
    }
  }
  for (const p of scanResult.files.keys()) addChain(p)
  for (const p of scanResult.ignored) addChain(p)
  for (const [notePath, note] of notes) {
    if (note.type !== 'dir' || !note.order?.length) continue
    const kids = childNames.get(notePath)
    for (const name of note.order) {
      if (kids?.has(name)) continue
      const lower = name.toLowerCase()
      const near = kids ? [...kids].find((k) => k.toLowerCase() === lower) : undefined
      broken.push({ note: notePath, noteFile: note.file, ref: `order: ${name}`, suggestion: near ?? null })
    }
  }

  for (const [notePath, note] of notes) {
    const base = note.type === 'dir' ? notePath : notePath.includes('/') ? notePath.slice(0, notePath.lastIndexOf('/')) : ''
    const prose = note.body.replace(FENCE, '')
    const seen = new Set<string>()
    INLINE_CODE.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = INLINE_CODE.exec(prose)) !== null) {
      const raw = m[1].trim()
      if (seen.has(raw) || !pathlike(raw)) continue
      seen.add(raw)
      const t = normalize(raw)
      if (!t || (!pathlike(t) && !raw.endsWith('/'))) continue
      if (searchBases(base).some((a) => exists(a ? a + '/' + t : t))) continue
      if (!t.includes('/')) {
        if (basenames.has(t)) continue
        const hint = [...movedTo.entries()].find(([from]) => path.posix.basename(from) === t)
        broken.push({ note: notePath, noteFile: note.file, ref: raw, suggestion: hint?.[1] ?? null })
        continue
      }
      const formerly = searchBases(base).map((a) => (a ? a + '/' + t : t)).find((c) => movedTo.has(c))
      const unique = basenames.get(path.posix.basename(t))
      broken.push({
        note: notePath,
        noteFile: note.file,
        ref: raw,
        suggestion: formerly ? movedTo.get(formerly)! : unique?.length === 1 ? unique[0] : null,
      })
    }
  }
  return broken
}