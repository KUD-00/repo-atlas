/** Shared with viewer/lib.ts — keep in sync if duplicated. */
export function escapeReg(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Resolve a content marker to a 1-based line in source.
 * Definition-shaped line first, then word boundary, then includes; skips import lines.
 */
export function findLine(lines: string[], name: string): number | null {
  const def = new RegExp(
    `\\b(?:function|class|interface|type|enum|const|let|var|def|fn)\\s+${escapeReg(name)}\\b`,
  )
  const word = new RegExp(`\\b${escapeReg(name)}\\b`)
  let firstWord: number | null = null
  let firstRaw: number | null = null
  for (let i = 0; i < lines.length; i++) {
    if (def.test(lines[i])) return i + 1
    if (/^\s*import\b/.test(lines[i])) continue
    if (firstWord === null && word.test(lines[i])) firstWord = i + 1
    if (firstRaw === null && lines[i].includes(name)) firstRaw = i + 1
  }
  return firstWord ?? firstRaw
}