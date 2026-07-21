/** Parse `file:line` / `file#symbol` into a code-jump target. Symbol anchors
 * land at line 1 (the panel has no symbol resolver). Empty/invalid → null.
 * Line numbers follow strict v2 positive-safe rules (`[1-9]\d*` within
 * Number.MAX_SAFE_INTEGER). Whitespace-only paths are rejected; full path
 * filesystem validation is intentionally out of scope. */
export function parseAuditLocation(value: string): { path: string; line: number } | null {
  const match = /^([^:#]+)(?::(\d+)|#(.+))?$/u.exec(value)
  if (!match) return null
  const path = match[1]
  if (!path.trim()) return null
  if (match[2] !== undefined) {
    // strict positive decimal: no zero, no leading zeros
    if (!/^[1-9]\d*$/u.test(match[2])) return null
    const line = Number(match[2])
    if (!Number.isSafeInteger(line) || line < 1) return null
    return { path, line }
  }
  return { path, line: 1 }
}

/** Detail payload for `atlas-code-jump` chips. */
export function auditLocationJumpDetail(
  value: string,
): { path: string; line: number; endLine: number } | null {
  const parsed = parseAuditLocation(value)
  if (!parsed) return null
  return { path: parsed.path, line: parsed.line, endLine: parsed.line }
}
