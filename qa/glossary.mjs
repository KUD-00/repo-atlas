/** Match glossary sections exactly as the viewer does: primary term plus
 * aliases, case-sensitive, with Latin/numeric identifier boundaries. */
export function relevantGlossary(glossaryRaw, body) {
  if (!glossaryRaw.trim() || !body) return ''
  const sections = glossaryRaw.split(/(?=^##\s+)/mu).filter((section) => /^##\s+/u.test(section))
  const isWord = (char) => !!char && /[A-Za-z0-9_]/u.test(char)
  const appears = (name) => {
    let from = 0
    while (from <= body.length - name.length) {
      const index = body.indexOf(name, from)
      if (index < 0) return false
      const before = body[index - 1]
      const after = body[index + name.length]
      if (!((/[A-Za-z0-9]/u.test(name[0]) && isWord(before)) ||
            (/[A-Za-z0-9]/u.test(name[name.length - 1]) && isWord(after)))) return true
      from = index + Math.max(1, name.length)
    }
    return false
  }
  const kept = sections.filter((section) => {
    const newline = section.indexOf('\n')
    const term = (newline >= 0 ? section.slice(3, newline) : section.slice(3)).trim()
    if (!term) return false
    const content = newline >= 0 ? section.slice(newline + 1) : ''
    const aliasMatch = content.match(/^(?:别名|aliases)[:：]\s*(.+)$/mu)
    const aliases = aliasMatch ? aliasMatch[1].split(/[,、]/u).map((value) => value.trim()).filter(Boolean) : []
    return [term, ...aliases].some(appears)
  })
  return kept.join('').trim()
}
