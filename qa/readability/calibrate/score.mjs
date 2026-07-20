// 校准评分：机械层 + grok 盲读 vs 人类均分（Spearman ρ，平局取平均秩）
//   node score.mjs
// env: CALIB_WORK；机械层需要 <repo-atlas>/dist/cli.js 已构建（pnpm build:cli）
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const WORK = process.env.CALIB_WORK ?? path.join(HERE, '.work')
const CLI = path.join(HERE, '../../..', 'dist/cli.js')

function spearman(xs, ys) {
  const n = xs.length
  const rank = (arr) => {
    const idx = arr.map((v, i) => [v, i]).sort((a, b) => a[0] - b[0])
    const r = new Array(n)
    let i = 0
    while (i < n) {
      let j = i
      while (j + 1 < n && idx[j + 1][0] === idx[i][0]) j++
      const avg = (i + j) / 2 + 1
      for (let k = i; k <= j; k++) r[idx[k][1]] = avg
      i = j + 1
    }
    return r
  }
  const pearson = (a, b) => {
    const x = a.reduce((s, v) => s + v, 0) / a.length
    const y = b.reduce((s, v) => s + v, 0) / b.length
    let s = 0, sx = 0, sy = 0
    for (let i = 0; i < a.length; i++) { s += (a[i] - x) * (b[i] - y); sx += (a[i] - x) ** 2; sy += (b[i] - y) ** 2 }
    return sx && sy ? s / Math.sqrt(sx * sy) : 0
  }
  return pearson(rank(xs), rank(ys))
}

const snips = JSON.parse(fs.readFileSync(path.join(WORK, 'snippets.json'), 'utf8'))
const extOf = (s) => (s.set === 'dorn-python' ? 'py' : s.set === 'dorn-cuda' ? 'c' : 'java')

// ---- 机械层 ----
const mechOut = JSON.parse(execFileSync('node', [CLI, 'readability', '--json'], { cwd: path.join(WORK, 'mech-repo'), encoding: 'utf8', maxBuffer: 1 << 28 }))
const rows = snips.map((s) => ({ ...s, f: mechOut.files[`${s.id}.${extOf(s)}`] })).filter((r) => r.f)
console.log(`mechanical: ${rows.length}/${snips.length} snippets analysed`)
const FEATS = [
  ['halsteadPerLine', (f) => f.halsteadPerLine, -1],
  ['lineLenMean', (f) => f.lineLen.mean, -1],
  ['tokenEntropy', (f) => f.tokenEntropy, -1],
  ['commentRatio', (f) => f.commentRatio, +1],
]
const EXTRA = [['maxNesting', (f) => f.maxNesting], ['lines', (f) => f.lines], ['identAvgLen', (f) => (f.ident.count >= 5 ? f.ident.avgLen : NaN)]]
const sets = [...new Set(rows.map((r) => r.set))]
for (const name of ['ALL', ...sets]) {
  const sub = name === 'ALL' ? rows : rows.filter((r) => r.set === name)
  if (sub.length < 10) continue
  const zs = FEATS.map(([, get, sign]) => {
    const vals = sub.map((r) => get(r.f))
    const m = vals.reduce((a, b) => a + b, 0) / vals.length
    const sd = Math.sqrt(vals.reduce((a, b) => a + (b - m) ** 2, 0) / vals.length) || 1
    return sub.map((r) => (sign * (get(r.f) - m)) / sd)
  })
  const comp = sub.map((_, i) => zs.reduce((a, z) => a + z[i], 0))
  const parts = FEATS.map(([n, g]) => `${n} ${spearman(sub.map((r) => r.humanMean), sub.map((r) => g(r.f))).toFixed(2)}`)
  const extras = EXTRA.map(([n, g]) => {
    const vals = sub.map((r) => g(r.f))
    const ok = vals.map((v, i) => [v, i]).filter(([v]) => Number.isFinite(v))
    return ok.length < 10 ? null : `${n} ${spearman(ok.map(([, i]) => sub[i].humanMean), ok.map(([v]) => v)).toFixed(2)}`
  }).filter(Boolean)
  console.log(`  ${name.padEnd(12)} n=${String(sub.length).padStart(3)}  composite ρ=${spearman(sub.map((r) => r.humanMean), comp).toFixed(3)}  [${parts.join(' · ')}]  ${extras.join(' · ')}`)
}

// ---- grok 盲读 ----
function lenient(file) {
  try {
    const out = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (out?.structuredOutput?.ratings) return out.structuredOutput.ratings
    const t = (out?.text ?? '').trim()
    const s = t.indexOf('{'), e = t.lastIndexOf('}')
    if (s < 0 || e <= s) return null
    return JSON.parse(t.slice(s, e + 1)).ratings
  } catch { return null }
}
const perPass = []
for (const dir of fs.readdirSync(WORK).filter((d) => d.startsWith('out-p')).sort()) {
  const ratings = new Map()
  let bad = 0
  for (const f of fs.readdirSync(path.join(WORK, dir))) {
    const rs = lenient(path.join(WORK, dir, f))
    if (!rs) { bad++; continue }
    for (const r of rs) if (r.id && Number(r.overall)) ratings.set(r.id, Number(r.overall))
  }
  perPass.push(ratings)
  console.log(`${dir}: ${ratings.size} ratings (${bad} unparsed)`)
}
if (perPass.length && perPass[0].size >= 10) {
  const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]
  const grows = rows.map((r) => ({ ...r, g: perPass.map((m) => m.get(r.id)).filter((v) => v !== undefined) })).filter((r) => r.g.length)
  for (const r of grows) r.grokMedian = median(r.g)
  for (const name of ['ALL', 'bw', 'scal']) {
    const sub = name === 'ALL' ? grows : grows.filter((r) => r.set === name)
    if (sub.length < 10) continue
    const rho = spearman(sub.map((r) => r.humanMean), sub.map((r) => r.grokMedian))
    const acc = sub.filter((r) => (r.humanMean >= 3) === (r.grokMedian >= 3)).length / sub.length
    console.log(`  grok ${name.padEnd(8)} n=${String(sub.length).padStart(3)}  ρ=${rho.toFixed(3)}  binary(>=3) acc=${(acc * 100).toFixed(1)}%`)
  }
  if (perPass.length >= 2) {
    const both = grows.filter((r) => perPass[0].has(r.id) && perPass[1].has(r.id))
    if (both.length > 10) console.log(`  inter-pass reliability p1~p2: ρ=${spearman(both.map((r) => perPass[0].get(r.id)), both.map((r) => perPass[1].get(r.id))).toFixed(3)}`)
  }
} else {
  console.log('grok: 暂无足够盲读输出（先跑 run.sh）')
}
