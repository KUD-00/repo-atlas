// 按语言组回归组合分权重，并与等权做留出对比。
//   node weights.mjs
// 输出：各组拟合权重、in-sample ρ、留一组出（LGO）ρ vs 等权 ρ —— 决定机械层要不要
// 上按语言权重（只有 LGO 显著优于等权才值得）。
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

// 4x4 normal equations solve (Gaussian elimination)
function solve4(A, b) {
  const M = A.map((row, i) => [...row, b[i]])
  for (let c = 0; c < 4; c++) {
    let p = c
    for (let r = c + 1; r < 4; r++) if (Math.abs(M[r][c]) > Math.abs(M[p][c])) p = r
    ;[M[c], M[p]] = [M[p], M[c]]
    for (let r = c + 1; r < 4; r++) {
      const f = M[r][c] / (M[c][c] || 1e-12)
      for (let k = c; k <= 4; k++) M[r][k] -= f * M[c][k]
    }
  }
  const x = [0, 0, 0, 0]
  for (let r = 3; r >= 0; r--) {
    x[r] = M[r][4]
    for (let k = r + 1; k < 4; k++) x[r] -= M[r][k] * x[k]
    x[r] /= M[r][r] || 1e-12
  }
  return x
}

const snips = JSON.parse(fs.readFileSync(path.join(WORK, 'snippets.json'), 'utf8'))
const extOf = (s) => (s.set === 'dorn-python' ? 'py' : s.set === 'dorn-cuda' ? 'c' : 'java')
const mechOut = JSON.parse(execFileSync('node', [CLI, 'readability', '--json'], { cwd: path.join(WORK, 'mech-repo'), encoding: 'utf8', maxBuffer: 1 << 28 }))
const rows = snips.map((s) => ({ ...s, f: mechOut.files[`${s.id}.${extOf(s)}`] })).filter((r) => r.f)

const GETTERS = [
  ['commentRatio', (f) => f.commentRatio],
  ['halsteadPerLine', (f) => f.halsteadPerLine],
  ['lineLenMean', (f) => f.lineLen.mean],
  ['tokenEntropy', (f) => f.tokenEntropy],
]
const GROUPS = {
  java: (r) => ['bw', 'scal', 'dorn-java'].includes(r.set),
  python: (r) => r.set === 'dorn-python',
  cuda: (r) => r.set === 'dorn-cuda',
}

function zfeats(sub) {
  return GETTERS.map(([, get]) => {
    const vals = sub.map((r) => get(r.f))
    const m = vals.reduce((a, b) => a + b, 0) / vals.length
    const sd = Math.sqrt(vals.reduce((a, b) => a + (b - m) ** 2, 0) / vals.length) || 1
    return sub.map((r) => (get(r.f) - m) / sd)
  })
}
function fit(sub) {
  const Z = zfeats(sub)
  const y = sub.map((r) => r.humanMean)
  const A = Array.from({ length: 4 }, () => [0, 0, 0, 0])
  const b = [0, 0, 0, 0]
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) A[i][j] = Z[i].reduce((a, _, k) => a + Z[i][k] * Z[j][k], 0) / sub.length
    b[i] = Z[i].reduce((a, _, k) => a + Z[i][k] * y[k], 0) / sub.length
  }
  return solve4(A, b)
}
const score = (sub, w) => {
  const Z = zfeats(sub)
  const pred = sub.map((_, k) => w[0] * Z[0][k] + w[1] * Z[1][k] + w[2] * Z[2][k] + w[3] * Z[3][k])
  return spearman(sub.map((r) => r.humanMean), pred)
}
const EQ = [1, -1, -1, -1]

const groupNames = Object.keys(GROUPS)
console.log(`feature order: ${GETTERS.map(([n]) => n).join(', ')}`)
console.log(`${'group'.padEnd(8)} ${'n'.padStart(4)}  equal-ρ   fit-ρ(in)  LGO-ρ(fit others)`)
const fits = {}
for (const g of groupNames) {
  const sub = rows.filter(GROUPS[g])
  const w = fit(sub)
  fits[g] = w
  const others = rows.filter((r) => !GROUPS[g](r))
  const wOther = fit(others)
  console.log(`${g.padEnd(8)} ${String(sub.length).padStart(4)}  ${score(sub, EQ).toFixed(3)}   ${score(sub, w).toFixed(3)}      ${score(sub, wOther).toFixed(3)}`)
  console.log(`         w = [${w.map((x) => x.toFixed(3)).join(', ')}]`)
}
const wall = fit(rows)
console.log(`${'ALL'.padEnd(8)} ${String(rows.length).padStart(4)}  ${score(rows, EQ).toFixed(3)}   ${score(rows, wall).toFixed(3)}`)
console.log(`         w = [${wall.map((x) => x.toFixed(3)).join(', ')}]`)
// 交叉：用 ALL 权重在各组上的表现 vs 等权
console.log('\nALL-weights applied per group (vs equal-ρ):')
for (const g of groupNames) {
  const sub = rows.filter(GROUPS[g])
  console.log(`  ${g.padEnd(8)} ALL-w ρ=${score(sub, wall).toFixed(3)}   (equal ${score(sub, EQ).toFixed(3)})`)
}
