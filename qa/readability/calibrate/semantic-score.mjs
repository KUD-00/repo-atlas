// 语义校准评分：inter-pass 可靠性 + （有 semantic-labels.json 时）vs 人工标注的 Spearman。
//   node semantic-score.mjs
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createSemanticManifest, semanticManifestError, storedSemanticManifestError } from './semantic-manifest.mjs'
import { isRating, semanticDocumentError } from './semantic-result.mjs'
import { currentWorkspace } from './semantic-workspace.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const outIdx = process.argv.indexOf('--out-dir')
if (outIdx >= 0 && !process.argv[outIdx + 1]) {
  console.error('--out-dir requires a path')
  process.exit(2)
}
let OUT
try {
  OUT = outIdx >= 0 ? path.resolve(process.argv[outIdx + 1]) : currentWorkspace(HERE, process.cwd()).out
} catch (error) {
  console.error(`semantic calibration workspace unavailable: ${error instanceof Error ? error.message : String(error)}`)
  process.exit(1)
}

const fail = (message) => {
  console.error(`invalid semantic calibration: ${message}`)
  process.exit(1)
}

const readJson = (file, label) => {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch (error) {
    fail(`${label}: ${error instanceof Error ? error.message : String(error)}`)
  }
}

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
    const x = a.reduce((s, v) => s + v, 0) / a.length, y = b.reduce((s, v) => s + v, 0) / b.length
    let s = 0, sx = 0, sy = 0
    for (let i = 0; i < a.length; i++) { s += (a[i] - x) * (b[i] - y); sx += (a[i] - x) ** 2; sy += (b[i] - y) ** 2 }
    return sx && sy ? s / Math.sqrt(sx * sy) : null
  }
  return pearson(rank(xs), rank(ys))
}

function reliability(xs, ys) {
  const exact = xs.filter((value, index) => value === ys[index]).length / xs.length
  const mae = xs.reduce((sum, value, index) => sum + Math.abs(value - ys[index]), 0) / xs.length
  return { rho: spearman(xs, ys), exact, mae }
}

function showReliability(label, xs, ys) {
  const { rho, exact, mae } = reliability(xs, ys)
  const rhoText = rho === null ? 'n/a (zero variance)' : rho.toFixed(3)
  console.log(`${label}: exact agreement=${(exact * 100).toFixed(1)}% · MAE=${mae.toFixed(2)} · rho=${rhoText}`)
}

const manifest = readJson(path.join(OUT, 'manifest.json'), 'manifest.json')
const manifestError = storedSemanticManifestError(manifest)
if (manifestError) fail(manifestError)
const files = readJson(path.join(OUT, 'files.json'), 'files.json')
if (!Array.isArray(files) || files.length !== manifest.files.length || files.some((file, index) => file !== manifest.files[index])) {
  fail('files.json does not exactly match manifest.files')
}
try {
  const currentManifest = createSemanticManifest(manifest.repoRoot, files)
  const currentError = semanticManifestError(manifest, currentManifest)
  if (currentError) fail(currentError)
} catch (error) {
  fail(`cannot verify current sample bytes: ${error instanceof Error ? error.message : String(error)}`)
}
const passes = fs.readdirSync(OUT).filter((d) => /^pass\d+$/.test(d)).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
if (!passes.length) { console.log('先跑 semantic-run.sh'); process.exit(1) }

const perPass = passes.map((p) => {
  const m = new Map()
  for (const resultFile of fs.readdirSync(path.join(OUT, p)).filter((file) => file.endsWith('.json'))) {
    const document = readJson(path.join(OUT, p, resultFile), `${p}/${resultFile}`)
    const repoPath = document?.rows?.[0]?.path
    if (typeof repoPath !== 'string' || !manifest.files.includes(repoPath)) fail(`${p}/${resultFile} has a path outside the sample`)
    const error = semanticDocumentError(document, repoPath, manifest)
    if (error) fail(`${p}/${resultFile}: ${error}`)
    if (m.has(repoPath)) fail(`${p} contains duplicate results for ${repoPath}`)
    m.set(repoPath, document.rows[0])
  }
  const missing = files.filter((file) => !m.has(file))
  if (missing.length) fail(`${p} is incomplete (${m.size}/${files.length}); missing ${missing.join(', ')}`)
  return m
})
for (let i = 0; i < passes.length; i++) console.log(`${passes[i]}: ${perPass[i].size}/${files.length} ratings`)

for (let left = 0; left < passes.length; left++) {
  for (let right = left + 1; right < passes.length; right++) {
    const both = files.filter((file) => perPass[left].has(file) && perPass[right].has(file))
    if (both.length < 5) continue
    const pair = passes.length === 2 ? '' : ` ${passes[left]} ↔ ${passes[right]}`
    showReliability(`\ninter-pass reliability${pair} (naming, n=${both.length})`, both.map((file) => perPass[left].get(file).naming), both.map((file) => perPass[right].get(file).naming))
    const coherence = both.filter((file) => isRating(perPass[left].get(file).commentCoherence) && isRating(perPass[right].get(file).commentCoherence))
    if (coherence.length >= 5) {
      showReliability(`inter-pass reliability${pair} (coherence, n=${coherence.length})`, coherence.map((file) => perPass[left].get(file).commentCoherence), coherence.map((file) => perPass[right].get(file).commentCoherence))
    }
  }
}

const labelsFile = path.join(OUT, 'semantic-labels.json')
if (fs.existsSync(labelsFile)) {
  const rawLabels = JSON.parse(fs.readFileSync(labelsFile, 'utf8'))
  if (!rawLabels || rawLabels.formatVersion !== 1 || rawLabels.sampleHash !== manifest.sampleHash || !Array.isArray(rawLabels.rows)) {
    fail('semantic-labels.json must be a v1 document bound to this sampleHash')
  }
  const labels = new Map()
  for (const label of rawLabels.rows) {
    if (!label || typeof label.path !== 'string' || !files.includes(label.path)) fail('semantic-labels.json contains a path outside the sample')
    if (labels.has(label.path)) fail(`semantic-labels.json contains duplicate labels for ${label.path}`)
    if (!(label.naming == null || isRating(label.naming))) fail(`semantic-labels.json has an invalid naming rating for ${label.path}`)
    if (!(label.commentCoherence == null || isRating(label.commentCoherence))) fail(`semantic-labels.json has an invalid commentCoherence rating for ${label.path}`)
    labels.set(label.path, label)
  }
  const median = (values) => {
    const sorted = [...values].sort((a, b) => a - b)
    const middle = Math.floor(sorted.length / 2)
    return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
  }
  const showHuman = (dimension) => {
    const rows = [...labels.entries()]
      .filter(([repoPath, label]) => isRating(label[dimension]) && perPass.every((pass) => pass.has(repoPath) && isRating(pass.get(repoPath)[dimension])))
      .map(([repoPath, label]) => ({ human: label[dimension], grok: median(perPass.map((pass) => pass.get(repoPath)[dimension])) }))
    if (rows.length >= 5) {
      showReliability(`\ngrok vs 人工标注 (${dimension === 'commentCoherence' ? 'coherence' : dimension}, n=${rows.length})`, rows.map((row) => row.human), rows.map((row) => row.grok))
    } else {
      console.log(`\nsemantic-labels.json 的 ${dimension} 只有 ${rows.length} 个有效重叠，>=5 才能计算`)
    }
  }
  showHuman('naming')
  showHuman('commentCoherence')
} else {
  console.log('\n无 semantic-labels.json —— 人工填 worksheet.md 后存成该文件再跑本脚本即可算 ρ')
}
