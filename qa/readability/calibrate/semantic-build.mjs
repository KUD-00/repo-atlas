// 语义校准：从目标仓库抽样文件 + 生成人工标注工作单。
//   cd <目标仓库> && node semantic-build.mjs [--n 18]
// 需要 .atlas/readability.json 存在（先跑 repo-atlas readability --out .atlas/readability.json）。
// 产物（按 repo/sample 隔离在 calibrate/.work/semantic/）：files.json + worksheet.md
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createSemanticManifest, readSafeRepoFile } from './semantic-manifest.mjs'
import { workspaceForManifest, writeCurrentWorkspace } from './semantic-workspace.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const REPO = process.cwd()
const nIdx = process.argv.indexOf('--n')
const N = nIdx >= 0 ? Number(process.argv[nIdx + 1]) : 18
if (!Number.isSafeInteger(N) || N <= 0) throw new Error('--n must be a positive integer')

const report = JSON.parse(readSafeRepoFile(REPO, '.atlas/readability.json').toString('utf8'))
if (report?.format !== 'repo-atlas-readability-v1' || report?.formatVersion !== 1 || !report.files || !report.norms) {
  throw new Error('unsupported .atlas/readability.json; regenerate it with repo-atlas readability')
}
const NOISE = [/\/locales\//, /\.d\.ts$/, /\/icons\//, /\.sops\.yaml$|secrets/, /\.html$/, /\.config\.(ts|js|mjs)$/, /\/dist\//, /\/vendor\//]
const isNoise = (p) => NOISE.some((re) => re.test(p))
const files = Object.entries(report.files).filter(([p, f]) => !isNoise(p) && f.lang !== 'css' && f.nonBlankLines >= 30)

// 分层抽样：worst composite 1/3、中位 1/3、最好 1/3
const compOf = (f) => (f.commentRatio - report.norms.commentRatio.mean) / (report.norms.commentRatio.sd || 1)
  - (f.halsteadPerLine - report.norms.halsteadPerLine.mean) / (report.norms.halsteadPerLine.sd || 1)
  - (f.lineLen.mean - report.norms.lineLenMean.mean) / (report.norms.lineLenMean.sd || 1)
  - (f.tokenEntropy - report.norms.tokenEntropy.mean) / (report.norms.tokenEntropy.sd || 1)
const sorted = files.map(([p, f]) => ({ p, c: compOf(f) })).sort((a, b) => a.c - b.c)
const target = Math.min(N, sorted.length)
if (!target) throw new Error('no eligible readability files to sample')
const cut1 = Math.ceil(sorted.length / 3)
const cut2 = Math.ceil(sorted.length * 2 / 3)
const buckets = [sorted.slice(0, cut1), sorted.slice(cut1, cut2), sorted.slice(cut2)]
const order = [0, 2, 1]
const quotas = [Math.floor(target / 3), Math.floor(target / 3), Math.floor(target / 3)]
for (let index = 0; index < target % 3; index++) quotas[order[index]]++
for (let index = 0; index < quotas.length; index++) quotas[index] = Math.min(quotas[index], buckets[index].length)
let spare = target - quotas.reduce((sum, value) => sum + value, 0)
while (spare > 0) {
  let assigned = false
  for (const index of order) {
    if (quotas[index] >= buckets[index].length) continue
    quotas[index]++
    spare--
    assigned = true
    if (!spare) break
  }
  if (!assigned) break
}
const evenly = (bucket, count) => {
  if (!count) return []
  if (count >= bucket.length) return bucket
  if (count === 1) return [bucket[Math.floor((bucket.length - 1) / 2)]]
  return Array.from({ length: count }, (_, index) => bucket[Math.round(index * (bucket.length - 1) / (count - 1))])
}
const markdownText = (value) => [...value.replace(/[\r\n]+/gu, ' ')].map((character) =>
  /^[\p{L}\p{N} /._:@=-]$/u.test(character) ? character : `&#${character.codePointAt(0)};`,
).join('')
const picks = buckets.flatMap((bucket, index) => evenly(bucket, quotas[index])).map((entry) => entry.p)
if (picks.length !== target || new Set(picks).size !== picks.length) throw new Error('internal error: semantic sample is not unique')

const manifest = createSemanticManifest(REPO, picks)
const { out: OUT } = workspaceForManifest(HERE, manifest)
fs.mkdirSync(OUT, { recursive: true })
fs.writeFileSync(path.join(OUT, 'files.json'), JSON.stringify(picks, null, 2))
fs.writeFileSync(path.join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n')
let md = `# 语义可读性人工标注工作单

用法：每个文件按 1–5 给 naming（命名语义）打分；有注释的话再给 commentCoherence（注释-代码一致性，没有注释留空）。
填好后存成 semantic-labels.json 放本目录：
{"formatVersion":1,"sampleHash":"${manifest.sampleHash}","rows":[{"path":"...","naming":4,"commentCoherence":3}]}

| 文件 | naming (1-5) | commentCoherence (1-5) | 备注 |
|---|---|---|---|
`
for (const p of picks) md += `| ${markdownText(p)} |  |  |  |\n`
fs.writeFileSync(path.join(OUT, 'worksheet.md'), md)
// Publish the current pointer only after the complete sample exists.
writeCurrentWorkspace(HERE, manifest)
console.log(`sampled ${picks.length} files → ${OUT}/files.json · worksheet.md`)
