// build calibration corpus from the three public datasets.
//   node build.mjs
// env: CALIB_WORK (default <here>/.work), PASSES (3), BATCH (14)
//
// 解析要点（都是实测出来的格式，不是文档）：
// - B&W oracle.csv：无表头，每行一个标注者，第 3..102 列 = 片段 1..100。
// - Scalabrino scores.csv：表头 Snippet1..200，9 个 Evaluator 行。
// - Dorn scores/<lang>.csv：每行一次评测会话（第 1 列是会话 id），第 2..122 列按
//   **排序后的片段序号列**对位（列 j ↔ 排序后第 j-1 个 .jsnp）；每次评测覆盖 ~8 个
//   连续片段（滑动窗口）。这个列映射是从"每片段评分数 ≈ 214 且 humanMean 分布
//   (1.3–4.4, mean≈3.25) 与 Dorn 论文一致"反推验证的——若下载包结构变化需重验。
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const WORK = process.env.CALIB_WORK ?? path.join(HERE, '.work')
const DS = path.join(WORK, 'datasets')
const PASSES = Number(process.env.PASSES ?? 3)
const BATCH = Number(process.env.BATCH ?? 14)
fs.mkdirSync(WORK, { recursive: true })

const mean = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length
const snippets = []

// ---- B&W ----
for (const line of fs.readFileSync(path.join(DS, 'oracle.csv'), 'utf8').trim().split('\n')) {
  const cols = line.split(',')
  for (let i = 2; i < cols.length; i++) {
    const v = Number(cols[i])
    if (!v) continue
    const no = i - 1
    const file = path.join(DS, 'snippets', `${no}.jsnp`)
    if (!fs.existsSync(file)) continue
    let s = snippets.find((x) => x.set === 'bw' && x.no === no)
    if (!s) { s = { set: 'bw', no, id: `bw${no}`, code: fs.readFileSync(file, 'utf8').trim(), ratings: [] }; snippets.push(s) }
    s.ratings.push(v)
  }
}

// ---- Scalabrino ----
const scLines = fs.readFileSync(path.join(DS, 'Dataset/scores.csv'), 'utf8').trim().split('\n')
const header = scLines[0].split(',')
for (const line of scLines.slice(1)) {
  const cols = line.split(',')
  for (let i = 1; i < cols.length; i++) {
    const v = Number(cols[i])
    if (!v) continue
    const no = Number(header[i].replace('Snippet', ''))
    const file = path.join(DS, 'Dataset/Snippets', `${no}.jsnp`)
    if (!fs.existsSync(file)) continue
    let s = snippets.find((x) => x.set === 'scal' && x.no === no)
    if (!s) { s = { set: 'scal', no, id: `sc${no}`, code: fs.readFileSync(file, 'utf8').trim(), ratings: [] }; snippets.push(s) }
    s.ratings.push(v)
  }
}

// ---- Dorn (java/python/cuda) ----
for (const lang of ['java', 'python', 'cuda']) {
  const dir = path.join(DS, 'dataset/snippets', lang)
  const ids = fs.readdirSync(dir).filter((f) => f.endsWith('.jsnp')).map((f) => Number(f.replace('.jsnp', ''))).sort((a, b) => a - b)
  const ext = lang === 'python' ? 'py' : lang === 'cuda' ? 'c' : 'java'
  const byId = new Map(ids.map((id) => [id, []]))
  for (const line of fs.readFileSync(path.join(DS, 'dataset/scores', `${lang}.csv`), 'utf8').trim().split('\n')) {
    const cols = line.split(',')
    for (let c = 1; c < cols.length; c++) {
      const v = Number(cols[c])
      if (!(v >= 1 && v <= 5)) continue
      const id = ids[c - 1]
      if (id !== undefined) byId.get(id).push(v)
    }
  }
  for (const [id, ratings] of byId) {
    if (ratings.length < 3) continue
    snippets.push({ set: `dorn-${lang}`, no: id, id: `d${lang}${id}`, code: fs.readFileSync(path.join(dir, `${id}.jsnp`), 'utf8').trim(), ratings })
  }
}

for (const s of snippets) { s.humanMean = mean(s.ratings); s.humanN = s.ratings.length; delete s.ratings }
fs.writeFileSync(path.join(WORK, 'snippets.json'), JSON.stringify(snippets.map(({ code, ...r }) => r), null, 2))

// ---- mech-repo: 全部片段写成源码文件，供机械层扫描 ----
const mechDir = path.join(WORK, 'mech-repo')
fs.rmSync(mechDir, { recursive: true, force: true })
fs.mkdirSync(mechDir, { recursive: true })
const extOf = (s) => (s.set === 'dorn-python' ? 'py' : s.set === 'dorn-cuda' ? 'c' : 'java')
for (const s of snippets) fs.writeFileSync(path.join(mechDir, `${s.id}.${extOf(s)}`), s.code + '\n')
// 机械层 scan 以 git 仓库为根（会向上找）——mech-repo 必须自己是 repo，
// 否则会扫到外层 checkout（文件未 track 也没关系，scan 含 untracked-not-ignored）
try { execFileSync('git', ['init', '-q'], { cwd: mechDir }) } catch { console.warn('warn: git init mech-repo 失败，score.mjs 的机械层部分会扫错仓库') }

// ---- grok 盲读 prompts：bw 全量 + scal 分层抽样（与已报告的校准同配方）----
function mulberry32(seed) {
  return () => {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
const grokSet = snippets.filter((s) => s.set === 'bw')
const scAll = snippets.filter((s) => s.set === 'scal').sort((a, b) => a.humanMean - b.humanMean)
for (let i = 0; i < scAll.length; i += Math.floor(scAll.length / 60)) grokSet.push(scAll[i])

fs.rmSync(path.join(WORK, 'prompts'), { recursive: true, force: true })
fs.mkdirSync(path.join(WORK, 'prompts'), { recursive: true })
for (let pass = 1; pass <= PASSES; pass++) {
  const rnd = mulberry32(pass * 7919)
  const shuffled = [...grokSet].sort(() => rnd() - 0.5)
  for (let b = 0; b * BATCH < shuffled.length; b++) {
    const chunk = shuffled.slice(b * BATCH, (b + 1) * BATCH)
    let prompt = `以下是 ${chunk.length} 个匿名 Java 代码片段（来自公开可读性标注数据集，已隐去来源）。
只凭片段本身评价「人类可读性」，给每段一个 overall 分数：1–5 的整数（1=很难读，5=很好读）。
评分时独立看待每个片段，不要相互比较后刻意拉开分布；允许给相同分数。
只输出严格 JSON，不要任何其他文字：{"ratings":[{"id":"X1","overall":3},...]}
\n`
    for (const s of chunk) prompt += `\n=== ${s.id} ===\n${s.code}\n`
    fs.writeFileSync(path.join(WORK, 'prompts', `p${pass}-b${String(b).padStart(2, '0')}.md`), prompt)
  }
}
console.log(`snippets: ${snippets.length} (grok 盲读集 ${grokSet.length})`)
console.log(`mech-repo: ${mechDir} · prompts: ${path.join(WORK, 'prompts')} (${PASSES} passes × ~${Math.ceil(grokSet.length / BATCH)} batches)`)
