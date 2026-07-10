#!/usr/bin/env bun
/**
 * atlas 笔记质量流水线编排器（QA 引擎）。在**目标仓库**里跑：
 *   cd <你的仓库> && bun <repo-atlas>/qa/run.ts <repo路径...> [--mapify] [--revise] [--stamp] [--readers 3] [--concurrency 2] [--force]
 *
 * 每个路径：缺笔记则 writer（同目录多篇合并批写）→ 墙/扁平枢纽则 mapify →
 * 轻路径（机械违规先 reviser 清掉）→ 机械lint → N盲读(并行) → 共识 → 事实核查 →
 * rubric门 → （--revise 时）修订环(≤rubric.revision_rounds_max) → .atlas/qa/<path>.json 档案。
 *
 * 通用化约定（任意带 .atlas/ 的仓库可用）：
 * - 仓库根：从 cwd 向上找第一个含 .atlas/ 的目录。
 * - prompt/rubric/schema 默认件随引擎出厂（qa/prompts、qa/rubric.json、qa/schemas）；
 *   仓库可在 .atlas/pipeline/ 放同名文件整体覆盖，或放 <名字>.extra.md 追加仓库专属规则。
 * - 仓库自有内容从仓库读：.atlas/glossary.md、.atlas/CONVENTIONS.md、.atlas/templates/default.md
 *   （后两者缺失时用 qa/defaults/ 出厂件；glossary 缺失时从空表起步）。
 * - agent CLI：默认 grok（headless），env ATLAS_QA_AGENT 可换（须兼容 grok 的参数面：
 *   --prompt-file/--json-schema/--disallowed-tools/--max-turns/--output-format json 等）。
 * - 引擎不 import repo-atlas 内核（tool ⊥ data），stamp 走同仓 dist/cli.js。
 * - 长段落/顿号串/句读检测按中文行文设计；英文笔记仓库需覆盖阈值与正则后再用。
 */
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { assertOnlyAtlasWrites, validateMermaid, DENY_TERMINAL, DENY_ALL_WRITES } from "./lib";

// 仓库根 = 从 cwd 向上第一个含 .atlas/ 的目录（引擎住在工具仓，不假设与目标仓的相对位置）。
function findRepoRoot(): string {
  let d = process.cwd();
  while (true) {
    if (existsSync(join(d, ".atlas"))) return d;
    const up = dirname(d);
    if (up === d) throw new Error("未找到 .atlas/ —— 请在带 atlas 的仓库内运行");
    d = up;
  }
}
const REPO = findRepoRoot();
const QA = new URL(".", import.meta.url).pathname.replace(/\/$/, ""); // 本引擎目录（repo-atlas/qa）
const OVERRIDE = join(REPO, ".atlas/pipeline"); // 仓库覆盖/追加处

// prompt 三层加载：仓库同名整体覆盖 > 引擎默认；<名字>.extra.md 永远追加在尾部。
function loadPrompt(name: string): string {
  const o = join(OVERRIDE, `${name}.md`);
  let text = readFileSync(existsSync(o) ? o : join(QA, "prompts", `${name}.md`), "utf8");
  const extra = join(OVERRIDE, `${name}.extra.md`);
  if (existsSync(extra)) text += `\n\n## 本仓库追加规则\n\n${readFileSync(extra, "utf8")}`;
  return text;
}
const rubric = (() => {
  const base = JSON.parse(readFileSync(join(QA, "rubric.json"), "utf8"));
  const o = join(OVERRIDE, "rubric.json");
  if (!existsSync(o)) return base;
  const over = JSON.parse(readFileSync(o, "utf8")); // 浅合并：顶层 + consensus/gates（含 reader/factcheck 子层）
  return {
    ...base, ...over,
    consensus: { ...base.consensus, ...(over.consensus ?? {}) },
    gates: {
      ...base.gates, ...(over.gates ?? {}),
      reader: { ...base.gates.reader, ...(over.gates?.reader ?? {}) },
      factcheck: { ...base.gates.factcheck, ...(over.gates?.factcheck ?? {}) },
    },
  };
})();
const glossary = existsSync(join(REPO, ".atlas/glossary.md"))
  ? readFileSync(join(REPO, ".atlas/glossary.md"), "utf8")
  : "# 词汇表\n\n（本仓库尚未建 glossary——要用反复解释的跨切术语时，先在 .atlas/glossary.md 立条目再用。）\n";
const readerPrompt = loadPrompt("reader");
const factcheckPrompt = loadPrompt("factcheck");
const reviserPrompt = loadPrompt("reviser");
const writerPrompt = loadPrompt("writer");
const mapifyPrompt = loadPrompt("mapify");
const template = existsSync(join(REPO, ".atlas/templates/default.md")) ? readFileSync(join(REPO, ".atlas/templates/default.md"), "utf8") : readFileSync(join(QA, "defaults/template.md"), "utf8");
const conventions = existsSync(join(REPO, ".atlas/CONVENTIONS.md")) ? readFileSync(join(REPO, ".atlas/CONVENTIONS.md"), "utf8") : readFileSync(join(QA, "defaults/CONVENTIONS.md"), "utf8");
const readerSchema = readFileSync(existsSync(join(OVERRIDE, "reader-schema.json")) ? join(OVERRIDE, "reader-schema.json") : join(QA, "schemas/reader-schema.json"), "utf8");
const factcheckSchema = readFileSync(existsSync(join(OVERRIDE, "factcheck-schema.json")) ? join(OVERRIDE, "factcheck-schema.json") : join(QA, "schemas/factcheck-schema.json"), "utf8");
const AGENT_BIN = process.env.ATLAS_QA_AGENT || "grok";

// ---------- CLI args ----------
const args = process.argv.slice(2);
const flag = (name: string) => args.includes(`--${name}`);
const opt = (name: string, dflt: number) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? Number(args[i + 1]) : dflt;
};
const paths = args.filter((a, i) => !a.startsWith("--") && args[i - 1]?.replace("--", "") !== "readers" && args[i - 1]?.replace("--", "") !== "concurrency");
const DO_REVISE = flag("revise");
const DO_STAMP = flag("stamp");
const FORCE = flag("force");
const DO_MAPIFY = flag("mapify");
const LOCAL_ATLAS_CLI = join(QA, "..", "dist/cli.js"); // 同仓 CLI（qa/ 的兄弟目录）；未构建时回退 bunx

// 墙判据：body（去 callout）任一 #### 节 > 35 行，或 body 总 > 130 行。地图化只打墙。
function bodySection(body: string): { bodyLines: number; maxSection: number } {
  const ci = body.indexOf('<div class="callout"');
  const b = (ci >= 0 ? body.slice(0, ci) : body).split("\n");
  let max = 0, cur = 0;
  for (const ln of b) { if (/^#### /.test(ln)) { max = Math.max(max, cur); cur = 0; } else cur++; }
  max = Math.max(max, cur);
  return { bodyLines: b.length, maxSection: max };
}
function isWall(body: string): boolean {
  const { bodyLines, maxSection } = bodySection(body);
  return maxSection > 35 || bodyLines > 130;
}
// 长段落：正文里一个段落（笔记不硬换行，一段=一行）塞太多字/句 = 没分段，读者面对一堵长段。
// callout 是渐进披露的深细节区，允许密，不算；标题/列表项/图/表/引用/HTML 不是段落。
// hard=true 用于质量门（明显的墙段），false 用于喂修订的软告警（提前一格提醒分段）。
function longParagraphs(body: string, hard: boolean): string[] {
  const ci = body.indexOf('<div class="callout"');
  const prose = (ci >= 0 ? body.slice(0, ci) : body).replace(/```[\s\S]*?```/g, "");
  const [maxLen, maxSent] = hard ? [360, 6] : [280, 4];
  const bad: string[] = [];
  for (const raw of prose.split("\n")) {
    let t = raw.trim();
    if (!t || /^(#{1,6} |>|\||!\[|<)/.test(t)) continue; // 标题/引用/表/图/HTML 不算段落
    // 列表项也算：塞满整段的 bullet 同样是墙，只是套了 - / 1. 前缀。剥掉 marker 再量长度。
    const isList = /^\s*([-*+]|\d+[.、)])\s/.test(t);
    if (isList) t = t.replace(/^\s*([-*+]|\d+[.、)])\s+/, "");
    const sentences = (t.match(/[。！？]/g) || []).length;
    if (t.length > maxLen || sentences > maxSent) bad.push(`${isList ? "列表项" : "段落"}${t.length}字${sentences}句：${t.slice(0, 38)}…`);
  }
  return bad;
}
// 元话术禁令：笔记不许讲"自己怎么读"——受众标签 / viewer 说明 / "见文末"指针。
// callout 就在下面读者自己看得见，正文不用指「见文末」。用户明令这类不能出现在 docs。
const META_PROSE = [/这一篇是地图/, /不是\s?territory/i, /初读可(跳过|略)/, /回头(排查|再看)/, /见文末/, /文末\s?(进阶|callout|细节)/i, /讲决策海拔/, /本篇(不讲|只讲|不展开)/];
function metaProse(body: string): string[] {
  const noCode = body.replace(/```[\s\S]*?```/g, "");
  const hits: string[] = [];
  for (const line of noCode.split("\n")) {
    const t = line.trim();
    if (META_PROSE.some(re => re.test(t))) hits.push(t.slice(0, 50));
  }
  return hits;
}
// 平行枚举塞进顿号串（该拆成 `-` 列表）——之前只在 prompt 里说、盲读软判，"形同虚设"。
// 这里做成机械硬门，两个高精度形状：
//   A：数量词(≥2)+量词+冒号+顿号系列 ——「三个动作：A、B、C」「四种客人：…、…、…」（排除"一个"单数）
//   B：全角括号项系列 ——「X（…）、Y（…）、Z（…）」（"）、"出现 ≥2 次 = ≥3 个带括注的并列项）
function listCandidates(body: string): string[] {
  const prose = body.replace(/```[\s\S]*?```/g, "");
  const A = /(?:[二三四五六七八九十两]|[2-9]\d*)\s*(?:个|种|块|步|条|类|扇|轴|层|面|部分|方面|点)[^，。；：\n]{0,10}[：:][^。；\n]*、[^。；\n]*、/;
  const out: string[] = [];
  for (const raw of prose.split("\n")) {
    const t = raw.trim();
    if (!t || /^(#{1,6} |>|\||!\[|<|\s*[-*+] |\s*\d+[.、)] )/.test(t)) continue; // 已是列表/标题/表/图/HTML
    // 「比如/例如 A（…）、B（…）」是举例、不是结构性枚举，行内即可——不算。
    const illustrative = /比如|例如|诸如|譬如|如：/.test(t);
    const parenSeries = !illustrative && (t.match(/）、/g) || []).length >= 2;
    if (A.test(t) || parenSeries) out.push(`${t.slice(0, 44)}…`);
  }
  return out;
}
// 扁平枢纽：内容闷在一节里，右侧「本页大纲」反映不出结构（枢纽页常见病）。按任意标题(##/###/####)切最大节。
function isFlatHub(body: string): boolean {
  const ci = body.indexOf('<div class="callout"');
  const bo = ci >= 0 ? body.slice(0, ci) : body;
  const isHub = /```mermaid/.test(body) || bo.split("\n").length > 60;
  if (!isHub) return false;
  const lines = bo.split("\n"); let max = 0, cur = 0; const secs: number[] = [];
  for (const ln of lines) { if (/^#{2,4} /.test(ln)) { secs.push(cur); cur = 0; } else cur++; }
  secs.push(cur);
  max = Math.max(...secs);
  const heads = (bo.match(/^#{2,4} /gmu) || []).length;
  return heads <= 2 || max > 55; // 单节独大 / 某节挤了 >55 行
}
const N_READERS = opt("readers", rubric.readers_per_note ?? 3);
const CONCURRENCY = opt("concurrency", 10);
if (paths.length === 0) {
  console.error("usage: cd <目标仓库> && bun <repo-atlas>/qa/run.ts <repo路径...> [--mapify] [--revise] [--stamp] [--force] [--readers N] [--concurrency N]");
  process.exit(2);
}

// ---------- helpers ----------
function notePathFor(repoPath: string): string {
  const p = repoPath.replace(/\/$/, "");
  const file = join(REPO, ".atlas/notes", p + ".md");
  const dir = join(REPO, ".atlas/notes", p, "__dir__.md");
  const root = join(REPO, ".atlas/notes/__dir__.md");
  if (p === "." || p === "") return root;
  if (existsSync(file)) return file;
  if (existsSync(dir)) return dir;
  // Missing note: place it by what the code path IS on disk — dir → __dir__.md, else file note.
  try { if (statSync(join(REPO, p)).isDirectory()) return dir; } catch { /* not on disk → treat as file */ }
  return file;
}
function stripFrontmatter(md: string): string {
  const m = md.match(/^---\n[\s\S]*?\n---\n?/);
  return m ? md.slice(m[0].length) : md;
}
// 从本路径的父目录一路往上到根，拼出整条 __dir__ 笔记链（完整，不截断）。
// 这是本笔记的"上层框架"：目录页立起角色/心智模型/词汇，文件页在其上只写特有内容、
// 省略共享概念。writer/mapify/reviser/reader 都拿它（各 prompt 自述怎么用）。
function ancestorDirs(repoPath: string): string[] {
  const dirs: string[] = [];
  let dir = repoPath.includes("/") ? repoPath.slice(0, repoPath.lastIndexOf("/")) : "";
  while (true) { dirs.push(dir); if (dir === "") break; dir = dir.includes("/") ? dir.slice(0, dir.lastIndexOf("/")) : ""; }
  return dirs;
}
// 概览段：正文开头到第一个 #### 小节 / callout 之前（枢纽页的"是什么+形状"那段），封顶 ~1400 字。
function firstSection(body: string): string {
  const cut = body.search(/\n#### |\n<div class="callout"/);
  const s = (cut >= 0 ? body.slice(0, cut) : body).trim();
  return s.length > 1400 ? s.slice(0, 1400) + "…" : s;
}
function dirOverview(d: string): string | null {
  const f = join(REPO, ".atlas/notes", d, "__dir__.md");
  return existsSync(f) ? firstSection(stripFrontmatter(readFileSync(f, "utf8"))) : null;
}
// 生产阶段(writer/mapify/reviser)：整条祖先链，但每级只给"概览"（不灌全文）——够立框架，省 token。
function frameForProducer(repoPath: string): string {
  const parts = ancestorDirs(repoPath).map(d => { const ov = dirOverview(d); return ov ? `### 目录框架：${d || "(仓库根)"}\n\n${ov}` : null; }).filter(Boolean);
  return parts.length ? `## 上层目录框架（各级概览；本笔记在此框架上写，共享概念省略别重讲、别写"见目录页"指针）\n\n${parts.join("\n\n---\n\n")}` : "";
}
// 盲读：只给直系父目录概览（判断"省略共享概念是否合理"够用；全链在 viewer drawer 里读者可查）。
function frameForReader(repoPath: string): string {
  const ov = dirOverview(repoPath.includes("/") ? repoPath.slice(0, repoPath.lastIndexOf("/")) : "");
  return ov ? `## 父目录框架（概览；viewer drawer 里读者可查全文——文件页省略这里已讲的共享概念不算缺陷）\n\n${ov}` : "";
}
// glossary 按篇裁剪：只留正文里真出现的术语条目（22k 全表 → 通常几 k）。喂给已有正文的
// 阶段（reader/mapify/reviser）；writer 从零写、正文还不存在，仍用全表。
function relevantGlossary(body: string): string {
  const parts = glossary.split(/(?=^## )/m);
  const intro = parts[0];
  const kept = parts.slice(1).filter(e => {
    const nl = e.indexOf("\n");
    const term = (nl >= 0 ? e.slice(3, nl) : e.slice(3)).trim();
    return term.length > 0 && body.includes(term);
  });
  return kept.length ? intro + kept.join("") : intro;
}
async function runGrok(promptText: string, o: { cwd: string; schema?: string; maxTurns: number; disallowed?: string; approve?: boolean; timeoutMs: number }): Promise<any> {
  const pf = join(mkdtempSync(join(tmpdir(), "atlas-qa-")), "prompt.md");
  writeFileSync(pf, promptText);
  const argv = [AGENT_BIN, "--prompt-file", pf, "--no-memory", "--disable-web-search", "--no-subagents", "--max-turns", String(o.maxTurns), "--output-format", "json"];
  if (o.schema) argv.push("--json-schema", o.schema);
  if (o.disallowed) argv.push("--disallowed-tools", o.disallowed);
  if (o.approve) argv.push("--always-approve");
  const proc = Bun.spawn(argv, { cwd: o.cwd, stdout: "pipe", stderr: "pipe" });
  const killer = setTimeout(() => proc.kill(), o.timeoutMs);
  const out = await new Response(proc.stdout).text();
  clearTimeout(killer);
  await proc.exited;
  rmSync(dirname(pf), { recursive: true, force: true });
  try { return JSON.parse(out); } catch { return { text: out, structuredOutput: null }; }
}
// grok --json-schema 只校验不约束解码；结构化失败时从 text 里宽容捞 JSON
function lenientParse(grokOut: any): any | null {
  if (grokOut?.structuredOutput) return grokOut.structuredOutput;
  const t: string = (grokOut?.text ?? "").trim();
  const start = t.indexOf("{");
  const end = t.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try { return JSON.parse(t.slice(start, end + 1)); } catch { return null; }
}
// bigram dice 相似度（共识句子模糊匹配）
function similarity(a: string, b: string): number {
  const grams = (s: string) => {
    const g = new Map<string, number>();
    for (let i = 0; i < s.length - 1; i++) { const k = s.slice(i, i + 2); g.set(k, (g.get(k) ?? 0) + 1); }
    return g;
  };
  const ga = grams(a), gb = grams(b);
  let inter = 0, total = 0;
  for (const [k, v] of ga) { inter += Math.min(v, gb.get(k) ?? 0); total += v; }
  for (const v of gb.values()) total += v;
  return total === 0 ? 0 : (2 * inter) / total;
}
// 守卫比较"哪些路径脏了"而非暂存位——共享工作区里别的 agent 随时 add/restore，状态列翻转不代表越界写入。
function dirtyPaths(): Set<string> {
  const out = new TextDecoder().decode(Bun.spawnSync(["git", "status", "--porcelain"], { cwd: REPO }).stdout);
  return new Set(out.split("\n").filter(Boolean).map(l => l.slice(3).trim()));
}
// 关键不变量（CLAUDE.md 最高优先级）：本流水线的 grok 会话只许弄脏 .atlas/ 下的东西（笔记 body + QA 档案）。
// 任何 .atlas/ 之外的新脏路径 = 会话跑去改了源码或别人在飞的活，必须中止并报警。
// 只看 .atlas/ 外部，天然并发安全：并发修订各自改自己的 .atlas/notes/*.md 不会互相误伤。
function newDirtyOutsideAtlas(before: Set<string>): string[] {
  return [...dirtyPaths()].filter(p => !before.has(p) && !p.startsWith(".atlas/"));
}
function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
}

// ---------- 机械 lint（v1：只出警告喂给修订，不做硬门） ----------
function lint(body: string): string[] {
  const issues: string[] = [];
  const noCode = body.replace(/```[\s\S]*?```/g, "");
  if (/L\d{2,}\b/.test(noCode)) issues.push("疑似行号引用（会腐烂，应换 code: 锚点）");
  for (const p of ["值得注意的是", "有意思的是", "我们来看", "挑几个说", "一定要注意", "答案是——"])
    if (noCode.includes(p)) issues.push(`禁令句式：「${p}」`);
  for (const m of body.matchAll(/```(?!mermaid)[a-z]*\n([\s\S]*?)```/g))
    if (/^\s*(export |import |const \w+ =)/m.test(m[1])) issues.push("疑似围栏内粘贴仓库源码（应换 code: 嵌入）");
  for (const line of noCode.split("\n"))
    for (const sent of line.split(/[。；]/))
      if (sent.length > 110 && (sent.match(/`[^`]+`/g)?.length ?? 0) >= 4)
        issues.push(`高密度候审句：${sent.slice(0, 60)}…`);
  // 墙告警：body 单节过长 / 正文过长 = 海拔没分层，应地图化（细节下沉子笔记或 callout）。
  const { bodyLines, maxSection } = bodySection(body);
  if (maxSection > 35) issues.push(`section 过长（最长 ${maxSection} 行 > 35）：这一节是墙，把机制下沉到子笔记或 callout，正文只留决策海拔`);
  if (bodyLines > 130) issues.push(`正文过长（${bodyLines} 行 > 130，不含 callout）：整页缺循序渐进，按"地图不是territory"重排`);
  // 扁平结构告警：枢纽页内容全闷在「概览」下、真分节用加粗伪标题 → 右侧大纲看不见结构。
  const headings = (noCode.match(/^#{2,4} /gmu) || []).length;
  const ovMatch = noCode.match(/^###?\s*概览[\s\S]*?(?=^#{2,4} |<div class="callout"|$)/mu);
  const ovLines = ovMatch ? ovMatch[0].split("\n").length : 0;
  const isHubBody = /```mermaid/.test(body) || bodyLines > 60;
  if (isHubBody && (ovLines > 18 || headings < 3))
    issues.push(`结构扁平（概览 ${ovLines} 行 / 标题 ${headings} 个）：内容闷在概览下，每个真实小节开一个 #### 标题，让右侧「本页大纲」能反映结构`);
  // 长段落告警：一段塞太多字/句 = 没分段换行。软阈值（比硬门低一格），提前提醒拆段。
  for (const p of longParagraphs(body, false))
    issues.push(`段落过长（${p}）：分段换行，一段讲一件事；平行项改 - 列表`);
  // 图表密度告警：长页无图 = 散文墙的另一种形态。图=mermaid；表=markdown 表头分隔行或 <table>。
  const figures = (body.match(/```mermaid/g) || []).length
    + (body.match(/^\s*\|[-: |]+\|\s*$/gm) || []).length
    + (body.match(/<table\b/g) || []).length;
  if (bodyLines > 60 && figures === 0)
    issues.push(`长页无图表（正文 ${bodyLines} 行，图/表 0）：至少给 1 张——形态变换给具体实例两侧对照（并排 JSON/HTML 双栏），管线/分派画 mermaid（真实节点名）`);
  else if (bodyLines > 110 && figures < 2)
    issues.push(`图表不足（正文 ${bodyLines} 行，图/表 ${figures} < 2）：把逐句描述"A 键变 B 字段"的散文段改成对照图/表`);
  return issues;
}

// ---------- 门 ----------
type WeakSection = { section: string; median: number; comments: string[] };
type GateResult = {
  pass: boolean; reasons: string[];
  overallMedian: number; worstSection: [string, number] | null;
  consensusUnclear: { sentence: string; reasons: string[] }[];
  weakSections: WeakSection[];
  unsupported: any[]; noteMisleading: any[]; retellOkAll: boolean;
  concretenessMedian: number; abstractSpots: string[]; isHub: boolean;
  longParas: string[]; metaHits: string[]; listCand: string[];
};
function evaluate(readers: any[], factcheck: any, body = ""): GateResult {
  const g = rubric.gates, fuzz = rubric.consensus.fuzzy_ratio;
  // 渐进披露：「进阶细节」callout 是刻意的、可跳过的深细节区，允许密。它的句子不计入
  // 共识读不懂（否则地图正文再干净，也会被 callout 密度拖挂——惩罚了渐进披露本身）。
  const cIdx = body.indexOf('<div class="callout"');
  const calloutText = cIdx >= 0 ? body.slice(cIdx) : "";
  const inCallout = (s: string) => calloutText.length > 0 && calloutText.includes(s.slice(0, 30));
  // 共识 = 过半读者：随读者数缩放，保持「majority-of-N」语义（3→2, 5→3）
  const minFlag = rubric.consensus.flagged_by_min ?? (Math.floor(readers.length / 2) + 1);
  const overallMedian = median(readers.map(r => r.overall_score));
  // 分节中位（排除进阶 callout）
  const secScores = new Map<string, { scores: number[]; comments: string[] }>();
  for (const r of readers) for (const s of r.section_scores ?? []) {
    if (/进阶|callout/i.test(s.section)) continue;
    if (!secScores.has(s.section)) secScores.set(s.section, { scores: [], comments: [] });
    const e = secScores.get(s.section)!;
    e.scores.push(s.score);
    if (s.comment) e.comments.push(`${s.score}: ${s.comment}`);
  }
  let worstSection: [string, number] | null = null;
  const weakSections: WeakSection[] = [];
  for (const [name, { scores, comments }] of secScores) {
    const m = median(scores);
    if (!worstSection || m < worstSection[1]) worstSection = [name, m];
    if (m < g.reader.section_score_median_min) weakSections.push({ section: name, median: m, comments });
  }
  weakSections.sort((a, b) => a.median - b.median);
  // 共识读不懂句子
  const perReader = readers.map(r => (r.unclear_sentences ?? []).map((u: any) => u.sentence as string));
  const consensusUnclear: { sentence: string; reasons: string[] }[] = [];
  for (const cand of perReader.flat()) {
    if (inCallout(cand)) continue; // callout 深细节区的句子不计入共识
    const hits = perReader.filter(grp => grp.some(t => similarity(cand, t) > fuzz)).length;
    if (hits >= minFlag && !consensusUnclear.some(c => similarity(cand, c.sentence) > fuzz)) {
      const reasons = readers.flatMap(r => (r.unclear_sentences ?? []).filter((u: any) => similarity(u.sentence, cand) > fuzz).map((u: any) => `${u.reason}: ${u.note ?? ""}`));
      consensusUnclear.push({ sentence: cand, reasons });
    }
  }
  const retellOkAll = readers.every(r => r.retell_ok !== false);
  const unsupported = (factcheck?.claims ?? []).filter((c: any) => c.verdict === "unsupported");
  const noteMisleading = (factcheck?.retell_check?.issues ?? []).filter((i: any) => i.blame === "note_misleading");
  // 具体度：只对枢纽页强制（dir 笔记、含 mermaid、或正文>60 行——即会讲多个概念/机制的页）。
  const cScores = readers.map(r => r.concreteness).filter((x: any) => typeof x === "number");
  const concretenessMedian = cScores.length ? median(cScores) : 5;
  const abstractSpots = [...new Set(readers.flatMap(r => r.abstract_spots ?? []))].slice(0, 8) as string[];
  const bodyNoCallout = cIdx >= 0 ? body.slice(0, cIdx) : body;
  const isHub = /```mermaid/.test(body) || bodyNoCallout.split("\n").length > 60;
  const longParas = longParagraphs(body, true); // 硬门：正文里的墙段（一段过长未分段）
  const metaHits = metaProse(body); // 硬门：元话术（"见文末"/受众标签/viewer 说明）
  const listCand = listCandidates(body); // 硬门：平行枚举顿号串（该拆成 - 列表）
  const reasons: string[] = [];
  if (consensusUnclear.length > g.reader.consensus_unclear_max) reasons.push(`共识读不懂 ${consensusUnclear.length} > ${g.reader.consensus_unclear_max}`);
  if (worstSection && worstSection[1] < g.reader.section_score_median_min) reasons.push(`最差章节「${worstSection[0]}」中位 ${worstSection[1]} < ${g.reader.section_score_median_min}`);
  if (overallMedian < g.reader.overall_score_median_min) reasons.push(`overall 中位 ${overallMedian} < ${g.reader.overall_score_median_min}`);
  if (g.reader.retell_ok_required && !retellOkAll) reasons.push("有盲读者无法复述");
  if (isHub && g.reader.concreteness_median_min && concretenessMedian < g.reader.concreteness_median_min)
    reasons.push(`具体度 ${concretenessMedian} < ${g.reader.concreteness_median_min}（枢纽页太抽象，缺真实调用走查/具体例子）`);
  if (unsupported.length > g.factcheck.unsupported_max) reasons.push(`unsupported 断言 ${unsupported.length} 条`);
  if (noteMisleading.length > g.factcheck.note_misleading_max) reasons.push(`笔记误导复述 ${noteMisleading.length} 处`);
  if (longParas.length) reasons.push(`长段落 ${longParas.length} 处（一段过长未分段——拆成多段、每段一件事、平行项改列表）`);
  if (metaHits.length) reasons.push(`元话术 ${metaHits.length} 处（"见文末"/受众标签/viewer 说明——删掉，笔记只讲代码不讲自己怎么读）`);
  if (listCand.length) reasons.push(`平行枚举顿号串 ${listCand.length} 处（"N个X：A、B、C" 或 "X（…）、Y（…）、Z（…）"——拆成 - 列表，一项一行）`);
  return { pass: reasons.length === 0, reasons, overallMedian, worstSection, consensusUnclear, weakSections, unsupported, noteMisleading, retellOkAll, concretenessMedian, abstractSpots, isHub, longParas, metaHits, listCand };
}

// ---------- 各阶段 ----------
// 必须用 grok 的真实工具名（lib.DENY_*）——旧的 "Shell,Write,StrReplace…" 是 Claude Code
// 名字，grok 静默忽略，等于从没拦过（2026-07-10 探针实证后修正）。
// 生产阶段禁终端 → 所有写入必经 write/search_replace → transcript 可精确归因。
const DISALLOW_RO = DENY_ALL_WRITES;
const DISALLOW_REVISE = DENY_TERMINAL;

async function runReaders(repoPath: string, body: string): Promise<any[]> {
  const input = `${readerPrompt}\n## 术语表（glossary，可随时查阅）\n\n${relevantGlossary(body)}\n\n${frameForReader(repoPath)}\n\n## 笔记正文（这篇笔记描述的路径：${repoPath}）\n\n${body}`;
  const outs = await Promise.all(Array.from({ length: N_READERS }, () => {
    const emptyCwd = mkdtempSync(join(tmpdir(), "atlas-blind-")); // 空目录 = 结构性无码权限
    return runGrok(input, { cwd: emptyCwd, schema: readerSchema, maxTurns: 6, timeoutMs: 600_000 })
      .finally(() => rmSync(emptyCwd, { recursive: true, force: true }));
  }));
  const parsed = outs.map(lenientParse).filter(Boolean);
  if (parsed.length < Math.min(N_READERS, 2)) throw new Error(`盲读解析失败过多（${parsed.length}/${N_READERS}）`);
  return parsed;
}
async function runFactcheck(repoPath: string, body: string, reader: any): Promise<any> {
  const retell = `${reader.retell}\n关键决定: ${(reader.key_decisions ?? []).join(" / ")}`;
  const input = `${factcheckPrompt}\n## 目标路径\n\n${repoPath}（仓库根：${REPO}）\n\n## 笔记正文\n\n${body}\n\n## 盲读者复述（请核对）\n\n${retell}`;
  const before = dirtyPaths();
  const out = await runGrok(input, { cwd: REPO, schema: factcheckSchema, maxTurns: 40, disallowed: DISALLOW_RO, approve: true, timeoutMs: 900_000 });
  assertOnlyAtlasWrites(REPO, REPO, out?.sessionId, before, `事实核查(${repoPath})`);
  const parsed = lenientParse(out);
  if (!parsed?.claims) throw new Error("事实核查输出解析失败");
  return parsed;
}
async function runReviser(repoPath: string, noteFile: string, gate: GateResult, lintIssues: string[]): Promise<string> {
  const issues = [
    "## 盲读共识问题（过半读者标了同一句 → 优先修）",
    ...gate.consensusUnclear.map(c => `- 「${c.sentence}」\n  - ${c.reasons.join("\n  - ")}`),
    "## 低分章节（盲读者认为这一节整体不合格，可能需要给独立内容、合并进相邻节、或删除冗余薄节）",
    ...gate.weakSections.map(w => `- 「${w.section}」中位 ${w.median} 分\n  - ${w.comments.join("\n  - ") || "（无评语）"}`),
    ...(gate.isHub && gate.concretenessMedian < rubric.gates.reader.concreteness_median_min ? [
      `## 太抽象（具体度 ${gate.concretenessMedian}）——这些地方只给了比喻/机制名词，要用一个真实例子或一次真实调用走查落地（点名真实标识符、真实路径，走一遍）：`,
      ...gate.abstractSpots.map((s: string) => `- ${s}`),
    ] : []),
    "## 事实核查 unsupported 断言",
    ...gate.unsupported.map((c: any) => `- 断言：「${c.claim}」\n  - 证据：${c.evidence}`),
    "## 笔记误导了盲读者的复述",
    ...gate.noteMisleading.map((i: any) => `- ${i.issue}（笔记原句：「${i.note_quote ?? ""}」）`),
    ...(gate.longParas.length ? [
      "## 长段落（硬门：一段过长未分段）——把这些段拆开：每段只讲一件事、段间空行；平行枚举（A、B、C 顿号串）改成 - 列表；跨切概念一句点到别展开",
      ...gate.longParas.map((p: string) => `- ${p}`),
    ] : []),
    ...(gate.metaHits.length ? [
      "## 元话术（硬门）——删掉这些「讲自己怎么读」的话：受众标签、viewer 说明、「见文末 / 见 callout」指针。callout 就在正文下方，读者自己看得见，不用指。笔记只讲被描述的代码。",
      ...gate.metaHits.map((p: string) => `- 「${p}」`),
    ] : []),
    ...(gate.listCand.length ? [
      "## 平行枚举顿号串（硬门）——把这些拆成 `-` 列表，一项一行：凡是「N个X：A、B、C」或「X（说明）、Y（说明）、Z（说明）」这种各自独立、调换顺序不影响理解的并列项，读者要逐项扫，扫不了长句里的顿号串。",
      ...gate.listCand.map((p: string) => `- ${p}`),
    ] : []),
    "## 机械 lint 警告",
    ...lintIssues.map(l => `- ${l}`),
  ].join("\n");
  const reviserBody = stripFrontmatter(readFileSync(noteFile, "utf8"));
  const input = `${reviserPrompt}\n## 目标\n\n被描述的源码路径：${repoPath}\n**唯一允许修改的文件**：${noteFile}\n\n${issues}\n\n## 术语表\n\n${relevantGlossary(reviserBody)}\n\n${frameForProducer(repoPath)}`;
  const before = dirtyPaths();
  const beforeNote = readFileSync(noteFile, "utf8");
  const out = await runGrok(input, { cwd: REPO, maxTurns: 60, disallowed: DISALLOW_REVISE, approve: true, timeoutMs: 1_200_000 });
  const rel = noteFile.slice(REPO.length + 1);
  assertOnlyAtlasWrites(REPO, REPO, out?.sessionId, before, `修订(${repoPath})`);
  if (readFileSync(noteFile, "utf8") === beforeNote) console.warn(`  ⚠ 修订会话没有改动 ${rel}`);
  return out?.text ?? "";
}

// ---------- writer：从零写一篇缺失的笔记 ----------
async function runWriter(repoPath: string, noteFile: string): Promise<string> {
  const isDir = noteFile.endsWith("__dir__.md");
  // 邻居上下文：父目录的 __dir__ 笔记（若有）——让 writer 知道本路径在局部的位置
  const input = `${writerPrompt}\n## 目标\n\n描述的仓库路径：\`${repoPath}\`（${isDir ? "目录" : "文件"}）\n要写到的笔记文件：\`${noteFile.slice(REPO.length + 1)}\`\n\n## 模板\n\n${template.slice(0, 3500)}\n\n## 规范\n\n${conventions.slice(0, 2500)}\n\n## 术语表（用里面的术语，别重讲这些概念）\n\n${glossary}\n\n${frameForProducer(repoPath)}`;
  const before = dirtyPaths();
  mkdirSync(dirname(noteFile), { recursive: true });
  const out = await runGrok(input, { cwd: REPO, maxTurns: 60, disallowed: DISALLOW_REVISE, approve: true, timeoutMs: 1_200_000 });
  assertOnlyAtlasWrites(REPO, REPO, out?.sessionId, before, `写作(${repoPath})`);
  return out?.text ?? "";
}

// ---------- mapify：把墙笔记结构性重排成地图 ----------
async function runMapify(repoPath: string, noteFile: string): Promise<string> {
  const body = stripFrontmatter(readFileSync(noteFile, "utf8"));
  const input = `${mapifyPrompt}\n## 目标\n\n描述的仓库路径：\`${repoPath}\`\n要改写的笔记文件：\`${noteFile.slice(REPO.length + 1)}\`\n\n## 当前笔记正文（这堵墙）\n\n${body}\n\n## 术语表（用术语点到，别重讲）\n\n${relevantGlossary(body)}\n\n${frameForProducer(repoPath)}`;
  const before = dirtyPaths();
  const out = await runGrok(input, { cwd: REPO, maxTurns: 60, disallowed: DISALLOW_REVISE, approve: true, timeoutMs: 1_200_000 });
  assertOnlyAtlasWrites(REPO, REPO, out?.sessionId, before, `地图化(${repoPath})`);
  return out?.text ?? "";
}

// 只用静态可测维度（顿号串/长段/元话术）构一个 GateResult，喂 reviser 走"轻路径"——
// 这些机械违规不用盲读+核查去发现，reviser 直接按清单改即可。
function staticGate(body: string): GateResult {
  const longParas = longParagraphs(body, true);
  const metaHits = metaProse(body);
  const listCand = listCandidates(body);
  return {
    pass: longParas.length + metaHits.length + listCand.length === 0,
    reasons: [], overallMedian: 5, worstSection: null, consensusUnclear: [],
    weakSections: [], unsupported: [], noteMisleading: [], retellOkAll: true,
    concretenessMedian: 5, abstractSpots: [], isHub: false, longParas, metaHits, listCand,
  };
}

// ---------- 主循环 ----------
// 目录批处理：同目录多篇缺失笔记合并给一个 writer，共享上下文（模板/规范/术语/框架）只发一次。
async function runWriterBatch(dir: string, repoPaths: string[]): Promise<void> {
  const targets = repoPaths.map(rp => {
    const nf = notePathFor(rp);
    return `- \`${rp}\`（${nf.endsWith("__dir__.md") ? "目录" : "文件"}）→ 写入 \`${nf.slice(REPO.length + 1)}\``;
  }).join("\n");
  const input = `${writerPrompt}\n## 目标（一次新建同目录下多篇缺失笔记）\n\n下面是同一目录 \`${dir}\` 下需要**从零新建**的笔记。**逐个**读对应源码、各写一篇，用 Write 工具**分别落盘每个笔记文件**。共享上下文（模板/规范/术语表/目录框架）只给一次，但每篇要各自完整、独立成篇。\n\n${targets}\n\n## 模板\n\n${template.slice(0, 3500)}\n\n## 规范\n\n${conventions.slice(0, 2500)}\n\n## 术语表\n\n${glossary}\n\n${frameForProducer(repoPaths[0])}`;
  const before = dirtyPaths();
  for (const rp of repoPaths) mkdirSync(dirname(notePathFor(rp)), { recursive: true });
  const out = await runGrok(input, { cwd: REPO, maxTurns: 120, disallowed: DISALLOW_REVISE, approve: true, timeoutMs: 1_800_000 });
  assertOnlyAtlasWrites(REPO, REPO, out?.sessionId, before, `批量写作(${dir})`);
}

async function processPath(repoPath: string) {
  const noteFile = notePathFor(repoPath);
  const qaFile = join(REPO, ".atlas/qa", repoPath.replace(/\/$/, "") + ".json");
  // 断点续跑：已过门的笔记直接跳过（--force 强制重跑）。让整夜任务崩了能原地续，不重做已完成的。
  if (!FORCE && existsSync(qaFile)) {
    try {
      const prev = JSON.parse(readFileSync(qaFile, "utf8"));
      if (prev.finalPass) { console.log(`[${repoPath}] ⏭  已过门，跳过`); return { repoPath, pass: true, reasons: [], rounds: 0, skipped: true }; }
    } catch { /* 档案损坏则重跑 */ }
  }
  // 缺笔记：先跑 writer 从零写一篇（写进 noteFile），再进 QA 环。
  if (!existsSync(noteFile)) {
    console.log(`[${repoPath}] ✍ 笔记缺失，writer 从零写…`);
    await runWriter(repoPath, noteFile);
    if (!existsSync(noteFile)) return { repoPath, pass: false, reasons: ["writer 未能创建笔记"], rounds: 0 };
  }
  // 墙 或 扁平枢纽：地图化(结构性重排——拆 #### 小节、概览收短、机制下沉)，再进 QA 环。
  if (DO_MAPIFY) {
    const b0 = stripFrontmatter(readFileSync(noteFile, "utf8"));
    if (isWall(b0) || isFlatHub(b0)) {
      const s = bodySection(b0);
      console.log(`[${repoPath}] 🗺  ${isWall(b0) ? "墙" : "扁平枢纽"}(正文${s.bodyLines}行)，mapify 地图化…`);
      await runMapify(repoPath, noteFile);
    }
  }
  // 轻路径：进 QA 环前先用 reviser 把机械违规（顿号串/长段/元话术）清干净，不跑盲读+核查。
  // 这些静态就能测出，不必让 5 读者+核查去"发现"；把最贵的两步留给静态干净的笔记。
  if (DO_REVISE) {
    for (let s = 0; s < 3; s++) {
      const b = stripFrontmatter(readFileSync(noteFile, "utf8"));
      const sg = staticGate(b);
      const mm = await validateMermaid(b);
      if (sg.pass && mm.length === 0) break;
      const n = sg.longParas.length + sg.metaHits.length + sg.listCand.length + mm.length;
      console.log(`[${repoPath}] 轻路径：修 ${n} 处机械违规（不跑盲读/核查）…`);
      await runReviser(repoPath, noteFile, sg, [...lint(b), ...mm]);
    }
  }
  const record: any = { path: repoPath, note: noteFile.slice(REPO.length + 1), rubricVersion: rubric.version, startedAt: new Date().toISOString(), rounds: [] };
  const fullBefore = readFileSync(noteFile, "utf8");
  const frontmatter = fullBefore.slice(0, fullBefore.length - stripFrontmatter(fullBefore).length);
  record.originalBody = stripFrontmatter(fullBefore);
  let finalGate: GateResult | null = null;
  // 保留最好一轮而非最后一轮：修订可能把笔记越改越差（实测出现过 round1 共识3 → round2 共识7）。
  // penalty 越低越好；结束时若磁盘上的 body 不是最好那版，把最好那版写回。
  // 通过轮永远胜出（penalty -1）；否则按违规加权。避免"失败轮与通过轮 penalty 打平时错留失败轮"。
  const penalty = (g: GateResult) => g.pass ? -1 : g.consensusUnclear.length + g.unsupported.length * 3 + g.noteMisleading.length * 3 + g.weakSections.length * 2 + g.longParas.length * 2 + g.metaHits.length * 2 + g.listCand.length * 2 + (g.retellOkAll ? 0 : 5) + Math.max(0, (rubric.gates.reader.overall_score_median_min - g.overallMedian)) + (g.isHub ? Math.max(0, (rubric.gates.reader.concreteness_median_min - g.concretenessMedian)) * 2 : 0);
  let best: { body: string; gate: GateResult; pen: number } | null = null;
  const maxRounds = 1 + (DO_REVISE ? rubric.gates.revision_rounds_max : 0);
  try {
  for (let round = 0; round < maxRounds; round++) {
    const body = stripFrontmatter(readFileSync(noteFile, "utf8"));
    const mermaidErrs = await validateMermaid(body);
    const lintIssues = [...lint(body), ...mermaidErrs];
    console.log(`[${repoPath}] round ${round}: lint=${lintIssues.length}，盲读 ×${N_READERS}…`);
    const readers = await runReaders(repoPath, body);
    console.log(`[${repoPath}] round ${round}: 事实核查…`);
    const factcheck = await runFactcheck(repoPath, body, readers[0]);
    const gate = evaluate(readers, factcheck, body);
    if (mermaidErrs.length) { gate.pass = false; gate.reasons.push(`mermaid 解析失败 ${mermaidErrs.length} 块（机械硬门）`); }
    record.rounds.push({ round, lintIssues, readers, factcheck, gate: { ...gate, consensusUnclear: gate.consensusUnclear } });
    finalGate = gate;
    const pen = penalty(gate);
    if (!best || pen < best.pen) best = { body, gate, pen };
    console.log(`[${repoPath}] round ${round}: ${gate.pass ? "✅ 过门" : `❌ ${gate.reasons.join("；")}`}（penalty ${pen}）`);
    if (gate.pass || round === maxRounds - 1) break;
    console.log(`[${repoPath}] round ${round}: 修订中…`);
    const summary = await runReviser(repoPath, noteFile, gate, lintIssues);
    record.rounds.at(-1).reviserSummary = summary;
  }
  // 把最好一轮的 body 写回磁盘（若它不是当前磁盘上的版本）
  if (best && stripFrontmatter(readFileSync(noteFile, "utf8")) !== best.body) {
    writeFileSync(noteFile, frontmatter + best.body);
    console.log(`[${repoPath}] 回退到最好一轮（penalty ${best.pen}）`);
  }
  if (best) finalGate = best.gate;
  } finally {
    // 失败/中止也落档案——半程结果（盲读报告、核查证据）是返工的输入，不许丢
    record.finalPass = finalGate?.pass ?? false;
    record.bestPenalty = best?.pen ?? null;
    record.finishedAt = new Date().toISOString();
    mkdirSync(dirname(qaFile), { recursive: true });
    writeFileSync(qaFile, JSON.stringify(record, null, 1));
  }
  if (finalGate!.pass && DO_STAMP) {
    // 本地 repo-atlas 优先（避免每篇 bunx 重新下载工具）；stamp 只动这一篇的 frontmatter
    const st = existsSync(LOCAL_ATLAS_CLI)
      ? Bun.spawnSync(["bun", LOCAL_ATLAS_CLI, "stamp", repoPath], { cwd: REPO })
      : Bun.spawnSync(["bunx", "github:KUD-00/repo-atlas", "stamp", repoPath], { cwd: REPO });
    console.log(`[${repoPath}] stamp: ${st.exitCode === 0 ? "ok" : new TextDecoder().decode(st.stderr).trim().slice(0, 120)}`);
  }
  return { repoPath, pass: finalGate!.pass, reasons: finalGate!.reasons, rounds: record.rounds.length };
}

// 目录批处理预跑：同目录、缺笔记的路径合并给一个 writer（共享上下文只发一次）。
// 只对确实缺 .md 的路径；singleton 目录留给 processPath 逐篇写。跑完笔记就存在了，
// 主队列不再触发单篇 writer，直接进 QA。对"多为存量"的目录几乎是空操作；对新建为主的仓库省最多。
{
  const missing = paths.filter(p => !existsSync(notePathFor(p)));
  const byDir = new Map<string, string[]>();
  for (const p of missing) {
    const d = p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "";
    const arr = byDir.get(d);
    if (arr) arr.push(p); else byDir.set(d, [p]);
  }
  const batches: [string, string[]][] = [];
  for (const [d, ps] of byDir) {
    if (ps.length < 2) continue; // 单篇留给逐篇 writer
    for (let i = 0; i < ps.length; i += 6) batches.push([d, ps.slice(i, i + 6)]); // 封顶 6 篇/批
  }
  if (batches.length) {
    console.log(`✍ 目录批处理：${batches.length} 批（同目录多篇缺失笔记合并新建）`);
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, batches.length) }, async () => {
      while (batches.length) {
        const [d, ps] = batches.shift()!;
        try { await runWriterBatch(d, ps); }
        catch (e: any) { console.warn(`批量写作 ${d}/ 失败，回退逐篇：${e.message}`); }
      }
    }));
  }
}
const results: any[] = [];
const queue = [...paths];
await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
  while (queue.length) {
    const p = queue.shift()!;
    try { results.push(await processPath(p)); }
    catch (e: any) { results.push({ repoPath: p, pass: false, reasons: [`pipeline error: ${e.message}`], rounds: 0 }); }
  }
}));
console.log("\n===== 汇总 =====");
for (const r of results) console.log(`${r.pass ? (r.skipped ? "⏭ " : "✅") : "❌"} ${r.repoPath}  (${r.rounds} 轮)${r.pass ? "" : "  " + r.reasons.join("；")}`);
const passed = results.filter(r => r.pass).length;
console.log(`\n过门 ${passed}/${results.length}（其中跳过 ${results.filter(r => r.skipped).length}），未过 ${results.length - passed}`);
process.exit(results.every(r => r.pass) ? 0 : 1);
