#!/usr/bin/env bun
/**
 * 概念抽取编排器。把跨切概念收敛成「唯一归属页讲全 + glossary 一行本质 + 家门外瘦身成一句+指路」。
 * 在目标仓库里跑：
 *   cd <你的仓库> && bun <repo-atlas>/qa/extract.ts <conceptId...>|--all [--concurrency 4] [--dry]
 * 概念清单是仓库自有内容：.atlas/pipeline/concepts.json
 *   { "includeRoots": ["src", "packages"], "concepts": [{ id, name, pattern, home, homeType, glossary: [{term, hint}] }] }
 * 之后用 QA 门复验触碰的笔记：
 *   bun <repo-atlas>/qa/run.ts <触碰的路径...> --revise --stamp --force
 *
 * 设计：概念间串行（glossary 写串行、避免同一篇被两概念并发改）；概念内瘦身并发。
 * 不 import repo-atlas 内核（只 CLI + 目录约定）。
 */
import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync, appendFileSync } from "node:fs";
import { assertOnlyAtlasWrites } from "./lib";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

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
const QA = new URL(".", import.meta.url).pathname.replace(/\/$/, "");
const PIPE = join(REPO, ".atlas/pipeline"); // 仓库自有：concepts.json 与 extract-touched.txt 落这里
const GLOSSARY = join(REPO, ".atlas/glossary.md");
if (!existsSync(join(PIPE, "concepts.json"))) { console.error("缺 .atlas/pipeline/concepts.json（概念清单是仓库自有内容，格式见本文件头注释）"); process.exit(2); }
const spec = JSON.parse(readFileSync(join(PIPE, "concepts.json"), "utf8"));
const template = existsSync(join(REPO, ".atlas/templates/default.md")) ? readFileSync(join(REPO, ".atlas/templates/default.md"), "utf8") : readFileSync(join(QA, "defaults/template.md"), "utf8");
const conventions = existsSync(join(REPO, ".atlas/CONVENTIONS.md")) ? readFileSync(join(REPO, ".atlas/CONVENTIONS.md"), "utf8") : readFileSync(join(QA, "defaults/CONVENTIONS.md"), "utf8");
const AGENT_BIN = process.env.ATLAS_QA_AGENT || "grok";

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(`--${n}`);
const optNum = (n: string, d: number) => { const i = args.indexOf(`--${n}`); return i >= 0 ? Number(args[i + 1]) : d; };
const DRY = flag("dry");
const CONC = optNum("concurrency", 10);
const wanted = flag("all") ? spec.concepts.map((c: any) => c.id) : args.filter(a => !a.startsWith("--") && !/^\d+$/.test(a));
if (!wanted.length) { console.error("usage: bun extract.ts <conceptId...>|--all [--concurrency N] [--dry]"); process.exit(2); }

// ---------- 共用 helper（与 run.ts 同源） ----------
function noteFileFor(repoPath: string, type: "dir" | "file"): string {
  return join(REPO, ".atlas/notes", repoPath + (type === "dir" ? "/__dir__.md" : ".md"));
}
function stripFrontmatter(md: string): string { const m = md.match(/^---\n[\s\S]*?\n---\n?/); return m ? md.slice(m[0].length) : md; }
function dirtyPaths(): Set<string> {
  const out = new TextDecoder().decode(Bun.spawnSync(["git", "status", "--porcelain"], { cwd: REPO }).stdout);
  return new Set(out.split("\n").filter(Boolean).map(l => l.slice(3).trim()));
}
// 关键不变量：grok 会话只许弄脏 .atlas/ 下的东西。任何 .atlas 外新脏路径 = 越界改源码/别人的活，中止。
function newDirtyOutsideAtlas(before: Set<string>): string[] {
  return [...dirtyPaths()].filter(p => !before.has(p) && !p.startsWith(".atlas/"));
}
async function runGrok(prompt: string, o: { schema?: string; maxTurns: number; disallowed?: string; timeoutMs: number }): Promise<any> {
  const pf = join(mkdtempSync(join(tmpdir(), "atlas-ext-")), "p.md");
  writeFileSync(pf, prompt);
  const argv = [AGENT_BIN, "--prompt-file", pf, "--no-memory", "--disable-web-search", "--no-subagents", "--always-approve", "--max-turns", String(o.maxTurns), "--output-format", "json"];
  if (o.schema) argv.push("--json-schema", o.schema);
  if (o.disallowed) argv.push("--disallowed-tools", o.disallowed);
  const proc = Bun.spawn(argv, { cwd: REPO, stdout: "pipe", stderr: "pipe" });
  const t = setTimeout(() => proc.kill(), o.timeoutMs);
  const out = await new Response(proc.stdout).text();
  clearTimeout(t); await proc.exited;
  rmSync(dirname(pf), { recursive: true, force: true });
  try { return JSON.parse(out); } catch { return { text: out, structuredOutput: null }; }
}
function lenient(g: any): any | null {
  if (g?.structuredOutput) return g.structuredOutput;
  const t: string = (g?.text ?? "").trim();
  const s = t.indexOf("{"), e = t.lastIndexOf("}");
  if (s < 0 || e <= s) return null;
  try { return JSON.parse(t.slice(s, e + 1)); } catch { return null; }
}
const DISALLOW_NOTEONLY = "run_terminal_cmd"; // 禁终端(grok 真名)——写入全走 write/search_replace,transcript 可归因

// ---------- glossary 读写 ----------
function glossaryTerms(): Set<string> {
  if (!existsSync(GLOSSARY)) return new Set();
  return new Set([...readFileSync(GLOSSARY, "utf8").matchAll(/^##\s+(.+)$/gm)].map(m => m[1].trim()));
}
function appendGlossary(term: string, def: string) {
  appendFileSync(GLOSSARY, `\n## ${term}\n${def}\n`);
}

// ---------- 找家门外的重讲 ----------
// 搜索范围由仓库在 concepts.json 里声明（includeRoots）——把另一套行文规范的区域（如面向
// 用户的 docs 站）排除在外，别让代码栈概念镜头去瘦身它们。缺省全库。
const INCLUDE_ROOTS: string[] = spec.includeRoots ?? ["."];
// 机制指示词：出现才算「在讲机制」，只提一次名字不算。
const MECH = /是|指|表示|负责|流程|按需|解析|组装|分两|分三|三步|构建|校验|钉|投影|派发|签发|维持|长驻|反代|递增|快照|合成/;
function reExplainers(concept: any): { file: string; repoPath: string; excerpt: string }[] {
  const rx = new RegExp(concept.pattern);
  const homePrefix = concept.home + (concept.homeType === "dir" ? "/" : "");
  const notesRoot = join(REPO, ".atlas/notes");
  const roots = INCLUDE_ROOTS.map(r => `${notesRoot}/${r}`).join(" ");
  const all = new TextDecoder().decode(Bun.spawnSync(["bash", "-c", `grep -rlE '${concept.pattern}' ${roots} 2>/dev/null`], { cwd: REPO }).stdout).split("\n").filter(Boolean);
  const out: { file: string; repoPath: string; excerpt: string }[] = [];
  for (const f of all) {
    const rel = f.replace(notesRoot + "/", "");
    const repoPath = rel.endsWith("/__dir__.md") ? rel.slice(0, -"/__dir__.md".length) : rel.slice(0, -".md".length);
    // 排除归属页本身与其目录下的文件（它们是该概念的主场，保留）
    if (repoPath === concept.home || repoPath.startsWith(homePrefix)) continue;
    const body = stripFrontmatter(readFileSync(f, "utf8"));
    const paras = body.split(/\n\n+/).filter(p => rx.test(p));
    if (!paras.length) continue;
    const matched = paras.join("\n");
    // 实质重讲门槛：匹配段落够长 且 含机制词——只提一次名字的笔记（长度短或无机制词）不进候选。
    if (matched.length < 240 || !MECH.test(matched)) continue;
    out.push({ file: f, repoPath, excerpt: paras.join("\n---\n").slice(0, 1500) });
  }
  return out;
}

// ---------- Stage 1：固化归属页 + 产出 glossary 本质 ----------
const CONSOLIDATE_SCHEMA = JSON.stringify({
  type: "object",
  properties: {
    glossary: { type: "array", items: { type: "object", properties: { term: { type: "string" }, essence: { type: "string" } }, required: ["term", "essence"] } },
    homeChanged: { type: "boolean" },
    summary: { type: "string" },
  },
  required: ["glossary", "summary"],
});
async function consolidate(concept: any, res: { repoPath: string; excerpt: string }[]): Promise<any> {
  const homeFile = noteFileFor(concept.home, concept.homeType);
  const homeExists = existsSync(homeFile);
  const scattered = res.map(r => `### 出现在 ${r.repoPath}\n${r.excerpt}`).join("\n\n");
  const glossaryAsk = concept.glossary.map((g: any) => `- \`${g.term}\`：${g.hint}`).join("\n");
  const prompt = `你在给一个 codebase atlas 收敛一个跨切概念，让它只在唯一归属页讲全。

概念：**${concept.name}**
归属页（该概念的唯一权威讲解处）：\`${homeFile.slice(REPO.length + 1)}\`（描述代码路径 \`${concept.home}\`）${homeExists ? "" : "——此笔记尚不存在，你要新建它"}

这个概念目前散落在多篇笔记里各讲一遍（下面是摘录）。你的任务：

1. **让归属页成为该概念机制的唯一权威讲解**：${homeExists ? "读归属页当前内容" : "新建归属页"}，把该概念的完整机制在这里讲透（合并各处最准确的说法，**用代码读权限逐条核实**，纠正任何与当前源码不符的说法）。保持归属页自己的职责范围不变——只补强/新增覆盖本概念的那部分，别把它写成只讲这一个概念。遵守 atlas 笔记规范（见下）。
2. **产出 glossary 一行本质**：为下列术语各写一句独立可读的本质（≤2 句，读者不看代码也能懂）。这行本质将进 glossary、在别处悬停可见——是别的笔记'引用而不重讲'后仍可读的命门。建议术语与提示：
${glossaryAsk}

硬边界：
- **只允许写归属页这一个文件**（${homeFile.slice(REPO.length + 1)}）。仓库任何其它文件（源码、别的笔记、glossary）一律不许动——glossary 由编排器写。这是多 agent 共享工作区。
- 事实以当前源码为准，不许照抄注释里的意图。
- 只读不改代码。

atlas 笔记规范（节选）：
${conventions.slice(0, 1800)}

笔记模板语气要点：
${template.slice(0, 1200)}

散落的现有讲解：
${scattered.slice(0, 6000)}

最后只输出一个 JSON（字段名严格如下，不要代码围栏）：
{"glossary":[{"term":"...","essence":"..."}],"homeChanged":true,"summary":"一句话说你改了归属页什么"}`;

  const before = dirtyPaths();
  const out = await runGrok(prompt, { schema: CONSOLIDATE_SCHEMA, maxTurns: 60, disallowed: DISALLOW_NOTEONLY, timeoutMs: 1_200_000 });
  assertOnlyAtlasWrites(REPO, REPO, out?.sessionId, before, `Stage1(${concept.id})`);
  const parsed = lenient(out);
  if (!parsed?.glossary) throw new Error("Stage1 输出解析失败");
  return parsed;
}

// ---------- Stage 2：瘦身一篇家门外的重讲 ----------
const THIN_SCHEMA = JSON.stringify({ type: "object", properties: { changed: { type: "boolean" }, summary: { type: "string" } }, required: ["changed", "summary"] });
async function thin(concept: any, r: { file: string; repoPath: string }): Promise<any> {
  const homeFile = noteFileFor(concept.home, concept.homeType);
  const terms = concept.glossary.map((g: any) => `\`${g.term}\``).join("、");
  const prompt = `你在瘦身一篇 codebase atlas 笔记，去掉它对某跨切概念的**通用机制重讲**——因为该机制现在有了唯一权威归属页，别处不该再讲一遍。

这篇笔记：\`${r.file.slice(REPO.length + 1)}\`（描述 \`${r.repoPath}\`）
要收敛的概念：**${concept.name}**
它的权威归属页：\`${homeFile.slice(REPO.length + 1)}\`
它的本质已进 glossary（术语 ${terms}，全库悬停可见）。

任务：在这篇笔记里，把对该概念**通用机制的重讲**替换成——**一句本质（或直接用 glossary 术语）+ 指向归属页的引用**（如「…见 \`${concept.home}\`」）。

务必保留：
- 这篇笔记**自己的主题**和它与该概念的**具体交互**（这个文件/目录**特有**地怎么用到该概念——这不是通用重讲，要留）。
- 与该概念无关的一切内容，一个字不动。

分寸：读者读完瘦身后的这篇，靠 glossary 级的一句本质就能懂本篇的本地论点，想深挖再点归属页。别把笔记掏空成只剩链接；也别删掉本篇特有的交互细节。若这篇其实没有'通用重讲'、只有特有交互，就基本不用改（changed=false）。

硬边界：
- **只允许改这一个文件**（${r.file.slice(REPO.length + 1)}）。别的笔记、源码、glossary 一律不许动。
- 不许改 frontmatter。只读不改代码。

最后只输出 JSON（不要围栏）：{"changed":true|false,"summary":"一句话说你改了什么/为何没改"}`;

  const before = dirtyPaths();
  const out = await runGrok(prompt, { schema: THIN_SCHEMA, maxTurns: 40, disallowed: DISALLOW_NOTEONLY, timeoutMs: 900_000 });
  assertOnlyAtlasWrites(REPO, REPO, out?.sessionId, before, `Stage2(${concept.id}→${r.repoPath})`);
  const parsed = lenient(out) ?? { changed: false, summary: "解析失败" };
  return parsed;
}

// ---------- 主流程（概念间串行） ----------
const touched = new Set<string>();
for (const id of wanted) {
  const concept = spec.concepts.find((c: any) => c.id === id);
  if (!concept) { console.error(`未知概念 ${id}`); continue; }
  const res = reExplainers(concept);
  console.log(`\n===== [${id}] ${concept.name} =====`);
  console.log(`  家门外重讲 ${res.length} 篇: ${res.map(r => r.repoPath).join(", ") || "(无)"}`);
  if (DRY) continue;

  // Stage 1：固化归属页 + glossary
  console.log(`  Stage1 固化归属页 ${concept.home} …`);
  const c1 = await consolidate(concept, res);
  console.log(`    ${c1.summary}`);
  touched.add(concept.home + (concept.homeType === "dir" ? "" : ""));
  // 写 glossary（串行、去重）
  const have = glossaryTerms();
  for (const g of c1.glossary) {
    if (have.has(g.term)) { console.log(`    glossary 已有 '${g.term}'，跳过`); continue; }
    appendGlossary(g.term, g.essence);
    console.log(`    + glossary '${g.term}'`);
  }

  // Stage 2：并发瘦身家门外重讲
  if (res.length) {
    console.log(`  Stage2 瘦身 ${res.length} 篇 …`);
    const queue = [...res];
    await Promise.all(Array.from({ length: Math.min(CONC, queue.length) }, async () => {
      while (queue.length) {
        const r = queue.shift()!;
        try {
          const t = await thin(concept, r);
          console.log(`    ${t.changed ? "✎" : "·"} ${r.repoPath}: ${t.summary.slice(0, 70)}`);
          if (t.changed) touched.add(r.repoPath);
        } catch (e: any) { console.log(`    ✗ ${r.repoPath}: ${e.message}`); }
      }
    }));
  }
}

console.log(`\n===== 触碰的笔记（交 QA 门复验）=====`);
const list = [...touched];
for (const p of list) console.log("  " + p);
writeFileSync(join(PIPE, "extract-touched.txt"), list.join("\n") + "\n");
console.log(`\n已写 ${join(PIPE, "extract-touched.txt")}；复验：`);
console.log(`  bun ${join(QA, "run.ts")} $(cat .atlas/pipeline/extract-touched.txt) --revise --stamp --force --concurrency 6`);
