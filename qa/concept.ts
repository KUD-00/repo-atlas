#!/usr/bin/env bun
/**
 * 概念页生产线：让 agent 从 sources 写出「概念页」（.atlas/concepts/<slug>.md），
 * 过 audience 对应 persona 的盲读 + 只对 sources 的事实核查 + 可视化硬门，然后 stamp。
 * 在目标仓库里跑：
 *   cd <你的仓库> && bun <repo-atlas>/qa/concept.ts <slug...>|--all [--concurrency 2] [--force]
 *
 * 页面清单是仓库自有内容：.atlas/pipeline/concept-pages.json —— 它是一张**课程表**：
 *   { "pages": [{ "slug", "title", "audience": "dev"|"general", "sources": [repo路径...],
 *                 "brief": "要讲什么/给谁/必须回答的疑问",
 *                 "requires": ["前置slug"...],   // 可选：前置页（必须排在本页之前）
 *                 "owns": "一句话：本页独占讲透什么" }] }  // 可选：兄弟页只准点到不准展开
 *   数组顺序 = 阅读顺序（viewer 侧栏按 frontmatter order 排）。writer 拿到课程表+前置页
 *   全文，在其上写、不重讲；盲读者以前置页为唯一先验（零代码、零 glossary），并报告
 *   "循序渐进断线"（用了没立起的概念）——breakMed>1 挂门。生成按依赖分波跑。
 *
 * 门（简化版，硬门三条）：
 *   - 可视化 ≥2 处（内嵌 HTML 块或 mermaid；audience=general 至少 1 处为 HTML）
 *   - 盲读（audience persona）：读不懂句子中位数 ≤3，复述过半成立
 *   - 事实核查：unsupported 断言 = 0
 * 未过带评语返工，≤3 轮。档案落 .atlas/qa/_concepts/<slug>.json（resume-skip，--force 重跑）。
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { findRepoRoot, runAgent as libRunAgent, lenientParse as lenient, dirtyPaths as libDirty, assertOnlyAtlasWrites, lintBannedPhrases, countVisuals as libVisuals, longParagraphs, listCandidates, flatStructure, loadPrompt, median, DENY_TERMINAL, DENY_ALL_WRITES } from "./lib";

const REPO = findRepoRoot();
const QA = new URL(".", import.meta.url).pathname.replace(/\/$/, "");
const SPEC_FILE = join(REPO, ".atlas/pipeline/concept-pages.json");
const ARCHIVE = join(REPO, ".atlas/qa/_concepts");
mkdirSync(ARCHIVE, { recursive: true });
if (!existsSync(SPEC_FILE)) { console.error("缺 .atlas/pipeline/concept-pages.json（格式见本文件头注释）"); process.exit(2); }
const spec = JSON.parse(readFileSync(SPEC_FILE, "utf8"));

// ---------- 课程表（curriculum）----------
// pages 的数组顺序 = 阅读顺序（大纲）。每页可声明：
//   requires: [slug...]  前置页（必须排在本页之前）——writer 在其上写、不重讲；盲读者先读它们
//   owns: "一句话"        本页独占讲透的机制范围——兄弟页只准点到，不准展开
// 违反（引用不存在 / 前置排在后面）= 配置错误，启动即失败（fail-loud）。
const curIndex = new Map<string, number>(spec.pages.map((p: any, i: number) => [p.slug, i]));
for (const p of spec.pages) {
  for (const r of p.requires ?? []) {
    if (!curIndex.has(r)) { console.error(`concept-pages.json 配置错误：${p.slug} requires 了不存在的 "${r}"`); process.exit(2); }
    if (curIndex.get(r)! >= curIndex.get(p.slug)!) { console.error(`concept-pages.json 配置错误：${p.slug} 的前置 "${r}" 必须排在它之前（数组顺序=阅读顺序）`); process.exit(2); }
  }
}
function curriculumTable(self: string): string {
  return spec.pages.map((p: any, i: number) =>
    `${i + 1}. ${p.slug === self ? "▶ " : ""}**${p.title}**（${p.slug}）${p.owns ? ` — 独占范围：${p.owns}` : ""}`).join("\n");
}
function prereqBodies(page: any): { slug: string; title: string; body: string }[] {
  return (page.requires ?? []).map((slug: string) => {
    const f = pageFile(slug);
    const p = spec.pages.find((x: any) => x.slug === slug);
    return existsSync(f)
      ? { slug, title: p?.title ?? slug, body: readFileSync(f, "utf8").replace(/^---\n[\s\S]*?\n---\n?/, "") }
      : null;
  }).filter(Boolean);
}

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(`--${n}`);
const optNum = (n: string, d: number) => { const i = args.indexOf(`--${n}`); return i >= 0 ? Number(args[i + 1]) : d; };
const FORCE = flag("force");
const CONC = optNum("concurrency", 10);
const wanted: string[] = (flag("all") ? spec.pages.map((p: any) => p.slug)
  : args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--concurrency"))
  .sort((a: string, b: string) => (curIndex.get(a) ?? 1e9) - (curIndex.get(b) ?? 1e9)); // 按课程表顺序跑：前置先成稿
if (!wanted.length) { console.error("usage: bun concept.ts <slug...>|--all [--concurrency N] [--force]"); process.exit(2); }

const dirtyPaths = () => libDirty(REPO);
const runAgent = (prompt: string, o: { cwd?: string; schema?: string; maxTurns: number; disallowed?: string; timeoutMs: number }) =>
  libRunAgent(prompt, { ...o, cwd: o.cwd ?? REPO });
// 禁掉终端（写路径全部可 transcript 归因）——writer 只需 read/grep/list + write。
// 注意必须用 grok 的真实工具名（lib.DENY_*）；错名会被静默忽略。
const DISALLOW_NOTEONLY = DENY_TERMINAL;

// ---------- 机械硬门（共通核 qa/lib.ts：禁令句式单一来源 + 可视化计数） ----------
function countVisuals(body: string): { html: number; mermaid: number } {
  const v = libVisuals(body);
  return { html: v.html, mermaid: v.mermaid };
}
const lintConcept = (body: string) => lintBannedPhrases(body);

// ---------- persona ----------
function personaOf(aud: string): string {
  return aud === "general"
    ? "你是酒店集团的运营/客服负责人，不懂编程、没见过代码，但每天和这套系统打交道"
    : "你是第一天入职这个仓库的工程师，还没读过代码";
}

// ---------- 各阶段 ----------
function pageFile(slug: string) { return join(REPO, ".atlas/concepts", slug + ".md"); }

async function write(page: any, feedback: string | null): Promise<void> {
  const glossary = existsSync(join(REPO, ".atlas/glossary.md")) ? readFileSync(join(REPO, ".atlas/glossary.md"), "utf8") : "";
  const rel = pageFile(page.slug).slice(REPO.length + 1);
  const existing = existsSync(pageFile(page.slug)) ? readFileSync(pageFile(page.slug), "utf8") : null;
  const prereqs = prereqBodies(page);
  const later = spec.pages.filter((p: any) => (curIndex.get(p.slug) ?? 0) > (curIndex.get(page.slug) ?? 0) && p.owns);
  const prompt = `你在为 codebase atlas 写一篇「概念页」——不锚定单一文件、把一个重要机制端到端讲清的独立页面。它是一套**课程**里的一页，不是孤立文章。

## 课程表（阅读顺序；▶ 是你要写的这页）

${curriculumTable(page.slug)}

分工纪律（硬规则）：
- **前置页已讲的机制不重讲**——读者按顺序读到这页时已读过前置页；用一句话点到（提它的标题）即可，重讲=返工。
- **不提前展开后面页的独占范围**${later.length ? `（${later.map((p: any) => `「${p.owns}」归 ${p.title}`).join("；")}）` : ""}——需要提及时一句带过，不讲机制。
- 本页独占范围${page.owns ? `：**${page.owns}**——这是全课程唯一讲透它的地方，讲全` : "以 brief 为准"}。

${prereqs.length ? `## 前置页全文（读者已读过；你在其上写作）\n\n${prereqs.map((p: any) => `### ${p.title}\n\n${p.body.slice(0, 6000)}`).join("\n\n---\n\n")}\n` : ""}
## 本页

标题：**${page.title}**
受众：${page.audience === "general" ? "**非开发者**（运营/销售/客服/PM）——大白话，任何术语出现必须当句用平实话解释，禁术语墙" : "开发者（第一天入职，还没读过代码）"}
要讲什么：${page.brief}

事实来源（唯一允许的依据，先读完再写；写下的每条断言必须能在这些文件里指到）：
${page.sources.map((s: string) => `- \`${s}\``).join("\n")}

硬要求：
1. **循序渐进的教学结构（硬门）**：开头一段 = 这页回答什么疑问 + 引入贯穿例子；接着**定义在先**——核心名词先用大白话立起来再用；主体 = 跟着贯穿例子**一步步走完整个机制**（编号步骤，每步只新增一个概念，且只建立在前置页或本页已立起的概念上——顺序错了读者就断线）；每个真实小节开 \`####\` 独立标题（右侧大纲从标题生成，别用加粗伪标题）。
2. **可视化 ≥2 处**：内嵌 HTML（viewer 直接渲染——时间线/双栏对照/流程卡片/表格，形式随你发挥，以一眼看懂为准；朴素行内样式即可）${page.audience === "general" ? "，至少 1 处必须是 HTML" : ""}；拓扑（管线/状态机）可用 mermaid。别机械套模板。
3. **一个例子贯穿全文**，别每节换例子。例子里的场景细节可以虚构，但要用「比如」明示是举例；例子中体现的**机制、数字、顺序、字段行为必须全部来自 sources**，不许为了例子顺手编机制。
4. 中文行文；**一段讲一件事**（一段 ≤~5 句 ~300 字，超了拆段，机械硬门）；**平行枚举用 - 列表不用顿号串**（机械硬门）。
5. **禁令句式（机械硬门，出现即不过）**：「值得注意的是/有意思的是/我们来看/一定要注意/先记住/记住一件事/简单来说/换句话说/别担心/让我们/想象一下/见文末/如上所述/综上所述/总而言之」——这些是 AI 教学腔，是什么就直接说什么。标题也不许用"先记住一件事"这类句式。
${feedback ? `\n上一轮验收未过，逐条修复：\n${feedback}\n` : ""}
${existing ? `当前草稿（在此基础上修，别推翻重写没被投诉的部分）：\n\`\`\`\n${existing.slice(0, 8000)}\n\`\`\`` : ""}
术语表（悬停可见，正文可直接用这些词）：
${glossary.slice(0, 2000)}

产出：把完整页面写入 \`${rel}\`（用 Write 工具）。frontmatter 原样写这几行再跟正文：
---
title: ${page.title}
audience: ${page.audience}
sources: ${JSON.stringify(page.sources)}
order: ${(curIndex.get(page.slug) ?? 0) + 1}
---

硬边界：只允许写这一个文件；不许改源码/别的笔记/glossary；sources_hash 等字段不要写（由 stamp 管）。\n${loadPrompt(QA, REPO, "concept-writer")}`;
  const before = dirtyPaths();
  const out = await runAgent(prompt, { maxTurns: 80, disallowed: DISALLOW_NOTEONLY, timeoutMs: 1_500_000 });
  assertOnlyAtlasWrites(REPO, REPO, out?.sessionId, before, `writer(${page.slug})`);
  if (!existsSync(pageFile(page.slug))) throw new Error("writer 没有写出页面文件");
}

const READER_SCHEMA = JSON.stringify({
  type: "object",
  properties: {
    unclear_sentences: { type: "array", items: { type: "string" } },
    undefined_terms: { type: "array", items: { type: "string" } },
    progression_breaks: { type: "array", items: { type: "string" }, description: "断线处：哪一句/哪一步用了此前(本页+已读前置页)没立起的概念,或步骤顺序跳跃让你跟丢" },
    retell: { type: "string", description: "用自己的话复述这个机制(3-5句)" },
    can_explain_to_colleague: { type: "boolean" },
    overall_score: { type: "number", description: "1-5" },
  },
  required: ["unclear_sentences", "progression_breaks", "retell", "can_explain_to_colleague", "overall_score"],
});
// 盲读者零 context：空目录 cwd（结构性无码权限）、不给 glossary（概念页必须在"前置页+本页"内自立）。
// 唯一的先验 = 课程表里排在前面的前置页——和真实读者一致（按顺序读到这页）。
async function blindRead(page: any, body: string): Promise<any[]> {
  const prereqs = prereqBodies(page);
  const prior = prereqs.length
    ? `你此前已经按顺序读过这套课程的前几页（内容如下，可作为已知背景）：\n\n${prereqs.map((p: any) => `《${p.title}》\n${p.body.slice(0, 6000)}`).join("\n\n---\n\n")}\n\n现在读新的一页：\n\n`
    : "";
  const emptyCwd = () => mkdtempSync(join(tmpdir(), "atlas-cpt-blind-"));
  const mk = () => runAgent(`${personaOf(page.audience)}。除了下面给你的材料，你没有任何其它背景，也看不到任何代码。${prior ? "" : "这是这套课程的第一页。"}

${prior}${body}

认真读完并如实报告：读不懂/要读两遍的句子（原文摘录）；没解释就使用的词；**断线处**——哪一步用了此前没立起的概念、或步骤跳跃让你跟丢（原文摘录+一句为什么断）；用自己的话复述机制；你能否把它讲给同事听；总体 1-5 分。只输出 JSON。\n${loadPrompt(QA, REPO, "concept-reader")}`,
    { cwd: emptyCwd(), schema: READER_SCHEMA, maxTurns: 4, timeoutMs: 300_000 });
  const outs = await Promise.all([mk(), mk(), mk()]);
  return outs.map(lenient).filter(Boolean);
}

const FACT_SCHEMA = JSON.stringify({
  type: "object",
  properties: {
    unsupported: { type: "array", items: { type: "object", properties: { claim: { type: "string" }, why: { type: "string" } }, required: ["claim", "why"] } },
    summary: { type: "string" },
  },
  required: ["unsupported", "summary"],
});
async function factcheck(page: any, body: string): Promise<any> {
  const prompt = `你是事实核查员，有代码读权限。核对下面这页讲解里的每条事实断言是否被这些源码文件支撑（只读这些）：
${page.sources.map((s: string) => `- ${s}`).join("\n")}

注意受众是${page.audience === "general" ? "非开发者：允许合理的通俗化省略（比如把 Twilio Studio 说成'电话平台的流程图'），只抓**与源码行为相悖**的断言，不抓简化" : "开发者：按常规严格核对"}。明示为举例的虚构场景（假想的酒店名/时间/客人提问）不算违规——只核查例子中体现的机制/数字/字段行为是否与源码一致。

页面：
${body}

只输出 JSON：{"unsupported":[{"claim":"...","why":"..."}],"summary":"..."}\n${loadPrompt(QA, REPO, "concept-factcheck")}`;
  const before = dirtyPaths();
  const out = await runAgent(prompt, { schema: FACT_SCHEMA, maxTurns: 30, disallowed: DENY_ALL_WRITES, timeoutMs: 900_000 });
  assertOnlyAtlasWrites(REPO, REPO, out?.sessionId, before, `factcheck(${page.slug})`);
  return lenient(out) ?? { unsupported: [], summary: "解析失败(视为通过存疑)" };
}

// ---------- 单页主循环 ----------
async function runPage(slug: string): Promise<{ slug: string; pass: boolean; reasons: string[] }> {
  const page = spec.pages.find((p: any) => p.slug === slug);
  if (!page) return { slug, pass: false, reasons: ["未知 slug"] };
  const arch = join(ARCHIVE, slug + ".json");
  if (!FORCE && existsSync(arch)) {
    try { const prev = JSON.parse(readFileSync(arch, "utf8")); if (prev.finalPass) { console.log(`[${slug}] ⏭ 已过门，跳过`); return { slug, pass: true, reasons: [] }; } } catch {}
  }
  const record: any = { slug, rounds: [], finalPass: false };
  let feedback: string | null = null;
  // keep-best：修订可能越改越差（路径笔记线的老教训），失败收场时把最好一轮写回盘。
  let best: { raw: string; pen: number } | null = null;
  const penaltyOf = (reasons: string[], unclearMed: number, breakMed: number, unsupported: number) =>
    reasons.length * 2 + unclearMed + breakMed * 2 + unsupported * 3;
  for (let round = 0; round < 3; round++) {
    console.log(`[${slug}] round ${round}: ${round === 0 && !existsSync(pageFile(slug)) ? "写作" : "修订"}…`);
    await write(page, feedback);
    const raw = readFileSync(pageFile(slug), "utf8");
    const body = raw.replace(/^---\n[\s\S]*?\n---\n?/, "");
    const reasons: string[] = [];
    const vis = countVisuals(body);
    if (vis.html + vis.mermaid < 2) reasons.push(`可视化不足（HTML ${vis.html} + mermaid ${vis.mermaid} < 2）`);
    if (page.audience === "general" && vis.html < 1) reasons.push("general 页至少 1 处 HTML 可视化");
    reasons.push(...lintConcept(body));
    // 结构机械硬门（与路径笔记同源）：长段落 / 顿号串 / 大纲可见的标题结构
    reasons.push(...longParagraphs(body, true).map(p => `长段落（拆成多段，每段一件事）：${p}`));
    reasons.push(...listCandidates(body));
    const flat = flatStructure(body);
    if (flat) reasons.push(flat);
    console.log(`[${slug}] round ${round}: 盲读 ×3 + 核查…`);
    const [readers, fc] = await Promise.all([blindRead(page, body), factcheck(page, body)]);
    const unclearMed = median(readers.map(r => r.unclear_sentences.length));
    const retellOk = readers.filter(r => r.can_explain_to_colleague).length;
    const unclearMax = page.audience === "general" ? 5 : 4;
    const breakMed = median(readers.map(r => (r.progression_breaks ?? []).length));
    if (unclearMed > unclearMax) reasons.push(`读不懂句子中位 ${unclearMed} > ${unclearMax}：${readers.flatMap(r => r.unclear_sentences).slice(0, 5).join("｜")}`);
    if (breakMed > 1) reasons.push(`循序渐进断线中位 ${breakMed} > 1：${readers.flatMap(r => r.progression_breaks ?? []).slice(0, 4).join("｜")}`);
    if (retellOk < 2) reasons.push(`复述不成立（${retellOk}/3 能讲给同事）`);
    if (fc.unsupported.length) reasons.push(`unsupported ${fc.unsupported.length} 条：${fc.unsupported.map((u: any) => u.claim).slice(0, 3).join("｜")}`);
    record.rounds.push({ round, visuals: vis, unclearMed, breakMed, retellOk, unsupported: fc.unsupported, reasons });
    const pen = penaltyOf(reasons, unclearMed, breakMed, fc.unsupported.length);
    if (!best || pen < best.pen) best = { raw, pen };
    if (!reasons.length) {
      record.finalPass = true;
      writeFileSync(arch, JSON.stringify(record, null, 2));
      const st = Bun.spawnSync(["bun", join(QA, "..", "dist/cli.js"), "stamp", `.atlas/concepts/${slug}.md`], { cwd: REPO });
      console.log(`[${slug}] ✅ 过门（round ${round}）；stamp: ${st.exitCode === 0 ? "ok" : new TextDecoder().decode(st.stderr).slice(0, 120)}`);
      return { slug, pass: true, reasons: [] };
    }
    console.log(`[${slug}] round ${round}: ❌ ${reasons.join("；")}`);
    feedback = [
      ...reasons.map(r => `- ${r}`),
      ...readers.flatMap(r => r.unclear_sentences).slice(0, 8).map(s => `- 读不懂：「${s}」`),
      ...readers.flatMap(r => r.progression_breaks ?? []).slice(0, 6).map(s => `- 循序渐进断线（这一步用了没立起的概念/顺序跳跃）：「${s}」——把缺的概念在它之前立起来，或调整步骤顺序`),
      ...(readers.flatMap(r => r.undefined_terms ?? [])).slice(0, 6).map(t => `- 术语没解释：${t}`),
      ...fc.unsupported.map((u: any) => `- 事实不符：「${u.claim}」——${u.why}`),
    ].join("\n");
  }
  // 三轮都没过：盘上留"最好一轮"而非"最后一轮"
  if (best && readFileSync(pageFile(slug), "utf8") !== best.raw) {
    writeFileSync(pageFile(slug), best.raw);
    console.log(`[${slug}] 回退到最好一轮（penalty ${best.pen}）`);
  }
  writeFileSync(arch, JSON.stringify(record, null, 2));
  return { slug, pass: false, reasons: record.rounds.at(-1).reasons };
}

// ---------- 并发驱动（按依赖分波：前置页成稿后，依赖它的页才开跑） ----------
function depthOf(slug: string, seen = new Set<string>()): number {
  if (seen.has(slug)) return 0; // requires 校验已保证无环，这里只是防御
  seen.add(slug);
  const reqs: string[] = spec.pages.find((p: any) => p.slug === slug)?.requires ?? [];
  return reqs.length ? 1 + Math.max(...reqs.map(r => depthOf(r, seen))) : 0;
}
const waves = new Map<number, string[]>();
for (const slug of wanted) {
  const d = depthOf(slug);
  waves.set(d, [...(waves.get(d) ?? []), slug]);
}
const results: { slug: string; pass: boolean; reasons: string[] }[] = [];
for (const d of [...waves.keys()].sort((a, b) => a - b)) {
  const queue = [...waves.get(d)!];
  if (queue.length) console.log(`\n—— 第 ${d + 1} 波（${queue.join(", ")}）——`);
  await Promise.all(Array.from({ length: Math.min(CONC, queue.length) }, async () => {
    while (queue.length) {
      const slug = queue.shift()!;
      try { results.push(await runPage(slug)); }
      catch (e: any) { results.push({ slug, pass: false, reasons: [`pipeline error: ${e?.message ?? e}`] }); }
    }
  }));
}
console.log("\n===== 汇总 =====");
for (const r of results) console.log(`${r.pass ? "✅" : "❌"} ${r.slug}${r.reasons.length ? "  " + r.reasons.join("；") : ""}`);
const failed = results.filter(r => !r.pass).length;
console.log(`过门 ${results.length - failed}/${results.length}`);
process.exit(failed ? 1 : 0);
