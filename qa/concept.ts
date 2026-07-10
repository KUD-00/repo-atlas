#!/usr/bin/env bun
/**
 * 概念页生产线：让 agent 从 sources 写出「概念页」（.atlas/concepts/<slug>.md），
 * 过 audience 对应 persona 的盲读 + 只对 sources 的事实核查 + 可视化硬门，然后 stamp。
 * 在目标仓库里跑：
 *   cd <你的仓库> && bun <repo-atlas>/qa/concept.ts <slug...>|--all [--concurrency 2] [--force]
 *
 * 页面清单是仓库自有内容：.atlas/pipeline/concept-pages.json
 *   { "pages": [{ "slug", "title", "audience": "dev"|"general", "sources": [repo路径...],
 *                 "brief": "要讲什么/给谁/必须回答的疑问" }] }
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
import { findRepoRoot, runAgent as libRunAgent, lenientParse as lenient, dirtyPaths as libDirty, newDirtyOutsideAtlas as libGuard, lintBannedPhrases, countVisuals as libVisuals, loadPrompt, median } from "./lib";

const REPO = findRepoRoot();
const QA = new URL(".", import.meta.url).pathname.replace(/\/$/, "");
const SPEC_FILE = join(REPO, ".atlas/pipeline/concept-pages.json");
const ARCHIVE = join(REPO, ".atlas/qa/_concepts");
mkdirSync(ARCHIVE, { recursive: true });
if (!existsSync(SPEC_FILE)) { console.error("缺 .atlas/pipeline/concept-pages.json（格式见本文件头注释）"); process.exit(2); }
const spec = JSON.parse(readFileSync(SPEC_FILE, "utf8"));

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(`--${n}`);
const optNum = (n: string, d: number) => { const i = args.indexOf(`--${n}`); return i >= 0 ? Number(args[i + 1]) : d; };
const FORCE = flag("force");
const CONC = optNum("concurrency", 2);
const wanted: string[] = flag("all") ? spec.pages.map((p: any) => p.slug)
  : args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--concurrency");
if (!wanted.length) { console.error("usage: bun concept.ts <slug...>|--all [--concurrency N] [--force]"); process.exit(2); }

const dirtyPaths = () => libDirty(REPO);
const newDirtyOutsideAtlas = (before: Set<string>) => libGuard(REPO, before);
const runAgent = (prompt: string, o: { cwd?: string; schema?: string; maxTurns: number; disallowed?: string; timeoutMs: number }) =>
  libRunAgent(prompt, { ...o, cwd: o.cwd ?? REPO });
const DISALLOW_NOTEONLY = "Delete,EditNotebook,GenerateImage";

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
  const prompt = `你在为 codebase atlas 写一篇「概念页」——不锚定单一文件、把一个重要机制端到端讲清的独立页面。

标题：**${page.title}**
受众：${page.audience === "general" ? "**非开发者**（运营/销售/客服/PM）——大白话，任何术语出现必须当句用平实话解释，禁术语墙" : "开发者（第一天入职，还没读过代码）"}
要讲什么：${page.brief}

事实来源（唯一允许的依据，先读完再写；写下的每条断言必须能在这些文件里指到）：
${page.sources.map((s: string) => `- \`${s}\``).join("\n")}

硬要求：
1. **可视化 ≥2 处**：内嵌 HTML（viewer 直接渲染——时间线/双栏对照/流程卡片/表格，形式随你发挥，以一眼看懂为准；朴素行内样式即可）${page.audience === "general" ? "，至少 1 处必须是 HTML" : ""}；拓扑（管线/状态机）可用 mermaid。别机械套模板。
2. **一个真实例子贯穿全文**（一通具体的电话/一条具体的菜单配置），别每节换例子。
3. 中文行文；一段讲一件事；平行枚举用列表不用顿号串。
4. 读者读完要能向同事复述这个机制——按"是什么→一个例子→怎么运作→常见疑问"的顺序教。
5. **禁令句式（机械硬门，出现即不过）**：「值得注意的是/有意思的是/我们来看/一定要注意/先记住/记住一件事/简单来说/换句话说/别担心/让我们/想象一下/见文末/如上所述/综上所述/总而言之」——这些是 AI 教学腔，是什么就直接说什么。标题也不许用"先记住一件事"这类句式。
${feedback ? `\n上一轮验收未过，逐条修复：\n${feedback}\n` : ""}
${existing ? `当前草稿（在此基础上修，别推翻重写没被投诉的部分）：\n\`\`\`\n${existing.slice(0, 8000)}\n\`\`\`` : ""}
术语表（悬停可见，正文可直接用这些词）：
${glossary.slice(0, 2000)}

产出：把完整页面写入 \`${rel}\`（用 Write 工具）。frontmatter 原样写这三行再跟正文：
---
title: ${page.title}
audience: ${page.audience}
sources: ${JSON.stringify(page.sources)}
---

硬边界：只允许写这一个文件；不许改源码/别的笔记/glossary；sources_hash 等字段不要写（由 stamp 管）。\n${loadPrompt(QA, REPO, "concept-writer")}`;
  const before = dirtyPaths();
  await runAgent(prompt, { maxTurns: 80, disallowed: DISALLOW_NOTEONLY, timeoutMs: 1_500_000 });
  const extra = newDirtyOutsideAtlas(before);
  if (extra.length) throw new Error(`writer 越界改了 .atlas 外路径：${extra.join(" | ")}`);
  if (!existsSync(pageFile(page.slug))) throw new Error("writer 没有写出页面文件");
}

const READER_SCHEMA = JSON.stringify({
  type: "object",
  properties: {
    unclear_sentences: { type: "array", items: { type: "string" } },
    undefined_terms: { type: "array", items: { type: "string" } },
    retell: { type: "string", description: "用自己的话复述这个机制(3-5句)" },
    can_explain_to_colleague: { type: "boolean" },
    overall_score: { type: "number", description: "1-5" },
  },
  required: ["unclear_sentences", "retell", "can_explain_to_colleague", "overall_score"],
});
async function blindRead(page: any, body: string): Promise<any[]> {
  const emptyCwd = () => mkdtempSync(join(tmpdir(), "atlas-cpt-blind-"));
  const mk = () => runAgent(`${personaOf(page.audience)}。下面是一页给你的讲解，认真读完并如实报告。

${body}

报告：读不懂/要读两遍的句子（原文摘录）；没解释就使用的词；用自己的话复述机制；你能否把它讲给同事听；总体 1-5 分。只输出 JSON。\n${loadPrompt(QA, REPO, "concept-reader")}`,
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

注意受众是${page.audience === "general" ? "非开发者：允许合理的通俗化省略（比如把 Twilio Studio 说成'电话平台的流程图'），只抓**与源码行为相悖**的断言，不抓简化" : "开发者：按常规严格核对"}。

页面：
${body}

只输出 JSON：{"unsupported":[{"claim":"...","why":"..."}],"summary":"..."}\n${loadPrompt(QA, REPO, "concept-factcheck")}`;
  const before = dirtyPaths();
  const out = await runAgent(prompt, { schema: FACT_SCHEMA, maxTurns: 30, disallowed: DISALLOW_NOTEONLY + ",Write,StrReplace,Edit", timeoutMs: 900_000 });
  const extra = newDirtyOutsideAtlas(before);
  if (extra.length) throw new Error(`核查越界改了路径：${extra.join(" | ")}`);
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
    console.log(`[${slug}] round ${round}: 盲读 ×3 + 核查…`);
    const [readers, fc] = await Promise.all([blindRead(page, body), factcheck(page, body)]);
    const unclearMed = median(readers.map(r => r.unclear_sentences.length));
    const retellOk = readers.filter(r => r.can_explain_to_colleague).length;
    if (unclearMed > 3) reasons.push(`读不懂句子中位 ${unclearMed} > 3：${readers.flatMap(r => r.unclear_sentences).slice(0, 5).join("｜")}`);
    if (retellOk < 2) reasons.push(`复述不成立（${retellOk}/3 能讲给同事）`);
    if (fc.unsupported.length) reasons.push(`unsupported ${fc.unsupported.length} 条：${fc.unsupported.map((u: any) => u.claim).slice(0, 3).join("｜")}`);
    record.rounds.push({ round, visuals: vis, unclearMed, retellOk, unsupported: fc.unsupported, reasons });
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
      ...(readers.flatMap(r => r.undefined_terms ?? [])).slice(0, 6).map(t => `- 术语没解释：${t}`),
      ...fc.unsupported.map((u: any) => `- 事实不符：「${u.claim}」——${u.why}`),
    ].join("\n");
  }
  writeFileSync(arch, JSON.stringify(record, null, 2));
  return { slug, pass: false, reasons: record.rounds.at(-1).reasons };
}

// ---------- 并发驱动 ----------
const queue = [...wanted];
const results: { slug: string; pass: boolean; reasons: string[] }[] = [];
await Promise.all(Array.from({ length: Math.min(CONC, queue.length) }, async () => {
  while (queue.length) {
    const slug = queue.shift()!;
    try { results.push(await runPage(slug)); }
    catch (e: any) { results.push({ slug, pass: false, reasons: [`pipeline error: ${e?.message ?? e}`] }); }
  }
}));
console.log("\n===== 汇总 =====");
for (const r of results) console.log(`${r.pass ? "✅" : "❌"} ${r.slug}${r.reasons.length ? "  " + r.reasons.join("；") : ""}`);
const failed = results.filter(r => !r.pass).length;
console.log(`过门 ${results.length - failed}/${results.length}`);
process.exit(failed ? 1 : 0);
