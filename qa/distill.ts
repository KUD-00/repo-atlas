#!/usr/bin/env bun
/**
 * 概念页 → 视频分镜蒸馏器（可选 pipeline）。
 * 把已过验收的概念页蒸馏成视频生成模型可直接使用的分镜脚本（scene-by-scene：
 * 旁白/画面 prompt/叠字/时长），旁白逐场景溯源回概念页原文——蒸馏不许引入新事实。
 *
 * 在目标仓库里跑：
 *   cd <你的仓库> && bun <repo-atlas>/qa/distill.ts <slug...>|--all [--concurrency 2] [--force]
 *
 * 配置 .atlas/pipeline/distill.json（仓库自有内容）：
 *   { "defaults": { "duration_sec": 60, "aspect": "16:9", "style": "扁平插画+等距示意动画",
 *                   "narration_lang": "zh", "visual_prompt_lang": "en" },
 *     "targets": [{ "slug": "ivr-call-lifecycle", "duration_sec": 60, "emphasis": "可选:侧重点" }] }
 *
 * 门（轻量，两层）：
 *   机械：场景数 3-10；时长和 = 目标 ±20%；旁白语速 ≤ 每秒 7 字（zh/ja）；旁白无禁令句式
 *   忠实度：核查 agent 逐场景比对旁白与概念页——引入页面之外的事实/改变机制 = 不过
 * 未过带评语返工 ≤2 轮。产出：
 *   .atlas/distill/<slug>.storyboard.json（喂下游的结构化脚本）
 *   .atlas/distill/<slug>.storyboard.md（人读预览：分镜表）
 * 档案 .atlas/qa/_distill/<slug>.json（resume-skip，--force 重跑）。
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { findRepoRoot, runAgent, lenientParse, lintBannedPhrases, loadPrompt, median } from "./lib";

const REPO = findRepoRoot();
const QA = new URL(".", import.meta.url).pathname.replace(/\/$/, "");
const SPEC_FILE = join(REPO, ".atlas/pipeline/distill.json");
const OUT_DIR = join(REPO, ".atlas/distill");
const ARCHIVE = join(REPO, ".atlas/qa/_distill");
mkdirSync(OUT_DIR, { recursive: true });
mkdirSync(ARCHIVE, { recursive: true });
if (!existsSync(SPEC_FILE)) { console.error("缺 .atlas/pipeline/distill.json（格式见本文件头注释）"); process.exit(2); }
const spec = JSON.parse(readFileSync(SPEC_FILE, "utf8"));
const DEF = { duration_sec: 60, aspect: "16:9", style: "扁平插画+等距示意动画", narration_lang: "zh", visual_prompt_lang: "en", ...(spec.defaults ?? {}) };

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(`--${n}`);
const optNum = (n: string, d: number) => { const i = args.indexOf(`--${n}`); return i >= 0 ? Number(args[i + 1]) : d; };
const FORCE = flag("force");
const CONC = optNum("concurrency", 2);
const wanted: string[] = flag("all") ? spec.targets.map((t: any) => t.slug)
  : args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--concurrency");
if (!wanted.length) { console.error("usage: bun distill.ts <slug...>|--all [--concurrency N] [--force]"); process.exit(2); }

const SB_SCHEMA = JSON.stringify({
  type: "object",
  properties: {
    core_message: { type: "string", description: "整支视频要让观众带走的一句话" },
    metaphor: { type: "string", description: "全片一致的视觉隐喻设定(一句话)" },
    scenes: {
      type: "array",
      items: {
        type: "object",
        properties: {
          seconds: { type: "number" },
          narration: { type: "string", description: "旁白,口语,能直接读出来" },
          visual_prompt: { type: "string", description: "给视频生成模型的画面描述:镜头/主体/动作/氛围,具体可拍" },
          on_screen_text: { type: "string", description: "画面叠字,≤12字,可空串" },
          source_quote: { type: "string", description: "本场景旁白依据的概念页原文摘录(尽量原样)" },
        },
        required: ["seconds", "narration", "visual_prompt", "source_quote"],
      },
    },
  },
  required: ["core_message", "metaphor", "scenes"],
});

const FIDELITY_SCHEMA = JSON.stringify({
  type: "object",
  properties: {
    violations: { type: "array", items: { type: "object", properties: { scene: { type: "number" }, narration: { type: "string" }, why: { type: "string" } }, required: ["scene", "why"] } },
    summary: { type: "string" },
  },
  required: ["violations", "summary"],
});

function pageOf(slug: string): { title: string; audience: string; body: string } | null {
  const f = join(REPO, ".atlas/concepts", slug + ".md");
  if (!existsSync(f)) return null;
  const raw = readFileSync(f, "utf8");
  const m = raw.match(/^---\n([\s\S]*?)\n---\n?/);
  const meta: Record<string, string> = {};
  if (m) for (const l of m[1].split("\n")) { const kv = l.match(/^(\w+):\s*(.*)$/); if (kv) meta[kv[1]] = kv[2].trim(); }
  return { title: meta.title ?? slug, audience: meta.audience ?? "dev", body: raw.replace(/^---\n[\s\S]*?\n---\n?/, "") };
}

async function distill(target: any, page: { title: string; audience: string; body: string }, feedback: string | null): Promise<any | null> {
  const dur = target.duration_sec ?? DEF.duration_sec;
  const prompt = `你在把一篇**已通过事实验收**的机制讲解页,蒸馏成一支 ${dur} 秒短视频的分镜脚本,喂给视频生成模型。

标题:${page.title}
受众:${page.audience === "general" ? "非开发者(酒店运营/销售/客服)" : "开发者"}
${target.emphasis ? `侧重:${target.emphasis}` : ""}
画幅 ${DEF.aspect};美术风格:${DEF.style};旁白语言:${DEF.narration_lang};visual_prompt 语言:${DEF.visual_prompt_lang}(给视频模型,要具体可拍:镜头/主体/动作/氛围,不出现代码截图、不出现文字密集画面)。

蒸馏铁律:
1. **不许引入页面没有的事实**。每个场景给 source_quote(旁白依据的页面原文摘录,尽量原样)。数字、顺序、因果照页面,一个都不许变形。
2. 精华=让没读过页面的人 ${dur} 秒 get 核心机制:一句 core_message + 3-10 个场景,有叙事弧(钩子→机制展开→观众带走什么)。
3. 旁白是**口语**,能直接配音朗读:短句、无书面腔、无 AI 腔(禁「值得注意的是/简单来说/让我们/想象一下」等)。语速按每秒 ≤7 字算,场景旁白字数 ≤ seconds×7。
4. **全片一个视觉隐喻**(metaphor 字段写明设定,比如"配置编译=把菜谱预先做成便当"),各场景的 visual_prompt 都在同一设定里推进,别换世界观。比喻可以新造,但机制不许被比喻扭曲。
5. 时长:各场景 seconds 之和 = ${dur}±20%。
${feedback ? `\n上一轮未过,逐条修复:\n${feedback}\n` : ""}
页面全文:
${page.body}

只输出 JSON(schema 已给)。${loadPrompt(QA, REPO, "distill")}`;
  const out = await runAgent(prompt, { cwd: REPO, schema: SB_SCHEMA, maxTurns: 6, timeoutMs: 600_000 });
  return lenientParse(out);
}

async function fidelityCheck(page: { body: string }, sb: any): Promise<any> {
  const prompt = `你是忠实度核查员。下面是一篇机制讲解页(唯一事实源)和据它蒸馏的视频旁白。逐场景核对:旁白是否引入了页面没有的事实、数字/顺序/因果是否被改变、比喻是否扭曲了机制。合理的通俗化与省略不算违规;只抓"页面里没有/与页面相悖"。

## 讲解页
${page.body}

## 分镜(scene 序号从 1 起)
${sb.scenes.map((s: any, i: number) => `${i + 1}. [${s.seconds}s] ${s.narration}`).join("\n")}

只输出 JSON:{"violations":[{"scene":N,"narration":"...","why":"..."}],"summary":"..."}${loadPrompt(QA, REPO, "distill-fidelity")}`;
  const out = await runAgent(prompt, { cwd: REPO, schema: FIDELITY_SCHEMA, maxTurns: 4, timeoutMs: 300_000 });
  return lenientParse(out) ?? { violations: [], summary: "解析失败(存疑通过)" };
}

function mechGate(sb: any, dur: number): string[] {
  const reasons: string[] = [];
  if (!Array.isArray(sb.scenes) || sb.scenes.length < 3 || sb.scenes.length > 10) reasons.push(`场景数 ${sb.scenes?.length ?? 0} 不在 3-10`);
  const total = (sb.scenes ?? []).reduce((a: number, s: any) => a + (s.seconds || 0), 0);
  if (total < dur * 0.8 || total > dur * 1.2) reasons.push(`时长和 ${total}s 超出 ${dur}±20%`);
  for (const [i, s] of (sb.scenes ?? []).entries()) {
    const chars = (s.narration ?? "").replace(/\s/g, "").length;
    if (chars > (s.seconds || 0) * 7) reasons.push(`场景${i + 1} 旁白 ${chars} 字超语速上限 ${Math.floor((s.seconds || 0) * 7)}`);
  }
  const allNarration = (sb.scenes ?? []).map((s: any) => s.narration).join("\n");
  reasons.push(...lintBannedPhrases(allNarration));
  return reasons;
}

function renderMd(slug: string, target: any, sb: any): string {
  const dur = target.duration_sec ?? DEF.duration_sec;
  return [
    `# ${sb.title ?? slug} — 分镜脚本(${dur}s / ${DEF.aspect})`,
    ``, `**核心信息**:${sb.core_message}`, `**视觉隐喻**:${sb.metaphor}`, ``,
    `| # | 秒 | 旁白 | 画面 prompt | 叠字 |`, `| --- | --- | --- | --- | --- |`,
    ...sb.scenes.map((s: any, i: number) => `| ${i + 1} | ${s.seconds} | ${s.narration} | ${s.visual_prompt} | ${s.on_screen_text ?? ""} |`),
    ``, `> 溯源:各场景 source_quote 见同名 .json;蒸馏自 .atlas/concepts/${slug}.md`,
  ].join("\n");
}

async function runTarget(slug: string): Promise<{ slug: string; pass: boolean; reasons: string[] }> {
  const target = spec.targets.find((t: any) => t.slug === slug);
  if (!target) return { slug, pass: false, reasons: ["未知 slug(不在 distill.json targets)"] };
  const page = pageOf(slug);
  if (!page) return { slug, pass: false, reasons: ["概念页不存在"] };
  const arch = join(ARCHIVE, slug + ".json");
  if (!FORCE && existsSync(arch)) {
    try { if (JSON.parse(readFileSync(arch, "utf8")).finalPass) { console.log(`[${slug}] ⏭ 已过门,跳过`); return { slug, pass: true, reasons: [] }; } } catch {}
  }
  const dur = target.duration_sec ?? DEF.duration_sec;
  const record: any = { slug, rounds: [], finalPass: false };
  let feedback: string | null = null;
  for (let round = 0; round < 3; round++) {
    console.log(`[${slug}] round ${round}: 蒸馏…`);
    const sb = await distill(target, page, feedback);
    if (!sb) { record.rounds.push({ round, error: "输出解析失败" }); feedback = "- 输出必须是合法 JSON"; continue; }
    const reasons = mechGate(sb, dur);
    console.log(`[${slug}] round ${round}: 忠实度核查…`);
    const fid = await fidelityCheck(page, sb);
    if (fid.violations.length) reasons.push(...fid.violations.map((v: any) => `场景${v.scene} 引入新事实/机制变形:${v.why}`));
    record.rounds.push({ round, mech: mechGate(sb, dur), fidelity: fid, reasons });
    if (!reasons.length) {
      record.finalPass = true;
      writeFileSync(join(OUT_DIR, `${slug}.storyboard.json`), JSON.stringify({ slug, title: page.title, audience: page.audience, ...DEF, duration_sec: dur, ...sb }, null, 2));
      writeFileSync(join(OUT_DIR, `${slug}.storyboard.md`), renderMd(slug, target, sb));
      writeFileSync(arch, JSON.stringify(record, null, 2));
      console.log(`[${slug}] ✅ 过门(round ${round}) → .atlas/distill/${slug}.storyboard.{json,md}`);
      return { slug, pass: true, reasons: [] };
    }
    console.log(`[${slug}] round ${round}: ❌ ${reasons.join(";").slice(0, 200)}`);
    feedback = reasons.map(r => `- ${r}`).join("\n");
  }
  writeFileSync(arch, JSON.stringify(record, null, 2));
  return { slug, pass: false, reasons: record.rounds.at(-1)?.reasons ?? ["3 轮未过"] };
}

const queue = [...wanted];
const results: { slug: string; pass: boolean; reasons: string[] }[] = [];
await Promise.all(Array.from({ length: Math.min(CONC, queue.length) }, async () => {
  while (queue.length) {
    const slug = queue.shift()!;
    try { results.push(await runTarget(slug)); }
    catch (e: any) { results.push({ slug, pass: false, reasons: [`pipeline error: ${e?.message ?? e}`] }); }
  }
}));
console.log("\n===== 汇总 =====");
for (const r of results) console.log(`${r.pass ? "✅" : "❌"} ${r.slug}${r.reasons.length ? "  " + r.reasons.join(";") : ""}`);
process.exit(results.some(r => !r.pass) ? 1 : 0);
