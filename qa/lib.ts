/**
 * QA 编排脚本的共通核（组合机制的底层）。
 *
 * 分层约定：
 *   共通核（本文件）＝ 所有文体共享的机械检测（禁令句式/可视化计数）、agent 调用、
 *   git 越界守卫、宽容 JSON 解析、prompt 三层加载（出厂 → 仓库整替 → .extra.md 追加）。
 *   文体层 ＝ 各编排器（run.ts 路径笔记 / concept.ts 概念页）自己的 prompt 与门阈值。
 *   仓库层 ＝ .atlas/pipeline/<名字>.md（整替）与 <名字>.extra.md（追加）。
 *
 * 不 import repo-atlas 内核（src/）——tool ⊥ data；qa/ 内部共享走本文件。
 */
import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

export function findRepoRoot(): string {
  let d = process.cwd();
  while (true) {
    if (existsSync(join(d, ".atlas"))) return d;
    const up = dirname(d);
    if (up === d) throw new Error("未找到 .atlas/ —— 请在带 atlas 的仓库内运行");
    d = up;
  }
}

export const AGENT_BIN = process.env.ATLAS_QA_AGENT || "grok";

// ---------- 禁令句式（AI 腔/元话术，单一来源；文体层可再追加） ----------
export const BANNED_PHRASES = [
  "值得注意的是", "有意思的是", "我们来看", "挑几个说", "一定要注意", "答案是——",
  "先记住", "记住一件事", "简单来说", "换句话说", "别担心", "让我们", "想象一下",
  "见文末", "如上所述", "综上所述", "总而言之",
];
export function lintBannedPhrases(body: string, extra: string[] = []): string[] {
  const noCode = body.replace(/```[\s\S]*?```/g, "");
  const issues: string[] = [];
  for (const p of [...BANNED_PHRASES, ...extra])
    if (noCode.includes(p)) issues.push(`禁令句式（AI 腔/元话术）：「${p}」——删掉或改成直接陈述`);
  return issues;
}

// ---------- 结构机械门（中文行文；run.ts 有历史局部副本=已知债，新文体一律用这里） ----------
// 长段落：一段塞太多字/句 = 没分段。callout 区允许密（渐进披露），列表项剥掉 marker 同样计。
export function longParagraphs(body: string, hard: boolean): string[] {
  const ci = body.indexOf('<div class="callout"');
  const prose = (ci >= 0 ? body.slice(0, ci) : body).replace(/```[\s\S]*?```/g, "");
  const [maxLen, maxSent] = hard ? [360, 6] : [280, 4];
  const bad: string[] = [];
  for (const raw of prose.split("\n")) {
    let t = raw.trim();
    if (!t || /^(#{1,6} |>|\||!\[|<)/.test(t)) continue;
    const isList = /^\s*([-*+]|\d+[.、)])\s/.test(t);
    if (isList) t = t.replace(/^\s*([-*+]|\d+[.、)])\s+/, "");
    const sentences = (t.match(/[。！？]/g) || []).length;
    if (t.length > maxLen || sentences > maxSent) bad.push(`${isList ? "列表项" : "段落"}${t.length}字${sentences}句：${t.slice(0, 38)}…`);
  }
  return bad;
}
// 平行枚举顿号串（该拆 - 列表）。A「N个X：A、B、C」；B「X（…）、Y（…）、Z（…）」；排除"比如/例如"举例串。
export function listCandidates(body: string): string[] {
  const prose = body.replace(/```[\s\S]*?```/g, "");
  const A = /(?:[二三四五六七八九十两]|[2-9]\d*)\s*(?:个|种|块|步|条|类|扇|轴|层|面|部分|方面|点)[^，。；：\n]{0,10}[：:][^。；\n]*、[^。；\n]*、/;
  const out: string[] = [];
  for (const raw of prose.split("\n")) {
    const t = raw.trim();
    if (!t || /^(#{1,6} |>|\||!\[|<|\s*[-*+] |\s*\d+[.、)] )/.test(t)) continue;
    const illustrative = /比如|例如|诸如|譬如|如：/.test(t);
    const parenSeries = !illustrative && (t.match(/）、/g) || []).length >= 2;
    if (A.test(t) || parenSeries) out.push(`平行枚举顿号串（拆成 - 列表）：${t.slice(0, 44)}…`);
  }
  return out;
}
// 结构扁平：正文很长却只有 1-2 个标题 → 大纲反映不出结构（内容闷在一节里）。
export function flatStructure(body: string, minHeadings = 3, minLines = 60): string | null {
  const ci = body.indexOf('<div class="callout"');
  const bo = ci >= 0 ? body.slice(0, ci) : body;
  const lines = bo.split("\n").length;
  const heads = (bo.replace(/```[\s\S]*?```/g, "").match(/^#{2,4} /gm) || []).length;
  if (lines > minLines && heads < minHeadings)
    return `结构扁平（${lines} 行只有 ${heads} 个标题）：每个真实小节开一个 #### 标题，让大纲反映结构`;
  return null;
}

// ---------- 可视化计数（图表密度门共用） ----------
export function countVisuals(body: string): { html: number; mermaid: number; tables: number } {
  return {
    html: (body.match(/<(div|table|details|section|figure)\b/g) || []).length,
    mermaid: (body.match(/```mermaid/g) || []).length,
    tables: (body.match(/^\s*\|[-: |]+\|\s*$/gm) || []).length,
  };
}

// ---------- git 越界守卫 ----------
export function dirtyPaths(repo: string): Set<string> {
  const out = new TextDecoder().decode(Bun.spawnSync(["git", "status", "--porcelain"], { cwd: repo }).stdout);
  return new Set(out.split("\n").filter(Boolean).map(l => l.slice(3).trim()));
}
export function newDirtyOutsideAtlas(repo: string, before: Set<string>): string[] {
  return [...dirtyPaths(repo)].filter(p => !before.has(p) && !p.startsWith(".atlas/"));
}

// ---------- agent 调用（grok 参数面） ----------
export interface AgentOpts { cwd: string; schema?: string; maxTurns: number; disallowed?: string; approve?: boolean; timeoutMs: number }
export async function runAgent(promptText: string, o: AgentOpts): Promise<any> {
  const pf = join(mkdtempSync(join(tmpdir(), "atlas-qa-")), "prompt.md");
  writeFileSync(pf, promptText);
  const argv = [AGENT_BIN, "--prompt-file", pf, "--no-memory", "--disable-web-search", "--no-subagents", "--max-turns", String(o.maxTurns), "--output-format", "json"];
  if (o.schema) argv.push("--json-schema", o.schema);
  if (o.disallowed) argv.push("--disallowed-tools", o.disallowed);
  if (o.approve !== false) argv.push("--always-approve");
  const proc = Bun.spawn(argv, { cwd: o.cwd, stdout: "pipe", stderr: "pipe" });
  const t = setTimeout(() => proc.kill(), o.timeoutMs);
  const out = await new Response(proc.stdout).text();
  clearTimeout(t); await proc.exited;
  rmSync(dirname(pf), { recursive: true, force: true });
  try { return JSON.parse(out); } catch { return { text: out, structuredOutput: null }; }
}
export function lenientParse(g: any): any | null {
  if (g?.structuredOutput) return g.structuredOutput;
  const t: string = (g?.text ?? "").trim();
  const s = t.indexOf("{"), e = t.lastIndexOf("}");
  if (s < 0 || e <= s) return null;
  try { return JSON.parse(t.slice(s, e + 1)); } catch { return null; }
}

// ---------- prompt 三层加载：出厂 → 仓库同名整替 → .extra.md 追加 ----------
export function loadPrompt(qaDir: string, repo: string, name: string): string {
  const override = join(repo, ".atlas/pipeline", `${name}.md`);
  const factory = join(qaDir, "prompts", `${name}.md`);
  let text = existsSync(override) ? readFileSync(override, "utf8")
    : existsSync(factory) ? readFileSync(factory, "utf8") : "";
  const extra = join(repo, ".atlas/pipeline", `${name}.extra.md`);
  if (existsSync(extra)) text += `\n\n## 本仓库追加规则\n\n${readFileSync(extra, "utf8")}`;
  return text;
}

export function median(ns: number[]): number { const s = [...ns].sort((a, b) => a - b); return s[Math.floor(s.length / 2)] ?? 0; }
