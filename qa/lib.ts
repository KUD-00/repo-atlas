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
