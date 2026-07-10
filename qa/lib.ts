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

// ---------- mermaid 语法机械门 ----------
// 「图必须能通过 mermaid 解析」一直只是规范文字，没人兜底——坏图要等人打开页面看到红框
// 才发现（实测：sequenceDiagram 的 Note 文本里一个分号就碎）。这里用 mermaid.parse 无头
// 校验每个围栏块。mermaid 装在本工具仓的 node_modules；装不上时降级为跳过并警告一次。
let _mermaid: any | undefined;
async function getMermaid(): Promise<any | null> {
  if (_mermaid !== undefined) return _mermaid;
  try {
    // mermaid 的部分解析路径（如带 <br/> 标签的 label）会走 DOMPurify，需要 DOM——
    // 无头环境先用 happy-dom 把 window/document 立起来，否则报
    // "DOMPurify.addHook is not a function" 造成所有带图页面被误判失败。
    if (typeof (globalThis as any).document === "undefined") {
      const { Window } = await import("happy-dom");
      const w: any = new Window();
      (globalThis as any).window = w;
      (globalThis as any).document = w.document;
    }
    _mermaid = (await import("mermaid")).default;
  }
  catch { _mermaid = null; console.warn("  ⚠ mermaid 不可用（repo-atlas 未安装依赖？），跳过图语法校验"); }
  return _mermaid;
}
export async function validateMermaid(body: string): Promise<string[]> {
  const blocks = [...body.matchAll(/```mermaid\n([\s\S]*?)```/g)].map(m => m[1]);
  if (!blocks.length) return [];
  const mermaid = await getMermaid();
  if (!mermaid) return [];
  const errs: string[] = [];
  for (let i = 0; i < blocks.length; i++) {
    try { await mermaid.parse(blocks[i]); }
    catch (e: any) {
      const head = String(e?.message ?? e).split("\n").slice(0, 2).join(" ");
      errs.push(`mermaid 第 ${i + 1} 块（${blocks[i].trim().split("\n")[0]}）解析失败：${head.slice(0, 160)} —— 常见病：Note/标签文本里的分号、括号、引号；修语法或把特殊符号换成中文标点`);
    }
  }
  return errs;
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

// ---------- 精确越界守卫（transcript 归因） ----------
// 共享工作区里，git 差分守卫会把"别的 session 并发弄脏的路径"冤枉成本 agent 越界（实测
// 一整波 concept 生成被另一 session 的重构误杀）。grok 把每次会话的工具调用记录在
// ~/.grok/sessions/<urlencode(cwd)>/<sessionId>/chat_history.jsonl —— 据此精确回答
// "这个 agent 自己写了哪些文件"。终端命令无法按路径归因，调用方应对无需终端的阶段
// 直接 disallow Shell，让全部写入可归因。
const WRITE_TOOLS = new Set(["write", "search_replace", "edit_file", "create_file", "apply_patch", "str_replace"]);
const SHELL_TOOLS = new Set(["run_terminal_command", "run_terminal_cmd", "bash", "shell", "terminal"]);

// grok --disallowed-tools 的**真实**工具名（实测：喂错名会被静默忽略——"Shell,Write,StrReplace"
// 这类 Claude Code 名字从来没拦住过任何东西）。探针验证 2026-07-10：
//   run_terminal_cmd → 终端；write/search_replace/create_file/edit_file/apply_patch → 写文件。
export const DENY_TERMINAL = "run_terminal_cmd";
export const DENY_ALL_WRITES = "run_terminal_cmd,write,search_replace,create_file,edit_file,apply_patch";
export function agentWrites(cwd: string, sessionId: string): { files: string[]; shells: string[] } | null {
  const home = process.env.HOME || "";
  const f = join(home, ".grok/sessions", encodeURIComponent(cwd), sessionId, "chat_history.jsonl");
  if (!home || !sessionId || !existsSync(f)) return null;
  const files: string[] = [], shells: string[] = [];
  for (const ln of readFileSync(f, "utf8").split("\n")) {
    if (!ln.trim()) continue;
    let d: any; try { d = JSON.parse(ln); } catch { continue; }
    for (const tc of d?.tool_calls ?? []) {
      let a: any = {}; try { a = JSON.parse(tc.arguments ?? "{}"); } catch { /* 参数解析失败按未知处理 */ }
      const p = a.target_file ?? a.file_path ?? a.path ?? a.filePath;
      if (WRITE_TOOLS.has(tc.name)) { if (p) files.push(String(p)); }
      else if (SHELL_TOOLS.has(tc.name)) shells.push(String(a.command ?? a.cmd ?? "").slice(0, 200));
    }
  }
  return { files, shells };
}
// 终端命令里"像写操作"的形状（无法按路径归因时的兜底判据）
const SHELL_WRITEY = /(^|[;&|]\s*)(rm|mv|cp|tee|sed\s+-i|git\s+(add|commit|checkout|restore|clean|stash|reset))\b|>>?\s*\S/;
/**
 * 断言"这个 agent 会话没有写 .atlas 之外的东西"。
 * 优先 transcript 归因：agent 自己写的文件越界 → 抛；终端跑了写形状的命令且树上出现
 * .atlas 外新脏 → 无法归因，fail-safe 抛；只有环境脏（别的 session 并发改动）→ 警告放行。
 * transcript 不可得（非 grok / 日志缺失）→ 回退老的 git 差分硬门。
 */
export function assertOnlyAtlasWrites(repo: string, agentCwd: string, sessionId: string | undefined, before: Set<string>, label: string): void {
  const ambient = newDirtyOutsideAtlas(repo, before);
  const t = sessionId ? agentWrites(agentCwd, sessionId) : null;
  if (t === null) {
    if (ambient.length) throw new Error(`${label} 越界改了 .atlas 外路径（transcript 不可得，按 git 差分判）：${ambient.join(" | ")}`);
    return;
  }
  const bad = t.files.filter(p => {
    const abs = p.startsWith("/") ? p : join(agentCwd, p);
    return abs.startsWith(repo + "/") && !abs.startsWith(join(repo, ".atlas") + "/");
  });
  if (bad.length) throw new Error(`${label} 的 agent 亲手写了 .atlas 外文件：${bad.join(" | ")}`);
  if (ambient.length) {
    const writey = t.shells.filter(c => SHELL_WRITEY.test(c));
    if (writey.length) throw new Error(`${label}：树上出现 .atlas 外新脏（${ambient.join(" | ")}），且该 agent 跑过写形状的终端命令（${writey[0]}…）——无法归因，按越界处理`);
    console.warn(`  ⚠ ${label}：检测到 .atlas 外新脏路径（${ambient.slice(0, 4).join(", ")}${ambient.length > 4 ? "…" : ""}）——transcript 显示本 agent 未写它们，判为其它 session 的并发改动，放行`);
  }
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
