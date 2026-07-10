#!/usr/bin/env bun
/**
 * reading order 提案器：给目录页 frontmatter 补 `order: [...]`（viewer 的 ①② 阅读顺序徽标）。
 * 在目标仓库里跑：
 *   cd <你的仓库> && bun <repo-atlas>/qa/order.ts [dir路径...] [选项]
 *
 * 不带路径 = 扫 .atlas/notes 下所有**还没有 order** 且子项 ≥3 的目录页。
 *
 * 选项：
 *   --all    已有 order 的也重新提案（覆盖写）
 *   --dry    只打印提案不写文件
 *
 * 机制：读目录页正文 + 各子项笔记的首段概览，让 agent 按「读者应该先懂什么」
 * 排一个（允许部分的）子项名列表；校验名字都真实存在后写回 frontmatter。
 * order 是导航元数据，不过 QA 门；hash/anchor/stamped 原样保留（stamp 会保序）。
 */
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";

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
const NOTES = join(REPO, ".atlas/notes");
const AGENT_BIN = process.env.ATLAS_QA_AGENT || "grok";

const args = process.argv.slice(2);
const DRY = args.includes("--dry");
const ALL = args.includes("--all");
const wanted = args.filter((a) => !a.startsWith("--")).map((p) => p.replace(/\/+$/, ""));

// 目录页的子项：X.md → 文件 X；子目录（含 __dir__.md）→ 目录名
function childrenOf(dirNotesPath: string): { name: string; overview: string }[] {
  const out: { name: string; overview: string }[] = [];
  for (const e of readdirSync(dirNotesPath)) {
    const full = join(dirNotesPath, e);
    let name: string, noteFile: string;
    if (statSync(full).isDirectory()) {
      name = e; noteFile = join(full, "__dir__.md");
      if (!existsSync(noteFile)) continue;
    } else {
      if (!e.endsWith(".md") || e === "__dir__.md") continue;
      name = e.slice(0, -3); noteFile = full;
    }
    const body = readFileSync(noteFile, "utf8").replace(/^---\n[\s\S]*?\n---\n?/, "");
    const firstPara = body.split(/\n\s*\n/).find((p) => p.trim() && !p.trim().startsWith("#")) ?? "";
    out.push({ name, overview: firstPara.trim().slice(0, 400) });
  }
  return out;
}

function dirNotePaths(): string[] {
  const found: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d)) {
      const full = join(d, e);
      if (statSync(full).isDirectory()) { walk(full); }
    }
    if (existsSync(join(d, "__dir__.md"))) found.push(d);
  };
  if (existsSync(NOTES)) walk(NOTES);
  return found;
}

const SCHEMA = JSON.stringify({
  type: "object",
  properties: {
    order: { type: "array", items: { type: "string" }, description: "子项名(name)按建议阅读顺序;允许部分列表,没把握的省略" },
    reason: { type: "string", description: "一句话:这个顺序的教学逻辑" },
  },
  required: ["order"],
});

async function propose(repoDir: string, dirBody: string, kids: { name: string; overview: string }[]): Promise<{ order: string[]; reason?: string } | null> {
  const prompt = [
    `你在给 codebase atlas 的目录页排「阅读顺序」。目录:${repoDir || "(仓库根)"}`,
    `原则:按**读者应该先懂什么**排,不是按字母/重要性——先立地基概念(被别人依赖的契约/核心模型),再读依赖它的实现与外围。允许部分列表:没把握的子项省略,viewer 会把它们按默认顺序排在已列项之后。`,
    `只能用下面给出的子项 name,原样照抄。`,
    `\n## 目录页正文(节选)\n\n${dirBody.slice(0, 2500)}`,
    `\n## 子项(name + 各自笔记首段)\n`,
    ...kids.map((k) => `- **${k.name}** — ${k.overview || "(无概览)"}`),
    `\n输出 JSON:{"order": ["name", ...], "reason": "一句话"}`,
  ].join("\n");
  const pf = join(mkdtempSync(join(tmpdir(), "atlas-order-")), "prompt.md");
  writeFileSync(pf, prompt);
  const argv = [AGENT_BIN, "--prompt-file", pf, "--no-memory", "--disable-web-search", "--no-subagents",
    "--max-turns", "3", "--output-format", "json", "--json-schema", SCHEMA, "--always-approve"];
  const proc = Bun.spawn(argv, { cwd: REPO, stdout: "pipe", stderr: "pipe" });
  const killer = setTimeout(() => proc.kill(), 120_000);
  const out = await new Response(proc.stdout).text();
  clearTimeout(killer);
  await proc.exited;
  rmSync(dirname(pf), { recursive: true, force: true });
  let parsed: any;
  try { parsed = JSON.parse(out); } catch { return null; }
  const so = parsed?.structuredOutput ?? (() => { try { return JSON.parse((parsed?.text ?? "").match(/\{[\s\S]*\}/)?.[0] ?? ""); } catch { return null; } })();
  return so && Array.isArray(so.order) ? so : null;
}

function writeOrder(noteFile: string, order: string[]) {
  const s = readFileSync(noteFile, "utf8");
  const m = s.match(/^---\n([\s\S]*?)\n---\n/);
  if (!m) throw new Error(`无 frontmatter:${noteFile}(先 stamp 再定 order)`);
  const fm = m[1].split("\n").filter((l) => !l.startsWith("order:"));
  fm.push(`order: ${JSON.stringify(order)}`);
  writeFileSync(noteFile, s.replace(m[0], `---\n${fm.join("\n")}\n---\n`));
}

const targets = (wanted.length ? wanted.map((p) => join(NOTES, p)) : dirNotePaths()).filter((d) => {
  if (!existsSync(join(d, "__dir__.md"))) { console.error(`跳过(无目录页):${d}`); return false; }
  const hasOrder = /^order:/m.test(readFileSync(join(d, "__dir__.md"), "utf8").split("---")[1] ?? "");
  if (hasOrder && !ALL && !wanted.length) return false;
  return true;
});

let done = 0;
for (const d of targets) {
  const repoDir = d === NOTES ? "" : d.slice(NOTES.length + 1);
  const kids = childrenOf(d);
  if (kids.length < 3) { if (wanted.length) console.log(`[${repoDir}] 子项 ${kids.length} 个,不值得排序,跳过`); continue; }
  const noteFile = join(d, "__dir__.md");
  const body = readFileSync(noteFile, "utf8").replace(/^---\n[\s\S]*?\n---\n?/, "");
  const res = await propose(repoDir, body, kids);
  if (!res) { console.error(`[${repoDir}] agent 提案失败`); continue; }
  const valid = res.order.filter((n) => kids.some((k) => k.name === n));
  const dropped = res.order.filter((n) => !kids.some((k) => k.name === n));
  if (dropped.length) console.error(`[${repoDir}] 丢弃不存在的子项名:${dropped.join(", ")}`);
  if (!valid.length) { console.error(`[${repoDir}] 提案全无效,跳过`); continue; }
  console.log(`[${repoDir}] order: ${valid.join(" → ")}${res.reason ? `\n  理由:${res.reason}` : ""}`);
  if (!DRY) { writeOrder(noteFile, valid); done++; }
}
console.log(DRY ? "(dry run,未写文件)" : `写入 ${done} 个目录页的 order`);
