#!/usr/bin/env bun
/**
 * 语义可读性检测器（grok 维度限定，不评表面）——设计见 docs/readability-audit.md §5：
 * 机械层管表面（组合分 ρ≈0.54 已校准），本脚本管机械层看不见的语义维度：
 * naming（命名语义 1–5）、commentCoherence（注释-代码一致性 1–5/null）、
 * antipatterns（语言反模式）、barrel（re-export 墙）。
 *
 * 在目标仓库里跑：
 *   cd <你的仓库> && bun <repo-atlas>/qa/readability/semantic.ts <路径...> [选项]
 *
 * 选项：
 *   --lines N    每文件取前 N 行做摘录（默认 120；更长截断并在 prompt 里声明）
 *   --out <file> 结果 JSON 落盘（默认只打摘要到 stdout）
 *   --timeout ms 单文件 agent 超时（默认 120000）
 *
 * 覆盖契约与 qa 其它脚本一致：仓库侧放 .atlas/pipeline/readability-semantic.md
 * 整替出厂 prompt，或 readability-semantic.extra.md 追加规则。
 */
import { writeFileSync, existsSync, lstatSync, realpathSync, renameSync, unlinkSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname, resolve, basename, sep } from "node:path";
import { tmpdir } from "node:os";
import { createHash, randomUUID } from "node:crypto";
import { runAgent, lenientParse, DENY_ALL_WRITES, findRepoRoot, loadPrompt } from "../lib.js";
import { semanticAgentResponseError, semanticRowError } from "./calibrate/semantic-result.mjs";
import { readSafeRepoFile } from "./calibrate/semantic-manifest.mjs";

const REPO = findRepoRoot();
const QA_DIR = dirname(new URL(import.meta.url).pathname);

const args = process.argv.slice(2);
let LINES = 120;
let TIMEOUT = 120_000;
let outFile: string | null = null;
const paths: string[] = [];
let positionalOnly = false;
for (let index = 0; index < args.length; index++) {
  const arg = args[index];
  if (!positionalOnly && arg === "--") { positionalOnly = true; continue; }
  if (!positionalOnly && ["--lines", "--out", "--timeout"].includes(arg)) {
    const value = args[++index];
    if (value === undefined) { console.error(`${arg} requires a value`); process.exit(2); }
    if (arg === "--lines") LINES = Number(value);
    else if (arg === "--timeout") TIMEOUT = Number(value);
    else outFile = value;
    continue;
  }
  if (!positionalOnly && arg.startsWith("--")) { console.error(`unknown option: ${arg}`); process.exit(2); }
  paths.push(arg);
}
if (!Number.isSafeInteger(LINES) || LINES <= 0 || !Number.isSafeInteger(TIMEOUT) || TIMEOUT <= 0) {
  console.error("--lines and --timeout must be positive integers"); process.exit(2);
}
if (!paths.length) { console.error("usage: bun semantic.ts <路径...> [--lines N] [--out f] [--timeout ms]"); process.exit(2); }

const inputs = paths.map((rel) => ({ rel }));

const factory = loadPrompt(QA_DIR, REPO, "readability-semantic");
if (!factory) { console.error("prompt 缺失：qa/readability/prompts/readability-semantic.md"); process.exit(1); }

interface Row { path: string; sourceHash: string; naming: number | null; commentCoherence: number | null; antipatterns: any[]; barrel: boolean | null; reason: string; error?: string }

const sampleHash = process.env.ATLAS_SEMANTIC_SAMPLE_HASH ?? null;
if (sampleHash !== null && !/^[0-9a-f]{64}$/u.test(sampleHash)) {
  throw new Error("ATLAS_SEMANTIC_SAMPLE_HASH must be a lowercase SHA-256");
}
const expectedSourceHash = process.env.ATLAS_SEMANTIC_SOURCE_HASH ?? null;
if (expectedSourceHash !== null && !/^[0-9a-f]{64}$/u.test(expectedSourceHash)) {
  throw new Error("ATLAS_SEMANTIC_SOURCE_HASH must be a lowercase SHA-256");
}

const rows: Row[] = [];
for (const { rel } of inputs) {
  // Re-open and revalidate immediately before the bytes enter the prompt. A
  // prior manifest/path check may be minutes old in a multi-file run.
  const source = readSafeRepoFile(REPO, rel);
  const sourceHash = createHash("sha256").update(source).digest("hex");
  if (expectedSourceHash !== null && sourceHash !== expectedSourceHash) {
    throw new Error(`semantic source bytes no longer match the calibration manifest: ${rel}`);
  }
  const all = source.toString("utf8").split("\n");
  const truncated = all.length > LINES;
  const code = all.slice(0, LINES).join("\n") + (truncated ? `\n// …（截断，全文共 ${all.length} 行，以上仅前 ${LINES} 行）` : "");
  const prompt = `${factory}\n\n=== 文件: ${rel} ===\n${code}\n`;
  const cwd = mkdtempSync(join(tmpdir(), "atlas-rb-sem-"));
  try {
    let row: Row | null = null;
    let lastError = "解析失败";
    for (let attempt = 0; attempt < 2 && !row; attempt++) {
      const out = await runAgent(prompt, { cwd, maxTurns: 1, disallowed: DENY_ALL_WRITES, timeoutMs: TIMEOUT });
      const r: any = lenientParse(out);
      if (!r) continue;
      const responseError = semanticAgentResponseError(r);
      if (responseError) { lastError = responseError; continue; }
      const candidate: Row = {
        path: rel,
        sourceHash,
        naming: r.naming,
        commentCoherence: r.commentCoherence,
        antipatterns: r.antipatterns,
        barrel: r.barrel,
        reason: r.reason,
      };
      const error = semanticRowError(candidate, rel);
      if (error) lastError = error;
      else row = candidate;
    }
    rows.push(row ?? { path: rel, sourceHash, naming: null, commentCoherence: null, antipatterns: [], barrel: null, reason: "", error: lastError });
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
  const last = rows[rows.length - 1];
  console.log(`${last.error ? "ERR" : " ok"}  ${rel}  naming=${last.naming ?? "-"} coherence=${last.commentCoherence ?? "-"} anti=${last.antipatterns.length} barrel=${last.barrel ?? "-"}  ${last.reason || last.error || ""}`);
}

const ok = rows.filter((r) => !r.error);
const mean = (xs: number[]) => (xs.length ? (xs.reduce((a, b) => a + b, 0) / xs.length).toFixed(2) : "-");
console.log(`\n${ok.length}/${rows.length} 完成 · naming 均分 ${mean(ok.map((r) => r.naming!).filter(Number.isFinite))} · coherence 均分 ${mean(ok.map((r) => r.commentCoherence!).filter(Number.isFinite))} · 有反模式 ${ok.filter((r) => r.antipatterns.length).length} · barrel ${ok.filter((r) => r.barrel).length}`);
if (outFile !== null) {
  const target = resolve(REPO, outFile);
  const parent = dirname(target);
  const parentStat = lstatSync(parent);
  const repoReal = realpathSync(REPO);
  const parentReal = realpathSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink() ||
      (target.startsWith(resolve(REPO) + sep) && parentReal !== repoReal && !parentReal.startsWith(repoReal + sep))) {
    throw new Error(`unsafe semantic output directory: ${parent}`);
  }
  if (existsSync(target)) {
    const stat = lstatSync(target);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`unsafe semantic output: ${target}`);
  }
  const temp = join(parent, `.${basename(target)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    writeFileSync(temp, JSON.stringify({ formatVersion: 1, sampleHash, generatedAt: new Date().toISOString(), rows }, null, 2) + "\n", { flag: "wx", mode: 0o600 });
    renameSync(temp, target);
  } finally {
    try { unlinkSync(temp); } catch {}
  }
  console.log(`wrote ${target}`);
}
if (rows.some((row) => row.error)) process.exitCode = 1;
