#!/usr/bin/env bun
/**
 * 概念级安全审计：以 .atlas/concepts/<slug>.md 的 sources 为审计单元（信任边界），
 * 让 agent 顺着概念页这张「地图」审数据流，再对每个 finding 过只读 factcheck 门，
 * 落 .atlas/audits/<slug>.json 档案（机器账，rounds 追加），并渲染
 * .atlas/artifacts/concepts/<slug>/security-audit.md 投影（viewer 侧栏 tab 给人看）。
 * scope 字节漂移（git blob sha）或 ruleset 换版才重审。
 *
 *   cd <目标仓库> && bun <repo-atlas>/qa/audit.ts <slug...|--all> [--concurrency 4] [--fresh]
 *
 * 与 run.ts/concept.ts 同属「文体层」，共用 lib.ts 机制（runAgent / loadPrompt /
 * DENY_ALL_WRITES / assertOnlyAtlasWrites）；产出不是笔记而是 verdict 档案，
 * 档案每轮追加（审计要有历史，不像笔记 stamp 覆盖）。
 *
 * 不用 --json-schema：实测它会令 agent 概率性跳过工具调用直接编答案（2026-07-19 探针）。
 * 改用 prompt 内嵌 JSON 契约 + lenientParse 兜底 + agentToolCounts 工具证据硬门——
 * 输出形状完美但一次读工具没调的，按幻觉处理、整轮作废。
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { join, basename } from "node:path";
import { createHash } from "node:crypto";
import {
  findRepoRoot, runAgent, lenientParse, loadPrompt,
  DENY_ALL_WRITES, assertOnlyAtlasWrites, agentToolCounts, dirtyPaths,
} from "./lib.ts";

const REPO = findRepoRoot();
const QA = new URL(".", import.meta.url).pathname.replace(/\/$/, "");
const RULESET_ID = "atlas-secscan-v1"; // 规则正文 = prompts/audit.md（仓库可 .atlas/pipeline 整替/追加）

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(`--${n}`);
const optNum = (n: string, d: number) => { const i = args.indexOf(`--${n}`); return i >= 0 ? Number(args[i + 1]) : d; };
const CONC = optNum("concurrency", 4);
const FRESH = flag("fresh");
const ALL = flag("all");
const slugs = ALL
  ? readdirSync(join(REPO, ".atlas/concepts")).filter(f => f.endsWith(".md")).map(f => basename(f, ".md"))
  : args.filter(a => !a.startsWith("--") && a !== String(CONC));
if (!slugs.length) {
  console.error("usage: cd <目标仓库> && bun audit.ts <slug...|--all> [--concurrency 4] [--fresh]");
  process.exit(2);
}

const SEV = ["info", "low", "medium", "high", "critical"] as const;
type Finding = { severity: string; category: string; title: string; locations: string[]; dataflow: string; fix: string; confidence?: string };

// ---------- 概念页解析（只要 title/sources；sources_hash 等机器字段不归这里管） ----------
function parseConcept(slug: string): { title: string; sources: string[]; body: string } {
  const f = join(REPO, ".atlas/concepts", `${slug}.md`);
  if (!existsSync(f)) throw new Error(`概念页不存在：.atlas/concepts/${slug}.md`);
  const text = readFileSync(f, "utf8");
  const m = text.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!m) throw new Error(`${slug}.md 缺 frontmatter`);
  const fm = m[1];
  const title = fm.match(/^title:\s*(.+)$/m)?.[1]?.trim() ?? slug;
  const srcLine = fm.match(/^sources:\s*(\[.*\])\s*$/m)?.[1];
  if (!srcLine) throw new Error(`${slug}.md frontmatter 里没有 sources: [...]`);
  return { title, sources: JSON.parse(srcLine), body: m[2].trim() };
}

// ---------- sources → 文件清单（测试/fixture/二进制不算攻击面） ----------
const SKIP = /(__tests__|\.test\.|\.spec\.|fixture|\.png$|\.jpe?g$|\.gif$|\.webp$|\.lock$|\.bin$|\.wasm$|\.pdf$|\.map$)/i;
function enumerateFiles(sources: string[]): string[] {
  const out = new Set<string>();
  for (const src of sources) {
    const r = Bun.spawnSync(["git", "ls-files", "--", src], { cwd: REPO });
    if (!r.exitCode && r.stdout) {
      for (const p of new TextDecoder().decode(r.stdout).split("\n").filter(Boolean))
        if (!SKIP.test(p)) out.add(p);
    }
  }
  return [...out].sort();
}

// ---------- scope 指纹：sorted "blobSha  path" 行的 sha1（= 这批字节的审计绑定） ----------
function scopeHash(files: string[]): string {
  const r = Bun.spawnSync(["git", "hash-object", "--", ...files], { cwd: REPO });
  if (r.exitCode) throw new Error("git hash-object 失败");
  const shas = new TextDecoder().decode(r.stdout).split("\n").filter(Boolean);
  const lines = files.map((f, i) => `${shas[i]}  ${f}`).sort();
  return createHash("sha1").update(lines.join("\n") + "\n").digest("hex");
}

// ---------- 输出校验（形状） ----------
function validFindings(x: any): Finding[] | null {
  if (!x || !Array.isArray(x.findings)) return null;
  const ok = x.findings.every((f: any) =>
    SEV.includes(f.severity) && typeof f.category === "string" && typeof f.title === "string" &&
    Array.isArray(f.locations) && f.locations.every((l: any) => typeof l === "string") &&
    typeof f.dataflow === "string" && typeof f.fix === "string");
  return ok ? x.findings : null;
}

// ---------- 幻觉守门：要求读过码的阶段必须真的调过读类工具 ----------
function assertReadEvidence(sessionId: string | undefined, minReads: number, label: string): void {
  if (!sessionId) throw new Error(`${label}：无 sessionId，无法核工具证据`);
  const t = agentToolCounts(REPO, sessionId);
  if (!t) throw new Error(`${label}：transcript 不可得，无法核工具证据`);
  if (t.reads < minReads)
    throw new Error(`${label}：工具证据不足（读类调用 ${t.reads} 次 < ${minReads}）——按幻觉处理，整轮作废`);
}

const ARCHIVE_DIR = join(REPO, ".atlas/audits");
mkdirSync(ARCHIVE_DIR, { recursive: true });

// ---------- viewer 投影：档案 → .atlas/artifacts/concepts/<slug>/security-audit.md ----------
// artifacts 机制（src/artifacts.ts）：挂在页面侧栏 tab 展示、print 跳过、引擎不记 hash——
// 正是"管线产物给页面看"的位置。 audits/ 是机器账（rounds 历史、resume 依据），
// artifacts/ 是给人看的投影；跳过路径也会补渲染，保证投影不缺席。
// locations 渲染成 `路径`:line / `路径`#符号——反引号纯路径在 viewer 里自动成链接。
function locMd(loc: string): string {
  const m = loc.match(/^([^:#]+)([:#].*)$/);
  return m ? `\`${m[1]}\`${m[2]}` : `\`${loc}\``;
}
function renderProjection(slug: string, a: any): void {
  const dir = join(REPO, ".atlas/artifacts", "concepts", slug);
  mkdirSync(dir, { recursive: true });
  const tally = new Map<string, number>();
  for (const f of a.findings ?? []) tally.set(f.severity, (tally.get(f.severity) ?? 0) + 1);
  const tallyStr = [...tally.entries()]
    .sort(([x], [y]) => SEV.indexOf(y as any) - SEV.indexOf(x as any))
    .map(([s, n]) => `**${n} ${s}**`).join(" · ") || "无";
  const L: string[] = [];
  L.push(`# 安全审计 · ${a.title ?? slug}`, "");
  L.push(`- 扫描：${a.scanned_at} · ruleset \`${a.ruleset}\` · agent ${a.rounds?.at(-1)?.agent ?? "?"}`);
  L.push(`- 覆盖：${a.file_count} 文件（scope 指纹 \`${String(a.scope_hash).slice(0, 12)}…\`；字节漂移或换 ruleset 才重审）`);
  L.push(`- 结果：${tallyStr}${a.dropped?.length ? `；另有 ${a.dropped.length} 条被 factcheck 核查丢弃` : ""}`);
  L.push("", "---", "");
  for (const sev of [...SEV].reverse()) {
    const fs = (a.findings ?? []).filter((f: any) => f.severity === sev);
    if (!fs.length) continue;
    L.push(`## ${sev.toUpperCase()}`, "");
    for (const f of fs) {
      L.push(`### ${f.title}${f.confidence === "unverified" ? "（⚠ 未核实）" : ""}`, "");
      L.push(`- **类目**：${f.category}`);
      L.push(`- **位置**：${(f.locations ?? []).map(locMd).join("、")}`);
      L.push(`- **数据流**：${f.dataflow}`);
      L.push(`- **修法**：${f.fix}`, "");
    }
  }
  if (!(a.findings ?? []).length) L.push("本轮无 finding——干净是合法结论。", "");
  if (a.dropped?.length) {
    L.push("<details><summary>被 factcheck 丢弃的 findings（假阳性复盘用）</summary>", "");
    for (const d of a.dropped) {
      L.push(`- **${d.finding.title}**（原判 ${d.finding.severity}）`);
      L.push(`  - 丢弃理由：${d.reason}`);
    }
    L.push("", "</details>", "");
  }
  L.push("---", "", `机器档案（逐轮历史与 resume 依据）：\`.atlas/audits/${slug}.json\``, "");
  writeFileSync(join(dir, "security-audit.md"), L.join("\n"));
}

async function auditOne(slug: string): Promise<{ slug: string; kept: number; dropped: number; unverified: number; skipped?: boolean; failed?: string }> {
  const { title, sources, body } = parseConcept(slug);
  const files = enumerateFiles(sources);
  if (!files.length) return { slug, kept: 0, dropped: 0, unverified: 0, failed: "sources 下没有可审文件" };
  const scope = scopeHash(files);
  const archivePath = join(ARCHIVE_DIR, `${slug}.json`);
  if (!FRESH && existsSync(archivePath)) {
    try {
      const a = JSON.parse(readFileSync(archivePath, "utf8"));
      if (a.scope_hash === scope && a.ruleset === RULESET_ID) {
        renderProjection(slug, a); // 跳过也补渲染：投影可能缺失或档案是手工改的
        console.log(`[${slug}] scope 未漂移且 ruleset 未变，跳过（--fresh 强制重审）`);
        return { slug, kept: a.findings?.length ?? 0, dropped: 0, unverified: 0, skipped: true };
      }
    } catch { /* 档案损坏 → 重审 */ }
  }

  const before = dirtyPaths(REPO);
  const fileList = files.map(f => `- \`${f}\``).join("\n");
  const auditInput = `${loadPrompt(QA, REPO, "audit")}\n\n## 概念页（地图）\n\n# ${title}\n\n${body}\n\n## 审计单元 sources\n\n${sources.map(s => `- \`${s}\``).join("\n")}\n\n## 文件清单（${files.length} 个，全部要读）\n\n${fileList}`;
  const auditOut = await runAgent(auditInput, { cwd: REPO, maxTurns: files.length * 3 + 40, disallowed: DENY_ALL_WRITES, timeoutMs: 20 * 60_000 });
  assertOnlyAtlasWrites(REPO, REPO, auditOut?.sessionId, before, `audit(${slug})`);
  assertReadEvidence(auditOut?.sessionId, files.length, `audit(${slug})`);
  const findings = validFindings(lenientParse(auditOut));
  if (!findings) {
    writeFileSync(archivePath, JSON.stringify({ slug, title, ruleset: RULESET_ID, scope_hash: scope, finalPass: false, error: "审计输出解析/校验失败", raw_tail: String(auditOut?.text ?? "").slice(-2000) }, null, 2) + "\n");
    return { slug, kept: 0, dropped: 0, unverified: 0, failed: "审计输出解析/校验失败" };
  }

  let kept: Finding[] = findings;
  let dropped: { finding: Finding; reason: string }[] = [];
  let unverified = 0;
  if (findings.length) {
    const fcInput = `${loadPrompt(QA, REPO, "audit-factcheck")}\n\n## 审计单元文件清单\n\n${fileList}\n\n## findings JSON\n\n${JSON.stringify(findings, null, 2)}`;
    const fcOut = await runAgent(fcInput, { cwd: REPO, maxTurns: findings.length * 12 + 30, disallowed: DENY_ALL_WRITES, timeoutMs: 15 * 60_000 });
    assertOnlyAtlasWrites(REPO, REPO, fcOut?.sessionId, before, `audit-factcheck(${slug})`);
    assertReadEvidence(fcOut?.sessionId, findings.length, `audit-factcheck(${slug})`);
    const fc = lenientParse(fcOut);
    if (!fc || !Array.isArray(fc.verdicts)) {
      writeFileSync(archivePath, JSON.stringify({ slug, title, ruleset: RULESET_ID, scope_hash: scope, finalPass: false, error: "factcheck 输出解析失败", raw_tail: String(fcOut?.text ?? "").slice(-2000) }, null, 2) + "\n");
      return { slug, kept: 0, dropped: 0, unverified: 0, failed: "factcheck 输出解析失败" };
    }
    const byTitle = new Map(findings.map(f => [f.title, f]));
    kept = []; dropped = [];
    for (const v of fc.verdicts) {
      const f = byTitle.get(v.title);
      if (!f) continue;
      if (v.verdict === "unsupported") { dropped.push({ finding: f, reason: v.evidence }); continue; }
      if (v.adjusted_severity && SEV.includes(v.adjusted_severity)) f.severity = v.adjusted_severity;
      if (v.verdict === "unverifiable") { f.confidence = "unverified"; unverified++; }
      kept.push(f);
    }
    // factcheck 漏判的 finding 按未核实保留（宁多勿丢）
    const judged = new Set(fc.verdicts.map((v: any) => v.title));
    for (const f of findings) if (!judged.has(f.title)) { f.confidence = "unverified"; unverified++; kept.push(f); }
  }

  const rank = (s: string) => SEV.indexOf(s as any);
  kept.sort((a, b) => rank(b.severity) - rank(a.severity));
  const prev = existsSync(archivePath) ? JSON.parse(readFileSync(archivePath, "utf8")) : null;
  const rounds = [...(prev?.rounds ?? []), {
    at: new Date().toISOString(), agent: process.env.ATLAS_QA_AGENT || "grok",
    audit_count: findings.length, kept: kept.length, dropped: dropped.length, unverified,
  }];
  writeFileSync(archivePath, JSON.stringify({
    formatVersion: 1, // audits 格式契约：engine（src/audits.ts）按此识别；不兼容变更必须 +1
    slug, title, ruleset: RULESET_ID, scanned_at: new Date().toISOString().slice(0, 10),
    scope_hash: scope, sources, file_count: files.length, files,
    findings: kept, dropped, rounds, finalPass: true,
  }, null, 2) + "\n");
  renderProjection(slug, JSON.parse(readFileSync(archivePath, "utf8")));
  return { slug, kept: kept.length, dropped: dropped.length, unverified };
}

let idx = 0;
const results: Awaited<ReturnType<typeof auditOne>>[] = [];
async function worker(id: number) {
  while (idx < slugs.length) {
    const slug = slugs[idx++];
    const t0 = Date.now();
    try {
      const r = await auditOne(slug);
      results.push(r);
      console.log(`[w${id}] ${slug}: ${r.skipped ? "跳过" : r.failed ? `失败（${r.failed}）` : `${r.kept} findings（丢 ${r.dropped}，未核实 ${r.unverified}）`} ${Math.round((Date.now() - t0) / 1000)}s`);
    } catch (e: any) {
      results.push({ slug, kept: 0, dropped: 0, unverified: 0, failed: e?.message ?? String(e) });
      console.log(`[w${id}] ${slug}: 异常 — ${e?.message ?? e}`);
    }
  }
}
await Promise.all(Array.from({ length: Math.min(CONC, slugs.length) }, (_, i) => worker(i + 1)));
const failed = results.filter(r => r.failed);
console.log(`\n[audit] ${results.length} 个单元：${results.filter(r => !r.failed && !r.skipped).length} 审完，${results.filter(r => r.skipped).length} 跳过，${failed.length} 失败`);
for (const f of failed) console.log(`  ✗ ${f.slug}: ${f.failed}`);
process.exit(failed.length ? 1 : 0);
