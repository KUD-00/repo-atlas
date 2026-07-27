#!/usr/bin/env bun
/**
 * 设计合理性审计（judgment 层）：对一批源码文件问"这是不是它要表达的东西的最简
 * 正确形状"，逐条过只读 factcheck 门，落 `.atlas/audits/<slug>.json`
 * （`atlas-audit-v2`, domain=design）机器账，并把 finding 投影成
 * `.atlas/artifacts/<被点名的文件>/<slug>.md` 给人看。
 *
 *   cd <目标仓库> && bun <repo-atlas>/qa/design.ts <slug...|--all> [--concurrency 2] [--fresh]
 *   cd <目标仓库> && bun <repo-atlas>/qa/design.ts --slug <slug> --scope <path...>   # 一次性
 *
 * 单元清单是仓库自有内容：`.atlas/pipeline/design-units.json`
 *   [{ "slug": "design-type-contract-layer", "title": "类型与契约层",
 *      "scope": ["packages/protocols/runtime-types/src", "..."] }]
 *
 * 与 audit.ts（security）同属旁挂 LLM 套件，共用 lib.ts 机制。两处刻意的差别：
 *   · 审计单元是**路径集合**而非概念页——设计缺陷住在模块的形状里，不在信任边界上。
 *   · 机械可判定的那半边不在这里：`repo-atlas quality` 用零误差检测器扫 import 环、
 *     分层违规、陈旧 marker、type-escape 计数、`?:`/`| null` 混用、布尔陷阱。
 *     prompt 明确要求 agent 不要重复报这些。
 *
 * 不用 --json-schema：实测它会令 agent 概率性跳过工具调用直接编答案（2026-07-19 探针）。
 * 改用 prompt 内嵌 JSON 契约 + lenientParse 兜底 + agentToolCounts 工具证据硬门。
 *
 * 失败绝不落成"已完成的评审"：解析失败/证据不足时写 reviewState="in-progress" 的档案，
 * engine 会把它报成 invalid（status 里可见），永远不会被当成一次 review 计入。
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";
import {
  findRepoRoot, runAgent, lenientParse, loadPrompt,
  DENY_ALL_WRITES, assertOnlyAtlasWrites, agentToolCounts, dirtyPaths,
} from "./lib.ts";

const REPO = findRepoRoot();
const QA = new URL(".", import.meta.url).pathname.replace(/\/$/, "");
const RULESET_ID = "atlas-designscan-v1"; // 规则正文 = prompts/design.md（仓库可 .atlas/pipeline 整替/追加）

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(`--${n}`);
const optStr = (n: string): string | null => { const i = args.indexOf(`--${n}`); return i >= 0 ? (args[i + 1] ?? null) : null; };
const optNum = (n: string, d: number) => { const i = args.indexOf(`--${n}`); return i >= 0 ? Number(args[i + 1]) : d; };
const optList = (n: string): string[] => {
  const i = args.indexOf(`--${n}`);
  if (i < 0) return [];
  const out: string[] = [];
  for (let j = i + 1; j < args.length && !args[j].startsWith("--"); j++) out.push(args[j]);
  return out;
};

const CONC = optNum("concurrency", 2);
const FRESH = flag("fresh");
const ALL = flag("all");

const SEV = ["low", "medium", "high"] as const;
const CATEGORIES = new Set([
  "optionality", "absence-semantics", "boolean-trap", "type-escape",
  "over-abstraction", "layering-violation", "duplicate-logic", "dead-code",
  "redundant-fields", "over-complication", "first-principles",
  "masking-default", "swallowed-failure", "magic-constant",
  "dead-forward-compat", "compat-shim", "stale-marker",
  "naming-drift", "unexplained-export",
]);

type Finding = {
  severity: string; category: string; title: string; locations: string[];
  evidence: string; fix: string; confidence?: string; disposition?: string;
};
interface Unit { slug: string; title: string; scope: string[] }

// ---------- 单元清单 ----------
const UNITS_FILE = join(REPO, ".atlas/pipeline/design-units.json");

function loadUnits(): Unit[] {
  if (!existsSync(UNITS_FILE)) return [];
  const raw = JSON.parse(readFileSync(UNITS_FILE, "utf8"));
  if (!Array.isArray(raw)) throw new Error("design-units.json 必须是数组");
  return raw.map((u: any, i: number) => {
    if (!u || typeof u.slug !== "string" || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(u.slug)) {
      throw new Error(`design-units.json[${i}]: slug 必须是小写 kebab（要进 audit:<domain>/<slug> 路由）`);
    }
    if (!Array.isArray(u.scope) || !u.scope.length || !u.scope.every((s: any) => typeof s === "string" && s)) {
      throw new Error(`design-units.json[${i}] (${u.slug}): scope 必须是非空字符串数组`);
    }
    return { slug: u.slug, title: typeof u.title === "string" && u.title.trim() ? u.title : u.slug, scope: u.scope };
  });
}

function selectUnits(): Unit[] {
  const adHocSlug = optStr("slug");
  const adHocScope = optList("scope");
  if (adHocSlug || adHocScope.length) {
    if (!adHocSlug || !adHocScope.length) throw new Error("--slug 与 --scope 必须同时给出");
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(adHocSlug)) throw new Error("--slug 必须是小写 kebab");
    return [{ slug: adHocSlug, title: optStr("title") ?? adHocSlug, scope: adHocScope }];
  }
  const units = loadUnits();
  if (ALL) return units;
  const wanted = args.filter(a => !a.startsWith("--") && a !== String(CONC));
  if (!wanted.length) return [];
  const bySlug = new Map(units.map(u => [u.slug, u]));
  return wanted.map(slug => {
    const unit = bySlug.get(slug);
    if (!unit) throw new Error(`未知单元 ${slug}——加进 .atlas/pipeline/design-units.json，或用 --slug/--scope 跑一次性审计`);
    return unit;
  });
}

let units: Unit[];
try {
  units = selectUnits();
} catch (e: any) {
  console.error(e?.message ?? String(e));
  process.exit(2);
}
if (!units.length) {
  console.error("usage: cd <目标仓库> && bun design.ts <slug...|--all> [--concurrency 2] [--fresh]");
  console.error("       cd <目标仓库> && bun design.ts --slug <slug> --scope <path...> [--title <t>]");
  console.error(`单元清单：${UNITS_FILE}`);
  process.exit(2);
}

// ---------- scope → 文件清单（测试/fixture/二进制不是设计面） ----------
const SKIP = /(__tests__|\.test\.|\.spec\.|fixture|\.png$|\.jpe?g$|\.gif$|\.webp$|\.lock$|\.bin$|\.wasm$|\.pdf$|\.map$|\.snap$)/i;
function enumerateFiles(scope: string[]): string[] {
  const out = new Set<string>();
  for (const src of scope) {
    const r = Bun.spawnSync(["git", "ls-files", "--", src], { cwd: REPO });
    if (!r.exitCode && r.stdout) {
      for (const p of new TextDecoder().decode(r.stdout).split("\n").filter(Boolean)) {
        if (!SKIP.test(p)) out.add(p);
      }
    }
  }
  return [...out].sort();
}

/** scope 指纹 + 逐文件 hash：sorted "blobSha  path" 行的 sha1（与 engine 同算法）。 */
function hashScope(files: string[]): { hash: string; hashes: Record<string, string> } {
  const r = Bun.spawnSync(["git", "hash-object", "--", ...files], { cwd: REPO });
  if (r.exitCode) throw new Error("git hash-object 失败");
  const shas = new TextDecoder().decode(r.stdout).split("\n").filter(Boolean);
  if (shas.length !== files.length) throw new Error(`git hash-object 返回 ${shas.length} 个 hash，期望 ${files.length}`);
  const hashes: Record<string, string> = {};
  files.forEach((f, i) => { hashes[f] = shas[i]; });
  const lines = files.map(f => `${hashes[f]}  ${f}`).sort();
  return { hash: createHash("sha1").update(lines.join("\n") + "\n").digest("hex"), hashes };
}

// ---------- 输出校验：形状不合的整条丢掉并记账，绝不静默纠正 ----------
function partitionFindings(x: any, files: Set<string>): { valid: Finding[]; rejected: { finding: any; reason: string }[] } {
  const valid: Finding[] = [];
  const rejected: { finding: any; reason: string }[] = [];
  for (const f of Array.isArray(x?.findings) ? x.findings : []) {
    const reason = findingShapeError(f, files);
    if (reason) rejected.push({ finding: f, reason });
    else valid.push({
      severity: f.severity, category: f.category, title: f.title.trim(),
      locations: normalizeLocations(f.locations as string[], files),
      evidence: f.evidence.trim(), fix: f.fix.trim(), disposition: "open",
    });
  }
  return { valid, rejected };
}

/** `path` · `path:12` · `path:12-19`（范围归一成起始行）· `path#symbol`。 */
const LOCATION_RE = /^([^:#]+)(?::(\d+)(?:-\d+)?|#(.+))?$/;

function locationPath(loc: string): string | null {
  return LOCATION_RE.exec(loc.trim())?.[1] ?? null;
}

/**
 * 一条契约层 finding **天生跨两个文件**：spec 在被审单元里，证明它成立的 handler
 * 在外面。所以规则是「**至少一个** location 落在单元内」，不是「全部都在」——后者
 * 会把"这个字段 handler 从不读"这类最有价值的 finding 全杀掉（实测 9 条里 8 条）。
 * 范围外的 location 是**证据引用**，不是对那个文件当前状态的断言：账本的字节绑定
 * 只覆盖单元内的文件，所以卡片也只落在单元内的页面上。
 */
function findingShapeError(f: any, files: Set<string>): string | null {
  if (!f || typeof f !== "object") return "不是对象";
  if (!SEV.includes(f.severity)) return `severity 必须是 low|medium|high（得到 ${JSON.stringify(f.severity)}）`;
  if (typeof f.category !== "string" || !CATEGORIES.has(f.category)) return `未知 category ${JSON.stringify(f.category)}`;
  for (const key of ["title", "evidence", "fix"]) {
    if (typeof f[key] !== "string" || !f[key].trim()) return `${key} 必须是非空字符串`;
  }
  if (!Array.isArray(f.locations) || !f.locations.length) return "locations 必须非空";
  let inScope = 0;
  for (const loc of f.locations) {
    if (typeof loc !== "string" || !loc.trim()) return "locations 只能是非空字符串";
    const m = LOCATION_RE.exec(loc.trim());
    if (!m) return `location 格式非法：${loc}`;
    if (m[2] !== undefined && !/^[1-9]\d*$/.test(m[2])) return `行号必须是正整数：${loc}`;
    if (files.has(m[1])) inScope++;
  }
  if (!inScope) {
    return `没有任何 location 落在审计范围内（finding 必须归属被审单元）：${f.locations.join(", ")}`;
  }
  return null;
}

/** 单元内的 location 排前（主位置决定卡片落哪页），行范围归一成起始行。 */
function normalizeLocations(locations: string[], files: Set<string>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of locations) {
    const m = LOCATION_RE.exec(raw.trim());
    if (!m) continue;
    const normalized = m[2] !== undefined ? `${m[1]}:${m[2]}` : m[3] !== undefined ? `${m[1]}#${m[3]}` : m[1];
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out.sort((left, right) =>
    Number(files.has(locationPath(right)!)) - Number(files.has(locationPath(left)!)));
}

/** 幻觉守门：要求读过码的阶段必须真的调过读类工具。 */
function assertReadEvidence(sessionId: string | undefined, minReads: number, label: string): void {
  if (!sessionId) throw new Error(`${label}：无 sessionId，无法核工具证据`);
  const t = agentToolCounts(REPO, sessionId);
  if (!t) throw new Error(`${label}：transcript 不可得，无法核工具证据`);
  if (t.reads < minReads) {
    throw new Error(`${label}：工具证据不足（读类调用 ${t.reads} 次 < ${minReads}）——按幻觉处理，整轮作废`);
  }
}

const ARCHIVE_DIR = join(REPO, ".atlas/audits");
mkdirSync(ARCHIVE_DIR, { recursive: true });

// ---------- viewer 投影 ----------
// 设计域没有 portfolio 页（engine 刻意不给它 unit 投影），读者在**被点名的那个文件的页面**
// 侧栏遇到它。卡片按 slug 命名，所以多个单元点到同一文件也不会互相覆盖，且能按单元清理。
function locMd(loc: string): string {
  const m = loc.match(/^([^:#]+)([:#].*)$/);
  return m ? `\`${m[1]}\`${m[2]}` : `\`${loc}\``;
}

function renderProjection(unit: Unit, ledger: any): number {
  const card = `${unit.slug}.md`; // 卡片按单元命名：多个单元点到同一文件不互相覆盖，也能按单元清理
  // 只给单元内的页面出卡片：账本的字节绑定只覆盖这些文件，范围外的 location 是证据引用。
  const inScope = new Set<string>(ledger.files ?? []);
  const byPath = new Map<string, Finding[]>();
  for (const f of ledger.findings ?? []) {
    for (const p of new Set(f.locations.map((l: string) => l.replace(/[:#].*$/, "")))) {
      if (!inScope.has(p as string)) continue;
      if (!byPath.has(p as string)) byPath.set(p as string, []);
      byPath.get(p as string)!.push(f);
    }
  }
  // 先清掉本单元上一轮留下的卡片（findings 可能已消失）
  const base = join(REPO, ".atlas/artifacts");
  if (existsSync(base)) {
    const walk = (dir: string) => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, e.name);
        if (e.isDirectory()) walk(full);
        else if (e.name === card) rmSync(full);
      }
    };
    walk(base);
  }
  let written = 0;
  for (const [p, fs] of byPath) {
    const dir = join(base, p);
    mkdirSync(dir, { recursive: true });
    const L: string[] = [];
    L.push(`# 设计合理性 · ${ledger.title}`, "");
    L.push(`判断类审计（ruleset \`${ledger.ruleset}\`，${ledger.scanned_at}）。只报告，不改代码——每条修法都是要人拍板的取舍。`, "");
    for (const sev of ["high", "medium", "low"]) {
      const group = fs.filter(f => f.severity === sev);
      if (!group.length) continue;
      L.push(`## ${sev.toUpperCase()}`, "");
      for (const f of group) {
        L.push(`### ${f.title}${f.confidence === "unverified" ? "（⚠ 未核实）" : ""}`, "");
        L.push(`- **类目**：\`${f.category}\``);
        L.push(`- **位置**：${f.locations.map(locMd).join("、")}`);
        L.push(`- **证据**：${f.evidence}`);
        L.push(`- **修法**：${f.fix}`, "");
      }
    }
    L.push("---", "", `机器档案：\`.atlas/audits/${unit.slug}.json\`（逐轮历史 + scope 字节绑定）`, "");
    writeFileSync(join(dir, card), L.join("\n"));
    written++;
  }
  return written;
}

/**
 * 记录一轮没跑完的审计。
 *
 * 硬规则：**绝不用一次失败覆盖掉一份仍然成立的评审**。若盘上已有针对当前字节的
 * complete 档案，那份结论依然为真——失败只该以退出码与日志汇报，不该把它降级。
 * 只有在没有档案、或档案已经对不上当前字节时，才落一份 in-progress 记录，让
 * `repo-atlas status` 把这个单元报成 invalid（而不是"零 finding 的干净单元"）。
 */
function writeIncomplete(unit: Unit, scope: { hash: string; hashes: Record<string, string> }, files: string[], error: string, tail?: string): void {
  const archivePath = join(ARCHIVE_DIR, `${unit.slug}.json`);
  if (existsSync(archivePath)) {
    try {
      const prev = JSON.parse(readFileSync(archivePath, "utf8"));
      if (prev.reviewState === "complete" && prev.scope_hash === scope.hash) {
        console.warn(`  ⚠ ${unit.slug}: 本轮失败（${error}）——盘上那份针对当前字节的评审仍然成立，保留不动`);
        return;
      }
    } catch { /* 档案损坏 → 照写 in-progress */ }
  }
  writeFileSync(archivePath, JSON.stringify({
    formatVersion: 2,
    format: "atlas-audit-v2",
    domain: "design",
    // 没跑完的一轮绝不冒充评审：engine 会把它报成 invalid，而不是"零 finding 的干净单元"。
    reviewState: "in-progress",
    slug: unit.slug,
    title: unit.title,
    ruleset: RULESET_ID,
    scanned_at: new Date().toISOString().slice(0, 10),
    scope_hash: scope.hash,
    file_count: files.length,
    files,
    hashes: scope.hashes,
    findings: [],
    error,
    ...(tail ? { raw_tail: tail } : {}),
  }, null, 2) + "\n");
}

async function auditOne(unit: Unit): Promise<{ slug: string; kept: number; dropped: number; unverified: number; rejected: number; cards?: number; skipped?: boolean; failed?: string }> {
  const files = enumerateFiles(unit.scope);
  if (!files.length) return { slug: unit.slug, kept: 0, dropped: 0, unverified: 0, rejected: 0, failed: "scope 下没有可审文件" };
  const scope = hashScope(files);
  const archivePath = join(ARCHIVE_DIR, `${unit.slug}.json`);
  if (!FRESH && existsSync(archivePath)) {
    try {
      const a = JSON.parse(readFileSync(archivePath, "utf8"));
      if (a.scope_hash === scope.hash && a.ruleset === RULESET_ID && a.reviewState === "complete") {
        renderProjection(unit, a); // 跳过也补渲染：投影可能缺失或档案是手工改的
        console.log(`[${unit.slug}] scope 未漂移且 ruleset 未变，跳过（--fresh 强制重审）`);
        return { slug: unit.slug, kept: a.findings?.length ?? 0, dropped: 0, unverified: 0, rejected: 0, skipped: true };
      }
    } catch { /* 档案损坏 → 重审 */ }
  }

  // 网关（工具证据 / 越界写）抛出的失败也要留痕：写一份 in-progress 记录，
  // 但 writeIncomplete 仍拒绝覆盖一份对当前字节仍然成立的 complete 评审。
  try {
    const before = dirtyPaths(REPO);
    const fileSet = new Set(files);
    const fileList = files.map(f => `- \`${f}\``).join("\n");
    const scopeList = unit.scope.map(s => `- \`${s}\``).join("\n");
    const auditInput = `${loadPrompt(QA, REPO, "design")}\n\n## 审计单元\n\n**${unit.title}**（slug \`${unit.slug}\`）\n\n声明的范围：\n\n${scopeList}\n\n## 文件清单（${files.length} 个，全部要读）\n\n${fileList}`;
    const auditOut = await runAgent(auditInput, {
      cwd: REPO, maxTurns: files.length * 3 + 40, disallowed: DENY_ALL_WRITES, timeoutMs: 25 * 60_000,
    });
    assertOnlyAtlasWrites(REPO, REPO, auditOut?.sessionId, before, `design(${unit.slug})`);
    assertReadEvidence(auditOut?.sessionId, files.length, `design(${unit.slug})`);

    const parsed = lenientParse(auditOut);
    if (!parsed || !Array.isArray(parsed.findings)) {
      writeIncomplete(unit, scope, files, "审计输出解析失败", String(auditOut?.text ?? "").slice(-2000));
      return { slug: unit.slug, kept: 0, dropped: 0, unverified: 0, rejected: 0, failed: "审计输出解析失败" };
    }
    const { valid: findings, rejected } = partitionFindings(parsed, fileSet);
    const barHeld = (Array.isArray(parsed.bar_held) ? parsed.bar_held : [])
      .filter((b: any) => b && typeof b.subject === "string" && typeof b.reason === "string")
      .map((b: any) => ({ subject: b.subject, reason: b.reason, outcome: "bar-held" }));

    let kept: Finding[] = findings;
    let dropped: { finding: Finding; reason: string }[] = [];
    let unverified = 0;
    if (findings.length) {
      const fcInput = `${loadPrompt(QA, REPO, "design-factcheck")}\n\n## 审计单元文件清单\n\n${fileList}\n\n## findings JSON\n\n${JSON.stringify(findings, null, 2)}`;
      const fcOut = await runAgent(fcInput, {
        cwd: REPO, maxTurns: findings.length * 12 + 30, disallowed: DENY_ALL_WRITES, timeoutMs: 20 * 60_000,
      });
      assertOnlyAtlasWrites(REPO, REPO, fcOut?.sessionId, before, `design-factcheck(${unit.slug})`);
      assertReadEvidence(fcOut?.sessionId, findings.length, `design-factcheck(${unit.slug})`);
      const fc = lenientParse(fcOut);
      if (!fc || !Array.isArray(fc.verdicts)) {
        writeIncomplete(unit, scope, files, "factcheck 输出解析失败", String(fcOut?.text ?? "").slice(-2000));
        return { slug: unit.slug, kept: 0, dropped: 0, unverified: 0, rejected: rejected.length, failed: "factcheck 输出解析失败" };
      }
      const byTitle = new Map(findings.map(f => [f.title, f]));
      kept = []; dropped = [];
      for (const v of fc.verdicts) {
        const f = byTitle.get(v.title);
        if (!f) continue;
        if (v.verdict === "unsupported") { dropped.push({ finding: f, reason: v.evidence ?? "核查未通过" }); continue; }
        if (v.verdict === "out-of-scope") { dropped.push({ finding: f, reason: `越域（${v.evidence ?? "属于其它审计域"}）` }); continue; }
        if (v.adjusted_severity && SEV.includes(v.adjusted_severity)) f.severity = v.adjusted_severity;
        if (v.verdict === "unverifiable") { f.confidence = "unverified"; unverified++; }
        kept.push(f);
      }
      // factcheck 漏判的 finding 按未核实保留（宁多勿丢）
      const judged = new Set(fc.verdicts.map((v: any) => v.title));
      for (const f of findings) {
        if (!judged.has(f.title)) { f.confidence = "unverified"; unverified++; kept.push(f); }
      }
    }

    const rank = (s: string) => SEV.indexOf(s as any);
    kept.sort((a, b) => rank(b.severity) - rank(a.severity) || a.category.localeCompare(b.category));
    const prev = existsSync(archivePath) ? (() => { try { return JSON.parse(readFileSync(archivePath, "utf8")); } catch { return null; } })() : null;
    const rounds = [...(prev?.rounds ?? []), {
      at: new Date().toISOString(), agent: process.env.ATLAS_QA_AGENT || "grok",
      audit_count: findings.length, kept: kept.length, dropped: dropped.length,
      rejected: rejected.length, unverified,
    }];
    const evidenceRefs = [".atlas/pipeline/design-units.json"].filter(p => existsSync(join(REPO, p)));

    const ledger = {
      formatVersion: 2,
      format: "atlas-audit-v2",
      domain: "design",
      reviewState: "complete",
      slug: unit.slug,
      title: unit.title,
      ruleset: RULESET_ID,
      scanned_at: new Date().toISOString().slice(0, 10),
      scope_hash: scope.hash,
      file_count: files.length,
      files,
      hashes: scope.hashes,
      ...(evidenceRefs.length ? { evidenceRefs } : {}),
      scope: unit.scope,
      findings: kept,
      dropped: [...dropped.map(d => ({ subject: d.finding.title, reason: d.reason, outcome: "factcheck-dropped" })), ...barHeld],
      rejected_shape: rejected.map(r => ({ reason: r.reason, title: r.finding?.title ?? null })),
      coverage_note: typeof parsed.coverage_note === "string" ? parsed.coverage_note : null,
      rounds,
    };
    writeFileSync(archivePath, JSON.stringify(ledger, null, 2) + "\n");
    const cards = renderProjection(unit, ledger);
    return { slug: unit.slug, kept: kept.length, dropped: dropped.length, unverified, rejected: rejected.length, cards };
  } catch (e: any) {
    const message = e?.message ?? String(e);
    writeIncomplete(unit, scope, files, message);
    return { slug: unit.slug, kept: 0, dropped: 0, unverified: 0, rejected: 0, failed: message };
  }
}

let idx = 0;
const results: Awaited<ReturnType<typeof auditOne>>[] = [];
async function worker(id: number) {
  while (idx < units.length) {
    const unit = units[idx++];
    const t0 = Date.now();
    try {
      const r = await auditOne(unit);
      results.push(r);
      const what = r.skipped ? "跳过"
        : r.failed ? `失败（${r.failed}）`
          : `${r.kept} findings（核查丢 ${r.dropped}，形状丢 ${r.rejected}，未核实 ${r.unverified}，卡片 ${r.cards}）`;
      console.log(`[w${id}] ${unit.slug}: ${what} ${Math.round((Date.now() - t0) / 1000)}s`);
    } catch (e: any) {
      results.push({ slug: unit.slug, kept: 0, dropped: 0, unverified: 0, rejected: 0, failed: e?.message ?? String(e) });
      console.log(`[w${id}] ${unit.slug}: 异常 — ${e?.message ?? e}`);
    }
  }
}
await Promise.all(Array.from({ length: Math.max(1, Math.min(CONC, units.length)) }, (_, i) => worker(i + 1)));

const failed = results.filter(r => r.failed);
console.log(`\n[design] ${results.length} 个单元：${results.filter(r => !r.failed && !r.skipped).length} 审完，${results.filter(r => r.skipped).length} 跳过，${failed.length} 失败`);
for (const f of failed) console.log(`  ✗ ${f.slug}: ${f.failed}`);
console.log(`\n复核：repo-atlas status（design 账本的 scope 漂移与 finding 漂移都在 audits 段）`);
process.exit(failed.length ? 1 : 0);
