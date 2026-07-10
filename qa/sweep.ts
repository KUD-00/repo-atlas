#!/usr/bin/env bun
/**
 * QA sweep 驱动：对一批路径反复跑 run.ts 直到全过或零进展。在目标仓库里跑：
 *   cd <你的仓库> && bun <repo-atlas>/qa/sweep.ts --file 路径清单.txt [选项]
 *   cd <你的仓库> && bun <repo-atlas>/qa/sweep.ts <repo路径...> [选项]
 *
 * 选项：
 *   --iters N        最多迭代几轮（默认 4）
 *   --concurrency N  run.ts 的并发（默认 12；agent 调用是网络密集型，CPU 有余量可开大）
 *   --readers N      每篇盲读者数（默认走 rubric）
 *   --fresh          先删这批路径的 QA 档案，强制全部重跑（默认 resume-skip：已过门的跳过）
 *   --no-mapify      不做结构性地图化（默认开）
 *
 * 行为：每轮 = run.ts <paths> --mapify --revise --stamp；轮后统计 finalPass；
 * 全过 → 停；相比上一轮零进展 → 停（剩下的通常需要人工看）。
 * 日志与状态落在 <仓库>/.atlas/qa/_sweep/（在仓库内，不会被 /tmp 清理器回收）。
 * 断点续跑：进程死掉直接重跑同一命令即可——resume-skip 会跳过已过门的。
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync, appendFileSync } from "node:fs";
import { join, dirname } from "node:path";

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
const QA = new URL(".", import.meta.url).pathname.replace(/\/$/, "");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(`--${n}`);
const optNum = (n: string, d: number) => { const i = args.indexOf(`--${n}`); return i >= 0 ? Number(args[i + 1]) : d; };
const optStr = (n: string) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : null; };
const NUM_OPTS = new Set(["iters", "concurrency", "readers", "file"]);
const ITERS = optNum("iters", 4);
const CONC = optNum("concurrency", 12);
const READERS = optNum("readers", 0);
const FRESH = flag("fresh");
const MAPIFY = !flag("no-mapify");
const listFile = optStr("file");

let paths: string[] = [];
if (listFile) paths = readFileSync(listFile, "utf8").split("\n").map(s => s.trim()).filter(Boolean);
else paths = args.filter((a, i) => !a.startsWith("--") && !NUM_OPTS.has(args[i - 1]?.replace("--", "") ?? ""));
if (!paths.length) {
  console.error("usage: cd <目标仓库> && bun sweep.ts (--file 清单.txt | <repo路径...>) [--iters 4] [--concurrency 12] [--readers N] [--fresh] [--no-mapify]");
  process.exit(2);
}

const OUT = join(REPO, ".atlas/qa/_sweep");
mkdirSync(OUT, { recursive: true });
const STATUS = join(OUT, "STATUS.txt");
const log = (s: string) => { console.log(s); appendFileSync(STATUS, s + "\n"); };

function count(): { pass: number; fail: number; missing: number; failList: string[] } {
  let pass = 0, fail = 0, missing = 0; const failList: string[] = [];
  for (const p of paths) {
    const qa = join(REPO, ".atlas/qa", p + ".json");
    if (!existsSync(qa)) { missing++; failList.push(p + " (未跑)"); continue; }
    try {
      const r = JSON.parse(readFileSync(qa, "utf8"));
      if (r.finalPass) pass++; else { fail++; failList.push(p + " :: " + (r.rounds?.at(-1)?.gate?.reasons?.join("；") ?? "?")); }
    } catch { fail++; failList.push(p + " (档案损坏)"); }
  }
  return { pass, fail, missing, failList };
}

if (FRESH) {
  let n = 0;
  for (const p of paths) { const qa = join(REPO, ".atlas/qa", p + ".json"); if (existsSync(qa)) { rmSync(qa); n++; } }
  console.log(`--fresh：清了 ${n} 个 QA 档案`);
}

writeFileSync(STATUS, `sweep 开始 ${new Date().toISOString()} 共 ${paths.length} 篇（iters≤${ITERS}, c=${CONC}${FRESH ? ", fresh" : ", resume-skip"}）\n`);
let prev = -1;
for (let it = 1; it <= ITERS; it++) {
  log(`=== ITER ${it} ${new Date().toISOString()} ===`);
  const cmd = ["bun", join(QA, "run.ts"), ...paths, "--revise", "--stamp", "--concurrency", String(CONC)];
  if (MAPIFY) cmd.push("--mapify");
  if (READERS > 0) cmd.push("--readers", String(READERS));
  const proc = Bun.spawnSync(cmd, { cwd: REPO, stdout: "pipe", stderr: "pipe" });
  writeFileSync(join(OUT, `iter-${it}.log`), new TextDecoder().decode(proc.stdout) + "\n--- stderr ---\n" + new TextDecoder().decode(proc.stderr));
  const c = count();
  log(`ITER ${it} -> PASS=${c.pass} FAIL=${c.fail} MISSING=${c.missing} TOTAL=${paths.length}`);
  if (c.pass >= paths.length) { log("全过 ✅"); break; }
  if (c.pass <= prev) { log("零进展停（剩下的通常需要人工看）"); break; }
  prev = c.pass;
}
const final = count();
log(`结束 ${new Date().toISOString()}：PASS=${final.pass}/${paths.length}`);
for (const f of final.failList) log("  ✗ " + f);
process.exit(final.pass === paths.length ? 0 : 1);
