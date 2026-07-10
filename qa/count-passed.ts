#!/usr/bin/env bun
// 统计 QA 档案（.atlas/qa/<path>.json）里 finalPass 的分布。在目标仓库里跑：
//   bun <repo-atlas>/qa/count-passed.ts <路径清单文件> [--list]
import { readFileSync, existsSync } from "node:fs";
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
const listFile = process.argv[2];
if (!listFile) { console.error("usage: bun count-passed.ts <路径清单文件> [--list]"); process.exit(2); }
const paths = readFileSync(listFile, "utf8").split("\n").map(s => s.trim()).filter(Boolean);
let pass = 0, fail = 0, missing = 0;
const failList: string[] = [];
for (const p of paths) {
  const qa = join(REPO, ".atlas/qa", p + ".json");
  if (!existsSync(qa)) { missing++; failList.push(p + " (未跑)"); continue; }
  try {
    const r = JSON.parse(readFileSync(qa, "utf8"));
    if (r.finalPass) pass++; else { fail++; failList.push(p + " :: " + (r.rounds?.at(-1)?.gate?.reasons?.join("；") ?? "?")); }
  } catch { fail++; failList.push(p + " (档案损坏)"); }
}
console.log(`PASS=${pass} FAIL=${fail} MISSING=${missing} TOTAL=${paths.length}`);
if (process.argv[3] === "--list") failList.forEach(f => console.log("  ✗ " + f));
