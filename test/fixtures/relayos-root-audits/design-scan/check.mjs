#!/usr/bin/env node
// Fixture stand-in for the read-only design-scan drift/coverage check.
// Reports files whose content changed since they were scanned (stale) and
// scanned files that no longer exist (missing).
import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const ledger = JSON.parse(readFileSync(join(here, "ledger.json"), "utf8"));

const blobHash = (path) =>
  execFileSync("git", ["hash-object", path], { cwd: repoRoot }).toString().trim();

const stale = [];
const missing = [];
for (const entry of ledger.scans) {
  const abs = join(repoRoot, entry.path);
  if (!existsSync(abs)) missing.push(entry.path);
  else if (blobHash(entry.path) !== entry.git_blob_sha1) stale.push(entry.path);
}
console.log(`design-scan ledger: ${ledger.scans.length} files`);
for (const p of stale) console.log(`   stale - ${p}`);
for (const p of missing) console.log(`   missing - ${p}`);
process.exit(stale.length || missing.length ? 1 : 0);
