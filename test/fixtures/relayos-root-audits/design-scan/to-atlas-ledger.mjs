#!/usr/bin/env node
/**
 * Fixture stand-in for the one-shot migration: design-scan round 1 →
 * `.atlas/audits/design-fixture-layer.json` in `atlas-audit-v2` with
 * `domain: "design"`.
 *
 * Every prose field (evidence, fix) is copied VERBATIM out of findings.md, so
 * the migration cannot paraphrase the verdicts. Scan-time `git_blob_sha1`
 * values are preserved as the ledger's `hashes`.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const HERE = path.dirname(new URL(import.meta.url).pathname);
const SLUG = "design-fixture-layer";

const legacy = JSON.parse(fs.readFileSync(path.join(HERE, "ledger.json"), "utf8"));
const files = legacy.scans.map((scan) => scan.path).sort();
const hashes = Object.fromEntries(
  legacy.scans.map((scan) => [scan.path, scan.git_blob_sha1]),
);
const scopeHash = createHash("sha1")
  .update(files.map((file) => `${hashes[file]}  ${file}`).sort().join("\n") + "\n")
  .digest("hex");

console.log(`${SLUG}: scope ${files.length} files, hash ${scopeHash}`);
