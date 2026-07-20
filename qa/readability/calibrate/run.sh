#!/bin/bash
# grok 盲读批：对 .work/prompts/p<pass>-b<nn>.md 逐批调用 headless agent。
# 断点续跑：已有非空输出的批次自动跳过。env: CALIB_WORK, AGENT (default grok), ONLY_BATCHES（调试限量）
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${CALIB_WORK:-$HERE/.work}"
AGENT="${AGENT:-grok}"
cd "$(mktemp -d)"   # 空 cwd：结构性无码权限，盲读
for pf in "$WORK"/prompts/p*-b*.md; do
  b=$(basename "$pf" .md)
  pass=$(echo "$b" | sed 's/-.*//')
  out="$WORK/out-$pass/$b.json"
  mkdir -p "$WORK/out-$pass"
  [ -s "$out" ] && continue
  [ -n "${ONLY_BATCHES:-}" ] && [ "$(ls "$WORK/out-$pass" | wc -l)" -ge "$ONLY_BATCHES" ] && continue
  echo "[$(date +%H:%M:%S)] $b"
  "$AGENT" --prompt-file "$pf" --no-memory --disable-web-search --no-subagents \
    --max-turns 1 --output-format json > "$out" 2>>"$WORK/agent-err.log"
done
echo DONE
