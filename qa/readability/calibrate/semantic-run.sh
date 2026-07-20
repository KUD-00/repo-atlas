#!/bin/bash
# 语义校准批：对抽样文件跑 N 遍 semantic.ts（默认 2 遍），断点续跑。
#   cd <目标仓库> && bash semantic-run.sh [passes]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${ATLAS_SEMANTIC_OUT:-$(node "$HERE/semantic-workspace.mjs")}"
QA="$(cd "$HERE/.." && pwd)"
PASSES="${1:-2}"
case "$PASSES" in
  ''|*[!0-9]*) echo "passes must be a positive integer" >&2; exit 2 ;;
esac
[ "$PASSES" -ge 1 ] || { echo "passes must be a positive integer" >&2; exit 2; }
node "$HERE/semantic-manifest.mjs" "$OUT/manifest.json" "$OUT/files.json"
SAMPLE_HASH="$(node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).sampleHash)" "$OUT/manifest.json")"
EXPECTED_COUNT="$(node -e "process.stdout.write(String(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')).files.length))" "$OUT/manifest.json")"
for pass in $(seq 1 "$PASSES"); do
  mkdir -p "$OUT/pass$pass"
  i=0
  while IFS= read -r -d '' f; do
    i=$((i + 1))
    EXPECTED_SOURCE_HASH="$(node -e "const m=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')); const h=m.fileHashes[process.argv[2]]; if (!h) process.exit(1); process.stdout.write(h)" "$OUT/manifest.json" "$f")"
    out="$OUT/pass$pass/$(printf %02d "$i").json"
    if [ -s "$out" ]; then
      if node "$HERE/semantic-result.mjs" "$out" "$f" "$OUT/manifest.json"; then
        continue
      fi
      echo "discarding invalid semantic checkpoint: pass$pass $f" >&2
      rm -f "$out"
    fi
    echo "[$(date +%H:%M:%S)] pass$pass $f"
    log="$out.log"
    if ! ATLAS_SEMANTIC_SAMPLE_HASH="$SAMPLE_HASH" ATLAS_SEMANTIC_SOURCE_HASH="$EXPECTED_SOURCE_HASH" bun "$QA/semantic.ts" --out "$out" -- "$f" >"$log" 2>&1; then
      cat "$log" >&2
      echo "semantic evaluation failed: pass$pass $f" >&2
      rm -f "$out"
      exit 1
    fi
    if [ ! -s "$out" ]; then
      cat "$log" >&2
      echo "semantic evaluation produced no result: pass$pass $f" >&2
      exit 1
    fi
    if ! node "$HERE/semantic-result.mjs" "$out" "$f" "$OUT/manifest.json"; then
      cat "$log" >&2
      rm -f "$out"
      exit 1
    fi
    rm -f "$log"
  done < <(node -e "for (const file of JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))) process.stdout.write(file + '\\0')" "$OUT/files.json")
  if [ "$i" -ne "$EXPECTED_COUNT" ]; then
    echo "semantic calibration file stream incomplete: pass$pass processed $i/$EXPECTED_COUNT" >&2
    exit 1
  fi
done
echo DONE
