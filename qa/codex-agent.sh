#!/usr/bin/env bash
# codex-agent.sh — grok 参数面 → `codex exec` 适配器，给 ATLAS_QA_AGENT 用。
#
#   ATLAS_QA_AGENT=<repo-atlas>/qa/codex-agent.sh bun qa/sweep.ts ...
#
# 环境变量：
#   CODEX_QA_MODEL   默认 gpt-5.3-codex-spark
#   CODEX_QA_EFFORT  默认 xhigh（用户指定；spark 只接受 none|minimal|low|medium|high|xhigh，
#                    全局 config.toml 里的 "max" 会 400，必须在这里覆盖）
#
# 参数映射（引擎侧形状见 qa/lib.ts runAgent）：
#   --prompt-file <f>        → stdin 喂给 codex exec
#   --json-schema <内联JSON> → 追加进 prompt 让模型直接产 JSON（不能用 --output-schema：
#                              codex 走 OpenAI strict 模式，要求每层 additionalProperties:false
#                              + required 全列，引擎的 grok 风格 schema 过不了 400）
#   --disallowed-tools <..>  → 含写工具 → -s read-only；否则 -s workspace-write
#   --no-memory              → --ephemeral
#   --max-turns / --output-format / --always-approve / --disable-web-search /
#   --no-subagents           → 无对应件或默认已满足，吞掉（超时由引擎侧 kill 兜底）
# 输出：stdout 打 grok json 形状 {text, structuredOutput}，lenientParse 可解。
set -euo pipefail

MODEL="${CODEX_QA_MODEL:-gpt-5.3-codex-spark}"
EFFORT="${CODEX_QA_EFFORT:-xhigh}"
PROMPT_FILE="" SCHEMA="" DISALLOWED=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prompt-file)       PROMPT_FILE="$2"; shift 2 ;;
    --json-schema)       SCHEMA="$2";      shift 2 ;;
    --disallowed-tools)  DISALLOWED="$2";  shift 2 ;;
    --max-turns)         shift 2 ;;
    --output-format)     shift 2 ;;
    *)                   shift ;;
  esac
done
[[ -n "$PROMPT_FILE" && -r "$PROMPT_FILE" ]] || { echo '{"text":"codex-agent: missing --prompt-file","structuredOutput":null}'; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/codex-agent-XXXXXX")
trap 'rm -rf "$TMP"' EXIT

ARGS=(exec -m "$MODEL"
  -c "model_reasoning_effort=\"$EFFORT\""
  -c 'approval_policy="never"'
  --ephemeral --skip-git-repo-check --ignore-rules --ignore-user-config
  --disable multi_agent
  --color never -o "$TMP/last.txt")

# 盲读/事实核查禁写 → read-only 沙箱；writer/reviser 要落笔记 → workspace-write
if [[ "$DISALLOWED" == *write* || "$DISALLOWED" == *apply_patch* ]]; then
  ARGS+=(-s read-only)
else
  ARGS+=(-s workspace-write)
fi

cp "$PROMPT_FILE" "$TMP/prompt.md"
if [[ -n "$SCHEMA" ]]; then
  {
    printf '\n\n## 输出格式（硬性）\n\n最终回复必须是且仅是一个 JSON 对象（不带 markdown 代码围栏），严格符合以下 JSON Schema：\n\n'
    printf '%s\n' "$SCHEMA"
  } >> "$TMP/prompt.md"
fi

codex "${ARGS[@]}" - < "$TMP/prompt.md" >"$TMP/events.log" 2>&1 || true

# 编成引擎认的形状；structuredOutput = 最终消息若是合法 JSON（含剥代码围栏后）
if [[ -s "$TMP/last.txt" ]]; then
  sed -e 's/^```json$//' -e 's/^```$//' "$TMP/last.txt" \
    | jq -Rs '{text: ., structuredOutput: (. as $t | try ($t | fromjson) catch null)}'
else
  tail -c 2000 "$TMP/events.log" | jq -Rs '{text: ("codex-agent: empty last message; events tail: " + .), structuredOutput: null}'
fi
