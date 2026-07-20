# 代码可读性套件（readability）

对目标仓库的**代码本身**做「人类可读性」评估。设计与研究依据：`docs/readability-audit.md`。
校准后的分工（标注集实证，勿合并成单一分）：

| 层 | 工具 | 评什么 | 校准成绩 |
| --- | --- | --- | --- |
| 表面 | `repo-atlas readability [--top N] [--exclude glob] [--artifacts]`（src/readability.ts，LLM-free） | 行长/密度/注释率/熵的组合分 + 各单维 + barrel + 目录 rollup 的 repo 内离群 | 组合分 vs 人类 ρ≈0.51–0.69（660 片段留出；等权经 LGO 验证胜过拟合权重） |
| 语义 | `qa/readability/semantic.ts`（grok，维度限定） | 命名语义、注释-代码一致性、语言反模式、barrel 墙 | 机械层在这些维度 ρ≈0（词法统计无效）——正是它的补位 |

`--artifacts` 把离群文件/目录的可读性卡片写进 `.atlas/artifacts/<页>/readability.md`，
viewer 侧栏直接展示（stale 自动清理）；典型配方：
`repo-atlas readability --top 10 --exclude '**/locales/**' --exclude '**/*.d.ts' --artifacts --out .atlas/readability.json`

canonical `--out .atlas/readability.json` 同时写 `.atlas/audits/readability.json` 薄索引；
`repo-atlas status` 只读薄索引就能报告报告后改动/消失的文件，并保留上次运行的
added/removed 与 improved/worsened 精确总数（数组只保留 top-N 明细）。报告格式是
`repo-atlas-readability-v1`；不可用的 `commentCoherence` / `dupRatio` 明确为 `null`。
机械 `commentCoherence` 只比较每条注释与前后各 2 行标识符的词面重合；它是实验画像，
不进 `surfaceComposite`。

LLM 盲读 overall 总分已被校准否定（ρ=0.39，且稳定地偏语义、漏表面，见文档 §5 分歧案例）；
**禁止**把 semantic.ts 改成打 overall 分——要打表面分就用机械层。

## 用 semantic.ts

```sh
cd <你的仓库>
bun <repo-atlas>/qa/readability/semantic.ts apps/x/src/a.ts apps/x/src/b.ts --out .atlas/readability-semantic.json
```

输入是显式路径清单（典型来源：`repo-atlas readability --json` 里机械层完全无感的文件，
或人审想抽查的文件）。仓库可用 `.atlas/pipeline/readability-semantic{.md,.extra.md}` 覆盖/追加 prompt。

## 语义校准（calibrate/semantic-*）

```sh
cd <目标仓库>
node <repo-atlas>/qa/readability/calibrate/semantic-build.mjs     # 分层抽样 → manifest + worksheet
bash <repo-atlas>/qa/readability/calibrate/semantic-run.sh 2      # 每文件 ×2 pass（断点续跑）
node <repo-atlas>/qa/readability/calibrate/semantic-score.mjs     # inter-pass；有人标后再算 human ρ
```

工作区按 repo realpath + sample hash 隔离。runner 会把 manifest、每份结果和人工 labels 都绑定到
同一 sample/file SHA-256；score 还会重算当前源码，拒绝把旧 agent 结果与改动后的文件人工标签混评。
换 repo、重抽样或源码变化后，旧 checkpoint 不会复用。无论新结果还是
断点结果，都必须恰有一行、路径一致、字段完整、1–5 整数合法且无 `error`；evaluator 非零、超时、
空产出或畸形 JSON 都会立即失败，不会误报 DONE。score 要求每个 pass 完整覆盖 manifest，超过
两轮时报告所有 pass pair；人工标注分别报告 naming 与 commentCoherence 的 exact/MAE/ρ。
2026-07-19 RelayOS 分层样本（18 文件 ×2 pass）的现状：naming exact agreement=77.8%、
MAE=0.22、ρ=0.553；comment coherence exact agreement=92.3%、MAE=0.08，但一轮全挤在
同一分数，ρ 因零方差不可定义。**这只是重测可靠性，不是人类对齐成绩**；
`semantic-labels.json` 尚未有人类标注前，不得把语义判官写成“已校准”。

## 复现校准（calibrate/）

```sh
bash qa/readability/calibrate/download.sh   # 拉 B&W/Dorn/Scalabrino 三套公开标注集 → .work/
node qa/readability/calibrate/build.mjs     # 解析 → snippets.json + mech-repo + 盲读 prompts
bash qa/readability/calibrate/run.sh        # grok 盲读批（断点续跑；调试先 ONLY_BATCHES=2）
node qa/readability/calibrate/score.mjs     # Spearman：机械层（含组合分）+ grok vs 人类均分
```

- 需要 bun（semantic.ts）与已构建的 `dist/cli.js`（score.mjs 跑机械层）。
- `.work/` 已 gitignore；数据集版权归原论文作者，仅用于研究复现。
- Dorn 数据集的「列 ↔ 排序片段序号」映射是反推的（build.mjs 头注释），
  依据：每片段评分数 ≈ 214、humanMean 分布 (1.3–4.4, mean≈3.25) 与论文一致。
- 2026-07-18 基线成绩（527 片段）：机械组合分 ALL ρ=0.541；grok overall ALL ρ=0.387、
  inter-pass ρ=0.826；分集合明细见 docs/readability-audit.md §5。
