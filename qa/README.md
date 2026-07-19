# atlas QA 流水线（LLM 套件）

给 `.atlas/notes/` 批量生成并验收笔记的 LLM 编排层。repo-atlas 内核（status/stamp/build/serve）**依旧不调 LLM**；本目录是旁挂的可选套件——想要"任意仓库跑出能过验收的 docs"，用这里。

在一个 ~200 篇笔记的真实仓库上打磨而成：所有门维度都来自"人读真实页面挑出的毛病 → 固化成规则"，不是凭空设计。

## 前提

- [bun](https://bun.sh)（引擎与驱动都是 bun 脚本）
- `grok` CLI（headless agent；`ATLAS_QA_AGENT` 可换成参数面兼容的其它 CLI：需支持 `--prompt-file/--json-schema/--disallowed-tools/--max-turns/--output-format json/--no-memory/--always-approve`）
- 目标仓库已初始化 atlas（有 `.atlas/config.json`；`repo-atlas status` 能跑）
- 本仓库已 `pnpm build`（stamp 走 `dist/cli.js`）
- 笔记语言为中文（长段落/顿号串/句读检测器按中文行文设计；英文仓库需覆盖 `run.ts` 里的阈值与正则后再用）

## 每篇笔记经历什么

```
缺笔记 → writer 从零写（同目录多篇合并成一批，共享上下文只发一次）
是墙/扁平枢纽 → mapify 结构性重排（拆 #### 小节、概览收短、机制下沉 callout）
轻路径 → 机械违规（长段/顿号串/元话术）先让 reviser 清掉，不烧盲读
QA 环（≤ revision_rounds_max 轮）：
  机械 lint → 盲读 ×N（空目录 cwd = 结构性无码权限）→ 共识汇总
  → 事实核查（有码只读，逐断言核对 + 给盲读复述判真伪）
  → rubric 门 → 不过则带着[共识句+低分节+unsupported+误导+机械违规]返工
keep-best：留最好一轮的正文（修订可能越改越差）；通过轮永远胜出
落档案 .atlas/qa/<path>.json（无论过没过）→ 过门且 --stamp 则 repo-atlas stamp
```

门维度（rubric.json 默认值，全部可覆盖）：共识读不懂句数、最差章节中位分、overall 中位、复述必须成立、具体度（枢纽页必须有端到端真实走查）、unsupported 断言=0、误导复述=0；外加机械硬门：长段落、平行枚举顿号串、元话术（"见文末"/受众标签）。

## 在一个新仓库上跑通（配方）

```sh
cd <你的仓库>
QA=<repo-atlas>/qa      # 本目录

# 0. bootstrap（清单别放 /tmp——长跑期间会被系统清理器回收，放仓库内或 ~/.cache）
repo-atlas init                   # 首次：建 .atlas/ + config.json（再编辑 exclude/basePoints）
repo-atlas status --json | jq -r '.missing[].path' > .atlas/qa/missing.txt
touch .atlas/glossary.md          # 可从空表起步；跨切术语随写随立
#（可选）放 .atlas/CONVENTIONS.md 与 .atlas/templates/default.md 覆盖出厂件

# 1. 标定（强烈建议）：挑一篇公认好的和一篇公认差的先各跑一遍，确认门判对
bun $QA/run.ts <好的路径> <差的路径> --readers 3
#   好的挂了 → 阈值太严，放 .atlas/pipeline/rubric.json 放宽；差的过了 → 收紧

# 2. 批量生成 + 验收 + 修订 + stamp（可整夜跑；断了重跑同一命令即续）
bun $QA/sweep.ts --file .atlas/qa/missing.txt --concurrency 12

# 3. 阅读顺序：给子项 ≥3 的目录页排 ①② 徽标（agent 提案 → 人扫一眼理由）
bun $QA/order.ts --dry          # 先看提案与理由
bun $QA/order.ts                # 认可后写入 frontmatter 的 order:（stamp 会保序）

# 4. 概念收敛：跨切概念 → 归属页讲全 + glossary 一行本质 + 别处瘦身指路
#    概念清单 .atlas/pipeline/concepts.json 是仓库自有内容（格式见 extract.ts 头注释）
bun $QA/extract.ts --all --dry   # 先看会触碰哪些页
bun $QA/extract.ts --all         # 执行；触碰过的页用 run.ts --revise --stamp --force 复验

# 5. 人审概念主页（必做，见下"门的边界"）

# 6. 代码演进后：只重扫过时的
repo-atlas status --json | jq -r '.outdated[].path' > .atlas/qa/outdated.txt
bun $QA/sweep.ts --file .atlas/qa/outdated.txt --fresh
```

## 仓库怎么定制（覆盖契约）

仓库侧一律放 `.atlas/pipeline/`，引擎按此解析：

| 文件 | 作用 |
| --- | --- |
| `<writer\|reader\|factcheck\|reviser\|mapify>.md` | 整体**替换**同名出厂 prompt |
| `<名字>.extra.md` | **追加**在出厂 prompt 尾部（放仓库专属规则，推荐用这个而不是整替） |
| `rubric.json` | 与出厂 rubric **合并**（顶层 + consensus/gates.reader/gates.factcheck 两层） |
| `reader-schema.json` / `factcheck-schema.json` | 整体替换出厂 schema |
| `concepts.json` | `extract.ts` 的概念清单（含 `includeRoots` 搜索范围），纯仓库内容 |
| `concept-pages.json` | `concept.ts` 的概念页**课程表**（数组顺序=阅读顺序；每页 slug/title/audience/sources/brief + 可选 `requires` 前置页、`owns` 独占范围），纯仓库内容 |
| `distill.json` | `distill.ts` 的蒸馏配置(defaults: 时长/画幅/风格/旁白与 prompt 语言;targets: slug/时长/侧重),纯仓库内容 |
| `concept-<writer\|reader\|factcheck>.md` / `.extra.md` | 概念页三阶段的 prompt 覆盖/追加（与路径笔记同一契约） |
| `audit.md` / `audit-factcheck.md` / `.extra.md` | 概念级安全审计两阶段的 prompt 覆盖/追加（ruleset 与定标放这里，见"概念级安全审计"节） |

仓库自有内容（不属于引擎）：`.atlas/glossary.md`、`.atlas/CONVENTIONS.md`、`.atlas/templates/default.md`、`.atlas/qa/` 档案、`.atlas/audits/` 安全审计档案。

## 组合机制（文体如何共享与分叉）

共通核在 `qa/lib.ts`：禁令句式清单（单一来源）、可视化计数、agent 调用参数面、git 越界守卫、宽容 JSON 解析、prompt 三层加载（出厂 → 仓库整替 → `.extra.md` 追加）。

文体层各自持有：prompt 与门阈值。路径笔记（`run.ts`）的具体度=端到端代码走查、盲读 persona=第一天入职工程师；概念页（`concept.ts`）的具体度=贯穿的现实例子、persona 按 `audience` 切（general=不懂编程的运营）、核查允许受众级通俗化、可视化门更严。

仓库层对两种文体是同一契约：`.atlas/pipeline/<名字>.md` 整替、`<名字>.extra.md` 追加（概念页的名字是 `concept-writer` / `concept-reader` / `concept-factcheck`）。

已知债：`run.ts` 的禁令句式仍是自己的短清单（迁到 lib 的长清单会改变既有门行为，需要配合全量重验做，别静默换）。

## 概念级安全审计（audit.ts）

以概念页的 `sources` 为**审计单元**（信任边界）做只读安全审计：agent 拿概念页正文当「地图」审数据流（跨文件是一等公民），再对每个 finding 过独立 factcheck 门，档案落 `.atlas/audits/<slug>.json`。

```sh
cd <目标仓库>
bun $QA/audit.ts auth-identity           # 单个概念
bun $QA/audit.ts --all --concurrency 4   # 全部概念页
bun $QA/audit.ts auth-identity --fresh   # scope 没变也强制重审
```

- **审计单元 = `sources` 覆盖的文件集**（`git ls-files` 展开，测试/fixture/二进制排除）。跳过条件：scope 指纹（sorted `blobSha  path` 的 sha1）与 ruleset 都没变——字节级 drift 或换 ruleset 才重审，与笔记 stamp 无关。
- **两段式**：audit（`prompts/audit.md`：概念页当地图定位、逐文件读、追「不可信输入→危险汇聚点」数据流、按严重度定标）→ factcheck（`prompts/audit-factcheck.md`：逐条核位置/数据流/可达性三要素，`unsupported` 丢弃、`unverifiable` 标 `confidence:"unverified"` 保留、可纠正严重度）。LLM 安全扫描的头号问题是假阳性洪水，factcheck 门就是治它的——每个 finding 的滥用路径必须经独立只读核查才作数。
- **幻觉硬门**：两段都过 `agentToolCounts` 工具证据（audit 读类调用 ≥ 文件数，factcheck ≥ finding 数），输出形状再完美、没读过码也整轮作废。不用 `--json-schema`（见"编排上踩过的坑"）。
- **档案即历史**：`rounds[]` 每轮追加（审计要审计追踪，不像笔记 stamp 覆盖）；顶层 `findings` 是最新一轮。`dropped[]` 留被 factcheck 杀掉的 finding 及理由（校准复盘用）。
- **viewer 投影**：每轮（含跳过路径）把最新档案渲染成 `.atlas/artifacts/concepts/<slug>/security-audit.md`——概念页右侧 Artifacts tab 直接看，严重度分节、位置路径自动成链接、dropped 折叠。机器账（audits/）与人看投影（artifacts/）分离；投影是生成物，别手改。
- **定位（诚实条款）**：concept 级抓数据流级问题强（实测在 RelayOS auth-identity 上抓到文件级扫描 9 轮没抓到的跨 3 文件 medium），但会漏单文件校验类 low（实测漏 displayName 无上限、配额缺失）——**它不是文件级扫描的替代，是加深层**。完整覆盖 = concept 审计 + 残余文件扫（不在任何概念 sources 里的文件，或单文件维度）。

仓库定制沿用同一契约：`.atlas/pipeline/audit.md` 整替、`audit.extra.md` 追加（放仓库专属 ruleset/定标）；`audit-factcheck` 同理。

## 省 token（按 ROI 排序，多数已内建自动生效）

1. **别删 QA 档案**——resume-skip 是最大的省法：已过门的直接跳过，重跑同一命令只花在没过的上。`--fresh` 只在规则大改、要求全量重验时用。
2. **轻路径**（内建）：机械违规不烧盲读+核查，reviser 直接按静态清单改。
3. **glossary 按篇裁剪**（内建）：只喂正文里真出现的术语条目（实测 14k→1.5k 字符/调用）。
4. **目录框架只喂概览**（内建）：生产阶段拿整条祖先链的概览（~6k），盲读只拿直系父目录概览（~0.8k）。
5. **读者数 3**（默认）：共识按"过半"缩放，3 读者足够；5 更平滑但贵 ~70%。
6. **目录批写**（内建）：同目录多篇缺失笔记合并给一个 writer，共享上下文只发一次——新铺仓库时省最多。

并发：agent 调用是网络密集型，`--concurrency 12` 在 20 核机器上 CPU 仍大量空闲；瓶颈在 agent 端。

## 门的边界（诚实条款）

**门是必要不充分。** 一整个仓库刷绿之后，人读真实页面仍会发现门测不出的毛病——实测反复发生，而且每次都是新维度（密度→海拔→具体度→标题结构→段落→元话术→教学顺序）。两条应对都要做：

- **概念主页必须人审**：各 `__dir__` 页和 glossary 里标了归属的页（就是"看不懂"最集中的地方）。"教得好不好"是整体判断，机器测不全——知识诅咒（写的人已懂，必跳地基）+ 盲读者手里有 glossary 这根拐杖（页内缺定义被拐杖遮住）。人审是设计内的一步，不是流程失败。
- **人挑出新毛病 → 固化成规则再批量跑**，别一页页手修。能机械检测的进 `run.ts` 硬门（本套件的墙/顿号串/元话术都是这么来的），只能语义判断的进 prompt 规则 + 盲读扣分维度。

## 编排上踩过的坑（引擎已内建应对，改引擎前先读）

- **agent 的 `--json-schema` 只校验不约束解码**：输出骨架必须原文写进 prompt，编排端再宽容捞 JSON 兜底。更重的是 2026-07-19 探针实测：它还会**概率性令 agent 跳过全部工具调用直接编结构化答案**（0 次 Read 产出形状完美的"审计结果"）——所以本套件一律不用它产分析结果；凡要求"读过码"的阶段，必须用 `agentToolCounts`（lib.ts）核 chat_history 里的读类工具调用数，0 次按幻觉作废，**不许只信输出形状**。
- **盲读隔离靠空目录 cwd**（结构性无码权限），不靠 prompt 自觉。
- **git 守卫按"新增脏路径"判越界**（多 agent 共享工作区里别的进程随时 add/restore，比对整串 status 会误报）；任何会话弄脏 `.atlas/` 之外的路径立即中止。
- **低分章节必须带读者评语回灌给修订者**，否则修订者收不到信号修不动。
- **keep-best 轮**：修订可能把笔记越改越差，留最好一轮；通过轮 penalty=-1 永远胜出。
- **事实核查是采样性的**：每轮抓到的不实断言可能不同，靠多轮收敛（revision_rounds_max=4）+ 修订者"收尾自查对照源码"。
- **驱动/清单放仓库内或 ~/.cache**，不放 /tmp——长跑任务的编排文件会被 /tmp 清理器回收（实测损失过一次）。

## 文件清单

| 文件 | 职责 |
| --- | --- |
| `run.ts` | 单篇引擎：writer/mapify/轻路径/盲读/核查/门/修订/keep-best/档案/stamp |
| `sweep.ts` | 批量驱动：多轮迭代、resume-skip、全过/零进展停、日志落 `.atlas/qa/_sweep/` |
| `count-passed.ts` | 按清单统计 finalPass 分布 |
| `order.ts` | 目录页阅读顺序提案：读子项概览 → agent 按"先懂什么"排 order → 写 frontmatter（`--dry` 先看） |
| `concept.ts` | 概念页生产线（课程制）：concept-pages.json 是课程表（顺序+requires 前置+owns 分工）；writer 拿课程表+前置页全文在其上写、不重讲不越界；盲读 ×3 零代码零 glossary、唯一先验=前置页，报告"循序渐进断线"（breakMed>1 挂门）；+ 长段/顿号串/标题结构机械硬门 + 只对 sources 的事实核查 + 可视化门 → 按依赖分波生成 → stamp（frontmatter order=课程位次，viewer 侧栏按它排） |
| `distill.ts` | 概念页 → 视频分镜蒸馏：core_message + 逐场景旁白/画面 prompt/叠字/时长,旁白逐场景溯源;门=语速/时长机械校验+忠实度核查(不许引入新事实) |
| `extract.ts` | 概念抽取：跨切概念收敛成"归属页讲全 + glossary 一行本质 + 别处瘦身指路" |
| `audit.ts` | 概念级安全审计：以概念页 sources 为审计单元（scope 指纹绑定字节）→ audit 审数据流 + factcheck 杀假 finding + 工具证据幻觉门 → 档案落 `.atlas/audits/`（详见"概念级安全审计"节） |
| `prompts/` | 五阶段出厂 prompt（可被仓库覆盖/追加） |
| `schemas/` | 盲读/核查的输出 JSON schema |
| `rubric.json` | 出厂门槛（可被仓库合并覆盖） |
| `defaults/` | 仓库缺 CONVENTIONS/template 时的出厂件 |
