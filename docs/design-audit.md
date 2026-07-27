# 设计合理性审计（design 轴）

> 状态：机械层 + judgment 层均已实装。ruleset `atlas-designscan-v1`（19 类）。
> 问题：这段代码的形状，是不是它要表达的东西的**最简正确形状**？

## 0. 先把四条轴分开

atlas 里有四种"质量"，各自有各自的判据，混在一起就都失效：

| 轴 | 问的问题 | 谁来判 | 能不能当 CI 门 |
|---|---|---|---|
| security | 谁能打进来 | `qa/audit.ts` + `domain: security` 账本 | 不能（判断类） |
| test | 测试证明了预期的不变量吗 | `domain: test` 账本 | 不能（判断类） |
| readability | 好不好读 | `repo-atlas readability`（机械）+ `qa/readability/semantic.ts` | **明确不做**（精度天花板，见 readability-audit.md §3） |
| **design** | 这是最简正确形状吗 | `repo-atlas quality`（机械）+ `domain: design` 账本（判断） | **机械那半边可以** |

design 轴与 readability 的关键差别：readability 的**全部**维度都有精度天花板（人类之间都不一致），
所以它整轴都只能排序提示。design 轴不是——它的一半问题是**机械可判定**的。

## 1. 分半的判据：不是"机械 vs LLM"，是"能不能判死"

```
能判死（precision ≈ 1）              需要判断（precision 有上限）
─────────────────────────────        ──────────────────────────────
import 环存在                          这个 `?:` 是设计还是变通
一条 import 边逆着声明的分层           这个字段对应真实领域概念吗
一个 marker 注释三年没动                这两个名字是不是同一件事
一个声明里 `?:` 与 `| null` 混用        这个 fallback 糊住的是真问题吗
一个尾随可选布尔参数                    这段逻辑放错层了吗
类型逃逸点的位置与数量                  这两处实现是不是语义重复
─────────────────────────────        ──────────────────────────────
repo-atlas quality                    .atlas/audits/<slug>.json (domain: design)
可以 --fail-on 进 CI                   永远 report-only
```

左边那列的东西**不该**交给 LLM——每轮花 token 重新发现一个正则就能判死的事实，还带幻觉风险。
右边那列**不该**交给检测器——写不出不误报的规则，硬写只会训练出"全部忽略"的习惯。

## 2. 机械层：`repo-atlas quality`

```sh
repo-atlas quality                        # 只看
repo-atlas quality --write --artifacts    # 存报告 + 写页面卡片
repo-atlas quality --fail-on import-cycle --fail-on layer-violation   # CI 门
```

六个检测器，每个都在 `test/quality.test.mjs` 里同时钉了**真阳性**与**必须不报的近似情形**：

| detector | 类别 | 抓什么 | 精度说明 |
|---|---|---|---|
| `import-cycle` | `layering-violation` | 包级与模块级 SCC。每条边都用**去注释、留字符串**的源码复核过，所以注释掉的 import 不会凭空造出环；全边都是 `import type` 的环单独标出（构建期被擦除，缺陷是概念性的而非运行期危险） | 高。deps.ts 从裸字节抽 specifier，复核这一步就是为它兜底 |
| `layer-violation` | `layering-violation` | `.atlas/config.json` 的 `layers`（自上而下声明）里，任何朝 index 0 爬的 import | 取决于声明；声明本身是仓库的事实 |
| `stale-marker` | `stale-marker` | 注释里的 TODO/FIXME/HACK/XXX/KLUDGE，按 `git blame` 的作者时间算年龄，超过 `--stale-days`（默认 180）才报 | 高。无 git 历史的文件**算"年龄未知"而不是"新"**，并在 detector note 里说出来 |
| `type-escape` | `type-escape` | `as unknown as` / `as any` / `: any` / `@ts-ignore` / `Record<string, unknown>`，单文件 ≥3 处才报 | 检测精确；"是否该改"是判断，所以只排序不设门 |
| `absence-mixing` | `absence-semantics` | 同一个 interface/type 里既有 `?:` 又有 `\| null` 的**直接**成员（嵌套对象字面量自己算一套约定，不计入） | 高。这条独立重现了 RelayOS 2026-06-23 那轮人工审计里的 `ArtifactDetail` |
| `boolean-trap` | `boolean-trap` | 尾随的可选布尔**位置参数**。对象参数（`{ compact }: Props`、options bag）在调用点已经有名字，是修法不是缺陷，不报 | 中高 |

刻意**不做**的事：

- 不重造别人做得更好的东西。死导出/无人 import 的文件交给 knip，规则 lint 交给 eslint，
  两者从 `--ingest-knip` / `--ingest-eslint` 进来。atlas 只贴上它独有的三件事：
  与其它账本同一套 **blob-hash 新鲜度契约**、**页面锚定的卡片**、以及 viewer 本来就在建的**import 图**。
- 不把 eslint 的风格规则改标成设计缺陷。`ESLINT_CATEGORY` 只映射带设计主张的规则，
  其余**丢弃并计数**（`ingested[].dropped`），永不悄悄吸收。
- 不做绝对分。没有"设计分 87 分"这种东西。

外部结果的中立入口（任何工具几行 jq 就能接）：

```jsonc
// repo-atlas quality --ingest <file>
{ "tool": "mytool",
  "findings": [{ "path": "src/a.ts", "line": 12, "category": "magic-constant",
                 "title": "裸 86400", "evidence": "一天的秒数写死在这里",
                 "fix": "提成命名常量", "detector": "numbers" }] }
```
字段不全的条目**整条丢掉并计数**，不猜。

产物：`.atlas/quality.json`（`repo-atlas-quality-v1`）+ 薄索引 `.atlas/audits/quality.json`
（`atlas-audit-v1` 通用形，只为让 `status` 报漂移而不必重解析全报告）。

**薄索引刻意是 v1 通用形，不是 v2 design 账本**——一次检测器跑不是一次评审，
只有评审才配写 `reviewState: complete`。

## 3. judgment 层：`domain: design` 账本

```sh
cd <目标仓库>
bun <repo-atlas>/qa/design.ts --all            # 按 .atlas/pipeline/design-units.json
bun <repo-atlas>/qa/design.ts --slug design-contracts --scope packages/x/src   # 一次性
```

审计单元是**路径集合**（不是 security 那样的概念页）——设计缺陷住在模块的形状里，不在信任边界上。
单元清单是仓库自有内容：

```json
[{ "slug": "design-type-contract-layer", "title": "类型与契约层",
   "scope": ["packages/protocols/runtime-types/src", "packages/rpc/spec/src/capabilities"] }]
```

管线形状（与 `qa/audit.ts` 同源，共用 `lib.ts`）：

```
文件清单（测试/fixture 排除）
  → design.md prompt（19 类 ruleset + 严进定标 + "机械层已扫过的别重复报"）
  → 形状校验：severity/category/locations 不合契约的**整条丢掉并记账**（rejected_shape）
  → design-factcheck.md：逐条只读复核，专杀"编零引用/编从不缺失/编同一事实"三种幻觉
  → atlas-audit-v2 (domain=design, reviewState=complete) + 页面卡片
```

四道硬门，任一不过就整轮作废：

1. **只读**：`DENY_ALL_WRITES` + `assertOnlyAtlasWrites` 按 transcript 归因。
2. **工具证据**：读类工具调用次数 < 文件数 → 按幻觉处理（实测 grok 会概率性跳过工具直接编答案）。
3. **形状**：19 个 category 之外、`critical` severity、一个 location 都不落在被审单元内的（跨文件引用是允许的，至少一个必须在单元内），全部拒收并记进 `rejected_shape`。
4. **事实**：`unsupported` 丢弃，`out-of-scope`（其实是 security/test/readability 的事）丢弃，
   `unverifiable` 保留但标 `⚠ 未核实`。

两条**绝不**：

- **绝不用一次失败覆盖一份仍然成立的评审**。盘上已有针对当前字节的 `complete` 档案时，
  失败只以退出码与日志汇报。没有档案（或档案已对不上当前字节）才落 `reviewState: "in-progress"`，
  让 `repo-atlas status` 把它报成 invalid——而不是"零 finding 的干净单元"。
- **绝不给 design 域做 portfolio 页**。engine 刻意不给它 unit 投影（`src/types.ts` 里写了原因）：
  设计结论要在**被点名的那个文件的页面**上遇到读者，不是在又一个孤岛列表里。
  卡片落 `.atlas/artifacts/<文件>/<slug>.md`，按单元命名，所以多单元点到同一文件不互相覆盖。

`design` 也**不参与** `review-coverage` 的闭世界覆盖闭合（`PortfolioDomain` 只含 security/test）。
理由：把"每个路径都必须被设计评审过"当成可达目标是假的。要加进去，先回答"够了"是什么意思。

## 4. ruleset `atlas-designscan-v1`（19 类）

正文在 `qa/prompts/design.md`（仓库可用 `.atlas/pipeline/design.md` 整替、`design.extra.md` 追加）。
类别与它们分别由谁判：

| 组 | id | 机械层能判的部分 | 判断层要判的部分 |
|---|---|---|---|
| 类型与契约 | `optionality` | — | `?:` 从来没真的缺失过（要数构造点） |
| | `absence-semantics` | 单个声明内 `?:`/`\| null` 混用 | 跨函数跨层的缺失语义不一致 |
| | `boolean-trap` | 尾随可选布尔参数 | 布尔字段其实是三态 |
| | `type-escape` | 逃逸点位置与计数 | 为什么这里必须撒谎 |
| 抽象与结构 | `over-abstraction` | — | 单实现 interface、只转调的包装、没人设的开关 |
| | `layering-violation` | import 边逆向 | 这段逻辑放错层了 |
| | `duplicate-logic` | 字面重复（readability 的 dupRatio） | 语义重复、写法不同 |
| | `dead-code` | knip 摄入 | 不可能进入的分支、为不可能状态写的防御 |
| 状态与唯一真值 | `redundant-fields` | — | N 个字段编码同一事实 |
| | `over-complication` | — | 可推导状态被存下来 |
| | `first-principles` | — | 字段不对应领域概念；兄弟结构里类型不一致 |
| 失败模式 | `masking-default` | — | `?? fallback` 糊住了本该大声失败的缺失 |
| | `swallowed-failure` | eslint `no-empty` 摄入 | catch 吞异常、log 完继续 |
| | `magic-constant` | eslint `no-magic-numbers` 摄入 | 写死的重试/超时/阈值 |
| 演化残留 | `dead-forward-compat` | — | 为"以后"留着、当前零引用 |
| | `compat-shim` | — | 迁移早已结束的兼容层 |
| | `stale-marker` | marker 年龄 | 注释承诺的事从未发生且在误导 |
| 概念完整性 | `naming-drift` | — | 同概念多名、与 glossary 本质不一致 |
| | `unexplained-export` | — | 对外导出的概念在笔记/glossary 里无处可读 |

最后两类是 **atlas 独有能力**的判断题：只有把代码和 `.atlas/notes/` + `.atlas/glossary.md`
放在一起才判得出来。也正是它们**没有**机械版——同义词判定需要语义，硬写规则只会误报。

严重度只有 `low | medium | high`。**没有 critical**：设计缺陷是清晰度债，不是崩溃。
想报 critical 说明找到的是 bug，那属于 security 或 test 域。

## 5. 判据之外：这一轴的诚实边界

1. **机械层报的是"形状"，不是"对错"**。`absence-mixing` 报 `AttentionItem` 混用两种缺失写法——
   那可能正是有意的（optional = 没被 snooze，null = 从未 stamp）。所以它是 low/medium，且 report-only。
   能上 CI 门的只有 `import-cycle` / `layer-violation` 这类判死的。
2. **判断层的产出是意见，不是事实**。`dropped` 与 `bar_held` 与 finding 同等重要：
   它们让下一轮不再重复审同一个被证明承重的东西。
3. **两层都不给分**。没有"设计健康度 87"。有的是：一份钉在字节上的 finding 清单，
   和一条"这些字节从那次评审起改了多少"的漂移线。
4. **`layers` 是可选的，不是补齐项**。仓库已经有更强的自家分层门（例如 RelayOS 的
   `check-context-boundaries.ts`，带 grandfathered 边与表所有权）时，**不要**再声明 `layers`——
   重复一份更弱的规则只会制造噪声。detector 会在报告里直说自己没被激活。
