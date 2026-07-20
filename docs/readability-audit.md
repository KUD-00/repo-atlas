# 代码「人类可读性」评估：研究地图与 atlas 功能设计

> 状态：研究综述 + 已实现的机械层/语义校准套件（语义人类对齐仍待标注）。
> 问题：atlas 能否对目标仓库的**代码本身**（不是笔记）自动判断「人类可读性」——
> 命名是否一致、行长/版式是否失衡、注释是否打断流动，以及更多维度。

## 0. 先把三个词分开

文献里 readability / legibility / understandability 是三个被分开测量的东西
（[Oliveira et al., ICSME 2020, 54 篇人本实验的系统综述](https://paperswithcode.com/paper/evaluating-code-readability-and-legibility-an)）：

- **legibility（易辨识）**：能不能快速认出代码里的元素——版式、缩进、标识符风格。
- **readability（感知可读性）**：读者主观觉得「这段好不好读」。
- **understandability（可理解性）**：读者实际理解对没有——用问答正确率、理解时间、眼动/fMRI 测量。

三者**会打架**：著名的 Börstler & Paech 实验（TSE 2016）发现，加了注释的代码
*感知*更可读——**即使注释是坏的、对理解没有帮助**
（[论文条目](https://dblp.org/db/journals/tse/tse42)；[该发现的转述](https://research.ou.nl/ws/portalfiles/portal/46333009/Lung_C_IM9906_SE_AF_scriptie_Pure.pdf)）。
所以这个功能的第一步决策是：**atlas 评的是「感知可读性画像」，不是「实际理解度」**
——后者只能做人本实验，工具只能逼近。

## 1. 研究谱系（这个领域是成熟子领域，不用从零发明）

| 代际 | 工作 | 要点 |
|---|---|---|
| 奠基 | Buse & Weimer, ISSTA 2008 / TSE 2010 [「Learning a Metric for Code Readability」](https://docslib.org/doc/2568628/learning-a-metric-for-code-readability-raymond-p-l) | 120 人标注 100 个片段（~1.2 万条判断），ML 拟合局部特征：行长、标识符长度、空白、关键词密度。~80% 复现人类判断 |
| 简化 | Posnett, Hindle & Devanbu, MSR 2011 | 只用 3 个特征（Halstead volume、token 熵、行数）达到相近效果——「大小+信息密度」解释了大头 |
| 视觉化 | Dorn 2012（三语言，特征含对齐/缩进变化，见 [Springer 综述转述](https://link.springer.com/article/10.1007/s10664-023-10396-7)） | 「美感」最接近的量化：visual/spatial/alignment/linguistic 四类特征 |
| 文本化 | Scalabrino et al., ICPC 2016 + [JSEP 2018](https://www.cs.wm.edu/~denys/pubs/JSEP'18-ReadabilityPaper.pdf) | 加 textual features：注释自身可读性、**注释与标识符的一致性**；104 特征、600+ 标注片段，传统模型最强 |
| 泼冷水 | Scalabrino et al., ASE 2017/EMSE 2019；[复分析「Combined Metrics Matter」](https://ui.adsabs.harvard.edu/abs/2018msr..conf...61T/abstract) | 121 个指标、444 次人类评估：**没有任何单一指标能预测可理解性**，必须组合 |
| 深度学习 | Mi et al. 2018–2022（视觉+语义+结构三通道，见 [PPIG 2024 转述](https://ppig.org/files/2024-PPIG-35th-sergeyuk.pdf)） | 超过传统 ML，但仍是分类人类评分 |
| LLM 时代 | [Human-Aligned Code Readability Assessment with LLMs](https://arxiv.org/html/2510.16579v1)；[Atlassian 工业案例 HULA](https://ar5iv.org/html/2501.11264)；[The Readability Spectrum](https://arxiv.org/html/2605.13280v1) | LLM-as-judge 对齐人类评分；LLM 生成代码的可读性本身也成了研究对象 |

公开标注数据集（校准用）：Buse & Weimer 集、Dorn 三语言集、Scalabrino 600+ 片段集。

## 2. 维度清单（九维，含证据强度分级）

证据强度：**A**=人本实验支持；**B**=证据混合/弱；**C**=主要是惯例与专家意见；**D**=未验证的直觉。

### D1 版式与视觉节奏 — 证据 B/C
- 可计算：函数内行长的 max/P95/标准差（「某一行特别长」= **repo 内离群点检测**，不是固定 80 列阈值）；缩进深度分布；空行节奏（代码「分段」）。
- 证据：[JSS 2023 格式元素 SLR](https://arxiv.org/pdf/2208.12141.pdf) 是最接近的综述——80 列这类具体参数证据大多停在专家意见层面；缩进「有 vs 无」效应大，「2 vs 4 空格」无显著差异（[Bauer et al. 2019 眼动复现](https://www.se.cs.uni-saarland.de/publications/docs/Bauer19.pdf)，但 [2023 RCT](https://www.scitepress.org/Papers/2023/120875/120875.pdf) 又称有大效应——诚实说：混合）。纯文本阅读研究支持中等行长（[55 CPL 实验](https://www.researchgate.net/publication/220968790)），算是间接依据。
- Wang, Pollock & Vijay-Shankar, WCRE 2011：把方法体自动分割成「meaningful blocks」提升可读性——空行分块是有依据的维度。

### D2 命名与词汇 — 证据 A（最硬的一维）
- 可计算：标识符长度分布、缩写/全词比、词法风格一致性（camelCase/snake_case 混用率）、同概念异名（词干聚类）。
- 证据：描述性复合名提升理解（Schankin et al., ICPC 2018）；**短名反而拖慢理解**（Hofmeister et al., SANER 2017，反直觉）；camelCase vs underscore 差异小且受熟悉度调制（[Binkley et al. 2009](http://www.cs.loyola.edu/~binkley/papers/icpc09-clouds.pdf)、[EMSE 2013](https://www.cs.kent.edu/~jmaletic/papers/EMSE12.pdf)，Sharif & Maletic 2010 眼动）——**一致性比选哪种重要**。
- 命名一致性的自动检测已有专门工作：Lin et al., SCAM 2017（代码分析+NLP 促进标识符一致使用，见 [作者主页](https://sscalabrino.github.io/)）；Allamanis et al. [「Learning Natural Coding Conventions」](https://www.bcs.org/media/2406/dd-natural-coding-conventions.pdf)（从 repo 自身学惯例再抓违背者——**这个思路直接可用**）。
- 语言反模式（名字与行为不符）：Arnaoudova et al. [「Linguistic Anti-Patterns」](https://www.ptidej.net/publications/documents/CSMR13d.doc.pdf)（17 条目录 + LAPD 检测器）；含反模式的代码显著增加评审者认知负荷（Fakhoury et al.，[转述](https://fpalomba.github.io/pdf/Journals/J48.pdf)）。

### D3 注释与文档 — 证据 A（但方向反直觉）
- 可计算：注释密度（注释行/代码行）、行内注释占比、commented-out code 检测、注释与相邻标识符的词面一致性（Scalabrino textual features 的简化版）。
- 证据：注释提升理解（Tenny, TSE 1988）；**但坏注释也提升感知可读性**（Börstler & Paech 2016）——「感知」和「理解」在此分离。密度统计见 [Arafat & Riehle 对 5000+ 项目的调查](https://www.spinellis.gr/pubs/conf/2016-ICSE-ProgEvol/html/SLK16.html)（随语言/领域差异大）。
- **「注释过多打断流动」（倒 U 型）是 D 级**：没找到直接验证的实验。现有证据只支持「质量（与代码一致性）比密度重要」。可以做密度分布 + commented-out code，但别声称「过多注释有害」有实证背书。

### D4 结构复杂度 — 证据 A/B
- 可计算：cognitive complexity（SonarSource 规则可独立实现）、嵌套深度、每函数分支/递归点数。
- 证据：Cognitive Complexity 是唯一经过大规模验证的纯代码指标——[Wyrich et al. 2020 元分析](https://arxiv.org/abs/2007.12520)（24,000 次理解评估、427 个片段）：与理解时间和主观评分正相关，与正确率关系混合；[与 cyclomatic 的对比研究](https://arxiv.org/pdf/2303.07722v1.pdf)结论同样是「相关但有限」。减少嵌套降低阅读时间（[Johnson et al., ICSME 2019](https://www.semanticscholar.org/paper/An-Empirical-Study-Assessing-Source-Code-in-Johnson-Lubo/4e63ff35c69adaedb6c9bb2fbe15c1ab7a84efce)，[2024 眼动复现](https://link.springer.com/article/10.1007/s10664-024-10532-x)）。Spaghetti/Blob 反模式损害理解（Politowski et al., IST 2020）。

### D5 信息密度与「自然性」 — 证据 A/B
- 可计算：Halstead volume、token 熵、对 repo 自身语料训练的小 n-gram 模型的 cross-entropy。
- 证据：Posnett 2011（3 特征 ≈ B&W）；Hindle et al., ICSE 2012「On the Naturalness of Software」（代码比自然语言更可预测）；**Casalnuovo et al. 2019 [「Do People Prefer 'Natural' Code?」](https://arxiv.org/abs/1910.03704)：首次证实人类偏好与语言模型 naturalness 分数对齐**——这给「用词法模型给可读性打分」提供了人本依据。注意双向：熵过高=意外写法，熵过低=复制粘贴（接 D6）。

### D6 重复与克隆 — 证据 B
- 可计算：文件内/跨文件近似重复率（token 级 hash 窗口即可，不用上 NiCad）。
- 证据：克隆不总是有害（Kapser & Godfrey 2008「'Cloning considered harmful' considered harmful」）；测试代码克隆损害理解与维护（Bavota et al. 2012/2015；[van Bladel & Demeyer, SANER 2020](https://www.conference-publishing.com/toc/SANER20&Full=abs)：测试代码 23–29% 是克隆）。定位为「可疑信号」而非「扣分项」。

### D7 类型与静态信息 — 证据 B（不做独立维度）
- Hanenberg, OOPSLA 2010：静态类型对开发速度**无显著正效应**（[转述](https://neverworkintheory.org/tex/nwit.pdf)）；Kleinschmager et al., ICPC 2012（Java vs Groovy）同样混合。
- 处理：不评「有没有类型」，只把「语言/项目是否带类型」作为其它维度的上下文修正。

### D8 控制流风格与习语 — 证据 B/D
- method chaining **不损害**理解（Börstler & Paech 2016，有[复现](https://www.researchgate.net/publication/381982477)）；递归 vs 迭代等构造对比见 Oliveira ICSME 2020 综述。
- guard clause / early return「更好读」：**D 级**，无直接实验。可以做结构特征（嵌套形态），别写成规则。

### D9 项目内一致性（横切） — 证据 A（机制层面）
- 人最敏感的不是「绝对风格」而是「漂移」：同一 repo 里格式/命名/注释习惯的突变。
- 可计算：per-file 特征向量在 repo 分布中的离群度（z-score / 百分位）。这是把 D1–D6 落地的**默认输出形态**：不报「差」，报「和本仓库其它代码不一样」。

## 3. 诚实的边界（写进功能定位，别夸大）

1. **单一指标全部失败**（Scalabrino 2019）——任何单维红线都是伪科学，只能组合使用。
2. **模型跨范式退化**：B&W/Scalabrino 换到 reactive 等范式明显变差（[案例研究](https://ar5iv.labs.arxiv.org/html/2110.15246)）——按语言/范式分别校准。
3. **人类之间也不一致**（[Assessing Consensus of Developers' Views](https://arxiv.org/pdf/2407.03790)）——分数有天花板，输出应该是「画像 + 离群点」，不是「百分制审判」。
4. **感知 ≠ 理解**：工具能逼近的是感知可读性；后者需要人本实验。
5. 最新工作也在质疑「理解度代理指标」的可靠性（[On the Reliability of Code Comprehension Proxies, 2026](https://arxiv.org/html/2605.23008v1)）——这是一个仍在活跃的开放问题，功能要留出随研究更新的余地。

## 4. 落到 repo-atlas 的设计

镜像本仓库既有分层哲学：**内核 LLM-free，LLM 套件旁挂**。

### 机械层（已实现：`src/readability.ts` + `repo-atlas readability`）

- 输入：`scan.ts` 已有的文件清单；tree-sitter 或轻量词法器做 per-function 切分。
- 输出：每文件/每函数的**特征向量**（D1–D6 的可计算项），落 `.atlas/readability.json`。
- 增量：报告记录每文件 git blob hash；`status` 只做 hash 验鲜，重跑时对旧/新报告做趋势 diff，artifact 内容不变则不重写。
- 报告形态：repo 内**相对离群**（D9），不是绝对分。例如「此函数行长 P95 在 repo 分布的 99 分位」「此文件命名风格与 repo 主流不一致」。

### LLM 层（`qa/` 旁挂，对齐现有 QA 管线）

- 「盲读」判官：复用 qa 的 reader 模式（空 cwd、结构性无码权限 → 换成「只见片段不见上下文」），对抽样函数打可读性分。
- **校准先行**：先在 Buse & Weimer / Dorn / Scalabrino 公开标注集上跑，报告 judge 分数与人类评分的 Spearman 相关；相关系数写进报告头，不达标不出报告。这是 qa/README 里「标定」配方的同款思路。
- 机械层与 LLM 层交叉验证：两者离群点取交集输出，分歧大的标「人审建议」。

### 明确不做

- 不做绝对阈值红线（80 列、注释密度区间）——那是 formatter/linter 的地盘，且证据等级 C/D。
- 不做跨语言统一分数；每语言独立基线。
- 不把 readability 做成 CI 硬门——证据天花板（§3）决定了它只能是「提示与排序」。

## 5. 原型状态（2026-07-18）

机械层已实现：`src/readability.ts` + `repo-atlas readability [--json] [--out f] [--top N]`
（无需 `.atlas/` 也能跑）。特征：行长分布与离群行、嵌套深度、分支密度、注释密度/行内注释/
commented-out code、标识符长度与风格一致性、token 熵、Halstead 密度、4 行 shingle 重复率、
函数区（regex+brace 启发式）。输出 = §D9 的 repo 内相对离群（z ≥ 2），无绝对分。

实测（RelayOS monorepo）：1330 个代码文件、4873 个函数，全量 1.3s。信号抽查合理
（单行 locale 文件、100% 重复的 vite/lingui 配置、457 行组件函数、组合根大函数均被捕获）。

**grok 盲读交叉验证（8 片段小样，一次调用）**：被标片段均分 3.75 vs 干净片段 4.00——
方向对但分离度弱，与文献结论一致（单特征不预测人类判断）。三种不一致值得记住：

- 最差片段两边一致（457 行组件函数，grok 也打 2 分）；
- 机械误报类：短标识符比例高的文件 grok 觉得命名清楚（正则密代码的短变量名无伤）；
- 机械漏报类：桶文件（barrel）「导出墙」grok 打 2 分，机械特征毫无反应——纯 re-export
  的行长/嵌套/熵全都正常。这类需要专门检测器（re-export 占比）。

已修的假阳性：`/// <reference>` 指令不再算 commented-out code；<10 行小文件退出比率类
指标；标识符 <20 个的文件退出命名类指标。commented-out code 启发式又修过两轮：
英文「word (paren)」不再误判为函数调用（要求 `(` 前无空格）、英文句尾分号、
`// ----` 分隔线（误判为 `--` 运算符）均不再触发——RelayOS 当初被标的 4 个文件
（db/config.ts、capabilities/packages/list.ts 等）实为高质量"为什么"注释，修正后归零。
教训写进功能定位：commented-out code 是低精度启发式，只用于排序提示，永远需要人复核。

**标注集校准（2026-07-18，B&W 100 片段 + Scalabrino 67 片段分层样本，vs 人类均分的 Spearman ρ）**：

- 机械层单指标方向全部与文献一致：halsteadPerLine −0.52（最强，信息越密越难读）、lineLenMean −0.39、tokenEntropy −0.31、commentRatio **+0.36**（注释多则*感知*可读，正合 Börstler & Paech）；scal 子集上 maxNesting −0.23。
- **命名类指标（identAvgLen / shortRatio / dominantShare）ρ≈0**——词法级命名统计不预测人类评分，命名维度必须上语义（一致性/反模式），纯统计无效。这是本次校准最重要的负面结果。
- **等权 4 特征组合（+commentRatio −halstead −lineLen −entropy）ρ=0.55（全集）/0.66（bw）/0.62（scal）**，碾压任何单指标——"Combined Metrics Matter"在我们自己的实现上复现。机械层下一步应把组合分作为 repo 内相对画像的输出维度（仍为相对分，不设绝对阈值）。
- grok 盲读校准（同批 167 片段 ×3 pass，盲评 1–5 overall）：**ρ=0.39（全集）/0.33（bw）/0.53（scal）**，二分类准确率 73%。inter-pass 可靠性 ρ=0.83——判官自身高度稳定，但**稳定地测量着与人类不同的东西**。分歧案例定性：bw78（拥挤排版，人类 2.3 / grok 5）grok 看语义清晰就放过表面密度；bw94（稀疏排版+单字母名，人类 4.1 / grok 2）grok 重罚无语义命名。**人类标注（尤其 B&W 的 cs101 学生）偏表面密度，LLM 零样本盲评偏命名/语义。**

**全量校准（管线沉淀后复跑，660 片段全集合：bw 100 + scal 200 + dorn-java 121 + dorn-python 119 + dorn-cuda 120）**：

- 机械组合分 **ALL ρ=0.505**；分集合：bw 0.667 · scal 0.584 · dorn-java **0.349** · dorn-python 0.475 · dorn-cuda 0.685。跨语言、跨数据集留出成立，但 dorn-java 上 halstead/lineLen 方向反转——**特征重要性随语言与数据集漂移，权重按部署语言回归调优是后续工作**。
- 组合分已进机械层输出：`surfaceComposite` 维度（worst tail = 最难读），等权 z-sum。
- 校准管线沉淀在 `qa/readability/calibrate/`（download → build → run → score，断点续跑）；Dorn 的「列 ↔ 排序片段序号」映射为反推假设，依据写在该文件头注释。
- 语义检测器在 `qa/readability/semantic.ts`（grok 维度限定：naming / commentCoherence / antipatterns / barrel，禁 overall）。RelayOS 小样验证（7 文件）：barrel 墙正确捕获（机械层盲区补上）、机械层短标识符误报被语义分排除（sanitize.ts naming=5）；grok 偶发不吐 JSON，runner 已带一次重试。

**校准后的分工修正（推翻"LLM 盲评当总评"的原计划）**：

1. **表面可读性总评用机械组合分**（ρ=0.55–0.66，且零成本、可增量、无幻觉）——它就是 B&W 式人类表面感知更好的预测器。
2. **LLM 用在机械层看不见的语义维度**：命名语义质量、注释-代码一致性、语言反模式——即机械层 ρ≈0 的那块（命名）。zero-shot overall 提示词不可用；若要 LLM 打表面分，必须用人类标注对做 few-shot 锚定。
3. 报告头应同时给两个分数（表面 / 语义），不合并成单一分——合并会同时稀释两边各自有效的信号。

**功能二轮（2026-07-18，同日后续）**：

- `barrelRatio` 维度（re-export 行占比，**≥30 code 行才计**——RelayOS 的 L1 契约层故意用小桶做 API 面，不设门槛会被惯例性小桶刷屏；剩下的 extension-sdk/index.ts 52.8% 这类大桶才是真信号）。
- 目录 rollup 进报告（`dirs[]` + 控制台 worst areas）：两级目录聚合 meanComposite/低分文件数/最差文件。
- `--artifacts`：给每个离群文件与受影响目录写 `.atlas/artifacts/<页>/readability.md`（viewer 侧栏直接展示，stale 卡片自动清理），零 viewer 改动。
- **按语言调权实验 → 否决**（calibrate/weights.mjs 可复跑）：最小二乘拟合 in-sample 只比等权好 0.01–0.07，且留组出（LGO）全面退化——java 0.277 vs 等权 0.425、cuda 0.648 vs 0.685，仅 python 例外（0.524 vs 0.475）。结论：**等权 z-sum 保持为默认**，拟合权重过拟合数据集怪癖；文档保留实验证据。

**功能三轮（2026-07-19）**：

- **audit ledger 引擎侧落地**：`src/audits.ts` 的 `loadAudits()` 保持 security viewer 的严格 `finalPass` 契约；通用 status/stamp 层接受 `atlas-audit-v1` generic findings。加载时重算 scope 指纹；有 per-file hashes 时再报精确 changed/missing 与 drifted findings。`audit-stamp` 会拒绝 scope 已漂移的 ledger，避免把旧结论“洗白”；`audit-import` 可把历史 `scans[]` ledger 的扫描时 hash 原样迁入。
- **可读性趋势**：`repo-atlas-readability-v1` 报告记录实际分析 buffer 的 git blob hash；`--out` 写新报告前先验证旧 schema，再按路径 union 记录 modified/added/removed，组合分 Δ≥1 的 improved/worsened 保留精确总数与 top-N 明细。canonical `.atlas/readability.json` 另写 `atlas-audit-v1` 薄索引（hash + 小型 trend summary）；`status` 只读薄索引即可报告后续漂移，不再解析整份特征 corpus。无注释/样本过小分别以 nullable `commentCoherence` / `dupRatio` 表达。
- **dup 小文件 guard**：shingle 数 <8 的文件退出 dupRatio（误报教训，见下）。
- **机械 commentCoherence**：每条注释的词与前后各 2 行标识符词做重合率（Scalabrino textual features 的简化版），进画像与文件卡片，不进组合分（未校准）。
- **语义校准套件**：`calibrate/semantic-{build,run.sh,score.mjs}`——对 worst/中位/best 做不重叠分层抽样（最多 eligible 总数）。工作区按 repo realpath + sample hash 隔离；manifest 绑定规范化样本路径与文件 SHA-256，实际送判前再次验证当前字节。结果/checkpoint 再绑定 `sampleHash + sourceHash`，严格验证 exact path、单行、1–5、反模式结构、外部判官成功退出与无 error；任一 pass 不完整就拒绝评分。路径逃逸/符号链接在字节进入外部判官前拒绝。score 评分前还会重算当前 sample，避免拿旧 agent 结果和改动后的源码人工标签比较；随后报告所有完整 pass pair，并分别计算 naming/commentCoherence 对人工标注的 exact/MAE/ρ。人工 `semantic-labels.json` 也必须绑定同一 sample hash，零方差 ρ 明确标 n/a。

  ```sh
  cd <目标仓库>
  repo-atlas readability --out .atlas/readability.json
  node <repo-atlas>/qa/readability/calibrate/semantic-build.mjs --n 18
  bash <repo-atlas>/qa/readability/calibrate/semantic-run.sh 2
  node <repo-atlas>/qa/readability/calibrate/semantic-score.mjs
  ```

RelayOS 18 文件 ×2 pass 的第一份本地重测成绩：naming exact agreement=77.8%、MAE=0.22、ρ=0.553；comment coherence exact agreement=92.3%、MAE=0.08，但因一轮零方差，ρ 不可定义。该样本证明 runner 能工作，也暴露了 ceiling effect；**没有 `semantic-labels.json` 的人类标注就没有人类对齐 ρ，当前不能称“语义层已校准”**。

**下一步**：完成人类 `semantic-labels.json`，再决定语义分是否值得进入报告头；viewer 内嵌可读性页（目前走 artifacts 侧栏）；语义分与机械分并排报告。明确不做 CI 硬门、绝对分与 LLM overall 总分。

## 6. 参考文献（按主题）

- 可读性模型：Buse & Weimer [TSE 2010](https://docslib.org/doc/2568628/learning-a-metric-for-code-readability-raymond-p-l)；Scalabrino et al. [JSEP 2018](https://www.cs.wm.edu/~denys/pubs/JSEP'18-ReadabilityPaper.pdf)、[ICPC 2016](https://www.researchgate.net/publication/301685380)；[Combined Metrics Matter 复分析](https://ui.adsabs.harvard.edu/abs/2018msr..conf...61T/abstract)
- 综述：[Oliveira et al. ICSME 2020](https://paperswithcode.com/paper/evaluating-code-readability-and-legibility-an)（人本实验 54 篇）；[Oliveira et al. JSS 2023](https://arxiv.org/pdf/2208.12141.pdf)（格式元素 SLR）
- 命名：[Binkley et al. 2009](http://www.cs.loyola.edu/~binkley/papers/icpc09-clouds.pdf) / [EMSE 2013](https://www.cs.kent.edu/~jmaletic/papers/EMSE12.pdf)；[Arnaoudova et al. 2013](https://www.ptidej.net/publications/documents/CSMR13d.doc.pdf)；[Allamanis et al.](https://www.bcs.org/media/2406/dd-natural-coding-conventions.pdf)；Lin et al. SCAM 2017（[作者主页](https://sscalabrino.github.io/)）
- 注释：[Börstler & Paech TSE 2016](https://dblp.org/db/journals/tse/tse42)；[密度统计（Spinellis 文内转述）](https://www.spinellis.gr/pubs/conf/2016-ICSE-ProgEvol/html/SLK16.html)
- 版式：[Bauer et al. 2019](https://www.se.cs.uni-saarland.de/publications/docs/Bauer19.pdf)；[2023 RCT](https://www.scitepress.org/Papers/2023/120875/120875.pdf)；[Miara 1983 转述](https://chuniversiteit.nl/papers/how-many-spaces-should-you-indent)
- 复杂度：[Wyrich et al. 2020 元分析](https://arxiv.org/abs/2007.12520)；[cyclomatic vs cognitive 2023](https://arxiv.org/pdf/2303.07722v1.pdf)；[Johnson et al. ICSME 2019](https://www.semanticscholar.org/paper/An-Empirical-Study-Assessing-Source-Code-in-Johnson-Lubo/4e63ff35c69adaedb6c9bb2fbe15c1ab7a84efce) + [2024 眼动复现](https://link.springer.com/article/10.1007/s10664-024-10532-x)；[SonarSource cognitive complexity](https://www.sonarsource.com/blog/cognitive-complexity-because-testability-understandability/)
- 自然性：[Casalnuovo et al. 2019](https://arxiv.org/abs/1910.03704)
- 克隆：[van Bladel & Demeyer SANER 2020](https://www.conference-publishing.com/toc/SANER20&Full=abs)
- 类型：[Hanenberg 2010 转述](https://neverworkintheory.org/tex/nwit.pdf)；[Kleinschmager et al. ICPC 2012](https://pleiad.cl/papers/2012/kleinschmagerAl-icpc2012.pdf)
- LLM 时代：[Human-Aligned LLM Assessment](https://arxiv.org/html/2510.16579v1)；[Atlassian HULA](https://ar5iv.org/html/2501.11264)；[The Readability Spectrum](https://arxiv.org/html/2605.13280v1)
- 边界：[范式退化案例](https://ar5iv.labs.arxiv.org/html/2110.15246)；[开发者共识上限](https://arxiv.org/pdf/2407.03790)；[代理指标可靠性 2026](https://arxiv.org/html/2605.23008v1)
