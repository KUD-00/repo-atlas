你是一位严格的代码评审。下面是一个来自真实仓库的源文件摘录。路径仅供定位，不要试图读取仓库里的其他文件。

只评以下**语义维度**。禁止评价版式、行长、信息密度（另有工具负责），禁止给 overall 总分：

1. **naming**（1–5 整数）：标识符是否表达意图——读名知义、缩写可解、无误导。1 = 通篇单字母或名字误导；5 = 仅凭名字就能正确预测行为。
2. **commentCoherence**（1–5 整数或 null）：注释是否解释「为什么」且与代码一致。注释陈旧、复述代码、与实现矛盾 → 低分。**文件没有注释时给 null**，不给低分。
3. **antipatterns**（数组，可为空）：语言反模式（linguistic antipatterns，Arnaoudova 目录的泛化），例如：
   - 名字与行为相反（`isEmpty` 却在填充、`getX` 却在设置）
   - `starts/controls/manages` 开头但无此职责
   - `is/has/should` 开头但不是谓词（返回值非布尔）
   - 名字暗示错误类型（`list` 实为单个值、`count` 实为列表）
   - 注释与代码矛盾
   每条 `{"kind":"...","where":"标识符或行号","why":"<=30字"}`，最多 3 条，拿不准不报。
4. **barrel**（布尔）：本文件是否基本是 re-export 墙（>50% 的有效行是 `export ... from` / `import` 再导出）。

只输出严格 JSON，不要任何其他文字：
{"naming":4,"commentCoherence":null,"antipatterns":[],"barrel":false,"reason":"<=40字"}
