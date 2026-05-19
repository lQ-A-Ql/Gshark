# 日期: 2026-04-30
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round28）

## 一、本轮目标

本轮延续 2026-04-29 round27 的遗留建议，重点不再继续增加新页面样式，而是推动上一轮新增的共享分析基元真实落地。目标是：

- 将 `AnalysisBadge` / `AnalysisCallout` 应用到真实业务页面，减少手写 badge / callout class。
- 优先替换工控分析、威胁狩猎中心中的风险等级、事务类型、运行状态等标签。
- 修复 Payload / WebShell 解码模块中仍偏暗色模式的输入框，使其回到浅色单主题。
- 继续保持 MISC 页面为视觉准线，不引入深色模式残留。

## 二、本轮复核评论

round27 已经扩展 `AnalysisPrimitives`，但复查后发现共享基元还没有充分落到页面内：

1. `IndustrialAnalysis.tsx` 仍保留 `kindBadge()`、`ruleLevelBadge()` 两个本地样式函数。
2. 工控页面的规则说明、可疑写操作说明、控制指令说明仍是手写 callout 样式。
3. `ThreatHunting.tsx` 仍保留 `levelColor()`，命中等级、运行状态、分类计数仍散落为手写 `rounded border ...`。
4. `PayloadWebShellDecoderModule.tsx` 的输入区使用 `bg-slate-950 text-slate-100`，视觉上接近深色模式块，与用户“不需要深色模式”的要求不一致。

因此本轮选择窄口径优化：把已经存在的共享组件真正用起来，并处理一个明确的浅色主题残留。

## 三、本轮开发内容

### 1. 工控分析页标签与提示块统一

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\IndustrialAnalysis.tsx
```

完成：

- 引入 `AnalysisBadge`、`AnalysisCallout` 与 `AnalysisTone`。
- 规则命中等级从 `ruleLevelBadge()` 迁移到 `AnalysisBadge`。
- Modbus 事务类型从 `kindBadge()` 迁移到 `AnalysisBadge`。
- 控制指令协议标签迁移到 `AnalysisBadge`。
- 规则检测说明、可疑写操作说明、控制指令说明迁移到 `AnalysisCallout`。
- 分析提示列表迁移到 `AnalysisCallout`。
- 删除 `kindBadge()` 与 `ruleLevelBadge()` 两个本地样式函数。

当前收益：

- 工控页风险等级与事务类型不再维护本地 badge class。
- 提示块视觉与共享分析页组件一致。
- 后续替换更多页面时有明确范式：业务只提供 tone，样式由共享组件接管。

### 2. 威胁狩猎中心等级与状态标签统一

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\ThreatHunting.tsx
```

完成：

- 引入 `AnalysisBadge` 与 `AnalysisTone`。
- 命中等级标签从 `levelColor()` 迁移到 `AnalysisBadge`。
- 威胁分析进度阶段标签迁移到 `AnalysisBadge`。
- 运行状态标签迁移到 `AnalysisBadge`。
- 分类卡片计数胶囊迁移到 `AnalysisBadge`。
- 删除 `levelColor()` 本地样式函数。

当前收益：

- 威胁狩猎中心的标签体系与工控页、MISC 工具箱更一致。
- 高风险 / 中风险 / 普通标签不再散落成字符串拼接。
- 后续可以继续把按钮、命中详情与表格容器纳入共享组件。

### 3. Payload / WebShell 解码模块浅色输入优化

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\PayloadWebShellDecoderModule.tsx
```

完成：

- 输入 textarea 从暗色 `bg-slate-950 text-slate-100` 改为浅色 `bg-white/95 text-slate-800`。
- 保留等宽字体、较高行距、内阴影和 focus ring，仍适合粘贴 HTTP 报文与编码 payload。
- “实验性 webshell 解码，需人工复核”标签迁移到 `AnalysisBadge tone="amber"`。

当前收益：

- MISC 解码模块不再出现明显暗色块。
- 安全工具感通过字体、边框、内阴影和焦点状态表达，而不是依赖深色输入区。
- 实验性风险提示和全站标签风格一致。

## 四、验证结果

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
```

结果：

- 通过。

已执行局部残留扫描：

```powershell
Select-String -Path frontend/src/app/pages/IndustrialAnalysis.tsx,frontend/src/app/pages/ThreatHunting.tsx,frontend/src/app/misc/modules/PayloadWebShellDecoderModule.tsx -Encoding UTF8 -Pattern 'levelColor|ruleLevelBadge|kindBadge|bg-slate-950|text-slate-100|rounded border border-blue-200 bg-blue-50 px-1.5'
```

结果：

- 通过，未发现本轮目标残留。

已执行浅色模式残留扫描：

```powershell
Get-ChildItem -Path frontend/src -Recurse -Include *.tsx,*.ts,*.css | Select-String -Pattern '\bdark\b|dark:'
```

结果：

- 通过，未发现 `dark:` 或 dark 主题分支残留。

## 五、当前收益

- `AnalysisBadge` / `AnalysisCallout` 从“已创建”进入“业务页面真实使用”。
- 工控分析与威胁狩猎两个风险标签密集页面的局部样式重复减少。
- Payload / WebShell 解码工作台更符合浅色单主题。
- 本轮没有改动后端协议逻辑，也没有改变页面数据流。

## 六、遗留与下一轮建议

### 遗留问题

1. `IndustrialAnalysis.tsx` 中仍有部分大型手写 table，可继续迁移到支持列配置的 `AnalysisDataTable`。
2. `ThreatHunting.tsx` 的命中结果表和底部详情区仍是页面内手写结构，可继续抽成“命中表 + 详情抽屉/面板”共享模式。
3. `PayloadWebShellDecoderModule.tsx` 仍以输入 + 工作台纵向堆叠为主，后续可优化为候选区、配置区、结果区三段式布局。
4. `AnalysisBadge` 当前只支持 tone，不支持 size / variant；如果继续覆盖更多页面，可能需要增加 `size="xs|sm"` 和 `shape="pill|soft"`。
5. 仍需继续检查全站是否存在非 `dark:` 但视觉上偏深色模式的局部块，例如代码区、Hex 区、预览区。

### 下一轮建议

1. 为 `AnalysisDataTable` 增加列宽和 cell class 配置，优先迁移工控规则表、Modbus 事务表和威胁狩猎命中表。
2. 将 Payload / WebShell 解码模块布局升级为更清晰的三栏或分段工作台。
3. 扫描全站 `bg-slate-9xx`、`bg-black`、`text-white` 等暗色视觉残留，区分“代码/Hex 合理深色”与“主题残留”。
4. 继续以 MISC 页面为准线，对附件提取、媒体流、USB 内部卡片做更细粒度统一。
