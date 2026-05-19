# 日期: 2026-04-30
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round29）

## 一、本轮目标

本轮延续 round28 的共享组件落地路线，在保留原计划的基础上增加两项收束工作：

- 删除一批低风险、可证明等价的前端冗余代码。
- 将 docs 下分散的开发报告按方向合并为更易交接的分类摘要。

本轮不改动协议算法、不删除历史逐轮报告、不引入深色模式。

## 二、本轮复核评论

复查前端代码后，C2 与 APT 页面仍存在一组重复 UI helper：

1. `C2Analysis.tsx` 内维护本地 `StatCard`、`BucketList`、`ConversationList`。
2. `AptAnalysis.tsx` 内维护本地 `StatCard`、`MiniMetric`、`BucketList`。
3. 上述组件与已经新增的 `MetricCard`、`AnalysisMiniStat`、`AnalysisBucketChart`、`AnalysisList` 职责重叠。
4. 重复组件主要差异是空状态文案和页面默认图标，适合通过共享组件参数承接，而不是继续复制实现。

复查 docs 后，当前报告已形成多条主线：

1. C2 / APT 能力迭代报告。
2. 前端设计与页面协调报告。
3. 协议专项与 MISC 工具箱报告。
4. 车机 / 工控方向方案与旧工具页对齐记录。

因此本轮选择先“合并入口”，保留原始逐轮报告作为审计轨迹。

## 三、本轮开发内容

### 1. 扩展共享分析组件

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\analysis\AnalysisPrimitives.tsx
```

完成：

- `AnalysisBucketChart` 增加 `emptyText` 参数。
- `AnalysisList` 增加 `emptyText` 参数。
- 桶图和列表中的计数统一使用 `toLocaleString()`。

当前收益：

- 页面可以保留原有业务空状态文案，不再为了文案差异维护本地桶图/列表。
- C2、APT、工控、车机等页面的分布展示继续向同一共享组件收敛。

### 2. 清理 C2 页面冗余 helper

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx
```

完成：

- 指标卡从本地 `StatCard` 改为直接使用 `MetricCard`。
- Family 分布、Channel 分布、指标类型改为 `AnalysisBucketChart`。
- 会话概览改为 `AnalysisList`。
- 删除本地 `StatCard`、`BucketList`、`ConversationList`。
- 保留 `C2Panel` 作为 C2 页面默认图标的语义封装。

当前收益：

- C2 页面减少一组通用 UI 复制实现。
- 分布图和列表的空状态文案由共享组件承接。
- 页面仍保持原来的 C2 业务结构、证据表、聚合详情和数据请求逻辑。

### 3. 清理 APT 页面冗余 helper

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\AptAnalysis.tsx
```

完成：

- 顶部指标卡从本地 `StatCard` 改为直接使用 `MetricCard`。
- 画像概览小指标从本地 `MiniMetric` 改为 `AnalysisMiniStat`。
- 样本家族、投递阶段、传输特征、基础设施、C2 技术证据来源改为 `AnalysisBucketChart`。
- 删除本地 `StatCard`、`MiniMetric`、`BucketList`。
- 保留 `AptPanel` 作为 APT 页面默认图标的语义封装。

当前收益：

- APT 页面减少一组通用 UI 复制实现。
- 页面风格继续贴近 MISC 准线和共享分析组件。
- 不改变 APT 证据过滤、归因解释、时间线和数据请求逻辑。

### 4. 分类合并开发文档

新增文件：

```text
C:\Users\QAQ\Desktop\gshark\docs\audit-development-report-archive-2026-04-30\merged-frontend-design-development-summary-2026-04-30.md
C:\Users\QAQ\Desktop\gshark\docs\audit-development-report-archive-2026-04-30\merged-c2-apt-development-summary-2026-04-30.md
C:\Users\QAQ\Desktop\gshark\docs\audit-development-report-archive-2026-04-30\merged-protocol-misc-development-summary-2026-04-30.md
C:\Users\QAQ\Desktop\gshark\docs\audit-development-report-archive-2026-04-30\merged-vehicle-industrial-development-summary-2026-04-30.md
```

完成：

- 按前端设计、C2/APT、协议/MISC、车机/工控四个方向建立合并摘要。
- 原始逐轮报告继续保留，合并摘要只作为快速阅读入口。
- 合并摘要中同步记录当前缺陷和下一步建议，方便后续继续按方向推进。

## 四、验证结果

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
```

结果：

- 通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm test
```

结果：

- 通过，12 个测试文件、47 个测试全部通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm run build
```

结果：

- 通过，Vite production build 成功。

已执行冗余 helper 扫描：

```powershell
Get-ChildItem -Path frontend/src/app -Recurse -Include *.tsx,*.ts |
  Select-String -Pattern '^function StatCard|^function Panel|^function BucketList|^function ConversationList|^function MiniMetric'
```

结果：

- C2/APT 页面不再出现本轮清理的重复 helper。
- 仅 `CaptureMissionControl.tsx` 仍保留局部 `StatCard`，该组件承担任务控制台布局语义，本轮暂不强行迁移。

已执行浅色主题分支扫描：

```powershell
Get-ChildItem -Path frontend/src -Recurse -Include *.tsx,*.ts,*.css |
  Select-String -Pattern '\bdark\b|dark:'
```

结果：

- 通过，未发现 `dark` / `dark:` 主题分支残留。

已执行空白检查：

```powershell
git diff --check -- <本轮触碰文件>
```

结果：

- 通过。

说明：

- 本轮未改动后端协议逻辑，因此未额外运行后端 `go test`。

## 五、当前收益

- C2/APT 页面删除了可证明等价的重复 UI 代码。
- 共享分析组件获得更实用的空状态文案扩展。
- 页面视觉继续向 MISC 准线收束，未引入深色模式分支。
- docs 从“逐轮报告堆叠”升级为“逐轮报告 + 分类合并入口”。
- 后续接手者可以先读四个合并摘要，再按需回看原始报告。

## 六、遗留与下一轮建议

### 遗留问题

1. `CaptureMissionControl.tsx` 仍保留局部 `StatCard`，需要确认是否适合迁移到 `MetricCard`。
2. C2 / APT 页面仍有复杂手写 table 和展开详情面板，需要更强的共享数据表能力后再迁移。
3. `AnalysisDataTable` 仍缺少列宽、cell class、展开行和 actions slot 配置。
4. 部分代码/JSON/Hex 预览使用深色代码块，应继续区分“功能性代码预览”与“深色主题残留”。
5. 合并摘要是人工归纳入口，后续若新增大量报告，应持续维护分类索引。

### 下一轮建议

1. 增强 `AnalysisDataTable`，优先迁移工控规则表、威胁狩猎命中表、APT 证据表。
2. 复查 `CaptureMissionControl` 是否能安全复用 `MetricCard` 和 `StatusHint`。
3. 对 `bg-slate-950`、`bg-black`、`text-white` 做人工分类清理，避免误删代码预览的有效对比。
4. 把 MISC 模块 manifest 的 `cancellable`、`requires_capture`、`supports_export` 能力显示为统一徽标。
5. 继续维护 docs 分类摘要，让开发报告从流水账逐步变成方向型知识库。
