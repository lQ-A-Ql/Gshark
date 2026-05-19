# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round25）

## 一、本轮目标

本轮继续保留 round24 的原计划：以 MISC 页面为视觉准线，逐步统一旧工具页的页面层次、卡片风格和交互手感。同时新增一个全局体验要求：屏蔽浏览器拖拽页面导致文件打开或跳转的默认行为。目标是：

- 将流量图、工控分析、车机分析三类旧工具页向 MISC 的浅色工作台风格对齐。
- 优先改页面外壳、统计卡、通用面板、图表空状态和表格容器，不改业务数据逻辑。
- 在全局布局层屏蔽 `dragover` / `drop` 默认导航。
- 不引入深色模式，不保留 dark variant。

## 二、本轮复核评论

round24 已经把 HTTP / TCP / UDP 流追踪页向 MISC 风格收敛，并抽出了 `StreamCurrentChunkPanel`。继续复核旧工具页后，本轮发现：

1. `TrafficGraph.tsx`、`IndustrialAnalysis.tsx`、`VehicleAnalysis.tsx` 仍使用旧式 `rounded-xl border-border bg-card shadow-sm` 卡片，与 MISC 的白色半透明大圆角卡片存在明显割裂。
2. 三类旧工具页都在本地定义 `Panel`、`StatCard`、`BucketChart`、`DataTable` 等结构，适合先通过本地组件样式统一快速提升一致性。
3. 浏览器默认拖拽行为存在体验风险：用户误拖文件到页面时，浏览器可能尝试打开文件或跳转，容易打断当前分析状态。

因此本轮选择窄口径优化：保留数据流和接口调用，优先完成风格统一与全局拖拽拦截。

## 三、本轮开发内容

### 1. 流量图页面风格对齐

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TrafficGraph.tsx
```

完成：

- 页面外壳增加 amber 主题浅色渐变和顶部光晕。
- `StatCard` 改为大圆角、白色半透明、柔和阴影、uppercase 小标签和更强数字层级。
- `Panel` 改为 MISC 风格大圆角白卡、顶部标题分割线和 hover 阴影。
- `SimpleBarChart` 的空状态、行 hover、进度条圆角和文字层级统一为浅色工作台风格。
- loading / error 提示改为半透明圆角提示卡。

当前收益：

- 流量图从“传统后台统计块”更接近“MISC 式分析工作台”。
- 仍保留原有点击图表跳转过滤器行为。
- 全局视图在视觉上与 MISC、流追踪页的最新风格更一致。

### 2. 工控分析页面风格对齐

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\IndustrialAnalysis.tsx
```

完成：

- 页面外壳增加 blue 主题浅色渐变和顶部光晕。
- `StatCard` / `Panel` 迁移为白色半透明大圆角卡片。
- `BucketChart` 使用圆角条、slate 浅色背景和更统一的文本层级。
- `ConversationList` 改为浅色胶囊式列表项。
- `DataTable` 改为圆角表格容器、浅色 sticky 表头和 hover 行反馈。
- loading / error 提示改为 MISC 风格提示卡。

当前收益：

- 工控页的高密度表格仍保持可读，同时视觉不再像老式面板堆叠。
- 后续如果抽共享 `AnalysisPanel` / `AnalysisStatCard`，工控页已经具备可迁移的目标样式。

### 3. 车机分析页面风格对齐

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\VehicleAnalysis.tsx
```

完成：

- 页面外壳增加 emerald 主题浅色渐变和顶部光晕。
- `StatCard` / `MiniStat` / `Panel` 统一为 MISC 方向的浅色圆角卡片。
- `BucketChart`、`ConversationList`、`DataTable` 同步浅色化、圆角化和阴影层级。
- loading / error 提示改为半透明提示卡。

当前收益：

- 车机页与工控页形成更一致的“垂直行业分析页”视觉结构。
- DBC、CAN、J1939、DoIP、UDS 等大量卡片不再与 MISC/流追踪的现代化风格割裂。

### 4. 全局屏蔽浏览器拖拽页面默认行为

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.tsx
```

完成：

- 在 `MainLayout` 中增加 window 级 `dragover` / `drop` 监听。
- 对拖拽事件执行 `preventDefault()` 和 `stopPropagation()`。
- 组件卸载时移除监听。

当前收益：

- 用户误拖文件、文本或链接到页面时，不会触发浏览器默认打开/跳转。
- 统一在全局布局入口处理，不需要每个工具页重复拦截。
- 不影响现有“打开文件”“导入 DBC”“导入模块 ZIP”等按钮式导入流程。

## 四、验证结果

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
npm test
npm run build
```

结果：

- `npx tsc --noEmit --noUnusedLocals --noUnusedParameters`：通过。
- `npm test`：通过，11 个测试文件、43 项测试通过。
- `npm run build`：通过。

已执行浅色模式残留扫描：

```powershell
Get-ChildItem -Path frontend/src -Recurse -Include *.tsx,*.ts,*.css | Select-String -Pattern '\bdark\b|dark:'
```

结果：

- 通过，未发现 `dark:` 或 dark 主题分支残留。

已执行本轮触碰文件局部格式检查：

```powershell
git diff --check -- frontend/src/app/pages/TrafficGraph.tsx frontend/src/app/pages/IndustrialAnalysis.tsx frontend/src/app/pages/VehicleAnalysis.tsx frontend/src/app/layouts/MainLayout.tsx
```

结果：

- 通过。

## 五、当前收益

- MISC 作为全站设计准线的影响范围从流追踪扩展到流量图、工控、车机三类旧工具页。
- 旧工具页保留原业务逻辑，仅通过页面外壳和本地 UI 基元获得更统一的视觉层级。
- 浏览器拖拽默认导航已在全局布局层屏蔽，降低误操作打断分析的风险。
- 本轮仍保持浅色单主题，没有引入 dark variant。

## 六、遗留与下一轮建议

### 遗留问题

1. `TrafficGraph`、`IndustrialAnalysis`、`VehicleAnalysis` 仍各自维护本地 `Panel`、`StatCard`、`BucketChart`、`DataTable`，下一步可抽为共享 `AnalysisPanel` / `AnalysisStatCard` / `AnalysisDataTable`。
2. 工控和车机页面内部仍有部分手写表格块没有完全走 `DataTable`，视觉已改善但结构仍可继续收敛。
3. Workspace 主工作区仍偏传统 packet workbench，需要单独评估如何在不降低密度的情况下对齐 MISC 风格。
4. USB、媒体流、附件提取、威胁狩猎中心仍需纳入同一设计协调 checklist。
5. 全局拖拽现在是完全屏蔽，后续若要支持拖拽打开 PCAP，需要设计明确的 drop zone，而不是恢复浏览器默认行为。

### 下一轮建议

1. 抽取共享分析页组件：`AnalysisPanel`、`AnalysisStatCard`、`AnalysisBucketChart`、`AnalysisDataTable`。
2. 继续以 MISC 为准线审查 USB、媒体流还原、附件提取和威胁狩猎中心。
3. 针对 Workspace 制定“高密度工作台版 MISC 风格”方案，避免简单套大卡片导致信息密度下降。
4. 为全局拖拽屏蔽补一个前端测试，验证 `dragover` / `drop` 默认行为被阻止。
5. 继续保留 dark 扫描作为每轮固定验证项。
