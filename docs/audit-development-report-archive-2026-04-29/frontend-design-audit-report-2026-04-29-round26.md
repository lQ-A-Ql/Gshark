# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round26）

## 一、本轮目标

本轮继续保留 round25 的原计划：以 MISC 页面为视觉准线，逐步统一旧工具页的页面层次、卡片风格、交互反馈和浅色单主题表达。同时针对用户截图反馈的已知问题进行修复复核：页面拖拽行为仍未被完全屏蔽。

目标是：

- 修复浏览器页面/元素原生拖拽仍可触发的问题，而不影响按钮式导入、文件选择、导出等现有流程。
- 继续推进旧工具页风格对齐，将上一轮在流量图页面内沉淀的样式抽成共享分析页 UI 基元。
- 保持浅色单主题，不引入深色模式，不保留 `dark:` variant。
- 继续按“复查、优化、报告”的节奏记录本轮发现、修改与遗留。

## 二、本轮复核评论

round25 已经在全局布局层加入 `dragover` / `drop` 拦截，用于避免用户误拖文件到浏览器后触发打开文件或页面跳转。但复查用户截图和浏览器默认行为后，本轮确认该处理仍有缺口：

1. `dragover` / `drop` 主要阻止“拖入页面后释放”的默认导航，不能覆盖元素自身发起拖拽的 `dragstart`。
2. 页面内的图片、链接、SVG、按钮等元素仍可能参与浏览器原生拖拽，表现为页面内容被拖起、出现半透明拖拽影像或拖拽光标。
3. 仅在 `window` 层监听仍不够稳妥，复杂组件树内的事件可能先被内部节点处理，因此需要补充捕获阶段和根容器级兜底。
4. 旧工具页风格对齐后，`TrafficGraph`、工控、车机等页面开始出现重复的白色半透明卡片、统计卡和空状态样式，适合先抽一组小而稳的共享组件。

因此本轮选择两个低风险优化点：完整补齐拖拽屏蔽链路，并先从 `TrafficGraph` 迁移到共享分析页 UI 基元。

## 三、本轮开发内容

### 1. 完整屏蔽浏览器页面拖拽默认行为

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\styles\theme.css
C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.test.ts
```

完成：

- 新增并导出 `preventBrowserPageDrag`，统一执行 `preventDefault()` 和 `stopPropagation()`。
- 在 `window` 捕获阶段监听 `dragstart`、`dragover`、`drop`。
- 在 `document` 捕获阶段同步监听 `dragstart`、`dragover`、`drop`，增强对组件内部事件的兜底能力。
- 在 `MainLayout` 根容器补充 React 捕获阶段处理：`onDragStartCapture`、`onDragOverCapture`、`onDropCapture`。
- 在全局 CSS 中对 `body`、`#root`、`img`、`a`、`svg`、`button` 增加 `-webkit-user-drag: none` 与 `user-drag: none`。
- 增加单元测试，验证拖拽拦截函数会同时调用 `preventDefault` 和 `stopPropagation`。

当前收益：

- 修复了 round25 只处理 `dragover/drop` 导致 `dragstart` 仍可触发的缺口。
- 页面内图片、链接、按钮等元素不再轻易触发浏览器原生拖拽影像。
- 仍保留现有按钮式导入入口，不把“禁止浏览器默认拖拽”误做成“禁止用户打开文件”。

### 2. 抽取共享分析页 UI 基元

新增文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\analysis\AnalysisPrimitives.tsx
```

完成：

- 新增 `AnalysisStatCard`，承载旧工具页常见的统计数字卡片。
- 新增 `AnalysisPanel`，承载白色半透明大圆角面板、标题区、操作区和 hover 阴影。
- 新增 `AnalysisEmptyState`，统一图表/列表无数据时的浅色虚线空状态。
- 提供 `amber`、`blue`、`emerald`、`slate` tone，用于兼容流量图、工控、车机等不同工具页主题色。

当前收益：

- 将 round25 中散落在页面内部的 MISC 风格表达开始沉淀为可复用基元。
- 后续迁移工控、车机、媒体流、USB、附件提取时可以减少重复样式和复制粘贴。
- 共享组件保持轻量，不绑定业务数据结构，适合作为旧工具页逐步统一的第一层。

### 3. 流量图页面迁移到共享基元

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TrafficGraph.tsx
```

完成：

- `TrafficGraph` 不再维护本地 `StatCard` / `Panel` / `EmptyState` 样式实现。
- 统计区迁移为 `AnalysisStatCard`。
- 图表面板迁移为 `AnalysisPanel`。
- 空状态迁移为 `AnalysisEmptyState`。
- 移除迁移后不再使用的 `ReactNode` import。

当前收益：

- 流量图页面仍保持 round25 的 amber 浅色风格，但结构更清晰。
- 页面级代码减少重复 UI 定义，后续更适合继续抽取 `AnalysisBucketChart` / `AnalysisDataTable`。
- 本轮没有改动图表点击、过滤器跳转、数据获取和错误处理逻辑。

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
- `npm test`：通过，12 个测试文件、44 项测试通过。
- `npm run build`：通过。

已执行浅色模式残留扫描：

```powershell
Get-ChildItem -Path frontend/src -Recurse -Include *.tsx,*.ts,*.css | Select-String -Pattern '\bdark\b|dark:'
```

结果：

- 通过，未发现 `dark:` 或 dark 主题分支残留。

已执行本轮触碰文件局部格式检查：

```powershell
git diff --check -- frontend/src/app/layouts/MainLayout.tsx frontend/src/styles/theme.css frontend/src/app/components/analysis/AnalysisPrimitives.tsx frontend/src/app/pages/TrafficGraph.tsx frontend/src/app/layouts/MainLayout.test.ts
```

结果：

- 通过。

## 五、当前收益

- 用户反馈的页面拖拽问题已从“只挡释放阶段”升级为“发起、悬停、释放全链路拦截”。
- 拖拽屏蔽同时落在 window、document、React 根容器和 CSS 四层，覆盖面更稳。
- 旧工具页风格统一开始从“逐页改样式”转向“共享分析页基元”，后续维护成本更低。
- `TrafficGraph` 已完成第一批共享组件迁移，可作为工控、车机继续迁移的参照。
- 本轮仍保持浅色单主题，没有新增深色模式代码。

## 六、遗留与下一轮建议

### 遗留问题

1. `IndustrialAnalysis.tsx` 与 `VehicleAnalysis.tsx` 仍保留本地 `Panel`、`StatCard`、`BucketChart`、`DataTable`，需要继续迁移到共享分析页组件。
2. `AnalysisPrimitives` 当前只覆盖统计卡、面板、空状态，尚未覆盖条形图、数据表、列表项、风险标签等高频结构。
3. 全局拖拽当前采取完全屏蔽策略，后续如果要支持拖拽导入 PCAP，需要新增明确 drop zone，而不是恢复浏览器默认行为。
4. Workspace 主工作区、USB、媒体流还原、附件提取、威胁狩猎中心仍需要继续按 MISC 风格做协调统一。
5. 当前拖拽测试覆盖的是拦截函数本身，尚未使用浏览器级 E2E 验证真实 DOM 中 `dragstart` 的视觉表现。

### 下一轮建议

1. 将工控与车机页面的 `Panel` / `StatCard` 迁移到 `AnalysisPrimitives`。
2. 抽取 `AnalysisBucketChart`、`AnalysisDataTable`、`AnalysisListItem`，减少旧工具页重复实现。
3. 继续审查 USB、媒体流、附件提取和威胁狩猎中心，以 MISC 页面为准线统一页面外壳和空状态。
4. 为“禁止页面拖拽”补浏览器级交互验证，确认图片、链接、按钮和空白区域均不会触发原生拖拽影像。
5. 保持每轮固定执行 `dark:` 扫描，避免深色模式残留重新进入前端代码。
