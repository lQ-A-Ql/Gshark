# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round16）

## 一、本轮目标

本轮把工作重心从 C2/APT 检测能力继续推进到前端全站 UI/UX 一致性治理。目标不是重写所有页面，而是先建立可复用的前端设计收敛层，并优先修复用户多次反馈的高频痛点：

- MISC 页面仍存在卡片套卡片观感。
- C2 / APT 页面本地重复定义 `Panel`、`StatCard`、空态、表格壳，导致后续页面风格继续漂移。
- 折叠/展开动画各页各写一套，MISC 模块工作台应统一到共享过渡。
- 数据表滚动、空态、加载态需要有统一基线。
- 工作区与流追踪页后续必须继续保留白底专业工作台风格，本轮先不强行套专题页大卡片。

## 二、上一轮复核评论

round15 已经完成 C2 intervals 可视化与 APT 结构化评分，使 C2 / APT 两个专题页进入“可解释 + 可视化”阶段。但复核前端实现后发现，页面能力增长同时带来了 UI 维护债：

1. `C2Analysis.tsx` 与 `AptAnalysis.tsx` 都保留本地 `StatCard` / `Panel` 实现，样式与其它页面类似但不完全一致。
2. MISC 页面外层模块卡片和内部模块渲染之间仍有重复标题与视觉层级，尤其是 Payload WebShell 解码模块嵌入时仍显示完整内层标题卡。
3. 表格容器、空态、加载态分散实现，后续如果逐页手工调整会继续产生漂移。
4. 目前最合理的路线是先新增共享 UI 基础组件，再逐页迁移，而不是直接大规模重写所有页面。

## 三、本轮开发内容

### 1. 新增前端共享设计组件

新增文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
```

本轮新增组件：

- `SurfacePanel`
  - 统一页面主面板、section 面板、flat/subtle 内部分区。
  - 支持 `page / section / flat / subtle` 视觉层级。
  - 作为后续替换各页面本地 `Panel` 的基础。

- `MetricCard`
  - 统一统计卡片。
  - 支持 `slate / blue / cyan / emerald / amber / rose / indigo / violet` tone。
  - 用于逐步替换各页本地 `StatCard`。

- `StatusHint`
  - 统一加载、错误、提示状态。
  - 本轮已接入 C2 / APT / MISC。

- `EmptyState`
  - 统一空态与无数据状态。
  - 本轮已接入 C2 / APT 的主要空态。

- `DataTableShell`
  - 统一表格边框、内部滚动、最大高度。
  - 本轮已接入 C2 candidate table 与 APT evidence table。

- `CollapsibleContent`
  - 统一 grid-template-rows 折叠动画。
  - 本轮已接入 MISC 模块工作台展开/收起区域。

### 2. C2 样本分析页前端收敛

改造文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx
```

完成内容：

- 本地 `StatCard` 改为委托 `MetricCard`，统计卡片视觉进入共享基线。
- 本地 `Panel` 改为委托 `SurfacePanel`，后续其它页面可按同样模式迁移。
- 加载/错误提示改为 `StatusHint`。
- Family 分布、会话概览、Host/URI、DNS、VShell Stream、候选表、Notes 的空态逐步改为 `EmptyState`。
- Candidate table 外壳改为 `DataTableShell`，表格滚动从裸 `max-h + overflow-auto` 收敛到统一容器。

效果：

- C2 页面仍保持原有业务行为、缓存、AbortController 与证据联动不变。
- 视觉层级更稳定，表格滚动容器不再在页面里单独散写。
- 为后续继续迁移 DNS / stream 聚合详情表格打下基础。

### 3. APT 组织画像页前端收敛

改造文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\AptAnalysis.tsx
```

完成内容：

- 本地 `StatCard` 改为委托 `MetricCard`。
- 本地 `Panel` 改为委托 `SurfacePanel`。
- 加载/错误提示改为 `StatusHint`。
- Bucket 空态、Evidence table 空态、Notes 空态、无 actor profile 空态改为 `EmptyState`。
- Evidence table 外壳改为 `DataTableShell`，统一边框与滚动行为。

效果：

- APT 页面保留 actor tabs、Attribution Explainer、Evidence Timeline 与 Evidence source tabs 行为不变。
- 页面主面板与 C2 页面使用同一视觉基线。
- 表格壳统一后，后续可以继续将 Timeline 列表和 score factor 列表收敛到同一组件族。

### 4. MISC 工具箱卡片套卡片修正

改造文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\PayloadWebShellDecoderModule.tsx
```

完成内容：

- MISC 模块展开区域改用 `CollapsibleContent`，统一展开/收起动画。
- 展开内容顶部加入轻量分割线，减少“内层完整卡片”观感。
- MISC loading / empty 状态改用共享 `StatusHint` / `EmptyState`。
- Payload WebShell 解码模块在 `embedded` 模式下不再重复显示完整模块标题，而是显示 `手动 Payload 输入`。
- Payload WebShell 解码模块在 `embedded` 模式下移除内层重阴影，改为轻量 `slate-50` flat surface。

效果：

- MISC 外层模块标题与内层 payload 输入区语义分离。
- 用户截图中“外层 HTTP 登录行为分析卡片 + 内层同名大卡片”的问题，在后续模块按同样 embedded 规范迁移后可系统性消除。
- 当前 Payload/WebShell 入口已先完成扁平化处理。

## 四、验证结果

已执行前端验证：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit
npm test -- C2Analysis AptAnalysis MiscTools
npm run build
npm test
```

结果：

- `npx tsc --noEmit`：通过。
- `npm test -- C2Analysis AptAnalysis MiscTools`：3 个测试文件、22 项测试通过。
- `npm run build`：通过。
- `npm test`：11 个测试文件、43 项测试通过。

本轮未改动后端接口与数据结构，后端 round15 改动保持原样。

## 五、当前遗留与下一轮建议

### 仍需继续迁移的页面

下一轮建议继续按共享组件迁移以下页面：

1. `UsbAnalysis.tsx` / `VehicleAnalysis.tsx`
   - 仍有本地 `Panel` / `StatCard` 类模式。
   - 可优先替换为 `SurfacePanel` / `MetricCard`。

2. `IndustrialAnalysis.tsx` / `MediaAnalysis.tsx`
   - 表格与分区较多，适合接入 `DataTableShell` 与 `EmptyState`。

3. `ThreatHunting.tsx` / `ObjectExport.tsx`
   - 命中列表、对象列表、导出候选表应统一表格壳。

4. `Workspace.tsx` / `TcpStream.tsx` / `HttpStream.tsx` / `UdpStream.tsx`
   - 保持白底工作台，不套渐变专题卡片。
   - 后续单独设计 `WorkbenchTitleBar` 与白底 `WorkbenchSurface`。
   - 重点修复流追踪 payload 工作台越界、工具栏按钮分散、过滤器阻塞感。

### 下一轮建议优先级

1. 新增 `WorkbenchTitleBar`，先统一工作区与流追踪页标题/工具栏。
2. 将 USB / Vehicle / Industrial 的统计卡和主面板迁移到共享组件。
3. 将 Threat Hunting / Object Export 表格统一迁移到 `DataTableShell`。
4. 为 `DataTableShell` 增加可选 `empty / loading / error / actions` props，进一步减少页面重复代码。
5. 为所有 embedded MISC 模块制定统一规则：外层模块负责标题，内层模块只展示工作区与结果，不再重复完整标题卡。
