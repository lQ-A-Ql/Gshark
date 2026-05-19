# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round27）

## 一、本轮目标

本轮重点解决 round26 报告列出的五个遗留问题，并继续保留既定方向：不引入深色模式，以 MISC 页面为全站视觉准线，优先用共享组件降低旧工具页重复实现。

目标是：

- 将工控与车机页面的本地 `Panel` / `StatCard` 等重复 UI 迁移到共享分析组件。
- 扩展 `AnalysisPrimitives`，覆盖条形图、列表、通用表格、提示块、小统计卡和风险标签。
- 对 Workspace、USB、媒体流还原、附件提取、威胁狩猎中心补齐 MISC 风格协调基线。
- 继续强化浏览器拖拽屏蔽，补显式 drop zone 白名单与安装/清理测试。
- 固定执行浅色模式残留扫描，确保没有 `dark:` 或 dark 主题分支回流。

## 二、本轮复核评论

round26 已经修复页面原生拖拽没有完全屏蔽的问题，并抽出第一版 `AnalysisPrimitives`。继续复核后，本轮确认：

1. 工控、车机、USB、媒体流页面仍保留本地 `StatCard`、`Panel`、`BucketChart` 等重复实现，样式虽然接近，但维护上会再次分叉。
2. `AnalysisPrimitives` 缺少条形图、数据表、列表项、提示块和风险标签等高频结构，导致页面迁移只能停留在部分壳层。
3. Workspace、USB、媒体流、附件、威胁狩猎中心之间仍存在背景、卡片透明度、阴影层级不一致的问题。
4. round26 的拖拽测试只覆盖拦截函数本身，尚未验证安装到 DOM 捕获阶段后的真实事件表现。
5. 如果未来设计拖拽导入 PCAP，需要一个明确白名单入口，而不是拆掉全局默认拖拽屏蔽。

因此本轮按“先共享、再迁移、再验证”的顺序推进。

## 三、本轮开发内容

### 1. 扩展共享分析页 UI 基元

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\analysis\AnalysisPrimitives.tsx
```

完成：

- `AnalysisTone` 导出，统一 amber、blue、cyan、emerald、rose、slate、violet 主题口径。
- 新增 `AnalysisMiniStat`，覆盖页面内嵌小统计卡。
- 新增 `AnalysisBadge`，为风险等级、状态标签等高频胶囊标签提供统一样式。
- 新增 `AnalysisCallout`，统一提示块、告警说明、规则说明的浅色卡片表达。
- 新增 `AnalysisBucketChart`，替代多个页面重复的条形图实现。
- 新增 `AnalysisList`，替代重复的 conversation/list bucket 实现。
- 新增 `AnalysisDataTable`，提供通用浅色圆角表格容器。

当前收益：

- 共享组件从“统计卡/面板/空状态”扩展为一套可覆盖多数旧工具页的分析页基元。
- 后续迁移页面时不需要继续复制 Tailwind 样式。
- 风格统一从“页面作者自觉遵守”变为“组件默认约束”。

### 2. 工控与车机页面迁移到共享组件

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\IndustrialAnalysis.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\VehicleAnalysis.tsx
```

完成：

- 工控页移除本地 `StatCard`、`Panel`、`BucketChart`、`ConversationList`、`DataTable`。
- 车机页移除本地 `StatCard`、`MiniStat`、`Panel`、`BucketChart`、`ConversationList`、`DataTable`。
- 两页统一使用 `AnalysisStatCard`、`AnalysisPanel`、`AnalysisBucketChart`、`AnalysisList`、`AnalysisDataTable`、`AnalysisMiniStat`。
- 保留业务专用的 `CanIdDataBoard`，避免把 CAN ID 数据区硬抽象成无语义表格。

当前收益：

- 工控与车机页面不再维护重复 UI 壳层。
- 两个垂直行业分析页在卡片、条形图、表格和空状态层面更接近 MISC 的浅色工作台风格。
- 业务逻辑、缓存、接口调用、刷新、中断逻辑未改动。

### 3. USB 与媒体流页面同步吃共享组件

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UsbAnalysis.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MediaAnalysis.tsx
```

完成：

- USB 页移除本地 `StatCard`、`Panel`、`BucketChart`。
- 媒体流页移除本地 `StatCard`、`Panel`、`BucketChart`。
- 两页统一接入共享分析页组件。
- USB 页面外壳增加 cyan 浅色渐变背景。
- 媒体流页面外壳增加 rose 浅色渐变背景。

当前收益：

- USB 与媒体流页面进入同一套共享分析页视觉语法。
- 保留 USB 的键盘重放、鼠标轨迹、热区图、Mass Storage 表格等复杂业务结构。
- 保留媒体流播放、导出、批量语音转写、转写汇总等业务流程。

### 4. Workspace、附件、威胁狩猎中心风格协调

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\Workspace.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\ObjectExport.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\ThreatHunting.tsx
```

完成：

- Workspace 保留高密度抓包工作台布局，但页面背景改为浅色蓝系渐变。
- Workspace 标题栏、过滤器区、预加载区、筛选加载空态改为白色半透明和柔和阴影。
- 附件提取页增加 amber 浅色背景，列表容器改为大圆角白色半透明卡片。
- 附件提取对象卡片、后缀标签、底部导出条统一为浅色工作台质感。
- 威胁狩猎中心增加 blue 浅色背景，与已有白色卡片结构更协调。

当前收益：

- Workspace 没有牺牲信息密度，但视觉上不再像旧式纯白后台。
- 附件提取页从传统文件网格更接近 MISC 式工具模块。
- 威胁狩猎中心与 C2/APT/MISC 的白色玻璃卡片语言更统一。

### 5. 拖拽屏蔽补白名单与真实事件测试

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.test.ts
```

完成：

- 新增 `installBrowserPageDragGuard()`，集中安装和清理 `dragstart` / `dragover` / `drop` 捕获阶段监听。
- `preventBrowserPageDrag()` 支持显式白名单：位于 `data-gshark-drop-zone="true"` 内的事件不再被全局 guard 拦截。
- 保持默认策略：未标记区域全部屏蔽浏览器原生拖拽。
- 测试从单纯验证 helper 扩展为：
  - 默认事件会执行 `preventDefault()` / `stopPropagation()`。
  - 显式 drop zone 不会被拦截。
  - 安装到 DOM 捕获阶段后，真实 `dragstart` 会被阻止。
  - cleanup 后事件不再被 guard 影响。

当前收益：

- 当前仍解决用户截图中的页面拖拽问题。
- 未来如果要做 PCAP 拖拽导入，可以只在明确 drop zone 上添加 `data-gshark-drop-zone="true"`，不需要拆全局防护。
- 测试更接近真实浏览器事件路径。

## 四、验证结果

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
```

结果：

- 通过。

已执行浅色模式残留扫描：

```powershell
Get-ChildItem -Path frontend/src -Recurse -Include *.tsx,*.ts,*.css | Select-String -Pattern '\bdark\b|dark:'
```

结果：

- 通过，未发现 `dark:` 或 dark 主题分支残留。

已执行重复本地组件扫描：

```powershell
Select-String -Path frontend/src/app/pages/IndustrialAnalysis.tsx,frontend/src/app/pages/VehicleAnalysis.tsx,frontend/src/app/pages/UsbAnalysis.tsx,frontend/src/app/pages/MediaAnalysis.tsx -Encoding UTF8 -Pattern '^function StatCard|^function Panel|^function BucketChart|^function DataTable|^function ConversationList|^function MiniStat'
```

结果：

- 通过，目标页面中已不再保留这些本地重复 UI 函数。

## 五、当前收益

- round26 的五个遗留问题本轮均有代码层推进。
- 共享分析页组件覆盖面明显扩大，旧工具页后续迁移成本降低。
- 工控、车机、USB、媒体流的通用 UI 壳层已经统一到共享组件。
- Workspace、附件、威胁狩猎中心完成页面外壳风格协调，仍保留原业务密度。
- 拖拽屏蔽既保持默认强保护，也为未来受控 drop zone 留出口。
- 本轮继续保持浅色单主题，没有引入深色模式。

## 六、遗留与下一轮建议

### 遗留问题

1. USB、媒体流、附件、威胁狩猎中心内部仍有业务专用表格和复杂可视化，后续可逐个迁移到 `AnalysisDataTable` 或专用共享组件。
2. `AnalysisDataTable` 当前是通用表格壳层，尚未支持列宽、单元格 className、虚拟滚动等更复杂需求。
3. Workspace 的 `PacketVirtualTable`、协议树、Hex 视图仍是高密度旧工作台组件，下一轮需要专项制定“高密度 MISC 风格”而不是简单套卡片。
4. `AnalysisBadge` 已新增但尚未大规模替换页面内已有等级标签，后续可优先替换工控规则等级、威胁狩猎等级、WebShell 置信度标签。
5. 拖拽屏蔽已补 DOM 事件测试，但仍未做浏览器级截图/交互验证；如后续引入 E2E，可补真实拖拽视觉回归。

### 下一轮建议

1. 将工控规则命中、威胁狩猎命中、Payload/WebShell 置信度标签迁移到 `AnalysisBadge`。
2. 为 `AnalysisDataTable` 增加列配置能力，替代更多手写 table。
3. 继续拆 Workspace：先从过滤器状态条、加载空态、协议树容器和 Hex 容器做共享化。
4. 对附件提取和媒体流的内部文件/会话卡片继续做 MISC 风格统一。
5. 如果要恢复拖拽导入，先设计显式 drop zone，再使用 `data-gshark-drop-zone="true"` 接入，不恢复浏览器默认拖拽。
