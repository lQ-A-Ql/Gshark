# 日期: 2026-04-30
# 署名: Codex

# 前端设计与交互开发合并摘要

## 一、合并范围

本文件按“前端设计与交互统一”方向合并 2026-04-29 round16 至 round27、2026-04-30 round28 至 round37 的主要开发结论。原始逐轮报告继续保留在归档目录中，本文件作为快速阅读与交接入口。

## 二、主线目标

- 以 MISC 页面为视觉准线，统一全站浅色单主题、柔和卡片、轻量阴影、渐变背景和圆角尺度。
- 移除深色模式分支与明显暗色主题残留，不再维护深色模式。
- 将流追踪页面从“功能堆叠页”收束为流还原、片段浏览、搜索、视图切换和当前片段预览。
- 将 Payload / WebShell 解码工作台迁移到 MISC，避免 HTTP/TCP/UDP 流追踪页面继续承载不稳定实验能力。
- 将旧工具页逐步迁移到共享设计组件，降低页面间样式割裂。
- 屏蔽浏览器默认拖拽页面行为，仅保留明确白名单输入控件的拖放能力。

## 三、已完成能力

### 1. 全局视觉基线

- `PageShell`、`AnalysisHero`、`DesignSystem`、`AnalysisPrimitives` 已成为主要共享层。
- 旧页面标题区、工作台标题栏、状态提示、指标卡、卡片面板、空状态、折叠内容、流导航和搜索条已逐步收束。
- 页面切换、背景色切换与卡片交互已加入更柔和的过渡，减少页面跳变感。
- MISC 页面作为浅色安全工具箱基线，影响流量图、工控、车机、媒体、USB、对象导出、威胁狩猎等旧工具页。

### 2. 流追踪页面

- HTTP/TCP/UDP 页面移除内嵌 Payload 解码工作台。
- 右侧保留“当前片段”预览，避免协议还原页面被实验性解码功能挤占。
- 搜索、高亮、流切换、视图模式和完整 payload 弹窗统一到共享组件。
- Payload / WebShell 的完整工作台迁移到 MISC 内建模块。

### 3. MISC 工具箱

- MISC 成为轻量工具与实验性分析能力入口。
- Payload / WebShell 解码模块支持手动粘贴 HTTP 报文、body、参数值、Base64、Hex 等输入。
- 解码结果表达补充置信度、警告、失败原因和实验性提示，避免把低置信结果误导为稳定解密。
- 输入区已从暗色块调整为浅色单主题。

### 4. 旧工具页风格对齐

- 流量图、工控、车机、媒体、USB、对象导出、威胁狩猎、C2、APT 等页面已逐步改为共享卡片、标签、提示块和桶图。
- 工控页和威胁狩猎页已用 `AnalysisBadge` / `AnalysisCallout` 替换部分本地标签函数。
- 车机和工控页与 MISC 的浅色卡片、柔和边框、轻量阴影保持一致。

### 5. 本轮冗余清理

- C2 页面移除本地 `StatCard`、`BucketList`、`ConversationList` 通用重复实现。
- APT 页面移除本地 `StatCard`、`MiniMetric`、`BucketList` 通用重复实现。
- `AnalysisBucketChart` 和 `AnalysisList` 扩展 `emptyText`，用于承接页面原有空状态文案。
- 指标卡直接使用 `MetricCard`，小指标直接使用 `AnalysisMiniStat`，桶图和列表直接使用共享分析组件。
- 任务控制台移除局部 `StatCard`，四个首页概览指标改为共享 `MetricCard`。
- 威胁狩猎页移除局部 `GlassStatCard`，顶部三项狩猎指标改为共享 `MetricCard`。
- `StatCard`、`GlassStatCard`、`BucketList`、`ConversationList`、`MiniMetric` 这批通用重复 helper 当前扫描已无残留。
- `AnalysisDataTable` 已扩展为泛型业务表格基座，支持列配置、列宽、单元格 class、行点击、空状态和展开详情行。
- C2 与 USB 页面内手写业务表格已迁移到 `AnalysisDataTable`，页面级表格 DOM 重复基本闭环。
- 已删除失去职责的 `DataTableShell`，避免共享表格层继续分裂。
- 当前 `<table>` 扫描只剩 `AnalysisPrimitives.tsx` 的共享表格原语和 `UpdateCenter.tsx` 的 Markdown 渲染器映射。
- `browserFile` 成为浏览器下载与复制共享入口，`wailsBridge` 中可复用的下载逻辑已接入 `downloadBlob`。

### 6. 浅色单主题收口

- MISC 模块中的普通黑色按钮、黑色 pill、深色头图和局部暗色状态标签已改为 cyan / sky / slate 系浅色表达。
- Dialog、Sheet、AlertDialog、Payload 弹窗和设置侧栏遮罩已从黑色半透明 overlay 改为浅色模糊 overlay。
- `dark` / `dark:` 显式深色模式分支当前扫描无命中。
- C2 / USB / UpdateCenter 的代码、Hex、Markdown code block 预览，以及 MediaAnalysis 的 video 播放黑底，作为功能性高对比例外保留。
- 浏览器默认拖拽页面导航已在 `MainLayout` 布局层统一屏蔽，并通过单测覆盖普通区域拦截、显式 drop zone 白名单和 cleanup。

### 7. 显示缺陷与浮层稳定性

- 数据包表格右键菜单已从裸用 `clientX` / `clientY` 改为视口安全定位，靠近窗口右侧或底部时会自动夹取到可见区域内。
- `viewportPosition`、`useViewportSafePosition` 和 `FloatingSurface` 已形成共享浮层定位基座，覆盖坐标计算、打开状态、上下文携带和 portal 浅色浮层壳。
- 数据包表格右键菜单已迁移到共享浮层基座，并增加右下角真实渲染夹取断言。
- 共享 `TooltipContent` 已默认启用 Radix collision 保护，并改为 MISC 准线下的浅色浮层。
- round34 已用真实浏览器加载 `http.pcap` 复核数据包右键菜单边界，并直达 `/misc` 复核页面浅色实机表现。
- 启动 runtime check 增加有限等待与 degraded 进入机制，避免后端长耗时分析期间前端无限停留在启动页。
- 新增 `asyncControl.withTimeout` 与 `OperationTimeoutError`，作为后续统一请求超时 / cancellable 生命周期治理的基础。
- 新增 `useAbortableRequest` 统一 cancellable 请求 hook，已迁移 C2、APT、工控、流量图、USB、车机、媒体页面以及 HTTP 登录、MySQL、SMTP、Shiro rememberMe MISC 模块。
- 浏览器路由冒烟发现并修复 `MainLayout` 背景 fade 与 route 容器同 pathname sibling key 导致的 React duplicate key warning。
- 新增 `captureTaskScope`，把 `SentinelContext` 的 packet page、preload、threat analysis、stream index、stream switch、packet detail/raw/layers 等抓包生命周期请求纳入 capture scope 失效保护。
- 关闭抓包改为前端 UI 立即脱离当前 capture，先清空 packets、streams、threat hits、objects、file meta 与缓存，再等待后端 closeCapture 返回最终文案。
- MISC 模块列表已从“折叠但全部挂载”改为“默认挂载首个模块，其余展开后再挂载”，隐藏模块不再在首屏发起 MySQL、SMTP、Shiro、NTLM、SMB3 等后台请求。
- Payload / WebShell 示例输入与 USB 默认页签识别修复了两个前端边界：示例后立即识别不再读取旧值，USB 页面可识别嵌套 HID / Mass Storage / Other USB 数据。
- Testing Library 异步等待窗口统一为 3 秒，配合懒挂载测试契约稳定通过 Windows / jsdom 全量测试。
- 数据包表格右键事件链已收紧，行级右键、表格空白右键和菜单自身右键不会再与浏览器原生上下文菜单互相冲突。
- 顶部导航菜单增加视口高度约束和滚动保护，避免长菜单在低高度窗口中溢出。
- 侧栏 tooltip 已改为浅色浮层并垂直居中，继续贴近 MISC 页面风格。
- MISC 通用 select 下拉增加低高度窗口约束，避免选项列表盲目向下撑开。
- 工作区 HEX / ASCII 面板完成可读性优化：更大字号、更宽 offset 与 ASCII 列、字节间距、左侧分割线和更清楚的选中/范围高亮。

## 四、当前设计缺陷

1. `MiscTools` 已完成隐藏模块懒挂载，解决首屏后台请求噪声；但内建模块代码仍在同一 chunk 内，后续仍需模块级 dynamic import。`UpdateCenter` 和主入口 chunk 也继续偏大。
2. `RecommendationCard`、`CategoryCard`、`GuideCard` 等仍是页面级业务卡片，需要继续区分“业务语义封装”和“通用 UI 重复”。
3. 部分代码/Hex/JSON/Markdown 预览仍使用深色代码块，这是功能性对比而非深色模式；后续需要维护白名单，避免误删影响可读性。
4. 页面动效已统一基础过渡，但跨页面转场、局部数据刷新和长表格展开仍可继续细化节奏。
5. 共享浮层基座已落地，但 Radix Dialog、Sheet、Popover、Select 等封装仍主要依赖自身 collision / overlay 机制；新手写浮层应优先接入 `useViewportSafePosition` / `FloatingSurface`。
6. HEX 面板当前选择“舒适阅读优先”，窄面板下会横向滚动；后续可考虑增加“紧凑 / 舒适”密度切换。
7. 真实浏览器视觉回归清单已完成首轮执行，但低高度、窄宽、长表格展开、HEX 横向滚动和 MISC 下拉仍需要继续覆盖。
8. 页面级请求生命周期已开始统一到 `useAbortableRequest`，`SentinelContext` 抓包加载、威胁分析、流追踪等 capture-scoped 请求已接入 `captureTaskScope`；MISC 隐藏模块后台请求已完成首轮收口，后续重点转向模块级动态加载、后端 closeCapture 取消传播和锁竞争。

## 五、下一步建议

1. 若开始处理构建体积，优先把 `MiscTools` 已懒挂载的内建模块进一步拆为 dynamic import，并检查 `UpdateCenter` 的 Markdown 渲染依赖是否可以延迟加载。
2. 对功能性暗色块建立明确白名单，只清理主题残留，不破坏代码/Hex/视频可读性。
3. 继续以 MISC 页面为准线，检查新协议模块是否出现标题区、状态标签、按钮和空状态样式孤岛。
4. 如果继续做冗余治理，优先从可证明等价的业务卡片开始，不要把有明确领域语义的组件过度抽象。
5. 建议延续 round34 / round35 的浏览器验证方式继续补低高度、窄宽、C2 / USB 表格展开、HEX 横向滚动和 MISC 下拉/折叠动画。
6. 如果继续修显示 bug，下一轮重点关注表格列设置面板、长文本弹窗、协议详情预览和低分辨率窗口布局。

## 六、round35 补充结论

- `useAbortableRequest` 已成为页面级专题请求的默认取消与过期保护基座。
- 已覆盖 C2、APT、工控、流量图、USB、车机、媒体页面以及 HTTP 登录、MySQL、SMTP、Shiro rememberMe MISC 模块。
- targeted tests 覆盖 `useAbortableRequest`、`asyncControl`、C2、APT、TrafficGraph、VehicleAnalysis、UsbAnalysis、MiscTools；全量前端测试为 15 个测试文件、62 个测试通过。
- 浏览器实机路由冒烟补充修复了 `MainLayout` duplicate key warning；低高度 / 窄屏 / 长表格等视觉回归仍是下一阶段任务。
- 下一步不要继续让页面局部手写 `AbortController` 分叉；页面级用 `useAbortableRequest`，capture 生命周期用 `captureTaskScope`，后端 closeCapture 链路需继续审计。

## 七、round36 补充结论

- `captureTaskScope` 已成为 `SentinelContext` 抓包生命周期请求的默认失效保护基座。
- 关闭抓包现在会立即清空前端 session、stream cache、威胁分析结果、对象结果和 file meta，不再等后端威胁分析 / closeCapture 完成后才清 UI。
- 无 active capture 时，旧解析 / 预加载 / 威胁分析 / 媒体流事件会被抑制，避免迟到事件污染状态栏。
- 本轮验证通过 `npx tsc --noEmit`、targeted tests、全量测试和构建；全量前端测试为 16 个测试文件、65 个测试通过。
- 下一阶段优先审计后端 closeCapture、威胁分析、对象导出、runtime config / TLS config 是否存在锁竞争或取消传播不足。

## 八、round37 补充结论

- 本轮先执行测试再落 plan，确认前端目标测试、全量测试、类型检查、严格未用符号检查、构建和后端目标测试均通过。
- MISC 模块列表已从“折叠但全部挂载”改为“默认挂载首个模块，其余展开后挂载”，隐藏模块不再首屏发起 MySQL、SMTP、Shiro、NTLM、SMB3 等后台请求。
- `MiscTools.test.tsx` 已把“隐藏模块不请求、展开后再请求”写成回归契约，后续不应再靠折叠内容挂载副作用预热数据。
- Payload / WebShell 示例输入与 USB 默认页签识别修复了两个小但真实的前端显示 / 交互边界。
- 新 plan 已收束为：MISC 模块级 dynamic import、隐藏面板后台请求审计、异步边界一致化、真实浏览器回归补齐和构建体积治理。
