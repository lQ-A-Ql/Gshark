# 日期: 2026-04-30
# 署名: Codex

# 当前开发态势与下一步规划整合报告

## 一、整合范围

本报告基于 2026-04-30 归档目录中的四个方向合并摘要、前端 round28 至 round37 逐轮审计报告，以及当前工作区最新的前端冗余治理结果，整合项目各方向的开发情况、设计缺陷和下一步规划。

本报告不替代原始逐轮报告。原始报告继续作为审计证据链，本文件作为跨方向交接入口，用于判断当前优先级和后续开发顺序。

## 二、总体状态判断

当前项目已经从单点功能补齐阶段，进入跨页面一致性、证据链表达、协议专项深化和冗余代码治理并行推进的阶段。

前端方向已经形成以 MISC 页面为准线的浅色单主题体系，流追踪页面也从功能堆叠逐步收束为流还原工作台。协议方向已经完成 HTTP 登录、SMTP、MySQL 等基础专项能力，并把实验性 Payload / WebShell 解码集中到 MISC。C2/APT、车机/工控方向已经具备候选聚合与初步解释能力，但下一步需要从“统计展示”升级到“证据链调查工作台”。

当前最值得继续投入的不是继续堆新页面，而是继续把已有页面中的通用能力沉淀为稳定基座：共享浮层定位、统一数据表、统一导出/复制、统一证据动作、统一报告 schema、统一 cancellable 请求生命周期。

## 三、各方向当前开发情况

### 1. 前端设计与交互

前端已经建立 MISC 页面作为全站浅色单主题准线，`PageShell`、`AnalysisHero`、`DesignSystem`、`AnalysisPrimitives`、`MetricCard`、`AnalysisBadge`、`AnalysisCallout`、`AnalysisBucketChart`、`AnalysisList` 和 `AnalysisDataTable` 已经承担主要共享职责。

已经完成的关键进展包括：

- 流追踪 HTTP/TCP/UDP 页面移除 Payload / WebShell 解码工作台，只保留流还原、片段浏览、搜索、视图切换和当前片段预览。
- Payload / WebShell 解码迁移到 MISC，避免实验性能力挤占流追踪主页面。
- 流量图、工控、车机、媒体、USB、对象导出、威胁狩猎、C2、APT 等旧页面逐步按 MISC 风格完成浅色卡片、柔和边框、轻量阴影和共享提示组件对齐。
- 显式 `dark` / `dark:` 深色主题分支已清理，当前只保留代码、HEX、视频等功能性高对比区域。
- 页面切换、背景色切换、卡片 hover、弹窗遮罩和局部浮层已经加入更柔和的过渡。
- 浏览器默认拖拽页面导航已经在布局层屏蔽，并保留明确 drop zone 白名单。
- 数据包表格右键菜单改为视口安全定位，同类顶部菜单、侧栏 tooltip、MISC select 也补充了边界保护。
- 共享 `viewportPosition`、`useViewportSafePosition` 和 `FloatingSurface` 已落地，数据包右键菜单已迁移到共享浮层定位基座。
- 共享 `TooltipContent` 已默认启用碰撞保护，并改为贴近 MISC 准线的浅色浮层。
- 工作区 HEX / ASCII 面板已完成可读性优化，修正字体过小、过紧和列对齐问题。
- 最新冗余治理新增 `frontend/src/app/utils/browserFile.ts`，集中 `downloadBlob`、`downloadText`、`copyTextToClipboard`，收敛多个页面和 MISC 模块中重复的浏览器下载与复制逻辑。
- `wailsBridge` 中可复用的下载逻辑已接入 `browserFile.downloadBlob`，下载/复制/导出重复实现进一步收敛。
- round34 已使用真实浏览器执行首批视觉回归：本地加载 `http.pcap`，复核数据包右键菜单边界与 `/misc` 页面实机显示。
- round34 修复启动门阻塞问题：当后端长耗时分析拖慢 runtime check 时，前端会在有限等待后以 degraded 状态进入主界面，并提示用户稍后在设置侧栏刷新运行时状态。
- 新增 `asyncControl.withTimeout` / `OperationTimeoutError`，为启动 runtime check、TLS config check 和后续统一 cancellable 请求治理提供基础工具。
- round35 新增 `useAbortableRequest` 统一请求生命周期 hook，覆盖 abort-like error 识别、sequence 过期保护、unmount 自动取消和当前请求 `onSettled` 保护。
- round35 已迁移 C2、APT、工控、流量图、USB、车机、媒体页面，以及 HTTP 登录、MySQL、SMTP、Shiro rememberMe MISC 模块，减少局部 `AbortController` 分裂。
- round35 使用真实浏览器继续执行路由冒烟，发现并修复 `MainLayout` 背景 fade 与 route 容器使用相同 pathname 造成的 React duplicate key warning。
- round36 新增 `captureTaskScope`，为 `SentinelContext` 建立 capture-scoped 请求生命周期控制，覆盖 packet page、preload、threat analysis、stream index、stream switch、packet detail/raw/layers 等抓包强绑定任务。
- round36 将关闭抓包调整为 UI 立即脱离当前 capture：先清空前端 session、缓存、stream、威胁结果和 file meta，再等待后端 close 返回最终状态，避免关闭按钮视觉上继续等待威胁分析。
- round36 为无 active capture 场景增加旧解析 / 预加载 / 威胁分析 / 媒体流事件回落抑制。
- round37 完成 MISC 隐藏模块懒挂载：默认只挂载首个模块，其余模块展开后才挂载，避免折叠模块首屏发起 HTTP/MySQL/SMTP/Shiro/NTLM/SMB3 等后台请求。
- round37 修复 Payload / WebShell 示例后立即识别读取旧状态的问题，并补强 USB 页面默认 tab 对嵌套 HID、Mass Storage、Other USB 数据的识别。
- round37 将 Testing Library 异步等待窗口统一为 3 秒，并确认前端目标测试、全量测试、类型检查、严格未用符号检查、构建和后端目标测试均通过。

当前缺陷和风险包括：

- `MiscTools` 已解决隐藏模块首屏后台请求问题，但模块代码仍打在同一 chunk 内；`UpdateCenter` 和主入口 chunk 也仍偏大，后续需要以 dynamic import 和依赖延迟加载继续拆分。
- 右键菜单类手写浮层已有 `useViewportSafePosition` / `FloatingSurface` 基座，但 Radix Dialog、Sheet、Popover、Select 等复杂浮层仍应保留自身焦点管理与 collision 机制，后续按证据逐步接入或配置。
- `RecommendationCard`、`CategoryCard`、`GuideCard` 等页面级业务卡片仍需判断是否值得继续抽象，避免过度泛化。
- HEX 面板当前偏向舒适阅读，窄面板下依赖横向滚动，后续可以增加“紧凑 / 舒适”密度切换。
- 真实浏览器视觉回归已经完成首轮执行，但本轮浏览器插件交互被中断，round37 主要依赖命令行验证；低高度窗口、窄宽窗口、长表格展开、HEX 横向滚动和 MISC 下拉仍需继续覆盖。
- `SentinelContext` 内抓包加载、威胁分析、流追踪等 capture 生命周期请求已接入 `captureTaskScope`；后续风险转向后端 closeCapture / 威胁分析 / runtime config 锁竞争。

下一步规划：

- 已建立浮层安全定位通用层；后续新增手写右键菜单、轻量 popover 和自定义 select 时应优先复用该基座。
- 继续推进 `AnalysisDataTable` 到 C2、工控、车机、对象导出等复杂表格，降低页面级 table 重复。
- 将浏览器下载、复制、导出、反馈 toast 的交互进一步统一，减少各模块自建工具函数。
- 保持浅色单主题，不恢复深色模式，不新增 `dark:` 分支。
- 继续执行前端视觉回归清单，优先补低高度窗口、窄宽窗口、HEX 横向滚动、流追踪搜索和 MISC 模块切换。
- 新增页面级专题请求默认使用 `useAbortableRequest`；与 capture 生命周期强耦合的请求默认使用 `captureTaskScope`，不再继续散落本地 `AbortController`。
- MISC 新增模块默认遵守“折叠不挂载、展开才请求”的契约；若模块本身体积较大，下一步应直接拆为 dynamic import，而不是只依赖折叠 UI。

### 2. 协议专项与 MISC 工具箱

协议方向已经完成 HTTP 登录行为、SMTP、MySQL 等专项分析的主路径，MISC 工具箱承担轻量工具、实验性解码、密钥材料辅助分析和不适合塞进主流追踪页的专项能力。

已经完成的关键进展包括：

- HTTP 登录行为分析覆盖认证尝试明细、账号/来源/路径聚合和异常登录线索。
- SMTP 分析覆盖邮件会话、认证、发件行为和附件/对象线索。
- MySQL 分析覆盖连接、认证、查询和异常行为基础审计。
- Payload / WebShell 解码工作台已经迁移到 MISC，支持手动粘贴 HTTP 报文、body、参数值、Base64、Hex 等输入。
- 解码结果表达补充置信度、警告、失败原因和实验性提示，避免把低置信结果展示为稳定解密。
- `cancellable=true` 的语义已经明确：模块请求支持取消，前端切换模块、刷新、重新输入或离开页面时可以中止请求，并避免过期结果覆盖当前 UI。
- HTTP 登录、MySQL、SMTP、Shiro rememberMe 模块已经迁移到统一 cancellable 请求 hook，模块切换、刷新、卸载时的取消和过期保护更一致。
- WinRM、SMB3 session key、Payload / WebShell 等复杂模块继续作为内建模块暴露。

当前缺陷和风险包括：

- Behinder、AntSword、Godzilla 等 WebShell 解码能力真实样本覆盖不足，仍需要用更多样本验证算法路径。
- 协议专项报告输出尚未统一为稳定 schema，HTTP、SMTP、MySQL、Shiro 等模块之间仍存在表达差异。
- MISC manifest 已有 `requires_capture`、`supports_export`、`cancellable` 等字段，但 UI 能力徽标仍不够显性。
- cancellable 请求模式已经有统一 hook，但 WinRM、SMB3、Payload / WebShell 与 capture-scoped 请求仍需继续分批迁移或建立专用控制器。
- 协议分析结果与证据定位、过滤动作、报告导出之间的联动还不够完整。

下一步规划：

- 统一协议专项报告结构为“摘要、证据、明细、建议”四段，优先覆盖 HTTP 登录、SMTP、MySQL、Shiro。
- 为 MISC 模块列表增加能力徽标，明确无需抓包、支持导出、可取消、实验性等状态。
- 将 `/api/streams/inspect` 与 `/api/streams/decode` 的候选、失败阶段、置信度字段继续补齐测试。
- 建立统一 cancellable 请求 hook，禁止过期请求覆盖当前 UI。
- 推进 Shiro rememberMe 专项工具，补齐 cookie 分析、key 测试、低置信提示和导出报告。

### 3. C2 样本分析与 APT 组织画像

C2/APT 方向已经从页面骨架进入候选聚合、解释面板和证据动作阶段。当前重点不是强行归因，而是把 C2 候选、对象线索、威胁狩猎、认证行为和时间线组织成可复核证据链。

已经完成的关键进展包括：

- C2 页面覆盖 Cobalt Strike、VShell 候选证据、Family 分布、会话概览、Channel 分布和指标类型。
- CS Host / URI、DNS Beacon、VShell Stream 聚合画像已经形成，能够展示请求形态、时间范围、平均间隔、jitter、stream 和 packet 列表。
- APT 页面以银狐类活动为优先画像样例，覆盖样本家族、投递阶段、传输特征、基础设施线索和 C2 技术证据。
- 归因解释面板区分 Supporting Evidence、Weak Observations、Missing Evidence、Suppression / Caveat。
- Evidence Timeline 已经按 actor 与证据来源组织可读时间线。
- C2/APT 前端冗余 helper 已清理，分布图、列表、小指标逐步迁移到共享分析组件。

当前缺陷和风险包括：

- C2 聚合表和展开详情仍有一部分页面内复杂实现，需要继续迁移到增强后的 `AnalysisDataTable`。
- APT 归因依赖证据字段质量，缺少跨模块统一 evidence schema 和冲突解释机制。
- CS / VShell 检测仍以公开流量特征和候选画像为主，需要更多真实样本回放测试。
- 当前 APT 画像偏单 actor，缺少多 actor 并列、冲突、排除和合并策略。
- UI 对分数因子、负向抑制、缺失证据的解释仍可继续增强。

下一步规划：

- 抽象 C2/APT 复杂证据表，把展开行、actions slot、证据定位和过滤联动合并到共享数据表能力。
- 定义跨模块 evidence schema，统一 C2、对象提取、威胁狩猎、认证、协议专项输出。
- 补充 C2 聚合画像后端单测，覆盖空数据、弱信号、强信号和误报抑制。
- 增加多 actor 画像与冲突提示，不把单一弱观察升级为强归因。
- 将 APT caveat 面板产品化，让用户清楚看到哪些证据只是弱观察。

### 4. 车机与工控分析

车机和工控方向已经完成基础协议识别、风险展示和页面风格对齐，但仍处于从统计页向调查工作台过渡的前半段。下一步要加强协议语义、请求响应配对、控制行为时间线和证据定位。

已经完成的关键进展包括：

- 车机方向覆盖 CAN、J1939、DoIP、UDS 基础识别与字段展示。
- 车机页面已经按 MISC 风格完成浅色卡片、指标、桶图和列表对齐。
- 工控方向覆盖 Modbus 事务、规则命中、可疑写操作和控制指令结构化展示入口。
- 工控页面风险标签、事务类型和提示块开始使用共享 `AnalysisBadge` / `AnalysisCallout`。
- 两类页面均强调“协议字段 + 安全解释 + 可定位证据”的组合方向。

当前缺陷和风险包括：

- 车机缺少 OBD-II PID 级解析、DBC/ARXML 映射、UDS 请求响应配对和负响应解释。
- DoIP + UDS 组合事务视图、刷写流程、安全访问和例程控制链路仍未成型。
- 工控 Modbus 功能码解释还不够细，尤其是写线圈、写寄存器、多寄存器写入和异常响应。
- 工控缺少按设备、功能码、寄存器和值组织的控制行为时间线。
- 车机/工控复杂表格和详情面板仍存在本地实现重复。

下一步规划：

- 优先补 UDS 请求响应配对、耗时统计和负响应解释，让车机页面具备诊断链路可读性。
- 设计轻量 DBC/ARXML 导入和字段映射展示，不急于实现完整编辑器。
- 为 Modbus 写操作建立风险时间线，突出“谁在什么时候写了什么寄存器和值”。
- 继续迁移车机/工控复杂表格到 `AnalysisDataTable`。
- 将高风险车机/工控事件接入证据定位、过滤动作和报告导出。

### 5. 对象、媒体、USB 与通用工具页

对象、媒体、USB 和通用工具页已经完成多轮风格对齐和局部冗余治理，当前定位是作为跨模块证据来源和辅助工作台，而不是孤立展示页。

已经完成的关键进展包括：

- USB 页面业务表格已迁移到 `AnalysisDataTable`。
- 媒体分析、对象导出、任务控制台、威胁狩猎等页面逐步使用共享指标卡、列表、提示和导出逻辑。
- 当前最新冗余治理已经把多个页面的下载文本、下载 Blob 和复制文本收敛到 `browserFile` 工具。
- `wailsBridge` 下载 helper 和媒体播放 `createObjectURL` 被保留，因为它们属于桥接层和播放生命周期特例。

当前缺陷和风险包括：

- 对象、媒体、USB 与协议、C2、APT 之间的证据 schema 还没有完全统一。
- 媒体播放、对象导出和 Markdown 渲染保留了功能性高对比区域，需要继续维护白名单。
- 通用导出结果与报告导出之间还存在边界重叠。

下一步规划：

- 将对象、媒体、USB 输出接入统一 evidence schema。
- 继续收敛下载、复制、导出和 toast 反馈，保留桥接层与生命周期特例。
- 对对象导出、媒体预览、USB 明细继续做真实浏览器布局走查。

## 四、跨方向共性问题

- 证据 schema 分裂：协议、C2/APT、车机/工控、对象/媒体/USB 都在产生证据，但字段、严重性、来源、定位动作和导出结构还未完全统一。
- 浮层定位分裂：右键菜单类手写浮层已有共享基座，但下拉、tooltip、弹窗和表格 actions 仍需要继续统一配置或接入视口安全逻辑。
- 表格实现分裂：`AnalysisDataTable` 已经成型，但复杂页面还没有全部迁移。
- 请求生命周期分裂：页面级请求已开始统一到 `useAbortableRequest`，capture 生命周期请求已接入 `captureTaskScope`；WinRM/SMB3/Payload 等复杂 MISC 模块仍需继续迁移或明确例外。
- 视觉回归不足：当前有单测和构建验证，但真实浏览器低分辨率、低高度和边界点击场景仍需专门走查。
- 构建体积压力：MISC、UpdateCenter 和主入口 chunk 是后续性能治理重点。

## 五、下一步规划

### 第一优先级：前端稳定性与一致性（已闭环，转入维护）

- `viewportPosition`、`useViewportSafePosition` 和 `FloatingSurface` 已落地，数据包右键菜单已迁移到共享浮层基座并补充右下角渲染断言。
- 复杂业务表格迁移已完成当前阶段扫描复核，页面级 `<table>` 只剩共享 `AnalysisDataTable` 原语和 `UpdateCenter` Markdown renderer 例外。
- 真实浏览器视觉回归清单已建立并完成首轮执行，覆盖本地工作区加载、数据包右键菜单边界与 MISC 页面实机显示；后续需继续补低高度、窄屏、长表格和 HEX 横向滚动。
- 下载、复制、导出重复代码已进一步收敛到 `browserFile`，`wailsBridge` 下载逻辑已复用 `downloadBlob`。
- 启动 runtime 检测已加入有限等待与 degraded 进入机制，避免后端长耗时分析期间前端无限停留在启动页。
- 统一 cancellable 请求 hook 已落地，并迁移多个专题页与 MISC 模块；浏览器路由冒烟修复了 `MainLayout` duplicate key warning。
- capture-scoped 请求控制器已落地到 `SentinelContext`，关闭抓包现在先清空前端 session，再等待后端清理结果，不再让 UI 继续挂在旧威胁分析状态上。
- MISC 隐藏模块懒挂载已落地，隐藏模块不再在首屏触发后台分析请求；这把第一优先级中的“看不见的请求副作用”纳入回归契约。
- 后续维护要求：新增手写浮层必须复用共享基座或明确使用 Radix collision；新增下载/复制优先走 `browserFile`；不得新增 `dark:` 深色模式分支。

### 第二优先级：协议与 MISC 产品化

- 统一协议专项报告 schema，先覆盖 HTTP 登录、SMTP、MySQL、Shiro。
- 为 MISC manifest 增加更清晰的 UI 能力表达。
- 给 Payload / WebShell 解码补足候选提取、失败阶段、置信度和实验性提示测试。
- 基于 `useAbortableRequest` 继续迁移剩余 MISC 模块；基于 `captureTaskScope` 继续补充抓包生命周期边界用例，并转入后端 closeCapture 取消传播与锁竞争审计。
- MISC 新增或复杂模块需要同时声明“是否首屏挂载、是否后台请求、是否 dynamic import”，避免工具箱继续膨胀成单一大 chunk。

### 第三优先级：证据链与安全调查工作台

- 定义跨方向 evidence schema，统一 severity、source、location、confidence、actions、export 字段。
- C2/APT 增加多 actor 冲突解释和 caveat 面板。
- 车机补 UDS 配对与 DBC/ARXML 映射，工控补 Modbus 写操作时间线。
- 将高风险事件统一接入 EvidenceActions / FilterActions，形成可追踪、可过滤、可导出的调查链。

### 第四优先级：性能与可维护性

- 拆分 `MiscTools`、`UpdateCenter` 和主入口大 chunk。
- 优先把 round37 已完成行为懒挂载的 MISC 内建模块继续拆成动态模块；随后处理 `UpdateCenter` Markdown 渲染依赖延迟加载。
- 对共享组件建立边界说明，区分通用 UI、业务语义封装和协议专用组件。
- 继续维护功能性高对比白名单，避免把代码、HEX、视频预览误当作深色模式残留删除。

## 六、建议执行顺序

1. 继续补真实浏览器视觉回归执行，把低高度、窄屏、长表格展开、HEX 横向滚动和 MISC 下拉用截图或人工记录闭环。
2. 随后把 round37 的 MISC 懒挂载推进到模块级 dynamic import，并同步审计 `UpdateCenter` Markdown 渲染依赖，降低首包与工具箱 chunk 压力。
3. 再把 round35 的 `useAbortableRequest` 扩展到剩余模块，并把 round36 的 `captureTaskScope` 纳入抓包生命周期约定；同时审计后端 closeCapture / 威胁分析 / runtime config 锁竞争，统一协议报告 schema。
4. 接着定义 evidence schema，把协议、C2/APT、对象、车机、工控的输出连接成同一条证据链。
5. 再继续做 `AnalysisDataTable` 深化迁移和表格 actions 统一，重点处理后续新增复杂表格。
6. 最后处理更大范围的性能治理，避免在结构仍变化时过早优化。

## 七、验证与风险

最近一轮测试先行与计划落地已经通过 `npm test -- MiscTools UsbAnalysis`、`npm test`、`npx tsc --noEmit`、`npx tsc --noEmit --noUnusedLocals --noUnusedParameters`、`go test ./backend/internal/transport ./backend/internal/engine` 和 `npm run build` 验证，其中全量前端测试为 16 个测试文件、65 个测试通过。后续若继续改动共享组件、请求生命周期或启动链路，建议至少保留这些验证命令，并继续补浏览器真实交互走查。

当前最大风险不是单一功能缺失，而是多个方向同时扩张导致 schema、浮层、表格、导出和请求生命周期继续分叉。下一阶段应优先做可复用基座，而不是继续增加页面级局部实现。


