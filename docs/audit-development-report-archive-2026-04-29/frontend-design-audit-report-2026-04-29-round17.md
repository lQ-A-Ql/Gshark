# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round17）

## 一、本轮目标

本轮继续执行前端设计系统收敛路线，重点从专题分析页转向用户明确要求保留白底的核心工作台区域：

- 主工作区 `Workspace`。
- TCP 流追踪页。
- HTTP 会话追踪页。
- UDP 流追踪页。

本轮目标是建立“白底工作台标题区”共享基线，避免把工作区与流追踪页错误套入专题页大 Hero / 渐变卡片风格，同时统一返回按钮、标题、副标题、状态 chip 与右侧工具区布局。

## 二、上一轮复核评论

round16 已新增 `DesignSystem.tsx`，并让 C2 / APT / MISC 三个页面开始使用 `SurfacePanel`、`MetricCard`、`StatusHint`、`EmptyState`、`DataTableShell` 与 `CollapsibleContent`。复核后确认：

- 专题页方向已经具备统一面板与统计卡基线。
- 但工作区与流追踪页仍沿用各自散写的顶部栏：返回按钮、标题、stream endpoint、加载状态、切流性能指标等样式不统一。
- 用户此前强调“工作区和流追踪区背景颜色保留白色”，因此这类页面不应该改成专题页渐变 Hero，而应该单独建设 `Workbench` 风格组件。

本轮即补齐该组件族的第一步。

## 三、本轮开发内容

### 1. 扩展共享设计组件：白底工作台标题区

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
```

新增：

- `WorkbenchTitleBar`
  - 固定白底。
  - 轻量 border-bottom 与 shadow。
  - 支持返回按钮。
  - 支持 icon、标题、副标题。
  - 支持右侧 `meta` 与 `actions` 插槽。
  - 用于工作区、TCP/HTTP/UDP 流追踪等高密度页面。

- `WorkbenchChip`
  - 统一工作台顶部状态 chip。
  - 用于“已载入 X/Y”、“来源 cache/index/tshark”、“切流 p50/p95”等短状态。

### 2. Workspace 顶部栏迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\Workspace.tsx
```

完成：

- 根容器背景显式改为 `bg-white`，强化用户要求的白底工作区。
- 原顶部文件/分页工具栏迁移到 `WorkbenchTitleBar.actions`。
- 标题区显示：
  - `流量工作区`
  - 当前文件名与包数量；无文件时显示打开提示。
- 保留原有全部操作：
  - 路径输入；
  - 选择文件；
  - 路径打开；
  - 关闭抓包；
  - 上一页 / 下一页；
  - 页码跳转；
  - 分组号定位；
  - 快捷分页按钮。

未改变：

- 过滤器逻辑。
- filter loading 进度。
- PacketVirtualTable。
- 协议树 / Hex 视图。
- 抓包关闭与取消链路。

### 3. TCP 流追踪页顶部栏迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TcpStream.tsx
```

完成：

- 根容器显式改为白底。
- 顶部标题栏迁移到 `WorkbenchTitleBar`。
- endpoint 信息放入副标题：`from -> to`。
- 载入数量和 load meta 使用 `WorkbenchChip`。
- 返回按钮由共享组件统一渲染。

未改变：

- TCP stream 自动路由选择。
- 分片加载更多。
- 当前片段预览。
- 展开完整 payload 弹层。
- 底部 view mode / stream switch / export 工具条。

### 4. HTTP 会话追踪页顶部栏迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\HttpStream.tsx
```

完成：

- 根容器显式改为白底。
- 顶部标题栏迁移到 `WorkbenchTitleBar`。
- client/server endpoint 放入副标题。
- stream switch 性能指标使用 `WorkbenchChip`。
- 原 stream 切换控件与 view mode 控件进入 `actions` 插槽。

未改变：

- HTTP 请求/响应 chunk 构建。
- deferred search。
- formatted/raw/hex 视图。
- gzip/JSON/HTML 格式化。
- 导出流文本。

### 5. UDP 流追踪页顶部栏迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UdpStream.tsx
```

完成：

- 根容器显式改为白底。
- 顶部标题栏迁移到 `WorkbenchTitleBar`。
- endpoint 信息放入副标题。
- 载入数量和 load meta 使用 `WorkbenchChip`。
- 返回按钮由共享组件统一渲染。

未改变：

- UDP stream 自动路由选择。
- 分片加载。
- 当前片段预览。
- 底部 view mode / stream switch / export 工具条。

## 四、验证结果

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit
npm test
npm run build
```

结果：

- `npx tsc --noEmit`：通过。
- `npm test`：通过，11 个测试文件、43 项测试通过。
- `npm run build`：通过。

本轮只改前端工作台 UI，不修改后端接口与数据结构。

## 五、当前收益

- 工作区与 TCP/HTTP/UDP 流追踪页已经有统一的白底标题区基线。
- 返回按钮、标题、endpoint、副标题、状态 chip、工具区开始统一。
- 工作区和流追踪区继续保留白色背景，没有回退到专题页渐变风格。
- 后续可以在同一组件上继续治理顶部拥挤、响应式换行、流追踪工具条分散等问题。

## 六、遗留问题与下一轮建议

### 遗留问题

1. Workspace 顶部 actions 仍然承载大量控件，虽然已进入统一标题区，但后续需要拆成“文件操作组 / 翻页组 / 定位组”。
2. TCP / UDP 底部工具条仍各自散写，下一轮可抽象为 `StreamControlBar`。
3. HTTP 搜索工具条仍是独立实现，下一轮可统一为 `StreamSearchBar`。
4. 流追踪内容区的片段卡片仍使用协议页本地样式，尚未收敛为共享 `StreamChunkCard`。

### 下一轮建议

1. 新增 `StreamControlBar`，统一 TCP / UDP 的显示方式、切流、导出工具区。
2. 新增 `StreamNavigator`，统一 HTTP / TCP / UDP 的上一条/下一条/stream id 输入控件。
3. 新增 `StreamChunkCard`，统一请求/响应、client/server、packet id、截断提示与选中态。
4. Workspace 顶部 actions 拆分为语义化小组件，降低单文件 JSX 复杂度。
5. 开始把 USB / Vehicle / Industrial 的本地 `Panel` / `StatCard` 迁移到 round16 的共享组件。
