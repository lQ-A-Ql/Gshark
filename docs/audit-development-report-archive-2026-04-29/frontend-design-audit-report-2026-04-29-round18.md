# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round18）

## 一、本轮目标

本轮继续 round17 的白底工作台路线，重点治理 TCP / HTTP / UDP 三个流追踪页中重复散写的“切流控件、视图模式切换、底部工具条”。目标是：

- 将上一条 / 下一条 / stream id 输入 / ordinal label 抽象为统一组件。
- 将 ASCII / Hex / Raw / Formatted 等视图切换抽象为统一组件。
- 将 TCP / UDP 底部工具条抽象为统一白底 control bar。
- 保持所有流追踪页白底，不改变现有流加载、搜索、导出与 payload 展示行为。

## 二、上一轮复核评论

round17 已经完成 `WorkbenchTitleBar` 与 `WorkbenchChip`，并迁移 Workspace、TCP、HTTP、UDP 顶部标题区。复核后确认：

- 顶部标题区已经统一，但 TCP / UDP 底部工具条仍各写一套。
- HTTP 顶部 actions 中的 stream 切换和 view mode 控件与 TCP / UDP 语义相同，但实现不同。
- 若继续散写，后续做“流追踪页面前端越界修复、响应式压缩、按钮数量收敛”会成本很高。

因此本轮优先抽象 stream-level 控件。

## 三、本轮开发内容

### 1. 扩展 DesignSystem：流追踪共享控件

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
```

新增：

- `StreamNavigator`
  - 统一 stream 切换控件。
  - 包含：
    - `流切换` label；
    - 上一条按钮；
    - `第 x / y 条 / stream eq N`；
    - 下一条按钮；
    - stream id 输入框；
    - Enter 提交。
  - 支持协议标签与总数 title。

- `ViewModeToggle<T>`
  - 泛型视图模式切换组件。
  - 支持 HTTP 的 `formatted / raw / hex`。
  - 支持 TCP / UDP 的 `ascii / hex / raw`。
  - 替换原先 TCP / UDP radio 组与 HTTP 手写按钮组。

- `StreamControlBar`
  - 统一 TCP / UDP 底部白底工具条。
  - 保持白底与轻量 border-top / shadow。
  - 后续可继续接入 HTTP 搜索工具条或统一导出区。

### 2. HTTP 会话追踪页迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\HttpStream.tsx
```

完成：

- 顶部 actions 中原手写 stream 切换控件替换为 `StreamNavigator`。
- 原 `Formatted / Raw / Hex` 手写按钮组替换为 `ViewModeToggle<HTTPViewMode>`。
- 保留 HTTP 搜索栏、chunk 渲染、格式化、导出等行为不变。

### 3. TCP 流追踪页迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TcpStream.tsx
```

完成：

- 底部工具条容器替换为 `StreamControlBar`。
- 原 radio 视图模式替换为 `ViewModeToggle<RawViewMode>`。
- 原手写 stream 切换组替换为 `StreamNavigator`。
- 已载入数量改为复用 `WorkbenchChip`。
- 导出按钮保留在右侧。

### 4. UDP 流追踪页迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UdpStream.tsx
```

完成：

- 底部工具条容器替换为 `StreamControlBar`。
- 原 radio 视图模式替换为 `ViewModeToggle<RawViewMode>`。
- 原手写 stream 切换组替换为 `StreamNavigator`。
- 已载入数量改为复用 `WorkbenchChip`。
- 导出按钮保留在右侧。

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

说明：当前沙箱对 esbuild / vitest 子进程启动有限制，`npm test` 与 `npm run build` 第一次出现 `spawn EPERM` 后按规则在授权环境重跑并通过。

## 五、当前收益

- HTTP / TCP / UDP 的 stream 切换交互已统一。
- HTTP / TCP / UDP 的视图模式切换开始统一。
- TCP / UDP 底部工具条白底风格统一。
- TCP / UDP / HTTP 页面中重复 JSX 明显减少，后续处理响应式与越界问题的修改点更集中。

## 六、遗留与下一轮建议

### 遗留问题

1. TCP / UDP / HTTP chunk 卡片仍是页面本地实现。
2. HTTP 搜索栏仍是页面本地工具条，尚未并入统一 stream workbench 控件族。
3. Workspace 顶部 actions 仍然较重，尚未拆成语义化子组件。
4. `StreamNavigator` 当前使用文本箭头 `‹ / ›`，后续可按项目图标风格改回 lucide icon，但统一由组件内部处理。

### 下一轮建议

1. 新增 `StreamChunkCard`，统一 TCP / UDP / HTTP 的片段卡片。
2. 新增 `StreamSearchBar`，统一 HTTP 搜索、匹配数量、上一匹配 / 下一匹配。
3. 将 Workspace 顶部 actions 拆成 `CaptureFileControls`、`PacketPagingControls`、`PacketLocatorControls`。
4. 继续迁移 USB / Vehicle / Industrial 的本地 `Panel` / `StatCard`，扩大共享 UI 覆盖面。
