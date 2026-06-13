# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round19）

## 一、本轮目标

本轮继续 round18 的流追踪工作台收敛，重点治理 TCP / HTTP / UDP 三个流追踪页仍各自散写的片段卡片与 HTTP 搜索栏。目标是：

- 将请求/响应、client/server、packet id、选中态、截断入口统一到 `StreamChunkCard`。
- 将 HTTP 搜索输入、上一匹配、下一匹配、匹配数量统一到 `StreamSearchBar`。
- 保持 TCP / HTTP / UDP 白底工作台风格与现有渲染逻辑不变。

## 二、上一轮复核评论

round18 已经完成 `StreamNavigator`、`ViewModeToggle`、`StreamControlBar`，使 HTTP / TCP / UDP 的切流和视图模式切换进入共享组件。但复查后仍存在两个重复点：

1. TCP / UDP / HTTP 的 chunk 卡片样式与结构相似，但分别在页面里实现。
2. HTTP 搜索栏仍是页面内手写控件，后续如果扩展到 TCP / UDP payload 搜索，会再次重复。

因此本轮继续把流内容区的基础 UI 收敛到设计系统。

## 三、本轮开发内容

### 1. 扩展 DesignSystem：流片段卡片与搜索栏

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
```

新增：

- `StreamSearchBar`
  - 统一搜索输入、上一条、下一条、匹配数量。
  - 当前先接入 HTTP 页面。
  - 后续可直接扩展到 TCP / UDP payload 搜索。

- `StreamChunkCard`
  - 统一流片段卡片外壳。
  - 支持：
    - direction label；
    - packet id；
    - rendered payload；
    - selected 状态；
    - tone 颜色；
    - truncated 状态；
    - 查看完整 payload 入口；
    - 可选最小高度。

### 2. TCP 流追踪页迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TcpStream.tsx
```

完成：

- 删除本地 `RawStreamChunkCard`。
- TCP chunk 列表改用 `StreamChunkCard`。
- 保留原有：
  - `renderStreamChunk`；
  - `isChunkTruncated`；
  - 完整 payload 弹层；
  - client/server tone；
  - selected chunk 行为。

### 3. UDP 流追踪页迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UdpStream.tsx
```

完成：

- 删除本地 `RawStreamChunkCard`。
- UDP chunk 列表改用 `StreamChunkCard`。
- 保留原有：
  - `renderStreamChunk`；
  - client/server tone；
  - selected chunk 行为；
  - 加载更多逻辑。

### 4. HTTP 会话追踪页迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\HttpStream.tsx
```

完成：

- 删除本地 `HTTPChunkCard`。
- HTTP chunk 列表改用 `StreamChunkCard`。
- 新增 `renderHTTPChunk`，保留原 formatted/raw/hex 渲染规则。
- HTTP 搜索栏改用 `StreamSearchBar`。
- 保留原有：
  - deferred search；
  - match count；
  - cursor 上下切换；
  - selected chunk preview；
  - gzip / JSON / HTML 格式化。

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

## 五、当前收益

- TCP / HTTP / UDP 流片段卡片外壳统一。
- HTTP 搜索栏进入共享组件，为 TCP / UDP 搜索扩展预留入口。
- TCP / UDP 页面移除了本地 `RawStreamChunkCard` 重复实现。
- HTTP 页面移除了本地 `HTTPChunkCard` 重复实现。
- 流追踪页的白底工作台风格继续保持一致。

## 六、遗留与下一轮建议

### 遗留问题

1. TCP 与 UDP 当前仍没有 payload 搜索功能，仅 HTTP 接入搜索栏。
2. TCP 完整 payload 弹层仍是页面本地实现，可继续抽象为 `StreamPayloadDialog`。
3. Workspace 顶部 actions 仍然较大，尚未拆分为文件操作、翻页、定位三个子组件。
4. `StreamChunkCard` 当前由页面传入 rendered string，后续可考虑将 truncation summary、copy/export action 也内置。

### 下一轮建议

1. 将 `StreamSearchBar` 扩展到 TCP / UDP，支持 payload 文本搜索与 chunk 过滤。
2. 新增 `StreamPayloadDialog`，统一完整 payload 弹层。
3. 拆分 Workspace 顶部 actions 为 `CaptureFileControls`、`PacketPagingControls`、`PacketLocatorControls`。
4. 继续迁移 USB / Vehicle / Industrial 的本地 `Panel` / `StatCard`。
