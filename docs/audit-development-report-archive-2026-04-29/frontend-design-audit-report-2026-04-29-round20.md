# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round20）

## 一、本轮目标

本轮承接 round19 的遗留项，按“前五层”完成一次前端集中清理，重点不再扩展新协议能力，而是治理流追踪与工作台 UI 的重复实现、严格类型残留和深色模式残留。目标是：

- 修复严格 TypeScript 下的未用符号失败。
- 将 `StreamSearchBar` 从 HTTP 扩展到 TCP / UDP。
- 抽取统一 `StreamPayloadDialog`，替换 TCP 本地弹窗，并补齐 HTTP / UDP 完整 payload 查看。
- 拆分 Workspace 顶部 actions，降低主页面 JSX 密度。
- 移除深色模式残留，保持项目为浅色单主题。

## 二、上一轮复核评论

round19 已完成 `StreamChunkCard` 与 `StreamSearchBar` 的第一步收敛，但复查后仍有几个明显断点：

1. `StreamSearchBar` 只接入 HTTP，TCP / UDP 仍不能按 payload 搜索。
2. TCP 完整 payload 弹窗仍在页面内本地实现，HTTP / UDP 缺少统一完整 payload 入口。
3. Workspace 标题区 actions 同时承担抓包文件、翻页、分组定位， JSX 过长且职责混杂。
4. 前序组件与 UI primitive 中仍残留 `dark:` class 和 dark variant 声明，与当前“只需要浅色模式”的产品方向不一致。
5. 严格 TS 检查已有未用符号失败，影响后续继续以 `--noUnusedLocals --noUnusedParameters` 做质量门禁。

因此本轮以收束前端实现质量为主，优先完成这些会持续影响后续开发效率的基础层。

## 三、本轮开发内容

### 1. 修复严格 TypeScript 未用符号

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\AptAnalysis.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.test.tsx
```

完成：

- 移除 APT 页面未使用的 `RefreshCw` import。
- 将 C2 测试中 `getAllByText` predicate 的未读参数改为 `_content`，保留断言语义。
- `npx tsc --noEmit --noUnusedLocals --noUnusedParameters` 已重新通过。

### 2. 扩展 DesignSystem：统一完整 payload 弹窗

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
```

新增：

- `StreamPayloadDialog`
  - 统一完整 payload 的 overlay、标题、说明、正文容器。
  - 内置复制与导出动作。
  - 使用浅色弹窗、浅色遮罩与一致的边框/阴影。
  - 不包含任何深色模式分支。

当前收益：

- TCP / HTTP / UDP 后续不再需要各自维护 payload 弹层。
- 完整 payload 查看、复制、导出行为集中在共享组件。

### 3. TCP 流追踪页优化

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TcpStream.tsx
```

完成：

- 接入 `StreamSearchBar`。
- 新增 TCP payload 搜索、chunk 过滤、上一匹配、下一匹配、匹配数量。
- 使用 `useDeferredValue` 降低大流搜索输入抖动。
- 将选中 chunk 从原始数组下标调整为过滤后可见下标，并保留 `streamIndex` 展示原始 chunk 序号。
- 删除本地完整 payload 弹窗，改用 `StreamPayloadDialog`。
- 移除所有 `dark:` class。

### 4. UDP 流追踪页优化

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UdpStream.tsx
```

完成：

- 接入 `StreamSearchBar`。
- 新增 UDP payload 搜索、chunk 过滤、上一匹配、下一匹配、匹配数量。
- 补齐 UDP chunk 截断判断与“查看完整 payload”入口。
- 扩展 `renderStreamChunk`，支持 preview 与 expanded 两种输出。
- 完整 payload 查看改用 `StreamPayloadDialog`。
- 移除所有 `dark:` class。

### 5. HTTP 会话追踪页优化

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\HttpStream.tsx
```

完成：

- HTTP chunk 卡片接入 `StreamPayloadDialog`。
- 新增 HTTP payload preview 截断阈值，避免超长请求/响应直接撑开列表。
- 保持 formatted/raw/hex 三种视图逻辑不变。
- 当前片段面板也提供完整 payload 查看入口。
- 移除所有 `dark:` class。

### 6. Workspace 顶部 actions 拆分

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\Workspace.tsx
```

新增局部组件：

- `CaptureFileControls`
  - 负责路径输入、选择文件、路径打开、关闭抓包。
- `PacketPagingControls`
  - 负责上一页、下一页、页码跳转、页码快捷按钮。
- `PacketLocatorControls`
  - 负责按分组号定位。

当前收益：

- `Workspace` 主 JSX 的标题区职责更清晰。
- 后续继续优化工作台标题栏时，可以按控件粒度调整布局，不必再编辑一整段混合 actions。

### 7. 浅色模式收束与 dark 残留清理

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\StreamDecoderWorkbench.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\ui\badge.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\ui\button.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\ui\input.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MediaAnalysis.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\styles\theme.css
```

完成：

- 移除 `dark:` Tailwind class。
- 移除 `@custom-variant dark`。
- 移除入口布局中对 `documentElement.classList.remove("dark")` 的主题清理逻辑。
- 保留 `gshark-theme=light` 写入，用于兼容历史本地存储，但不再引入深色主题分支。
- 已扫描 `frontend/src`，未发现 `dark:` 或 dark 主题分支残留。

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
- `frontend/src` dark 残留扫描：通过，未发现 `dark:` / `dark` 主题分支。

额外执行：

```powershell
git diff --check
```

结果：

- 未作为本轮质量门禁通过项计入。
- 当前脏工作区中已有大量前序 trailing whitespace，主要来自既有未提交文件，例如 `frontend/src/app/core/types.ts`、`frontend/src/app/pages/C2Analysis.tsx`。
- 本轮未批量格式化这些历史脏文件，避免扩大改动面和覆盖前序 agent / 用户变更。

## 五、当前收益

- TCP / HTTP / UDP 的 chunk 卡片、搜索栏、完整 payload 弹窗进一步统一。
- TCP / UDP 已具备和 HTTP 一致的 payload 搜索入口，流追踪页分析效率提升。
- HTTP 大 payload 不再无约束撑开列表，可通过弹窗查看完整内容。
- Workspace 标题区从“大段混合 JSX”拆成三个职责明确的控件组。
- 项目源码层面移除了深色模式残留，更贴合当前浅色单主题定位。
- 严格 TS 未用符号门禁恢复可用。

## 六、遗留与下一轮建议

### 遗留问题

1. `Workspace.tsx` 已拆标题区 actions，但协议解析树、Hex 视图、过滤器栏仍是页面内本地实现，仍可继续拆为工作台子组件。
2. `StreamSearchBar` 当前按 chunk body 做纯文本过滤，尚未做高亮命中位置，也没有“跳转到 chunk 内具体偏移”。
3. `StreamPayloadDialog` 已提供复制/导出，但还没有统一摘要信息区，例如编码、原始字节数、截断原因。
4. `git diff --check` 暂受前序脏工作区 trailing whitespace 影响，建议单独开一轮“格式噪声清理”，避免与功能改动混在一起。
5. USB / Vehicle / Industrial 页面仍存在本地 Panel / StatCard 模式，可继续迁移到 `SurfacePanel` / `MetricCard`。

### 下一轮建议

1. 拆分 Workspace 的过滤器栏、协议树、Hex 视图为独立组件，继续降低主页面复杂度。
2. 给 `StreamSearchBar` 增加命中高亮与当前命中序号，例如 `3 / 18`。
3. 给 `StreamPayloadDialog` 增加 payload 元信息区和“发送到 MISC 解码工作台”的可选入口。
4. 开一轮独立 trailing whitespace / EOF 格式清理，仅处理格式噪声，不夹带功能改动。
5. 继续迁移 USB / Vehicle / Industrial 的页面内通用卡片组件。
