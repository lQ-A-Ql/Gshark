# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round22）

## 一、本轮目标

本轮继续 round21 的前端结构治理，重点是把已经切出边界的 Workspace 局部组件迁出主页面文件，并补齐流搜索的可视化反馈。目标是：

- 将 Workspace 的过滤器栏、协议树、Hex / ASCII 视图迁移到独立组件文件。
- 保持 Workspace 主文件作为页面编排层，减少内嵌 UI 细节。
- 给 `StreamChunkCard` 增加搜索词高亮能力。
- 在 HTTP / TCP / UDP 流追踪列表中显示轻量命中高亮。
- 继续保持浅色单主题，不引入 deep theme / dark variant。

## 二、本轮复核评论

round21 已经把 `DisplayFilterBar`、`ProtocolTreePanel`、`HexAsciiPanel`、`HexAsciiRow`、`HexByteButton` 从主 JSX 中拆成局部组件，但它们仍在 `Workspace.tsx` 内部，导致文件仍然偏大。继续评审后，主要问题有两个：

1. `Workspace.tsx` 虽然职责更清楚，但仍承载过多组件定义，后续编辑过滤器或 Hex 视图时仍会频繁打开同一个大文件。
2. 流搜索栏已经显示当前位置与匹配数，但片段正文没有视觉命中高亮，搜索结果需要用户自己在 payload 文本里找关键词。

因此本轮不再扩大页面范围，优先把这两个可控问题解决掉。

## 三、本轮开发内容

### 1. 迁移 Workspace 过滤器栏组件

新增文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\workspace\DisplayFilterBar.tsx
```

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\Workspace.tsx
```

完成：

- 将 `DisplayFilterBar` 从 `Workspace.tsx` 迁移到独立组件文件。
- 保留原有：
  - display filter 输入；
  - datalist 建议；
  - Enter 应用；
  - 清空过滤；
  - 清空历史；
  - 禁用态控制。

当前收益：

- 过滤器栏可以独立演进，例如后续增加语法提示、最近过滤器面板、错误定位提示，不必继续拉长 Workspace 主文件。

### 2. 迁移 Workspace 协议树组件

新增文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\workspace\ProtocolTreePanel.tsx
```

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\Workspace.tsx
```

完成：

- 将 `ProtocolTreePanel` 与内部 `TreeNode` 从 `Workspace.tsx` 迁移到独立组件文件。
- 保留原有：
  - 节点展开 / 收起；
  - 选中态；
  - byte range 展示；
  - 点击协议字段联动 Hex 偏移；
  - 节点 ref 注册与自动滚动。

当前收益：

- 协议树可以独立优化，例如字段搜索、节点折叠策略、字段 tooltip、异常字段标识。

### 3. 迁移 Workspace Hex / ASCII 视图组件

新增文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\workspace\HexAsciiPanel.tsx
```

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\Workspace.tsx
```

完成：

- 将 `HexAsciiPanel`、`HexAsciiRow`、`HexByteButton` 和 `buildHexRows` 迁移到独立组件文件。
- 保留原有：
  - Packet 标签；
  - Hex 与 ASCII 双列视图；
  - 字节范围高亮；
  - 当前字节 cursor 高亮；
  - 点击字节反向联动协议树最近节点。

当前收益：

- `Workspace.tsx` 不再维护 Hex 行渲染和按钮状态细节。
- Hex 视图后续可以独立演进，例如字段边界提示、右键复制、ASCII/Hex hover 联动。

### 4. StreamChunkCard 搜索命中高亮

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\HttpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TcpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UdpStream.tsx
```

完成：

- `StreamChunkCard` 新增 `highlight` 参数。
- 新增内部 `renderHighlightedText`，按大小写不敏感方式切分文本并用浅色 `mark` 高亮。
- HTTP / TCP / UDP 片段列表均传入当前 deferred 搜索词。

当前收益：

- 用户能在流片段卡片内直接看到命中位置。
- 高亮逻辑集中在 `StreamChunkCard`，不需要三个流页面分别实现。
- 对 hex / formatted / ascii 模式保持宽容：只有渲染文本中实际存在的查询词会高亮，不改变原有过滤逻辑。

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
git diff --check -- frontend/src/app/components/DesignSystem.tsx frontend/src/app/components/workspace/DisplayFilterBar.tsx frontend/src/app/components/workspace/ProtocolTreePanel.tsx frontend/src/app/components/workspace/HexAsciiPanel.tsx frontend/src/app/pages/Workspace.tsx frontend/src/app/pages/TcpStream.tsx frontend/src/app/pages/UdpStream.tsx frontend/src/app/pages/HttpStream.tsx
```

结果：

- 通过。

## 五、当前收益

- Workspace 主文件进一步回到页面编排职责，过滤器、协议树、Hex 视图都已进入 `components/workspace`。
- 流搜索从“筛选 + 数字反馈”升级为“筛选 + 数字反馈 + 片段内高亮”。
- HTTP / TCP / UDP 的流片段视觉行为继续保持统一。
- 本轮触碰文件通过严格 TS、测试、构建、dark 扫描和局部 diff check。

## 六、遗留与下一轮建议

### 遗留问题

1. Workspace 顶部 `CaptureFileControls`、`PacketPagingControls`、`PacketLocatorControls` 仍在 `Workspace.tsx` 内，可继续迁移到 `components/workspace`。
2. 搜索高亮目前只在片段卡片中生效，右侧“当前片段”预览与完整 payload 弹窗尚未高亮。
3. 搜索仍是 chunk 级过滤，没有定位到具体命中偏移，也没有当前命中 `n / total` 的词级导航。
4. MISC 解码工作台入口仍是普通导航，不携带 payload 上下文。
5. 全局 trailing whitespace 历史噪声仍建议单独处理，避免与功能改动混在一起。

### 下一轮建议

1. 迁移 Workspace 顶部三个 controls 到 `components/workspace`。
2. 提炼 `HighlightedPayloadText` 为可复用组件，让右侧预览和 Payload 弹窗也能复用同一高亮逻辑。
3. 评估是否增加“发送到 MISC 解码工作台”的可选路由状态，若实现需保持用户可感知且不自动覆盖 MISC 输入。
4. 单独开格式噪声清理轮，集中处理 trailing whitespace / EOF。
5. 继续迁移 USB / Vehicle / Industrial 的本地通用卡片到 `SurfacePanel` / `MetricCard`。
