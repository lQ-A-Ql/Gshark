# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round23）

## 一、本轮目标

本轮继续 round22 的前端结构治理，不扩大功能面，优先完成上一轮明确留下的两项可控问题：

- 将 Workspace 顶部抓包、分页、分组定位控制区迁出主页面文件。
- 将流追踪搜索高亮从片段卡内部逻辑提炼为可复用组件。
- 让 HTTP / TCP / UDP 的片段列表、右侧当前片段预览、完整 payload 弹窗共享同一套高亮表达。
- 继续保持浅色单主题，不引入 dark variant 或深色模式分支。

## 二、本轮复核评论

round22 已经把 Workspace 的过滤器栏、协议树、Hex / ASCII 视图移入 `components/workspace`，并在 `StreamChunkCard` 中补了片段级搜索高亮。继续复核后，本轮确认还有两个“已经暴露边界但尚未收束”的问题：

1. `Workspace.tsx` 顶部仍内嵌 `CaptureFileControls`、`PacketPagingControls`、`PacketLocatorControls`，导致页面文件仍保存较多低层 UI 细节。
2. 搜索高亮只在流片段卡片内生效，右侧固定预览与完整 payload 弹窗仍是纯文本，用户在打开详情后会失去搜索定位反馈。

因此本轮继续做窄切口优化：不改变路由、不改变数据状态、不新增后端接口，只把已存在的 UI 能力组件化并复用。

## 三、本轮开发内容

### 1. 迁移 Workspace 顶部控制区

新增文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\workspace\WorkspaceTopControls.tsx
```

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\Workspace.tsx
```

完成：

- 将 `CaptureFileControls` 从 `Workspace.tsx` 迁移到 `WorkspaceTopControls.tsx`。
- 将 `PacketPagingControls` 从 `Workspace.tsx` 迁移到 `WorkspaceTopControls.tsx`。
- 将 `PacketLocatorControls` 从 `Workspace.tsx` 迁移到 `WorkspaceTopControls.tsx`。
- 保留原有抓包路径输入、选择文件、路径打开、关闭抓包、上一页、下一页、页码跳转、分组号定位行为。
- `Workspace.tsx` 只保留状态编排、事件绑定、数据派发和面板布局。

当前收益：

- Workspace 主页面进一步减少内嵌 JSX 组件定义。
- 后续调整抓包工具条、分页工具条或定位工具条时，不需要继续触碰 Workspace 主体。
- `components/workspace` 目录形成更清晰的工作区组件边界。

### 2. 提炼 HighlightedPayloadText

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
```

完成：

- 新增导出组件 `HighlightedPayloadText`。
- 保留原有大小写不敏感的文本切分与浅色 `mark` 高亮策略。
- `StreamChunkCard` 改为使用 `HighlightedPayloadText`，不再直接绑定内部渲染函数。
- `StreamPayloadDialog` 新增可选 `highlight` 参数，并复用同一高亮组件渲染完整 payload。

当前收益：

- 搜索命中高亮从局部实现升级为设计系统能力。
- 未来 USB HID 文本、对象导出预览、MISC 解码结果等大文本区域也可以复用该组件。
- 高亮样式集中维护，避免 HTTP / TCP / UDP 三个页面各自分叉。

### 3. 统一流追踪当前片段与弹窗高亮

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\HttpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TcpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UdpStream.tsx
```

完成：

- HTTP 当前片段预览接入 `HighlightedPayloadText`。
- TCP 当前片段预览接入 `HighlightedPayloadText`。
- UDP 当前片段预览接入 `HighlightedPayloadText`。
- HTTP / TCP / UDP 的 `StreamPayloadDialog` 均传入当前 deferred 搜索词。
- 列表卡片、右侧预览、完整弹窗现在共用同一套高亮逻辑。

当前收益：

- 用户从列表点开详情后，搜索词不会“消失”。
- 右侧预览和弹窗在 ASCII / Raw / Formatted / Hex 等视图下保持宽容行为：只有渲染文本中实际存在的查询词会高亮，不改变原有过滤与渲染逻辑。
- 这是一处低风险体验优化，不影响流加载、切流、分页和导出流程。

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
git diff --check -- frontend/src/app/components/DesignSystem.tsx frontend/src/app/components/workspace/WorkspaceTopControls.tsx frontend/src/app/pages/Workspace.tsx frontend/src/app/pages/TcpStream.tsx frontend/src/app/pages/UdpStream.tsx frontend/src/app/pages/HttpStream.tsx
```

结果：

- 通过。

## 五、当前收益

- Workspace 顶部控制区已完成组件迁移，主页面职责进一步回到“状态 + 布局 + 数据流”。
- 流追踪搜索体验从片段卡扩展到当前片段预览和完整 payload 弹窗，减少用户在详情视图中重新寻找关键词的成本。
- `HighlightedPayloadText` 成为可复用的大文本高亮基元，为后续 MISC 解码结果、导出预览、对象内容预览继续统一 UI 留出入口。
- 本轮触碰文件通过严格 TS、测试、构建、dark 扫描和局部 diff check。

## 六、遗留与下一轮建议

### 遗留问题

1. HTTP / TCP / UDP 流页面仍各自维护 chunk 可见列表、匹配计数、当前片段、弹窗参数等相似逻辑，可继续抽取为 stream preview hook 或共享工具。
2. 搜索仍是 chunk 级过滤，高亮不是词级导航，尚不支持“当前第 n 个命中 / 总命中”的精确跳转。
3. `StreamPayloadDialog` 目前只支持文本复制与导出，尚未提供“发送到 MISC 解码工作台”的上下文传递。
4. `Workspace.tsx` 仍保留 `buildFrameBytes`、`findClosestNodeByOffset` 等纯逻辑函数，可考虑迁移到 workspace 工具文件并补单测。
5. 全局 trailing whitespace 历史噪声仍建议单独处理，避免与功能改动混在一起。

### 下一轮建议

1. 抽取 HTTP / TCP / UDP 流追踪共同的搜索统计、当前片段选择和弹窗 meta 生成逻辑。
2. 给 `HighlightedPayloadText` 增加可选命中统计返回能力，或者拆出纯函数以支持词级导航。
3. 评估“发送到 MISC 解码工作台”的轻量路由状态设计，确保不自动覆盖用户当前输入。
4. 将 Workspace 的纯逻辑函数迁移到 `core` 或 `components/workspace` 附近，并增加 focused 单测。
5. 单独开格式噪声清理轮，集中处理 trailing whitespace / EOF，不与功能优化混提交。
