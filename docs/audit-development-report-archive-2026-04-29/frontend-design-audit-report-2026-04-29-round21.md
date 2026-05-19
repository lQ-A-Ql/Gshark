# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round21）

## 一、本轮目标

本轮继续解决 round20 遗留问题，重点保持在前端结构治理与流追踪体验优化，不引入新的后端协议能力。目标是：

- 将 Workspace 内仍然内嵌的过滤器栏、协议解析树、Hex / ASCII 视图拆成局部组件。
- 给 `StreamSearchBar` 补充当前结果位置表达，避免只显示总匹配数。
- 给 `StreamPayloadDialog` 增加统一元信息区和额外操作插槽。
- 在 HTTP / TCP / UDP 的完整 payload 弹窗中展示协议、stream、packet、方向、视图、字节数等上下文。
- 保持浅色单主题，不恢复任何深色模式分支。

## 二、上一轮复核评论

round20 已经完成 TCP / UDP 搜索、统一 Payload 弹窗、Workspace 顶部 actions 拆分和 dark 残留清理。继续复查后，仍有三个适合本轮收掉的 UI 债务：

1. `Workspace.tsx` 主 JSX 仍包含过滤器栏、协议树和 Hex/ASCII 视图的大段细节，页面仍偏“巨型组件”。
2. `StreamSearchBar` 虽然在 HTTP / TCP / UDP 统一，但只显示“匹配数”，用户无法直接看到当前位于第几个过滤结果。
3. `StreamPayloadDialog` 只有标题、副标题、复制和导出，缺少结构化上下文信息，用户需要从标题文本中推断 stream / packet / 方向 / 视图。

本轮围绕这三项继续做低风险收敛。

## 三、本轮开发内容

### 1. Workspace 过滤器栏拆分

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\Workspace.tsx
```

新增局部组件：

- `DisplayFilterBar`
  - 负责显示过滤器输入框。
  - 负责 datalist 建议、Enter 应用、清空过滤、清空历史。
  - 主 `Workspace` 不再直接维护过滤器栏 JSX。

当前收益：

- 过滤器交互从主工作台编排中剥离。
- 后续如果要增强过滤器语法提示、错误态、高亮历史记录，可集中改 `DisplayFilterBar`。

### 2. Workspace 协议树拆分

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\Workspace.tsx
```

新增局部组件：

- `ProtocolTreePanel`
  - 负责协议解析树标题、空态、节点渲染。
  - 继续复用既有 `TreeNode`，不改变展开/收起、选中、字节范围联动行为。

当前收益：

- 主 `PanelGroup` 只保留布局关系。
- 协议树后续可继续迁移到独立文件，而不需要再切割业务逻辑。

### 3. Workspace Hex / ASCII 视图拆分

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\Workspace.tsx
```

新增局部组件：

- `HexAsciiPanel`
  - 负责 Hex / ASCII 面板标题、空态、滚动容器。
- `HexAsciiRow`
  - 负责单行 offset、hex bytes、ascii bytes。
- `HexByteButton`
  - 负责单字节选中态、范围高亮、点击联动。

当前收益：

- Hex 视图的渲染细节不再堆在主页面里。
- 字节按钮状态计算从行内 JSX 中抽出，后续可继续优化 hover、range tooltip、字段解释提示。

### 4. StreamSearchBar 当前结果表达增强

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\HttpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TcpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UdpStream.tsx
```

完成：

- `StreamSearchBar` 新增可选 props：
  - `resultCount`
  - `currentIndex`
  - `resultLabel`
  - `disabled`
- 搜索栏现在可以显示类似：

```text
第 3 / 18 片段 · 24 匹配
```

- HTTP / TCP / UDP 均传入当前可见结果数和当前选中结果序号。
- 当结果数为 0 时，上一条 / 下一条按钮会进入禁用态。

当前收益：

- 用户能知道当前在过滤结果中的位置。
- “匹配数”和“可见片段数”不再混在一个模糊数字里。

### 5. StreamPayloadDialog 元信息区与额外操作插槽

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\HttpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TcpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UdpStream.tsx
```

完成：

- `StreamPayloadDialog` 新增：
  - `meta`
  - `extraActions`
- 弹窗标题下新增浅色元信息网格，展示：
  - 协议；
  - stream；
  - packet；
  - 方向；
  - chunk / stream index；
  - 当前视图模式；
  - 原始字节或估算字节；
  - 预览阈值。
- HTTP / TCP / UDP 弹窗新增“打开 MISC 解码工作台”操作入口。

当前收益：

- 完整 payload 弹窗从“纯文本详情”升级为“带上下文的取证视图”。
- 用户在查看 payload 时不需要回看流列表确认来源。
- MISC 解码工作台入口已出现，但本轮仍不做 payload 路由态传递，避免重新引入流追踪页与 MISC 的强耦合。

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

已执行本轮触碰文件格式检查：

```powershell
git diff --check -- frontend/src/app/components/DesignSystem.tsx frontend/src/app/pages/Workspace.tsx frontend/src/app/pages/TcpStream.tsx frontend/src/app/pages/UdpStream.tsx frontend/src/app/pages/HttpStream.tsx
```

结果：

- 通过。

说明：

- 本轮只对触碰文件做 diff check。
- 全局 `git diff --check` 仍建议单独开“历史格式噪声清理”处理，因为前序脏工作区中还有与本轮无关的 trailing whitespace。

## 五、当前收益

- `Workspace.tsx` 从“一页包办所有细节”进一步转为编排层，过滤器、协议树、Hex 视图已有清晰局部组件边界。
- HTTP / TCP / UDP 的搜索栏现在能表达当前结果位置，流追踪搜索体验更接近可用工作台。
- Payload 弹窗具备统一元信息区，取证上下文更明确。
- Payload 弹窗新增 MISC 入口，但仍保持手动解码工作台集中在 MISC 页。
- 本轮触碰文件通过严格 TS、测试、构建、dark 扫描和局部 diff check。

## 六、遗留与下一轮建议

### 遗留问题

1. `Workspace.tsx` 的局部组件已经拆出，但仍在同一文件内；下一步可迁移到 `components/workspace/*`，进一步降低文件体积。
2. `StreamSearchBar` 已显示当前结果位置，但还没有对 payload 内容中的命中词做 inline highlight，也没有跳转到 chunk 内具体偏移。
3. “打开 MISC 解码工作台”当前只是导航入口，尚未携带 payload 或候选上下文；这保持了解耦，但少了一步自动填充。
4. 全局 trailing whitespace 历史噪声仍存在，应单独处理，不建议和功能改动混在一起。
5. USB / Vehicle / Industrial 页面仍存在本地 Panel / StatCard 模式，可继续迁移到 `SurfacePanel` / `MetricCard`。

### 下一轮建议

1. 把 `DisplayFilterBar`、`ProtocolTreePanel`、`HexAsciiPanel` 迁移到独立 workspace 组件文件。
2. 给流 payload 搜索增加命中词高亮与当前命中偏移。
3. 设计 MISC 解码工作台的可选输入上下文协议，决定是否允许从流弹窗“一键带入 payload”。
4. 单独执行格式噪声清理轮，只处理 trailing whitespace / EOF，不夹带功能修改。
5. 继续迁移 USB / Vehicle / Industrial 的页面内通用卡片。
