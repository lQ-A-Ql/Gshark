# 日期: 2026-04-29
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round24）

## 一、本轮目标

本轮在保留 round23 遗留计划的基础上，新增一条审查准线：各页面视觉风格需要逐步协调统一，并以当前 MISC 页面为主要设计参考。目标是：

- 继续抽取 HTTP / TCP / UDP 流追踪中的重复 UI。
- 将“当前片段”预览区抽为共享设计系统组件。
- 以 MISC 页的浅色渐变、白色半透明卡片、柔和阴影、大圆角为准线，收敛流追踪页面的视觉层级。
- 不引入深色模式，不保留 dark variant。

## 二、本轮复核评论

本轮复查 MISC 页面后，确认它已经形成较完整的视觉基调：

- 背景使用浅色径向光晕与线性渐变。
- 主体模块使用 `bg-white/88`、`backdrop-blur-xl`、大圆角与柔和阴影。
- 操作入口多使用圆角胶囊、细边框、浅色状态色。
- 页面整体偏“工具工作台”，而不是传统表格后台。

对照 HTTP / TCP / UDP 流追踪页，主要不协调点有三个：

1. 流追踪页面仍以纯白背景和较硬的 `rounded-xl border-border bg-card` 为主，视觉上比 MISC 更生硬。
2. 三个流页面都维护了相似的“当前片段”预览 JSX，重复且难以统一风格。
3. 片段卡虽然已经有搜索高亮，但卡片形态仍偏旧式边框块，与 MISC 的轻卡片风格不完全一致。

因此本轮优先做低风险风格协调：抽共享组件、轻调卡片，不改变数据加载和流切换逻辑。

## 三、本轮开发内容

### 1. 新增 StreamCurrentChunkPanel

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
```

完成：

- 新增 `StreamCurrentChunkPanel` 共享组件。
- 统一支持：
  - 标题与说明；
  - 方向 badge；
  - packet / stream-index / bytes 等 chips；
  - payload 文本预览；
  - 搜索高亮；
  - 空状态；
  - “查看完整 payload”操作。
- 使用接近 MISC 页的视觉语言：
  - `rounded-[24px]`；
  - `border-white/80`；
  - `bg-white/88`；
  - `backdrop-blur-xl`；
  - 柔和 slate 阴影；
  - 胶囊 chips。

当前收益：

- 三个流页面不再各自维护右侧当前片段预览结构。
- 当前片段卡片拥有和 MISC 模块卡片更一致的视觉层级。
- 后续若要增加“发送到 MISC 解码工作台”，只需在共享组件或调用处扩展 action。

### 2. 替换 HTTP / TCP / UDP 当前片段预览

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\HttpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TcpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UdpStream.tsx
```

完成：

- HTTP 当前片段预览替换为 `StreamCurrentChunkPanel`。
- TCP 当前片段预览替换为 `StreamCurrentChunkPanel`。
- UDP 当前片段预览替换为 `StreamCurrentChunkPanel`。
- 保留原有：
  - packet / chunk / stream-index / bytes 元信息；
  - 方向 badge；
  - 搜索词高亮；
  - 截断时打开完整 payload；
  - 空状态文案。

当前收益：

- HTTP / TCP / UDP 的右侧预览一致性明显提升。
- 重复 JSX 减少，后续调整当前片段视觉时只改一处。
- 用户在三类流追踪间切换时，预览区结构和交互位置更稳定。

### 3. 流追踪页面向 MISC 视觉准线收敛

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\HttpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\TcpStream.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UdpStream.tsx
```

完成：

- HTTP / TCP / UDP 页面背景改为浅色渐变与轻微顶部光晕。
- TCP / UDP 列表容器从硬边框卡片调整为白色半透明大圆角卡片。
- `StreamChunkCard` 圆角、阴影、hover 和选中态调整为更接近 MISC 模块卡片。
- 选中态从偏硬的蓝色 ring 调整为更柔和的 violet ring 与阴影。

当前收益：

- 流追踪页不再与 MISC 页呈现明显割裂的背景和卡片系统。
- 页面仍保持分析工具的高密度信息承载，没有过度装饰化。
- MISC 作为全站风格准线开始沉淀到共享设计系统组件。

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
git diff --check -- frontend/src/app/components/DesignSystem.tsx frontend/src/app/pages/HttpStream.tsx frontend/src/app/pages/TcpStream.tsx frontend/src/app/pages/UdpStream.tsx
```

结果：

- 通过。

## 五、当前收益

- 在保留原计划的重复 UI 清理方向上，完成了当前片段预览组件抽取。
- 新增“以 MISC 为准线”的设计协调要求，并实际落到流追踪页面。
- HTTP / TCP / UDP 页面背景、卡片层级、预览区和片段卡视觉更统一。
- 本轮没有引入深色模式残留，严格 TS、测试、构建、dark 扫描和局部 diff check 均通过。

## 六、遗留与下一轮建议

### 遗留问题

1. HTTP / TCP / UDP 仍各自维护搜索统计、当前索引、chunk 过滤逻辑，可继续抽为共享 hook。
2. TCP / UDP 的 raw chunk 渲染与截断逻辑高度相似，可抽到 `core/stream-utils` 或共享 hook。
3. HTTP 顶部搜索条区域仍比 TCP / UDP 更独立，下一轮可继续统一控制区卡片层级。
4. Workspace 仍偏传统工作台风格，尚未完全对齐 MISC 的渐变背景与卡片阴影。
5. “发送到 MISC 解码工作台”仍未实现上下文传递。

### 下一轮建议

1. 抽取 `useStreamSearch` 或 `useChunkSearch`，统一 chunk 过滤、匹配计数、当前索引导航。
2. 抽取 TCP / UDP raw stream 页面公共逻辑，减少两个页面的平行维护成本。
3. 以 MISC 为准线继续审查 Workspace、C2/APT、USB/Vehicle/Industrial 的卡片、标题、背景和按钮风格。
4. 为 `StreamCurrentChunkPanel` 增加可选二级 action slot，承接“发送到 MISC”而不破坏当前布局。
5. 单独设计页面风格协调 checklist，纳入后续报告固定复核项。
