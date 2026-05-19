# 日期: 2026-04-30
# 署名: Codex

# 前端第一优先级闭环审计与修复报告（round33）

## 一、本轮目标

本轮按“第一优先级相关内容彻底完成”的口径继续收口，重点不是继续扩大页面范围，而是把上一轮暴露出的前端基础问题沉淀为可复用能力：

- 将数据包右键菜单的局部视口夹取逻辑升级为共享 `viewportPosition`、`useViewportSafePosition` 和 `FloatingSurface` 能力。
- 复核复杂业务表格是否仍存在页面级手写 table 残留。
- 复核深色模式残留，确保不恢复深色模式、不新增 `dark:` 分支。
- 继续收敛下载、复制、导出类重复实现，把可证明等价的浏览器文件动作集中到共享工具。
- 建立真实浏览器视觉回归清单，覆盖页面切换、背景过渡、拖拽屏蔽、浮层边界、HEX 对齐和窄屏滚动。
- 按既有归档格式续写报告，并同步更新当天归档索引、前端合并摘要和跨方向路线图。

## 二、本轮复核评论

本轮复查上一轮报告和当前源码后，结论如下：

1. 右键菜单位置异常的直接根因已经修复，但上一轮仍只是组件局部 helper；如果后续 select、tooltip、popover、右键菜单各自再写一套边界算法，显示 bug 会复发。本轮把它提升为共享基础层。
2. 复杂业务表格迁移基本闭环。当前 `<table>` 扫描只剩 `AnalysisPrimitives.tsx` 中的共享 `AnalysisDataTable` 原语，以及 `UpdateCenter.tsx` 的 Markdown renderer 映射，后者属于渲染 Markdown 表格的功能性例外。
3. `dark` / `dark:` 扫描无命中，浅色单主题策略仍成立。代码、HEX、视频等高对比区域不属于深色模式残留，应继续作为功能白名单维护。
4. 下载、复制、导出重复实现已明显收敛。`browserFile` 成为浏览器下载与剪贴板动作的集中入口，`wailsBridge` 中可复用的下载逻辑已改为调用该入口。
5. Tooltip 浮层已经具备 Radix collision 默认值，并从暗色气泡改为更贴近 MISC 准线的浅色浮层。
6. 当前仍缺少真实浏览器截图走查工具链的可用入口，本轮建立回归清单并完成代码/单测/构建验证，但不把清单误报为已截图执行。

## 三、本轮开发内容

### 1. 共享视口安全定位基座

新增文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\utils\viewportPosition.ts
C:\Users\QAQ\Desktop\gshark\frontend\src\app\utils\viewportPosition.test.ts
C:\Users\QAQ\Desktop\gshark\frontend\src\app\hooks\useViewportSafePosition.ts
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\ui\FloatingSurface.tsx
```

完成：

- 新增 `getViewportSize()`、`clampFloatingPoint()`、`getPointerFloatingPosition()`，统一处理浮层尺寸、视口尺寸、安全边距和极小视口回退。
- 新增 `useViewportSafePosition()`，把“按鼠标事件打开、携带上下文、关闭浮层、判断是否打开”的状态管理从页面中抽出。
- 新增 `FloatingSurface`，统一 fixed portal、浅色半透明面板、圆角、边框、阴影和 backdrop blur。
- `viewportPosition` 单测覆盖正常坐标、右下角夹取、负坐标、极小视口、自定义 margin 与浮层尺寸。

当前收益：

- 第一优先级中的 `useViewportSafePosition` / `FloatingSurface` 类能力已经落地。
- 后续自定义右键菜单、轻量 popover、手写 select 面板不需要再复制坐标夹取代码。
- 视口边界逻辑从“组件经验修复”升级为“共享可测试基座”。

### 2. 数据包右键菜单迁移到共享浮层

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\PacketVirtualTable.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\PacketVirtualTable.test.tsx
```

完成：

- 移除组件内局部 `getContextMenuPosition()`，改用 `useViewportSafePosition<Packet>()`。
- 菜单渲染从手写 `createPortal()` div 改为 `FloatingSurface`。
- 菜单上下文从 `{ x, y, packet }` 改为共享 hook 的 `position.context`，减少页面状态形状重复。
- 增加真实渲染断言：在 `800x600` 视口右下角 `clientX=790`、`clientY=590` 右键时，菜单会渲染为 `left: 596px; top: 470px`，确保 portal UI 实际使用了夹取结果。
- 继续保留菜单外点击关闭、Escape 关闭、滚动/resize 关闭、菜单自身阻止冒泡等交互。

当前收益：

- 用户截图类“右键菜单位置异常”问题有了共享层和集成测试双重保护。
- 右键菜单不再是表格组件内部的一次性实现，后续其他页面可以复用相同模式。

### 3. Tooltip 边界与浅色风格收口

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\ui\tooltip.tsx
```

完成：

- `TooltipContent` 默认启用 `avoidCollisions=true`。
- 默认 `collisionPadding=12`、`sideOffset=6`，避免 tooltip 盲目贴边或越界。
- 暗色 tooltip 改为 `bg-white/95`、`border-slate-200`、`text-slate-700` 和柔和阴影。
- Arrow 同步改为浅色边框与浅色填充。
- 增加 `max-w-[min(22rem,calc(100vw-1.5rem))]`，窄屏下不会无限撑宽。

当前收益：

- 侧栏、按钮提示和其他共享 tooltip 更贴近 MISC 浅色准线。
- 不再保留暗色 tooltip 残留，也没有引入深色模式分支。

### 4. 下载、复制、导出重复实现继续收敛

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\integrations\wailsBridge.ts
```

关联共享入口：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\utils\browserFile.ts
```

完成：

- `wailsBridge` 引入 `downloadBlob`。
- WinRM 导出下载不再保留本地 Blob 下载实现，改为复用 `browserFile.downloadBlob()`。
- 扫描结果显示：浏览器下载和剪贴板动作集中在 `browserFile`；剩余 `createObjectURL` / `document.createElement` 命中分别属于媒体播放生命周期、文件选择 input、测试 DOM 构造和共享浏览器文件工具本身。

当前收益：

- 第一优先级中的“继续清理下载、复制、导出重复代码”已完成一层可证明等价收敛。
- 后续页面新增下载/复制能力应优先走 `browserFile`，不再内联创建 `<a>` 下载或直接写 `navigator.clipboard`。

### 5. 真实浏览器视觉回归清单

本轮建立以下清单，用于后续真实浏览器人工/自动截图走查：

1. 页面切换和背景过渡：Workspace、MISC、C2、APT、工控、车机、对象导出。
2. 拖拽屏蔽：普通区域拖入文件不触发浏览器跳转；显式 drop zone 仍可接收拖拽。
3. 浮层边界：数据包表格右下角右键、顶部导航菜单、侧栏 tooltip、MISC select。
4. HEX 对齐：16 字节行、offset、hex、ASCII 在正常和窄屏下不错位；窄屏可以横向滚动。
5. 窄屏滚动：MISC 模块、流追踪、复杂表格展开行。
6. 浅色单主题：无 `dark:` 残留；代码、视频、HEX 等功能性高对比区域按白名单复核。

说明：

- 本轮尝试查找本地浏览器控制工具入口，但当前可用工具列表未暴露可直接执行 localhost 截图走查的浏览器控制接口。
- 因此本轮只把视觉回归清单固化到报告，不声称已经完成截图级回归。

## 四、验证结果

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx vitest run src/app/utils/viewportPosition.test.ts src/app/components/PacketVirtualTable.test.tsx
```

结果：

- 通过，2 个测试文件、10 个测试通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npx tsc --noEmit --noUnusedLocals --noUnusedParameters
```

结果：

- 通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm test
```

结果：

- 通过，13 个测试文件、56 个测试通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm run build
```

结果：

- 通过，Vite production build 成功。
- 既有大 chunk 仍存在：`MiscTools`、`UpdateCenter`、主入口 `index`，这是后续性能治理事项。

已执行表格扫描：

```powershell
Get-ChildItem -LiteralPath 'frontend\src\app' -Recurse -File -Include *.tsx,*.ts |
  Select-String -Pattern '<table\b|<thead\b|<tbody\b|<tr\b|<td\b|<th\b'
```

结果：

- 仅命中 `AnalysisPrimitives.tsx` 的共享 `AnalysisDataTable` 表格原语。
- 另命中 `UpdateCenter.tsx` 的 Markdown renderer 表格映射，作为功能性例外保留。

已执行深色模式扫描：

```powershell
Get-ChildItem -LiteralPath 'frontend\src\app' -Recurse -File -Include *.tsx,*.ts,*.css |
  Select-String -Pattern 'dark:|\bdark\b'
```

结果：

- 无命中。

已执行下载/复制实现扫描：

```powershell
Get-ChildItem -LiteralPath 'frontend\src\app' -Recurse -File -Include *.tsx,*.ts |
  Select-String -Pattern 'navigator\.clipboard|URL\.createObjectURL\(|document\.createElement\("a"\)|document\.createElement\('
```

结果：

- `browserFile.ts`：共享下载与复制入口，保留。
- `MediaAnalysis.tsx`：媒体播放 Blob URL 生命周期，保留。
- `wailsBridge.ts`：文件选择 input，保留。
- `MainLayout.test.ts`：拖拽屏蔽测试 DOM 构造，保留。

## 五、当前收益

- 第一优先级中最关键的浮层定位基座已完成：纯函数、hook、surface、集成测试四层齐备。
- 数据包右键菜单已迁移到共享浮层能力，截图类位置异常具备回归保护。
- Tooltip 的视口碰撞默认值和浅色风格已经统一，不再残留暗色气泡。
- 复杂表格迁移经过扫描复核，业务页面手写 table 基本闭环。
- 下载/复制/导出重复实现继续收敛，桥接层下载逻辑已接入共享 `browserFile`。
- 深色模式扫描无命中，继续保持浅色单主题。
- 前端类型检查、目标单测、全量单测和生产构建均通过。

## 六、遗留与下一轮建议

### 遗留问题

1. 真实浏览器视觉清单已经建立，但本轮未完成截图级执行；后续应在可用浏览器工具或人工走查环境中执行。
2. Radix Dialog、Sheet、Popover、Select 等第三方封装主要依赖自身 collision / overlay 机制；本轮未强行改造成 `FloatingSurface`，避免破坏无障碍和焦点管理。
3. `FloatingSurface` 当前适合右键菜单、轻量 popover 和手写浮层；复杂可聚焦菜单若要继续增强，应补键盘导航、焦点陷阱或迁移到成熟菜单组件。
4. 构建体积偏大的遗留仍存在，尤其是 `MiscTools`、`UpdateCenter` 和主入口 chunk。
5. 功能性高对比区域仍需白名单维护，避免后续误把代码、HEX、视频预览当作深色模式残留删除。

### 下一轮建议

1. 使用真实浏览器按本轮清单做截图走查，优先覆盖浮层边界、拖拽屏蔽、HEX 对齐和低高度窗口。
2. 继续将新出现的手写浮层接入 `useViewportSafePosition` / `FloatingSurface`，不要再新增局部坐标夹取 helper。
3. 若继续做冗余治理，优先治理下载/导出后的 toast 反馈、筛选动作和按钮动作重复。
4. 若转入性能治理，优先拆 `MiscTools` 模块懒加载和 `UpdateCenter` Markdown 渲染依赖。
5. 继续以 MISC 页面为视觉准线，但对代码、HEX、视频等安全分析阅读区保留功能性高对比白名单。
