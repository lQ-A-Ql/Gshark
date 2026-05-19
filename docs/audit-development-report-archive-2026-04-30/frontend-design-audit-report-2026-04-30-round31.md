# 日期: 2026-04-30
# 署名: Codex

# 前端全站设计缺陷复核与优化报告（round31）

## 一、本轮目标

本轮继续执行“复查评论、优化、报告”的前端收口迭代，目标从新增功能转为彻底解决上一轮遗留的低风险设计债务：

- 收束页面级业务表格冗余，优先处理 C2 与 USB 页面中仍手写的表格结构。
- 扩展共享 `AnalysisDataTable`，让它能够承接复杂列、行点击、展开详情和空状态。
- 继续以 MISC 页面为浅色单主题准线，清理普通 UI 中残留的暗色块、暗色遮罩和黑色按钮。
- 复核浏览器拖拽页面行为屏蔽逻辑，确认不会再因拖放文件触发浏览器默认导航。
- 续写 docs 下的前端开发报告，并更新当天归档索引和分类摘要。

本轮不引入深色模式，不修改后端协议算法，不改变页面路由结构。

## 二、本轮复核评论

复查 round30 后的代码，主要遗留集中在两类：

1. 复杂表格虽然已经有共享组件基础，但 C2 聚合详情与 USB 会话/设备/文件列表仍存在页面内手写 `<table>`。
2. MISC 相关模块和弹窗遮罩中还有若干普通暗色 UI 表达，例如黑色按钮、深色头图和黑色半透明 overlay。
3. `dark` / `dark:` 显式深色模式分支已经没有命中，当前问题不是“双主题残留”，而是局部暗色视觉块未完全贴合 MISC 浅色准线。
4. 浏览器拖拽屏蔽逻辑已经在 `MainLayout` 中存在，并有单测覆盖 `dragstart`、显式 drop zone 白名单和 cleanup 行为，本轮只做复核与验证。

因此本轮选择先增强共享表格，再迁移 C2 / USB 中可证明等价的业务表格；对代码/Hex 预览和视频播放底色只做白名单记录，不为了浅色统一牺牲内容可读性。

## 三、本轮开发内容

### 1. `AnalysisDataTable` 增强为复杂业务表格基座

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\analysis\AnalysisPrimitives.tsx
```

完成：

- 新增泛型列定义 `AnalysisTableColumn<T>`。
- 支持 `columns`、`data`、`rowKey`、`emptyText` 等结构化输入。
- 支持 `rowClassName`、`cellClassName`、`headerCellClassName`、`wrapperClassName`、`tableClassName`、`headerClassName`。
- 支持 `onRowClick`，用于保留原页面的行选择与详情联动。
- 支持 `renderExpandedRow`、`expandedRowClassName`、`expandedCellClassName`，用于承接详情展开行。
- 保持旧 children 用法兼容，避免一次性迁移影响仍未接入的页面。

当前收益：

- 表格能力从简单容器升级为可复用的数据表格原语。
- 后续页面迁移不再需要继续复制 `<table>`、`<thead>`、`<tbody>`、空状态和行展开样板。
- 共享组件仍保持轻量，没有引入新的表格库或复杂状态机。

### 2. C2 页面业务表格迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\C2Analysis.tsx
```

完成：

- 将 C2 聚合、会话、端点等页面内业务表格迁移到 `AnalysisDataTable`。
- 保留原有行点击、选中态、展开详情和证据预览行为。
- 使用列定义表达列宽、标题、单元格渲染与空状态文案。
- 页面不再直接维护大段表格 DOM 样板。

当前收益：

- C2 页面从“功能表格孤岛”回到共享分析组件体系。
- 行为保持稳定，但后续样式调整可以集中在 `AnalysisDataTable`。
- C2 页面代码更聚焦于分析数据与业务渲染，而不是重复布局结构。

### 3. USB 页面业务表格迁移

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\UsbAnalysis.tsx
```

完成：

- 将 USB 设备、会话、文件/对象等业务表格迁移到 `AnalysisDataTable`。
- 保留原有选中态、详情区、播放控制入口和 payload 预览。
- 表格空状态、列宽、单元格内容和点击行为统一通过共享表格配置承接。

当前收益：

- USB 页面与 C2、APT、MISC 等分析页面的视觉结构进一步统一。
- 页面级表格重复实现大幅减少。
- 后续如果要调整 hover、sticky header、空状态和边框，只需优先改共享表格。

### 4. 删除已失去职责的冗余组件

修改文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\DesignSystem.tsx
```

完成：

- 删除不再使用的 `DataTableShell`。
- 业务表格统一转向 `AnalysisDataTable`，避免两个共享表格壳并存。

复查结果：

```powershell
Get-ChildItem -Path frontend/src/app -Recurse -Include *.tsx,*.ts |
  Select-String -Pattern '<table|<thead|<tbody|DataTableShell'
```

当前只剩：

- `AnalysisPrimitives.tsx`：共享表格原语。
- `UpdateCenter.tsx`：Markdown 渲染器的 table / thead 映射。

这两处均不是页面级业务表格冗余。

### 5. 普通暗色 UI 残留清理

修改范围：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\CaptureMissionControl.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\StreamDecoderWorkbench.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\ui\alert-dialog.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\ui\dialog.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\components\ui\sheet.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\misc\modules\*.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\pages\MiscTools.tsx
```

完成：

- MISC 模块中的普通黑色 pill、按钮和状态标签改为浅色 cyan / sky / slate 系表达。
- Payload 解码模块“识别候选”按钮从黑色按钮改为 cyan 主按钮。
- MISC 导入按钮从黑色按钮改为 cyan 主按钮。
- `GenericMiscModule` 头图区从深色渐变改为浅色 cyan / blue 渐变。
- Dialog、Sheet、AlertDialog、Payload 弹窗与设置侧栏 overlay 从黑色半透明遮罩改为浅色模糊遮罩。
- “去 MISC”等快捷动作按钮改为浅色边框按钮。

复查结果：

```powershell
Get-ChildItem -Path frontend/src -Recurse -Include *.tsx,*.ts,*.css |
  Select-String -Pattern '\bdark\b|dark:'
```

结果：

- 无命中。

剩余暗色白名单：

- C2 / USB / UpdateCenter 的代码、Hex、Markdown code block 预览。
- MediaAnalysis 的 video 播放黑底。
- 正常彩色主按钮上的 `text-white`。

这些属于可读性或媒体播放需要，不属于深色模式残留。

### 6. 浏览器拖拽页面屏蔽复核

复核文件：

```text
C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.tsx
C:\Users\QAQ\Desktop\gshark\frontend\src\app\layouts\MainLayout.test.ts
```

确认：

- `installBrowserPageDragGuard()` 同时在 `window` 与 `document` capture 阶段监听 `dragstart`、`dragover`、`drop`。
- 非显式白名单区域会执行 `preventDefault()` 与 `stopPropagation()`。
- 显式设置 `data-gshark-drop-zone="true"` 的拖放区不被全局拦截。
- cleanup 后事件恢复默认行为。

这意味着浏览器默认拖放导航问题已经在布局层统一屏蔽，不需要每个页面重复处理。

## 四、验证结果

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

- 通过，12 个测试文件、47 个测试全部通过。

已执行：

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
npm run build
```

结果：

- 通过，Vite production build 成功。

已执行：

```powershell
git diff --check -- frontend/src/app/components/CaptureMissionControl.tsx frontend/src/app/components/DesignSystem.tsx frontend/src/app/components/StreamDecoderWorkbench.tsx frontend/src/app/components/analysis/AnalysisPrimitives.tsx frontend/src/app/components/ui/alert-dialog.tsx frontend/src/app/components/ui/dialog.tsx frontend/src/app/components/ui/sheet.tsx frontend/src/app/layouts/MainLayout.tsx frontend/src/app/misc/modules/GenericMiscModule.tsx frontend/src/app/misc/modules/HTTPLoginAnalysisModule.tsx frontend/src/app/misc/modules/MySQLSessionAnalysisModule.tsx frontend/src/app/misc/modules/NTLMSessionMaterialsModule.tsx frontend/src/app/misc/modules/PayloadWebShellDecoderModule.tsx frontend/src/app/misc/modules/ShiroRememberMeAnalysisModule.tsx frontend/src/app/misc/modules/SMB3SessionKeyModule.tsx frontend/src/app/misc/modules/SMTPSessionAnalysisModule.tsx frontend/src/app/pages/MiscTools.tsx frontend/src/app/pages/C2Analysis.tsx frontend/src/app/pages/UsbAnalysis.tsx
```

结果：

- 通过。

说明：

- 本轮未修改后端协议逻辑，因此未额外运行后端 `go test`。
- `npm run build` 仍提示 `MiscTools`、`UpdateCenter`、`index` 等 chunk 偏大，这是构建体积治理问题，不影响本轮表格与风格收口结论。

## 五、当前收益

- 页面级业务表格冗余已经基本闭环，扫描只剩共享表格原语和 Markdown 渲染器。
- `AnalysisDataTable` 已具备承接复杂分析表格的基础能力，后续迁移成本更低。
- `DataTableShell` 已删除，表格共享层不再分裂。
- 普通暗色 UI 残留已清理，MISC 模块、弹窗遮罩和快捷按钮更贴近浅色单主题准线。
- `dark` / `dark:` 显式深色模式分支仍为零命中。
- 浏览器拖拽页面导航屏蔽已由布局层统一覆盖，并有测试保护。
- 前端类型检查、单测和生产构建均通过。

## 六、遗留与下一轮建议

### 遗留问题

1. `MiscTools`、`UpdateCenter` 和主入口 chunk 仍偏大，后续需要做懒加载和模块拆分。
2. 代码/Hex/Markdown 预览仍保留功能性深色块，这是可读性例外，不应按深色模式残留直接删除。
3. `RecommendationCard`、`CategoryCard`、`GuideCard` 等业务语义卡片仍需继续观察，暂不建议为了“零重复”强行抽象。
4. 本轮验证以命令行为主，仍建议后续用浏览器做一次视觉走查，确认 C2 / USB 表格迁移后的真实滚动、展开和响应式表现。

### 下一轮建议

1. 优先处理构建体积，检查 `MiscTools` 内建模块和 `UpdateCenter` Markdown 渲染依赖是否能进一步延迟加载。
2. 对功能性深色块建立明确白名单，避免后续审计反复把代码预览误判为主题残留。
3. 继续以 MISC 页面为准线复查新增协议模块，重点关注标题区、状态标签、按钮、空状态和导出入口。
4. 如果继续做冗余治理，优先从“可证明等价”的业务卡片开始，不要把有明确领域语义的组件过度抽象。
