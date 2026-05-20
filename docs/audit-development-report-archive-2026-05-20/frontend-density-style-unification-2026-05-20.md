# 前端全量美化与风格统一报告

署名：Codex

时间：2026-05-20 00:57:08 +08:00（Asia/Shanghai）

## 本轮目标

- 保留当前浅色、卡片、圆角与主题色体系。
- 提高分析页、工作台页和旧页面的信息密度。
- 统一新旧页面的页面壳、Hero、面板、表格、工具栏和空态风格。
- 不修改 API、业务数据流、缓存逻辑、路由结构或分析行为。

## 文档评审

- 已阅读 `docs/audit-development-report-archive-2026-05-19/usb-hid-performance-optimization-2026-05-19.md`。
- 已阅读 `docs/audit-development-report-archive-2026-05-19/usb-hid-limit-source-final-review-2026-05-19.md`。
- 本轮前端美化没有改变此前 USB HID source、limit、缓存、Canvas 绘制和表格分页优化语义。
- 本报告仅本地保留，不纳入 commit。

## 修改摘要

- 统一基础壳体
  - `PageShell` 增加 `compact/roomy` 密度 preset，默认改为紧凑分析页间距。
  - `AnalysisHero` 收紧圆角、阴影、字号、标签、刷新按钮，并补齐 `actions/children` 插槽。
  - `AnalysisPanel`、`AnalysisStatCard`、`SurfacePanel`、`MetricCard`、`StatusHint`、`EmptyState`、`WorkbenchTitleBar` 统一到更轻的阴影和更紧凑的 `20-24px` 圆角体系。
  - `AnalysisDataTable` 收紧表头、单元格、空态行距。

- 旧页面迁移
  - `EvidencePanel` 改用统一 `AnalysisHero` 与 `AnalysisPanel`，移除页面内重复径向背景和自定义大 Hero 外壳。
  - `ObjectExport` 改用统一 `AnalysisHero` 与 `AnalysisPanel`，对象筛选、分组、导出队列拆成一致面板。
  - `MiscToolsHero` 对齐统一 Hero 密度，同时保留模块分类切换和导入模块能力。
  - `MiscModuleCard` 收紧模块卡片标题区、展开区、阴影和图标尺寸。

- 工作台与高频页面
  - `Workspace`、`HttpStream`、`RawStreamPage`、`ThreatHunting` 移除重复页面背景，继续由 `MainLayout` route theme 提供背景。
  - `CaptureMissionControl`、推荐入口、命中面板、Payload 快捷区改为更紧凑的工作台卡片。
  - `ThreatHunting` 配置/命中工作台和分类/进度面板统一圆角与阴影。
  - `C2Analysis`、`AptAnalysis` 标签容器、C2 家族卡片、聚合详情、候选详情、VShell 汇总卡片收紧密度。
  - `Workspace` 加载态、错误态、RawStream payload 面板、当前 chunk 面板统一为较轻卡片。

- 页面背景收敛
  - 移除 `TrafficGraph`、`IndustrialAnalysis`、`VehicleAnalysis`、`MediaAnalysis`、`UsbAnalysis`、`ThreatHunting`、`Workspace`、`HttpStream`、`RawStreamPage` 的页面级 inline radial/linear 背景。
  - 保留 USB 轨迹/热区等可视化画布内部背景，因为它们属于图表内容，不属于页面壳背景。
  - 保留欢迎页与设置侧栏的大圆角，因为它们是一级欢迎/浮层容器。

## 验证记录

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run typecheck
pnpm run lint
pnpm run format:check
pnpm run size:check
pnpm run boundary:check
pnpm exec vitest run src/app/pages/Workspace.test.tsx src/app/pages/AnalysisCockpit.test.tsx src/app/pages/C2Analysis.test.tsx src/app/pages/C2Analysis.vshell.test.tsx src/app/pages/C2Analysis.candidates.test.tsx src/app/pages/C2Analysis.decrypt.test.tsx src/app/pages/AptAnalysis.test.tsx src/app/pages/UsbAnalysis.test.tsx src/app/pages/UsbAnalysis.hidPanel.test.tsx src/app/pages/EvidencePanel.test.tsx src/app/pages/MiscTools.test.tsx src/app/pages/MiscTools.customModules.test.tsx src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.smb3.test.tsx src/app/pages/MiscTools.payloadHints.test.tsx src/app/pages/TrafficGraph.test.ts
pnpm run ci

cd C:\Users\QAQ\Desktop\gshark
git diff --check
```

结果：

- `typecheck` 通过。
- `lint` 通过。
- `format:check` 通过。
- `size:check` 通过。
- `boundary:check` 通过。
- 目标页面回归测试 16 个文件、49 个测试通过。
- 前端完整 `pnpm run ci` 通过，225 个测试文件、692 个测试通过，Vite build 通过。
- `git diff --check` 通过。

## 视觉验收

- 启动临时后端与专用前端端口后抽查：
  - 工作区欢迎页
  - USB 分析
  - 证据链
  - 对象提取
  - MISC 工具箱
  - 流量图
  - HTTP Stream 工作台
- 主体页面未发现横向滚动。
- 证据链、对象提取、MISC、USB、HTTP 工作台的页壳、Hero、面板密度和背景已明显收敛。
- 检测到的离屏控件来自右侧运行时设置抽屉的隐藏 DOM，不属于主体页面溢出。

## 复审结论

- 本轮改动仅触及前端视觉与布局类名，没有改变 API、缓存、数据映射或分析逻辑。
- 老页面 `EvidencePanel`、`ObjectExport`、`MiscTools` 已向统一分析页体系靠拢。
- 工作台类页面保留 `WorkbenchTitleBar`/高频操作结构，只收敛背景、圆角、阴影和间距。
- `frontend/dist/` 由前端 CI build 生成，仍为忽略产物，不纳入 commit。
