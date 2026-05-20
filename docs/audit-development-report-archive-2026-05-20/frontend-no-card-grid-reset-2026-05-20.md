# 前端无卡片层矩形背景分格重设报告

署名：Codex

时间：2026-05-20 19:57:28 +08:00（Asia/Shanghai）

## 目标

- 将主体分析/工作台页面从“卡片叠层”改为“背景分格 + 内容填格”。
- 保留路由渐变背景，并在主内容区覆盖半透明毛玻璃幕布。
- 通过公共样式和公共组件落地，减少页面级自定义卡片样式。
- 按用户要求不迁移 HTTP/TCP/UDP 流追踪页面。

## 文档评审

- 已阅读 `docs/audit-development-report-archive-2026-05-20/frontend-tiled-glass-redesign-implementation-2026-05-20.md`。
- 已阅读 `docs/audit-development-report-archive-2026-05-20/worker-c-page-migration-report-2026-05-20.md`。
- 已阅读 `docs/audit-development-report-archive-2026-05-20/frontend-density-style-unification-2026-05-20.md`。
- 本轮在前一版“矩形平铺 + 毛玻璃幕布”基础上继续去卡片化：tile 不再承担独立白底、阴影和 blur，页面背景负责分格。

## 修改摘要

- `theme.css`
  - 增加页面级主网格线与细网格线变量。
  - `gshark-theme-main::before` 负责绘制毛玻璃幕布与 repeating-linear-gradient 矩形网格。
  - `gshark-tile`、`gshark-tile-strong`、`gshark-tile-toolbar`、`gshark-tile-table` 改为透明矩形分区：无圆角、无阴影、无独立 blur。
  - 新增 `gshark-grid-cell` / `gshark-grid-section` 语义别名。

- 公共组件
  - `PageShell` tiled 布局贴合滚动区域，改为 `p-px + gap-px`。
  - `AnalysisHero` 改为首行网格单元，图标、标签、按钮改为透明/轻底色边框风格。
  - `DesignSystem`、`AnalysisCards`、`AnalysisDataTable`、`AnalysisCollections`、`ui/card` 继续收敛为 grid cell 语义。
  - 全局 `Select` 触发器改为透明小圆角矩形控件；下拉内容作为浮层保留轻量面板感。

- 页面与功能残留
  - 清理 USB、ThreatHunting、Workspace 错误态/进度态、Mass Storage 过滤器等主体控件的白底、阴影、大圆角残留。
  - 保留弹窗、tooltip、下拉浮层、媒体播放对话框、图例圆点等必要浮层/语义形态。
  - 同步更新 `C2Analysis.decrypt.test.tsx` 中 Select 样式断言。

## 流追踪排除确认

- 已确认以下路径无本轮 diff：
  - `frontend/src/app/pages/HttpStream.tsx`
  - `frontend/src/app/pages/HttpStreamTitleBar.tsx`
  - `frontend/src/app/pages/HttpStreamPayloadGrid.tsx`
  - `frontend/src/app/pages/HttpStreamDialog.tsx`
  - `frontend/src/app/pages/RawStreamPage.tsx`
  - `frontend/src/app/pages/RawStreamControlBar.tsx`
  - `frontend/src/app/pages/RawStreamDialog.tsx`
  - `frontend/src/app/pages/RawStreamPayloadPanels.tsx`
  - `frontend/src/app/pages/RawStreamDirectionBadge.tsx`
  - `frontend/src/app/components/stream/**`
  - `frontend/src/app/features/raw-stream/**`

## 验证记录

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run typecheck
pnpm run lint
pnpm run format:check
pnpm run size:check
pnpm run boundary:check
pnpm exec vitest run src/app/pages/Workspace.test.tsx src/app/pages/AnalysisCockpit.test.tsx src/app/pages/C2Analysis.test.tsx src/app/pages/C2Analysis.vshell.test.tsx src/app/pages/C2Analysis.candidates.test.tsx src/app/pages/C2Analysis.decrypt.test.tsx src/app/pages/AptAnalysis.test.tsx src/app/pages/UsbAnalysis.test.tsx src/app/pages/UsbAnalysis.hidPanel.test.tsx src/app/pages/EvidencePanel.test.tsx src/app/pages/MiscTools.test.tsx src/app/pages/MiscTools.customModules.test.tsx src/app/pages/MiscTools.sessions.test.tsx src/app/pages/MiscTools.smb3.test.tsx src/app/pages/MiscTools.payloadHints.test.tsx src/app/pages/TrafficGraph.test.ts src/app/pages/IndustrialAnalysis.test.tsx src/app/pages/VehicleAnalysis.test.tsx
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
- 目标页面回归测试 17 个文件、50 个测试通过。
- 完整前端 `pnpm run ci` 通过：225 个测试文件、692 个测试通过，Vite build 通过。
- `git diff --check` 通过。

## Playwright / Chrome 验收

- 使用 Playwright CLI 调用 Chrome 截图抽查：
  - `/analysis-cockpit`
  - `/usb-analysis`
  - `/misc`
  - `/c2-analysis`
  - `/http-stream`
- 验收结果：
  - 分析页背景可见矩形分格。
  - 主体 tile 为透明网格单元，不再呈现独立白色卡片层、厚阴影或大圆角。
  - USB/MISC 页面为“背景分格 + 内容填格”。
  - `/http-stream` 保持原流追踪工作台结构，未迁移为 `gshark-tile-page`。
  - 临时截图、临时日志、临时服务已清理。

## 注意事项

- 本报告为本地开发报告，不纳入 commit。
- 未提交 `frontend/dist/`、`build/`、样本或 Playwright 产物。
