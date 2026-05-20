# 前端全局白色毛玻璃幕布与去网格线修正报告

署名：Codex

时间：2026-05-20 20:12:03 +08:00（Asia/Shanghai）

## 目标

- 将上一轮“背景矩形网格线”改为全局白色半透明毛玻璃幕布。
- 保留底层路由渐变，但移除截图中可见的横纵细网格线。
- 主体页面继续使用弱分区边界，不恢复独立白色卡片、厚阴影或大圆角卡片层。
- 按用户要求继续排除 HTTP/TCP/UDP 流追踪页面结构迁移。

## 文档评审

- 已阅读 `docs/audit-development-report-archive-2026-05-20/frontend-no-card-grid-reset-2026-05-20.md`。
- 本轮在“无卡片层矩形背景分格”实现基础上修正视觉方向：去掉全局 repeating grid，仅保留白色毛玻璃幕布和必要内容分区线。
- 旧报告中关于“页面背景绘制主网格线/细网格线”的目标已被本轮用户需求覆盖并修正。

## 修改摘要

- `frontend/src/styles/theme.css`
  - 从 `.gshark-page-bg` 移除 `repeating-linear-gradient` 细网格背景。
  - 从 `.gshark-theme-main::before` 移除所有 repeating grid 绘制。
  - 新增 `.gshark-glass-shell::before`，在全 app viewport 覆盖白色半透明毛玻璃幕布。
  - 提高 `--gshark-curtain-bg` 白色透明度，新增 `--gshark-glass-shell-bg`。
  - 降低 `--gshark-tile-border` / `--gshark-tile-divider` 透明度，避免分区线看起来像全局网格。

- `frontend/src/app/layouts/MainLayout.tsx`
  - 最外层 app 容器增加 `gshark-glass-shell`。
  - header、sidebar、main、footer 保持在全局幕布上方，幕布不拦截点击。
  - `main.gshark-theme-main` 保留路由内容层职责，但不再绘制网格背景。

## 流追踪排除确认

以下路径无本轮 diff：

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
- 完整前端 `pnpm run ci` 通过：225 个测试文件、692 个测试通过，Vite build 通过。
- `git diff --check` 通过。
- `theme.css` 已确认不存在 `repeating-linear-gradient`。

## Playwright / Chrome 验收

使用 Playwright CLI 调用 Chrome 截图抽查：

- `/analysis-cockpit`
- `/usb-analysis`
- `/misc`
- `/c2-analysis`
- `/evidence`
- `/http-stream`

验收结果：

- 分析页无截图中那种横纵全局网格线。
- 底层路由渐变仍可见，并被全局白色毛玻璃幕布统一覆盖。
- 主体内容保留弱矩形分区边界，但不再呈现整页细网格背景。
- `/http-stream` 保持原流追踪工作台结构，未迁移为新视觉结构。

## 注意事项

- 本报告为本地开发报告，不纳入 commit。
- 未提交 `frontend/dist/`、`build/`、样本或 Playwright 产物。
