# USB 页面去间距/去内框与毛玻璃深化报告

署名：Codex

时间：2026-05-20 20:24:52 +08:00（Asia/Shanghai）

## 目标

- 删除截图红圈处 tile 之间的明显留白。
- 删除截图绿圈处面板内部空态边框。
- 深化全局白色毛玻璃质感，同时不恢复网格线、白底卡片或厚阴影。
- 继续保持 HTTP/TCP/UDP 流追踪页面不迁移。

## 文档评审

- 已阅读 `docs/audit-development-report-archive-2026-05-20/frontend-global-glass-curtain-no-grid-2026-05-20.md`。
- 本轮在上一轮“全局白色毛玻璃幕布 + 去网格线”基础上继续细化：压平 USB 页面分区 gutter，移除图表空态的二次框线，并加强幕布磨砂感。

## 修改摘要

- 公共布局
  - `PageShell` tiled 模式从 `gap-px p-px` 收敛为 `gap-0 p-0`。
  - `AnalysisEmptyState` 改为无边框透明空态，仅保留居中文案和内边距。

- USB 页面
  - USB 概览、HID、Mass Storage、Other 子页的统计区和图表区从 `gap-4/mt-4/space-y-4` 收敛为贴合矩形分区。
  - USB 专用 `EmptyState`、`UsbHidEmptyState` 去掉 dashed border、背景和圆角。
  - 鼠标行为列表从独立小卡片改为列表分隔线。
  - Mass Storage 过滤条、键盘编辑文本区、调查报告入口同步减少外部留白。

- 全局玻璃
  - 提高 `--gshark-curtain-bg` 与 `--gshark-glass-shell-bg` 的白色覆盖度。
  - 降低 `--gshark-tile-border` / `--gshark-tile-divider` 透明度。
  - `.gshark-glass-shell::before` 增加多层柔和径向高光，并提高 blur/saturate。
  - `.gshark-tile-grid` 不再用背景色制造缝隙。

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
pnpm exec vitest run src/app/pages/UsbAnalysis.test.tsx src/app/pages/UsbAnalysis.hidPanel.test.tsx src/app/pages/AnalysisCockpit.test.tsx src/app/pages/EvidencePanel.test.tsx src/app/pages/MiscTools.test.tsx
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

- 目标页面回归测试通过：5 个测试文件、15 个测试。
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

- `/usb-analysis`
- `/analysis-cockpit`
- `/misc`
- `/c2-analysis`
- `/evidence`
- `/http-stream`

验收结果：

- `/usb-analysis` 红圈处大间距已收敛为连续矩形分区。
- 图表/提示空态不再出现绿圈那种内部边框。
- 全局白色毛玻璃幕布更明显，底层渐变仍可见。
- `/http-stream` 保持原流追踪工作台结构。

## 注意事项

- 本报告为本地开发报告，不纳入 commit。
- 未提交 `frontend/dist/`、`build/`、样本或 Playwright 产物。
