# 前端矩形平铺与毛玻璃幕布重设执行报告

署名：Codex

时间：2026-05-20 19:26:11 +08:00（Asia/Shanghai）

## 目标

- 将原有分散圆角卡片视觉收敛为紧密相连的矩形 tile。
- 保留路由渐变背景，并在主内容区覆盖半透明毛玻璃幕布。
- 尽量通过公共样式和公共组件落地，降低页面内自定义卡片类名占比。
- 按用户要求不修改 HTTP/TCP/UDP 流追踪页面。

## 分工与复审

- Worker B/C 完成分析页、工作台页、MISC、Evidence、Object、USB、Traffic、ThreatHunting、UpdateCenter 等范围的初始迁移。
- 主线程完成集成、门禁修复与最终复审。
- 额外启用两个 GPT-5.5 xhigh agent 只读复审：
  - 视觉复审确认整体方向合格，并指出 PageShell 重复背景、C2/APT gap 覆盖、工作台 toolbar 圆角残留、TrafficGraph 条形图旧圆角等问题。
  - 代码复审指出 C2 解密表格测试断言、DataTable class 重复、TrafficGraphPanels 未纳入 size budget 等问题。
- 两个复审 agent 均已关闭；指出的高优先级问题已修复。

## 主要修改

- `theme.css`
  - 新增 `gshark-theme-main::before` 毛玻璃幕布。
  - 新增 `gshark-tile-page`、`gshark-tile-grid`、`gshark-tile`、`gshark-tile-strong`、`gshark-tile-header`、`gshark-tile-toolbar`、`gshark-tile-table` 公共视觉语义。

- 公共组件
  - `PageShell` 默认使用 tiled 布局，并移除重复 `gshark-page-bg`，避免覆盖主内容幕布。
  - `AnalysisHero`、`AnalysisPanel`、`AnalysisDataTable`、`DesignSystem`、`ui/card` 统一到矩形 tile 体系。
  - `AnalysisDataTable` 保留公共表格滚动语义，C2 调用方去除重复 `gshark-tile-table` 类。

- 页面迁移
  - `EvidencePanel` 移除自定义 `EvidenceHero`，改用统一 hero/面板体系。
  - `ObjectExport`、`MiscTools`、`C2Analysis`、`AptAnalysis`、`UsbAnalysis`、`TrafficGraph`、`ThreatHunting`、`UpdateCenter`、工控/车机/媒体等分析页迁移到 tile 视觉。
  - `Workspace` 工作台控件、过滤器、协议树、Hex/ASCII、分页/定位工具条收敛到公共 tile/toolbar 语义。
  - `TrafficGraph` 抽出 `TrafficGraphPanels`，并将新组件纳入 size budget。
  - `CaptureMissionControl` 抽出 `CaptureMissionNavigation`，保持主组件预算和职责边界。

## 流追踪排除确认

- 已确认以下路径无本轮 diff：
  - `frontend/src/app/pages/HttpStream.tsx`
  - `frontend/src/app/pages/RawStreamPage.tsx`
  - `frontend/src/app/pages/RawStreamPayloadPanels.tsx`
  - `frontend/src/app/components/stream/**`
  - `frontend/src/app/features/raw-stream/**`
- Playwright 抽查 `/http-stream`、`/tcp-stream`、`/udp-stream` 均可打开，且未迁移为 `gshark-tile-page` 页面壳。

## 验证

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run typecheck
pnpm run lint
pnpm run format:check
pnpm run size:check
pnpm run boundary:check
pnpm exec vitest run src/app/pages/Workspace.test.tsx src/app/pages/C2Analysis.decrypt.test.tsx src/app/pages/AptAnalysis.test.tsx src/app/pages/TrafficGraph.test.ts
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
- 目标回归测试通过。
- 完整 `pnpm run ci` 通过：225 个测试文件、692 个测试通过，Vite build 通过。
- `git diff --check` 通过。

## Playwright / Chrome 验收

- 启动临时后端：`GSHARK_BACKEND_TOKEN=codex-ui-review-token go run ./cmd/sentinel serve 127.0.0.1:17891`
- 启动临时前端：`VITE_BACKEND_TOKEN=codex-ui-review-token VITE_BACKEND_URL=http://127.0.0.1:17891 vite --host 127.0.0.1 --port 5174 --strictPort`
- 使用 Chrome/Playwright 抽查：
  - `/`
  - `/analysis-cockpit`
  - `/usb-analysis`
  - `/evidence`
  - `/objects`
  - `/misc`
  - `/traffic-graph`
  - `/c2-analysis`
  - `/apt-analysis`
  - `/industrial-analysis`
  - `/vehicle-analysis`
  - `/media-analysis`
  - `/hunting`
  - `/updates`
  - `/http-stream`
  - `/tcp-stream`
  - `/udp-stream`

结果：

- 已进入真实 GShark 主界面，不再停留在启动页。
- 主要分析页存在 `gshark-theme-main` 幕布与 tile 结构。
- 抽查页面未发现横向滚动。
- 流追踪页面保持原工作台结构，不进入 tile-page 迁移。
- Chrome 控制台仅出现开发模式 React DevTools 提示、favicon 缺失等非本轮功能问题。

## 注意事项

- 本报告为本地开发报告，不纳入 commit。
- 未提交 `frontend/dist/`、`build/`、样本或 Playwright 产物。
