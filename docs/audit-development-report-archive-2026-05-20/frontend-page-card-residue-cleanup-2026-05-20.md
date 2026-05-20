# 前端页面卡片层残留清理报告

署名：Codex

时间：2026-05-20 19:44:46 +08:00（Asia/Shanghai）

## 本轮范围

- 执行前端“无卡片层”矩形背景分格重设后的页面残留清理。
- 只处理非流追踪页面及其直接使用的非 stream feature 视觉组件。
- 不修改公共组件、不改业务逻辑、不迁移 HTTP/TCP/UDP/Raw stream 相关页面和组件。

## 最新文档评审

- 已阅读 `docs/audit-development-report-archive-2026-05-20/frontend-tiled-glass-redesign-implementation-2026-05-20.md`。
- 已阅读 `docs/audit-development-report-archive-2026-05-20/worker-c-page-migration-report-2026-05-20.md`。
- 两份文档共同确认当前方向是：页面内容依赖 `gshark-tile-*`、`AnalysisPanel`、`AnalysisDataTable` 形成矩形分格，不继续保留页面内自定义白底、大圆角、强阴影和毛玻璃卡片层。
- 两份文档均强调流追踪路径排除；本轮继续遵守该边界。
- 本轮保留按钮、输入、select、dialog、tooltip、badge、图例点等交互或标记所需的少量圆角/面板感，避免破坏可用性。

## 主要修改

- Evidence：状态提示、筛选 chip、导出工具条、证据标签和 caveat 提示改为 tile/toolbar 语义，去除页面内白底阴影和圆角残留。
- ThreatHunting：工作台外壳、结果表头、命中详情、分类卡和进度提示继续收敛为 `gshark-tile` 分区；结果表头去除本地 `backdrop-blur`。
- UpdateCenter：加载状态、Release 正文容器、诊断行、步骤行和状态提示使用矩形 tile；Markdown 代码块/表格去除圆角阴影白底卡片层。
- USB/Industrial/Vehicle/Traffic：筛选条、表格壳、HID 分页按钮、USB 轨迹/热区外壳、Modbus/UDS 筛选 chip 和 Traffic 重试按钮降为矩形分格。
- MISC：工具箱 Hero、模块卡、通用表单、结果面板、模块摘要工具条、WebShell source/input、NTLM/Shiro/SMTP/MySQL/HTTP/SMB3/WinRM 相关摘要提示从本地卡片层改为 tile/toolbar。
- C2/Media：候选详情 JSON 预览、解密结果导出/搜索、解密输入、C2 小图标、媒体操作按钮做视觉降噪。

## 流追踪排除确认

- 未修改以下禁止迁移路径：
  - `frontend/src/app/pages/HttpStream*.tsx`
  - `frontend/src/app/pages/TcpStream.tsx`
  - `frontend/src/app/pages/UdpStream.tsx`
  - `frontend/src/app/pages/RawStream*`
  - `frontend/src/app/components/stream/**`
  - `frontend/src/app/features/raw-stream/**`
- `git diff --name-only -- frontend/src/app/pages frontend/src/app/features frontend/src/app/misc | rg "(^|/|\\)(HttpStream|TcpStream|UdpStream|RawStream|stream|raw-stream)"` 无命中。

## 验证记录

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm exec prettier --write <本轮触及文件>
pnpm run typecheck
pnpm exec vitest run src/app/pages/C2Analysis.decrypt.test.tsx src/app/pages/EvidencePanel.test.tsx src/app/pages/TrafficGraph.test.ts src/app/pages/UsbAnalysis.test.tsx src/app/pages/UsbAnalysis.hidPanel.test.tsx src/app/pages/IndustrialAnalysis.test.tsx src/app/pages/VehicleAnalysis.test.ts src/app/features/object/ObjectExportPanels.test.tsx src/app/features/update/UpdateReleaseMarkdown.test.tsx src/app/features/update/useUpdateCenter.test.tsx src/app/features/update/updateCenterUtils.test.ts src/app/features/media/MediaSessionCells.test.tsx
pnpm run lint
pnpm run format:check

cd C:\Users\QAQ\Desktop\gshark
git diff --check -- frontend/src/app/pages frontend/src/app/features frontend/src/app/misc
```

结果：

- `typecheck` 通过。
- 目标 Vitest 12 个文件、25 个测试通过。
- `lint` 通过。
- `format:check` 通过。
- scoped `git diff --check` 通过。

## 注意事项

- 残留扫描中仍可见少量 `rounded-full`、`bg-white`、`shadow-sm`，主要属于 badge、输入框、select 下拉、dialog、图例点、测试断言和按钮等交互/标记语义，本轮按任务要求保留。
- 工作树已有大量并行改动，本轮未回退公共组件、主题、stream 或其他 worker 改动。
- 本报告为本地开发文档，不应随功能代码提交。
