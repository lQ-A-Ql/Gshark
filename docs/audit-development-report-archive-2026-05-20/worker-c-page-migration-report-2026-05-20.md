# Worker C 页面迁移第二组报告

署名：Codex Worker C

时间：2026-05-20 18:27:45 +08:00（Asia/Shanghai）

## 本轮目标

- 仅处理 Evidence/Object/USB/TrafficGraph/Industrial/Vehicle/Media/ThreatHunting/UpdateCenter 相关页面与 feature 组件。
- 清理页面级大圆角卡片、白底阴影和自定义背景，优先使用公共 `AnalysisPanel` 或主线程提供的 `gshark-tile-*` 语义类。
- 不修改 `theme.css`、`MainLayout`、`PageShell`、`AnalysisHero`、`AnalysisCards`、`AnalysisDataTable`、`DesignSystem`、`ui/card`，也不触碰 stream/raw-stream 范围。
- 保护并行工作树，不回退其他 worker 或用户已有改动。

## 最新文档评审

- 已阅读 `docs/audit-development-report-archive-2026-05-20/frontend-density-style-unification-2026-05-20.md`。
- 该文档明确本阶段目标是前端密度与风格统一，并已经移除多处页面级 radial/linear 背景。
- 本轮延续该方向：继续收敛 Worker C 范围内残留的局部大圆角、强阴影、白底层叠和自定义渐变。
- 文档中提到 USB 轨迹/热区等可视化画布内部背景不属于页面壳背景，本轮保留这些图表内容背景，没有误删可视化语义。

## 修改摘要

- `UpdateCenterPanels` 从 `ui/card` 外壳迁移到 `AnalysisPanel`，Release 说明、诊断、步骤、状态区统一成 tile 面板。
- `ThreatHunting` 工作台、分类面板、进度面板、结果表头和详情区加入 `gshark-tile-*` 语义类，去掉页面内自定义渐变与强阴影。
- `Evidence` 工具栏、状态提示和 caveat 提示收紧为更轻的 tile/toolbar 风格。
- 删除已无引用的旧 `EvidenceHero`，避免旧自定义 Hero 被误用回迁。
- `ObjectExport` 工具栏、分组 chips、导出队列收敛为 `gshark-tile-toolbar`，对象网格间距更紧凑。
- `TrafficGraph` 移除页面级自定义背景，条形图行 hover 不再制造额外阴影，并格式化长行。

## 验证记录

```powershell
cd C:\Users\QAQ\Desktop\gshark\frontend
pnpm run typecheck
pnpm exec eslint <Worker C touched files> --max-warnings=0
pnpm exec prettier --check <Worker C touched files>
pnpm exec vitest run src/app/pages/EvidencePanel.test.tsx src/app/features/object/ObjectExportPanels.test.tsx src/app/pages/TrafficGraph.test.ts src/app/pages/UsbAnalysis.test.tsx src/app/pages/UsbAnalysis.hidPanel.test.tsx src/app/pages/IndustrialAnalysis.test.tsx src/app/pages/VehicleAnalysis.test.ts src/app/features/hunting/ThreatHuntingMetricCards.test.tsx src/app/features/update/useUpdateCenter.test.tsx src/app/features/update/UpdateReleaseMarkdown.test.tsx src/app/features/update/updateCenterUtils.test.ts

cd C:\Users\QAQ\Desktop\gshark
git diff --check -- <Worker C touched files>
```

结果：

- `typecheck` 通过。
- scoped ESLint 通过。
- scoped Prettier 通过。
- Worker C 相关 Vitest：11 个测试文件、21 个测试通过。
- scoped `git diff --check` 通过。

## 未覆盖风险

- 未启动浏览器进行视觉截图验收；本轮验证以类型、lint、format、单元/页面测试为主。
- 工作树存在大量并行改动，包含公共组件、C2/APT、stream、theme 等其他 worker 范围；本轮未评审也未回退这些改动。
- `UpdateCenter` 迁移为视觉外壳调整，未执行真实下载/替换流程。
