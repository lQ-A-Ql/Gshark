# Frontend Size Budget 拆分方案

_制定人: Codex | 时间: 2026-06-06 19:40:32 +08:00_

## 背景

`cd frontend && pnpm run size:check` 当前失败 18 项。失败文件均为既有 size-budget baseline，未包含本轮新增的 preload/layout 文件。preload 实施已通过 typecheck、lint、format、focused guards、backend tests、frontend tests、build；size-budget 旧债单独拆分治理。

## 拆分原则

- 只做行为等价拆分，不顺手改业务逻辑。
- 保留现有 public imports；旧文件优先降为 re-export / orchestration facade，减少调用方 churn。
- 先拆 pure helper / DTO / mapper，再拆 UI 组件，最后拆慢测试。
- 每批都必须跑相关 focused tests、`pnpm run typecheck`、`pnpm run lint`、`pnpm run size:check`。
- 不通过提高 budget 掩盖超线；只有文件职责变化后才调整 guard 文案。

## 当前超预算清单

| 文件 | 当前/预算 | 拆分方向 |
|---|---:|---|
| `src/app/integrations/wire/captureWireDtos.ts` | 91/85 | 拆 capture status、packet、page/locate DTO |
| `src/app/integrations/wire/evidenceWireDtos.ts` | 52/45 | 拆 evidence record 与 object payload DTO |
| `src/app/integrations/wire/trafficWireDtos.ts` | 26/20 | 拆 protocol hierarchy DTO |
| `src/app/integrations/mappers/packetMapper.ts` | 115/95 | 拆 packet、page、color feature mapper |
| `src/app/integrations/mappers/evidenceMapper.ts` | 108/60 | 拆 module/name/tag normalization helper |
| `src/app/integrations/mappers/trafficMapper.ts` | 52/35 | 拆 protocol hierarchy mapper |
| `src/app/components/StreamDecoderCandidatePanel.tsx` | 157/145 | 拆 summary、apply mode、candidate grid |
| `src/app/components/StreamDecoderCandidateCard.tsx` | 127/115 | 拆 badge、preview、decoder hint |
| `src/app/pages/TrafficGraph.tsx` | 135/115 | 抽 page state / route actions hook |
| `src/app/features/traffic/TrafficGraphPanels.tsx` | 325/105 | 按 overview、timeline、protocol、endpoint panels 拆 |
| `src/app/pages/EvidencePanel.tsx` | 178/85 | 抽 page state、export actions、empty/error panels |
| `src/app/features/evidence/EvidenceFilters.tsx` | 236/150 | 拆 severity/module/search/export controls |
| `src/app/features/evidence/EvidenceResults.tsx` | 336/140 | 拆 table、tag cells、state panels、details cells |
| `src/app/features/evidence/evidencePanelRules.ts` | 421/130 | 拆 filter/sort/count/export/label pure rules |
| `src/app/pages/IndustrialAnalysis.tsx` | 175/170 | 抽 page state hook 与 protocol section |
| `src/app/features/industrial/IndustrialAuxiliaryPanels.tsx` | 479/180 | 拆 rule/control-command/protocol-detail tables |
| `src/app/pages/MiscTools.test.tsx` | 304/275 | 拆 payload workflow、source loading、confidence states |
| `src/app/features/evidence/evidencePanelRules.test.ts` | 278/80 | 按 filter/sort/count/export 分 test files |

## Phase S1 - Wire DTO 与 Mapper 拆分

### Design

保持 `wire/*WireDtos.ts` 与 `mappers/*Mapper.ts` 作为兼容 facade；新增窄文件承载具体类型与转换函数。调用方 import 可逐步迁移，但本阶段不强制大范围改调用点。

### Tasks

1. `captureWireDtos.ts` 拆出 `captureStatusWireDtos.ts`、`packetWireDtos.ts`、`capturePageWireDtos.ts`。
2. `evidenceWireDtos.ts` 拆出 `evidenceRecordWireDtos.ts`、`objectEvidenceWireDtos.ts`。
3. `trafficWireDtos.ts` 拆出 `trafficProtocolWireDtos.ts`。
4. `packetMapper.ts` 拆出 `packetColorFeatureMapper.ts`、`packetPageMapper.ts`。
5. `evidenceMapper.ts` 拆出 `evidenceModuleMapper.ts`、`evidenceTagMapper.ts`。
6. `trafficMapper.ts` 拆出 `trafficProtocolHierarchyMapper.ts`。
7. 更新 mapper/wire tests，确保 facade export 与原行为一致。

### Gate

- 上述 6 个原文件全部低于预算。
- `pnpm run wire:any:check && pnpm run mapper:any:check` 通过。
- `pnpm exec vitest run src/app/integrations/mappers` 通过。

## Phase S2 - Evidence 页面与规则拆分

### Design

先拆 pure rules，再拆 UI。`EvidencePanel.tsx` 只保留 route/page orchestration；`EvidenceFilters.tsx` 与 `EvidenceResults.tsx` 保留组合层，具体控件/单元格进入子文件。

### Tasks

1. `evidencePanelRules.ts` 拆为 `evidenceFilterRules.ts`、`evidenceSortRules.ts`、`evidenceCountRules.ts`、`evidenceExportRules.ts`、`evidenceLabelRules.ts`。
2. `evidencePanelRules.test.ts` 按上述 pure rules 拆成 5 个测试文件，每个测试文件聚焦单一职责。
3. `EvidenceFilters.tsx` 拆出 `EvidenceSeverityFilter.tsx`、`EvidenceModuleFilter.tsx`、`EvidenceSearchFilter.tsx`、`EvidenceExportActions.tsx`。
4. `EvidenceResults.tsx` 拆出 `EvidenceResultsState.tsx`、`EvidenceResultsTable.tsx`、`EvidenceTagCells.tsx`、`EvidenceDetailCells.tsx`。
5. `EvidencePanel.tsx` 抽 `useEvidencePanelState.ts` 与 `useEvidenceExportActions.ts`。

### Gate

- Evidence 4 个超预算文件全部低于预算。
- `pnpm exec vitest run src/app/features/evidence src/app/pages/EvidencePanel.test.tsx` 通过。
- Evidence preload tests 继续证明 light prefetch 不触发 all-module `/api/evidence`。

## Phase S3 - Traffic 页面拆分

### Design

`TrafficGraph.tsx` 只负责 capture/path 参数、hook 调用和 panel composition；`TrafficGraphPanels.tsx` 降为 section router，具体图表/桶/端点/时间线进入独立 panels。

### Tasks

1. 从 `TrafficGraph.tsx` 抽 `useTrafficGraphPageState.ts` 与 `TrafficGraphPageActions.tsx`。
2. 从 `TrafficGraphPanels.tsx` 拆出 `TrafficOverviewPanel.tsx`、`TrafficProtocolPanel.tsx`、`TrafficEndpointPanel.tsx`、`TrafficTimelinePanel.tsx`。
3. 抽通用展示 helpers：`TrafficMetricRows.tsx`、`TrafficEmptyState.tsx`。
4. 更新 `TrafficGraphPanels.test.tsx`，按 panel 行为拆 focused tests。

### Gate

- `TrafficGraph.tsx` 与 `TrafficGraphPanels.tsx` 低于预算。
- `pnpm exec vitest run src/app/features/traffic src/app/pages/TrafficGraph.test.ts` 通过。
- Traffic preload cache/inflight 测试继续通过。

## Phase S4 - Industrial 辅助面板拆分

### Design

保持 `IndustrialAnalysis.tsx` 为页面壳，`IndustrialAuxiliaryPanels.tsx` 为轻量组合层。规则列表、控制命令、协议详情、表格 cell 分别独立。

### Tasks

1. 从 `IndustrialAnalysis.tsx` 抽 `useIndustrialAnalysisPage.ts` 与 `IndustrialProtocolSummary.tsx`。
2. 从 `IndustrialAuxiliaryPanels.tsx` 拆出 `IndustrialRulePanel.tsx`、`IndustrialControlCommandPanel.tsx`、`IndustrialProtocolDetailPanel.tsx`。
3. 抽 `IndustrialTableCells.tsx` 与 `industrialPanelFormatters.ts`。
4. 补 focused component tests，覆盖原大面板关键分支。

### Gate

- Industrial 2 个超预算文件低于预算。
- `pnpm exec vitest run src/app/pages/IndustrialAnalysis.test.tsx src/app/features/industrial` 通过。
- Heavy warmup target 与 cache key 行为不变。

## Phase S5 - Stream Decoder 与慢测试拆分

### Design

Stream decoder UI 先拆显示子组件，不改状态流。测试拆分以稳定 CI 与定位失败为目标，不降低断言覆盖。

### Tasks

1. `StreamDecoderCandidatePanel.tsx` 拆出 `StreamDecoderInspectionSummary.tsx`、`StreamDecoderApplyMode.tsx`、`StreamDecoderCandidateGrid.tsx`。
2. `StreamDecoderCandidateCard.tsx` 拆出 `StreamDecoderCandidateBadges.tsx`、`StreamDecoderCandidatePreview.tsx`、`StreamDecoderCandidateHints.tsx`。
3. `MiscTools.test.tsx` 拆为 `MiscTools.payload.test.tsx`、`MiscTools.sources.test.tsx`、`MiscTools.confidence.test.tsx`。
4. 将重复 fixtures 移入 `src/app/pages/__tests__/miscToolsFixtures.ts`。

### Gate

- Stream decoder 与 MISC test 文件低于预算。
- `pnpm exec vitest run src/app/components/StreamDecoderCandidate* src/app/pages/MiscTools*.test.tsx` 通过。

## Final Gate

```powershell
cd frontend
pnpm run size:check
pnpm run typecheck
pnpm run lint
pnpm run test:run
pnpm run build
```

完成条件：`size:check` 无失败项；所有拆出的 facade 保持兼容；preload 相关测试仍全绿。
