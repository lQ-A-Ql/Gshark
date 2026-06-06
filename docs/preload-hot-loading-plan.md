# Async Hot Loading / Preload Implementation Plan

本文档规划 meow~traffic 功能页异步热加载、轻量数据预取与受控分析预热的逐步实施边界、门禁、测试、验收标准和评分规则。

## 目标

在不破坏现有 React Router lazy routes、typed Wails IPC、frontend integrations 分层和 Go backend analysis 边界的前提下，降低高频功能页首次进入和页面切换时的等待感。

目标能力分三层：

1. **Code preload**：提前加载 route/page JavaScript chunk，不触发后端请求。
2. **Light data prefetch**：提前拉取轻量 summary、metadata、首屏数据，并复用页面 hook/cache。
3. **Heavy analysis warmup**：仅在明确用户意图或显式开关下，受控预热少量高价值分析结果。

## 非目标

- 不做全站无差别 preload-all。
- 不恢复 generic IPC。
- 不让 desktop WebView 绕过 typed IPC 直接请求 migrated data-plane backend API。
- 不让 `pages/` 或 `features/` 直接 import Wails/desktop bridge internals。
- 不在首阶段引入复杂预测模型、行为学习或完整后端任务调度系统。
- 不默认触发 Media、Object extraction、YARA batch、APT deep aggregation、MISC run 等高成本任务。

## 架构前提

- `frontend/src/app/routes.tsx` 已使用 React Router lazy page imports。
- `frontend/src/app/layouts/MainLayout.tsx` 是导航 intent 的自然触发点。
- 功能页数据加载通常通过 feature hook + `backendClients` + local cache/inflight request 完成。
- Desktop data-plane 使用 typed Wails IPC；browser-dev 保留 HTTP/SSE fallback。
- 后端已有部分 analysis cache/singleflight，但缺少 backend-wide heavy-analysis/tshark limiter。
- 部分后端 builder 仍可能使用 `context.Background()`，前端 abort 不一定能取消已经启动的外部进程。

## 开发边界

### 前端边界

1. 路由代码预加载只允许定义在 route-adjacent registry 或 `frontend/src/app/preload/`。
2. 数据预取只允许通过 feature preload contract、domain clients 或 `backendClients`，不得绕过 integrations 层。
3. `pages/**` 不得 import `desktopBridge`、`httpBridge`、`bridgeFactory`、`bridgeDomains`、`bridgeTypes` 或 typed bridge internals。
4. `features/**` 不得跨 feature domain 直接引用预取实现；共享逻辑放在 `core/`、`integrations/`、`components/analysis/` 或 `preload/`。
5. Preload state 不应散落在多个 page-local effect 中；应集中到 scheduler/shared hook。
6. Preload 失败必须不影响正常导航、正常页面请求或用户显式操作。

### 桌面 IPC 边界

1. Desktop preload 与正常请求共用 typed IPC/domain client contract。
2. 缺 typed binding 时继续 fail-fast `generic_ipc_disabled`。
3. 不允许为 preload 恢复 generic IPC data-plane 或 browser HTTP silent fallback。
4. Browser-dev HTTP/SSE fallback 不能被 preload 改造误删。

### 后端边界

1. Heavy warmup 必须受 limiter/timeout/cancel 保护。
2. 用户显式请求优先级高于 warmup。
3. Warmup 请求必须能标记来源，用于日志、指标和降级。
4. Capture 切换/关闭后，旧 warmup 结果不得写入新 capture cache/UI。
5. Warmup failure 不应被报告成用户主流程错误。

## Preload 分类

| 类型 | 定义 | 默认策略 | 示例 |
|---|---|---|---|
| Code preload | 只加载 page chunk | 可自动启用 | TrafficGraph/EvidencePanel/C2 route module |
| Light data prefetch | 轻量 summary/metadata/首屏数据 | capture-ready 或 route intent 触发，限流 | traffic buckets、evidence first page、rule metadata |
| Heavy analysis warmup | 触发 tshark/CPU/IO/deep analysis | 默认关闭；仅 intent/manual/flag + limiter | C2、Industrial、Vehicle、USB deep analysis |

## 成本等级

| 等级 | 定义 | 默认行为 |
|---|---|---|
| LOW | import chunk、小 metadata、cached config | 可 hover/focus/idle 自动触发 |
| MEDIUM | 普通 API、小聚合、可取消首屏数据 | intent-based 或 capture-ready 后限流触发 |
| HIGH | tshark、deep analysis、大 IO、artifact side effect | 默认 disabled；必须 flag/manual/intent + backend limiter |

## 初始预算建议

```ts
const PRELOAD_BUDGET = {
  maxConcurrentCodePreloads: 4,
  maxConcurrentLightDataPreloads: 2,
  maxConcurrentHeavyWarmups: 1,
  hoverIntentDelayMs: 180,
  heavyHoverIntentDelayMs: 400,
  idleDelayMs: 1200,
  lightDataTimeoutMs: 5000,
  heavyWarmupTimeoutMs: 15000,
};
```

规则：

- 当前 route 的用户显式请求永远优先于 preload。
- 同 target + same capture key 必须 dedupe/inflight reuse。
- Capture revision/file path 变化时 abort 旧 preload。
- HIGH cost target 不得 `enabledByDefault: true`。

## Telemetry 事件口径

建议记录以下事件：

- `preload.started`
- `preload.skipped`
- `preload.reused`
- `preload.aborted`
- `preload.fulfilled`
- `preload.failed`
- `preload.promoted`

建议字段：

```ts
type PreloadTelemetry = {
  targetId: string;
  kind: "code" | "light-data" | "heavy-analysis";
  cost: "low" | "medium" | "high";
  trigger: "hover" | "focus" | "idle" | "capture-ready" | "manual" | "route-enter";
  captureRevision?: number;
  durationMs?: number;
  reason?: string;
};
```

## Phase 0 — 基线、分类与门禁

### 目标

在启用任何新 preload 行为前，定义 target inventory、成本分类、预算、指标和一票否决项。

### Tasks

1. 建立 preload target inventory。
2. 定义 code/light/heavy taxonomy。
3. 定义成本等级和预算表。
4. 定义 telemetry event schema。
5. 文档化一票否决项。
6. 设计 `check-preload-budget` / `check-preload-boundaries` 的规则草案。

### Tests

- Target inventory schema test。
- Budget decision pure-function test。
- HIGH cost target default-disabled test。
- Unknown target safe-skip test。

### Acceptance Criteria

- 所有首批 target 有 kind/cost/trigger/timeout/canAbort/requiresCapture。
- HIGH cost target 默认关闭。
- 有明确预算和 telemetry 字段。
- 计划文档中列明一票否决项。

### Scoring

| 项目 | 分数 |
|---|---:|
| Target inventory 完整 | 25 |
| Budget 明确 | 20 |
| HIGH cost 默认受控 | 20 |
| Telemetry 定义 | 15 |
| 文档清晰 | 20 |

通过线：85/100。

## Phase 1 — Route Code Chunk Preload

### 目标

只预加载页面代码 chunk，不发后端请求，不触发 analysis。

### Tasks

1. 从 `routes.tsx` 抽出 route import registry。
2. 实现 `preloadRouteModule(routeId)`：dedupe promise、失败可重试、unknown route safe-skip。
3. 在 `MainLayout` 侧边栏导航 hover/focus 接入 route module preload。
4. 增加 hover intent debounce，快速划过不触发。
5. 可选：当前页稳定后 idle 预加载 1-2 个邻近高频 route chunk。

### Tests

- `preloadRouteModule` 重复调用只触发一次 import。
- import 失败后 cache 清理并允许重试。
- unknown route 不抛异常。
- hover 超过阈值触发 preload。
- 快速 hover/移出不触发。
- focus 触发 preload。
- preload 不调用 `backendClients`。

### Required Checks

```bash
cd frontend && pnpm run typecheck
cd frontend && pnpm run lint
cd frontend && pnpm run boundary:check
cd frontend && pnpm run size:check
cd frontend && pnpm run test:run
cd frontend && pnpm run build
```

### Acceptance Criteria

- 高频 route chunk 可被 hover/focus 提前加载。
- 失败不影响正常 navigation。
- 无后端请求副作用。
- 无分层违规。
- 主 bundle 不因改造显著膨胀或超过 size budget。

### Scoring

| 项目 | 分数 |
|---|---:|
| Registry 与 lazy route 复用干净 | 20 |
| Hover/focus 行为稳定 | 20 |
| 无后端副作用 | 20 |
| 无 bundle/size 回归 | 15 |
| 测试完整 | 15 |
| 失败可恢复 | 10 |

通过线：85/100。

## Phase 2 — Light Data Prefetch

### 目标

对少数低风险高价值页面预取轻量数据，并与页面 hook/cache 共享 key 和 inflight promise。

建议试点：

1. TrafficGraph。
2. EvidencePanel。
3. ThreatHunting 的规则/metadata，不跑重扫描。

### Tasks

1. 为试点 feature 抽取 preload/cache contract：
   - `getCacheKey(input)`
   - `readCache(key)`
   - `writeCache(key, data)`
   - `getInflight(key)`
   - `prefetch(input, signal)`
2. TrafficGraph 预取 global stats / timeline buckets / lightweight evidence marker summary。
3. EvidencePanel 预取 first page / filter options / module summary / YARA/community counters。
4. 实现 preload scheduler v1：light data 并发最多 2，capture 变更 abort，same key dedupe。
5. 页面 mount 时复用 in-flight preload 或 cache hit。

### Tests

- Cache key stable test。
- Preload 写入 cache 后 hook 命中 test。
- Hook mount 复用 in-flight preload promise test。
- Capture revision 改变 abort old preload test。
- Preload failure 不污染 cache test。
- Scheduler concurrency <= 2 test。
- TrafficGraph/EvidencePanel 进入时不重复请求 test。

### Required Checks

```bash
cd frontend && pnpm run typecheck
cd frontend && pnpm run lint
cd frontend && pnpm run boundary:check
cd frontend && pnpm run size:check
cd frontend && pnpm run test:run
cd frontend && pnpm run build
```

### Acceptance Criteria

- 至少 2 个页面稳定复用 light-data preload。
- 没有重复请求风暴。
- 不触发 heavy analysis。
- Capture 切换不展示旧数据。
- 所有 preload 可 abort。

### Scoring

| 项目 | 分数 |
|---|---:|
| Cache contract 干净 | 20 |
| TrafficGraph 预取稳定 | 15 |
| EvidencePanel 预取稳定 | 15 |
| Scheduler 限流有效 | 20 |
| Stale/abort 正确 | 15 |
| 测试覆盖 | 15 |

通过线：85/100。

## Phase 3 — Intent-based Medium/Heavy Warmup

### 目标

只对少量高价值页面，在明确用户意图下受控预热 heavy analysis。

### 初始白名单

| 页面 | 是否允许 | 触发 |
|---|---:|---|
| C2Analysis | 是 | hover/focus + capture-ready + idle + flag |
| IndustrialAnalysis | 是 | hover/focus + flag |
| VehicleAnalysis | 是 | hover/focus + flag |
| USBAnalysis | 是 | hover/focus + flag |
| APTAnalysis | 暂缓 | 等 singleflight/去重补齐 |
| MediaAnalysis | 否 | 用户显式 |
| ObjectExport | 否 | 用户显式 |
| MiscTools run | 否 | 用户显式 |

### Tasks

1. 增加 heavy warmup feature flag，默认 false。
2. Heavy warmup 前端 gate：desktop-only、idle-only、hover >= 400ms、maxConcurrent=1。
3. 修复/确认 Vehicle/USB/C2 等页面 fetch ownership，避免 hook 与 page effect 重复 refresh。
4. 后端增加 heavy-analysis/tshark limiter。
5. Warmup 请求加来源标记，用于日志/指标/降级。
6. 后端逐步把 request/capture context 传入 tshark builders，减少 `context.Background()`。
7. Warmup failure 不更新用户主错误状态。

### Backend Tests

- Limiter 最大并发不超过阈值。
- Warmup cancel 释放 slot。
- Timeout 释放 slot。
- Normal request 优先于 warmup。
- Stale capture 不提交结果。
- Singleflight + limiter 不死锁。

### Frontend Tests

- Heavy warmup 默认 disabled。
- Flag enabled + hover 超阈值触发。
- 快速 hover 不触发。
- Capture 切换 abort warmup。
- 页面进入复用 inflight warmup。

### Required Checks

```bash
cd frontend && pnpm run typecheck
cd frontend && pnpm run lint
cd frontend && pnpm run boundary:check
cd frontend && pnpm run size:check
cd frontend && pnpm run test:run
cd backend && gofmt -l .
cd backend && go test ./...
cd backend && go test ./internal/architecture -run TestBackendArchitectureBoundaries -count=1 -v
```

### Acceptance Criteria

- HIGH cost warmup 默认关闭。
- 启用后也不会并发风暴。
- 后端主请求不饥饿。
- Warmup 可取消、可超时、可降级。
- Telemetry 可见 hit/waste/abort/fail。

### Scoring

| 项目 | 分数 |
|---|---:|
| HIGH cost gate 安全 | 20 |
| Backend limiter 有效 | 25 |
| Context cancel 有效 | 20 |
| Normal request 优先 | 15 |
| Telemetry 可用 | 10 |
| 测试充分 | 10 |

通过线：90/100。

## Phase 4 — 观测、灰度与持续优化

### 目标

让 preload 成为可量化、可回退、可逐页扩面的长期机制。

### Tasks

1. 增加前端指标：
   - route preload hit rate
   - data prefetch hit rate
   - waste rate
   - abort/fail rate
   - skeleton duration
   - route interactive time
2. 增加后端指标：
   - warmup queue depth
   - warmup cancel/timeout
   - limiter wait time
   - main request latency p95
3. 每个页面独立 feature flag。
4. 自动降级策略：high warmup off -> light data off -> code-only。
5. 新增 preload 准入模板。

### Tests

- Flag on/off test。
- Auto downgrade policy test。
- Telemetry schema test。
- Page-level preload independent disable test。
- Metrics 不影响主流程 test。

### Acceptance Criteria

- 每个 preload target 可独立开关。
- 有 hit/waste/abort/fail 数据。
- 可快速回退到 code-only。
- 新增 preload target 有准入记录和评分。

### Scoring

| 项目 | 分数 |
|---|---:|
| Metrics 完整 | 25 |
| Flag 粒度合理 | 20 |
| 自动降级有效 | 20 |
| Rollback 简单 | 15 |
| 准入流程清晰 | 10 |
| 测试覆盖 | 10 |

通过线：85/100。

## CI / 门禁建议

### 保持现有门禁

- `pnpm run typecheck`
- `pnpm run lint`
- `pnpm run format:check`
- `pnpm run size:check`
- `pnpm run boundary:check`
- `pnpm run test:run`
- `pnpm run build`
- `cd backend && go test ./...`
- Backend architecture boundary tests

### 新增建议门禁

#### `frontend/scripts/check-preload-boundaries.mjs`

规则草案：

- `pages/**` 不得 import preload implementation internals，只能使用 public hook/API。
- `preload/**` 不得 import Wails/desktop bridge internals。
- `features/**` 不得直接 import route module registry。
- Preload modules 不得绕过 `backendClients`/domain clients。

#### `frontend/scripts/check-preload-budget.mjs`

规则草案：

- 每个 target 必须声明 kind/cost/trigger/timeout/canAbort/requiresCapture。
- HIGH cost target 不得默认启用。
- 每个 route 的 idle neighbor preload 数量不得超过预算。
- Light data / heavy warmup 必须有 timeout。
- Heavy warmup 必须有 feature flag。

#### 后端 focused tests

```bash
cd backend && go test ./internal/engine -run "TestAnalysisLimiter|TestWarmup|TestAnalysisCancel" -count=1 -v
```

## 总评分 Rubric

总分 100，80 分以上允许进入下一阶段，涉及 heavy warmup 时建议 90 分以上。

| 维度 | 分数 | 说明 |
|---|---:|---|
| 架构合规性 | 25 | 遵守 pages/features/integrations/state/IPC 边界 |
| 用户体验收益 | 20 | 页面进入、skeleton 时长、可交互时间明显改善 |
| 资源效率 | 20 | 高命中、低浪费、无请求风暴 |
| 后端安全性 | 15 | limiter/cancel/priority/stale guard 完整 |
| 可观测性与回退 | 10 | telemetry、flag、rollback、降级完整 |
| 测试覆盖 | 10 | unit/component/integration/backend focused 覆盖关键路径 |

## 一票否决项

出现以下任一情况直接不通过：

1. Preload 失败阻断正常导航。
2. HIGH cost warmup 默认全开。
3. 无 limiter 发起多个 heavy analysis。
4. 页面直接访问 Wails/desktop bridge internals。
5. 预加载结果跨 capture 污染。
6. 用户显式请求被 warmup 饿死。
7. 主 bundle 因 preload 改造显著膨胀并超过 size budget。
8. Desktop typed IPC 策略被破坏或恢复 generic IPC。
9. Browser-dev fallback 被误删。
10. 测试缺失但宣称性能完成。

## 推荐落地顺序

1. Phase 0：文档、target inventory、budget policy、评分表。
2. Phase 1：route import registry + `preloadRouteModule`。
3. Phase 1：MainLayout hover/focus code preload + tests。
4. Phase 2：TrafficGraph light prefetch cache contract。
5. Phase 2：EvidencePanel light prefetch cache contract。
6. Phase 2：preload scheduler + telemetry。
7. Phase 3：backend limiter design 和 tests，先不接 heavy warmup。
8. Phase 3：C2/Industrial/Vehicle/USB intent-based warmup 试点。
9. Phase 4：metrics、灰度、自动降级、准入模板。

## Phase 1 最小改动集建议

```text
frontend/src/app/routes.tsx
frontend/src/app/preload/routePreload.ts
frontend/src/app/preload/routePreload.test.ts
frontend/src/app/layouts/MainLayout.tsx
frontend/src/app/layouts/MainLayout.test.tsx
```

Phase 1 不应触碰后端，不应引入数据 prefetch，不应改变正常 route 行为。

## 2026-06-06 实施状态

本轮已按计划完成 Phase 0 至 Phase 4 的首版闭环，默认行为保持保守：

- 默认开启：Phase 1 route code preload。
- 默认关闭：Phase 2 light-data preload（`VITE_PRELOAD_LIGHT_DATA=1` 才启用）。
- 默认关闭：Phase 3 heavy warmup（`VITE_PRELOAD_HEAVY_WARMUP=1` 且 desktop/capture-ready/idle/hover gate 通过才启用）。
- 一键回退：`VITE_PRELOAD_CODE_ONLY=1` 禁用 data/heavy job；`VITE_PRELOAD_DISABLED_TARGETS` 可按 target 独立禁用。

### 已落地设计

| Phase | 状态 | 关键落点 |
|---|---|---|
| Phase 0 | Done | `frontend/src/app/preload/preloadTargets.ts` inventory、`preloadBudget.ts`、`preloadTelemetry.ts`、CI budget/boundary guard |
| Phase 1 | Done | `routeModuleLoaders.ts` 与 `routes.tsx` 共用 lazy import registry；hover/focus/idle code preload 无后端请求 |
| Phase 2 | Done | `preloadScheduler.ts` light queue；Traffic/Evidence/Hunting/Rules preload contract；Evidence 默认只预取 `modules=["hunting"]` |
| Phase 3A | Done | backend `AnalysisRequestMeta`、warmup limiter、context-aware warmer、C2 cold ctx、singleflight fallback、warmup telemetry |
| Phase 3B | Done | desktop-only heavy gate、hover 400ms、capture-ready、idle、flag 默认 off、失败只写 telemetry |
| Phase 3C | Done | C2/Industrial/Vehicle/USB heavy targets；Vehicle key 含 DBC paths；USB key 含 HID source/limit；APT/Media/Object/MISC 仍禁止 |
| Phase 4 | Done | 前端 metrics recorder、target flags、code-only rollback、后端 warmup/request telemetry 聚合 |

### 实施测试矩阵结果

| Area | 覆盖 |
|---|---|
| Inventory/budget | HIGH default-off、timeout、featureFlag、unknown target safe-skip、guard script tests |
| Boundary | preload 不 import desktop bridge internals；pages 不 import preload internals；CI 已接入 `preload:budget:check` / `preload:boundary:check` |
| Route code preload | dedupe、reject retry、unknown route telemetry、hover delay、focus preload、idle neighbor |
| Light scheduler | concurrency <=2、same target/cacheKey dedupe、timeout abort、capture abort |
| Traffic/Evidence | hook cache/inflight 复用；Traffic background 不走 `listPackets()` fallback；Evidence preload 必须显式 modules |
| Hunting/Rules | Hunting 只预取 runtime config；Rules direct fetch 已迁入 domain client，只预取 status |
| Heavy backend | warmup max 1、wait cancel release、normal bypass、C2 ctx propagation、user+warmup same-key singleflight |
| Heavy frontend | flag off skip、desktop gate、forbidden targets skip、C2 warmup source、Vehicle/USB cache key |
| Metrics/rollback | telemetry sink throw safe、summary/downgrade、code-only/target-disable flag、backend `__analysis_warmup__`/`__analysis_request__` status events |

### 新 target 准入模板

新增 preload target 前必须补齐：

```text
targetId:
routePath:
kind: code | light-data | heavy-analysis
cost: low | medium | high
featureFlag:
enabledByDefault:
request path / domain client:
cache key fields:
capture stale behavior:
abort behavior:
forbidden side effects:
tests:
rollback:
score:
```

准入要求：

- HIGH 必须默认关闭、必须有 feature flag、必须经过 backend limiter/context cancel test。
- Light data 必须能 abort，必须复用页面 cache/inflight，Evidence-like 聚合必须显式限定模块。
- Code preload 必须只 import route chunk，不能触发 backendClients 或 typed IPC。
- Rollback 至少支持 target 级 disable；高风险 target 还必须支持 code-only 降级。

### 验证结果

```powershell
cd backend && gofmt -l .                         # pass
cd backend && go test ./...                      # pass
cd frontend && pnpm run typecheck                # pass
cd frontend && pnpm run lint                     # pass
cd frontend && pnpm run format:check             # pass
cd frontend && pnpm run preload:budget:check     # pass
cd frontend && pnpm run preload:boundary:check   # pass
cd frontend && pnpm run boundary:check           # pass
cd frontend && pnpm run wails-binding:check      # pass
cd frontend && pnpm run test:run                 # pass, 262 files / 883 tests
cd frontend && pnpm run build                    # pass
cd frontend && pnpm run size:check               # fail: existing size-budget baseline only
```

`size:check` 失败项未包含本轮新增 preload/layout 文件，仍为既有超预算文件：wire DTO、mapper、TrafficGraph/Evidence/Industrial/Misc 相关大文件。该项需单独拆分治理，不属于 preload 实施引入的新增超预算。

_实施人: Codex | 时间: 2026-06-06 19:20:14 +08:00_

## 2026-06-06 健壮性复审补充

- 发现并修复：后端 internal telemetry status event（`__analysis_warmup__` / `__analysis_request__` / `__evidence_timing__`）可能被前端 lifecycle 写入用户可见 backend status。
- 修复方式：新增 `isInternalTelemetryStatusMessage`，在 `backendLifecycleEvents` 中直接丢弃 internal telemetry，不触发 progress、waiter 或状态栏更新。
- 覆盖测试：`backendStatusMessage.test.ts` 与 `useBackendLifecycle.test.tsx` 增加 telemetry drop 场景。
- 复验：backend tests、frontend full tests、typecheck、lint、format、preload guards、boundary guards、wails binding、build 均通过。
- `size:check` 仍失败于既有 baseline。拆分方案已独立记录在 `docs/frontend-size-budget-split-plan-2026-06-06.md`。

_复审人: Codex | 时间: 2026-06-06 19:40:32 +08:00_
