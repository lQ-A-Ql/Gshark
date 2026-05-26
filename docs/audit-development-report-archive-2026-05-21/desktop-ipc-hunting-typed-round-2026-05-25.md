# Desktop IPC hunting typed round

- Author: Codex
- Time: 2026-05-25 23:18:00 +08:00
- Round: 7
- Phase: post-phase-5
- Primary domain: hunting typed IPC

## 迁移域与目标

本轮只迁移 hunting 域，不并行迁移 plugin、vehicle DBC 或 MISC multipart。

目标：

- 新增 `ListThreatHits` typed DesktopApp binding，覆盖 `/api/hunting`。
- 新增 `GetHuntingRuntimeConfig` typed DesktopApp binding，覆盖 `GET /api/hunting/config`。
- 新增 `UpdateHuntingRuntimeConfig` typed DesktopApp binding，覆盖 `POST /api/hunting/config`。
- 桌面模式优先 typed IPC；typed binding 存在时，匹配的 generic IPC path 不得继续兜底。
- 浏览器 dev 保留 HTTP/SSE 调试链路。

## 修改面清单

- `desktop_backend_proxy.go`
  - 新增 hunting runtime config DTO。
  - 新增 `ListThreatHits`、`GetHuntingRuntimeConfig`、`UpdateHuntingRuntimeConfig`。
  - `backendProxyClient` 改为无全局 `http.Client.Timeout`，由每个 typed 方法的 context deadline 控制。
- `frontend/src/app/integrations/desktopTypedBridgeHunting.ts`
  - 新增 hunting typed override。
  - `ListThreatHits` 复用 `asThreatHit` mapper。
  - runtime config 复用 hunting client mapper。
- `frontend/src/app/integrations/clients/huntingClient.ts`
  - 导出 runtime config mapper，避免 typed path 重新实现 DTO 归一化。
- `frontend/src/app/integrations/desktopTypedBridge.ts`
  - 组合 hunting typed override。
- `frontend/src/app/integrations/desktopTypedBridgeCore.ts`
  - hunting route 到 typed method 映射。
- `frontend/src/app/integrations/desktopTransportBinding.ts`
  - 声明 hunting typed binding。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - `/api/hunting` 和 `/api/hunting/config` generic IPC 路径映射到 typed binding。
- `frontend/scripts/check-wails-bindings.mjs`
  - 新增 `typed-hunting` binding group。
- `frontend/scripts/check-desktop-transport-policy.mjs`
  - 新增 hunting typed override 和 route policy guard。
- `frontend/wailsjs/go/main/DesktopApp.{js,d.ts}`
  - 增加 hunting generated binding 声明与调用包装。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - WebView typed smoke 覆盖 `ListThreatHits` 和 `GetHuntingRuntimeConfig`。
- `scripts/check-desktop-ipc-smoke.ps1`
  - 断言 hunting runtime config 至少包含一个 prefix，summary 记录 `threatHitCount`、`huntingPrefixCount`、`huntingYaraEnabled`。
- `desktop_typed_bindings_test.go`
  - 新增 hunting typed backend route contract test。
  - 新增 proxy client 使用 per-request context timeout 的契约测试。
- `backend/internal/engine/service.go`
  - YARA scan config 在构建 stream targets 前执行 preflight。
- `backend/internal/engine/yara_batch.go`
  - 提取 `preflightYaraScanConfig` / `resolveYaraScanConfig`。
- `backend/internal/engine/yara_batch_test.go`
  - 覆盖 YARA 不可用时不先构建 stream targets。
- `backend/internal/engine/evidence_test.go`
  - 关闭本测试的外部 YARA 依赖，避免本机工具安装状态改变 Evidence 核心映射计数。

## Focused Test 结果

通过：

```powershell
go test ./internal/engine -run TestCachedYaraHitsPreflightsYaraBeforeBuildingStreamTargets -count=1 -v
go test ./internal/engine
go test -tags dev ./...
cd frontend; pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/bridgeFactory.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/clients/huntingClient.test.ts scripts/check-desktop-transport-policy.test.mjs
node frontend/scripts/check-wails-bindings.mjs
node frontend/scripts/check-desktop-transport-policy.mjs
```

Focused frontend result:

- 5 test files passed
- 50 tests passed

## Full Gate 结果

通过：

```powershell
go test -tags dev ./...
go test -tags production ./...
cd backend; go test ./...
cd frontend; pnpm run typecheck
cd frontend; pnpm run lint
cd frontend; pnpm run format:check
cd frontend; pnpm run size:check
cd frontend; pnpm run ci
cd frontend; pnpm run build:wails
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
node frontend/scripts/check-wails-bindings.mjs
node frontend/scripts/check-desktop-transport-policy.mjs
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1
git diff --check
```

Frontend CI result:

- 228 test files passed
- 716 tests passed

Smoke result:

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `capturePackets = 7074`
- `threatHitCount = 721`
- `huntingPrefixCount = 2`
- `huntingYaraEnabled = true`
- `directBackendApiRequestCount = 0`

Note:

- 一次并行执行中的 `check-desktop-assets.ps1` 抢在 `build:wails` 完成前运行并失败；顺序重跑后通过。最终有效 gate 以顺序重跑结果为准。

## 桌面/浏览器行为差异说明

- Desktop release / desktop dev: hunting typed binding 存在时，`/api/hunting` 与 `/api/hunting/config` 不允许 generic IPC silent fallback；typed IPC 错误应作为 desktop IPC/typed endpoint failure 暴露。
- Browser dev: 无 Wails binding 时继续使用 HTTP/SSE；本轮 smoke 验证 `browserDev.ok = true`，SSE 首行是 `event: ready`。
- YARA unavailable: hunting API 仍返回业务层 warning hit，便于页面诊断；统一 Evidence 的核心映射测试不依赖本机是否安装 YARA。

## 评分

总分：96 / 100

- Contract Correctness: 24 / 25
  - typed binding、route mapping、DTO mapper 和 Go route contract 已覆盖。
  - 仍复用 backend HTTP proxy 调现有 `/api/...`，因此不满分。
- Desktop Policy Compliance: 20 / 20
  - typed binding 存在时 hunting generic IPC path 被 runtime guard 拒绝。
  - WebView smoke 记录 `directBackendApiRequestCount = 0`。
- Regression Safety: 20 / 20
  - focused tests、root dev/production、backend full、frontend CI、build:wails、binding/policy checks、desktop smoke 全部通过。
- Diagnostics and Failure Shape: 15 / 15
  - YARA 不可用从长超时变成显式 `YARA 扫描异常` warning。
  - hunting 业务 warning 与 desktop transport failure 可区分。
- Docs and Traceability: 10 / 10
  - tracker、migration plan、round report 已同步。
- Dev/Browser Compatibility: 7 / 10
  - browser dev HTTP/SSE smoke 通过。
  - 未做人工打开 UI 逐页点击，只用脚本化 smoke 覆盖。

## Open Blockers

无硬阻塞。

已修复的本轮 blocker：

- 本机没有 `yara.exe` 时，hunting smoke 原先会在构建 stream scan targets 后等待 context deadline。
- 修复后在构建 targets 前 preflight，返回 `YARA 扫描异常` warning，不再拖垮 typed smoke。

## 自迭代记录

自动决策：advance-to-next-remaining-domain。

原因：

- 本轮总分 96，超过 `>= 90` 阈值。
- 无硬阻塞。
- `docs/desktop-ipc-iteration-status.json` 已更新。
- 真实 Wails WebView typed smoke 通过，并证明 WebView 未直接请求 backend `/api/...`。

## 下一轮自动建议

推荐下一轮：vehicle DBC management typed IPC。

理由：

- 它比 plugin management 更窄，适合单轮切片。
- 它属于主线 vehicle analysis 工作流，比 MISC multipart compatibility 更接近检测主线。
- MISC multipart import/invoke/delete/list 仍保留为明确 generic IPC compatibility seam，不应与 DBC 管理并行迁移。
