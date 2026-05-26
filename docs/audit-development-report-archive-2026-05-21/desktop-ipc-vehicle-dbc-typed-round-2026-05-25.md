# Desktop IPC vehicle DBC typed round

- Author: Codex
- Time: 2026-05-25 23:50:00 +08:00
- Round: 8
- Phase: post-phase-5
- Primary domain: vehicle DBC management typed IPC

## 迁移域与目标

本轮只迁移 vehicle DBC management，不并行迁移 plugin management 或 MISC multipart compatibility。

目标：

- 新增 `ListVehicleDBCProfiles` typed DesktopApp binding，覆盖 `GET /api/analysis/vehicle/dbc`。
- 新增 `AddVehicleDBC` typed DesktopApp binding，覆盖 `POST /api/analysis/vehicle/dbc`。
- 新增 `RemoveVehicleDBC` typed DesktopApp binding，覆盖 `DELETE /api/analysis/vehicle/dbc?path=...`。
- 桌面模式优先 typed IPC；typed binding 存在时，匹配的 generic IPC path 不得继续兜底。
- 浏览器 dev 保留 HTTP/SSE 调试链路。

## 修改面清单

- `desktop_backend_proxy.go`
  - 新增 vehicle DBC typed request DTO。
  - 新增 `ListVehicleDBCProfiles`、`AddVehicleDBC`、`RemoveVehicleDBC`。
  - 新增 `desktopDeleteJSON`，复用现有 backend route 的 DELETE 语义。
- `desktop_typed_bindings_test.go`
  - 新增 vehicle DBC typed binding route contract test，覆盖 GET、POST body、DELETE query。
- `frontend/src/app/integrations/desktopTypedBridgeVehicleDbc.ts`
  - 新增 vehicle DBC typed override。
  - 复用 `asDBCProfiles` mapper 保持 DTO 归一化一致。
- `frontend/src/app/integrations/desktopTypedBridge.ts`
  - 组合 vehicle DBC typed override。
- `frontend/src/app/integrations/desktopTypedBridgeCore.ts`
  - 加入 vehicle DBC route 到 typed method 映射。
- `frontend/src/app/integrations/desktopTransportBinding.ts`
  - 声明 vehicle DBC typed binding。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - `/api/analysis/vehicle/dbc` GET/POST/DELETE generic IPC 路径映射到对应 typed binding。
- `frontend/src/app/integrations/desktopBridge.test.ts`
  - 覆盖 DBC typed call，验证不落 generic IPC。
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`
  - 覆盖 migrated DBC route 的 `typed_binding_required` 阻断。
- `frontend/scripts/check-wails-bindings.mjs`
  - 新增 `typed-vehicle-dbc` binding group。
- `frontend/scripts/check-desktop-transport-policy.mjs`
  - 将 DBC typed override 与 route policy 纳入静态检查。
- `frontend/scripts/check-desktop-transport-policy.test.mjs`
  - 增加 DBC typed override fixture。
- `frontend/wailsjs/go/main/DesktopApp.{js,d.ts}`
  - 增加 DBC generated binding 声明与调用包装。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - WebView typed smoke 覆盖 `ListVehicleDBCProfiles`。
- `scripts/check-desktop-ipc-smoke.ps1`
  - summary 记录 `vehicleDBCProfileCount`。
- `docs/desktop-ipc-migration-plan.md`
- `docs/desktop-ipc-iteration-status.json`

## Focused Test 结果

已通过：

```powershell
go test -tags dev ./...
cd frontend
pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/bridgeFactory.test.ts src/app/integrations/ipcBackendTransport.test.ts src/app/features/vehicle/useVehicleDbcProfiles.test.tsx src/app/integrations/clients/pluginClient.test.ts scripts/check-desktop-transport-policy.test.mjs
node scripts/check-wails-bindings.mjs
node scripts/check-desktop-transport-policy.mjs
```

Focused frontend result：

- 6 test files passed。
- 54 tests passed。

Root Go contract：

- `go test -tags dev ./...` passed。
- `TestDesktopVehicleDBCTypedBindingsProxyExpectedBackendRoutes` 覆盖 DBC GET/POST/DELETE route contract。

## Full Gate 结果

已通过：

```powershell
go test -tags dev ./...
go test -tags production ./...
cd backend && go test ./...
cd frontend && pnpm run typecheck
cd frontend && pnpm run lint
cd frontend && pnpm run format:check
cd frontend && pnpm run size:check
cd frontend && pnpm run ci
cd frontend && pnpm run build:wails
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
node frontend/scripts/check-wails-bindings.mjs
node frontend/scripts/check-desktop-transport-policy.mjs
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1
git diff --check
```

Full gate evidence：

- Frontend CI：228 test files passed，717 tests passed。
- `build:wails`：passed，Desktop asset check ok。
- Wails binding check：ok。
- Desktop transport policy check：passed。
- `git diff --check`：passed。
- Desktop IPC smoke：passed。

Desktop IPC smoke evidence：

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `capturePackets = 7074`
- `packetPageTotal = 7074`
- `vehicleDBCProfileCount = 0`
- `threatHitCount = 721`
- `huntingPrefixCount = 2`
- `objectCount = 205`
- `objectEvidenceCount = 205`
- `directBackendApiRequestCount = 0`

## 桌面/浏览器行为差异说明

- Desktop release / desktop dev: DBC typed binding 存在时，`/api/analysis/vehicle/dbc` GET/POST/DELETE 不允许 generic IPC silent fallback；typed IPC 错误应作为 desktop IPC/typed endpoint failure 暴露。
- Browser dev: 无 Wails binding 时继续使用 HTTP/SSE；本轮 smoke 验证 `browserDev.ok = true`，SSE 首行是 `event: ready`。
- 业务空结果：`http.pcap` 当前没有已注册 DBC profile，`ListVehicleDBCProfiles` 返回 `vehicleDBCProfileCount = 0`，这是 valid business-empty result，不是 IPC transport failure。
- 本轮 WebView smoke 不执行 add/remove DBC，避免修改用户本机 DBC profile 状态。

## 评分

总分：95 / 100

- Contract Correctness：25 / 25
  - DBC GET/POST/DELETE typed binding、route mapping、DTO mapper 和 Go route contract 已覆盖。
- Desktop Policy Compliance：20 / 20
  - typed binding 存在时 DBC generic IPC path 被 runtime guard 拒绝。
  - WebView smoke 记录 `directBackendApiRequestCount = 0`。
- Regression Safety：20 / 20
  - focused tests、root dev/production、backend full、frontend CI、build:wails、binding/policy checks、desktop smoke 全部通过。
- Diagnostics and Failure Shape：13 / 15
  - DBC list 业务空结果与 IPC failure 可区分。
  - 扣 2 分：add/remove 的真实桌面 smoke 未执行，避免修改本地 profile 状态；错误形态主要由 contract test 覆盖。
- Docs and Traceability：10 / 10
  - tracker、migration plan、round report 已同步。
- Dev/Browser Compatibility：7 / 10
  - browser-dev HTTP/SSE smoke 通过。
  - 扣 3 分：未做人工打开 UI 逐页点击，只做脚本化 smoke。

## Open Blockers

无硬阻塞。

Residual risk：

- WebView smoke 只验证 DBC list，不实际 add/remove 文件；add/remove route correctness 由 Go contract test 与 frontend integration test 覆盖。

## 自迭代记录

自动决策：advance-to-next-remaining-domain。

原因：

- 本轮总分 95，超过 `>= 90` 阈值。
- 无硬阻塞。
- `docs/desktop-ipc-iteration-status.json` 已更新。
- 真实 Wails WebView typed smoke 通过，并证明 WebView 未直接请求 backend `/api/...`。

## 下一轮自动建议

推荐下一轮：plugin management typed IPC。

理由：

- vehicle DBC management 已完成，remaining generic IPC category 中 plugin management 是下一条非 multipart 管理路径。
- plugin management 可作为单独一轮覆盖 metadata/source/save/add/delete/toggle/bulk-enabled 等管理接口。
- MISC multipart import/invoke/delete/list 仍应保留为明确 generic IPC compatibility seam，避免与 plugin management 并行迁移。
