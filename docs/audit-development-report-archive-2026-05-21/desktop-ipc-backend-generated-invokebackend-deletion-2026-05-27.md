# Desktop IPC backend/generated InvokeBackend* deletion

- Author: Codex
- Time: 2026-05-27 00:48:49 +08:00
- Round: 34
- Phase: post-phase-5

## 迁移域与目标

本轮主域是 backend/generated `InvokeBackend*` deletion candidate。

目标：删除发行版桌面不再使用的 generic IPC backend/generated binding surface，让 typed IPC 和显式 fail-fast transport 成为桌面数据面唯一入口。Browser-dev HTTP/SSE debugging 保持不变。

本轮删除：

- backend `DesktopApp.InvokeBackendJSON`
- backend `DesktopApp.InvokeBackendBlob`
- backend `DesktopApp.InvokeBackendText`
- generated Wails `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`
- `DesktopShellBinding.InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`
- `frontend/src/app/integrations/ipcBackendTransport.ts` legacy adapter inventory

本轮保留：

- `desktopDisabledGenericIpcTransport.ts` 的 `generic_ipc_disabled` fail-fast 行为
- `desktopEventTransport.ts` 的 Wails runtime event subscription
- browser-dev HTTP/SSE 调试链路
- shell/bootstrap bindings such as `GetBackendAuthToken`, `OpenCaptureDialog`, `BackendStatus`, update flow, and native dialogs

## 修改面清单

- `desktop_backend_proxy.go`
  - 删除 exported `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`。
  - typed blob/text methods 继续复用 non-exported `invokeBackendBlob` / `invokeBackendText`。
- `frontend/wailsjs/go/main/DesktopApp.d.ts`
  - 删除 generated `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` declaration。
- `frontend/wailsjs/go/main/DesktopApp.js`
  - 删除 generated `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` wrappers。
- `frontend/src/app/integrations/desktopTransportBindingShell.ts`
  - 删除 shell binding 中的 `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` fields。
- `frontend/src/app/integrations/desktopIpcControls.ts`
  - 新增 shared `DesktopIpcRequestError`、`IpcBackendTransport`、`withDesktopIpcControls`、`DESKTOP_IPC_BLOB_MAX_BYTES`、blob limit check。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - 删除 legacy generic IPC adapter inventory file。
- `frontend/src/app/integrations/desktopBridge.ts`
  - shared IPC controls import 改到 `desktopIpcControls.ts`。
- `frontend/src/app/integrations/desktopTypedBridgeCore.ts`
  - shared IPC controls import 改到 `desktopIpcControls.ts`。
  - typed blob call 在 base64 decode 前检查 50MB 上限。
- `frontend/src/app/integrations/desktopDisabledGenericIpcTransport.ts`
  - shared error/transport type import 改到 `desktopIpcControls.ts`。
- `frontend/scripts/check-wails-bindings.mjs`
  - 移除 `generic-ipc` required group。
  - 新增 removed `InvokeBackend*` forbidden binding check。
- `frontend/scripts/check-desktop-old-binding-compat.mjs`
  - 不再允许 `ipcBackendTransport.ts` `InvokeBackend*` inventory。
  - exit plan token 改为 removed `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`。
- `frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs`
  - 从 inventory allowlist 改为 deletion-completed 禁止回流扫描。
  - backend/generated cleanup 标记完成后要求 `adapterRemoved = true`。
- `frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs`
  - 支持并要求 blockers cleared 后 `status = deletion-completed`、`deletionReady = true`。
- `docs/desktop-ipc-iteration-status.json`
  - 更新 Round 34 事实源。
- `docs/desktop-ipc-migration-plan.md`
  - 追加 Round 34 记录和 post-removal audit 要求。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - 更新为 shell-compat-only 状态。

## Focused Test 结果

Commands:

```powershell
cd frontend
pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/desktopDisabledGenericIpcTransport.test.ts src/app/integrations/desktopIpcControls.test.ts scripts/check-desktop-old-binding-compat.test.mjs scripts/check-desktop-generic-ipc-removal-preflight.test.mjs scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs scripts/check-desktop-generic-ipc-binding-cleanup-preflight.test.mjs
pnpm run typecheck
cd ..
go test -tags dev ./...
node frontend/scripts/check-wails-bindings.mjs
```

Result:

- focused Vitest: passed, 7 files / 65 tests
- frontend typecheck: passed
- root dev Go: passed
- Wails binding check: passed

## Full Gate 结果

- `go test -tags dev ./...`: passed
- `go test -tags production ./...`: passed
- `cd backend && go test ./...`: passed
- `cd frontend && pnpm run ci`: passed, 237 files / 759 tests
- `cd frontend && pnpm run build:wails`: passed
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`: passed through `build:wails`
- `node frontend/scripts/check-wails-bindings.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs`: passed, `deletionReady = true`
- `node frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs`: passed, `adapterRemoved = true`
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`: passed
- `docs/desktop-ipc-iteration-status.json` JSON parse: passed
- `git diff --check`: passed before final doc refresh

## 桌面/浏览器行为差异说明

- Desktop release: typed IPC remains first. The old generated generic IPC methods are no longer available. Missing typed data-plane coverage fails with `generic_ipc_disabled` through `desktopDisabledGenericIpcTransport.ts`.
- Desktop dev: typed IPC remains first. Explicit control-plane HTTP fallback through `fallbackBridge` remains for control-plane compatibility.
- Browser dev: HTTP/SSE debugging remains independent and unchanged.
- Rollback: `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` remains recognizable but is a no-op for adapter enablement. Re-enabling generic IPC would require coordinated source rollback of backend methods, generated bindings, shell fields, and adapter construction.

Smoke evidence:

- `scripts/check-desktop-ipc-smoke.ps1`: passed
- Summary: `output/desktop-ipc-smoke/desktop-ipc-smoke-summary.json`
- Desktop WebView typed: `directBackendApiRequestCount = 0`, `totalInstrumentedNetworkRequests = 0`, `genericIpcPolicy = disabled`, `genericIpcDisableExperimentBuildFlag = true`
- Desktop capture evidence: `capturePackets = 7074`, `httpStreams = 119`, `tcpStreams = 177`, `udpStreams = 54`, `objectCount = 205`, `objectEvidenceCount = 205`
- Browser-dev: `ok = true`, HTTP auth and SSE ready event green

## 评分

Total: 98/100

- Contract Correctness: 25/25
- Desktop Policy Compliance: 20/20
- Regression Safety: 20/20
- Diagnostics and Failure Shape: 15/15
- Docs and Traceability: 10/10
- Dev/Browser Compatibility: 8/10

扣分原因：

- Browser-dev HTTP/SSE 保持可用并由 smoke 覆盖，但本轮没有新增浏览器调试链路专项回归，因此 Dev/Browser Compatibility 保留 2 分余量。

## Open Blockers

无硬阻塞。

无 soft blockers。Post-removal audit complete.

## 自迭代记录

Round 34 自评：backend/generated `InvokeBackend*` deletion candidate 和 post-removal audit 均完成。Full gates、`build:wails`、guardrails、真实 Wails smoke 均通过，分数 98。根据自动决策规则，可以离开 cleanup blocker 状态；下一轮可做 generic IPC post-removal monitoring 或 shell API typed cleanup。

## 下一轮自动建议

下一轮：generic IPC post-removal monitoring 或 shell API typed cleanup。

边界：

- 不恢复 generic IPC data-plane。
- 保留 browser-dev HTTP/SSE。
- `GetBackendAuthToken`、`OpenCaptureDialog`、`BackendStatus`、update/native dialogs 继续按 shell compatibility 管理，除非下一轮显式替换为 typed shell contract。
- 若出现新的 `InvokeBackend*` 或 `createIpcBackendTransport` token，下一轮只修 guardrail blocker，不推进新域。
