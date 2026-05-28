# Desktop IPC backend/generated binding cleanup preflight

- Author: Codex
- Time: 2026-05-26 22:32:00 +08:00
- Round: 30
- Phase: post-phase-5

## 迁移域与目标

本轮主域是 backend/generated generic IPC binding cleanup preflight。

目标不是删除 `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`，而是把后端、生成绑定、前端 shell 类型、guardrail 依赖和删除阻塞项变成机器可判定事实。

## 修改面清单

- 新增 `frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs`。
- 新增 `frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.test.mjs`。
- `frontend/package.json` 新增 `desktop-generic-ipc-binding-cleanup-preflight:check` 并接入 `pnpm run ci`。
- `docs/desktop-ipc-iteration-status.json` 新增 `genericIpcBackendGeneratedBindingCleanupPreflight` 域，并把当前 round 更新为 Round 30。
- `docs/desktop-ipc-migration-plan.md` 追加 Round 30 和 backend/generated cleanup preflight contract。
- `docs/desktop-ipc-old-binding-exit-plan.md` 追加 backend/generated cleanup preflight 约束。

## 事实清单

当前删除状态：`deletionReady = false`。

保留的后端导出方法：

- `DesktopApp.InvokeBackendJSON`
- `DesktopApp.InvokeBackendBlob`
- `DesktopApp.InvokeBackendText`

typed helper reuse 仍存在：

- `DownloadObjectsZip -> InvokeBackendBlob`
- `GetWinRMDecryptResultText -> InvokeBackendText`
- `ExportWinRMDecryptResult -> InvokeBackendBlob`
- `ExportMediaBatchTranscription -> InvokeBackendBlob`
- `DownloadMediaArtifact -> InvokeBackendBlob`
- `GetMediaPlaybackBlob -> InvokeBackendBlob`

生成绑定仍存在：

- `frontend/wailsjs/go/main/DesktopApp.d.ts` exports `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`
- `frontend/wailsjs/go/main/DesktopApp.js` exports `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`

前端 inventory 仍存在：

- `desktopTransportBindingShell.ts` declares `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`
- `ipcBackendTransport.ts` contains unreachable `createIpcBackendTransport`
- `ipcBackendTransport.ts` contains active `createDisabledGenericIpcBackendTransport`

guardrail 依赖仍存在：

- `check-wails-bindings.mjs` still requires the `generic-ipc` group.
- `check-desktop-old-binding-compat.mjs` still allows the `ipcBackendTransport.ts` `InvokeBackend*` inventory.

## Focused Test 结果

Command:

```powershell
cd frontend
pnpm exec vitest run scripts/check-desktop-generic-ipc-binding-cleanup-preflight.test.mjs scripts/check-desktop-generic-ipc-removal-preflight.test.mjs scripts/check-desktop-old-binding-compat.test.mjs src/app/integrations/desktopBridge.test.ts src/app/integrations/desktopGenericIpcPolicy.test.ts src/app/integrations/ipcBackendTransport.test.ts
```

Result:

- passed
- 6 files / 73 tests

## Full Gate 结果

- `go test -tags dev ./...`: passed
- `go test -tags production ./...`: passed
- `cd backend && go test ./...`: passed
- `cd frontend && pnpm run ci`: passed, 236 files / 772 tests
- `cd frontend && pnpm run build:wails`: passed
- `node frontend/scripts/check-wails-bindings.mjs`: passed
- `node frontend/scripts/check-desktop-transport-policy.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs`: passed
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`: passed
- `git diff --check`: passed

## 桌面/浏览器行为差异说明

本轮不修改 runtime transport。桌面 release 仍是 typed IPC 优先，frontend generic IPC adapter construction 已在 Round 29 移除；browser-dev HTTP/SSE 调试链路不受本轮影响。

本轮未重复 Wails smoke，因为只新增 inventory guardrail 和文档，没有改运行时路径。沿用上一轮真实 Wails smoke 事实：default-disabled WebView `directBackendApiRequestCount = 0`，browser-dev green。

## 评分

Total: 92/100

- Contract Correctness: 23/25
- Desktop Policy Compliance: 20/20
- Regression Safety: 17/20
- Diagnostics and Failure Shape: 13/15
- Docs and Traceability: 10/10
- Dev/Browser Compatibility: 9/10

扣分原因：

- 删除尚未就绪，typed helper reuse 仍需拆分。
- 本轮没有重复真实 Wails smoke，因为运行时路径未改。

## Open Blockers

无硬阻塞。

删除阻塞项如下：

- typed helper reuse still calls `DesktopApp.InvokeBackendBlob/Text` from typed methods.
- `desktop_backend_proxy_test.go` still directly tests `InvokeBackendJSON/Blob/Text`.
- `check-wails-bindings generic-ipc group` still requires generated `InvokeBackend*` bindings.
- `ipcBackendTransport.ts` still contains unreachable adapter implementation.
- `createDisabledGenericIpcBackendTransport` must be moved before deleting `ipcBackendTransport.ts`.

## 自迭代记录

Round 30 自评后不进入 generated binding deletion。虽然 frontend adapter construction 已移除且本轮 gate 全绿，但 backend/generated binding deletion 会破坏当前 typed blob/text 方法、Wails binding check 和 old-binding inventory。

自动决策：留在 post-phase-5 cleanup governance，下一轮先拆 typed blob/text helper reuse。

## 下一轮自动建议

下一轮：typed blob/text helper split。

边界：

- 不删除 generated Wails `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`。
- 不删除 `ipcBackendTransport.ts`。
- 先把 `DownloadObjectsZip`、`GetWinRMDecryptResultText`、`ExportWinRMDecryptResult`、`ExportMediaBatchTranscription`、`DownloadMediaArtifact`、`GetMediaPlaybackBlob` 从 exported generic helper 调用改到 non-exported helper。
- 保持 bounded read、content type、filename、size 和 text response 语义。
- 更新 `desktop_backend_proxy_test.go`，让测试覆盖 typed helper 语义而不是直接依赖 exported generic helper。
- 再跑 `frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs`，目标是 typed helper reuse 归零，但 deletionReady 仍可保持 false，直到 Wails generated binding removal round。
