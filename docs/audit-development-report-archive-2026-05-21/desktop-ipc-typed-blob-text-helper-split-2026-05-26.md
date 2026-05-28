# Desktop IPC typed blob/text helper split

- Author: Codex
- Time: 2026-05-26 22:57:00 +08:00
- Round: 31
- Phase: post-phase-5

## 迁移域与目标

本轮主域是 typed blob/text helper split。

目标：消除 typed 后端方法对 exported generic `DesktopApp.InvokeBackendBlob` / `DesktopApp.InvokeBackendText` 的内部复用，为后续 backend/generated `InvokeBackend*` 删除创造条件。

本轮不删除：

- backend `DesktopApp.InvokeBackendJSON`
- backend `DesktopApp.InvokeBackendBlob`
- backend `DesktopApp.InvokeBackendText`
- generated Wails `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`
- frontend `ipcBackendTransport.ts`

## 修改面清单

- `desktop_backend_proxy.go`
  - 新增 non-exported `invokeBackendBlob`。
  - 新增 non-exported `invokeBackendText`。
  - `InvokeBackendBlob` / `InvokeBackendText` 仅转发到 lowercase helper，保持现有 generated binding 行为。
  - `DownloadObjectsZip`、`GetWinRMDecryptResultText`、`ExportWinRMDecryptResult`、`ExportMediaBatchTranscription`、`DownloadMediaArtifact`、`GetMediaPlaybackBlob` 改为调用 lowercase helper。
- `desktop_backend_proxy_test.go`
  - blob/text 行为测试改为通过 typed methods 覆盖。
  - 覆盖 object ZIP、WinRM text/export、media batch export、media artifact download、media playback。
- `frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs`
  - 删除阻塞项更精确地列出仍直接测试的 exported generic helper。
- `frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.test.mjs`
  - fixture 更新为 typed helper reuse 为 0 的当前事实。
  - 保留旧 typed helper reuse 检出测试，防止回归。
- `docs/desktop-ipc-iteration-status.json`
  - `typedHelperReuse = []`。
  - 记录下一轮为 disabled transport module split。
- `docs/desktop-ipc-migration-plan.md`
  - 追加 Round 31。
  - 更新下一轮建议。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - 记录 typed helper reuse 已清零。

## Focused Test 结果

Commands:

```powershell
go test -tags dev ./...
cd frontend
pnpm exec vitest run scripts/check-desktop-generic-ipc-binding-cleanup-preflight.test.mjs
node ../frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs
```

Result:

- root dev Go: passed
- binding cleanup preflight Vitest: passed, 1 file / 7 tests
- binding cleanup preflight script: passed

## Full Gate 结果

- `go test -tags dev ./...`: passed
- `go test -tags production ./...`: passed
- `cd backend && go test ./...`: passed
- `cd frontend && pnpm run ci`: passed, 236 files / 773 tests
- `cd frontend && pnpm run build:wails`: passed
- `node frontend/scripts/check-wails-bindings.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs`: passed
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`: passed
- `docs/desktop-ipc-iteration-status.json` JSON parse: passed
- `git diff --check`: passed

## 桌面/浏览器行为差异说明

本轮只改后端 typed helper 内部调用路径，不改变 frontend runtime transport。

- Desktop release：typed IPC 优先策略不变；frontend generic IPC adapter construction 仍移除。
- Browser dev：HTTP/SSE 调试链路不受影响。
- Generated binding：`InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` 仍存在，等待后续专门删除轮。

本轮未重复 Wails smoke，因为没有改 WebView transport 或 generated binding 表面。风险由 root Go typed helper tests、frontend CI 和 `build:wails` 覆盖。

## 评分

Total: 95/100

- Contract Correctness: 25/25
- Desktop Policy Compliance: 20/20
- Regression Safety: 18/20
- Diagnostics and Failure Shape: 13/15
- Docs and Traceability: 10/10
- Dev/Browser Compatibility: 9/10

扣分原因：

- 本轮未跑真实 Wails smoke。
- backend/generated 删除仍未就绪，仍需拆 disabled transport module 和 generated binding group。

## Open Blockers

无硬阻塞。

删除阻塞项减少为：

- `desktop_backend_proxy_test.go` still directly tests exported generic helpers: `desktop_backend_proxy_test.go -> InvokeBackendJSON`
- `check-wails-bindings generic-ipc group` still requires generated `InvokeBackend*` bindings.
- `ipcBackendTransport.ts` still contains unreachable adapter implementation.
- `createDisabledGenericIpcBackendTransport` must be moved before deleting `ipcBackendTransport.ts`.

## 自迭代记录

Round 31 自评后不进入 generated binding deletion。typed helper reuse 已经清零，但 disabled transport 仍与 unreachable adapter implementation 共处于 `ipcBackendTransport.ts`，如果直接删除该文件会破坏 `desktopBridge` 的 fail-fast disabled transport。

自动决策：继续留在 post-phase-5 cleanup governance，下一轮做 disabled transport module split。

## 下一轮自动建议

下一轮：disabled transport module split。

边界：

- 不删除 generated Wails `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`。
- 不删除 backend `DesktopApp.InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`。
- 将 `createDisabledGenericIpcBackendTransport` 与 `generic_ipc_disabled` fail-fast 行为从 `ipcBackendTransport.ts` 移入独立模块。
- `desktopBridge` 改为 import 新 disabled transport 模块。
- `ipcBackendTransport.ts` 保留为 unreachable legacy adapter inventory。
- 更新 tests 与 cleanup preflight，使 frontend binding surfaces 能区分 active disabled transport 与 legacy adapter implementation。
