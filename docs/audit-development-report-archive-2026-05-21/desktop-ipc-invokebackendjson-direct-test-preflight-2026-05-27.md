# Desktop IPC InvokeBackendJSON direct test preflight

- Author: Codex
- Time: 2026-05-27 00:30:01 +08:00
- Round: 33
- Phase: post-phase-5

## 迁移域与目标

本轮主域是 backend/generated `InvokeBackendJSON` deletion preflight。

目标：移除 `desktop_backend_proxy_test.go` 对 exported generic `DesktopApp.InvokeBackendJSON` 的直接 contract 依赖，避免测试层继续把 old generated binding 当作新增/保留功能契约。行为覆盖仍保留，但改走 typed desktop methods。

本轮不删除：

- backend `DesktopApp.InvokeBackendJSON`
- backend `DesktopApp.InvokeBackendBlob`
- backend `DesktopApp.InvokeBackendText`
- generated Wails `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`
- `frontend/wailsjs/go/main/DesktopApp.*`
- `desktopTransportBindingShell.ts`
- `ipcBackendTransport.ts`
- `check-wails-bindings generic-ipc group`

## 修改面清单

- `desktop_backend_proxy_test.go`
  - `TestDesktopInvokeBackendJSONProxiesRequest` 改为 `TestDesktopTypedJSONProxiesRequest`。
  - JSON backend proxy 行为通过 typed `GetIndustrialAnalysis` 覆盖。
  - `TestDesktopInvokeBackendMultipart` 改为 `TestDesktopTypedMiscImportMultipart`。
  - Multipart proxy 行为通过 typed `ImportMiscModulePackageFromPath` 覆盖。
  - 不再直接调用 `app.InvokeBackendJSON(...)`。
- `docs/desktop-ipc-iteration-status.json`
  - 记录 Round 33。
  - 删除 direct-test blocker。
  - `deletionReady` 仍为 false。
- `docs/desktop-ipc-migration-plan.md`
  - 追加 Round 33。
  - 下一轮建议改为 dedicated backend/generated `InvokeBackend*` deletion candidate。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - 记录 direct-test blocker 已清除。

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
- `cd frontend && pnpm run ci`: passed, 237 files / 773 tests
- `cd frontend && pnpm run build:wails`: passed
- `node frontend/scripts/check-wails-bindings.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs`: passed
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`: passed
- `docs/desktop-ipc-iteration-status.json` JSON parse: passed
- `git diff --check`: passed

## 桌面/浏览器行为差异说明

本轮只改测试与迁移事实源，不改 runtime transport。

- Desktop release：typed IPC first policy unchanged.
- Browser dev：HTTP/SSE debugging path unchanged.
- Generated bindings：`InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` still exist and are still required by current Wails binding checks.
- Backend proxy behavior：JSON and multipart proxy behavior remain covered through typed method tests.

本轮未跑真实 Wails smoke，因为 runtime data-plane behavior did not change.

## 评分

Total: 95/100

- Contract Correctness: 25/25
- Desktop Policy Compliance: 20/20
- Regression Safety: 19/20
- Diagnostics and Failure Shape: 14/15
- Docs and Traceability: 10/10
- Dev/Browser Compatibility: 7/10

扣分原因：

- 本轮未跑真实 Wails smoke。
- generated binding deletion 仍未执行，剩余 blocker 需要 dedicated deletion round 处理。

## Open Blockers

无硬阻塞。

剩余 deletion blockers:

- `check-wails-bindings generic-ipc group` still requires generated `InvokeBackend*` bindings.
- `ipcBackendTransport.ts` still contains unreachable adapter implementation.

## 自迭代记录

Round 33 自评：direct `InvokeBackendJSON` test blocker 已清除，分数 95，full gates passed。根据自动决策规则，下一轮可以推进到 dedicated backend/generated binding deletion candidate，但必须作为单独 round，且必须同时处理 backend methods、Wails generated bindings、frontend shell type、legacy adapter inventory、binding check group 和 old-binding compatibility allowlist。

## 下一轮自动建议

下一轮：backend/generated `InvokeBackend*` deletion candidate。

边界：

- 删除 backend `DesktopApp.InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`。
- 重新生成或同步删除 generated Wails `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`。
- 删除或隔离 `ipcBackendTransport.ts` legacy adapter implementation。
- 更新 `desktopTransportBindingShell.ts`。
- 更新 `check-wails-bindings generic-ipc group`。
- 更新 old-binding compatibility allowlist。
- 保留 `desktopDisabledGenericIpcTransport.ts` 和 browser-dev HTTP/SSE。
- 跑 full gates、`build:wails`，再决定是否需要 Wails smoke。
