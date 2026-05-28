# Desktop IPC disabled transport module split

- Author: Codex
- Time: 2026-05-26 22:54:29 +08:00
- Round: 32
- Phase: post-phase-5

## 迁移域与目标

本轮主域是 disabled generic IPC transport module split。

目标：将仍在运行路径上的 disabled generic IPC transport 从 legacy `ipcBackendTransport.ts` 拆出，使 `ipcBackendTransport.ts` 更清晰地只保留 unreachable generic IPC adapter inventory 和 shared IPC controls。这样后续删除或隔离 legacy adapter 文件时，不会误删桌面发行版当前依赖的 `generic_ipc_disabled` fail-fast 行为。

本轮不删除：

- backend `DesktopApp.InvokeBackendJSON`
- backend `DesktopApp.InvokeBackendBlob`
- backend `DesktopApp.InvokeBackendText`
- generated Wails `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`
- `check-wails-bindings generic-ipc group`
- `desktopTransportBindingShell.ts` generic IPC fields

## 修改面清单

- `frontend/src/app/integrations/desktopDisabledGenericIpcTransport.ts`
  - 新增 active disabled generic IPC transport module。
  - `requestJSON` / `requestBlob` / `requestText` 统一抛出 `DesktopIpcRequestError(code = generic_ipc_disabled)`。
  - 保留 aborted signal 的 `AbortError` 语义。
- `frontend/src/app/integrations/desktopEventTransport.ts`
  - 新增 Wails runtime event subscription helper。
  - `gshark:backend:packet` 仍通过 `asPacket` 映射。
  - status/error events 语义不变。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - 移除 `createDisabledGenericIpcBackendTransport` 导出。
  - 移除本地 `throwGenericIpcDisabled`。
  - 保留 `createIpcBackendTransport`、`DesktopIpcRequestError`、`withDesktopIpcControls`、route typed-binding guard、blob limit。
  - legacy adapter event subscription 改为使用 `desktopEventTransport.ts`。
- `frontend/src/app/integrations/desktopBridge.ts`
  - disabled transport import 改为 `desktopDisabledGenericIpcTransport.ts`。
  - `withDesktopIpcControls` 仍来自 `ipcBackendTransport.ts`。
- `frontend/src/app/integrations/desktopDisabledGenericIpcTransport.test.ts`
  - 新增 disabled transport behavior test。
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`
  - 移出 disabled transport test，保留 legacy adapter inventory tests。
- `frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs`
  - inventory 现在区分 legacy `ipcBackendTransport.ts` adapter surface 与 active `desktopDisabledGenericIpcTransport.ts` disabled surface。
  - 删除 “createDisabledGenericIpcBackendTransport must be moved” blocker。
- `frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.test.mjs`
  - fixture 更新为 split 后事实。
- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`
  - disabled source token 改为检查 `desktopDisabledGenericIpcTransport.ts`。
  - legacy adapter token 仍检查 `ipcBackendTransport.ts`。
- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs`
  - fixture 更新为 split 后模块结构。
- `docs/desktop-ipc-iteration-status.json`
  - Round 32 成为 lastRound。
  - cleanup preflight inventory 增加 `desktopDisabledGenericIpcTransport.ts`。
  - blockers 缩减为 3 项。
- `docs/desktop-ipc-migration-plan.md`
  - 记录 Round 32 和下一轮建议。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - 记录 Round 32 后的 next safe step。

## Focused Test 结果

Command:

```powershell
cd frontend
pnpm exec vitest run src/app/integrations/ipcBackendTransport.test.ts src/app/integrations/desktopDisabledGenericIpcTransport.test.ts src/app/integrations/desktopBridge.test.ts scripts/check-desktop-generic-ipc-binding-cleanup-preflight.test.mjs scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs scripts/check-desktop-generic-ipc-removal-preflight.test.mjs
```

Result:

- passed: 6 files / 76 tests

## Full Gate 结果

- `go test -tags dev ./...`: passed
- `go test -tags production ./...`: passed
- `cd backend && go test ./...`: passed
- `cd frontend && pnpm run ci`: passed, 237 files / 773 tests
- `cd frontend && pnpm run build:wails`: passed
- `powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`: passed after `build:wails`
- `node frontend/scripts/check-wails-bindings.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`: passed
- `node frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs`: passed
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`: passed
- `docs/desktop-ipc-iteration-status.json` JSON parse: passed
- `git diff --check`: passed

Note: one standalone `check-desktop-assets.ps1` invocation failed while it was started in parallel with `build:wails`, before `frontend/dist/sentinel-backend.exe` and YARA assets had been written. The same asset check inside `build:wails` passed, and a sequential standalone rerun after the build also passed. This is treated as a command scheduling race, not a product blocker.

## 桌面/浏览器行为差异说明

- Desktop release：`desktopBridge` still builds the data-plane base from the disabled transport; missing typed data-plane routes still fail with `generic_ipc_disabled`.
- Desktop release：typed overrides still take precedence; no silent HTTP fallback is reintroduced.
- Desktop events：Wails runtime event subscription remains active through `desktopEventTransport.ts`.
- Browser dev：HTTP/SSE debugging remains independent of this split.
- Generated bindings：`InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` remain present and guarded.

本轮未重复 Wails smoke，因为 runtime data-plane policy did not change: the active disabled transport keeps the same fail-fast behavior and event subscription is covered by focused tests plus `build:wails`.

## 评分

Total: 96/100

- Contract Correctness: 25/25
- Desktop Policy Compliance: 20/20
- Regression Safety: 20/20
- Diagnostics and Failure Shape: 14/15
- Docs and Traceability: 10/10
- Dev/Browser Compatibility: 7/10

扣分原因：

- 本轮未跑真实 Wails smoke。
- browser-dev 兼容性由 CI/build/guardrail 间接覆盖，没有重复手工 smoke。
- backend/generated deletion still remains staged behind blockers.

## Open Blockers

无硬阻塞。

剩余 deletion blockers:

- `desktop_backend_proxy_test.go` still directly tests exported generic helpers: `desktop_backend_proxy_test.go -> InvokeBackendJSON`
- `check-wails-bindings generic-ipc group` still requires generated `InvokeBackend*` bindings.
- `ipcBackendTransport.ts` still contains unreachable adapter implementation.

## 自迭代记录

Round 32 自评：当前切片完成，分数 96，允许进入下一 round，但仍不得直接跨到大规模 generated binding deletion。原因是 cleanup preflight 仍显示 deletionReady=false，且剩余 blocker 中包含后端 direct test、Wails generated binding group、frontend legacy adapter inventory 三类独立事项。

自动决策：继续留在 post-phase-5 cleanup governance。下一轮只处理 backend/generated deletion 的前置 blocker，不并行删除所有 generated binding。

## 下一轮自动建议

下一轮：backend/generated `InvokeBackendJSON` deletion preflight。

边界：

- 先替换或删除 `desktop_backend_proxy_test.go` 中 remaining direct `InvokeBackendJSON` contract test。
- 不在同一轮删除所有 backend/generated `InvokeBackend*`。
- 复跑 `check-desktop-generic-ipc-binding-cleanup-preflight.mjs`，观察 blockers 是否缩减。
- 只有当 blockers 缩小到 generated Wails bindings + `check-wails-bindings generic-ipc group` + shell inventory 时，后续 deletion round 才能同时移除 backend methods、regenerate Wails bindings、更新 `desktopTransportBindingShell` 和 old-binding compatibility allowlist。
