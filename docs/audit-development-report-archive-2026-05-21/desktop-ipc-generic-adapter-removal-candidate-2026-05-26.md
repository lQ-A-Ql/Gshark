# Desktop IPC generic adapter removal candidate

- Author: Codex
- Time: 2026-05-26 21:41:45 +08:00
- Round: 29
- Phase: post-phase-5
- Primary slice: generic IPC adapter removal candidate

## 迁移域与目标

本轮只处理前端 generic IPC adapter 构造移除候选，不删除 backend Wails `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText` 方法，也不删除 generated Wails bindings。

目标：

- `desktopBridge` 不再 import 或 construct `createIpcBackendTransport`。
- typed desktop overrides 继续优先。
- 缺失 typed data-plane binding 时抛 `generic_ipc_disabled`，不调用 `InvokeBackendJSON`，不 silent fallback browser HTTP。
- runtime/MCP/capture/TLS 这类控制面兼容 fallback 明确走 `fallbackBridge`。
- Wails runtime event subscription 继续通过 `EventsOn`。
- `VITE_DESKTOP_GENERIC_IPC_POLICY=compat` 保留为可识别策略值，但不再重新启用 adapter。

## 修改面清单

- `frontend/src/app/integrations/desktopBridge.ts`
  - 移除 `createIpcBackendTransport` 构造路径。
  - 统一用 `createDisabledGenericIpcBackendTransport` 作为 data-plane base。
  - 控制面缺失 binding 或 typed runtime/MCP failure 时显式调用 `fallbackBridge`。
- `frontend/src/app/integrations/desktopGenericIpcPolicy.ts`
  - `resolveDesktopGenericIpcPolicy` 继续识别 `compat`。
  - `isDesktopGenericIpcDisabled` 恒为 `true`，使 `compat` 只作为 no-op policy value。
- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`
  - 要求 `desktopBridge` 不再构造 adapter。
  - 要求 compat no-op contract。
- `frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs`
  - 允许 tracker 状态进入 `candidate-completed`。
  - 继续 inventory remaining adapter bindings。
- `frontend/scripts/check-desktop-generic-ipc-rollback-guard.mjs`
  - 从 adapter-enabled rollback guard 调整为 compat no-op guard。
- `docs/desktop-ipc-iteration-status.json`
  - Round 29 记录前端 adapter construction removed。
  - `adapterRemoved` 仍为 `false`，因为 backend/generated bindings 仍存在。
- `docs/desktop-ipc-migration-plan.md`
  - 增加 Round 29。
  - 下一轮建议切到 backend/generated binding cleanup preflight。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - 记录 Round 29 后 `compat` 不再是 env-only rollback。

## Focused test 结果

已通过：

```powershell
cd frontend
pnpm exec vitest run scripts/check-desktop-generic-ipc-removal-preflight.test.mjs scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs scripts/check-desktop-generic-ipc-rollback-guard.test.mjs src/app/integrations/desktopGenericIpcPolicy.test.ts src/app/integrations/desktopBridge.test.ts src/app/integrations/ipcBackendTransport.test.ts
```

最终补跑结果：7 files / 82 tests passed。

## Full gate 结果

已通过：

- `go test -tags dev ./...`
- `go test -tags production ./...`
- `cd backend && go test ./...`
- `cd frontend && pnpm run ci`：235 files / 766 tests passed
- `cd frontend && pnpm run build:wails`
- `node frontend/scripts/check-wails-bindings.mjs`
- `node frontend/scripts/check-desktop-transport-policy.mjs`
- `node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs`
- `node frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`
- `node frontend/scripts/check-desktop-generic-ipc-rollback-guard.mjs`
- `node frontend/scripts/check-desktop-generic-ipc-removal-preflight.mjs`
- `node frontend/scripts/check-desktop-old-binding-compat.mjs`
- `node frontend/scripts/check-desktop-misc-compat-inventory.mjs`
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1`
- `git diff --check`

## Wails smoke 结果

已通过：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1 -TimeoutSeconds 180 -OutputDir .\output\desktop-ipc-smoke
```

证据：

- `genericIpcPolicy = disabled`
- `genericIpcDisableExperimentBuildFlag = true`
- `directBackendApiRequestCount = 0`
- `browserDev.ok = true`
- `capturePackets = 7074`
- `httpStreams = 119`
- `objectCount = 205`

## 桌面/浏览器行为差异说明

- Desktop release:
  - typed IPC data-plane 优先。
  - 缺 typed data-plane binding 直接 `generic_ipc_disabled`。
  - 不再构造 frontend generic IPC adapter。
  - `compat` 不再 env-only 恢复 adapter。
- Desktop control-plane:
  - runtime/MCP/capture/TLS 缺失 binding 或部分 typed failure 可走显式 `fallbackBridge`。
  - 这不是 generic IPC adapter fallback。
- Browser dev:
  - HTTP/SSE 保持独立，不受 desktop adapter removal candidate 影响。

## 评分

最终自评：97/100。

- Contract Correctness: 25/25
- Desktop Policy Compliance: 20/20
- Regression Safety: 18/20
- Diagnostics and Failure Shape: 15/15
- Docs and Traceability: 10/10
- Dev/Browser Compatibility: 9/10

扣分原因：

- backend/generated `InvokeBackend*` bindings 尚未清理。
- `compat` 已不再是 env-only rollback；若后续需要回滚，必须恢复源码构造路径。

## Open blockers

当前无硬阻塞。

## 自迭代记录

自动决策：

- Full gates、`build:wails`、default-disabled Wails smoke、final guardrails 全部通过。
- 下一轮进入 `backend/generated generic IPC binding cleanup preflight`。
- 下一轮仍不删除 backend/generated bindings，只做 inventory、风险评估和 guardrail 设计。

## 下一轮自动建议

下一轮建议：backend/generated generic IPC binding cleanup preflight。

范围：

- inventory root DesktopApp `InvokeBackendJSON` / `InvokeBackendBlob` / `InvokeBackendText`。
- inventory `desktopTransportBindingShell.ts`。
- inventory `ipcBackendTransport.ts` reachability。
- inventory generated Wails bindings。
- inventory smoke scripts and old-binding allowlist requirements。

明确不做：

- 不在 preflight 轮删除 backend/generated bindings。
- 不移除 browser-dev HTTP/SSE。
- 不把 shell/update/dialog 方法归为 data-plane debt。
