# Desktop IPC Round 20 - Generic IPC adapter disablement experiment

- Author: Codex
- Time: 2026-05-26 18:49:40 +08:00
- Phase: post-phase-5
- Primary slice: Generic IPC adapter disablement experiment

## 迁移域与目标

本轮只处理一个主切片：generic IPC adapter 的默认关闭实验设计与验证。

目标：

- 保持生产默认安全：不直接移除 `createIpcBackendTransport`。
- 提供默认关闭的 build-time 实验开关：`VITE_DESKTOP_DISABLE_GENERIC_IPC=1`。
- 实验开启时，桌面缺少 typed data-plane binding 的调用必须明确失败，不能静默走 generic IPC 或 browser HTTP。
- 保持 typed override 与 Wails runtime event subscription 可用。
- 让 smoke 证据能区分普通构建与真正带 flag 的禁用实验构建。

## 修改面清单

- `frontend/src/app/integrations/desktopBridge.ts`
  - 新增 `isDesktopGenericIpcDisableExperimentEnabled()`。
  - flag 开启时不创建 `createIpcBackendTransport`，改用 disabled transport。
  - typed overrides 继续覆盖 data bridge。
- `frontend/src/app/integrations/ipcBackendTransport.ts`
  - 新增 `generic_ipc_disabled` 错误码。
  - 新增 `createDisabledGenericIpcBackendTransport()`。
  - `requestJSON` / `requestBlob` / `requestText` 在实验模式下返回 endpoint-local `DesktopIpcRequestError`。
  - `subscribeEvents` 继续走 Wails runtime `EventsOn`，避免把事件通道误降级到 browser EventSource。
- `frontend/src/app/integrations/desktopBridge.test.ts`
  - 覆盖 flag 开启时 missing typed route fail-fast。
  - 覆盖 flag 开启时 typed `ListObjects` 仍成功。
  - 覆盖 flag 开启时事件订阅仍走 Wails runtime。
- `frontend/src/app/integrations/ipcBackendTransport.test.ts`
  - 覆盖 disabled generic IPC transport 的 JSON/blob/text 失败形态与事件订阅。
- `app.go`
  - `GetDesktopWebviewSmokeConfig()` 记录 `GSHARK_DESKTOP_DISABLE_GENERIC_IPC_EXPERIMENT`。
- `frontend/src/app/desktopWebviewSmoke.ts`
  - smoke result 记录 `genericIpcDisableExperimentRequested` 与 `genericIpcDisableExperimentBuildFlag`。
- `scripts/check-desktop-ipc-smoke.ps1`
  - 新增 `-DisableGenericIpcAdapterExperiment`。
  - 实验模式下断言 WebView smoke 结果包含 requested/build flag 双 true。
- `docs/desktop-ipc-old-binding-exit-plan.md`
  - 补充 `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` 与 smoke switch 作为 adapter 下线前提。
- `frontend/scripts/check-desktop-old-binding-compat.mjs`
  - 新增 exit-plan token 验证，防止实验事实源漂移。

## Focused test 结果

通过：

```powershell
cd frontend; pnpm exec vitest run src/app/integrations/desktopBridge.test.ts src/app/integrations/ipcBackendTransport.test.ts scripts/check-desktop-old-binding-compat.test.mjs
```

结果：

- 3 files passed
- 52 tests passed

## Full gate 结果

通过：

```powershell
go test -tags dev ./...
go test -tags production ./...
cd backend; go test ./...
cd frontend; pnpm run ci
cd frontend; pnpm run build:wails
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
node frontend/scripts/check-wails-bindings.mjs
node frontend/scripts/check-desktop-transport-policy.mjs
node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs
node frontend/scripts/check-desktop-old-binding-compat.mjs
node frontend/scripts/check-desktop-misc-compat-inventory.mjs
git diff --check
```

关键结果：

- Root dev Go tests passed.
- Root production Go tests passed.
- Backend Go tests passed.
- Frontend CI passed: 231 test files / 736 tests.
- `build:wails` passed after CI.
- Desktop asset check passed.
- Wails binding check passed.
- Desktop transport policy check passed.
- Generic IPC allowlist check passed.
- Old binding compatibility check passed.
- MISC transport inventory check passed; no MISC desktop compatibility routes remain.
- `git diff --check` passed.

## Smoke 结果

普通默认构建 smoke：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1 -TimeoutSeconds 180
```

结果：

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `genericIpcDisableExperiment = false`
- `desktopWebviewTyped.genericIpcDisableExperimentBuildFlag = false`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `capturePackets = 7074`
- `httpStreams = 119`
- `objectCount = 205`

禁用 adapter 实验 smoke：

```powershell
cd frontend; $env:VITE_DESKTOP_DISABLE_GENERIC_IPC='1'; pnpm run build:wails
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-desktop-ipc-smoke.ps1 -TimeoutSeconds 180 -DisableGenericIpcAdapterExperiment
```

结果：

- `desktopRelease.ok = true`
- `desktopWebviewTyped.ok = true`
- `browserDev.ok = true`
- `genericIpcDisableExperiment = true`
- `desktopWebviewTyped.genericIpcDisableExperimentRequested = true`
- `desktopWebviewTyped.genericIpcDisableExperimentBuildFlag = true`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `capturePackets = 7074`
- `httpStreams = 119`
- `objectCount = 205`

收尾安全动作：

- 实验 smoke 后已重新执行默认 `cd frontend && pnpm run build:wails`，当前嵌入资产回到默认 adapter-enabled 状态。

## 桌面/浏览器行为差异说明

- Desktop default build：仍保留 `createIpcBackendTransport`，用于未移除前的兼容窗口；typed route 仍优先。
- Desktop disabled experiment build：不创建 generic IPC adapter；缺 typed data-plane route 直接抛 `generic_ipc_disabled`。
- Desktop events：不随 disabled adapter 降级到 browser EventSource，仍走 Wails runtime events。
- Browser dev：不受 `createDesktopBridge` 的 disabled experiment 影响；HTTP/SSE smoke 仍 green。

## 评分

总分：99/100

- Contract Correctness: 25/25
  - flag 行为、disabled transport、typed override 优先级、事件通道均有测试覆盖。
- Desktop Policy Compliance: 20/20
  - 实验模式下 generic IPC 和 HTTP fallback 都不会被静默使用。
- Regression Safety: 20/20
  - focused tests、root dev/prod Go、backend Go、frontend CI、build:wails、guardrails、普通 smoke、实验 smoke 全部通过。
- Diagnostics and Failure Shape: 15/15
  - 新增 `generic_ipc_disabled`，endpoint 与 transport 字段明确。
- Docs and Traceability: 10/10
  - tracker、migration plan、old-binding exit plan、round report、开发记录同步。
- Dev/Browser Compatibility: 9/10
  - browser-dev HTTP/SSE smoke green；扣 1 分是因为实验 flag 是 build-time，不是运行时可热切换，符合 Wails 资产现实但操作上仍需要重新 build。

## Open blockers

无硬阻塞。

## 自迭代记录

- 判定：`99 >= 90`，当前切片完成，可以进入下一轮。
- 本轮没有新增 production 默认风险：默认构建最终已恢复 adapter-enabled。
- 实验已证明：当前 typed 主路径在禁用 generic IPC adapter 后仍能通过真实 Wails WebView smoke，且 WebView 没有直连 backend `/api`。
- 下线仍不应直接进行：需要再做一次 retirement readiness audit，确认 remaining old-binding shell/auth/dialog uses 与 browser-dev HTTP/SSE 边界未被误删。

## 下一轮自动建议

Generic IPC adapter retirement readiness audit：保持默认 adapter enabled，基于本轮 disabled-adapter smoke 证据审计 `createIpcBackendTransport` 是否仍有运行时必要性。只有在再次通过默认 full smoke 与 `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` 实验 smoke，且 `directBackendApiRequestCount = 0`、browser-dev HTTP/SSE green、approved shell/auth/dialog old-binding uses 不变时，才允许进入生产默认禁用或移除方案。
