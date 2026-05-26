# Desktop IPC Round 21 - Generic IPC adapter retirement readiness audit

- Author: Codex
- Time: 2026-05-26 19:02:28 +08:00
- Phase: post-phase-5
- Primary domain: generic IPC adapter retirement readiness

## 迁移域与目标

本轮不迁移新的业务域，也不移除 generic IPC adapter。目标是把 Round 20 的默认关闭实验变成机器可判定的 retirement readiness guardrail：

- 默认生产/发行版资产继续 adapter-enabled。
- `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` 只能作为显式实验开关启用。
- CI 必须验证实验不是 default-on、源码保留禁用 adapter/烟测/退出计划 token、tracker 记录了禁用实验烟测事实。
- 后续是否进入生产默认禁用必须由版本化 tracker 和 smoke evidence 决策，不能靠口头判断。

## 修改面清单

- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs`
  - 新增 retirement readiness 检查。
  - 校验 `desktopBridge.ts`、`ipcBackendTransport.ts`、`scripts/check-desktop-ipc-smoke.ps1`、`docs/desktop-ipc-old-binding-exit-plan.md` 的关键 token。
  - 拒绝 `VITE_DESKTOP_DISABLE_GENERIC_IPC` default-on 模式。
  - 校验 `docs/desktop-ipc-iteration-status.json` 中禁用实验烟测证据。
  - 校验 `frontend/package.json` 中 CI 已挂载 `desktop-generic-ipc-retirement:check`。
- `frontend/scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs`
  - 覆盖 valid contract、缺失禁用实验 smoke flag、default-on flag、CI 未挂载等场景。
- `frontend/package.json`
  - 新增 `desktop-generic-ipc-retirement:check`。
  - `pnpm run ci` 新增该 guardrail。
- `docs/desktop-ipc-iteration-status.json`
  - `currentRound` 更新为 21。
  - 新增 `genericIpcAdapterRetirementReadiness` 域。
  - `lastRound` 更新为 Round 21 自评和证据。
- `docs/desktop-ipc-migration-plan.md`
  - Post-phase typed cycles 追加 Round 21。
  - Next default slice 改为 production-default disablement preflight。
  - 新增 Round 21 development note。
- `docs/开发记录.md`
  - 追加本轮开发记录。

## Focused test 结果

已通过：

```powershell
cd frontend
pnpm exec vitest run scripts/check-desktop-generic-ipc-retirement-readiness.test.mjs scripts/check-desktop-generic-ipc-allowlist.test.mjs scripts/check-desktop-old-binding-compat.test.mjs src/app/integrations/desktopBridge.test.ts src/app/integrations/ipcBackendTransport.test.ts
```

结果：5 files / 58 tests passed。

## Full gate 结果

已通过：

```powershell
go test -tags dev ./...
go test -tags production ./...
cd backend && go test ./...
cd frontend && pnpm run ci
cd frontend && pnpm run build:wails
powershell -ExecutionPolicy Bypass -File .\scripts\check-desktop-assets.ps1
node frontend/scripts/check-wails-bindings.mjs
node frontend/scripts/check-desktop-transport-policy.mjs
node frontend/scripts/check-desktop-generic-ipc-allowlist.mjs
node frontend/scripts/check-desktop-generic-ipc-retirement-readiness.mjs
node frontend/scripts/check-desktop-old-binding-compat.mjs
node frontend/scripts/check-desktop-misc-compat-inventory.mjs
```

Frontend CI 结果：232 files / 740 tests passed。

## 桌面/浏览器行为差异说明

- Desktop release/default build: generic IPC adapter 仍保持 enabled，避免本轮直接改变生产默认行为。
- Desktop disabled-adapter experiment: 使用 `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` 构建后，`createDesktopBridge` 不创建 generic IPC adapter；缺 typed data-plane route 以 `generic_ipc_disabled` 快速失败，不回退 browser HTTP。
- Desktop typed overrides: 保持优先级不变，已迁移 typed route 继续走 typed Wails IPC。
- Wails runtime events: 禁用 generic IPC adapter 后仍通过 Wails runtime event subscription 工作。
- Browser dev: HTTP/SSE 调试链路保持 green，不受桌面 typed IPC 收紧策略误伤。

## Smoke 结果

普通 Wails smoke 已通过：

- `genericIpcDisableExperiment = false`
- `genericIpcDisableExperimentBuildFlag = false`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `browserDev.ok = true`

禁用 adapter 实验 Wails smoke 已通过：

- `genericIpcDisableExperiment = true`
- `genericIpcDisableExperimentRequested = true`
- `genericIpcDisableExperimentBuildFlag = true`
- `desktopWebviewTyped.directBackendApiRequestCount = 0`
- `browserDev.ok = true`
- `capturePackets = 7074`
- `httpStreams = 119`
- `objectCount = 205`

实验 smoke 后已重新执行默认 `cd frontend && pnpm run build:wails`，恢复 production/default adapter-enabled 资产。

## 评分

总分：99/100

- Contract Correctness: 25/25
  - Guardrail 明确绑定 disabled adapter、smoke switch、tracker evidence、package CI contract。
- Desktop Policy Compliance: 20/20
  - 默认 release 未 silent 改成 disabled；实验路径明确禁止 typed 缺失时回退 generic IPC/browser HTTP。
- Regression Safety: 20/20
  - Focused tests、root dev/production Go、backend Go、frontend CI、build:wails、静态 guardrails、普通和禁用实验 smoke 均通过。
- Diagnostics and Failure Shape: 15/15
  - 禁用 adapter 后缺 typed route 使用 `generic_ipc_disabled`，与业务错误和 browser-dev fallback 分层清晰。
- Docs and Traceability: 10/10
  - Tracker、plan、exit-plan guardrail、round report、开发记录同步。
- Dev/Browser Compatibility: 9/10
  - Browser-dev HTTP/SSE green；扣 1 分是因为生产默认禁用尚未执行，只完成 readiness audit。

硬阻塞：无。

## 自迭代记录

本轮评分 `99 >= 90`，可推进下一轮。自动决策为：进入 production-default generic IPC adapter disablement preflight，但仍不直接删除 `InvokeBackendJSON/Blob/Text` 或移除 `createIpcBackendTransport`。下一轮必须继续用 normal smoke 与 disabled-adapter smoke 双证据验证，确保默认策略变更不会破坏 browser-dev HTTP/SSE 或 shell/auth/dialog old-binding 例外。

## 下一轮自动建议

下一轮主切片：Production-default generic IPC adapter disablement preflight。

边界：

- 不删除 adapter 代码。
- 不移除 browser-dev HTTP/SSE。
- 不改 shell/auth/dialog old-binding 例外。
- 只评估是否把 desktop release 默认策略从 adapter-enabled 改成 disabled-by-policy，且必须保留显式回退/恢复路径。

准入条件：

- `pnpm run ci` 中 retirement readiness guardrail 继续 green。
- normal `build:wails` + Wails smoke green。
- `VITE_DESKTOP_DISABLE_GENERIC_IPC=1` build + `-DisableGenericIpcAdapterExperiment` smoke green。
- `desktopWebviewTyped.directBackendApiRequestCount = 0`。
- `browserDev.ok = true`。
